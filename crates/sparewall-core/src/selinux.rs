//! SELinux denials that concern the coordinator: by its domain,
//! `sparewalld_t`, or on its types. sparewalld watches the audit stream
//! and records them here; the `selinux` health check stays degraded until
//! an admin acknowledges them, across restarts and reboots, and /metrics
//! counts them.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::health::{Check, Level};
use crate::store::write_atomic;

/// The health check's name, which `sparewall health ack` takes.
pub const CHECK: &str = "selinux";
const FILE: &str = "selinux.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denials {
    /// Every denial recorded on this node.
    pub total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<Denial>,
    /// Times the stream overflowed and records were dropped: denials may
    /// have been missed, so this counts like one.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub lost: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<Ack>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denial {
    pub at: String,
    /// The AVC record, from `avc:` on.
    pub record: String,
    /// Logged but allowed: the domain was permissive.
    pub permissive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub by: String,
    pub at: String,
    /// The total it acknowledged.
    pub total: u64,
    /// And the overflows.
    #[serde(default)]
    pub lost: u64,
}

/// The denial in an audit record (kernel `AVC` or userspace `USER_AVC`),
/// if it concerns the coordinator: the record from `avc:` on, and
/// whether it was only logged (`permissive=1`). The same filter as the
/// VM suites' SELinux gate.
pub fn relevant(record: &str) -> Option<(String, bool)> {
    let start = record.find("avc:")?;
    // USER_AVC quotes the message: msg='avc: ... '.
    let avc = record[start..].split('\'').next()?.trim_end();
    if !avc.split_whitespace().any(|w| w == "denied") {
        return None;
    }
    let ty = |field: &str| {
        avc.split_whitespace()
            .find_map(|w| w.strip_prefix(field))
            .and_then(|c| c.split(':').nth(2))
    };
    let ours = ty("scontext=") == Some("sparewalld_t")
        || ty("tcontext=").is_some_and(|t| t.starts_with("sparewalld_"));
    ours.then(|| {
        (
            avc.to_string(),
            avc.split_whitespace().any(|w| w == "permissive=1"),
        )
    })
}

impl Denials {
    pub fn read(state_dir: &Path) -> Denials {
        fs::read(state_dir.join(FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn write(&self, state_dir: &Path) -> std::io::Result<()> {
        let mut b = serde_json::to_vec_pretty(self).expect("json");
        b.push(b'\n');
        write_atomic(&state_dir.join(FILE), &b)
    }

    pub fn record(&mut self, record: String, permissive: bool, at: String) {
        self.total += 1;
        self.last = Some(Denial {
            at,
            record,
            permissive,
        });
    }

    /// The stream overflowed: records were dropped.
    pub fn record_lost(&mut self, at: String) {
        self.lost += 1;
        self.lost_at = Some(at);
    }

    /// Denials since the last acknowledgement.
    pub fn unacknowledged(&self) -> u64 {
        self.total - self.ack.as_ref().map_or(0, |a| a.total)
    }

    /// Overflows since the last acknowledgement.
    pub fn unacknowledged_lost(&self) -> u64 {
        self.lost - self.ack.as_ref().map_or(0, |a| a.lost)
    }

    pub fn acknowledge(&mut self, by: String, at: String) {
        self.ack = Some(Ack {
            by,
            at,
            total: self.total,
            lost: self.lost,
        });
    }

    /// The `selinux` check. `enforcing` is the system's mode (`None`:
    /// SELinux is off); `watch_error`, why denials cannot be watched.
    pub fn check(&self, enforcing: Option<bool>, watch_error: Option<&str>) -> Check {
        let mut problems = Vec::new();
        match enforcing {
            None => problems.push("SELinux is disabled: nothing is confined".to_string()),
            Some(false) => problems.push("SELinux is permissive: nothing is confined".to_string()),
            Some(true) => {}
        }
        if let Some(e) = watch_error {
            problems.push(format!("cannot watch for denials: {e}"));
        }
        let n = self.unacknowledged();
        if n > 0
            && let Some(d) = &self.last
        {
            problems.push(format!(
                "{n} denial{} for the coordinator{}, the last at {}: {}{}; \
                 acknowledge with: sparewall health ack {CHECK}",
                if n == 1 { "" } else { "s" },
                match &self.ack {
                    Some(a) => format!(" since {} acknowledged them", a.by),
                    None => String::new(),
                },
                d.at,
                d.record,
                if d.permissive {
                    " (allowed: the coordinator's domain is permissive; make it \
                     enforcing again once the rule is in the image)"
                } else {
                    ""
                },
            ));
        }
        let lost = self.unacknowledged_lost();
        if lost > 0 {
            problems.push(format!(
                "audit records were dropped {lost} time{}, the last at {}: denials may have \
                 been missed (see the journal); acknowledge with: sparewall health ack {CHECK}",
                if lost == 1 { "" } else { "s" },
                self.lost_at.as_deref().unwrap_or("?"),
            ));
        }
        if !problems.is_empty() {
            return Check::new(CHECK, Level::Degraded, problems.join("; "));
        }
        Check::new(
            CHECK,
            Level::Ok,
            match &self.ack {
                Some(a) => format!(
                    "no denials since {} acknowledged {} at {}",
                    a.by, a.total, a.at
                ),
                None => "no denials".into(),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AVC: &str = "audit(1792185241.677:183): avc:  denied  { net_admin } for  pid=872 comm=\"nft\" capability=12  scontext=system_u:system_r:sparewalld_t:s0 tcontext=system_u:system_r:sparewalld_t:s0 tclass=capability permissive=0";

    #[test]
    fn keeps_only_the_coordinators_denials() {
        let (r, p) = relevant(AVC).unwrap();
        assert!(r.starts_with("avc:  denied  { net_admin }"), "{r}");
        assert!(!p);
        // On its types, by another domain.
        assert!(relevant("avc:  denied  { read } for comm=\"kea\" scontext=system_u:system_r:container_t:s0:c1,c2 tcontext=system_u:object_r:sparewalld_provider_conf_t:s0 tclass=file permissive=1").unwrap().1);
        // Neither.
        assert!(relevant("avc:  denied  { siginh } for pid=1 comm=\"sshd-session\" scontext=system_u:system_r:sshd_t:s0-s0:c0.c1023 tcontext=system_u:system_r:sshd_session_t:s0-s0:c0.c1023 tclass=process permissive=0").is_none());
        // Granted (auditallow), not denied.
        assert!(relevant(&AVC.replace("denied", "granted")).is_none());
        // systemd's userspace check, quoted.
        let user = "pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 msg='avc:  denied  { start } for auid=n/a uid=0 gid=0 path=\"/usr/lib/systemd/system/x.service\" cmdline=\"\" function=\"mac_selinux_filter\" scontext=system_u:system_r:sparewalld_t:s0 tcontext=system_u:object_r:systemd_unit_file_t:s0 tclass=service permissive=0 exe=\"/usr/lib/systemd/systemd\" sauid=0 hostname=? addr=? terminal=?'";
        let (r, _) = relevant(user).unwrap();
        assert!(
            r.ends_with(
                "permissive=0 exe=\"/usr/lib/systemd/systemd\" sauid=0 hostname=? addr=? terminal=?"
            ),
            "{r}"
        );
    }

    #[test]
    fn degraded_until_acknowledged_and_again_after() {
        let mut d = Denials::default();
        assert_eq!(d.check(Some(true), None).level, Level::Ok);
        let (r, p) = relevant(AVC).unwrap();
        d.record(r.clone(), p, "2026-10-17T20:00:00Z".into());
        d.record(r.clone(), p, "2026-10-17T20:00:01Z".into());
        let c = d.check(Some(true), None);
        assert_eq!(c.level, Level::Degraded);
        assert!(
            c.message.starts_with(
                "2 denials for the coordinator, the last at 2026-10-17T20:00:01Z: avc:"
            ),
            "{}",
            c.message
        );
        assert!(
            c.message
                .ends_with("acknowledge with: sparewall health ack selinux"),
            "{}",
            c.message
        );

        d.acknowledge("admin".into(), "2026-10-17T21:00:00Z".into());
        let c = d.check(Some(true), None);
        assert_eq!(c.level, Level::Ok);
        assert_eq!(
            c.message,
            "no denials since admin acknowledged 2 at 2026-10-17T21:00:00Z"
        );

        d.record(r, true, "2026-10-17T22:00:00Z".into());
        let c = d.check(Some(true), None);
        assert_eq!(c.level, Level::Degraded);
        assert!(
            c.message
                .starts_with("1 denial for the coordinator since admin acknowledged them"),
            "{}",
            c.message
        );
        assert!(c.message.contains("domain is permissive"), "{}", c.message);
        assert_eq!(d.total, 3);
    }

    #[test]
    fn dropped_records_count_until_acknowledged() {
        let mut d = Denials::default();
        d.record_lost("2026-10-17T20:00:00Z".into());
        let c = d.check(Some(true), None);
        assert_eq!(c.level, Level::Degraded);
        assert!(
            c.message
                .starts_with("audit records were dropped 1 time, the last at 2026-10-17T20:00:00Z"),
            "{}",
            c.message
        );
        d.acknowledge("admin".into(), "t".into());
        assert_eq!(d.check(Some(true), None).level, Level::Ok);
        d.record_lost("t2".into());
        assert_eq!(d.check(Some(true), None).level, Level::Degraded);
        // An acknowledgement written before overflows were counted.
        let old: Denials =
            serde_json::from_str(r#"{"total":1,"ack":{"by":"a","at":"t","total":1}}"#).unwrap();
        assert_eq!(old.check(Some(true), None).level, Level::Ok);
    }

    #[test]
    fn not_enforcing_or_not_watching_is_degraded() {
        let d = Denials::default();
        assert_eq!(d.check(Some(false), None).level, Level::Degraded);
        assert_eq!(
            d.check(None, None).message,
            "SELinux is disabled: nothing is confined"
        );
        let c = d.check(Some(true), Some("permission denied"));
        assert_eq!(c.message, "cannot watch for denials: permission denied");
    }

    #[test]
    fn persists() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Denials::read(dir.path()), Denials::default());
        let mut d = Denials::default();
        d.record("avc:  denied".into(), false, "t".into());
        d.acknowledge("admin".into(), "t2".into());
        d.write(dir.path()).unwrap();
        assert_eq!(Denials::read(dir.path()), d);
    }
}
