//! Scheduled upgrades in a maintenance window (#84): with
//! `updates.mode: windowed`, the pair's master (or a standalone node)
//! upgrades itself when `updates.window` opens, if the channel offers a
//! newer image, through exactly what `sparewall upgrade` runs.
//!
//! Each window is tried once. Unless every precondition holds (health ok,
//! nothing pending, the pair in sync and not held, this node its master,
//! no earlier failure unacknowledged), the window is skipped and why is
//! recorded. A failed scheduled upgrade makes the `upgrade` health check
//! degraded and blocks the next ones until it is acknowledged
//! (`sparewall health ack upgrade`) or an upgrade is started by hand.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sparewall_api::FirewallError;
use sparewall_core::{Check, Level};
use tokio::sync::broadcast;

use crate::peer::Pair;
use crate::service::{Core, booted_image_digest, status, with_core, with_core_raw};
use crate::update::{JOURNAL_TARGET, Kind};

/// The health check, and the name `sparewall health ack` takes.
pub const CHECK: &str = "upgrade";
/// The journal's `MESSAGE_ID` of each scheduled attempt (skipped,
/// started, succeeded, failed).
pub const MESSAGE_ATTEMPT: &str = "4f0b6f0a8f4c4e1f9c7d2b3a5e6d7c81";
const FILE: &str = "scheduled-upgrade.json";
pub const DEFAULT_MINUTES: u32 = 60;
const POLL: Duration = Duration::from_secs(30);

/// How an attempt ended (or where it stands).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Result_ {
    Skipped,
    Started,
    Succeeded,
    Failed,
}

/// One window's attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    /// When the window opened (RFC 3339), which identifies it.
    pub window: String,
    /// When the attempt was decided or ended.
    pub at: String,
    pub result: Result_,
    pub detail: String,
    /// The image booted when it started, to tell after the reboot whether
    /// the node moved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_image: Option<String>,
}

/// What is kept across restarts and reboots.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<Attempt>,
    /// A failed attempt nobody has acknowledged: it blocks the next ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking: Option<Attempt>,
}

impl Record {
    fn path(root: &Path) -> PathBuf {
        root.join(FILE)
    }

    pub fn read(root: &Path) -> Record {
        std::fs::read(Self::path(root))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn write(&self, root: &Path) -> std::io::Result<()> {
        sparewall_core::store::write_atomic(
            &Self::path(root),
            &serde_json::to_vec_pretty(self).expect("json"),
        )
    }

    /// The `upgrade` health check, once there is something to say:
    /// degraded while a failure blocks.
    pub fn check(&self) -> Option<Check> {
        if self.last.is_none() && self.blocking.is_none() {
            return None;
        }
        Some(match &self.blocking {
            Some(a) => Check::new(
                CHECK,
                Level::Degraded,
                format!(
                    "the scheduled upgrade at {} failed: {}; scheduled upgrades wait until \
                     acknowledged with: sparewall health ack upgrade",
                    a.at, a.detail
                ),
            ),
            None => Check::new(
                CHECK,
                Level::Ok,
                match &self.last {
                    Some(a) => {
                        format!("last scheduled upgrade: {:?} at {}", a.result, a.at).to_lowercase()
                    }
                    None => "no scheduled upgrade yet".into(),
                },
            ),
        })
    }

    fn checks(&self) -> Vec<Check> {
        self.check().into_iter().collect()
    }

    /// The outcome of an attempt that was running when the daemon
    /// stopped, now that it runs again: the node moved to another image
    /// (the upgrade rebooted it into the new one), or it did not.
    fn settle(&mut self, booted: Option<&str>, now: &str) -> Option<Attempt> {
        let a = self
            .last
            .as_ref()
            .filter(|a| a.result == Result_::Started)?;
        let moved = match (a.from_image.as_deref(), booted) {
            (Some(f), Some(b)) => digest(f) != digest(b),
            // Not known yet: decide later.
            _ => return None,
        };
        let done = Attempt {
            at: now.to_string(),
            result: if moved {
                Result_::Succeeded
            } else {
                Result_::Failed
            },
            detail: if moved {
                format!("now running {}", booted.unwrap_or_default())
            } else {
                "the node restarted during the upgrade and still runs the image it started from"
                    .into()
            },
            ..a.clone()
        };
        if !moved {
            self.blocking = Some(done.clone());
        }
        self.last = Some(done.clone());
        Some(done)
    }
}

fn digest(image: &str) -> &str {
    image.rsplit_once('@').map_or(image, |(_, d)| d)
}

/// What the preconditions look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// `standalone`, `MASTER`, `BACKUP`, …
    pub role: String,
    /// `standalone`, or the pair's sync state (`in-sync`, …).
    pub sync: String,
    pub held: bool,
    pub pending: bool,
    pub health: String,
}

/// Why this window is skipped, or `None` to go ahead. `Err` means this
/// node is not the one to run it (a backup): nothing worth recording.
pub fn precondition(f: &Facts, blocking: Option<&Attempt>) -> Result<Option<String>, ()> {
    if f.role != "standalone" && f.role != "MASTER" {
        return Err(());
    }
    Ok(if let Some(b) = blocking {
        Some(format!(
            "the scheduled upgrade at {} failed and is not acknowledged (sparewall health ack upgrade)",
            b.at
        ))
    } else if f.pending {
        Some("a change waits for confirmation".into())
    } else if f.held {
        Some("the pair is held (cluster.hold)".into())
    } else if f.role == "MASTER" && f.sync != "in-sync" {
        Some(format!("the pair is not in sync ({})", f.sync))
    } else if f.health != "ok" {
        Some(format!("health is {}, not ok", f.health))
    } else {
        None
    })
}

/// Parse `systemd-analyze calendar` output: the next elapse, in UTC.
pub fn parse_next(out: &str) -> Option<jiff::Timestamp> {
    let line = out
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("(in UTC):"))
        .or_else(|| {
            // A node whose zone is UTC prints only the next elapse.
            out.lines()
                .map(str::trim)
                .find_map(|l| l.strip_prefix("Next elapse:"))
                .filter(|l| l.trim_end().ends_with(" UTC"))
        })?
        .trim();
    // "Sun 2026-11-08 09:00:00 UTC"
    let civil = line
        .split_whitespace()
        .skip(1)
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let dt: jiff::civil::DateTime = civil.parse().ok()?;
    dt.to_zoned(jiff::tz::TimeZone::UTC)
        .ok()
        .map(|z| z.timestamp())
}

/// The first time `expr` elapses after `base`.
fn next_after(expr: &str, base: jiff::Timestamp) -> Result<Option<jiff::Timestamp>, String> {
    let out = crate::upgrade::host_run(
        "systemd-analyze",
        &[
            "calendar",
            "--iterations=1",
            &format!("--base-time=@{}", base.as_second()),
            expr,
        ],
    )?;
    Ok(parse_next(&out))
}

/// When the window that contains `now` opened, if one does: the first
/// elapse after `now - minutes`, if it is not after `now`.
fn open_window(
    expr: &str,
    minutes: u32,
    now: jiff::Timestamp,
) -> Result<Option<jiff::Timestamp>, String> {
    let base = now - jiff::SignedDuration::from_mins(i64::from(minutes));
    Ok(next_after(expr, base)?.filter(|t| *t <= now))
}

/// Whether a window that closes at `closes` is still open at `now`.
fn still_open(closes: jiff::Timestamp, now: jiff::Timestamp) -> bool {
    now < closes
}

/// When the next window opens, for `sparewall upgrade --check`.
pub fn next_window(expr: &str) -> Option<String> {
    next_after(expr, jiff::Timestamp::now())
        .ok()
        .flatten()
        .map(|t| t.to_string())
}

fn log(a: &Attempt) {
    let m = match a.result {
        Result_::Skipped => format!("scheduled upgrade skipped: {}", a.detail),
        Result_::Started => format!("scheduled upgrade started: {}", a.detail),
        Result_::Succeeded => format!("scheduled upgrade succeeded: {}", a.detail),
        Result_::Failed => format!("scheduled upgrade failed: {}", a.detail),
    };
    if a.result == Result_::Failed {
        tracing::warn!(target: JOURNAL_TARGET, message_id = MESSAGE_ATTEMPT, "{m}");
    } else {
        tracing::info!(target: JOURNAL_TARGET, message_id = MESSAGE_ATTEMPT, "{m}");
    }
}

/// Record an attempt (and a failure as blocking), log it, and update
/// health.
async fn record(core: &Core, events: &broadcast::Sender<Value>, a: Attempt) {
    log(&a);
    let _ = events.send(json!({"type": "scheduled-upgrade", "attempt": a}));
    let _ = with_core_raw(core, events, move |c| {
        let root = c.store().root().to_path_buf();
        let mut r = Record::read(&root);
        if a.result == Result_::Failed {
            r.blocking = Some(a.clone());
        }
        r.last = Some(a);
        if let Err(e) = r.write(&root) {
            tracing::warn!(error = %e, "cannot record the scheduled upgrade");
        }
        c.set_named_checks(CHECK, r.checks());
        Ok(())
    })
    .await;
}

/// Clear a blocking failure: acknowledged, or an upgrade started by hand.
pub async fn unblock(
    core: &Core,
    events: &broadcast::Sender<Value>,
    by: &str,
) -> Result<bool, FirewallError> {
    let by = by.to_string();
    with_core(core, events, move |c| {
        let root = c.store().root().to_path_buf();
        let mut r = Record::read(&root);
        let Some(b) = r.blocking.take() else {
            return Ok(false);
        };
        tracing::info!(by = %by, failed_at = %b.at, "scheduled upgrades unblocked");
        r.write(&root)
            .map_err(|e| sparewall_core::Error::io(&root, e))?;
        c.set_named_checks(CHECK, r.checks());
        Ok(true)
    })
    .await
}

/// The `upgrade` lines of `/metrics`.
pub fn metrics(root: &Path) -> String {
    let r = Record::read(root);
    let Some(a) = &r.last else {
        return String::new();
    };
    let mut o = String::new();
    if let Ok(t) = a.at.parse::<jiff::Timestamp>() {
        o.push_str(
            "# HELP sparewall_scheduled_upgrade_last_attempt_timestamp_seconds When the last scheduled upgrade attempt was decided or ended.\n\
             # TYPE sparewall_scheduled_upgrade_last_attempt_timestamp_seconds gauge\n",
        );
        o.push_str(&format!(
            "sparewall_scheduled_upgrade_last_attempt_timestamp_seconds {}\n",
            t.as_second()
        ));
    }
    o.push_str(
        "# HELP sparewall_scheduled_upgrade_last_result The last scheduled upgrade attempt's result (skipped, started, succeeded, failed).\n\
         # TYPE sparewall_scheduled_upgrade_last_result gauge\n",
    );
    for res in ["skipped", "started", "succeeded", "failed"] {
        let is = serde_json::to_value(a.result)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string));
        o.push_str(&format!(
            "sparewall_scheduled_upgrade_last_result{{result=\"{res}\"}} {}\n",
            u8::from(is.as_deref() == Some(res))
        ));
    }
    o.push_str(
        "# HELP sparewall_scheduled_upgrade_blocked 1 while a failed scheduled upgrade waits to be acknowledged.\n\
         # TYPE sparewall_scheduled_upgrade_blocked gauge\n",
    );
    o.push_str(&format!(
        "sparewall_scheduled_upgrade_blocked {}\n",
        u8::from(r.blocking.is_some())
    ));
    o
}

/// The windowed mode's settings, if it is on.
fn windowed(
    c: &mut sparewall_core::Coordinator<Box<dyn sparewall_core::System>>,
) -> Option<(String, u32)> {
    let u = c.active_document().ok()??.updates?;
    if u.mode != Some(sparewall_config::model::UpdateMode::Windowed) {
        return None;
    }
    Some((u.window?, u.window_minutes.unwrap_or(DEFAULT_MINUTES)))
}

/// Watch for windows, and run each once.
pub async fn schedule_loop(core: Core, events: broadcast::Sender<Value>, pair: Pair) {
    // Health and the outcome of an attempt that rebooted this node.
    let _ = with_core_raw(&core, &events, |c| {
        let root = c.store().root().to_path_buf();
        let r = Record::read(&root);
        c.set_named_checks(CHECK, r.checks());
        Ok(())
    })
    .await;
    let mut settled = false;
    let mut tried: Option<String> = None;
    loop {
        if !settled {
            // The booted image is looked up during boot; wait for it.
            if let Some(booted) = booted_image_digest() {
                settled = true;
                let now = jiff::Timestamp::now().to_string();
                let done = with_core_raw(&core, &events, move |c| {
                    let root = c.store().root().to_path_buf();
                    let mut r = Record::read(&root);
                    let done = r.settle(Some(&booted), &now);
                    if done.is_some() {
                        r.write(&root)
                            .map_err(|e| sparewall_core::Error::io(&root, e))?;
                        c.set_named_checks(CHECK, r.checks());
                    }
                    Ok(done)
                })
                .await;
                if let Ok(Some(a)) = done {
                    log(&a);
                }
            }
        }
        // Nothing starts before the booted image is known: an attempt
        // records it, to tell after the reboot whether the node moved.
        if !settled {
            tokio::time::sleep(POLL).await;
            continue;
        }
        if let Err(e) = tick(&core, &events, &pair, &mut tried).await {
            tracing::warn!(error = %e, "scheduled upgrades");
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn tick(
    core: &Core,
    events: &broadcast::Sender<Value>,
    pair: &Pair,
    tried: &mut Option<String>,
) -> Result<(), String> {
    let Ok(Some((expr, minutes))) = with_core_raw(core, events, |c| Ok(windowed(c))).await else {
        return Ok(());
    };
    let now = jiff::Timestamp::now();
    let e = expr.clone();
    let open = tokio::task::spawn_blocking(move || open_window(&e, minutes, now))
        .await
        .map_err(|e| e.to_string())??;
    let Some(opened) = open else { return Ok(()) };
    let window = opened.to_string();
    if tried.as_deref() == Some(window.as_str()) {
        return Ok(());
    }
    // Tried before a restart?
    let (kept, facts) = {
        let p = pair.lock().unwrap_or_else(|p| p.into_inner()).clone();
        with_core_raw(core, events, move |c| {
            let r = Record::read(c.store().root());
            let held = c.active_document()?.is_some_and(|d| d.cluster.hold);
            let s = status(c, &p)?;
            Ok((
                r,
                Facts {
                    role: s.role.clone(),
                    sync: s.sync["state"].as_str().unwrap_or("unknown").to_string(),
                    held,
                    pending: !s.sync["pending"].is_null(),
                    health: s.health["level"].as_str().unwrap_or("unknown").to_string(),
                },
            ))
        })
        .await
        .map_err(|e| e.to_string())?
    };
    *tried = Some(window.clone());
    if kept.last.as_ref().is_some_and(|a| a.window == window) {
        return Ok(());
    }
    let at = jiff::Timestamp::now().to_string();
    let skipped = |detail: String| Attempt {
        window: window.clone(),
        at: at.clone(),
        result: Result_::Skipped,
        detail,
        from_image: None,
    };
    match precondition(&facts, kept.blocking.as_ref()) {
        Err(()) => return Ok(()),
        Ok(Some(why)) => {
            record(core, events, skipped(why)).await;
            return Ok(());
        }
        Ok(None) => {}
    }
    // Anything to install? The same comparison as `upgrade --check`.
    let channel = with_core_raw(core, events, |c| {
        Ok(c.active_document()?
            .and_then(|d| d.updates)
            .and_then(|u| u.channel))
    })
    .await
    .map_err(|e| e.to_string())?;
    let found = tokio::task::spawn_blocking(move || {
        let tracked = crate::upgrade::tracked_ref();
        let target = crate::upgrade::target_ref(None, None, channel.as_deref(), tracked.as_deref());
        crate::update::check(&target).map(|(k, r)| (target, k, r))
    })
    .await
    .map_err(|e| e.to_string())?;
    let (target, remote) = match found {
        Err(e) => {
            record(
                core,
                events,
                skipped(format!("cannot check the channel: {e}")),
            )
            .await;
            return Ok(());
        }
        Ok((_, Kind::None, _)) => {
            record(core, events, skipped("nothing newer on the channel".into())).await;
            return Ok(());
        }
        Ok((t, _, r)) => (t, r),
    };
    // The check may have taken a while (skopeo waits up to two minutes):
    // never start after the window has closed.
    let closes = opened + jiff::SignedDuration::from_mins(i64::from(minutes));
    if !still_open(closes, jiff::Timestamp::now()) {
        record(
            core,
            events,
            skipped(format!(
                "the window closed at {closes} while the channel was checked"
            )),
        )
        .await;
        return Ok(());
    }
    // One started by hand (or another window's) is not this one's
    // failure: skip, rather than block the next windows.
    if crate::upgrade::running() {
        record(
            core,
            events,
            skipped("an upgrade is already running".into()),
        )
        .await;
        return Ok(());
    }
    let Some(from_image) = booted_image_digest() else {
        record(
            core,
            events,
            skipped("the booted image is not known yet".into()),
        )
        .await;
        return Ok(());
    };
    let from_image = Some(from_image);
    // Follow this run's events from before it starts.
    let mut rx = events.subscribe();
    let plan = crate::upgrade::start(core, events, pair, None, None, false, false).await;
    match plan {
        Err(e) => {
            let a = Attempt {
                window: window.clone(),
                at: jiff::Timestamp::now().to_string(),
                result: Result_::Failed,
                detail: e,
                from_image,
            };
            record(core, events, a).await;
            return Ok(());
        }
        Ok(_) => {
            let version = remote.version.unwrap_or_else(|| "a new image".into());
            record(
                core,
                events,
                Attempt {
                    window: window.clone(),
                    at: jiff::Timestamp::now().to_string(),
                    result: Result_::Started,
                    detail: format!("to {version} ({target}), in the window opened at {window}"),
                    from_image: from_image.clone(),
                },
            )
            .await;
        }
    }
    // Until it ends here: done or failed are recorded now; a reboot is
    // settled by the next start (Record::settle).
    loop {
        let ev = match rx.recv().await {
            Ok(ev) => ev,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        };
        if ev["type"] != "upgrade" {
            continue;
        }
        let detail = ev["detail"].as_str().unwrap_or_default().to_string();
        let result = match ev["step"].as_str() {
            Some("done") => Result_::Succeeded,
            Some("failed") => Result_::Failed,
            Some("reboot") => return Ok(()),
            _ => continue,
        };
        record(
            core,
            events,
            Attempt {
                window,
                at: jiff::Timestamp::now().to_string(),
                result,
                detail,
                from_image,
            },
        )
        .await;
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(role: &str) -> Facts {
        Facts {
            role: role.into(),
            sync: if role == "standalone" {
                "standalone"
            } else {
                "in-sync"
            }
            .into(),
            held: false,
            pending: false,
            health: "ok".into(),
        }
    }

    fn attempt(result: Result_) -> Attempt {
        Attempt {
            window: "2026-11-08T09:00:00Z".into(),
            at: "2026-11-08T09:00:30Z".into(),
            result,
            detail: "x".into(),
            from_image: Some("reg/sw:stable@sha256:aaa".into()),
        }
    }

    #[test]
    fn preconditions() {
        assert_eq!(precondition(&facts("standalone"), None), Ok(None));
        assert_eq!(precondition(&facts("MASTER"), None), Ok(None));
        // The backup leaves it to the master, and says nothing.
        assert_eq!(precondition(&facts("BACKUP"), None), Err(()));
        assert_eq!(precondition(&facts("FAULT"), None), Err(()));
        let why = |f: Facts| precondition(&f, None).unwrap().unwrap();
        assert_eq!(
            why(Facts {
                pending: true,
                ..facts("standalone")
            }),
            "a change waits for confirmation"
        );
        assert_eq!(
            why(Facts {
                held: true,
                ..facts("MASTER")
            }),
            "the pair is held (cluster.hold)"
        );
        assert_eq!(
            why(Facts {
                sync: "peer-unreachable".into(),
                ..facts("MASTER")
            }),
            "the pair is not in sync (peer-unreachable)"
        );
        assert_eq!(
            why(Facts {
                health: "degraded".into(),
                ..facts("standalone")
            }),
            "health is degraded, not ok"
        );
        let blocked = precondition(&facts("MASTER"), Some(&attempt(Result_::Failed)))
            .unwrap()
            .unwrap();
        assert!(blocked.contains("not acknowledged"), "{blocked}");
    }

    #[test]
    fn a_window_closes_at_its_end() {
        let t = |s: &str| s.parse::<jiff::Timestamp>().unwrap();
        let closes = t("2026-11-08T09:01:00Z");
        assert!(still_open(closes, t("2026-11-08T09:00:59Z")));
        assert!(!still_open(closes, t("2026-11-08T09:01:00Z")));
        assert!(!still_open(closes, t("2026-11-08T09:03:00Z")));
    }

    #[test]
    fn calendar_output() {
        let other_zone = "  Original form: Sun *-*-* 03:00\n\
                          Normalized form: Sun *-*-* 03:00:00\n    \
                          Next elapse: Sun 2026-11-08 03:00:00 CST\n       \
                          (in UTC): Sun 2026-11-08 09:00:00 UTC\n       \
                          From now: 6 days left\n";
        assert_eq!(
            parse_next(other_zone).map(|t| t.to_string()).as_deref(),
            Some("2026-11-08T09:00:00Z")
        );
        let utc = "Normalized form: *-*-* 03:00:00\n    Next elapse: Mon 2026-11-02 03:00:00 UTC\n       From now: 2h left\n";
        assert_eq!(
            parse_next(utc).map(|t| t.to_string()).as_deref(),
            Some("2026-11-02T03:00:00Z")
        );
        assert_eq!(parse_next("Failed to parse calendar specification"), None);
    }

    #[test]
    fn a_reboot_settles_the_attempt() {
        let mut r = Record {
            last: Some(attempt(Result_::Started)),
            blocking: None,
        };
        // The booted image is not known yet: nothing decided.
        assert_eq!(r.settle(None, "t"), None);
        // Moved to another digest: it worked.
        let mut ok = r.clone();
        let a = ok.settle(Some("reg/sw:stable@sha256:bbb"), "t").unwrap();
        assert_eq!(a.result, Result_::Succeeded);
        assert_eq!(ok.blocking, None);
        // The same digest under another name did not move.
        let a = r.settle(Some("other/ref@sha256:aaa"), "t").unwrap();
        assert_eq!(a.result, Result_::Failed);
        assert_eq!(r.blocking.as_ref(), Some(&a));
        assert_eq!(r.check().unwrap().level, Level::Degraded);
        // Settled once.
        assert_eq!(r.settle(Some("x@sha256:ccc"), "t"), None);
    }

    #[test]
    fn health_and_metrics_follow_the_record() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(metrics(dir.path()), "");
        let r = Record {
            last: Some(attempt(Result_::Failed)),
            blocking: Some(attempt(Result_::Failed)),
        };
        r.write(dir.path()).unwrap();
        let m = metrics(dir.path());
        assert!(
            m.contains("sparewall_scheduled_upgrade_last_result{result=\"failed\"} 1\n"),
            "{m}"
        );
        assert!(
            m.contains("sparewall_scheduled_upgrade_last_result{result=\"succeeded\"} 0\n"),
            "{m}"
        );
        assert!(m.contains("sparewall_scheduled_upgrade_blocked 1\n"), "{m}");
        assert!(
            m.contains("sparewall_scheduled_upgrade_last_attempt_timestamp_seconds 1794128430\n"),
            "{m}"
        );
        let c = r.check().unwrap();
        assert_eq!(c.level, Level::Degraded);
        assert!(
            c.message.contains("sparewall health ack upgrade"),
            "{}",
            c.message
        );
        assert_eq!(Record::default().check(), None);
    }
}
