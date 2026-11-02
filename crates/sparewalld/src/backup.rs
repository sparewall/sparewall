//! Backups off the node (design: "The bundle").
//!
//! `sparewall backup` (and the timer that runs it on `backup.schedule`)
//! writes a bundle and, when `backup.repository` is set, sends it with
//! restic. The repository password is the `backup-password` cluster
//! secret, which also seals the secrets inside the bundle; repository
//! credentials (S3 keys and the like) are `KEY=value` lines in the secret
//! `backup.credentials` names. The timer is a transient systemd timer,
//! recreated whenever the schedule changes and at every start.

use std::path::Path;
use std::time::Duration;

use serde_json::Value;
use sparewall_api::{BackupReply, FirewallError};
use sparewall_core::backup::{PASSWORD_SECRET, Sources};
use sparewall_core::host::{BackupRepository, Restic, SystemdTimers, TimerSpec, Timers};
use sparewall_core::{Check, Level};
use tokio::sync::broadcast;

use crate::service::{Core, booted_image_digest, with_core, with_core_raw};

const TIMER: &str = "sparewall-backup";
const DEFAULT_SCHEDULE: &str = "hourly";

/// `KEY=value` lines (blank lines and `#` comments skipped, `export`
/// allowed) as environment variables; `what` names them in errors.
pub(crate) fn credentials_env(what: &str, text: &str) -> Result<Vec<(String, String)>, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l
                .split_once('=')
                .ok_or_else(|| format!("{what} are KEY=value lines"))?;
            let k = k.trim().trim_start_matches("export ").trim();
            if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!("{what}: bad variable name {k:?}"));
            }
            Ok((k.to_string(), v.trim().to_string()))
        })
        .collect()
}

/// The lease file of the DHCP provider a document chooses, if it keeps
/// one the coordinator reads.
fn lease_file(doc: Option<&sparewall_config::Document>) -> Option<std::path::PathBuf> {
    use sparewall_config::providers::{Role, chosen, find};
    let name = chosen(doc?, Role::Dhcp)?;
    find(Role::Dhcp, name)?.state?.path.map(Into::into)
}

/// Write a bundle and send it to the repository, if one is configured.
pub async fn run(
    core: &Core,
    events: &broadcast::Sender<Value>,
    pair: &crate::peer::Pair,
) -> Result<BackupReply, FirewallError> {
    // One prune per pair is enough, and prune locks the repository: the
    // master's (or a standalone node's). The backup forgets without it.
    let prune = pair
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .role
        .as_deref()
        != Some("BACKUP");
    let made = with_core(core, events, |c| {
        let doc = c.active_document()?;
        let cfg = doc.as_ref().and_then(|d| d.backup.clone());
        let upload = match cfg.as_ref().filter(|b| b.enabled) {
            Some(b) if b.repository.is_some() => {
                let password = c.secret_get(PASSWORD_SECRET)?.ok_or_else(|| {
                    sparewall_core::Error::Validation(vec![format!(
                        "backup.repository needs the repository password: \
                         sparewall secret set {PASSWORD_SECRET}"
                    )])
                })?;
                let env = match &b.credentials {
                    Some(r) => {
                        let name = r.strip_prefix("secret:").unwrap_or(r);
                        let v = c.secret_get(name)?.ok_or_else(|| {
                            sparewall_core::Error::Validation(vec![format!(
                                "backup.credentials: no secret {name:?}"
                            )])
                        })?;
                        credentials_env("backup credentials", &String::from_utf8_lossy(&v))
                            .map_err(|e| sparewall_core::Error::Validation(vec![e]))?
                    }
                    None => vec![],
                };
                let repo = Restic {
                    repository: b.repository.clone().expect("matched"),
                    password,
                    env,
                    cache: c.store().root().join("restic-cache"),
                };
                let keep = b
                    .effective_retention()
                    .map(|r| r.keep_flags())
                    .filter(|k| !k.is_empty());
                Some((repo, c.node().to_string(), keep))
            }
            _ => None,
        };
        let src = Sources {
            leases: lease_file(doc.as_ref()),
            out_dir: c.store().root().join("backups"),
            image_digest: booted_image_digest(),
        };
        let keep = cfg
            .and_then(|b| b.generations)
            .map_or(sparewall_core::backup::DEFAULT_GENERATIONS, |g| g as usize);
        let (path, digest) = c.backup(&src, keep)?;
        let secrets = sparewall_core::backup::manifest(&path)?.secrets;
        Ok((path, digest, secrets, upload))
    })
    .await;
    let (path, digest, secrets, upload) = match made {
        Ok(m) => m,
        Err(e) => {
            finish(core, events, None, None, Some(format!("{e:?}"))).await;
            return Err(e);
        }
    };
    let mut retained = None;
    let snapshot = match upload {
        Some((repo, node, keep)) => {
            let p = path.clone();
            let sent = tokio::task::spawn_blocking(move || {
                let id = send(&repo, &p, &node)?;
                // Only after a send that worked, and never failing it.
                let kept = keep.map(|k| retain(&repo, &node, &k, prune));
                Ok::<_, String>((id, kept))
            })
            .await
            .map(|r| {
                r.map(|(id, kept)| {
                    retained = kept;
                    id
                })
            });
            match sent {
                Ok(Ok(id)) => Some(id),
                Ok(Err(e)) => {
                    finish(core, events, Some(&path), None, Some(e.clone())).await;
                    return Err(FirewallError::ApplyFailed {
                        message: format!(
                            "the bundle {} was written but not sent: {e}",
                            path.display()
                        ),
                    });
                }
                Err(e) => {
                    let e = e.to_string();
                    finish(core, events, Some(&path), None, Some(e.clone())).await;
                    return Err(FirewallError::ApplyFailed { message: e });
                }
            }
        }
        None => None,
    };
    finish(core, events, Some(&path), snapshot.clone(), None).await;
    if let Some(r) = retained {
        record_retention(core, events, r).await;
    }
    Ok(BackupReply {
        path: path.display().to_string(),
        digest,
        snapshot,
        secrets,
    })
}

/// Record the run and report it in health.
async fn finish(
    core: &Core,
    events: &broadcast::Sender<Value>,
    bundle: Option<&Path>,
    snapshot: Option<String>,
    error: Option<String>,
) {
    let bundle = bundle.map(Path::to_path_buf);
    let _ = with_core_raw(core, events, move |c| {
        let last =
            sparewall_core::backup::record(c.store().root(), bundle.as_deref(), snapshot, error)?;
        c.set_named_checks("backup", vec![check(&last)]);
        Ok(())
    })
    .await;
}

fn check(last: &sparewall_core::backup::Last) -> Check {
    match &last.error {
        Some(e) => Check::new(
            "backup",
            Level::Degraded,
            format!("the last backup failed: {e}"),
        ),
        None => Check::new("backup", Level::Ok, format!("last backup {}", last.time)),
    }
}

/// Send a bundle, initialising the repository on first use; returns the
/// snapshot ID.
fn send(repo: &dyn BackupRepository, bundle: &Path, node: &str) -> Result<String, String> {
    if !repo.exists()? {
        tracing::info!("initialising the backup repository");
        repo.init()?;
    }
    let id = repo.backup(bundle, &format!("sparewall-{node}.tar.gz"), node)?;
    tracing::info!(snapshot = %id, "sent the backup bundle");
    Ok(id)
}

/// Apply the retention rules to this node's own snapshots.
fn retain(
    repo: &dyn BackupRepository,
    node: &str,
    keep: &[String],
    prune: bool,
) -> Result<Retained, String> {
    let removed = repo.forget(node, keep, prune)?;
    tracing::info!(removed, prune, "applied the backup retention");
    Ok(Retained {
        removed,
        pruned: prune,
    })
}

/// What a retention run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retained {
    pub removed: usize,
    pub pruned: bool,
}

const RETENTION_CHECK: &str = "backup-retention";
const RETENTION_FILE: &str = "retention.json";

/// The last retention run, kept beside the backup record.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RetentionRecord {
    pub time: String,
    pub error: Option<String>,
    /// The last run that worked.
    pub success: Option<String>,
}

fn retention_path(root: &Path) -> std::path::PathBuf {
    root.join("backups").join(RETENTION_FILE)
}

pub fn read_retention(root: &Path) -> Option<RetentionRecord> {
    serde_json::from_slice(&std::fs::read(retention_path(root)).ok()?).ok()
}

fn retention_check(r: &RetentionRecord) -> Check {
    match &r.error {
        // The snapshot is in the repository; only pruning stopped.
        Some(e) => Check::new(
            RETENTION_CHECK,
            Level::Degraded,
            format!(
                "the backup was sent, but the repository's old snapshots were not removed: {e}"
            ),
        ),
        None => Check::new(
            RETENTION_CHECK,
            Level::Ok,
            format!("retention applied {}", r.time),
        ),
    }
}

async fn record_retention(
    core: &Core,
    events: &broadcast::Sender<Value>,
    r: Result<Retained, String>,
) {
    let _ = with_core_raw(core, events, move |c| {
        let root = c.store().root().to_path_buf();
        let now = jiff::Timestamp::now().to_string();
        let prev = read_retention(&root).unwrap_or_default();
        let rec = match &r {
            Ok(_) => RetentionRecord {
                time: now.clone(),
                error: None,
                success: Some(now),
            },
            Err(e) => {
                tracing::warn!(error = %e, "backup retention failed");
                RetentionRecord {
                    time: now,
                    error: Some(e.clone()),
                    success: prev.success,
                }
            }
        };
        let p = retention_path(&root);
        if let Err(e) =
            sparewall_core::store::write_atomic(&p, &serde_json::to_vec(&rec).expect("json"))
        {
            tracing::warn!(error = %e, "cannot record the backup retention");
        }
        c.set_named_checks(RETENTION_CHECK, vec![retention_check(&rec)]);
        Ok(())
    })
    .await;
}

/// The retention's line of `/metrics`.
pub fn metrics(root: &Path) -> String {
    let Some(t) = read_retention(root)
        .and_then(|r| r.success)
        .and_then(|t| t.parse::<jiff::Timestamp>().ok())
    else {
        return String::new();
    };
    format!(
        "# HELP sparewall_backup_retention_last_success_timestamp_seconds When the repository's retention last ran without error.\n\
         # TYPE sparewall_backup_retention_last_success_timestamp_seconds gauge\n\
         sparewall_backup_retention_last_success_timestamp_seconds {}\n",
        t.as_second()
    )
}

/// Keep the backup timer in line with `backup.schedule`.
pub async fn schedule_loop(core: Core, events: broadcast::Sender<Value>) {
    // Health reflects the last run from before a restart.
    let _ = with_core_raw(&core, &events, |c| {
        if let Some(last) = sparewall_core::backup::read_last(c.store().root()) {
            c.set_named_checks("backup", vec![check(&last)]);
        }
        if let Some(r) = read_retention(c.store().root()) {
            c.set_named_checks(RETENTION_CHECK, vec![retention_check(&r)]);
        }
        Ok(())
    })
    .await;
    let mut current: Option<Option<String>> = None;
    loop {
        let want = with_core_raw(&core, &events, |c| {
            Ok(c.active_document()?
                .and_then(|d| d.backup)
                .filter(|b| b.enabled)
                .map(|b| b.schedule.unwrap_or_else(|| DEFAULT_SCHEDULE.into())))
        })
        .await;
        if let Ok(want) = want
            && current.as_ref() != Some(&want)
        {
            let w = want.clone();
            match tokio::task::spawn_blocking(move || set_timer(&SystemdTimers, w.as_deref())).await
            {
                Ok(Ok(())) => {
                    tracing::info!(schedule = ?want, "backup timer");
                    current = Some(want);
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "cannot set the backup timer");
                    let _ = with_core_raw(&core, &events, move |c| {
                        c.set_named_checks(
                            "backup-timer",
                            vec![Check::new(
                                "backup",
                                Level::Degraded,
                                format!("backup timer: {e}"),
                            )],
                        );
                        Ok(())
                    })
                    .await;
                    // Do not retry a bad schedule every minute.
                    current = Some(want);
                }
                Err(_) => {}
            }
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// Replace the backup timer with one on `calendar`, or none.
fn set_timer(timers: &dyn Timers, calendar: Option<&str>) -> Result<(), String> {
    timers
        .remove(TIMER)
        .map_err(|e| format!("cannot remove the old timer: {e}"))?;
    let Some(cal) = calendar else { return Ok(()) };
    timers.create(&TimerSpec {
        unit: TIMER.into(),
        description: "Sparewall backup".into(),
        calendar: cal.into(),
        command: ["/usr/bin/sparewall", "backup", "--quiet"]
            .map(String::from)
            .to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials() {
        assert_eq!(
            credentials_env(
                "backup credentials",
                "# s3\nAWS_ACCESS_KEY_ID=abc\nexport AWS_SECRET_ACCESS_KEY = x=y\n\n"
            )
            .unwrap(),
            [
                ("AWS_ACCESS_KEY_ID".to_string(), "abc".to_string()),
                ("AWS_SECRET_ACCESS_KEY".to_string(), "x=y".to_string())
            ]
        );
        assert!(credentials_env("c", "no equals sign").is_err());
        assert!(credentials_env("c", "BAD-NAME=1").is_err());
    }

    use std::sync::Mutex;

    /// A repository whose operations fail as told; records the calls.
    #[derive(Default)]
    struct FakeRepo {
        exists: Option<Result<bool, String>>,
        init: Option<String>,
        backup: Option<String>,
        forget: Option<String>,
        calls: Mutex<Vec<String>>,
    }

    impl BackupRepository for FakeRepo {
        fn exists(&self) -> Result<bool, String> {
            self.calls.lock().unwrap().push("exists".into());
            self.exists.clone().unwrap_or(Ok(true))
        }
        fn init(&self) -> Result<(), String> {
            self.calls.lock().unwrap().push("init".into());
            self.init.clone().map_or(Ok(()), Err)
        }
        fn backup(&self, bundle: &Path, name: &str, host: &str) -> Result<String, String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("backup {} {name} {host}", bundle.display()));
            self.backup.clone().map_or(Ok("snap1".into()), Err)
        }
        fn forget(&self, host: &str, keep: &[String], prune: bool) -> Result<usize, String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("forget {host} {} prune={prune}", keep.join(" ")));
            self.forget.clone().map_or(Ok(3), Err)
        }
    }

    /// #140: retention forgets this node's own snapshots with the keep
    /// rules, prunes only where asked, and its failure is its own.
    #[test]
    fn retention() {
        let keep = ["--keep-daily=7".to_string()];
        let r = FakeRepo::default();
        assert_eq!(
            retain(&r, "fw1", &keep, true),
            Ok(Retained {
                removed: 3,
                pruned: true
            })
        );
        assert_eq!(
            *r.calls.lock().unwrap(),
            ["forget fw1 --keep-daily=7 prune=true"]
        );
        let r = FakeRepo::default();
        retain(&r, "fw2", &keep, false).unwrap();
        assert_eq!(
            *r.calls.lock().unwrap(),
            ["forget fw2 --keep-daily=7 prune=false"]
        );
        let r = FakeRepo {
            forget: Some("restic forget: repository is already locked".into()),
            ..Default::default()
        };
        let e = retain(&r, "fw1", &keep, true).unwrap_err();
        let c = retention_check(&RetentionRecord {
            time: "t2".into(),
            error: Some(e),
            success: Some("t1".into()),
        });
        assert_eq!(c.level, Level::Degraded);
        assert!(
            c.message.starts_with("the backup was sent, but"),
            "{}",
            c.message
        );
        assert_eq!(
            retention_check(&RetentionRecord {
                time: "t".into(),
                error: None,
                success: Some("t".into())
            })
            .level,
            Level::Ok
        );
    }

    #[test]
    fn retention_metric_follows_the_last_success() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(metrics(dir.path()), "");
        std::fs::create_dir_all(dir.path().join("backups")).unwrap();
        std::fs::write(
            retention_path(dir.path()),
            r#"{"time":"2026-11-02T01:00:00Z","error":"locked","success":"2026-11-01T00:00:00Z"}"#,
        )
        .unwrap();
        assert!(
            metrics(dir.path())
                .contains("sparewall_backup_retention_last_success_timestamp_seconds 1793491200\n")
        );
    }

    /// #12: each restic failure stops the send with its own error, and a
    /// new repository is initialised once before the first backup.
    #[test]
    fn backup_send_failures() {
        let b = Path::new("/b.tar.gz");
        let calls = |r: &FakeRepo| r.calls.lock().unwrap().clone();
        let r = FakeRepo::default();
        assert_eq!(send(&r, b, "fw1"), Ok("snap1".into()));
        assert_eq!(
            calls(&r),
            ["exists", "backup /b.tar.gz sparewall-fw1.tar.gz fw1"]
        );

        let r = FakeRepo {
            exists: Some(Ok(false)),
            ..Default::default()
        };
        assert_eq!(send(&r, b, "fw1"), Ok("snap1".into()));
        assert_eq!(calls(&r)[..2], ["exists", "init"]);

        let r = FakeRepo {
            exists: Some(Err("restic: wrong password".into())),
            ..Default::default()
        };
        assert_eq!(send(&r, b, "fw1"), Err("restic: wrong password".into()));
        assert_eq!(calls(&r), ["exists"]);

        let r = FakeRepo {
            exists: Some(Ok(false)),
            init: Some("restic init: no space".into()),
            ..Default::default()
        };
        assert_eq!(send(&r, b, "fw1"), Err("restic init: no space".into()));
        assert_eq!(calls(&r), ["exists", "init"]);

        let r = FakeRepo {
            backup: Some("restic backup: timeout".into()),
            ..Default::default()
        };
        assert_eq!(send(&r, b, "fw1"), Err("restic backup: timeout".into()));

        // A failed run is reported in health as degraded, naming the error.
        let c = check(&sparewall_core::backup::Last {
            time: "t".into(),
            bundle: None,
            snapshot: None,
            error: Some("restic backup: timeout".into()),
            success: None,
        });
        assert_eq!(c.level, Level::Degraded);
        assert!(
            c.message.contains("restic backup: timeout"),
            "{}",
            c.message
        );
    }

    #[derive(Default)]
    struct FakeTimers {
        fail: Option<String>,
        remove_fails: Option<String>,
        calls: Mutex<Vec<String>>,
    }

    impl Timers for FakeTimers {
        fn remove(&self, unit: &str) -> Result<(), String> {
            self.calls.lock().unwrap().push(format!("remove {unit}"));
            self.remove_fails.clone().map_or(Ok(()), Err)
        }
        fn create(&self, t: &TimerSpec) -> Result<(), String> {
            self.calls.lock().unwrap().push(format!(
                "create {} {} {}",
                t.unit,
                t.calendar,
                t.command.join(" ")
            ));
            self.fail.clone().map_or(Ok(()), Err)
        }
    }

    /// The timer is replaced, removed when backups are off, and a bad
    /// schedule's error is returned.
    #[test]
    fn backup_timer() {
        let t = FakeTimers::default();
        set_timer(&t, Some("daily")).unwrap();
        set_timer(&t, None).unwrap();
        assert_eq!(
            *t.calls.lock().unwrap(),
            [
                "remove sparewall-backup",
                "create sparewall-backup daily /usr/bin/sparewall backup --quiet",
                "remove sparewall-backup",
            ]
        );
        let t = FakeTimers {
            fail: Some("bad calendar".into()),
            ..Default::default()
        };
        assert_eq!(set_timer(&t, Some("never")), Err("bad calendar".into()));

        // The old timer cannot be stopped: reported, nothing new created
        // (also when turning backups off).
        let t = FakeTimers {
            remove_fails: Some("Access denied".into()),
            ..Default::default()
        };
        for cal in [Some("daily"), None] {
            assert_eq!(
                set_timer(&t, cal),
                Err("cannot remove the old timer: Access denied".into())
            );
        }
        assert!(
            t.calls
                .lock()
                .unwrap()
                .iter()
                .all(|c| c.starts_with("remove"))
        );
    }
}
