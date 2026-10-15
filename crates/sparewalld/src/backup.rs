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

fn credentials_env(text: &str) -> Result<Vec<(String, String)>, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l
                .split_once('=')
                .ok_or_else(|| "backup credentials are KEY=value lines".to_string())?;
            let k = k.trim().trim_start_matches("export ").trim();
            if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!("backup credentials: bad variable name {k:?}"));
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
) -> Result<BackupReply, FirewallError> {
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
                        credentials_env(&String::from_utf8_lossy(&v))
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
                Some((repo, c.node().to_string()))
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
    let snapshot = match upload {
        Some((repo, node)) => {
            let p = path.clone();
            match tokio::task::spawn_blocking(move || send(&repo, &p, &node)).await {
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

/// Keep the backup timer in line with `backup.schedule`.
pub async fn schedule_loop(core: Core, events: broadcast::Sender<Value>) {
    // Health reflects the last run from before a restart.
    let _ = with_core_raw(&core, &events, |c| {
        if let Some(last) = sparewall_core::backup::read_last(c.store().root()) {
            c.set_named_checks("backup", vec![check(&last)]);
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
            credentials_env("# s3\nAWS_ACCESS_KEY_ID=abc\nexport AWS_SECRET_ACCESS_KEY = x=y\n\n")
                .unwrap(),
            [
                ("AWS_ACCESS_KEY_ID".to_string(), "abc".to_string()),
                ("AWS_SECRET_ACCESS_KEY".to_string(), "x=y".to_string())
            ]
        );
        assert!(credentials_env("no equals sign").is_err());
        assert!(credentials_env("BAD-NAME=1").is_err());
    }

    use std::sync::Mutex;

    /// A repository whose operations fail as told; records the calls.
    #[derive(Default)]
    struct FakeRepo {
        exists: Option<Result<bool, String>>,
        init: Option<String>,
        backup: Option<String>,
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
