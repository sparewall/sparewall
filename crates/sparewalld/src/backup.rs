//! Backups off the node (design: "The bundle").
//!
//! `sparewall backup` (and the timer that runs it on `backup.schedule`)
//! writes a bundle and, when `backup.repository` is set, sends it with
//! restic. The repository password is the `backup-password` cluster
//! secret, which also seals the secrets inside the bundle; repository
//! credentials (S3 keys and the like) are `KEY=value` lines in the secret
//! `backup.credentials` names. The timer is a transient systemd timer,
//! recreated whenever the schedule changes and at every start.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;
use sparewall_api::{BackupReply, FirewallError};
use sparewall_core::backup::{PASSWORD_SECRET, Sources};
use sparewall_core::{Check, Level};
use tokio::sync::broadcast;

use crate::service::{Core, KEA_LEASES, booted_image_digest, with_core, with_core_raw};
use crate::upgrade::host_run;

const TIMER: &str = "sparewall-backup";
const DEFAULT_SCHEDULE: &str = "hourly";

/// Where and how to send a bundle.
struct Upload {
    repository: String,
    password: Vec<u8>,
    env: Vec<(String, String)>,
    node: String,
    cache: PathBuf,
}

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

/// Write a bundle and send it to the repository, if one is configured.
pub async fn run(
    core: &Core,
    events: &broadcast::Sender<Value>,
) -> Result<BackupReply, FirewallError> {
    let made = with_core(core, events, |c| {
        let cfg = c.active_document()?.and_then(|d| d.backup);
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
                Some(Upload {
                    repository: b.repository.clone().expect("matched"),
                    password,
                    env,
                    node: c.node().to_string(),
                    cache: c.store().root().join("restic-cache"),
                })
            }
            _ => None,
        };
        let src = Sources {
            leases: KEA_LEASES.into(),
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
        Some(u) => {
            let p = path.clone();
            match tokio::task::spawn_blocking(move || send(&u, &p)).await {
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

fn restic(u: &Upload, args: &[&str], stdin: Option<&Path>) -> Result<(i32, String), String> {
    let mut cmd = Command::new("restic");
    cmd.arg("--cache-dir")
        .arg(&u.cache)
        .args(args)
        .env("RESTIC_REPOSITORY", &u.repository)
        .env(
            "RESTIC_PASSWORD",
            String::from_utf8_lossy(&u.password).as_ref(),
        )
        .envs(u.env.iter().map(|(k, v)| (k, v)))
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("restic: {e}"))?;
    if let Some(p) = stdin {
        let data = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let mut w = child.stdin.take().expect("piped");
        // A writer thread, so a full stdout pipe cannot deadlock us.
        let t = std::thread::spawn(move || w.write_all(&data));
        let out = child
            .wait_with_output()
            .map_err(|e| format!("restic: {e}"))?;
        let _ = t.join();
        return Ok(outcome(out));
    }
    Ok(outcome(
        child
            .wait_with_output()
            .map_err(|e| format!("restic: {e}"))?,
    ))
}

fn outcome(out: std::process::Output) -> (i32, String) {
    let code = out.status.code().unwrap_or(-1);
    let text = if code == 0 { out.stdout } else { out.stderr };
    (code, String::from_utf8_lossy(&text).trim().to_string())
}

/// Send a bundle; returns the snapshot ID.
fn send(u: &Upload, bundle: &Path) -> Result<String, String> {
    // The repository does not exist yet: exit code 10 since restic 0.17,
    // only the message before.
    match restic(u, &["cat", "config"], None)? {
        (0, _) => {}
        (c, e) if c == 10 || e.contains("Is there a repository at the following location") => {
            tracing::info!(repository = %u.repository, "initialising the backup repository");
            match restic(u, &["init"], None)? {
                (0, _) => {}
                (_, e) => return Err(format!("restic init: {e}")),
            }
        }
        (_, e) => return Err(format!("restic: {e}")),
    }
    let name = format!("sparewall-{}.tar.gz", u.node);
    match restic(
        u,
        &[
            "backup",
            "--json",
            "--host",
            &u.node,
            "--tag",
            "sparewall",
            "--stdin",
            "--stdin-filename",
            &name,
        ],
        Some(bundle),
    )? {
        (0, out) => {
            let id = out
                .lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .find(|v| v["message_type"] == "summary")
                .and_then(|v| v["snapshot_id"].as_str().map(str::to_string))
                .unwrap_or_default();
            tracing::info!(snapshot = %id, repository = %u.repository, "sent the backup bundle");
            Ok(id)
        }
        (_, e) => Err(format!("restic backup: {e}")),
    }
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
            match tokio::task::spawn_blocking(move || set_timer(w.as_deref())).await {
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

fn set_timer(calendar: Option<&str>) -> Result<(), String> {
    let _ = host_run("systemctl", &["stop", &format!("{TIMER}.timer")]);
    let _ = host_run(
        "systemctl",
        &[
            "reset-failed",
            &format!("{TIMER}.timer"),
            &format!("{TIMER}.service"),
        ],
    );
    let Some(cal) = calendar else { return Ok(()) };
    host_run(
        "systemd-run",
        &[
            &format!("--unit={TIMER}"),
            "--description=Sparewall backup",
            &format!("--on-calendar={cal}"),
            "--timer-property=Persistent=yes",
            "--timer-property=RandomizedDelaySec=5min",
            "/usr/bin/sparewall",
            "backup",
            "--quiet",
        ],
    )
    .map(|_| ())
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
}
