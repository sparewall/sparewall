//! keepalived state changes, from its notify FIFO (design: "keepalived",
//! "conntrackd" and "Failover sequence").

use std::io::BufRead;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::peer::Pair;

/// conntrackd's configuration as rendered by the coordinator.
const CONNTRACKD_CONF: &str = "/run/sparewall/conntrackd/conntrackd.conf";

/// Parse a notify line: `GROUP SPAREWALL MASTER` or
/// `INSTANCE VI_users BACKUP 100`.
pub fn parse(line: &str) -> Option<(&str, &str, &str)> {
    let mut w = line.split_whitespace();
    let kind = w.next()?;
    let name = w.next()?;
    let state = w.next()?;
    matches!(kind, "GROUP" | "INSTANCE").then_some((kind, name, state))
}

/// The conntrackd commands for a new state (the standard primary-backup
/// sequence shipped with conntrack-tools).
pub fn conntrackd_steps(state: &str) -> &'static [&'static str] {
    match state {
        // Commit the external cache into the kernel, flush both caches,
        // resync with the kernel table, and send a bulk update.
        "MASTER" => &["-c", "-f", "-R", "-B"],
        // Ask the new master for a full resync.
        "BACKUP" => &["-n"],
        // Shorten kernel timers so stale entries go away.
        "FAULT" => &["-t"],
        _ => &[],
    }
}

fn run_conntrackd(state: &str) {
    if !Path::new(CONNTRACKD_CONF).exists() {
        return;
    }
    for step in conntrackd_steps(state) {
        match std::process::Command::new("conntrackd")
            .args(["-C", CONNTRACKD_CONF, step])
            .output()
        {
            Ok(o) if o.status.success() => {}
            Ok(o) => tracing::warn!(
                step,
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "conntrackd step failed"
            ),
            Err(e) => tracing::warn!(step, error = %e, "cannot run conntrackd"),
        }
    }
}

/// Read keepalived's FIFO forever, serializing transitions in one place.
pub async fn fifo_reader(pair: Pair, events: broadcast::Sender<Value>, path: PathBuf) {
    // The notify script writes into this FIFO (keepalived itself may not).
    if !path.exists() {
        let ok = std::process::Command::new("mkfifo")
            .args(["-m", "0600"])
            .arg(&path)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            tracing::error!(path = %path.display(), "cannot create keepalived FIFO");
            return std::future::pending().await;
        }
    }
    tracing::info!(path = %path.display(), "reading keepalived notifications");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        // Opened read-write so it never blocks waiting for a writer and
        // never sees end-of-file when keepalived restarts.
        let f = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, "cannot open keepalived FIFO");
                return;
            }
        };
        for line in std::io::BufReader::new(f).lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    while let Some(line) = rx.recv().await {
        let Some((kind, name, state)) = parse(&line) else {
            continue;
        };
        tracing::info!(kind, name, state, "keepalived transition");
        // The sync group moves every instance together; with a single
        // instance there is no group, only instance lines. Act once per
        // change of role.
        let changed = {
            let mut p = pair.lock().unwrap_or_else(|p| p.into_inner());
            let changed = p.role.as_deref() != Some(state);
            p.role = Some(state.to_string());
            changed
        };
        if changed {
            let _ = events.send(json!({"type": "vrrp", "source": name, "state": state}));
            let st = state.to_string();
            let _ = tokio::task::spawn_blocking(move || run_conntrackd(&st)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_notify_lines() {
        assert_eq!(
            parse("GROUP SPAREWALL MASTER"),
            Some(("GROUP", "SPAREWALL", "MASTER"))
        );
        assert_eq!(
            parse("INSTANCE VI_users BACKUP 100"),
            Some(("INSTANCE", "VI_users", "BACKUP"))
        );
        assert_eq!(parse("garbage"), None);
        assert_eq!(conntrackd_steps("MASTER"), ["-c", "-f", "-R", "-B"]);
    }
}
