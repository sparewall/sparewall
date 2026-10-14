//! keepalived state changes, from its notify FIFO (design: "keepalived",
//! "conntrackd" and "Failover sequence").

use std::io::BufRead;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use sparewall_core::host::{ConntrackStep, Conntrackd, HostConntrackd};
use tokio::sync::broadcast;

use crate::peer::Pair;

/// conntrackd's configuration as rendered by the coordinator.
const CONNTRACKD_CONF: &str = "/run/sparewall/conntrackd/conntrackd.conf";

/// conntrackd on this host.
pub fn host_conntrackd() -> Arc<dyn Conntrackd> {
    Arc::new(HostConntrackd {
        conf: CONNTRACKD_CONF.into(),
    })
}

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
pub fn conntrackd_steps(state: &str) -> &'static [ConntrackStep] {
    use ConntrackStep::*;
    match state {
        // Commit the external cache into the kernel, flush both caches,
        // resync with the kernel table, and send a bulk update.
        "MASTER" => &[Commit, Flush, Resync, BulkSend],
        // Ask the new master for a full resync.
        "BACKUP" => &[RequestResync],
        // Shorten kernel timers so stale entries go away.
        "FAULT" => &[ShortenTimers],
        _ => &[],
    }
}

/// Run the steps for `state`. Like conntrack-tools' script, a failed
/// step does not stop the ones after it: on becoming master, committing
/// the peer's state may fail, but this node must still resync with its
/// own kernel table and advertise it. Returns the failed steps.
pub fn conntrackd_transition(c: &dyn Conntrackd, state: &str) -> Vec<(ConntrackStep, String)> {
    if !c.configured() {
        return vec![];
    }
    let mut failed = Vec::new();
    for &step in conntrackd_steps(state) {
        if let Err(e) = c.run(step) {
            tracing::warn!(step = step.flag(), error = %e, "conntrackd step failed");
            failed.push((step, e));
        }
    }
    failed
}

/// Read keepalived's FIFO forever, serializing transitions in one place.
pub async fn fifo_reader(
    pair: Pair,
    events: broadcast::Sender<Value>,
    path: PathBuf,
    conntrackd: Arc<dyn Conntrackd>,
) {
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
    let tx_state = tx.clone();
    let state_file = path.with_file_name("keepalived.state");
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
    // A transition the FIFO missed is in the state file the notify script
    // also writes; read it now and every few seconds.
    let tx2 = tx_state;
    tokio::spawn(async move {
        let mut last = String::new();
        loop {
            if let Ok(s) = std::fs::read_to_string(&state_file)
                && s != last
            {
                last = s.clone();
                if tx2.send(s.trim().to_string()).is_err() {
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
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
            let (st, c) = (state.to_string(), conntrackd.clone());
            if let Ok(failed) =
                tokio::task::spawn_blocking(move || conntrackd_transition(&*c, &st)).await
                && !failed.is_empty()
            {
                let failed: Vec<Value> = failed
                    .iter()
                    .map(|(s, e)| json!({"step": s.flag(), "error": e}))
                    .collect();
                let _ =
                    events.send(json!({"type": "conntrackd", "state": state, "failed": failed}));
            }
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
    }

    /// Records the steps run and fails the ones listed.
    struct FakeConntrackd {
        configured: bool,
        fail: Vec<ConntrackStep>,
        ran: std::sync::Mutex<Vec<ConntrackStep>>,
    }

    impl Conntrackd for FakeConntrackd {
        fn configured(&self) -> bool {
            self.configured
        }
        fn run(&self, step: ConntrackStep) -> Result<(), String> {
            self.ran.lock().unwrap().push(step);
            if self.fail.contains(&step) {
                Err(format!("{} failed", step.flag()))
            } else {
                Ok(())
            }
        }
    }

    fn fake(configured: bool, fail: &[ConntrackStep]) -> FakeConntrackd {
        FakeConntrackd {
            configured,
            fail: fail.to_vec(),
            ran: Default::default(),
        }
    }

    /// #12: a failed conntrackd step is reported, and the steps after it
    /// still run, so a new master resyncs with its own table even if it
    /// could not commit the peer's.
    #[test]
    fn conntrackd_steps_continue_past_a_failure() {
        use ConntrackStep::*;
        let c = fake(true, &[Commit]);
        let failed = conntrackd_transition(&c, "MASTER");
        assert_eq!(*c.ran.lock().unwrap(), [Commit, Flush, Resync, BulkSend]);
        assert_eq!(failed, [(Commit, "-c failed".to_string())]);

        let c = fake(true, &[Flush, BulkSend]);
        let failed: Vec<_> = conntrackd_transition(&c, "MASTER")
            .into_iter()
            .map(|(s, _)| s)
            .collect();
        assert_eq!(failed, [Flush, BulkSend]);

        let c = fake(true, &[]);
        assert!(conntrackd_transition(&c, "BACKUP").is_empty());
        assert!(conntrackd_transition(&c, "FAULT").is_empty());
        assert!(conntrackd_transition(&c, "STOP").is_empty());
        assert_eq!(*c.ran.lock().unwrap(), [RequestResync, ShortenTimers]);

        // Standalone: no conntrackd, nothing runs.
        let c = fake(false, &[]);
        assert!(conntrackd_transition(&c, "MASTER").is_empty());
        assert!(c.ran.lock().unwrap().is_empty());
    }
}
