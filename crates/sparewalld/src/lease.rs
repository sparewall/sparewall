//! A pair's one WAN lease (#54). Both nodes have the lease link (a
//! macvlan with the VRRP virtual MAC, running the DHCP client), which
//! networkd leaves down; it is up on the master only, so the ISP sees one
//! MAC and one client ID, and the lease moves with the gateway. The link
//! is reconciled on every keepalived transition and every few seconds, so
//! a link created by an apply, or a restart of this daemon, catches up.

use std::time::Duration;

use serde_json::{Value, json};
use sparewall_config::topology::LEASE_IFACE;
use tokio::sync::broadcast;

use crate::peer::Pair;
use crate::service::{Core, with_core_raw};

const ROUND: Duration = Duration::from_secs(5);

/// Whether the link exists, and whether it is administratively up.
async fn link_up(iface: &str) -> Option<bool> {
    let out = tokio::process::Command::new("ip")
        .args(["-j", "link", "show", "dev", iface])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    let flags = v.get(0)?.get("flags")?.as_array()?;
    Some(flags.iter().any(|f| f == "UP"))
}

/// What to do with the lease link, if anything: `Some(true)` to bring it
/// up, `Some(false)` to take it down.
pub fn wanted(master: bool, up: Option<bool>) -> Option<bool> {
    match up {
        Some(up) if up != master => Some(master),
        _ => None,
    }
}

pub async fn lease_loop(core: Core, events: broadcast::Sender<Value>, pair: Pair) {
    let mut rx = events.subscribe();
    loop {
        let leased = with_core_raw(&core, &events, |c| {
            Ok(c.active_document()?
                .is_some_and(|d| d.networks.keys().any(|n| d.leased_wan(n).is_some())))
        })
        .await
        .unwrap_or(false);
        if leased {
            let master = {
                let p = pair.lock().unwrap_or_else(|p| p.into_inner());
                p.role.as_deref() == Some("MASTER")
            };
            if let Some(up) = wanted(master, link_up(LEASE_IFACE).await) {
                let verb = if up { "up" } else { "down" };
                let ok = tokio::process::Command::new("networkctl")
                    .args([verb, LEASE_IFACE])
                    .status()
                    .await
                    .is_ok_and(|s| s.success());
                if ok {
                    tracing::info!(link = LEASE_IFACE, verb, "WAN lease link");
                } else {
                    tracing::warn!(link = LEASE_IFACE, verb, "cannot change the WAN lease link");
                }
                let _ =
                    events.send(json!({"type": "lease", "link": LEASE_IFACE, "up": up, "ok": ok}));
            }
        }
        // Wake on a transition, or after a round.
        let _ = tokio::time::timeout(ROUND, async {
            loop {
                match rx.recv().await {
                    Ok(v) if v["type"] == "vrrp" => return,
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => return,
                    Err(broadcast::error::RecvError::Closed) => std::future::pending().await,
                }
            }
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_link_follows_the_role() {
        assert_eq!(wanted(true, Some(false)), Some(true));
        assert_eq!(wanted(false, Some(true)), Some(false));
        assert_eq!(wanted(true, Some(true)), None);
        assert_eq!(wanted(false, Some(false)), None);
        // Not created yet (an apply is on its way): nothing to do.
        assert_eq!(wanted(true, None), None);
    }
}
