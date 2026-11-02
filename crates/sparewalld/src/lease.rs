//! Links a pair keeps up on the master only, which networkd leaves down
//! (`ActivationPolicy=manual`):
//!
//! - the one WAN lease (#54): both nodes have the lease link (a macvlan
//!   with the VRRP virtual MAC, running the DHCP client), so the ISP sees
//!   one MAC and one client ID, and the lease moves with the gateway;
//! - the VPN clients (#149): both nodes hold the same key, so the
//!   service sees one client, which moves with the gateway.
//!
//! The links are reconciled on every keepalived transition and every few
//! seconds, so a link created by an apply, or a restart of this daemon,
//! catches up.

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

/// The links up on a pair's master only: the WAN lease's, and the VPN
/// clients'. None on a standalone node, which keeps them up.
pub fn master_links(doc: &sparewall_config::Document) -> Vec<String> {
    if !doc.is_pair() {
        return vec![];
    }
    let mut v: Vec<String> = Vec::new();
    if doc.networks.keys().any(|n| doc.leased_wan(n).is_some()) {
        v.push(LEASE_IFACE.to_string());
    }
    v.extend(doc.vpn_clients.keys().cloned());
    v
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
        let links = with_core_raw(&core, &events, |c| {
            Ok(c.active_document()?
                .map(|d| master_links(&d))
                .unwrap_or_default())
        })
        .await
        .unwrap_or_default();
        let master = {
            let p = pair.lock().unwrap_or_else(|p| p.into_inner());
            p.role.as_deref() == Some("MASTER")
        };
        for link in &links {
            if let Some(up) = wanted(master, link_up(link).await) {
                let verb = if up { "up" } else { "down" };
                let ok = tokio::process::Command::new("networkctl")
                    .args([verb, link])
                    .status()
                    .await
                    .is_ok_and(|s| s.success());
                if ok {
                    tracing::info!(link, verb, "a link that follows the master");
                } else {
                    tracing::warn!(link, verb, "cannot change a link that follows the master");
                }
                let _ = events.send(json!({"type": "lease", "link": link, "up": up, "ok": ok}));
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
