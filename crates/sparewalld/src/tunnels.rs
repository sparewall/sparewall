//! Site-to-site tunnels (#148): a peer with an endpoint is one this node
//! connects to. Every round, on the node that holds the tunnel (a
//! standalone node, or a pair's master):
//!
//! - a peer whose endpoint is a DNS name, and that has not completed a
//!   handshake lately, has the name resolved again, and the endpoint
//!   changed if it moved (networkd resolves it only when it creates the
//!   interface);
//! - a peer with a keepalive that has had no handshake for longer than
//!   [`STALE`] degrades health (`tunnels`). Without a keepalive an idle
//!   tunnel has no handshakes either, so nothing is said of it.
//!
//! A pair's backup sends nothing to its site peers (the output chain drops
//! it), so it neither resolves nor reports.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sparewall_core::system::WgPeer;
use sparewall_core::{Check, Level};
use tokio::sync::broadcast;

use crate::peer::Pair;
use crate::service::{Core, with_core_raw};

const ROUND: Duration = Duration::from_secs(30);
/// No handshake for this long, with a handshake every two minutes while
/// the tunnel is up (WireGuard rekeys after 120 s) and keepalives keeping
/// it up: the peer is not answering.
pub const STALE: u64 = 180;
/// A name is resolved again once the last handshake is older than this
/// (as wireguard-tools' reresolve-dns does).
const RESOLVE_AFTER: u64 = 135;

/// A site-to-site peer, and the kernel's view of it.
#[derive(Debug, Clone)]
struct Site {
    vpn: String,
    peer: String,
    public_key: String,
    endpoint: String,
    keepalive: Option<u16>,
    state: Option<WgPeer>,
}

impl Site {
    fn id(&self) -> (String, String) {
        (self.vpn.clone(), self.peer.clone())
    }

    /// Whether the endpoint names a host rather than an address.
    fn named(&self) -> bool {
        self.endpoint
            .rsplit_once(':')
            .is_some_and(|(h, _)| h.parse::<std::net::Ipv4Addr>().is_err())
    }

    fn last(&self) -> u64 {
        self.state.as_ref().map_or(0, |s| s.latest_handshake)
    }
}

/// What a round decides: the peers whose names to resolve again, and the
/// health checks. `watched` is when this node started holding each
/// tunnel, so a tunnel just brought up has time for its first handshake.
fn assess<'a>(
    sites: &'a [Site],
    now: u64,
    watched: &BTreeMap<(String, String), u64>,
) -> (Vec<&'a Site>, Vec<Check>) {
    let resolve = sites
        .iter()
        .filter(|s| s.named() && now.saturating_sub(s.last()) > RESOLVE_AFTER)
        .collect();
    let mut quiet = Vec::new();
    for s in sites.iter().filter(|s| s.keepalive.is_some()) {
        let since = watched.get(&s.id()).copied().unwrap_or(now);
        if now.saturating_sub(since) <= STALE || now.saturating_sub(s.last()) <= STALE {
            continue;
        }
        quiet.push(match s.last() {
            0 => format!("{}/{}: no handshake with {}", s.vpn, s.peer, s.endpoint),
            t => format!(
                "{}/{}: no handshake with {} for {} s",
                s.vpn,
                s.peer,
                s.endpoint,
                now - t
            ),
        });
    }
    let checks = if quiet.is_empty() {
        vec![]
    } else {
        vec![Check::new("tunnels", Level::Degraded, quiet.join("; "))]
    };
    (resolve, checks)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub async fn tunnel_loop(core: Core, events: broadcast::Sender<Value>, pair: Pair) {
    let mut watched: BTreeMap<(String, String), u64> = BTreeMap::new();
    loop {
        let role = pair.lock().unwrap_or_else(|p| p.into_inner()).role.clone();
        let sites = with_core_raw(&core, &events, move |c| {
            let Some(doc) = c.active_document()? else {
                return Ok(None);
            };
            if doc.is_pair() && role.as_deref() != Some("MASTER") {
                return Ok(None);
            }
            let mut sites = Vec::new();
            for (vpn, v) in &doc.vpn {
                let mut state = None;
                for (peer, p) in &v.peers {
                    let Some(endpoint) = &p.endpoint else {
                        continue;
                    };
                    let peers = match &state {
                        Some(s) => s,
                        None => state.insert(c.system().wg_peers(vpn).unwrap_or_default()),
                    };
                    sites.push(Site {
                        vpn: vpn.clone(),
                        peer: peer.clone(),
                        public_key: p.public_key.clone(),
                        endpoint: endpoint.clone(),
                        keepalive: p.keepalive,
                        state: peers.iter().find(|s| s.public_key == p.public_key).cloned(),
                    });
                }
            }
            Ok(Some(sites))
        })
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
        let now = now();
        watched.retain(|k, _| sites.iter().any(|s| &s.id() == k));
        for s in &sites {
            watched.entry(s.id()).or_insert(now);
        }
        let (resolve, checks) = assess(&sites, now, &watched);
        for s in resolve {
            let Ok(found) = tokio::time::timeout(
                Duration::from_secs(10),
                tokio::net::lookup_host(s.endpoint.clone()),
            )
            .await
            else {
                continue;
            };
            let Some(addr) = found.ok().and_then(|mut a| a.find(|a| a.is_ipv4())) else {
                tracing::info!(
                    vpn = s.vpn,
                    peer = s.peer,
                    endpoint = s.endpoint,
                    "cannot resolve a site-to-site peer's endpoint"
                );
                continue;
            };
            let addr = addr.to_string();
            if s.state.as_ref().and_then(|st| st.endpoint.as_deref()) == Some(addr.as_str()) {
                continue;
            }
            tracing::info!(
                vpn = s.vpn,
                peer = s.peer,
                endpoint = s.endpoint,
                address = addr,
                "a site-to-site peer's endpoint moved"
            );
            let (vpn, key) = (s.vpn.clone(), s.public_key.clone());
            let r = with_core_raw(&core, &events, move |c| {
                c.system().wg_set_endpoint(&vpn, &key, &addr)
            })
            .await;
            if let Err(e) = r {
                tracing::warn!(error = %e, "could not set a site-to-site peer's endpoint");
            }
        }
        let _ = with_core_raw(&core, &events, move |c| {
            c.set_named_checks("tunnels", checks);
            Ok(())
        })
        .await;
        tokio::time::sleep(ROUND).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(endpoint: &str, keepalive: Option<u16>, last: Option<u64>) -> Site {
        Site {
            vpn: "branch".into(),
            peer: "office-b".into(),
            public_key: "K".into(),
            endpoint: endpoint.into(),
            keepalive,
            state: last.map(|t| WgPeer {
                public_key: "K".into(),
                latest_handshake: t,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn names_are_resolved_while_quiet() {
        let w = BTreeMap::new();
        let now = 10_000;
        let s = [
            site("b.example.net:51821", None, Some(now - 200)),
            site("b.example.net:51821", None, Some(now - 30)),
            site("198.51.100.7:51821", None, Some(now - 200)),
            site("b.example.net:51821", None, None),
        ];
        let (r, _) = assess(&s, now, &w);
        assert_eq!(r.len(), 2);
        assert!(std::ptr::eq(r[0], &s[0]) && std::ptr::eq(r[1], &s[3]));
    }

    #[test]
    fn a_kept_alive_peer_without_handshakes_degrades_health() {
        let now = 10_000;
        let mut w = BTreeMap::new();
        w.insert(("branch".to_string(), "office-b".to_string()), now - 1000);
        let quiet = [site("198.51.100.7:51821", Some(25), Some(now - 400))];
        let (_, c) = assess(&quiet, now, &w);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].level, Level::Degraded);
        assert!(
            c[0].message
                .contains("branch/office-b: no handshake with 198.51.100.7:51821 for 400 s"),
            "{}",
            c[0].message
        );
        // Recent, never kept alive, or only just brought up: nothing.
        assert!(
            assess(
                &[site("198.51.100.7:51821", Some(25), Some(now - 60))],
                now,
                &w
            )
            .1
            .is_empty()
        );
        assert!(
            assess(&[site("198.51.100.7:51821", None, None)], now, &w)
                .1
                .is_empty()
        );
        let mut fresh = BTreeMap::new();
        fresh.insert(("branch".to_string(), "office-b".to_string()), now - 60);
        assert!(
            assess(&[site("198.51.100.7:51821", Some(25), None)], now, &fresh)
                .1
                .is_empty()
        );
    }
}
