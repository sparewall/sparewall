//! Which node of a pair has lost a service network (#41).
//!
//! A network cut on one node's side only (a VLAN pulled from its switch
//! port) leaves every link of both nodes up, so neither health nor
//! keepalived sees it: the backup keeps hearing the master on the other
//! networks and stays BACKUP, and the cut network has no gateway.
//!
//! So each node asks, every round, whether the peer's own address on each
//! network with a gateway address answers ARP. While it does not, the
//! node also asks the hosts either node knows there. The answers go to
//! the peer in its hello. A node whose peer is silent on a network, where
//! no host answers it but hosts do answer the peer, has lost that network
//! and fails health, which hands the gateway addresses over. A network
//! nobody answers on (empty, or cut on both sides) only degrades health.
//!
//! ARP is used rather than ping because nft does not filter it: hosts
//! and the peer may drop echo requests.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use serde_json::Value;
use sparewall_api::NetworkReach;
use sparewall_config::Document;
use sparewall_config::model::Cidr;
use sparewall_core::{Check, Level};
use tokio::sync::broadcast;

use crate::peer::Pair;
use crate::service::{Core, with_core_raw};

const ROUND: Duration = Duration::from_secs(10);
/// How long the kernel takes to give up on an address: three
/// solicitations a second apart (`mcast_solicit`, `retrans_time_ms`).
const ANSWER_WAIT: Duration = Duration::from_millis(3500);
/// Hosts probed on one network per round, and hosts reported to the peer.
const MAX_PROBES: usize = 16;
const MAX_KNOWN: usize = 8;
/// Rounds a network must look lost before health fails, so one lost
/// round of ARP cannot move the gateway addresses.
const LOST_ROUNDS: u32 = 2;
/// Any port does: only the ARP exchange it causes matters.
const DISCARD_PORT: u16 = 9;

/// A network with a gateway address, as this node probes it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    network: String,
    iface: String,
    subnet: Cidr,
    own: Ipv4Addr,
    peer: Ipv4Addr,
    vip: Ipv4Addr,
    /// The extra gateway addresses, which the master answers for too.
    extra_vips: Vec<Ipv4Addr>,
}

impl Target {
    /// A host on the network other than the pair and its gateway address.
    fn is_host(&self, a: Ipv4Addr) -> bool {
        self.subnet.0.contains(&a)
            && a != self.own
            && a != self.peer
            && a != self.vip
            && !self.extra_vips.contains(&a)
    }
}

fn targets(doc: &Document, node: &str) -> Vec<Target> {
    let Some(peer) = doc.peer_of(node) else {
        return vec![];
    };
    doc.networks
        .iter()
        .filter(|(_, n)| n.vrid.is_some())
        .filter_map(|(name, n)| {
            let own = n.addresses.get(node)?;
            Some(Target {
                network: name.clone(),
                iface: doc.network_iface(name)?.to_string(),
                subnet: Cidr(own.0.trunc()),
                own: own.0.addr(),
                peer: n.addresses.get(peer)?.0.addr(),
                vip: n.vip?.0.addr(),
                extra_vips: n.extra_vips.iter().map(|c| c.0.addr()).collect(),
            })
        })
        .collect()
}

/// One round's result for a network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Round {
    reach: NetworkReach,
    /// Hosts probed this round (none while the peer answers).
    probed: Vec<Ipv4Addr>,
}

/// The neighbour table of `iface`: each address with whether its link
/// address is known (it answered), and its state.
async fn neighbours(iface: &str) -> Vec<(Ipv4Addr, bool, String)> {
    let out = tokio::process::Command::new("ip")
        .args(["-4", "-j", "neigh", "show", "dev", iface])
        .output()
        .await;
    let Ok(out) = out else { return vec![] };
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    let addr = e["dst"].as_str()?.parse().ok()?;
                    let state = e["state"]
                        .as_array()
                        .and_then(|s| s.first())
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let answered = e.get("lladdr").is_some()
                        && matches!(state.as_str(), "REACHABLE" | "STALE" | "DELAY" | "PROBE");
                    Some((addr, answered, state))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Ask each address afresh: forget what the kernel knows of it, send it
/// a datagram (which makes the kernel resolve it), and see which answered.
async fn solicit(t: &Target, addrs: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    if addrs.is_empty() {
        return vec![];
    }
    let batch: String = addrs
        .iter()
        .map(|a| format!("neigh del {a} dev {}\n", t.iface))
        .collect();
    if let Ok(mut child) = tokio::process::Command::new("ip")
        .args(["-force", "-batch", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(batch.as_bytes()).await;
        }
        let _ = child.wait().await;
    }
    // Bound to the network's own address, so it leaves on that network.
    let Ok(sock) = UdpSocket::bind(SocketAddr::from((t.own, 0))) else {
        return vec![];
    };
    for a in addrs {
        let _ = sock.send_to(&[], SocketAddr::from((*a, DISCARD_PORT)));
    }
    tokio::time::sleep(ANSWER_WAIT).await;
    let table = neighbours(&t.iface).await;
    addrs
        .iter()
        .copied()
        .filter(|a| table.iter().any(|(n, ok, _)| n == a && *ok))
        .collect()
}

/// Hosts this node knows on the network, those that last answered first.
fn known(t: &Target, table: &[(Ipv4Addr, bool, String)]) -> Vec<Ipv4Addr> {
    let mut hosts: Vec<(bool, Ipv4Addr)> = table
        .iter()
        .filter(|(a, _, state)| t.is_host(*a) && state != "PERMANENT" && state != "NOARP")
        .map(|(a, ok, _)| (!ok, *a))
        .collect();
    hosts.sort();
    hosts.into_iter().map(|(_, a)| a).take(MAX_KNOWN).collect()
}

/// Whom to probe while the peer is silent: what answered the peer first,
/// then what the peer knows, then what this node knows.
fn candidates(t: &Target, theirs: Option<&NetworkReach>, ours: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let parse =
        |v: &[String]| -> Vec<Ipv4Addr> { v.iter().filter_map(|a| a.parse().ok()).collect() };
    let mut out: Vec<Ipv4Addr> = Vec::new();
    let from_peer = theirs
        .map(|r| [parse(&r.answered), parse(&r.known)].concat())
        .unwrap_or_default();
    for a in from_peer.into_iter().chain(ours.iter().copied()) {
        if t.is_host(a) && !out.contains(&a) {
            out.push(a);
        }
    }
    out.truncate(MAX_PROBES);
    out
}

async fn probe(t: &Target, theirs: Option<&NetworkReach>) -> Round {
    let table = neighbours(&t.iface).await;
    let ours = known(t, &table);
    let peer = !solicit(t, &[t.peer]).await.is_empty();
    let probed = if peer {
        vec![]
    } else {
        candidates(t, theirs, &ours)
    };
    let answered = solicit(t, &probed).await;
    Round {
        reach: NetworkReach {
            network: t.network.clone(),
            peer,
            answered: answered.iter().map(ToString::to_string).collect(),
            known: ours.iter().map(ToString::to_string).collect(),
        },
        probed,
    }
}

/// Whether this round says the network is lost on this node's side: the
/// peer is silent, nothing answered here, and a host that answers the
/// peer was asked here too.
fn lost_here(r: &Round, theirs: Option<&NetworkReach>) -> bool {
    !r.reach.peer
        && r.reach.answered.is_empty()
        && theirs.is_some_and(|t| {
            t.answered
                .iter()
                .filter_map(|a| a.parse::<Ipv4Addr>().ok())
                .any(|a| r.probed.contains(&a))
        })
}

fn checks(rounds: &[Round], lost: &BTreeMap<String, u32>, peer: &str) -> Vec<Check> {
    rounds
        .iter()
        .filter(|r| !r.reach.peer)
        .map(|r| {
            let net = &r.reach.network;
            if lost.get(net).copied().unwrap_or(0) >= LOST_ROUNDS {
                Check::new(
                    "reach",
                    Level::Failed,
                    format!(
                        "network {net}: neither {peer} nor any host answers here, \
                         but hosts answer {peer}: this node has lost it"
                    ),
                )
            } else {
                Check::new(
                    "reach",
                    Level::Degraded,
                    format!(
                        "network {net}: {peer} does not answer ARP{}",
                        if r.reach.answered.is_empty() {
                            String::new()
                        } else {
                            format!("; {} other hosts do", r.reach.answered.len())
                        }
                    ),
                )
            }
        })
        .collect()
}

/// Probe every network with a gateway address each round, publish the
/// result for the peer's hello, and set the `reach` health checks.
pub async fn probe_loop(core: Core, events: broadcast::Sender<Value>, pair: Pair) {
    let mut lost: BTreeMap<String, u32> = BTreeMap::new();
    loop {
        let doc = with_core_raw(&core, &events, |c| {
            Ok(c.active_document()?.map(|d| {
                (
                    targets(&d, c.node()),
                    d.peer_of(c.node()).map(str::to_string),
                )
            }))
        })
        .await
        .ok()
        .flatten();
        let (targets, peer) = doc.unwrap_or_default();
        let theirs = pair
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .peer_reach
            .clone();
        let find = |n: &str| {
            theirs
                .as_ref()
                .and_then(|v| v.iter().find(|r| r.network == n))
        };
        let rounds =
            futures_util::future::join_all(targets.iter().map(|t| probe(t, find(&t.network))))
                .await;
        lost.retain(|n, _| rounds.iter().any(|r| &r.reach.network == n));
        for r in &rounds {
            let n = lost.entry(r.reach.network.clone()).or_default();
            if lost_here(r, find(&r.reach.network)) {
                *n += 1;
                if *n == LOST_ROUNDS {
                    tracing::warn!(network = %r.reach.network, "this node has lost the network: failing health");
                }
            } else {
                *n = 0;
            }
        }
        let checks = checks(&rounds, &lost, peer.as_deref().unwrap_or("the peer"));
        pair.lock().unwrap_or_else(|p| p.into_inner()).reach =
            rounds.into_iter().map(|r| r.reach).collect();
        let _ = with_core_raw(&core, &events, move |c| {
            c.set_named_checks("reach", checks);
            Ok(())
        })
        .await;
        tokio::time::sleep(ROUND).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            network: "users".into(),
            iface: "users".into(),
            subnet: Cidr("10.20.0.0/24".parse().unwrap()),
            own: "10.20.0.2".parse().unwrap(),
            peer: "10.20.0.3".parse().unwrap(),
            vip: "10.20.0.1".parse().unwrap(),
            extra_vips: vec!["10.20.0.5".parse().unwrap()],
        }
    }

    fn reach(peer: bool, answered: &[&str], known: &[&str]) -> NetworkReach {
        NetworkReach {
            network: "users".into(),
            peer,
            answered: answered.iter().map(|s| s.to_string()).collect(),
            known: known.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn round(peer: bool, answered: &[&str], probed: &[&str]) -> Round {
        Round {
            reach: reach(peer, answered, &[]),
            probed: probed.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn known_hosts_exclude_the_pair_and_put_answers_first() {
        let t = target();
        let table = vec![
            ("10.20.0.3".parse().unwrap(), true, "REACHABLE".into()),
            ("10.20.0.1".parse().unwrap(), true, "REACHABLE".into()),
            ("10.20.0.50".parse().unwrap(), false, "FAILED".into()),
            ("10.20.0.60".parse().unwrap(), true, "STALE".into()),
            ("10.30.0.9".parse().unwrap(), true, "REACHABLE".into()),
            ("10.20.0.70".parse().unwrap(), true, "PERMANENT".into()),
            ("10.20.0.5".parse().unwrap(), true, "REACHABLE".into()),
        ];
        let k: Vec<String> = known(&t, &table).iter().map(ToString::to_string).collect();
        assert_eq!(k, ["10.20.0.60", "10.20.0.50"]);
    }

    #[test]
    fn candidates_put_the_peers_answers_first_and_dedup() {
        let t = target();
        let theirs = reach(false, &["10.20.0.80"], &["10.20.0.81", "10.20.0.3"]);
        let ours = ["10.20.0.81".parse().unwrap(), "10.20.0.82".parse().unwrap()];
        let c: Vec<String> = candidates(&t, Some(&theirs), &ours)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(c, ["10.20.0.80", "10.20.0.81", "10.20.0.82"]);
    }

    #[test]
    fn lost_only_when_a_host_that_answers_the_peer_is_silent_here() {
        let theirs = reach(false, &["10.20.0.80"], &[]);
        // The cut side: asked the host the peer reaches, got nothing.
        assert!(lost_here(
            &round(false, &[], &["10.20.0.80"]),
            Some(&theirs)
        ));
        // Hosts answer here: the network is split, or the peer is the cut side.
        assert!(!lost_here(
            &round(false, &["10.20.0.81"], &["10.20.0.80", "10.20.0.81"]),
            Some(&theirs)
        ));
        // The peer answers.
        assert!(!lost_here(&round(true, &[], &[]), Some(&theirs)));
        // Not yet asked the hosts the peer reaches.
        assert!(!lost_here(
            &round(false, &[], &["10.20.0.90"]),
            Some(&theirs)
        ));
        // Nothing answers the peer either (an empty network, or cut on both sides).
        assert!(!lost_here(
            &round(false, &[], &["10.20.0.80"]),
            Some(&reach(false, &[], &[]))
        ));
        // No word from the peer.
        assert!(!lost_here(&round(false, &[], &["10.20.0.80"]), None));
    }

    #[test]
    fn health_fails_only_after_consecutive_lost_rounds() {
        let rounds = [round(false, &[], &["10.20.0.80"])];
        let mut lost = BTreeMap::from([("users".to_string(), 1)]);
        let c = checks(&rounds, &lost, "fw1");
        assert_eq!(c[0].level, Level::Degraded);
        lost.insert("users".into(), LOST_ROUNDS);
        let c = checks(&rounds, &lost, "fw1");
        assert_eq!(c[0].level, Level::Failed);
        assert!(checks(&[round(true, &[], &[])], &lost, "fw1").is_empty());
    }
}
