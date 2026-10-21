//! Operator-driven failback (`sparewall failover`, #122).
//!
//! A pair runs with `nopreempt`, so the configured priority decides the
//! master only when both nodes start together. A failover moves the
//! gateway addresses to the node the operator names (by default the one
//! with the higher priority): the master yields, through the
//! `sparewall_yield` track script, which puts its instances in FAULT so
//! the peer takes over as it would for a failed node; once the peer is
//! master the yield ends and the old master returns as BACKUP, where
//! `nopreempt` keeps it. Started on the backup, the request goes to the
//! master, which starts the handover and returns; the backup watches its
//! own role for the end.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::Value;
use sparewall_api::{FailoverReply, PeerFailoverProxy};
use sparewall_render::keepalived::{YIELD_FILE, YIELD_MAX_S, preferred};
use tokio::sync::broadcast;

use crate::peer::{Link, Pair, connect, tunnel_addrs};
use crate::service::{Core, with_core_raw};
use crate::upgrade::{LinkPeer, UpgradePeer};

/// How long each step waits.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// For the peer to become master once this node yields.
    pub master_timeout: Duration,
    pub poll: Duration,
}

pub const TIMING: Timing = Timing {
    master_timeout: Duration::from_secs(60),
    poll: Duration::from_secs(1),
};

/// The yield request keepalived's track script looks for.
pub struct Yield(pub PathBuf);

impl Default for Yield {
    fn default() -> Self {
        Yield(YIELD_FILE.into())
    }
}

impl Yield {
    fn set(&self) -> Result<(), String> {
        std::fs::write(&self.0, b"").map_err(|e| format!("{}: {e}", self.0.display()))
    }

    /// End a yield (one left by an earlier run of the coordinator, too).
    /// An error means the node stays in FAULT until the track script
    /// ignores the request ([`YIELD_MAX_S`]).
    pub fn clear(&self) -> Result<(), String> {
        match std::fs::remove_file(&self.0) {
            Ok(()) => {
                tracing::info!("failover: no longer yielding");
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!(
                "cannot end this node's yield ({}: {e}); it stays in FAULT, claiming no \
                 gateway address, for up to {YIELD_MAX_S}s",
                self.0.display()
            )),
        }
    }
}

/// What a failover request comes to on this node.
#[derive(Debug, PartialEq)]
pub enum Planned {
    /// The target holds the addresses already.
    Already { master: String },
    /// This node is the master: hand over to the peer.
    Run { link: Link, peer: String },
    /// This node is the backup and the target: the master hands over.
    Forward { link: Link, master: String },
}

/// The facts a plan is made from.
pub struct Facts<'a> {
    pub node: &'a str,
    pub peer: Option<&'a str>,
    pub preferred: Option<&'a str>,
    pub held: bool,
    pub in_sync: bool,
    pub role: Option<&'a str>,
}

/// Decide what a failover to `to` means here, or why it cannot happen.
pub fn decide(f: &Facts, to: Option<&str>) -> Result<Target, String> {
    let Some(peer) = f.peer else {
        return Err("failover needs a paired HA pair".into());
    };
    let target = to.or(f.preferred).unwrap_or(f.node);
    if target != f.node && target != peer {
        return Err(format!(
            "{target} is not a node of this pair ({}, {peer})",
            f.node
        ));
    }
    if f.held {
        return Err("the pair is held (cluster.hold): no node claims the gateway addresses".into());
    }
    if !f.in_sync {
        return Err("the pair is not in sync; fail over only an in-sync pair".into());
    }
    match (f.role, target == f.node) {
        (Some("MASTER"), true) | (Some("BACKUP"), false) => Ok(Target::Already),
        (Some("MASTER"), false) => Ok(Target::Peer),
        (Some("BACKUP"), true) => Ok(Target::Here),
        (role, _) => Err(format!(
            "this node is {}, neither master nor backup",
            role.unwrap_or("of unknown VRRP state")
        )),
    }
}

/// Where the addresses go, from this node's side.
#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    Already,
    Peer,
    Here,
}

/// Plan a failover to `to` and check what this node can check.
pub async fn plan(
    core: &Core,
    events: &broadcast::Sender<Value>,
    pair: &Pair,
    to: Option<&str>,
) -> Result<Planned, String> {
    let (doc, node) = with_core_raw(core, events, |c| {
        Ok((c.active_document()?, c.node().to_string()))
    })
    .await
    .map_err(|e| e.to_string())?;
    let addrs = doc.as_ref().and_then(|d| tunnel_addrs(d, &node));
    let p = pair.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let facts = Facts {
        node: &node,
        peer: addrs.as_ref().map(|(_, _, p)| p.as_str()),
        preferred: doc.as_ref().and_then(|d| preferred(d)),
        held: doc.as_ref().is_some_and(|d| d.cluster.hold),
        in_sync: p.state.as_ref().map(|s| s.name()) == Some("in-sync"),
        role: p.role.as_deref(),
    };
    let target = decide(&facts, to)?;
    let (own, peer_addr, peer) = addrs.expect("decide checks the pair");
    let link = Link {
        own,
        peer: peer_addr,
    };
    Ok(match target {
        Target::Already => Planned::Already {
            master: if p.role.as_deref() == Some("MASTER") {
                node
            } else {
                peer
            },
        },
        Target::Peer => Planned::Run { link, peer },
        Target::Here => Planned::Forward { link, master: peer },
    })
}

/// Check that the peer is fit to take the addresses: the backup, healthy,
/// running this node's configuration. The same as becoming eligible to be
/// master, which health `ok` includes (every required link up).
async fn gate<P: UpgradePeer>(peer: &P, ours: &str) -> Result<String, String> {
    let h = peer.hello().await?;
    let name = h.node.clone();
    let refuse = |why: String| Err(format!("{name} cannot take over: {why}"));
    if h.role.as_deref() != Some("BACKUP") {
        return refuse(format!(
            "it is {}, not BACKUP",
            h.role.as_deref().unwrap_or("of unknown VRRP state")
        ));
    }
    match h.health.as_deref() {
        Some("ok") => {}
        other => return refuse(format!("its health is {}", other.unwrap_or("unknown"))),
    }
    if h.desired != ours || h.applied.as_deref() != Some(ours) || h.applying {
        return refuse("it is not running this node's configuration".into());
    }
    Ok(name)
}

/// The handover, on the master, against any peer and yield file.
pub async fn run_with<P: UpgradePeer>(
    peer: &P,
    y: &Yield,
    ours: &str,
    t: &Timing,
) -> Result<String, String> {
    let name = gate(peer, ours).await?;
    tracing::info!(peer = %name, "failover: yielding the gateway addresses");
    y.set()?;
    let t0 = Instant::now();
    let r = loop {
        if let Ok(h) = peer.hello().await
            && h.role.as_deref() == Some("MASTER")
        {
            break Ok(format!("{name} holds the gateway addresses"));
        }
        if t0.elapsed() >= t.master_timeout {
            break Err(format!(
                "{name} did not become master within {}s; the gateway addresses stay here",
                t.master_timeout.as_secs()
            ));
        }
        tokio::time::sleep(t.poll).await;
    };
    // Ending the yield is part of the result: on a failed handover it is
    // what gives the addresses back.
    let r = match (r, y.clear()) {
        (r, Ok(())) => r,
        (Ok(m), Err(e)) => Err(format!("{m}, but {e}")),
        (Err(m), Err(e)) => Err(format!("{m}; but {e}, so neither node may hold them")),
    };
    match &r {
        Ok(m) => tracing::info!("failover: {m}"),
        Err(e) => tracing::error!("failover: {e}"),
    }
    r
}

/// The handover from this node, the master, to the peer.
async fn run(core: &Core, events: &broadcast::Sender<Value>, link: Link) -> Result<String, String> {
    let (node, ours) = with_core_raw(core, events, |c| {
        Ok((c.node().to_string(), c.view()?.desired))
    })
    .await
    .map_err(|e| e.to_string())?;
    run_with(&LinkPeer { link, node }, &Yield::default(), &ours, &TIMING).await
}

/// `sparewall failover`, on either node: returns once the addresses have
/// moved, or why they did not.
pub async fn failover(
    core: &Core,
    events: &broadcast::Sender<Value>,
    pair: &Pair,
    to: Option<&str>,
) -> Result<FailoverReply, String> {
    match plan(core, events, pair, to).await? {
        Planned::Already { master } => Ok(FailoverReply {
            message: format!("{master} holds the gateway addresses already"),
            master,
        }),
        Planned::Run { link, peer } => {
            let message = run(core, events, link).await?;
            Ok(FailoverReply {
                master: peer,
                message,
            })
        }
        Planned::Forward { link, master } => {
            let node = with_core_raw(core, events, |c| Ok(c.node().to_string()))
                .await
                .map_err(|e| e.to_string())?;
            connect(link)
                .await?
                .failover(&node)
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| format!("{master} refused: {e}"))?;
            // The master yields; this node sees its own role change.
            let t0 = Instant::now();
            loop {
                let role = pair.lock().unwrap_or_else(|p| p.into_inner()).role.clone();
                if role.as_deref() == Some("MASTER") {
                    return Ok(FailoverReply {
                        message: format!("{node} holds the gateway addresses"),
                        master: node,
                    });
                }
                if t0.elapsed() >= TIMING.master_timeout + Duration::from_secs(15) {
                    return Err(format!(
                        "{node} did not become master; {master} keeps the gateway addresses"
                    ));
                }
                tokio::time::sleep(TIMING.poll).await;
            }
        }
    }
}

/// A failover the backup asked for (`Peer.Failover`): start the handover
/// and return. Never forwarded again.
pub async fn start_for_peer(
    core: &Core,
    events: &broadcast::Sender<Value>,
    pair: &Pair,
    to: &str,
) -> Result<FailoverReply, String> {
    match plan(core, events, pair, Some(to)).await? {
        Planned::Already { master } => Ok(FailoverReply {
            message: format!("{master} holds the gateway addresses already"),
            master,
        }),
        Planned::Run { link, peer } => {
            let (node, ours) = with_core_raw(core, events, |c| {
                Ok((c.node().to_string(), c.view()?.desired))
            })
            .await
            .map_err(|e| e.to_string())?;
            let lp = LinkPeer { link, node };
            // Refuse now, while the caller waits, rather than after.
            gate(&lp, &ours).await?;
            tokio::spawn(async move {
                let _ = run_with(&lp, &Yield::default(), &ours, &TIMING).await;
            });
            Ok(FailoverReply {
                message: format!("handing the gateway addresses to {peer}"),
                master: peer,
            })
        }
        Planned::Forward { master, .. } => Err(format!(
            "this node is the backup; {master} holds the gateway addresses"
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use sparewall_api::HelloReply;

    use super::*;

    fn facts<'a>(role: Option<&'a str>) -> Facts<'a> {
        Facts {
            node: "fw1",
            peer: Some("fw2"),
            preferred: Some("fw1"),
            held: false,
            in_sync: true,
            role,
        }
    }

    #[test]
    fn decide_where_the_addresses_go() {
        let d = |role, to| decide(&facts(role), to);
        assert_eq!(d(Some("MASTER"), None), Ok(Target::Already));
        assert_eq!(d(Some("BACKUP"), None), Ok(Target::Here));
        assert_eq!(d(Some("MASTER"), Some("fw2")), Ok(Target::Peer));
        assert_eq!(d(Some("BACKUP"), Some("fw2")), Ok(Target::Already));
        assert!(d(Some("FAULT"), None).unwrap_err().contains("FAULT"));
        assert!(
            d(Some("MASTER"), Some("fw3"))
                .unwrap_err()
                .contains("not a node")
        );
        let f = |change: fn(&mut Facts)| {
            let mut f = facts(Some("MASTER"));
            change(&mut f);
            decide(&f, Some("fw2")).unwrap_err()
        };
        assert!(f(|f| f.held = true).contains("held"));
        assert!(f(|f| f.in_sync = false).contains("not in sync"));
        assert!(f(|f| f.peer = None).contains("pair"));
    }

    /// A peer that becomes master once this node yields (or never).
    struct FakePeer {
        hello: Mutex<HelloReply>,
        takes_over: bool,
        yield_file: PathBuf,
        /// Make the yield impossible to end: a directory with something
        /// in it, which remove_file refuses.
        stick: bool,
    }

    impl UpgradePeer for FakePeer {
        async fn hello(&self) -> Result<HelloReply, String> {
            let mut h = self.hello.lock().unwrap();
            if self.stick && self.yield_file.is_file() {
                std::fs::remove_file(&self.yield_file).unwrap();
                std::fs::create_dir_all(self.yield_file.join("x")).unwrap();
            }
            if self.takes_over && self.yield_file.exists() {
                h.role = Some("MASTER".into());
            }
            Ok(h.clone())
        }
        async fn upgrade(&self, _: &str) -> Result<(), String> {
            unreachable!()
        }
    }

    fn peer(dir: &std::path::Path, takes_over: bool, change: fn(&mut HelloReply)) -> FakePeer {
        let mut h = HelloReply {
            node: "fw2".into(),
            protocol: sparewall_api::PEER_PROTOCOL,
            active: 3,
            desired: "h".into(),
            applied: Some("h".into()),
            applying: false,
            lineage: vec![],
            pending: false,
            image: None,
            health: Some("ok".into()),
            role: Some("BACKUP".into()),
            link_decision: None,
            reach: vec![],
        };
        change(&mut h);
        FakePeer {
            hello: Mutex::new(h),
            takes_over,
            yield_file: dir.join("yield"),
            stick: false,
        }
    }

    const FAST: Timing = Timing {
        master_timeout: Duration::from_millis(300),
        poll: Duration::from_millis(10),
    };

    #[tokio::test]
    async fn hands_over_and_stops_yielding() {
        let dir = tempfile::tempdir().unwrap();
        let y = Yield(dir.path().join("yield"));
        let p = peer(dir.path(), true, |_| {});
        let m = run_with(&p, &y, "h", &FAST).await.unwrap();
        assert!(m.contains("fw2 holds"), "{m}");
        assert!(!y.0.exists(), "the yield ends once the peer is master");
    }

    #[tokio::test]
    async fn a_peer_that_never_takes_over_leaves_the_addresses_here() {
        let dir = tempfile::tempdir().unwrap();
        let y = Yield(dir.path().join("yield"));
        let p = peer(dir.path(), false, |_| {});
        let e = run_with(&p, &y, "h", &FAST).await.unwrap_err();
        assert!(e.contains("stay here"), "{e}");
        assert!(!y.0.exists());
    }

    #[tokio::test]
    async fn a_yield_that_cannot_end_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("yield");
        let y = Yield(path.clone());
        for takes_over in [true, false] {
            let mut p = peer(dir.path(), takes_over, |_| {});
            p.stick = true;
            let e = run_with(&p, &y, "h", &FAST).await.unwrap_err();
            assert!(e.contains("cannot end this node's yield"), "{e}");
            if takes_over {
                assert!(e.starts_with("fw2 holds"), "{e}");
            } else {
                assert!(e.contains("neither node"), "{e}");
            }
            std::fs::remove_dir_all(&path).unwrap();
        }
    }

    #[tokio::test]
    async fn refuses_an_unfit_peer_without_yielding() {
        let dir = tempfile::tempdir().unwrap();
        let y = Yield(dir.path().join("yield"));
        type Case = (fn(&mut HelloReply), &'static str);
        let cases: [Case; 5] = [
            (|h| h.health = Some("degraded".into()), "health is degraded"),
            (|h| h.health = Some("failed".into()), "health is failed"),
            (|h| h.role = Some("FAULT".into()), "it is FAULT"),
            (|h| h.applied = Some("old".into()), "configuration"),
            (|h| h.desired = "other".into(), "configuration"),
        ];
        for (change, why) in cases {
            let p = peer(dir.path(), true, change);
            let e = run_with(&p, &y, "h", &FAST).await.unwrap_err();
            assert!(e.contains(why), "{e}");
            assert!(!y.0.exists());
        }
    }
}
