//! The peer link (design: "Configuration lifecycle", step 6, and "Pair
//! sync states").
//!
//! Each node serves `org.sparewall.Peer` on a root-only Unix socket and
//! listens on TCP on its sync-tunnel address, splicing connections onto
//! that socket. Only the peer can reach the tunnel address: WireGuard
//! authenticates it and nft admits the tunnel interface alone.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use sparewall_api::{
    FetchReply, HelloReply, LineageEntry, PEER_PORT, PEER_PROTOCOL, PeerError, PeerGeneration,
    PeerProxy, PushReply,
};
use sparewall_core::pair::{NodeView, SyncState, push_plan, sync_state};
use sparewall_core::{Check, Error, Generation, Level};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, broadcast};
use zlink::Connection;
use zlink::service;

use crate::service::{Core, with_core_raw};

/// What the daemon knows about the pair, for status and health.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PairStatus {
    pub paired: bool,
    pub peer: Option<String>,
    pub reachable: bool,
    pub state: Option<SyncState>,
    pub peer_view: Option<NodeView>,
    pub peer_image: Option<String>,
    pub last_error: Option<String>,
    /// VRRP role from keepalived (`MASTER`, `BACKUP`, `FAULT`).
    pub role: Option<String>,
}

pub type Pair = Arc<Mutex<PairStatus>>;

pub fn to_peer(g: &Generation) -> PeerGeneration {
    PeerGeneration {
        id: g.id as i64,
        hash: g.hash.clone(),
        base: g.base.map(|b| b as i64),
        schema: i64::from(g.schema),
        author: g.author.clone(),
        created: g.created.clone(),
        summary: g.summary.clone(),
    }
}

pub fn from_peer(g: &PeerGeneration) -> Generation {
    Generation {
        id: g.id.max(0) as u64,
        hash: g.hash.clone(),
        base: g.base.map(|b| b.max(0) as u64),
        schema: g.schema.max(0) as u32,
        author: g.author.clone(),
        created: g.created.clone(),
        summary: g.summary.clone(),
    }
}

fn peer_error(e: Error) -> PeerError {
    match e {
        Error::Conflict { current } => PeerError::Conflict {
            current: current as i64,
        },
        Error::NotFound(id) => PeerError::NotFound { id: id as i64 },
        other => PeerError::Rejected {
            message: other.to_string(),
        },
    }
}

/// The node's own and the peer's sync-tunnel addresses, once paired.
pub fn tunnel_addrs(
    doc: &sparewall_config::Document,
    node: &str,
) -> Option<(IpAddr, IpAddr, String)> {
    let peer = doc.peer_of(node)?;
    if !doc.cluster.sync_keys.contains_key(node) || !doc.cluster.sync_keys.contains_key(peer) {
        return None;
    }
    let own = sparewall_render::networkd::sync_tunnel_addr(doc, node)?.addr();
    let other = sparewall_render::networkd::sync_tunnel_addr(doc, peer)?.addr();
    Some((IpAddr::V4(own), IpAddr::V4(other), peer.to_string()))
}

pub struct PeerService {
    core: Core,
    events: broadcast::Sender<Value>,
    sync: Arc<Notify>,
}

impl PeerService {
    pub fn new(core: Core, events: broadcast::Sender<Value>, sync: Arc<Notify>) -> Self {
        PeerService { core, events, sync }
    }
}

#[service(interface = "org.sparewall.Peer", types = [PeerGeneration, LineageEntry])]
impl PeerService {
    async fn hello(&mut self, node: String, protocol: i64) -> Result<HelloReply, PeerError> {
        with_core_raw(&self.core, &self.events, move |c| {
            if let Some(doc) = c.active_document()?
                && let Some(expected) = doc.peer_of(c.node())
                && expected != node
            {
                return Ok(Err(PeerError::WrongNode {
                    expected: expected.to_string(),
                }));
            }
            let v = c.view()?;
            let pending = c.state()?.pending.is_some();
            Ok(Ok(HelloReply {
                node: v.node,
                protocol: PEER_PROTOCOL.min(protocol),
                active: v.active as i64,
                desired: v.desired,
                applied: v.applied,
                applying: v.applying,
                lineage: v
                    .lineage
                    .into_iter()
                    .map(|(id, hash)| LineageEntry {
                        id: id as i64,
                        hash,
                    })
                    .collect(),
                pending,
                image: crate::service::booted_image_digest(),
            }))
        })
        .await
        .map_err(peer_error)?
    }

    async fn push(
        &mut self,
        generation: PeerGeneration,
        config: Value,
        force: Option<bool>,
    ) -> Result<PushReply, PeerError> {
        let g = from_peer(&generation);
        let active = with_core_raw(&self.core, &self.events, move |c| {
            if force.unwrap_or(false) {
                c.adopt(&g, config)?;
            } else {
                c.receive(&g, config)?;
            }
            c.active()
        })
        .await
        .map_err(peer_error)?;
        self.sync.notify_one();
        Ok(PushReply {
            active: active as i64,
        })
    }

    async fn fetch(&mut self, id: Option<i64>) -> Result<FetchReply, PeerError> {
        with_core_raw(&self.core, &self.events, move |c| {
            let id = match id {
                Some(i) => i.max(0) as u64,
                None => c.active()?,
            };
            Ok(FetchReply {
                generation: to_peer(&c.generation(id)?),
                config: c.document_value(id)?,
            })
        })
        .await
        .map_err(peer_error)
    }
}

/// Connect to the peer's listener on the tunnel.
pub async fn connect(addr: IpAddr) -> Result<Connection<zlink::tokio::unix::Stream>, String> {
    let tcp = tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(SocketAddr::new(addr, PEER_PORT)),
    )
    .await
    .map_err(|_| format!("{addr}: timed out"))?
    .map_err(|e| format!("{addr}: {e}"))?;
    let (ours, theirs) = tokio::net::UnixStream::pair().map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let (mut tcp, mut theirs) = (tcp, theirs);
        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut theirs).await;
    });
    let stream: zlink::tokio::unix::Stream =
        ours.try_into().map_err(|e: zlink::Error| e.to_string())?;
    Ok(Connection::new(stream))
}

/// Accept connections from the peer on the tunnel address and splice them
/// onto the peer socket. Rebinds when the configuration changes.
pub async fn listener(core: Core, events: broadcast::Sender<Value>, socket: std::path::PathBuf) {
    let mut bound: Option<(IpAddr, TcpListener)> = None;
    loop {
        let want = with_core_raw(&core, &events, |c| {
            Ok(c.active_document()?
                .and_then(|d| tunnel_addrs(&d, c.node()))
                .map(|a| a.0))
        })
        .await
        .ok()
        .flatten();
        if bound.as_ref().map(|b| b.0) != want {
            bound = None;
            if let Some(addr) = want {
                match TcpListener::bind(SocketAddr::new(addr, PEER_PORT)).await {
                    Ok(l) => {
                        tracing::info!(%addr, port = PEER_PORT, "listening for the peer");
                        bound = Some((addr, l));
                    }
                    // The tunnel address appears once networkd brings it up.
                    Err(e) => tracing::debug!(%addr, error = %e, "peer listener not ready"),
                }
            }
        }
        let Some((_, l)) = &bound else {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        };
        tokio::select! {
            r = l.accept() => {
                if let Ok((mut tcp, from)) = r {
                    let socket = socket.clone();
                    tokio::spawn(async move {
                        match tokio::net::UnixStream::connect(&socket).await {
                            Ok(mut unix) => {
                                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut unix).await;
                            }
                            Err(e) => tracing::warn!(%from, error = %e, "peer socket unavailable"),
                        }
                    });
                }
            }
            () = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
    }
}

fn view_of(h: &HelloReply) -> NodeView {
    NodeView {
        node: h.node.clone(),
        active: h.active.max(0) as u64,
        desired: h.desired.clone(),
        applied: h.applied.clone(),
        lineage: h
            .lineage
            .iter()
            .map(|e| (e.id.max(0) as u64, e.hash.clone()))
            .collect(),
        applying: h.applying,
    }
}

/// Exchange state with the peer and bring it up to date. Runs every ten
/// seconds and whenever a change is applied or confirmed.
pub async fn sync_loop(
    core: Core,
    events: broadcast::Sender<Value>,
    pair: Pair,
    wake: Arc<Notify>,
) {
    loop {
        if let Err(e) = sync_once(&core, &events, &pair).await {
            tracing::debug!(error = %e, "pair sync");
        }
        tokio::select! {
            () = wake.notified() => {}
            () = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
    }
}

fn set_checks(pair: &PairStatus) -> Vec<Check> {
    if !pair.paired {
        return match &pair.peer {
            Some(p) => vec![Check::new(
                "pair",
                Level::Degraded,
                format!(
                    "not paired with {p}: add both nodes' sync keys (from sparewall status) to cluster.sync_keys"
                ),
            )],
            None => vec![],
        };
    }
    let peer = pair.peer.clone().unwrap_or_default();
    let (level, msg) = match &pair.state {
        Some(SyncState::InSync) => (Level::Ok, format!("in sync with {peer}")),
        Some(SyncState::Applying) => (Level::Ok, "applying".to_string()),
        Some(SyncState::ApplyFailed { node }) => (
            Level::Degraded,
            format!("{node} failed to apply the configuration"),
        ),
        Some(SyncState::PeerBehind) => (Level::Degraded, format!("{peer} is behind; pushing")),
        Some(SyncState::LocalBehind) => (Level::Degraded, format!("this node is behind {peer}")),
        Some(SyncState::Diverged) => (
            Level::Degraded,
            format!("diverged from {peer}: resolve with sparewall sync --from <node>"),
        ),
        Some(SyncState::PeerUnreachable) | None => (
            Level::Degraded,
            format!(
                "{peer} unreachable over the sync tunnel{}",
                pair.last_error
                    .as_ref()
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default()
            ),
        ),
        Some(SyncState::Unpaired) => (Level::Degraded, "unpaired".to_string()),
    };
    vec![Check::new("pair", level, msg)]
}

async fn sync_once(
    core: &Core,
    events: &broadcast::Sender<Value>,
    pair: &Pair,
) -> Result<(), String> {
    let (doc, local, pending, node) = with_core_raw(core, events, |c| {
        Ok((
            c.active_document()?,
            c.view()?,
            c.state()?.pending.is_some(),
            c.node().to_string(),
        ))
    })
    .await
    .map_err(|e| e.to_string())?;
    let peer_name = doc
        .as_ref()
        .and_then(|d| d.peer_of(&node))
        .map(str::to_string);
    let addrs = doc.as_ref().and_then(|d| tunnel_addrs(d, &node));
    let mut status = {
        let p = pair.lock().unwrap_or_else(|p| p.into_inner());
        PairStatus {
            role: p.role.clone(),
            ..Default::default()
        }
    };
    status.peer = peer_name.clone();
    if let Some((_, peer_addr, peer)) = addrs {
        status.paired = true;
        match hello(peer_addr, &node).await {
            Ok(h) => {
                status.reachable = true;
                status.peer_image = h.image.clone();
                let pv = view_of(&h);
                let state = sync_state(&local, Some(&pv));
                if state == SyncState::PeerBehind
                    && !pending
                    && !h.pending
                    && let Err(e) = push_missing(core, events, peer_addr, &local, &pv).await
                {
                    tracing::warn!(peer, error = %e, "push to peer failed");
                    status.last_error = Some(e);
                }
                status.state = Some(state);
                status.peer_view = Some(pv);
            }
            Err(e) => {
                status.state = Some(SyncState::PeerUnreachable);
                status.last_error = Some(e);
            }
        }
    }
    let checks = set_checks(&status);
    *pair.lock().unwrap_or_else(|p| p.into_inner()) = status;
    let _ = with_core_raw(core, events, move |c| {
        c.set_extra_checks(checks);
        Ok(())
    })
    .await;
    Ok(())
}

async fn hello(addr: IpAddr, node: &str) -> Result<HelloReply, String> {
    let mut conn = connect(addr).await?;
    let r = tokio::time::timeout(Duration::from_secs(5), conn.hello(node, PEER_PROTOCOL))
        .await
        .map_err(|_| "hello timed out".to_string())?
        .map_err(|e| e.to_string())?;
    r.map_err(|e| e.to_string())
}

async fn push_missing(
    core: &Core,
    events: &broadcast::Sender<Value>,
    addr: IpAddr,
    local: &NodeView,
    peer: &NodeView,
) -> Result<(), String> {
    let Some(plan) = push_plan(local, peer.active, &peer.desired) else {
        return Ok(());
    };
    let mut conn = connect(addr).await?;
    for id in plan {
        let (g, config) = with_core_raw(core, events, move |c| {
            Ok((c.generation(id)?, c.document_value(id)?))
        })
        .await
        .map_err(|e| e.to_string())?;
        tracing::info!(id, peer = %peer.node, "pushing generation to the peer");
        conn.push(&to_peer(&g), &config, None)
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// `sync --from <node>`: take the peer's active generation.
pub async fn take_from_peer(
    core: &Core,
    events: &broadcast::Sender<Value>,
) -> Result<Generation, String> {
    let (doc, node) = with_core_raw(core, events, |c| {
        Ok((c.active_document()?, c.node().to_string()))
    })
    .await
    .map_err(|e| e.to_string())?;
    let (_, addr, _) = doc
        .as_ref()
        .and_then(|d| tunnel_addrs(d, &node))
        .ok_or("this node is not paired")?;
    let mut conn = connect(addr).await?;
    let f = conn
        .fetch(None)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let g = from_peer(&f.generation);
    let g2 = g.clone();
    with_core_raw(core, events, move |c| c.adopt(&g2, f.config))
        .await
        .map_err(|e| e.to_string())?;
    Ok(g)
}

/// `sync --from <this node>`: make the peer adopt this node's generation.
pub async fn give_to_peer(
    core: &Core,
    events: &broadcast::Sender<Value>,
) -> Result<Generation, String> {
    let (doc, node, active) = with_core_raw(core, events, |c| {
        Ok((c.active_document()?, c.node().to_string(), c.active()?))
    })
    .await
    .map_err(|e| e.to_string())?;
    let (_, addr, _) = doc
        .as_ref()
        .and_then(|d| tunnel_addrs(d, &node))
        .ok_or("this node is not paired")?;
    let (g, config) = with_core_raw(core, events, move |c| {
        Ok((c.generation(active)?, c.document_value(active)?))
    })
    .await
    .map_err(|e| e.to_string())?;
    let mut conn = connect(addr).await?;
    conn.push(&to_peer(&g), &config, Some(true))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    Ok(g)
}

/// Ask the peer whether it is reachable, for gating changes.
pub fn reachable(pair: &Pair) -> (bool, bool, Option<SyncState>) {
    let p = pair.lock().unwrap_or_else(|p| p.into_inner());
    (p.paired, p.reachable, p.state.clone())
}
