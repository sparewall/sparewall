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
    PeerProxy, PeerSecret, PeerSecretsProxy, PushReply, PutSecretsReply, UpgradeReply,
};
use sparewall_core::pair::{NodeView, SyncState, push_plan, sync_state};
use sparewall_core::secrets::{SecretClass, SecretInfo, SharedSecret};
use sparewall_core::{Check, Error, Generation, Level};
use tokio::net::{TcpListener, TcpSocket};
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
    /// Cluster secret versions last delivered to the peer.
    #[serde(skip)]
    pub secrets_sent: Vec<(String, u64)>,
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
/// The two ends of the sync tunnel, as this node sees them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    pub own: IpAddr,
    pub peer: IpAddr,
}

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
    pair: Pair,
}

impl PeerService {
    pub fn new(
        core: Core,
        events: broadcast::Sender<Value>,
        sync: Arc<Notify>,
        pair: Pair,
    ) -> Self {
        PeerService {
            core,
            events,
            sync,
            pair,
        }
    }
}

#[service(interface = "org.sparewall.Peer", types = [PeerGeneration, LineageEntry, PeerSecret])]
impl PeerService {
    async fn hello(&mut self, node: String, protocol: i64) -> Result<HelloReply, PeerError> {
        let role = self
            .pair
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .role
            .clone();
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
            let health = c.health()?.level.as_str().to_string();
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
                health: Some(health),
                role,
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
        activate: Option<bool>,
    ) -> Result<PushReply, PeerError> {
        let g = from_peer(&generation);
        let active = with_core_raw(&self.core, &self.events, move |c| {
            if force.unwrap_or(false) {
                c.adopt(&g, config)?;
            } else if activate.unwrap_or(true) {
                c.receive(&g, config)?;
            } else {
                c.receive_history(&g, config)?;
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

    async fn put_secrets(
        &mut self,
        secrets: Vec<PeerSecret>,
    ) -> Result<PutSecretsReply, PeerError> {
        let mut shared = Vec::new();
        for s in secrets {
            let value = hex::decode(&s.value).map_err(|e| PeerError::Rejected {
                message: format!("secret {}: {e}", s.name),
            })?;
            shared.push(SharedSecret {
                info: SecretInfo {
                    name: s.name,
                    class: SecretClass::Cluster,
                    version: s.version.max(0) as u64,
                    updated: s.updated,
                },
                value,
            });
        }
        let stored = with_core_raw(&self.core, &self.events, move |c| {
            let changed = c.receive_secrets(shared)?;
            // Keys for the live generation may have just arrived.
            if !changed.is_empty() {
                c.refresh_vpn_keys(&changed)?;
            }
            Ok(changed.len())
        })
        .await
        .map_err(peer_error)?;
        Ok(PutSecretsReply {
            stored: stored as i64,
        })
    }

    async fn upgrade(&mut self, image: String) -> Result<UpgradeReply, PeerError> {
        let staged = tokio::task::spawn_blocking(move || crate::upgrade::stage(&image))
            .await
            .map_err(|e| PeerError::Rejected {
                message: e.to_string(),
            })?
            .map_err(|message| PeerError::Rejected { message })?;
        let Some(staged) = staged else {
            return Err(PeerError::Rejected {
                message: "already running the newest image".into(),
            });
        };
        crate::upgrade::reboot_soon().map_err(|message| PeerError::Rejected { message })?;
        Ok(UpgradeReply { staged })
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

/// Connect to the peer's listener on the tunnel, from this node's own
/// tunnel address (the peer accepts no other source).
pub async fn connect(link: Link) -> Result<Connection<zlink::tokio::unix::Stream>, String> {
    let addr = link.peer;
    let sock = match addr {
        IpAddr::V4(_) => TcpSocket::new_v4(),
        IpAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|e| e.to_string())?;
    sock.bind(SocketAddr::new(link.own, 0))
        .map_err(|e| format!("{}: {e}", link.own))?;
    let tcp = tokio::time::timeout(
        Duration::from_secs(3),
        sock.connect(SocketAddr::new(addr, PEER_PORT)),
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

/// Listen for the peer on this node's tunnel address. With `device`, the
/// socket is also bound to the tunnel interface (`SO_BINDTODEVICE`): the
/// kernel then delivers only connections that arrived through WireGuard,
/// whatever the firewall policy lets reach the address from elsewhere.
pub fn bind_peer(addr: IpAddr, device: Option<&str>) -> std::io::Result<TcpListener> {
    let s = match addr {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    s.set_reuseaddr(true)?;
    if let Some(d) = device {
        s.bind_device(Some(d.as_bytes()))?;
    }
    s.bind(SocketAddr::new(addr, PEER_PORT))?;
    s.listen(16)
}

/// Whether an accepted connection comes from the peer. WireGuard only
/// accepts the peer's tunnel address from the peer's key, so on the
/// tunnel interface the source address is the peer's identity.
pub fn from_peer_addr(link: &Link, from: SocketAddr) -> bool {
    from.ip() == link.peer
}

/// The peer listener's binding, kept in line with the configuration and
/// with the tunnel interface itself.
pub struct PeerListener {
    device: Option<String>,
    bound: Option<(Link, TcpListener)>,
}

impl PeerListener {
    /// `device` is the tunnel interface (`None` only for `--fake-system`).
    pub fn new(device: Option<String>) -> PeerListener {
        PeerListener {
            device,
            bound: None,
        }
    }

    /// Whether the socket is still bound to the live tunnel interface.
    /// `SO_BINDTODEVICE` stores an interface index: when networkd deletes
    /// and recreates `swsync` (a new sync key, a rollback), the old index
    /// no longer resolves and the socket would never see the peer again.
    fn attached(&self, l: &TcpListener) -> bool {
        match &self.device {
            None => true,
            Some(d) => {
                socket2::SockRef::from(l).device().ok().flatten().as_deref() == Some(d.as_bytes())
            }
        }
    }

    /// Bind (or rebind) for `want`: when the tunnel addresses change, when
    /// the interface was recreated, and until the interface and its
    /// address exist.
    pub fn refresh(&mut self, want: Option<Link>) {
        let current = self.bound.as_ref().map(|b| b.0);
        let stale = self.bound.as_ref().is_some_and(|(_, l)| !self.attached(l));
        if current == want && !stale {
            return;
        }
        if stale {
            tracing::info!(device = ?self.device, "the tunnel interface was recreated: rebinding");
        }
        self.bound = None;
        let Some(link) = want else { return };
        match bind_peer(link.own, self.device.as_deref()) {
            Ok(l) => {
                tracing::info!(addr = %link.own, port = PEER_PORT, device = ?self.device, "listening for the peer");
                self.bound = Some((link, l));
            }
            // The tunnel address appears once networkd brings it up.
            Err(e) => tracing::debug!(addr = %link.own, error = %e, "peer listener not ready"),
        }
    }

    /// Wait up to `wait` for a connection from the peer; connections from
    /// any other source are refused.
    pub async fn accept(&self, wait: Duration) -> Option<(tokio::net::TcpStream, SocketAddr)> {
        let Some((link, l)) = &self.bound else {
            tokio::time::sleep(wait).await;
            return None;
        };
        let (tcp, from) = tokio::time::timeout(wait, l.accept()).await.ok()?.ok()?;
        if !from_peer_addr(link, from) {
            tracing::warn!(%from, expected = %link.peer, "refused a peer connection from another address");
            return None;
        }
        Some((tcp, from))
    }
}

/// Accept connections from the peer on the tunnel and splice them onto the
/// peer socket. `device` is the tunnel interface (`None` only for
/// `--fake-system` tests).
pub async fn listener(
    core: Core,
    events: broadcast::Sender<Value>,
    socket: std::path::PathBuf,
    device: Option<String>,
) {
    let mut pl = PeerListener::new(device);
    loop {
        let want = with_core_raw(&core, &events, |c| {
            Ok(c.active_document()?
                .and_then(|d| tunnel_addrs(&d, c.node()))
                .map(|(own, peer, _)| Link { own, peer }))
        })
        .await
        .ok()
        .flatten();
        pl.refresh(want);
        if let Some((mut tcp, from)) = pl.accept(Duration::from_secs(5)).await {
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
            secrets_sent: p.secrets_sent.clone(),
            ..Default::default()
        }
    };
    status.peer = peer_name.clone();
    if let Some((own, peer_addr, peer)) = addrs {
        let link = Link {
            own,
            peer: peer_addr,
        };
        status.paired = true;
        match hello(link, &node).await {
            Ok(h) => {
                status.reachable = true;
                status.peer_image = h.image.clone();
                if let Err(e) = send_secrets(core, events, link, &mut status.secrets_sent).await {
                    tracing::warn!(peer, error = %e, "sending secrets to the peer failed");
                    status.last_error = Some(e);
                }
                let pv = view_of(&h);
                let state = sync_state(&local, Some(&pv));
                if state == SyncState::PeerBehind
                    && !pending
                    && !h.pending
                    && let Err(e) = push_missing(core, events, link, &local, &pv).await
                {
                    tracing::warn!(peer, error = %e, "push to peer failed");
                    status.last_error = Some(e);
                }
                status.state = Some(state);
                status.peer_view = Some(pv);
            }
            Err(e) => {
                // Resend everything once it is back (it may be a new node).
                status.secrets_sent.clear();
                status.state = Some(SyncState::PeerUnreachable);
                status.last_error = Some(e);
            }
        }
    }
    let checks = set_checks(&status);
    {
        // The role belongs to the keepalived reader, which may have moved
        // it while this pass was talking to the peer: keep its value.
        let mut p = pair.lock().unwrap_or_else(|p| p.into_inner());
        status.role = p.role.take();
        *p = status;
    }
    let _ = with_core_raw(core, events, move |c| {
        c.set_extra_checks(checks);
        Ok(())
    })
    .await;
    Ok(())
}

/// Deliver cluster secrets whose versions the peer has not had from us.
async fn send_secrets(
    core: &Core,
    events: &broadcast::Sender<Value>,
    link: Link,
    sent: &mut Vec<(String, u64)>,
) -> Result<(), String> {
    let list = with_core_raw(core, events, |c| c.secret_list())
        .await
        .map_err(|e| e.to_string())?;
    let now: Vec<(String, u64)> = list
        .iter()
        .filter(|i| i.class == SecretClass::Cluster)
        .map(|i| (i.name.clone(), i.version))
        .collect();
    if now.is_empty() || now == *sent {
        return Ok(());
    }
    let shared = with_core_raw(core, events, |c| c.cluster_secrets())
        .await
        .map_err(|e| e.to_string())?;
    let secrets: Vec<PeerSecret> = shared
        .into_iter()
        .map(|s| PeerSecret {
            name: s.info.name,
            version: s.info.version as i64,
            updated: s.info.updated,
            value: hex::encode(s.value),
        })
        .collect();
    let mut conn = connect(link).await?;
    conn.put_secrets(secrets)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    *sent = now;
    Ok(())
}

async fn hello(link: Link, node: &str) -> Result<HelloReply, String> {
    let mut conn = connect(link).await?;
    let r = tokio::time::timeout(Duration::from_secs(5), conn.hello(node, PEER_PROTOCOL))
        .await
        .map_err(|_| "hello timed out".to_string())?
        .map_err(|e| e.to_string())?;
    r.map_err(|e| e.to_string())
}

async fn push_missing(
    core: &Core,
    events: &broadcast::Sender<Value>,
    link: Link,
    local: &NodeView,
    peer: &NodeView,
) -> Result<(), String> {
    let Some(plan) = push_plan(local, peer.active, &peer.desired) else {
        return Ok(());
    };
    let mut conn = connect(link).await?;
    // Only the last generation runs on the peer; the ones before it are
    // history (after a rollback, one of them is what was rolled back).
    let last = plan.last().copied();
    for id in plan {
        let (g, config) = with_core_raw(core, events, move |c| {
            Ok((c.generation(id)?, c.document_value(id)?))
        })
        .await
        .map_err(|e| e.to_string())?;
        tracing::info!(id, peer = %peer.node, "pushing generation to the peer");
        let activate = (Some(id) != last).then_some(false);
        conn.push(&to_peer(&g), &config, None, activate)
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
    let (own, peer, _) = doc
        .as_ref()
        .and_then(|d| tunnel_addrs(d, &node))
        .ok_or("this node is not paired")?;
    let link = Link { own, peer };
    let mut conn = connect(link).await?;
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
    let (own, peer, _) = doc
        .as_ref()
        .and_then(|d| tunnel_addrs(d, &node))
        .ok_or("this node is not paired")?;
    let link = Link { own, peer };
    let (g, config) = with_core_raw(core, events, move |c| {
        Ok((c.generation(active)?, c.document_value(active)?))
    })
    .await
    .map_err(|e| e.to_string())?;
    let mut conn = connect(link).await?;
    conn.push(&to_peer(&g), &config, Some(true), None)
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
