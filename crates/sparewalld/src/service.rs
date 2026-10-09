//! `org.sparewall.Firewall` served over Varlink.

use std::sync::{Arc, Mutex};

use futures_util::Stream;
use serde_json::{Value, json};
use sparewall_api::{
    ApplyReply, BackupReply, ConfigReply, Empty, EventReply, ExportReply, FirewallError,
    GenerationReply, HealthCheck, HealthReply, HistoryReply, StatusReply, ValidateReply,
};
use sparewall_core::pair::SyncState;
use sparewall_core::{ApplyOptions, ApplyResult, Coordinator, Error, Generation, System};
use tokio::sync::{Notify, broadcast};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use zlink::connection::socket::FetchPeerCredentials;
use zlink::{Reply, service};

use crate::author;
use crate::peer::{Pair, PairStatus};

pub type Core = Arc<Mutex<Coordinator<Box<dyn System>>>>;

/// Kea's lease file in its named volume.
const KEA_LEASES: &str =
    "/var/lib/containers/storage/volumes/sparewall-kea-leases/_data/kea-leases4.csv";

/// The digest of the booted image, from `bootc status`.
pub fn booted_image_digest() -> Option<String> {
    let out = std::process::Command::new("bootc")
        .args(["status", "--format=json"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    let img = &v["status"]["booted"]["image"];
    let digest = img["imageDigest"].as_str()?;
    let name = img["image"]["image"].as_str().unwrap_or_default();
    Some(format!("{name}@{digest}"))
}

/// The Varlink service. Coordinator calls run on the blocking pool, since
/// they shell out to nft and networkctl.
pub struct Firewall {
    core: Core,
    events: broadcast::Sender<Value>,
    pair: Pair,
    sync: Arc<Notify>,
}

impl Firewall {
    pub fn new(
        core: Core,
        events: broadcast::Sender<Value>,
        pair: Pair,
        sync: Arc<Notify>,
    ) -> Self {
        Firewall {
            core,
            events,
            pair,
            sync,
        }
    }

    /// The divergence policy: in a pair, a change needs the peer reachable
    /// (or `allow_diverge`), and a node behind its peer takes no changes.
    fn gate(
        &self,
        allow_diverge: Option<bool>,
        dry_run: Option<bool>,
    ) -> Result<(), FirewallError> {
        if dry_run.unwrap_or(false) {
            return Ok(());
        }
        let (paired, reachable, state) = crate::peer::reachable(&self.pair);
        if !paired {
            return Ok(());
        }
        if state == Some(SyncState::LocalBehind) {
            return Err(FirewallError::ApplyFailed {
                message: "this node is behind its peer and catches up shortly; or run sparewall sync --from <peer>".into(),
            });
        }
        if !reachable && !allow_diverge.unwrap_or(false) {
            let peer = self
                .pair
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .peer
                .clone()
                .unwrap_or_default();
            return Err(FirewallError::PeerUnreachable { peer });
        }
        Ok(())
    }
}

/// Run a coordinator call off the async thread, then publish its events.
pub async fn with_core_raw<T: Send + 'static>(
    core: &Core,
    events: &broadcast::Sender<Value>,
    f: impl FnOnce(&mut Coordinator<Box<dyn System>>) -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    let core = core.clone();
    let (result, evs) = tokio::task::spawn_blocking(move || {
        let mut c = core.lock().unwrap_or_else(|p| p.into_inner());
        let r = f(&mut c);
        (r, c.drain_events())
    })
    .await
    .map_err(|e| Error::Internal(e.to_string()))?;
    for e in evs {
        let v = serde_json::to_value(&e).unwrap_or(Value::Null);
        tracing::info!(event = %v, "event");
        let _ = events.send(v);
    }
    result
}

/// [`with_core_raw`] with errors as the API reports them.
pub async fn with_core<T: Send + 'static>(
    core: &Core,
    events: &broadcast::Sender<Value>,
    f: impl FnOnce(&mut Coordinator<Box<dyn System>>) -> Result<T, Error> + Send + 'static,
) -> Result<T, FirewallError> {
    with_core_raw(core, events, f).await.map_err(to_api_error)
}

pub fn to_api_error(e: Error) -> FirewallError {
    match e {
        Error::Validation(errors) => FirewallError::ValidationFailed { errors },
        Error::Check(m) => FirewallError::ValidationFailed {
            errors: vec![format!("dry run: {m}")],
        },
        Error::Conflict { current } => FirewallError::Conflict {
            current: current as i64,
        },
        Error::NotFound(id) => FirewallError::NotFound { id: id as i64 },
        Error::NotPending(id) => FirewallError::NotPending { id: id as i64 },
        other => FirewallError::ApplyFailed {
            message: other.to_string(),
        },
    }
}

pub fn api_generation(g: &Generation, confirmed: bool) -> sparewall_api::Generation {
    sparewall_api::Generation {
        id: g.id as i64,
        hash: g.hash.clone(),
        base: g.base.map(|b| b as i64),
        schema: i64::from(g.schema),
        author: g.author.clone(),
        applied: g.created.clone(),
        confirmed,
        summary: g.summary.clone(),
    }
}

fn is_confirmed(c: &Coordinator<Box<dyn System>>, id: u64) -> bool {
    c.state()
        .map(|s| s.pending.is_none_or(|p| p.id != id) && id <= s.active.max(s.confirmed))
        .unwrap_or(false)
}

fn apply_reply(c: &Coordinator<Box<dyn System>>, r: ApplyResult) -> ApplyReply {
    let remaining = c
        .pending_remaining()
        .ok()
        .flatten()
        .filter(|(id, _)| *id == r.generation.id && !r.dry_run)
        .map_or(0, |(_, s)| s);
    ApplyReply {
        generation: api_generation(&r.generation, remaining == 0 && !r.dry_run),
        changed: r.changed,
        diff: r.diff,
        warnings: r.warnings,
        unchanged: r.unchanged,
        confirm_seconds: remaining,
    }
}

fn opts(base: i64, confirm: Option<i64>, dry_run: Option<bool>, author: String) -> ApplyOptions {
    ApplyOptions {
        base: base.max(0) as u64,
        confirm_seconds: confirm.map(|s| s.clamp(0, 24 * 3600) as u32),
        author,
        dry_run: dry_run.unwrap_or(false),
    }
}

#[service(
    interface = "org.sparewall.Firewall",
    types = [sparewall_api::Generation, HealthCheck],
    vendor = "Sparewall",
    product = "sparewalld",
    version = env!("CARGO_PKG_VERSION"),
    url = "https://sparewall.org"
)]
impl<Sock> Firewall
where
    Sock::ReadHalf: FetchPeerCredentials,
{
    async fn validate(&mut self, config: Value) -> Result<ValidateReply, FirewallError> {
        let warnings = with_core(&self.core, &self.events, move |c| c.validate(config)).await?;
        Ok(ValidateReply { warnings })
    }

    async fn apply(
        &mut self,
        config: Value,
        base: i64,
        confirm_seconds: Option<i64>,
        dry_run: Option<bool>,
        allow_diverge: Option<bool>,
        #[zlink(connection)] conn: &mut Connection<Sock>,
    ) -> Result<ApplyReply, FirewallError> {
        self.gate(allow_diverge, dry_run)?;
        let o = opts(base, confirm_seconds, dry_run, author::of(conn).await);
        let r = with_core(&self.core, &self.events, move |c| {
            let r = c.apply(config, &o)?;
            Ok(apply_reply(c, r))
        })
        .await;
        self.sync.notify_one();
        r
    }

    async fn merge(
        &mut self,
        patch: Value,
        base: i64,
        confirm_seconds: Option<i64>,
        dry_run: Option<bool>,
        allow_diverge: Option<bool>,
        #[zlink(connection)] conn: &mut Connection<Sock>,
    ) -> Result<ApplyReply, FirewallError> {
        self.gate(allow_diverge, dry_run)?;
        let o = opts(base, confirm_seconds, dry_run, author::of(conn).await);
        let r = with_core(&self.core, &self.events, move |c| {
            let r = c.merge(&patch, &o)?;
            Ok(apply_reply(c, r))
        })
        .await;
        self.sync.notify_one();
        r
    }

    async fn patch(
        &mut self,
        ops: Value,
        base: i64,
        confirm_seconds: Option<i64>,
        dry_run: Option<bool>,
        allow_diverge: Option<bool>,
        #[zlink(connection)] conn: &mut Connection<Sock>,
    ) -> Result<ApplyReply, FirewallError> {
        self.gate(allow_diverge, dry_run)?;
        let o = opts(base, confirm_seconds, dry_run, author::of(conn).await);
        let r = with_core(&self.core, &self.events, move |c| {
            let r = c.patch(&ops, &o)?;
            Ok(apply_reply(c, r))
        })
        .await;
        self.sync.notify_one();
        r
    }

    async fn confirm(&mut self, id: i64) -> Result<Empty, FirewallError> {
        with_core(&self.core, &self.events, move |c| {
            c.confirm(id.max(0) as u64)
        })
        .await?;
        // A confirmed generation goes to the peer.
        self.sync.notify_one();
        Ok(Empty {})
    }

    async fn rollback(&mut self, id: Option<i64>) -> Result<GenerationReply, FirewallError> {
        let g = with_core(&self.core, &self.events, move |c| {
            c.rollback(id.map(|i| i.max(0) as u64))
        })
        .await?;
        self.sync.notify_one();
        Ok(GenerationReply {
            generation: api_generation(&g, true),
        })
    }

    async fn get_config(&mut self, id: Option<i64>) -> Result<ConfigReply, FirewallError> {
        with_core(&self.core, &self.events, move |c| {
            let id = match id {
                Some(i) => i.max(0) as u64,
                None => c.active()?,
            };
            let g = c.generation(id)?;
            Ok(ConfigReply {
                config: c.document_value(id)?,
                generation: api_generation(&g, is_confirmed(c, id)),
            })
        })
        .await
    }

    async fn export(&mut self, id: Option<i64>) -> Result<ExportReply, FirewallError> {
        with_core(&self.core, &self.events, move |c| {
            let id = match id {
                Some(i) => i.max(0) as u64,
                None => c.active()?,
            };
            Ok(ExportReply {
                config: c.document_value(id)?,
            })
        })
        .await
    }

    async fn history(&mut self, limit: Option<i64>) -> Result<HistoryReply, FirewallError> {
        with_core(&self.core, &self.events, move |c| {
            let gens = c.history(limit.map(|l| l.max(0) as usize))?;
            Ok(HistoryReply {
                generations: gens
                    .iter()
                    .map(|g| api_generation(g, is_confirmed(c, g.id)))
                    .collect(),
            })
        })
        .await
    }

    async fn sync(&mut self, from_node: String) -> Result<GenerationReply, FirewallError> {
        let (node, peer) = with_core(&self.core, &self.events, |c| {
            let doc = c.active_document()?;
            Ok((
                c.node().to_string(),
                doc.and_then(|d| d.peer_of(c.node()).map(str::to_string)),
            ))
        })
        .await?;
        let Some(peer) = peer else {
            return Err(FirewallError::NotSupported {
                message: "this node is not in a pair".into(),
            });
        };
        let result = if from_node == peer {
            crate::peer::take_from_peer(&self.core, &self.events).await
        } else if from_node == node {
            crate::peer::give_to_peer(&self.core, &self.events).await
        } else {
            return Err(FirewallError::NotSupported {
                message: format!("{from_node} is neither {node} nor its peer {peer}"),
            });
        };
        let g = result.map_err(|e| {
            if e.contains("timed out") || e.contains("refused") || e.contains("unreachable") {
                FirewallError::PeerUnreachable { peer: peer.clone() }
            } else {
                FirewallError::ApplyFailed { message: e }
            }
        })?;
        self.sync.notify_one();
        Ok(GenerationReply {
            generation: api_generation(&g, true),
        })
    }

    async fn health(&mut self, verbose: Option<bool>) -> Result<HealthReply, FirewallError> {
        let vrrp = self
            .pair
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .role
            .clone();
        let (h, role) = with_core(&self.core, &self.events, move |c| {
            let role = match vrrp {
                Some(r) => r,
                None => role_of(c)?,
            };
            Ok((c.health()?, role))
        })
        .await?;
        Ok(HealthReply {
            level: h.level.as_str().into(),
            role,
            checks: verbose.unwrap_or(false).then(|| {
                h.checks
                    .iter()
                    .map(|c| HealthCheck {
                        name: c.name.clone(),
                        level: c.level.as_str().into(),
                        message: c.message.clone(),
                    })
                    .collect()
            }),
        })
    }

    async fn status(&mut self) -> Result<StatusReply, FirewallError> {
        let pair = self.pair.lock().unwrap_or_else(|p| p.into_inner()).clone();
        with_core(&self.core, &self.events, move |c| status(c, &pair)).await
    }

    async fn backup(&mut self) -> Result<BackupReply, FirewallError> {
        let (path, digest) = with_core(&self.core, &self.events, |c| {
            let src = sparewall_core::backup::Sources {
                leases: KEA_LEASES.into(),
                out_dir: c.store().root().join("backups"),
                image_digest: booted_image_digest(),
            };
            let keep = c
                .active_document()?
                .and_then(|d| d.backup)
                .and_then(|b| b.generations)
                .map_or(sparewall_core::backup::DEFAULT_GENERATIONS, |g| g as usize);
            c.backup(&src, keep)
        })
        .await?;
        Ok(BackupReply {
            path: path.display().to_string(),
            digest,
        })
    }

    #[zlink(more)]
    async fn subscribe(
        &mut self,
        more: bool,
    ) -> impl Stream<Item = Reply<EventReply>> + Unpin + 'static {
        let rx = self.events.subscribe();
        let hello = Reply::new(Some(EventReply {
            event: json!({"type": "subscribed"}),
        }))
        .set_continues(Some(more));
        let rest = BroadcastStream::new(rx).filter_map(move |e| {
            e.ok()
                .map(|event| Reply::new(Some(EventReply { event })).set_continues(Some(true)))
        });
        let rest: std::pin::Pin<Box<dyn Stream<Item = Reply<EventReply>> + Send>> = if more {
            Box::pin(rest)
        } else {
            Box::pin(tokio_stream::empty())
        };
        tokio_stream::once(hello).chain(rest)
    }
}

pub fn role_of(c: &Coordinator<Box<dyn System>>) -> Result<String, Error> {
    Ok(match c.active_document()? {
        None => "bootstrap".into(),
        Some(d) if d.is_pair() => "unknown".into(),
        Some(_) => "standalone".into(),
    })
}

pub fn status(
    c: &mut Coordinator<Box<dyn System>>,
    pair: &PairStatus,
) -> Result<StatusReply, Error> {
    let state = c.state()?;
    let role = match &pair.role {
        Some(r) => r.clone(),
        None => role_of(c)?,
    };
    let (desired, applied) = c.hashes()?;
    let pending = c
        .pending_remaining()?
        .map(|(id, s)| json!({"id": id, "reverts_in": s}));
    let health = c.health()?;
    let links = c.system().link_states();
    let sync_key = c.system().sync_public_key().ok();
    let ct = |c: &mut Coordinator<Box<dyn System>>, k: &str| {
        c.system()
            .proc_sys(&format!("net/netfilter/{k}"))
            .and_then(|s| s.parse::<u64>().ok())
    };
    let ct_count = ct(c, "nf_conntrack_count");
    let ct_max = ct(c, "nf_conntrack_max");
    let sync_state = if pair.peer.is_none() {
        "standalone".to_string()
    } else {
        pair.state
            .as_ref()
            .map_or("unknown".to_string(), |s| s.name().to_string())
    };
    Ok(StatusReply {
        node: c.node().to_string(),
        role,
        sync: json!({
            "active": state.active,
            "confirmed": state.confirmed,
            "pending": pending,
            "desired_hash": desired,
            "applied_hash": applied,
            "state": sync_state,
            "peer": pair.peer,
            "peer_reachable": pair.reachable,
            "peer_active": pair.peer_view.as_ref().map(|v| v.active),
            "peer_desired_hash": pair.peer_view.as_ref().map(|v| v.desired.clone()),
            "peer_applied_hash": pair.peer_view.as_ref().and_then(|v| v.applied.clone()),
            "peer_image": pair.peer_image,
            "sync_public_key": sync_key,
            "last_error": pair.last_error,
            "last_apply_ms": c.last_apply_ms(),
        }),
        links: serde_json::to_value(links).unwrap_or_default(),
        vrrp: json!({"role": pair.role}),
        conntrack: json!({"count": ct_count, "max": ct_max}),
        services: json!({}),
        tls: json!({"fingerprint": crate::http::FINGERPRINT.get()}),
        health: serde_json::to_value(&health).unwrap_or_default(),
    })
}
