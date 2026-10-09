//! `org.sparewall.Firewall` served over Varlink.

use std::sync::{Arc, Mutex};

use futures_util::Stream;
use serde_json::{Value, json};
use sparewall_api::{
    ApplyReply, BackupReply, ConfigReply, Empty, EventReply, ExportReply, FirewallError,
    GenerationReply, HealthCheck, HealthReply, HistoryReply, StatusReply, ValidateReply,
};
use sparewall_core::{ApplyOptions, ApplyResult, Coordinator, Error, Generation, System};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use zlink::connection::socket::FetchPeerCredentials;
use zlink::{Reply, service};

use crate::author;

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
}

impl Firewall {
    pub fn new(core: Core, events: broadcast::Sender<Value>) -> Self {
        Firewall { core, events }
    }
}

/// Run a coordinator call off the async thread, then publish its events.
pub async fn with_core<T: Send + 'static>(
    core: &Core,
    events: &broadcast::Sender<Value>,
    f: impl FnOnce(&mut Coordinator<Box<dyn System>>) -> Result<T, Error> + Send + 'static,
) -> Result<T, FirewallError> {
    let core = core.clone();
    let (result, evs) = tokio::task::spawn_blocking(move || {
        let mut c = core.lock().unwrap_or_else(|p| p.into_inner());
        let r = f(&mut c);
        (r, c.drain_events())
    })
    .await
    .map_err(|e| FirewallError::ApplyFailed {
        message: format!("internal: {e}"),
    })?;
    for e in evs {
        let v = serde_json::to_value(&e).unwrap_or(Value::Null);
        tracing::info!(event = %v, "event");
        let _ = events.send(v);
    }
    result.map_err(to_api_error)
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
        #[zlink(connection)] conn: &mut Connection<Sock>,
    ) -> Result<ApplyReply, FirewallError> {
        let o = opts(base, confirm_seconds, dry_run, author::of(conn).await);
        with_core(&self.core, &self.events, move |c| {
            let r = c.apply(config, &o)?;
            Ok(apply_reply(c, r))
        })
        .await
    }

    async fn merge(
        &mut self,
        patch: Value,
        base: i64,
        confirm_seconds: Option<i64>,
        dry_run: Option<bool>,
        #[zlink(connection)] conn: &mut Connection<Sock>,
    ) -> Result<ApplyReply, FirewallError> {
        let o = opts(base, confirm_seconds, dry_run, author::of(conn).await);
        with_core(&self.core, &self.events, move |c| {
            let r = c.merge(&patch, &o)?;
            Ok(apply_reply(c, r))
        })
        .await
    }

    async fn patch(
        &mut self,
        ops: Value,
        base: i64,
        confirm_seconds: Option<i64>,
        dry_run: Option<bool>,
        #[zlink(connection)] conn: &mut Connection<Sock>,
    ) -> Result<ApplyReply, FirewallError> {
        let o = opts(base, confirm_seconds, dry_run, author::of(conn).await);
        with_core(&self.core, &self.events, move |c| {
            let r = c.patch(&ops, &o)?;
            Ok(apply_reply(c, r))
        })
        .await
    }

    async fn confirm(&mut self, id: i64) -> Result<Empty, FirewallError> {
        with_core(&self.core, &self.events, move |c| {
            c.confirm(id.max(0) as u64)
        })
        .await?;
        Ok(Empty {})
    }

    async fn rollback(&mut self, id: Option<i64>) -> Result<GenerationReply, FirewallError> {
        let g = with_core(&self.core, &self.events, move |c| {
            c.rollback(id.map(|i| i.max(0) as u64))
        })
        .await?;
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
        Err(FirewallError::NotSupported {
            message: format!("sync --from {from_node}: HA pairs arrive in milestone 3"),
        })
    }

    async fn health(&mut self, verbose: Option<bool>) -> Result<HealthReply, FirewallError> {
        let (h, role) = with_core(&self.core, &self.events, |c| {
            let role = role_of(c)?;
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
        with_core(&self.core, &self.events, status).await
    }

    async fn backup(&mut self) -> Result<BackupReply, FirewallError> {
        let (path, digest) = with_core(&self.core, &self.events, |c| {
            let src = sparewall_core::backup::Sources {
                leases: KEA_LEASES.into(),
                out_dir: c.store().root().join("backups"),
                image_digest: booted_image_digest(),
            };
            let keep = c
                .active()
                .ok()
                .filter(|id| *id != 0)
                .and_then(|id| c.store().document(id).ok())
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
    let active = c.active()?;
    if active == 0 {
        return Ok("bootstrap".into());
    }
    let doc = c.store().document(active)?;
    Ok(if doc.is_pair() {
        "unknown".into()
    } else {
        "standalone".into()
    })
}

pub fn status(c: &mut Coordinator<Box<dyn System>>) -> Result<StatusReply, Error> {
    let state = c.state()?;
    let role = role_of(c)?;
    let (desired, applied) = c.hashes()?;
    let pending = c
        .pending_remaining()?
        .map(|(id, s)| json!({"id": id, "reverts_in": s}));
    let health = c.health()?;
    let links = c.system().link_states();
    let ct = |k: &str| {
        std::fs::read_to_string(format!("/proc/sys/net/netfilter/{k}"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
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
            "state": "standalone",
            "last_apply_ms": c.last_apply_ms(),
        }),
        links: serde_json::to_value(links).unwrap_or_default(),
        vrrp: json!({}),
        conntrack: json!({"count": ct("nf_conntrack_count"), "max": ct("nf_conntrack_max")}),
        services: json!({}),
        tls: json!({"fingerprint": crate::http::FINGERPRINT.get()}),
        health: serde_json::to_value(&health).unwrap_or_default(),
    })
}
