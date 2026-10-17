//! `org.sparewall.Firewall` served over Varlink.

use std::sync::{Arc, Mutex};

use futures_util::Stream;
use serde_json::{Value, json};
use sparewall_api::{
    ApplyReply, BackupReply, ConfigReply, Empty, EventReply, ExportReply, FirewallError,
    GenerationReply, HealthCheck, HealthReply, HistoryReply, SecretInfo, SecretListReply,
    SecretSetReply, StatusReply, TokenCreateReply, TokenInfo, TokenListReply, UpgradeCheckReply,
    UpgradeStartReply, ValidateReply, VpnConfigReply,
};
use sparewall_core::pair::SyncState;
use sparewall_core::secrets::SecretClass;
use sparewall_core::tokens::Role;
use sparewall_core::{ApplyOptions, ApplyResult, Coordinator, Error, Generation, System};
use tokio::sync::{Notify, broadcast};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use zlink::connection::socket::FetchPeerCredentials;
use zlink::{Reply, service};

use crate::author;
use crate::peer::{Pair, PairStatus};

pub type Core = Arc<Mutex<Coordinator<Box<dyn System>>>>;

/// The booted image (`name@digest`), looked up once by
/// [`lookup_booted_image`]; fixed for the life of the boot.
static BOOTED: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The digest of the booted image, once known. Never blocks: request
/// handlers call this.
pub fn booted_image_digest() -> Option<String> {
    BOOTED.get().cloned()
}

/// Ask bootc (outside the sandbox) for the booted image, retrying for a
/// while during boot. Blocking; run it off the async workers.
pub fn lookup_booted_image() {
    for _ in 0..20 {
        let found = crate::upgrade::host_run("bootc", &["status", "--format=json"])
            .ok()
            .and_then(|out| {
                let v: Value = serde_json::from_str(&out).ok()?;
                let img = &v["status"]["booted"]["image"];
                let digest = img["imageDigest"].as_str()?;
                let name = img["image"]["image"].as_str().unwrap_or_default();
                Some(format!("{name}@{digest}"))
            });
        if let Some(b) = found {
            let _ = BOOTED.set(b);
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(15));
    }
    tracing::warn!("cannot read the booted image from bootc status");
}

/// The Varlink service. Coordinator calls run on the blocking pool, since
/// they shell out to nft and networkctl. Each connection is served by its
/// own clone (`varlink::serve`), so calls from different clients overlap.
#[derive(Clone)]
pub struct Firewall {
    core: Core,
    events: broadcast::Sender<Value>,
    pair: Pair,
    sync: Arc<Notify>,
    /// Held for the whole of a call that changes the configuration, so
    /// changes still run one at a time: a sync-link change must not have
    /// another land between the peer taking it and it running here.
    changes: Arc<tokio::sync::Mutex<()>>,
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
            changes: Default::default(),
        }
    }

    /// The divergence policy: in a pair, a change needs the peer reachable
    /// (or `allow_diverge`), and a node behind its peer takes no changes.
    /// Returns whether the peer is reachable, so a change to the sync link
    /// can go to it first.
    fn gate(
        &self,
        allow_diverge: Option<bool>,
        dry_run: Option<bool>,
    ) -> Result<bool, FirewallError> {
        if dry_run.unwrap_or(false) {
            return Ok(false);
        }
        let (paired, reachable, state) = crate::peer::reachable(&self.pair);
        if !paired {
            return Ok(false);
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
        Ok(reachable)
    }

    /// Finish a change. One to the sync link was only stored: push it to
    /// the peer through the current link, then run it here.
    async fn finish(
        &self,
        r: Result<ApplyResult, FirewallError>,
        window: Option<i64>,
    ) -> Result<ApplyReply, FirewallError> {
        let r = r?;
        if r.staged {
            self.run_staged(r.generation.id, window).await?;
        }
        self.sync.notify_one();
        with_core(&self.core, &self.events, move |c| Ok(apply_reply(c, r))).await
    }

    async fn run_staged(&self, id: u64, window: Option<i64>) -> Result<(), FirewallError> {
        match crate::peer::push_first(&self.core, &self.events, id).await {
            Ok(crate::peer::PushFirst::Taken) => {}
            Ok(crate::peer::PushFirst::Unknown(e)) => {
                tracing::warn!(id, error = %e, "no reply to the sync-link push; running it, the peer's confirmation decides");
            }
            Err(e) => {
                let _ = with_core(&self.core, &self.events, move |c| c.discard_staged(id)).await;
                return Err(FirewallError::ApplyFailed {
                    message: format!(
                        "the change alters the sync link, so the peer takes it first, \
                         but it did not: {e}. Nothing changed"
                    ),
                });
            }
        }
        let w = window.unwrap_or(0).clamp(0, 24 * 3600) as u32;
        with_core(&self.core, &self.events, move |c| c.activate_staged(id, w)).await
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

/// A rollback under one coordinator lock: whether it only discards an
/// unconfirmed change (which never left this node, so needs no peer) is
/// decided in the same critical section that rolls back, so neither the
/// confirm-window ticker nor a confirmation can change the answer in
/// between. Any other rollback is a change the peer receives, and must
/// have passed the divergence `gate`.
/// Returns the generation, and whether it changes the sync link and was
/// only stored, to go to the peer first.
pub fn gated_rollback(
    c: &mut Coordinator<Box<dyn System>>,
    target: Option<u64>,
    author: &str,
    gate: Result<bool, FirewallError>,
) -> Result<Result<(Generation, bool), FirewallError>, Error> {
    let reachable = match gate {
        Ok(r) => r,
        Err(e) if !c.rollback_is_local(target)? => return Ok(Err(e)),
        Err(_) => false,
    };
    c.rollback_staging(target, author, reachable).map(Ok)
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

fn opts(
    base: i64,
    confirm: Option<i64>,
    dry_run: Option<bool>,
    author: String,
    peer_reachable: bool,
) -> ApplyOptions {
    ApplyOptions {
        stage_sync_link: peer_reachable,
        base: base.max(0) as u64,
        confirm_seconds: confirm.map(|s| s.clamp(0, 24 * 3600) as u32),
        author,
        dry_run: dry_run.unwrap_or(false),
        note: None,
    }
}

#[service(
    vendor = "Sparewall",
    product = "sparewalld",
    version = env!("CARGO_PKG_VERSION"),
    url = "https://sparewall.org"
)]
impl<Sock> Firewall
where
    Sock::ReadHalf: FetchPeerCredentials,
{
    #[zlink(interface = "org.sparewall.Firewall", types = [sparewall_api::Generation, HealthCheck])]
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
        let _change = self.changes.lock().await;
        let reachable = self.gate(allow_diverge, dry_run)?;
        let o = opts(
            base,
            confirm_seconds,
            dry_run,
            author::of(conn).await,
            reachable,
        );
        let r = with_core(&self.core, &self.events, move |c| c.apply(config, &o)).await;
        self.finish(r, confirm_seconds).await
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
        let _change = self.changes.lock().await;
        let reachable = self.gate(allow_diverge, dry_run)?;
        let o = opts(
            base,
            confirm_seconds,
            dry_run,
            author::of(conn).await,
            reachable,
        );
        let r = with_core(&self.core, &self.events, move |c| c.merge(&patch, &o)).await;
        self.finish(r, confirm_seconds).await
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
        let _change = self.changes.lock().await;
        let reachable = self.gate(allow_diverge, dry_run)?;
        let o = opts(
            base,
            confirm_seconds,
            dry_run,
            author::of(conn).await,
            reachable,
        );
        let r = with_core(&self.core, &self.events, move |c| c.patch(&ops, &o)).await;
        self.finish(r, confirm_seconds).await
    }

    async fn confirm(&mut self, id: i64) -> Result<Empty, FirewallError> {
        let _change = self.changes.lock().await;
        with_core(&self.core, &self.events, move |c| {
            c.confirm(id.max(0) as u64)
        })
        .await?;
        // A confirmed generation goes to the peer.
        self.sync.notify_one();
        Ok(Empty {})
    }

    async fn rollback(
        &mut self,
        id: Option<i64>,
        allow_diverge: Option<bool>,
        #[zlink(connection)] conn: &mut Connection<Sock>,
    ) -> Result<GenerationReply, FirewallError> {
        let _change = self.changes.lock().await;
        let target = id.map(|i| i.max(0) as u64);
        // Evaluated now, applied below only if the rollback reaches the peer.
        let gate = self.gate(allow_diverge, None);
        let author = author::of(conn).await;
        let (g, staged) = with_core_raw(&self.core, &self.events, move |c| {
            gated_rollback(c, target, &author, gate)
        })
        .await
        .map_err(to_api_error)??;
        if staged {
            self.run_staged(g.id, None).await?;
        }
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
        let _change = self.changes.lock().await;
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

    async fn ack_health(
        &mut self,
        name: String,
        #[zlink(connection)] conn: &mut Connection<Sock>,
    ) -> Result<Empty, FirewallError> {
        let by = author::of(conn).await;
        crate::selinux::acknowledge(&self.core, &self.events, name, by).await?;
        Ok(Empty {})
    }

    async fn status(&mut self) -> Result<StatusReply, FirewallError> {
        let pair = self.pair.lock().unwrap_or_else(|p| p.into_inner()).clone();
        with_core(&self.core, &self.events, move |c| status(c, &pair)).await
    }

    async fn backup(&mut self) -> Result<BackupReply, FirewallError> {
        crate::backup::run(&self.core, &self.events).await
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

    async fn vpn_client_config(
        &mut self,
        instance: Option<String>,
        peer: String,
        port: Option<i64>,
    ) -> Result<VpnConfigReply, FirewallError> {
        let port = port.map(|p| u16::try_from(p).unwrap_or(0));
        let config = with_core(&self.core, &self.events, move |c| {
            c.vpn_client_config(instance.as_deref(), &peer, port)
        })
        .await?;
        Ok(VpnConfigReply { config })
    }

    #[zlink(interface = "org.sparewall.Secrets", types = [SecretInfo], rename = "Set")]
    async fn secret_set(
        &mut self,
        name: String,
        value: String,
        cluster: Option<bool>,
    ) -> Result<SecretSetReply, FirewallError> {
        let class = if cluster.unwrap_or(true) {
            SecretClass::Cluster
        } else {
            SecretClass::Node
        };
        let info = with_core(&self.core, &self.events, move |c| {
            let info = c.secret_set(&name, value.as_bytes(), class)?;
            // A key the live remote-access VPN uses (a server key, or a
            // peer's preshared key) takes effect now.
            c.refresh_vpn_keys(std::slice::from_ref(&name))?;
            Ok(info)
        })
        .await?;
        self.sync.notify_one();
        Ok(SecretSetReply {
            secret: api_secret(&info),
        })
    }

    #[zlink(rename = "List")]
    async fn secret_list(&mut self) -> Result<SecretListReply, FirewallError> {
        let list = with_core(&self.core, &self.events, |c| c.secret_list()).await?;
        Ok(SecretListReply {
            secrets: list.iter().map(api_secret).collect(),
        })
    }

    #[zlink(interface = "org.sparewall.Upgrade", rename = "Check")]
    async fn upgrade_check(
        &mut self,
        channel: Option<String>,
        image: Option<String>,
    ) -> Result<UpgradeCheckReply, FirewallError> {
        let doc_channel = with_core(&self.core, &self.events, |c| {
            Ok(c.active_document()?
                .and_then(|d| d.updates)
                .and_then(|u| u.channel))
        })
        .await?;
        let tracked = crate::upgrade::tracked_ref();
        let target = crate::upgrade::target_ref(
            image.as_deref(),
            channel.as_deref(),
            doc_channel.as_deref(),
            tracked.as_deref(),
        );
        let available = if tracked.as_deref() == Some(target.as_str()) {
            let out = tokio::task::spawn_blocking(|| {
                crate::upgrade::host_run("bootc", &["upgrade", "--check"])
            })
            .await
            .map_err(|e| FirewallError::ApplyFailed {
                message: e.to_string(),
            })?;
            match &out {
                Ok(o) => !o.contains("No changes") && !o.contains("No update available"),
                Err(_) => false,
            }
        } else {
            // Moving to another channel or image is always a change.
            true
        };
        Ok(UpgradeCheckReply {
            booted: booted_image_digest(),
            target,
            available,
        })
    }

    #[zlink(rename = "Start")]
    async fn upgrade_start(
        &mut self,
        channel: Option<String>,
        image: Option<String>,
    ) -> Result<UpgradeStartReply, FirewallError> {
        let _change = self.changes.lock().await;
        let (target, peer, plan) =
            crate::upgrade::plan(&self.core, &self.events, &self.pair, channel, image)
                .await
                .map_err(|message| FirewallError::ApplyFailed { message })?;
        tokio::spawn(crate::upgrade::run(
            self.core.clone(),
            self.events.clone(),
            target,
            peer,
        ));
        Ok(UpgradeStartReply { plan })
    }

    #[zlink(interface = "org.sparewall.Auth", types = [TokenInfo])]
    async fn create_token(
        &mut self,
        name: String,
        role: String,
        expires_days: Option<i64>,
    ) -> Result<TokenCreateReply, FirewallError> {
        let role = Role::parse(&role).ok_or_else(|| FirewallError::ValidationFailed {
            errors: vec![format!(
                "role must be monitor, viewer, operator or admin, not {role:?}"
            )],
        })?;
        let ttl = expires_days.map(|d| d.clamp(1, 3650) as u32);
        let (token, info) = with_core(&self.core, &self.events, move |c| {
            c.token_create(&name, role, ttl)
        })
        .await?;
        Ok(TokenCreateReply {
            token,
            info: api_token(&info),
        })
    }

    async fn list_tokens(&mut self) -> Result<TokenListReply, FirewallError> {
        let t = with_core(&self.core, &self.events, |c| c.tokens()).await?;
        Ok(TokenListReply {
            tokens: t.iter().map(api_token).collect(),
        })
    }

    async fn revoke_token(&mut self, name: String) -> Result<Empty, FirewallError> {
        let existed = with_core(&self.core, &self.events, move |c| c.token_revoke(&name)).await?;
        if !existed {
            return Err(FirewallError::NotSupported {
                message: "no such token".into(),
            });
        }
        Ok(Empty {})
    }

    #[zlink(interface = "org.sparewall.Secrets", rename = "Delete")]
    async fn secret_delete(&mut self, name: String) -> Result<Empty, FirewallError> {
        let existed = with_core(&self.core, &self.events, move |c| c.secret_delete(&name)).await?;
        if !existed {
            return Err(FirewallError::NotSupported {
                message: "no such secret".into(),
            });
        }
        Ok(Empty {})
    }
}

pub fn api_token(t: &sparewall_core::tokens::TokenInfo) -> TokenInfo {
    TokenInfo {
        name: t.name.clone(),
        role: t.role.as_str().into(),
        created: t.created.clone(),
        expires: t.expires,
        last_used: t.last_used.clone(),
    }
}

pub fn api_secret(i: &sparewall_core::secrets::SecretInfo) -> SecretInfo {
    SecretInfo {
        name: i.name.clone(),
        class: match i.class {
            SecretClass::Node => "node".into(),
            SecretClass::Cluster => "cluster".into(),
        },
        version: i.version as i64,
        updated: i.updated.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use sparewall_config::identity::{BootstrapPort, Identity};
    use sparewall_core::Store;
    use sparewall_core::system::Fake;

    fn node() -> (tempfile::TempDir, Coordinator<Box<dyn System>>) {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity {
            node: "fw1".into(),
            ssh_keys: vec![],
            management: BootstrapPort {
                nic: "52:54:00:aa:00:01".into(),
                vlan: None,
                address: None,
                gateway: None,
                dns: vec![],
            },
        };
        let mut c = Coordinator::new(
            Store::open(dir.path()).unwrap(),
            Box::new(Fake::default()) as Box<dyn System>,
            id,
        );
        c.boot(false).unwrap();
        (dir, c)
    }

    fn doc(mtu: u32) -> Value {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/standalone.yaml"
        ))
        .unwrap();
        let mut v = sparewall_config::parse_value(&text, sparewall_config::Format::Yaml).unwrap();
        v["networks"]["users"]["mtu"] = json!(mtu);
        v
    }

    fn apply(c: &mut Coordinator<Box<dyn System>>, mtu: u32, confirm: Option<u32>) {
        let base = c.active().unwrap();
        c.apply(
            doc(mtu),
            &ApplyOptions {
                base,
                confirm_seconds: confirm,
                author: "test".into(),
                ..Default::default()
            },
        )
        .unwrap();
    }

    /// Generations 1 and 2 confirmed; 3 waiting for confirmation (revert
    /// target 2).
    fn with_pending() -> (tempfile::TempDir, Coordinator<Box<dyn System>>) {
        let (d, mut c) = node();
        apply(&mut c, 1400, None);
        apply(&mut c, 1300, None);
        apply(&mut c, 1200, Some(600));
        assert_eq!(c.state().unwrap().pending.as_ref().unwrap().revert_to, 2);
        (d, c)
    }

    fn refused() -> Result<bool, FirewallError> {
        Err(FirewallError::PeerUnreachable { peer: "fw2".into() })
    }

    /// With the peer unreachable, `rollback` of a pending change discards it.
    #[test]
    fn pending_discard_needs_no_peer() {
        let (_d, mut c) = with_pending();
        let g = gated_rollback(&mut c, None, "admin", refused())
            .unwrap()
            .unwrap();
        assert_eq!((g.0.id, c.active().unwrap()), (2, 2));
        assert!(c.state().unwrap().pending.is_none());
    }

    /// The confirm window expires between the request and the locked
    /// section: the pending change is already gone, so `rollback` would
    /// now be a new generation (back to 1), which the gate refuses
    /// instead of slipping through as a "discard".
    #[test]
    fn expiry_in_between_is_gated() {
        let (_d, mut c) = with_pending();
        c.tick(i64::MAX).unwrap();
        assert_eq!(c.active().unwrap(), 2);
        let r = gated_rollback(&mut c, None, "admin", refused()).unwrap();
        assert!(
            matches!(r, Err(FirewallError::PeerUnreachable { .. })),
            "{r:?}"
        );
        assert_eq!(c.active().unwrap(), 2);
        assert_eq!(c.history(None).unwrap().len(), 3, "no generation was made");
        // With the gate passed, the same request is an ordinary rollback.
        let g = gated_rollback(&mut c, None, "admin", Ok(true))
            .unwrap()
            .unwrap();
        assert_eq!((g.0.id, g.0.hash), (4, c.generation(1).unwrap().hash));
    }

    /// A confirmation lands in between: generation 3 is now confirmed and
    /// may have reached the peer, so rolling back is a new generation and
    /// is gated.
    #[test]
    fn confirmation_in_between_is_gated() {
        let (_d, mut c) = with_pending();
        c.confirm(3).unwrap();
        let r = gated_rollback(&mut c, None, "admin", refused()).unwrap();
        assert!(
            matches!(r, Err(FirewallError::PeerUnreachable { .. })),
            "{r:?}"
        );
        assert_eq!(c.active().unwrap(), 3);
        assert_eq!(c.history(None).unwrap().len(), 3);
    }

    /// Rolling back past a pending change's revert target goes beyond a
    /// discard, so it is gated even with the change still pending.
    #[test]
    fn rollback_past_the_revert_target_is_gated() {
        let (_d, mut c) = with_pending();
        let r = gated_rollback(&mut c, Some(1), "admin", refused()).unwrap();
        assert!(
            matches!(r, Err(FirewallError::PeerUnreachable { .. })),
            "{r:?}"
        );
        assert_eq!(c.active().unwrap(), 3, "nothing changed");
        assert!(c.state().unwrap().pending.is_some());
    }
}
