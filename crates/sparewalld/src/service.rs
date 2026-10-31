//! `org.sparewall.Firewall` served over Varlink.

use std::sync::{Arc, Mutex};

use futures_util::Stream;
use serde_json::{Value, json};
use sparewall_api::{
    ApplyReply, BackupReply, BindReply, ConfigReply, Empty, EventReply, ExportReply, FailoverReply,
    FirewallError, GenerationReply, HealthCheck, HealthReply, HistoryReply, LoginReply, SecretInfo,
    SecretListReply, SecretSetReply, StatusReply, TokenCreateReply, TokenInfo, TokenListReply,
    UpgradeCheckReply, UpgradeStartReply, UserInfo, UserListReply, ValidateReply, VpnConfigReply,
};
use sparewall_core::pair::SyncState;
use sparewall_core::secrets::{ADMIN_PASSWORD, SecretClass};
use sparewall_core::tokens::Role;
use sparewall_core::users::USER_PREFIX;
use sparewall_core::{ApplyOptions, ApplyResult, Coordinator, Error, Generation, System};
use tokio::sync::{Notify, broadcast};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use zlink::connection::socket::FetchPeerCredentials;
use zlink::{Reply, service};

use crate::access::{Principal, Session};
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
    changes: Changes,
    /// On the restricted socket, the connection's principal; `None` on
    /// the root-only sockets.
    session: Option<Session>,
    logins: Logins,
}

/// The lock that runs changes one at a time, shared with the peer service
/// (an upgrade the backup forwards takes it on the master).
pub type Changes = Arc<tokio::sync::Mutex<()>>;

impl Firewall {
    pub fn new(
        core: Core,
        events: broadcast::Sender<Value>,
        pair: Pair,
        sync: Arc<Notify>,
        changes: Changes,
    ) -> Self {
        Firewall {
            core,
            events,
            pair,
            sync,
            changes,
            session: None,
            logins: Logins::default(),
        }
    }

    /// This service for one connection of the restricted socket.
    pub fn restricted(&self, session: Session) -> Firewall {
        Firewall {
            session: Some(session),
            ..self.clone()
        }
    }

    fn principal(&self) -> Option<Principal> {
        self.session
            .as_ref()
            .and_then(|s| s.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }

    /// The caller's role on the restricted socket (`None`: root).
    fn role(&self) -> Option<Role> {
        self.session
            .as_ref()
            .map(|_| self.principal().map_or(Role::Monitor, |p| p.role))
    }

    /// Who is calling, for a generation's author and the journal.
    async fn author<Sock: zlink::connection::socket::Socket>(
        &self,
        conn: &mut zlink::Connection<Sock>,
    ) -> String
    where
        Sock::ReadHalf: FetchPeerCredentials,
    {
        match self.principal() {
            Some(p) => p.describe(),
            None => author::of(conn).await,
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
    role: Option<Role>,
) -> Result<Result<(Generation, bool), FirewallError>, Error> {
    let reachable = match gate {
        Ok(r) => r,
        Err(e) if !c.rollback_is_local(target)? => return Ok(Err(e)),
        Err(_) => false,
    };
    c.rollback_staging(target, author, reachable, role).map(Ok)
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
        Error::Denied { role, reason } => FirewallError::PermissionDenied {
            role,
            reason: Some(reason),
        },
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
    role: Option<Role>,
) -> ApplyOptions {
    ApplyOptions {
        role,
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
    version = sparewall_core::VERSION,
    url = "https://sparewall.org"
)]
impl<Sock> Firewall
where
    Sock::ReadHalf: FetchPeerCredentials,
{
    /// Check a document without applying it: errors (as ValidationFailed,
    /// each naming its path) or warnings.
    #[zlink(interface = "org.sparewall.Firewall", types = [sparewall_api::Generation, HealthCheck])]
    async fn validate(&mut self, config: Value) -> Result<ValidateReply, FirewallError> {
        let warnings = with_core(&self.core, &self.events, move |c| c.validate(config)).await?;
        Ok(ValidateReply { warnings })
    }

    /// Replace the configuration with `config`. `base` is the generation it
    /// was derived from: Conflict if another change landed meanwhile. With
    /// `confirm_seconds`, the change reverts unless confirmed (`Confirm`) in
    /// time. `dry_run` validates, renders and checks it without running it.
    /// In a pair the peer must be reachable, or `allow_diverge` set.
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
            self.author(conn).await,
            reachable,
            self.role(),
        );
        let r = with_core(&self.core, &self.events, move |c| c.apply(config, &o)).await;
        self.finish(r, confirm_seconds).await
    }

    /// Change the configuration with a JSON merge patch (RFC 7396) on
    /// generation `base`, as `Apply` does.
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
            self.author(conn).await,
            reachable,
            self.role(),
        );
        let r = with_core(&self.core, &self.events, move |c| c.merge(&patch, &o)).await;
        self.finish(r, confirm_seconds).await
    }

    /// Change the configuration with a JSON patch (RFC 6902) on generation
    /// `base`, as `Apply` does.
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
            self.author(conn).await,
            reachable,
            self.role(),
        );
        let r = with_core(&self.core, &self.events, move |c| c.patch(&ops, &o)).await;
        self.finish(r, confirm_seconds).await
    }

    /// Keep generation `id`, which waits for confirmation.
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

    /// Return to generation `id` (default: the one before the active one) as
    /// a new generation; an unconfirmed change is discarded instead.
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
        let author = self.author(conn).await;
        let role = self.role();
        let (g, staged) = with_core_raw(&self.core, &self.events, move |c| {
            gated_rollback(c, target, &author, gate, role)
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

    /// A generation's document and record (default: the active one).
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

    /// A generation's document alone (default: the active one).
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

    /// Generations, newest first, up to `limit`.
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

    /// In a pair, make both nodes run the configuration of `from_node`: this
    /// node (push it to the peer) or the peer (take the peer's).
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

    /// This node's health level and VRRP role; with `verbose`, each check.
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

    /// Acknowledge a check that stays degraded until someone has seen it
    /// (`selinux`).
    async fn ack_health(
        &mut self,
        name: String,
        #[zlink(connection)] conn: &mut Connection<Sock>,
    ) -> Result<Empty, FirewallError> {
        let by = self.author(conn).await;
        crate::selinux::acknowledge(&self.core, &self.events, name, by).await?;
        Ok(Empty {})
    }

    /// The node's state: generations and hashes, pair sync, links, VRRP,
    /// connection tracking, the certificate it serves, and health.
    async fn status(&mut self) -> Result<StatusReply, FirewallError> {
        let pair = self.pair.lock().unwrap_or_else(|p| p.into_inner()).clone();
        with_core(&self.core, &self.events, move |c| status(c, &pair)).await
    }

    /// Write a backup bundle now, and send it to `backup.repository` if one
    /// is set.
    async fn backup(&mut self) -> Result<BackupReply, FirewallError> {
        crate::backup::run(&self.core, &self.events).await
    }

    /// Events as they happen: applied and rolled-back generations, peer
    /// and health changes, upgrade steps. The first reply confirms the
    /// subscription.
    /// [Requires 'more' flag]
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

    /// A WireGuard client configuration for remote-access peer `peer`
    /// (on `port`, one of the instance's ports, if given).
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

    /// Store a secret (a cluster secret unless `cluster` is false). Values
    /// can never be read back.
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
        if name.starts_with(USER_PREFIX) {
            return Err(FirewallError::NotSupported {
                message: "users are set with sparewall user".into(),
            });
        }
        let info = with_core(&self.core, &self.events, move |c| {
            let admin_password = name == ADMIN_PASSWORD;
            if admin_password {
                if !sparewall_config::identity::password_hash_ok(&value) {
                    return Err(Error::Validation(vec![format!(
                        "{ADMIN_PASSWORD} takes a crypt(3) hash or \"!\": use sparewall passwd"
                    )]));
                }
                if class != SecretClass::Cluster {
                    return Err(Error::Validation(vec![format!(
                        "{ADMIN_PASSWORD} is a cluster secret"
                    )]));
                }
            }
            let info = c.secret_set(&name, value.as_bytes(), class)?;
            // A key the live remote-access VPN uses (a server key, or a
            // peer's preshared key) takes effect now.
            c.refresh_vpn_keys(std::slice::from_ref(&name))?;
            if admin_password {
                c.apply_admin_password()?;
                c.users_changed(std::slice::from_ref(&name))?;
            }
            Ok(info)
        })
        .await?;
        self.sync.notify_one();
        Ok(SecretSetReply {
            secret: api_secret(&info),
        })
    }

    /// Secrets' names, classes and versions, never their values.
    #[zlink(rename = "List")]
    async fn secret_list(&mut self) -> Result<SecretListReply, FirewallError> {
        let list = with_core(&self.core, &self.events, |c| c.secret_list()).await?;
        Ok(SecretListReply {
            secrets: list.iter().map(api_secret).collect(),
        })
    }

    /// Whether a newer image is available on the channel (or `image`, a full
    /// reference).
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
        let t = target.clone();
        let remote = tokio::task::spawn_blocking(move || crate::upgrade::inspect(&t))
            .await
            .map_err(|e| FirewallError::ApplyFailed {
                message: e.to_string(),
            })?;
        let booted = booted_image_digest();
        let offer = crate::upgrade::offer(
            sparewall_core::VERSION,
            booted
                .as_deref()
                .and_then(|b| b.rsplit_once('@'))
                .map(|(_, d)| d),
            &remote,
        );
        let available = if let Some(a) = offer.available {
            a
        } else if tracked.as_deref() == Some(target.as_str()) {
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
            booted,
            target,
            available,
            version: remote.ok().and_then(|r| r.version),
            running: Some(sparewall_core::VERSION.to_string()),
            note: offer.note,
        })
    }

    /// Start a rolling, health-gated upgrade; progress arrives as events
    /// (`Subscribe`).
    #[zlink(rename = "Start")]
    async fn upgrade_start(
        &mut self,
        channel: Option<String>,
        image: Option<String>,
        allow_downgrade: Option<bool>,
    ) -> Result<UpgradeStartReply, FirewallError> {
        let _change = self.changes.lock().await;
        let plan = crate::upgrade::start(
            &self.core,
            &self.events,
            &self.pair,
            channel,
            image,
            allow_downgrade.unwrap_or(false),
            true,
        )
        .await
        .map_err(|message| FirewallError::ApplyFailed { message })?;
        Ok(UpgradeStartReply { plan })
    }

    /// Move a pair's gateway addresses to `to` (default: the node with the
    /// higher VRRP priority). Returns when the move is done, or why it did
    /// not happen.
    #[zlink(interface = "org.sparewall.Cluster", rename = "Failover")]
    async fn failover(&mut self, to: Option<String>) -> Result<FailoverReply, FirewallError> {
        crate::failover::failover(&self.core, &self.events, &self.pair, to.as_deref())
            .await
            .map_err(|message| FirewallError::ApplyFailed { message })
    }

    /// Create an API token with `role`, expiring after `expires_days` if
    /// given. The token is shown once.
    #[zlink(interface = "org.sparewall.Auth", types = [TokenInfo])]
    async fn create_token(
        &mut self,
        name: String,
        role: String,
        expires_days: Option<i64>,
    ) -> Result<TokenCreateReply, FirewallError> {
        let role = parse_role(&role)?;
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

    /// Bind this connection to a token (an API token or a session's): later
    /// calls act with its role. Needed first on the restricted socket.
    async fn bind(&mut self, token: String) -> Result<BindReply, FirewallError> {
        let Some(session) = self.session.clone() else {
            return Err(FirewallError::NotSupported {
                message: "the root-only socket needs no token".into(),
            });
        };
        let found = with_core(&self.core, &self.events, move |c| c.token_use(&token)).await?;
        let mut s = session.lock().unwrap_or_else(|p| p.into_inner());
        let Some(t) = found else {
            *s = None;
            return Err(FirewallError::PermissionDenied {
                role: "none".into(),
                reason: Some("unknown or expired token".into()),
            });
        };
        let p = Principal::of(&t);
        tracing::info!(
            principal = p.describe(),
            role = t.role.as_str(),
            "bound a connection"
        );
        *s = Some(p);
        Ok(BindReply {
            name: t.name,
            role: t.role.as_str().into(),
        })
    }

    /// Check a user's password and open a session of 12 hours; the
    /// connection is bound to it. Failed logins are rate-limited per user.
    async fn login(&mut self, user: String, password: String) -> Result<LoginReply, FirewallError> {
        let refused = |reason: &str| FirewallError::PermissionDenied {
            role: "none".into(),
            reason: Some(reason.into()),
        };
        let name = user.clone();
        let exists = with_core(&self.core, &self.events, move |c| c.user_exists(&name)).await?;
        if !self.logins.attempt(&user, exists) {
            return Err(refused("too many failed logins; try again later"));
        }
        let name = user.clone();
        let found = with_core(&self.core, &self.events, move |c| c.login(&name, &password)).await?;
        let Some((token, t)) = found else {
            // Slows guessing on one connection; others are not held up.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            return Err(refused("wrong user name or password"));
        };
        self.logins.succeeded(&user);
        if let Some(s) = &self.session {
            *s.lock().unwrap_or_else(|p| p.into_inner()) = Some(Principal::of(&t));
        }
        Ok(LoginReply {
            token,
            user,
            role: t.role.as_str().into(),
            expires: t.expires.unwrap_or_default(),
        })
    }

    /// End the session this connection is bound to.
    async fn logout(&mut self) -> Result<Empty, FirewallError> {
        let Some(p) = self.principal().filter(|p| p.user.is_some()) else {
            return Err(FirewallError::NotSupported {
                message: "this connection is not bound to a session".into(),
            });
        };
        if let Some(s) = &self.session {
            *s.lock().unwrap_or_else(|p| p.into_inner()) = None;
        }
        let hash = p.hash.clone();
        with_core(&self.core, &self.events, move |c| {
            c.token_revoke_hash(&hash)
        })
        .await?;
        tracing::info!(user = p.describe(), "logged out");
        Ok(Empty {})
    }

    /// Add a user, or change its role or password (a crypt(3) hash; `!`
    /// locks it, empty keeps it). Ends the user's sessions.
    #[zlink(types = [UserInfo])]
    async fn set_user(
        &mut self,
        name: String,
        role: String,
        password_hash: String,
    ) -> Result<Empty, FirewallError> {
        let role = parse_role(&role)?;
        with_core(&self.core, &self.events, move |c| {
            c.user_set(&name, role, &password_hash)
        })
        .await?;
        self.sync.notify_one();
        Ok(Empty {})
    }

    /// Users and their roles, `admin` first.
    async fn list_users(&mut self) -> Result<UserListReply, FirewallError> {
        let users = with_core(&self.core, &self.events, |c| c.users()).await?;
        Ok(UserListReply {
            users: users
                .into_iter()
                .map(|u| UserInfo {
                    name: u.name,
                    role: u.role.as_str().into(),
                    locked: u.locked,
                    updated: u.updated,
                })
                .collect(),
        })
    }

    /// Remove a user and end its sessions.
    async fn remove_user(&mut self, name: String) -> Result<Empty, FirewallError> {
        let existed = with_core(&self.core, &self.events, move |c| c.user_remove(&name)).await?;
        if !existed {
            return Err(FirewallError::NotSupported {
                message: "no such user".into(),
            });
        }
        self.sync.notify_one();
        Ok(Empty {})
    }

    /// API tokens (never their values).
    async fn list_tokens(&mut self) -> Result<TokenListReply, FirewallError> {
        let t = with_core(&self.core, &self.events, |c| c.tokens()).await?;
        Ok(TokenListReply {
            // Sessions are the users'.
            tokens: t
                .iter()
                .filter(|t| t.user.is_none())
                .map(api_token)
                .collect(),
        })
    }

    /// Revoke an API token at once.
    async fn revoke_token(&mut self, name: String) -> Result<Empty, FirewallError> {
        let existed = with_core(&self.core, &self.events, move |c| c.token_revoke(&name)).await?;
        if !existed {
            return Err(FirewallError::NotSupported {
                message: "no such token".into(),
            });
        }
        Ok(Empty {})
    }

    /// Delete a secret on this node.
    #[zlink(interface = "org.sparewall.Secrets", rename = "Delete")]
    async fn secret_delete(&mut self, name: String) -> Result<Empty, FirewallError> {
        if name.starts_with(USER_PREFIX) {
            return Err(FirewallError::NotSupported {
                message: "users are removed with sparewall user remove".into(),
            });
        }
        // A deletion would neither reach the peer nor lock the account.
        if name == ADMIN_PASSWORD {
            return Err(FirewallError::NotSupported {
                message: format!("{ADMIN_PASSWORD} is removed with sparewall passwd --lock"),
            });
        }
        let existed = with_core(&self.core, &self.events, move |c| c.secret_delete(&name)).await?;
        if !existed {
            return Err(FirewallError::NotSupported {
                message: "no such secret".into(),
            });
        }
        Ok(Empty {})
    }
}

fn parse_role(role: &str) -> Result<Role, FirewallError> {
    Role::parse(role).ok_or_else(|| FirewallError::ValidationFailed {
        errors: vec![format!(
            "role must be monitor, viewer, operator or admin, not {role:?}"
        )],
    })
}

/// Login attempts per user name, to refuse guessing (design: "Password
/// logins are rate-limited"). Shared by every connection.
///
/// Users' counts are kept apart from other names' so that a flood of
/// made-up names, which no one can log in as, cannot lock out a user or
/// grow the table without end: other names share a table of
/// [`Self::NAMES`], emptied when it fills, and are refused the same way
/// as users meanwhile, so the refusal does not tell which names are users.
#[derive(Clone, Default)]
pub struct Logins(Arc<Mutex<LoginCounts>>);

type Counts = std::collections::HashMap<String, (u32, std::time::Instant)>;

#[derive(Default)]
pub struct LoginCounts {
    users: Counts,
    others: Counts,
}

impl Logins {
    /// Attempts allowed in a [`Self::WINDOW`].
    const LIMIT: u32 = 5;
    const WINDOW: std::time::Duration = std::time::Duration::from_secs(15 * 60);
    /// Names that are not users tracked at once.
    const NAMES: usize = 10_000;

    /// Count an attempt for `user` (a user or not, as `exists` says)
    /// before its password is checked, so that attempts made at once
    /// cannot pass the limit together; `false` when it is refused.
    /// [`Self::succeeded`] forgets the count.
    pub(crate) fn attempt(&self, user: &str, exists: bool) -> bool {
        let mut m = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let t = if exists { &mut m.users } else { &mut m.others };
        let now = std::time::Instant::now();
        if !t.contains_key(user) && t.len() >= Self::NAMES {
            t.retain(|_, (_, since)| since.elapsed() <= Self::WINDOW);
            if t.len() >= Self::NAMES {
                if exists {
                    // Only removed users' stale counts can fill it.
                    tracing::warn!("{} users failing to log in", t.len());
                } else {
                    t.clear();
                }
            }
        }
        let e = t.entry(user.to_string()).or_insert((0, now));
        if e.1.elapsed() > Self::WINDOW {
            *e = (0, now);
        }
        if e.0 >= Self::LIMIT {
            return false;
        }
        e.0 += 1;
        true
    }

    pub(crate) fn succeeded(&self, user: &str) {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .users
            .remove(user);
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
            password_hash: None,
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
        let g = gated_rollback(&mut c, None, "admin", refused(), None)
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
        let r = gated_rollback(&mut c, None, "admin", refused(), None).unwrap();
        assert!(
            matches!(r, Err(FirewallError::PeerUnreachable { .. })),
            "{r:?}"
        );
        assert_eq!(c.active().unwrap(), 2);
        assert_eq!(c.history(None).unwrap().len(), 3, "no generation was made");
        // With the gate passed, the same request is an ordinary rollback.
        let g = gated_rollback(&mut c, None, "admin", Ok(true), None)
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
        let r = gated_rollback(&mut c, None, "admin", refused(), None).unwrap();
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
        let r = gated_rollback(&mut c, Some(1), "admin", refused(), None).unwrap();
        assert!(
            matches!(r, Err(FirewallError::PeerUnreachable { .. })),
            "{r:?}"
        );
        assert_eq!(c.active().unwrap(), 3, "nothing changed");
        assert!(c.state().unwrap().pending.is_some());
    }
}
