//! The `org.sparewall.Firewall` Varlink interface, shared by `sparewalld`
//! (which serves it) and the `sparewall` CLI (its first client).
//!
//! Interface changes are additive only; a breaking change gets a new
//! interface name (design: "Versioning and compatibility").

pub mod notice;
pub mod openapi;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zlink::introspect::{CustomType, ReplyError, Type};

pub const INTERFACE: &str = "org.sparewall.Firewall";
/// The root-only admin socket.
pub const SOCKET: &str = "/run/sparewall/org.sparewall.Firewall";
/// A second root-only socket serving the same interface, for keepalived's
/// health check, so that nothing an admin client does on [`SOCKET`] can
/// hold the check up past its timeout and hand the gateway addresses over.
pub const HEALTH_SOCKET: &str = "/run/sparewall/org.sparewall.Health";
/// The restricted socket, open to unprivileged clients such as
/// `sparewall-httpd`. A client binds its connection to a token
/// (`org.sparewall.Auth.Bind`) before anything else, and every call is
/// checked against that token's role.
pub const API_SOCKET: &str = "/run/sparewall-api/org.sparewall.Api";

/// One configuration generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct Generation {
    pub id: i64,
    /// SHA-256 of the canonical document (empty for bootstrap).
    pub hash: String,
    pub base: Option<i64>,
    pub schema: i64,
    pub author: String,
    /// When it was created (RFC 3339).
    pub applied: String,
    /// False while it waits for `Confirm`.
    pub confirmed: bool,
    /// One line per changed path.
    pub summary: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct ValidateReply {
    pub warnings: Vec<String>,
    /// The same warnings, each with the place in the document it concerns,
    /// as in ValidationFailed's `issues` (#305). Absent from nodes older
    /// than 0.8.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issues: Option<Vec<ValidationIssue>>,
}

/// One validation problem, with the place in the document it concerns
/// (#305). An inline object, not a named type: errors are shared by every
/// interface, and a named type would have to be declared in each.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct ValidationIssue {
    /// The place as the validator names it: names joined by `.` (a name
    /// holding a `.` or `->` may be quoted with `'`), and `[n]` for a list
    /// index, e.g. `networks.lan.dhcp.ranges[0]`. Null for a problem with
    /// no place in the document.
    pub path: Option<String>,
    /// The same place as an RFC 6901 JSON Pointer into the document
    /// checked (for a partial change, `Merge` or `Patch`, the whole document
    /// it would make), e.g. `/networks/lan/dhcp/ranges/0`, for marking the
    /// field. It may name a field the document leaves out (a required
    /// one). Null when `path` is.
    pub pointer: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct ApplyReply {
    pub generation: Generation,
    /// Subsystems whose configuration changed.
    pub changed: Vec<String>,
    /// One line per changed document path.
    pub diff: Vec<String>,
    pub warnings: Vec<String>,
    /// The document was identical to the active one.
    pub unchanged: bool,
    /// Seconds until an unconfirmed generation reverts (0 if confirmed).
    pub confirm_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct Empty {}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct GenerationReply {
    pub generation: Generation,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct ConfigReply {
    pub config: Value,
    pub generation: Generation,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct ExportReply {
    pub config: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct HistoryReply {
    pub generations: Vec<Generation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, CustomType)]
pub struct HealthCheck {
    pub name: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct HealthReply {
    /// `ok`, `degraded` or `failed`.
    pub level: String,
    /// `standalone`, `bootstrap`, `MASTER` or `BACKUP`.
    pub role: String,
    pub checks: Option<Vec<HealthCheck>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct StatusReply {
    pub node: String,
    pub role: String,
    /// Active generation, pending confirmation, hashes.
    pub sync: Value,
    pub links: Value,
    pub vrrp: Value,
    pub conntrack: Value,
    pub services: Value,
    /// The certificate served on the management network.
    pub tls: Value,
    pub health: Value,
    /// The background update check (#188): whether it is on, the image it
    /// checks, what that offers (`none`, `newer`, `rebuild`, `different`),
    /// its version and digest, when it last ran and succeeded, and its last
    /// error. Absent from nodes older than 0.4.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<Value>,
    /// Each network with IPv6 (#216), by name: `iface`, `mode`, the
    /// interface's global `addresses`, the prefixes `delegated` to it by
    /// DHCPv6 and its `default_gateway`; an inside network also its
    /// advertised `prefixes`. Lifetimes are seconds left. Absent when no
    /// network has IPv6, and from nodes older than 0.6.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct BackupReply {
    pub path: String,
    pub digest: String,
    /// The restic snapshot, when sent to `backup.repository`.
    pub snapshot: Option<String>,
    /// Cluster secrets sealed in the bundle (none without a backup password).
    #[serde(default)]
    pub secrets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct EventReply {
    pub event: Value,
}

/// Method errors.
#[derive(Debug, Clone, PartialEq, Eq, zlink::ReplyError, ReplyError)]
#[zlink(interface = "org.sparewall.Firewall")]
pub enum FirewallError {
    ValidationFailed {
        /// Each problem as one line, `path: message`.
        errors: Vec<String>,
        /// The same problems, each with its place in the document (#305).
        /// Absent from nodes older than 0.8.0.
        issues: Option<Vec<ValidationIssue>>,
    },
    Conflict {
        current: i64,
    },
    ConfirmTimeout {
        rolled_back_to: i64,
    },
    PeerUnreachable {
        peer: String,
    },
    /// `role` is `none` on a connection not bound to a token.
    PermissionDenied {
        role: String,
        reason: Option<String>,
    },
    NotFound {
        id: i64,
    },
    NotPending {
        id: i64,
    },
    ApplyFailed {
        message: String,
    },
    NotSupported {
        message: String,
    },
    /// A service the call needs is not answering (the local Prometheus,
    /// for `org.sparewall.Metrics`).
    ServiceUnavailable {
        service: String,
        message: String,
    },
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallError::ValidationFailed { errors, .. } => {
                write!(f, "validation failed:")?;
                for e in errors {
                    write!(f, "\n  {e}")?;
                }
                Ok(())
            }
            FirewallError::Conflict { current } => write!(
                f,
                "conflict: the configuration changed meanwhile (now generation {current}); re-read it and try again"
            ),
            FirewallError::ConfirmTimeout { rolled_back_to } => {
                write!(
                    f,
                    "not confirmed in time; rolled back to generation {rolled_back_to}"
                )
            }
            FirewallError::PeerUnreachable { peer } => write!(f, "peer {peer} is unreachable"),
            FirewallError::PermissionDenied { role, reason } => {
                write!(f, "permission denied for role {role}")?;
                match reason {
                    Some(r) => write!(f, ": {r}"),
                    None => Ok(()),
                }
            }
            FirewallError::NotFound { id } => write!(f, "generation {id} not found"),
            FirewallError::NotPending { id } => {
                write!(f, "generation {id} is not waiting for confirmation")
            }
            FirewallError::ApplyFailed { message } => write!(f, "apply failed: {message}"),
            FirewallError::NotSupported { message } => write!(f, "not supported: {message}"),
            FirewallError::ServiceUnavailable { service, message } => {
                write!(f, "{service} is unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for FirewallError {}

impl FirewallError {
    /// A refusal from messages with no place in the document.
    pub fn invalid(errors: Vec<String>) -> Self {
        let issues = errors
            .iter()
            .map(|m| ValidationIssue {
                path: None,
                pointer: None,
                message: m.clone(),
            })
            .collect();
        FirewallError::ValidationFailed {
            errors,
            issues: Some(issues),
        }
    }
}

/// Client side of `org.sparewall.Firewall`.
#[zlink::proxy("org.sparewall.Firewall")]
pub trait FirewallProxy {
    async fn validate(
        &mut self,
        config: &Value,
    ) -> zlink::Result<Result<ValidateReply, FirewallError>>;
    async fn apply(
        &mut self,
        config: &Value,
        base: i64,
        confirm_seconds: Option<i64>,
        dry_run: Option<bool>,
        allow_diverge: Option<bool>,
    ) -> zlink::Result<Result<ApplyReply, FirewallError>>;
    async fn merge(
        &mut self,
        patch: &Value,
        base: i64,
        confirm_seconds: Option<i64>,
        dry_run: Option<bool>,
        allow_diverge: Option<bool>,
    ) -> zlink::Result<Result<ApplyReply, FirewallError>>;
    async fn patch(
        &mut self,
        ops: &Value,
        base: i64,
        confirm_seconds: Option<i64>,
        dry_run: Option<bool>,
        allow_diverge: Option<bool>,
    ) -> zlink::Result<Result<ApplyReply, FirewallError>>;
    async fn confirm(&mut self, id: i64) -> zlink::Result<Result<Empty, FirewallError>>;
    async fn rollback(
        &mut self,
        id: Option<i64>,
        allow_diverge: Option<bool>,
    ) -> zlink::Result<Result<GenerationReply, FirewallError>>;
    async fn get_config(
        &mut self,
        id: Option<i64>,
    ) -> zlink::Result<Result<ConfigReply, FirewallError>>;
    async fn export(
        &mut self,
        id: Option<i64>,
    ) -> zlink::Result<Result<ExportReply, FirewallError>>;
    async fn history(
        &mut self,
        limit: Option<i64>,
    ) -> zlink::Result<Result<HistoryReply, FirewallError>>;
    async fn sync(
        &mut self,
        from_node: &str,
    ) -> zlink::Result<Result<GenerationReply, FirewallError>>;
    async fn health(
        &mut self,
        verbose: Option<bool>,
    ) -> zlink::Result<Result<HealthReply, FirewallError>>;
    /// Acknowledge a check that stays degraded until someone has seen it
    /// (`selinux`).
    async fn ack_health(&mut self, name: &str) -> zlink::Result<Result<Empty, FirewallError>>;
    async fn status(&mut self) -> zlink::Result<Result<StatusReply, FirewallError>>;
    async fn backup(&mut self) -> zlink::Result<Result<BackupReply, FirewallError>>;
    #[zlink(more)]
    async fn subscribe(
        &mut self,
    ) -> zlink::Result<
        impl futures_util::Stream<Item = zlink::Result<Result<EventReply, FirewallError>>>,
    >;
}

// ---------------------------------------------------------------------------
// Node to node, over the sync tunnel only.

pub const PEER_INTERFACE: &str = "org.sparewall.Peer";
/// The peer service's root-only socket; the sync tunnel listener splices
/// connections from the peer onto it.
pub const PEER_SOCKET: &str = "/run/sparewall/org.sparewall.Peer";
/// TCP port of the peer listener on the sync tunnel address.
pub const PEER_PORT: u16 = 8649;
/// Peer protocol version, negotiated in `Hello`. 2: pushed generations
/// can be gated on the pusher's `Confirm`. 3: a gated generation that
/// changes the sync link stays in doubt after `Confirm` until the pusher's
/// decision shows in its `Hello` (so it can be pushed before it runs on
/// the pusher).
pub const PEER_PROTOCOL: i64 = 3;

/// A generation as it travels between nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct PeerGeneration {
    pub id: i64,
    pub hash: String,
    pub base: Option<i64>,
    pub schema: i64,
    pub author: String,
    pub created: String,
    pub summary: Vec<String>,
}

/// How a node decided a sync-link change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct LinkDecisionReply {
    pub id: i64,
    pub hash: String,
    /// Kept on both nodes, or reverted on both.
    pub kept: bool,
}

/// One step of a node's lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct LineageEntry {
    pub id: i64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct HelloReply {
    pub node: String,
    pub protocol: i64,
    pub active: i64,
    pub desired: String,
    pub applied: Option<String>,
    pub applying: bool,
    /// Newest first, back through each base.
    pub lineage: Vec<LineageEntry>,
    /// A change is waiting for confirmation on that node.
    pub pending: bool,
    pub image: Option<String>,
    /// The callee's health level (`ok`, `degraded`, `failed`).
    pub health: Option<String>,
    /// The callee's VRRP role, if known.
    pub role: Option<String>,
    /// How the callee decided its last sync-link change (protocol 3),
    /// until it sees the caller follow it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_decision: Option<LinkDecisionReply>,
    /// What the callee reaches on each network with a gateway address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reach: Vec<NetworkReach>,
    /// The newest schema revision the callee reads. Releases before it was
    /// reported read revision 1 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<i64>,
    /// The prefixes DHCPv6 delegated to the callee (#215): a pair's
    /// master's, which the backup advertises at a failover until its own
    /// reply arrives.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegated: Vec<DelegatedPrefix>,
}

/// A prefix DHCPv6 delegated, with the seconds left of its lifetimes when
/// it was sent; `None` is forever.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct DelegatedPrefix {
    pub prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_seconds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_seconds: Option<i64>,
}

/// One node's view of a network with a gateway address: whether the peer
/// answers on it, and, while it does not, which other hosts there do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct NetworkReach {
    pub network: String,
    /// The peer's own address answered ARP or neighbour discovery.
    pub peer: bool,
    /// Other hosts that answered. Probed only while the peer does not.
    #[serde(default)]
    pub answered: Vec<String>,
    /// Hosts this node knows on the network, for the peer to probe too.
    #[serde(default)]
    pub known: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct PushReply {
    pub active: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct FetchReply {
    pub generation: PeerGeneration,
    pub config: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, zlink::ReplyError, ReplyError)]
#[zlink(interface = "org.sparewall.Peer")]
pub enum PeerError {
    Conflict { current: i64 },
    Rejected { message: String },
    NotFound { id: i64 },
    WrongNode { expected: String },
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerError::Conflict { current } => {
                write!(f, "peer conflict: its generation is {current}")
            }
            PeerError::Rejected { message } => write!(f, "peer rejected the generation: {message}"),
            PeerError::NotFound { id } => write!(f, "peer has no generation {id}"),
            PeerError::WrongNode { expected } => write!(f, "peer expected node {expected}"),
        }
    }
}

impl std::error::Error for PeerError {}

#[zlink::proxy("org.sparewall.Peer")]
pub trait PeerProxy {
    /// Exchange state. `node` is the caller; the reply describes the callee.
    async fn hello(
        &mut self,
        node: &str,
        protocol: i64,
    ) -> zlink::Result<Result<HelloReply, PeerError>>;
    /// Offer a generation whose base should be the callee's active one.
    /// With `force`, the callee adopts it regardless (`sync --from`).
    async fn push(
        &mut self,
        generation: &PeerGeneration,
        config: &Value,
        force: Option<bool>,
        // `false`: store in history without running it (default `true`).
        // Older peers ignore it and run every generation pushed.
        activate: Option<bool>,
        // `true` (protocol 2): run it pending until the caller's `Confirm`.
        gated: Option<bool>,
    ) -> zlink::Result<Result<PushReply, PeerError>>;
    /// Confirm a generation the caller pushed with `gated` (protocol 2).
    async fn confirm(&mut self, id: i64) -> zlink::Result<Result<PushReply, PeerError>>;
    /// Read a generation (default: the active one).
    async fn fetch(&mut self, id: Option<i64>) -> zlink::Result<Result<FetchReply, PeerError>>;
}

// ---------------------------------------------------------------------------
// The write-only secret store.

pub const SECRETS_INTERFACE: &str = "org.sparewall.Secrets";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct SecretInfo {
    pub name: String,
    /// `node` or `cluster`.
    pub class: String,
    pub version: i64,
    pub updated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct SecretSetReply {
    pub secret: SecretInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct SecretListReply {
    pub secrets: Vec<SecretInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct VpnConfigReply {
    pub config: String,
}

/// Whether a backup password is the node's (#142). Nothing derived from
/// the stored secret comes back.
#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct CheckBackupPasswordReply {
    /// Whether it is the stored `backup-password`.
    pub matches_stored: bool,
    /// The newest bundle on the node, if there is one.
    pub bundle: Option<String>,
    /// Whether it opens that bundle's sealed secrets (which may predate a
    /// change of the password); absent without a bundle with secrets.
    pub opens_bundle: Option<bool>,
    /// The secrets it opens there.
    pub secrets: Vec<String>,
    /// Why a check could not be made (no stored password, no bundle).
    pub notes: Vec<String>,
}

#[zlink::proxy("org.sparewall.Secrets")]
pub trait SecretsProxy {
    /// Store a secret. Values can never be read back.
    async fn set(
        &mut self,
        name: &str,
        value: &str,
        cluster: Option<bool>,
    ) -> zlink::Result<Result<SecretSetReply, FirewallError>>;
    async fn list(&mut self) -> zlink::Result<Result<SecretListReply, FirewallError>>;
    async fn delete(&mut self, name: &str) -> zlink::Result<Result<Empty, FirewallError>>;
    /// Whether `password` is the stored backup password and opens the
    /// newest bundle on the node (admin only).
    async fn check_backup_password(
        &mut self,
        password: &str,
    ) -> zlink::Result<Result<CheckBackupPasswordReply, FirewallError>>;
}

#[zlink::proxy("org.sparewall.Firewall")]
pub trait VpnProxy {
    /// A WireGuard client configuration for one remote-access peer.
    async fn vpn_client_config(
        &mut self,
        instance: Option<&str>,
        peer: &str,
        port: Option<i64>,
    ) -> zlink::Result<Result<VpnConfigReply, FirewallError>>;
}

/// A cluster secret on its way to the peer (value hex-encoded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct PeerSecret {
    pub name: String,
    pub version: i64,
    pub updated: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct PutSecretsReply {
    pub stored: i64,
}

#[zlink::proxy("org.sparewall.Peer")]
pub trait PeerSecretsProxy {
    /// Store cluster secrets, keeping newer local versions.
    async fn put_secrets(
        &mut self,
        secrets: Vec<PeerSecret>,
    ) -> zlink::Result<Result<PutSecretsReply, PeerError>>;
}

// ---------------------------------------------------------------------------
// Users, tokens and roles.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct TokenInfo {
    pub name: String,
    /// `monitor`, `viewer`, `operator` or `admin`.
    pub role: String,
    pub created: String,
    /// Unix time it expires, if ever.
    pub expires: Option<i64>,
    pub last_used: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct TokenCreateReply {
    /// Shown once; only its hash is kept.
    pub token: String,
    pub info: TokenInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct TokenListReply {
    pub tokens: Vec<TokenInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct BindReply {
    /// The token's name.
    pub name: String,
    pub role: String,
}

/// A named user (design: "Browser authentication").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct UserInfo {
    pub name: String,
    pub role: String,
    /// No password: the user cannot log in.
    pub locked: bool,
    pub updated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct UserListReply {
    pub users: Vec<UserInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct LoginReply {
    /// The session token, shown once.
    pub token: String,
    pub user: String,
    pub role: String,
    /// Unix time the session ends.
    pub expires: i64,
}

#[zlink::proxy("org.sparewall.Auth")]
pub trait AuthProxy {
    /// Check a user's password and open a session; the connection is
    /// bound to it, and its token binds others (`Bind`) until it ends.
    /// Failed logins are rate-limited per user.
    async fn login(
        &mut self,
        user: &str,
        password: &str,
    ) -> zlink::Result<Result<LoginReply, FirewallError>>;
    /// End the session this connection is bound to.
    async fn logout(&mut self) -> zlink::Result<Result<Empty, FirewallError>>;
    /// Add a user, or change its role or password. `password_hash` is a
    /// crypt(3) hash (`!` locks the user, and an empty one keeps an
    /// existing user's); `admin` keeps the admin role.
    /// Ends the user's sessions.
    async fn set_user(
        &mut self,
        name: &str,
        role: &str,
        password_hash: &str,
    ) -> zlink::Result<Result<Empty, FirewallError>>;
    async fn list_users(&mut self) -> zlink::Result<Result<UserListReply, FirewallError>>;
    async fn remove_user(&mut self, name: &str) -> zlink::Result<Result<Empty, FirewallError>>;
    /// Bind this connection to a token: later calls on it act with the
    /// token's role. Needed first on the restricted socket
    /// ([`API_SOCKET`]); the root-only socket needs none.
    async fn bind(&mut self, token: &str) -> zlink::Result<Result<BindReply, FirewallError>>;
    async fn create_token(
        &mut self,
        name: &str,
        role: &str,
        expires_days: Option<i64>,
    ) -> zlink::Result<Result<TokenCreateReply, FirewallError>>;
    async fn list_tokens(&mut self) -> zlink::Result<Result<TokenListReply, FirewallError>>;
    async fn revoke_token(&mut self, name: &str) -> zlink::Result<Result<Empty, FirewallError>>;
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct UpgradeReply {
    /// The image the node will boot next.
    pub staged: String,
}

#[zlink::proxy("org.sparewall.Peer")]
pub trait PeerUpgradeProxy {
    /// Stage `image` with bootc (signature enforced) and reboot into it.
    async fn upgrade(&mut self, image: &str) -> zlink::Result<Result<UpgradeReply, PeerError>>;
    /// Run a rolling upgrade on the callee, the master, for a caller that
    /// is the backup (`sparewall upgrade` run there). The first event is
    /// `{"type": "upgrade", "step": "plan", "plan": [...]}`, or a `failed`
    /// step; the upgrade's own events follow until it ends.
    #[zlink(more)]
    async fn start_upgrade(
        &mut self,
        channel: Option<&str>,
        image: Option<&str>,
        allow_downgrade: Option<bool>,
    ) -> zlink::Result<impl futures_util::Stream<Item = zlink::Result<Result<EventReply, PeerError>>>>;
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct FailoverReply {
    /// The node that holds the gateway addresses now.
    pub master: String,
    /// What happened, in words.
    pub message: String,
}

#[zlink::proxy("org.sparewall.Peer")]
pub trait PeerFailoverProxy {
    /// Hand the gateway addresses to `to`, the caller, if the callee is
    /// the master and `to` is fit to take them. Returns once the handover
    /// has started; the caller watches its own VRRP role for the end.
    async fn failover(&mut self, to: &str) -> zlink::Result<Result<FailoverReply, PeerError>>;
}

pub const CLUSTER_INTERFACE: &str = "org.sparewall.Cluster";

#[zlink::proxy("org.sparewall.Cluster")]
pub trait ClusterProxy {
    /// Move a pair's gateway addresses to `to` (default: the node with
    /// the higher VRRP priority), from either node. Returns when the move
    /// is done, or why it was refused or did not happen.
    async fn failover(
        &mut self,
        to: Option<&str>,
    ) -> zlink::Result<Result<FailoverReply, FirewallError>>;
}

pub const UPGRADE_INTERFACE: &str = "org.sparewall.Upgrade";

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct UpgradeCheckReply {
    pub booted: Option<String>,
    pub target: String,
    pub available: bool,
    /// The target's Sparewall version, if its image says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// This node's Sparewall version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running: Option<String>,
    /// Why the target is or is not offered, when it is not plainly newer:
    /// older than this node, the same version, or no version to compare.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// When the next maintenance window opens (RFC 3339, UTC), with
    /// `updates.mode: windowed` (#84). Absent otherwise, and from nodes
    /// older than 0.4.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_window: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct UpgradeStartReply {
    /// What happens next, in words.
    pub plan: Vec<String>,
}

#[zlink::proxy("org.sparewall.Upgrade")]
pub trait UpgradeProxy {
    /// Whether a newer image is available on the channel. `image`, a full
    /// reference, overrides the channel (a mirror, a pinned build).
    async fn check(
        &mut self,
        channel: Option<&str>,
        image: Option<&str>,
    ) -> zlink::Result<Result<UpgradeCheckReply, FirewallError>>;
    /// Start a rolling, health-gated upgrade (one reboot for a standalone
    /// node). Progress arrives as events.
    async fn start(
        &mut self,
        channel: Option<&str>,
        image: Option<&str>,
        allow_downgrade: Option<bool>,
    ) -> zlink::Result<Result<UpgradeStartReply, FirewallError>>;
}

// ---------------------------------------------------------------------------
// History, from the local Prometheus (`metrics.mode: local`, #145).

pub const METRICS_INTERFACE: &str = "org.sparewall.Metrics";

/// A PromQL result, as Prometheus's HTTP API gives it.
#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct QueryReply {
    /// `vector`, `matrix`, `scalar` or `string`.
    pub result_type: String,
    /// Prometheus's `data.result`. A vector is `[{metric, value: [time,
    /// "value"]}]`, a matrix `[{metric, values: [[time, "value"], ...]}]`,
    /// a scalar or a string `[time, "value"]`.
    pub result: Value,
    /// What Prometheus noted about the query (its warnings and infos).
    pub warnings: Vec<String>,
}

#[zlink::proxy("org.sparewall.Metrics")]
pub trait MetricsProxy {
    /// Evaluate a PromQL expression at `time` (RFC 3339 or Unix seconds;
    /// default now) over this node's history.
    async fn query(
        &mut self,
        query: &str,
        time: Option<&str>,
    ) -> zlink::Result<Result<QueryReply, FirewallError>>;
    /// Evaluate a PromQL expression from `start` to `end` (RFC 3339 or Unix
    /// seconds), every `step` (a duration such as `1m`, or seconds).
    async fn query_range(
        &mut self,
        query: &str,
        start: &str,
        end: &str,
        step: &str,
    ) -> zlink::Result<Result<QueryReply, FirewallError>>;
}

// ---------------------------------------------------------------------------
// Diagnostics (#181): read-only views of the node, for the web UI and the
// CLI alike.

pub const DIAGNOSTICS_INTERFACE: &str = "org.sparewall.Diagnostics";

/// One journal entry of Sparewall's own units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct LogEntry {
    /// When it was logged (RFC 3339, in microseconds).
    pub time: String,
    /// Microseconds since the Unix epoch.
    pub usec: i64,
    /// The unit it came from (`sparewalld.service`), or `selinux` for a
    /// denial of the coordinator's domain.
    pub unit: String,
    /// syslog priority: 0 (emerg) to 7 (debug).
    pub priority: i64,
    /// The program that logged it (`SYSLOG_IDENTIFIER`).
    pub identifier: Option<String>,
    pub message: String,
    /// The entry's other fields, such as an upgrade's `F_STEP` and
    /// `F_DETAIL` or a rule hit's `F_RULE`; not the journal's own
    /// (`_PID`, `__CURSOR` and the like).
    pub fields: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct LogsReply {
    /// Newest first.
    pub entries: Vec<LogEntry>,
    /// Pass as `before`, as it is, for older entries; absent when there
    /// are none.
    pub older: Option<String>,
    /// The units one may ask for, `selinux` included.
    pub units: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct LogReply {
    /// Absent in the first reply, which says the follow has started.
    pub entry: Option<LogEntry>,
}

/// A hit of a rule, policy default or forward with `log: true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct RuleHit {
    /// When it was logged (RFC 3339, in microseconds).
    pub time: String,
    pub usec: i64,
    /// `users->self:ssh`, `guests->users:default` or `forward:web`.
    pub rule: String,
    /// One line: `tcp 192.0.2.7:51234 -> 10.0.0.2:443 in=wan0 out=lan0`.
    pub packet: String,
    /// `tcp`, `udp`, `icmp`, or the protocol's number.
    pub proto: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub sport: Option<i64>,
    pub dport: Option<i64>,
    /// The interfaces it came in on and was going out of.
    pub in_iface: Option<String>,
    pub out_iface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct HitsReply {
    /// Newest first.
    pub hits: Vec<RuleHit>,
    /// Pass as `before`, as it is, for older hits; absent when there are
    /// none.
    pub older: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct HitReply {
    /// Absent in the first reply, which says the follow has started.
    pub hit: Option<RuleHit>,
}

/// An entry of the neighbour table (ARP, NDP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct Neighbour {
    pub address: String,
    /// `4` or `6`.
    pub family: String,
    pub iface: String,
    /// The network the interface carries, if the document has it.
    pub network: Option<String>,
    pub mac: Option<String>,
    /// `REACHABLE`, `STALE`, `DELAY`, `PROBE`, `FAILED`, `INCOMPLETE`,
    /// `PERMANENT`, `NOARP`.
    pub state: Vec<String>,
    /// It says it is a router (IPv6).
    pub router: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct NeighboursReply {
    pub neighbours: Vec<Neighbour>,
    /// More than a reply holds: the rest were left out.
    pub cut: bool,
}

/// A route, from any table but the local one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct Route {
    /// A prefix, or `default`.
    pub destination: String,
    /// `4` or `6`.
    pub family: String,
    /// `main`, or another table's number.
    pub table: String,
    /// `unicast`, `unreachable`, `blackhole`…
    pub kind: String,
    pub gateway: Option<String>,
    pub iface: Option<String>,
    /// The network the interface carries, if the document has it.
    pub network: Option<String>,
    /// The source address it prefers.
    pub source: Option<String>,
    /// Who added it: `kernel`, `dhcp`, `ra`, `static`, `keepalived`…
    pub protocol: Option<String>,
    pub metric: Option<i64>,
    /// Seconds left, for one that expires.
    pub expires: Option<i64>,
    /// `linkdown`, `onlink`…
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct RoutesReply {
    pub routes: Vec<Route>,
    /// More than a reply holds: the rest were left out.
    pub cut: bool,
}

/// Output of a network tool run from the node (ping, traceroute, a DNS
/// lookup).
#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct ToolReply {
    /// Lines of output: one each as they come when streamed, all at once
    /// otherwise.
    pub lines: Vec<String>,
    /// The tool's exit status, in the last reply.
    pub exit: Option<i64>,
}

/// Part of a packet capture (#265): the pcap's bytes as they come, the
/// file's header first. Joined in order, a capture's `data` is one pcap
/// file, cut at a packet's end.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Type)]
pub struct CaptureReply {
    /// The next of the pcap's bytes, in base64: empty in the last reply
    /// of a stream.
    pub data: String,
    /// The capture's size so far, in bytes.
    pub bytes: i64,
    /// Packets captured so far.
    pub packets: i64,
    /// Why it ended, in the last reply: `time` (its time limit),
    /// `size` (its size limit; the packet past it is left out) or
    /// `stopped` (tcpdump stopped, the interface gone, say).
    pub end: Option<String>,
}

/// The client side of `org.sparewall.Diagnostics`, in a module of its own:
/// the proxy's generated code takes `Logs`'s filters as arguments.
mod diagnostics {
    #![allow(clippy::too_many_arguments)]

    use super::{
        CaptureReply, FirewallError, HitReply, HitsReply, LogReply, LogsReply, NeighboursReply,
        RoutesReply, ToolReply,
    };

    /// Each method takes `node`: this node's name or none for this
    /// node, its peer's in a pair for the peer's, through this node (#268).
    #[zlink::proxy("org.sparewall.Diagnostics")]
    pub trait DiagnosticsProxy {
        /// Entries of Sparewall's units, newest first.
        async fn logs(
            &mut self,
            units: Option<&[String]>,
            priority: Option<&str>,
            since: Option<&str>,
            until: Option<&str>,
            grep: Option<&str>,
            limit: Option<i64>,
            before: Option<&str>,
            node: Option<&str>,
        ) -> zlink::Result<Result<LogsReply, FirewallError>>;
        /// New entries as they are logged.
        #[zlink(more, rename = "FollowLogs")]
        async fn follow_logs(
            &mut self,
            units: Option<&[String]>,
            priority: Option<&str>,
            grep: Option<&str>,
            node: Option<&str>,
        ) -> zlink::Result<
            impl futures_util::Stream<Item = zlink::Result<Result<LogReply, FirewallError>>>,
        >;
        /// Hits of logged rules, newest first.
        async fn hits(
            &mut self,
            rule: Option<&str>,
            pair: Option<&str>,
            address: Option<&str>,
            port: Option<i64>,
            since: Option<&str>,
            until: Option<&str>,
            limit: Option<i64>,
            before: Option<&str>,
            node: Option<&str>,
        ) -> zlink::Result<Result<HitsReply, FirewallError>>;
        /// New hits as they are logged.
        #[zlink(more, rename = "FollowHits")]
        async fn follow_hits(
            &mut self,
            rule: Option<&str>,
            pair: Option<&str>,
            address: Option<&str>,
            port: Option<i64>,
            node: Option<&str>,
        ) -> zlink::Result<
            impl futures_util::Stream<Item = zlink::Result<Result<HitReply, FirewallError>>>,
        >;
        /// The neighbour table, of one network or all.
        async fn neighbours(
            &mut self,
            network: Option<&str>,
            node: Option<&str>,
        ) -> zlink::Result<Result<NeighboursReply, FirewallError>>;
        /// Routes, of one network or all, of one family (`4`, `6`) or both.
        async fn routes(
            &mut self,
            network: Option<&str>,
            family: Option<&str>,
            node: Option<&str>,
        ) -> zlink::Result<Result<RoutesReply, FirewallError>>;
        /// Ping a host from the node, from a network's address if named.
        #[zlink(more)]
        async fn ping(
            &mut self,
            host: &str,
            network: Option<&str>,
            count: Option<i64>,
            node: Option<&str>,
        ) -> zlink::Result<
            impl futures_util::Stream<Item = zlink::Result<Result<ToolReply, FirewallError>>>,
        >;
        /// Trace the route to a host from the node.
        #[zlink(more)]
        async fn traceroute(
            &mut self,
            host: &str,
            network: Option<&str>,
            node: Option<&str>,
        ) -> zlink::Result<
            impl futures_util::Stream<Item = zlink::Result<Result<ToolReply, FirewallError>>>,
        >;
        /// Look a name up from the node.
        #[zlink(more)]
        async fn lookup(
            &mut self,
            name: &str,
            record: Option<&str>,
            server: Option<&str>,
            node: Option<&str>,
        ) -> zlink::Result<
            impl futures_util::Stream<Item = zlink::Result<Result<ToolReply, FirewallError>>>,
        >;
        /// Capture packets on a network, as a pcap (#265).
        #[zlink(more)]
        async fn capture(
            &mut self,
            network: &str,
            filter: Option<&str>,
            seconds: Option<i64>,
            max_size: Option<i64>,
            node: Option<&str>,
        ) -> zlink::Result<
            impl futures_util::Stream<Item = zlink::Result<Result<CaptureReply, FirewallError>>>,
        >;
    }
}
pub use diagnostics::DiagnosticsProxy;
