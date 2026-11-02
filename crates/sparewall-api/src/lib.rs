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
        errors: Vec<String>,
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
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallError::ValidationFailed { errors } => {
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
        }
    }
}

impl std::error::Error for FirewallError {}

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
