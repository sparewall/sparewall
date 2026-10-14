//! The `org.sparewall.Firewall` Varlink interface, shared by `sparewalld`
//! (which serves it) and the `sparewall` CLI (its first client).
//!
//! Interface changes are additive only; a breaking change gets a new
//! interface name (design: "Versioning and compatibility").

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zlink::introspect::{CustomType, ReplyError, Type};

pub const INTERFACE: &str = "org.sparewall.Firewall";
/// The root-only admin socket.
pub const SOCKET: &str = "/run/sparewall/org.sparewall.Firewall";

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
    ValidationFailed { errors: Vec<String> },
    Conflict { current: i64 },
    ConfirmTimeout { rolled_back_to: i64 },
    PeerUnreachable { peer: String },
    PermissionDenied { role: String },
    NotFound { id: i64 },
    NotPending { id: i64 },
    ApplyFailed { message: String },
    NotSupported { message: String },
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
            FirewallError::PermissionDenied { role } => {
                write!(f, "permission denied for role {role}")
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

#[zlink::proxy("org.sparewall.Auth")]
pub trait AuthProxy {
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
}

pub const UPGRADE_INTERFACE: &str = "org.sparewall.Upgrade";

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct UpgradeCheckReply {
    pub booted: Option<String>,
    pub target: String,
    pub available: bool,
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
    ) -> zlink::Result<Result<UpgradeStartReply, FirewallError>>;
}
