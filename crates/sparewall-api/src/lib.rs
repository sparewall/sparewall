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
    pub health: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct BackupReply {
    pub path: String,
    pub digest: String,
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
    ) -> zlink::Result<Result<ApplyReply, FirewallError>>;
    async fn merge(
        &mut self,
        patch: &Value,
        base: i64,
        confirm_seconds: Option<i64>,
        dry_run: Option<bool>,
    ) -> zlink::Result<Result<ApplyReply, FirewallError>>;
    async fn patch(
        &mut self,
        ops: &Value,
        base: i64,
        confirm_seconds: Option<i64>,
        dry_run: Option<bool>,
    ) -> zlink::Result<Result<ApplyReply, FirewallError>>;
    async fn confirm(&mut self, id: i64) -> zlink::Result<Result<Empty, FirewallError>>;
    async fn rollback(
        &mut self,
        id: Option<i64>,
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
