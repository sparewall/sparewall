//! Coordinator logic: the generation store, the apply/confirm/rollback
//! state machine, health, and the adapters that touch the system.

pub mod backup;
pub mod coordinator;
pub mod health;
pub mod host;
pub mod linux;
pub mod metrics;
pub mod nft_state;
pub mod pair;
pub mod seal;
pub mod secrets;
pub mod selinux;
pub mod store;
pub mod system;
pub mod tokens;
pub mod users;

use std::path::Path;

pub use coordinator::{
    ApplyOptions, ApplyResult, Coordinator, Event, PEER_CONFIRM_SECONDS, PeerGate,
};
pub use health::{Check, Health, Level};
pub use store::{Generation, Store};
pub use system::System;

/// The release version: CI sets `SPAREWALL_VERSION` from the tag (or from
/// `git describe` between tags), so a build says which release it is
/// without anyone editing Cargo.toml. A local build falls back to Cargo's
/// (as does an image built without the build argument, which sets it empty).
pub const VERSION: &str = match option_env!("SPAREWALL_VERSION") {
    Some(v) if !v.is_empty() => v,
    _ => env!("CARGO_PKG_VERSION"),
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("validation failed: {}", .0.join("; "))]
    Validation(Vec<String>),
    #[error("conflict: the configuration changed (current generation is {current})")]
    Conflict { current: u64 },
    #[error("generation {0} not found")]
    NotFound(u64),
    #[error("generation {0} is not waiting for confirmation")]
    NotPending(u64),
    #[error("dry run failed: {0}")]
    Check(String),
    #[error("apply failed: {0}")]
    Apply(String),
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("internal error: {0}")]
    Internal(String),
    /// The caller's role does not allow the change.
    #[error("permission denied for role {role}: {reason}")]
    Denied { role: String, reason: String },
}

impl Error {
    pub fn io(path: &Path, source: std::io::Error) -> Self {
        Error::Io {
            path: path.display().to_string(),
            source,
        }
    }
}
