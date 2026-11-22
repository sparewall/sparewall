//! Coordinator logic: the generation store, the apply/confirm/rollback
//! state machine, health, and the adapters that touch the system.

pub mod backup;
pub mod coordinator;
pub mod health;
pub mod host;
pub mod hostop;
pub mod ipv6;
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
pub mod withdrawn;

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

/// A reason a document or a request is refused, with the part of the
/// document it concerns when there is one (#305).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The validator's path, e.g. `networks.lan.dhcp.ranges[0]`.
    pub path: Option<String>,
    /// The same place as an RFC 6901 JSON Pointer:
    /// `/networks/lan/dhcp/ranges/0`.
    pub pointer: Option<String>,
    pub message: String,
}

impl Problem {
    /// A problem at `path` in the document; its pointer follows from it.
    pub fn at(path: impl Into<String>, message: impl std::fmt::Display) -> Self {
        let path = path.into();
        Problem {
            pointer: sparewall_config::pointer(&path),
            path: Some(path),
            message: message.to_string(),
        }
    }
}

impl From<String> for Problem {
    fn from(message: String) -> Self {
        Problem {
            path: None,
            pointer: None,
            message,
        }
    }
}

impl From<&str> for Problem {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

/// As the CLI and the `errors` strings have always shown it: `path: message`.
impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.path {
            Some(p) => write!(f, "{p}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

fn joined(problems: &[Problem]) -> String {
    problems
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("validation failed: {}", joined(.0))]
    Validation(Vec<Problem>),
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
    /// A refusal with no place in the document.
    pub fn invalid(message: impl Into<String>) -> Self {
        Error::Validation(vec![Problem::from(message.into())])
    }

    /// A refusal at `path` in the document.
    pub fn invalid_at(path: impl Into<String>, message: impl std::fmt::Display) -> Self {
        Error::Validation(vec![Problem::at(path, message)])
    }

    pub fn io(path: &Path, source: std::io::Error) -> Self {
        Error::Io {
            path: path.display().to_string(),
            source,
        }
    }
}
