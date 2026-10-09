//! Coordinator logic: the generation store, the apply/confirm/rollback
//! state machine, health, and the adapters that touch the system.

pub mod backup;
pub mod coordinator;
pub mod health;
pub mod linux;
pub mod metrics;
pub mod pair;
pub mod store;
pub mod system;

use std::path::Path;

pub use coordinator::{ApplyOptions, ApplyResult, Coordinator, Event};
pub use health::{Check, Health, Level};
pub use store::{Generation, Store};
pub use system::System;

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
}

impl Error {
    pub fn io(path: &Path, source: std::io::Error) -> Self {
        Error::Io {
            path: path.display().to_string(),
            source,
        }
    }
}
