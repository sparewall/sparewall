//! Health levels and checks (design: "Health endpoints").

use serde::{Deserialize, Serialize};

/// `ok` and `degraded` mean the node can carry traffic; only `failed`
/// lowers VRRP priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Degraded,
    Failed,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Degraded => "degraded",
            Level::Failed => "failed",
        }
    }

    /// The HTTP status for `/readyz`.
    pub fn http_status(self) -> u16 {
        match self {
            Level::Ok | Level::Degraded => 200,
            Level::Failed => 503,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub level: Level,
    pub message: String,
}

impl Check {
    pub fn new(name: &str, level: Level, message: impl Into<String>) -> Self {
        Check {
            name: name.to_string(),
            level,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    pub level: Level,
    pub checks: Vec<Check>,
}

impl Health {
    pub fn from_checks(checks: Vec<Check>) -> Self {
        let level = checks.iter().map(|c| c.level).max().unwrap_or(Level::Ok);
        Health { level, checks }
    }

    pub fn check(&self, name: &str) -> Option<&Check> {
        self.checks.iter().find(|c| c.name == name)
    }
}
