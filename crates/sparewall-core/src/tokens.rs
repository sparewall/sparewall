//! API tokens (design: "Authentication" and "Roles").
//!
//! Tokens are random opaque strings, not JWTs, so revocation is immediate.
//! A token is shown once; the coordinator keeps only its SHA-256 with its
//! name, role, expiry and last use.

use std::io::Read;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::coordinator::Coordinator;
use crate::store::write_atomic;
use crate::system::System;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Verbose health and metrics only.
    Monitor,
    /// Read configuration and status.
    Viewer,
    /// Change, confirm, roll back and sync configuration.
    Operator,
    /// Everything, including tokens and secrets.
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "monitor" => Some(Role::Monitor),
            "viewer" => Some(Role::Viewer),
            "operator" => Some(Role::Operator),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Monitor => "monitor",
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    /// Whether this role may do what `needed` may. Monitor is not below
    /// viewer: it sees health and metrics, not configuration.
    pub fn allows(self, needed: Role) -> bool {
        match needed {
            Role::Monitor => true,
            _ => self >= needed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenInfo {
    pub name: String,
    pub role: Role,
    pub created: String,
    /// Unix time; `None` never expires.
    pub expires: Option<i64>,
    pub last_used: Option<String>,
    /// SHA-256 of the token.
    pub hash: String,
}

const PREFIX: &str = "swt_";

fn hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn random_token() -> Result<String, Error> {
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| Error::Internal(format!("random: {e}")))?;
    Ok(format!("{PREFIX}{}", hex::encode(buf)))
}

impl<S: System> Coordinator<S> {
    fn tokens_path(&self) -> std::path::PathBuf {
        self.store().root().join("tokens.json")
    }

    pub fn tokens(&self) -> Result<Vec<TokenInfo>, Error> {
        match std::fs::read(self.tokens_path()) {
            Ok(b) => {
                serde_json::from_slice(&b).map_err(|e| Error::Internal(format!("tokens.json: {e}")))
            }
            Err(_) => Ok(vec![]),
        }
    }

    fn save_tokens(&self, t: &[TokenInfo]) -> Result<(), Error> {
        let p = self.tokens_path();
        write_atomic(&p, &serde_json::to_vec_pretty(t).expect("json"))
            .map_err(|e| Error::io(&p, e))?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        Ok(())
    }

    /// Create a token; returns it (shown once) and its record.
    pub fn token_create(
        &mut self,
        name: &str,
        role: Role,
        ttl_days: Option<u32>,
    ) -> Result<(String, TokenInfo), Error> {
        if !crate::secrets::name_ok(name) {
            return Err(Error::Validation(vec![format!(
                "invalid token name {name:?}"
            )]));
        }
        let mut all = self.tokens()?;
        if all.iter().any(|t| t.name == name) {
            return Err(Error::Validation(vec![format!(
                "a token named {name:?} exists; revoke it first"
            )]));
        }
        let token = random_token()?;
        let now = jiff::Timestamp::now();
        let info = TokenInfo {
            name: name.to_string(),
            role,
            created: now.to_string(),
            expires: ttl_days.map(|d| now.as_second() + i64::from(d) * 86_400),
            last_used: None,
            hash: hash(&token),
        };
        all.push(info.clone());
        self.save_tokens(&all)?;
        tracing::info!(name, role = role.as_str(), "created API token");
        Ok((token, info))
    }

    pub fn token_revoke(&mut self, name: &str) -> Result<bool, Error> {
        let mut all = self.tokens()?;
        let before = all.len();
        all.retain(|t| t.name != name);
        self.save_tokens(&all)?;
        Ok(all.len() != before)
    }

    /// The role a presented token grants, recording its use.
    pub fn token_check(&mut self, token: &str) -> Result<Option<Role>, Error> {
        Ok(self.token_use(token)?.map(|t| t.role))
    }

    /// The record of a presented, unexpired token, recording its use.
    pub fn token_use(&mut self, token: &str) -> Result<Option<TokenInfo>, Error> {
        if !token.starts_with(PREFIX) {
            return Ok(None);
        }
        let h = hash(token);
        let mut all = self.tokens()?;
        let now = jiff::Timestamp::now();
        let Some(t) = all.iter_mut().find(|t| t.hash == h) else {
            return Ok(None);
        };
        if t.expires.is_some_and(|e| e <= now.as_second()) {
            return Ok(None);
        }
        t.last_used = Some(now.to_string());
        let t = t.clone();
        self.save_tokens(&all)?;
        Ok(Some(t))
    }
}

/// The record of the token with SHA-256 `hash` in the store at `root`, if
/// it still exists and has not expired. Reads without the coordinator, so
/// that a bound connection can check its token on every call while a
/// change holds the coordinator.
pub fn current(root: &std::path::Path, hash: &str) -> Result<Option<TokenInfo>, Error> {
    let p = root.join("tokens.json");
    let all: Vec<TokenInfo> = match std::fs::read(&p) {
        Ok(b) => {
            serde_json::from_slice(&b).map_err(|e| Error::Internal(format!("tokens.json: {e}")))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
        Err(e) => return Err(Error::io(&p, e)),
    };
    let now = jiff::Timestamp::now().as_second();
    Ok(all
        .into_iter()
        .find(|t| t.hash == hash && t.expires.is_none_or(|e| e > now)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        assert!(Role::Admin.allows(Role::Operator));
        assert!(Role::Monitor.allows(Role::Monitor));
        assert!(!Role::Monitor.allows(Role::Viewer));
        assert!(Role::Viewer.allows(Role::Monitor));
        assert!(!Role::Operator.allows(Role::Admin));
    }
}
