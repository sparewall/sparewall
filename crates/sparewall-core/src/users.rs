//! Named local users and browser sessions (design: "Browser
//! authentication").
//!
//! A user is a cluster secret, `user.<name>`, holding its role and a
//! crypt(3) password hash, so it reaches the peer and the encrypted
//! backup like the admin password, which is the built-in `admin` user.
//! Secret deletions do not reach the peer, so removing a user stores a
//! tombstone at a higher version instead.
//!
//! `login` checks a password and issues a session: a token from the
//! token store, tied to the user, that lasts [`SESSION_HOURS`]. Changing
//! or removing a user ends its sessions, here and on the peer when the
//! change arrives.

use serde::{Deserialize, Serialize};
use sparewall_config::identity::{LOCKED_PASSWORD, password_hash_ok};

use crate::Error;
use crate::coordinator::Coordinator;
use crate::secrets::{ADMIN_PASSWORD, SecretClass};
use crate::system::System;
use crate::tokens::{Role, TokenInfo};

/// Secret name prefix of a user.
pub const USER_PREFIX: &str = "user.";
/// The built-in user, whose password is [`ADMIN_PASSWORD`].
pub const ADMIN_USER: &str = "admin";
/// How long a browser session lasts.
pub const SESSION_HOURS: i64 = 12;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    role: Role,
    hash: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct User {
    pub name: String,
    pub role: Role,
    /// No password: the user cannot log in.
    pub locked: bool,
    pub updated: String,
}

/// User names: what a login prompt takes, and what fits a secret name.
pub fn user_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_".contains(c))
}

/// Whether a crypt(3) hash takes `password`. Logins check SHA-crypt
/// hashes (`$5$`, `$6$`), which `sparewall passwd` and `sparewall user`
/// make; another kind, seeded with the identity, never matches.
pub fn verify(hash: &str, password: &str) -> bool {
    use sha_crypt::password_hash::PasswordVerifier;
    (hash.starts_with("$5$") || hash.starts_with("$6$"))
        && sha_crypt::ShaCrypt::default()
            .verify_password(password.as_bytes(), hash)
            .is_ok()
}

/// A hash to check against when there is no user, so that a missing
/// user takes as long to refuse as a wrong password.
const DUMMY_HASH: &str = "$6$saltsaltsaltsalt$xBi0h9JAwekg0C/DjMgN2QuqkLmpxS6oSlGvlfbpVmNU6BoD2CIlyMob7DONgVGP/f3HoIdRtnZQ3hEVYIRer.";

impl<S: System> Coordinator<S> {
    fn user_record(&mut self, name: &str) -> Result<Option<Record>, Error> {
        if name == ADMIN_USER {
            return Ok(self.secret_get(ADMIN_PASSWORD)?.map(|v| Record {
                role: Role::Admin,
                hash: String::from_utf8(v).unwrap_or_default(),
                removed: false,
            }));
        }
        let Some(v) = self.secret_get(&format!("{USER_PREFIX}{name}"))? else {
            return Ok(None);
        };
        let r: Record =
            serde_json::from_slice(&v).map_err(|e| Error::Internal(format!("user {name}: {e}")))?;
        Ok((!r.removed).then_some(r))
    }

    /// Every user, `admin` first.
    pub fn users(&mut self) -> Result<Vec<User>, Error> {
        let mut out = vec![];
        let admin = self.secret_info(ADMIN_PASSWORD)?;
        let admin_hash = self.user_record(ADMIN_USER)?.map(|r| r.hash);
        out.push(User {
            name: ADMIN_USER.into(),
            role: Role::Admin,
            locked: admin_hash.is_none_or(|h| h == LOCKED_PASSWORD),
            updated: admin.map(|i| i.updated).unwrap_or_default(),
        });
        for info in self.secret_list()? {
            let Some(name) = info.name.strip_prefix(USER_PREFIX) else {
                continue;
            };
            if let Some(r) = self.user_record(name)? {
                out.push(User {
                    name: name.into(),
                    role: r.role,
                    locked: r.hash == LOCKED_PASSWORD,
                    updated: info.updated,
                });
            }
        }
        Ok(out)
    }

    /// Add a user or change its role or password hash (`!` locks it; an
    /// empty hash keeps an existing user's). `admin` keeps the admin role.
    /// Ends the user's sessions.
    pub fn user_set(&mut self, name: &str, role: Role, hash: &str) -> Result<(), Error> {
        if !user_name_ok(name) {
            return Err(Error::Validation(vec![format!(
                "invalid user name {name:?}: lowercase letters, digits, - and _, starting with a letter"
            )]));
        }
        let kept;
        let hash = if hash.is_empty() {
            kept = self
                .user_record(name)?
                .map(|r| r.hash)
                .ok_or_else(|| Error::Validation(vec![format!("no user named {name}")]))?;
            kept.as_str()
        } else {
            hash
        };
        if !password_hash_ok(hash) {
            return Err(Error::Validation(vec![
                "the password must be a crypt(3) hash or \"!\"".into(),
            ]));
        }
        if name == ADMIN_USER {
            if role != Role::Admin {
                return Err(Error::Validation(vec!["admin keeps the admin role".into()]));
            }
            self.secret_set(ADMIN_PASSWORD, hash.as_bytes(), SecretClass::Cluster)?;
            self.apply_admin_password()?;
        } else {
            let r = Record {
                role,
                hash: hash.into(),
                removed: false,
            };
            self.secret_set(
                &format!("{USER_PREFIX}{name}"),
                &serde_json::to_vec(&r).expect("json"),
                SecretClass::Cluster,
            )?;
        }
        self.end_sessions(name)?;
        tracing::info!(user = name, role = role.as_str(), "set a user");
        Ok(())
    }

    /// Remove a user; returns whether it existed. `admin` is locked with
    /// `sparewall passwd --lock` instead.
    pub fn user_remove(&mut self, name: &str) -> Result<bool, Error> {
        if name == ADMIN_USER {
            return Err(Error::Validation(vec![
                "admin cannot be removed; lock its password instead".into(),
            ]));
        }
        let Some(mut r) = self.user_record(name)? else {
            return Ok(false);
        };
        r.removed = true;
        r.hash = LOCKED_PASSWORD.into();
        self.secret_set(
            &format!("{USER_PREFIX}{name}"),
            &serde_json::to_vec(&r).expect("json"),
            SecretClass::Cluster,
        )?;
        self.end_sessions(name)?;
        tracing::info!(user = name, "removed a user");
        Ok(true)
    }

    /// Check a password and open a session: the session token (shown
    /// once) and its record. `None` for a wrong user or password.
    pub fn login(
        &mut self,
        name: &str,
        password: &str,
    ) -> Result<Option<(String, TokenInfo)>, Error> {
        let record = if user_name_ok(name) {
            self.user_record(name)?
        } else {
            None
        };
        let hash = record.as_ref().map_or(DUMMY_HASH, |r| r.hash.as_str());
        let ok = verify(hash, password);
        let Some(r) = record.filter(|_| ok) else {
            tracing::info!(user = name, "refused a login");
            return Ok(None);
        };
        self.prune_tokens()?;
        let session = self.session_create(name, r.role, SESSION_HOURS * 3600)?;
        tracing::info!(user = name, role = r.role.as_str(), "logged in");
        Ok(Some(session))
    }

    /// After cluster secrets arrived from the peer: end the sessions of
    /// users that changed there.
    pub fn users_changed(&mut self, changed: &[String]) -> Result<(), Error> {
        for n in changed {
            if let Some(name) = n.strip_prefix(USER_PREFIX) {
                self.end_sessions(name)?;
            } else if n == ADMIN_PASSWORD {
                self.end_sessions(ADMIN_USER)?;
            }
        }
        Ok(())
    }
}
