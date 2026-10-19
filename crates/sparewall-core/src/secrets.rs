//! The secret store (design: "Secret storage").
//!
//! Each secret is encrypted at rest for this node with `systemd-creds`
//! (bound to the TPM2 where present) in `<state>/secrets/<name>.cred`,
//! with metadata beside it. Secrets are write-only through the API; the
//! coordinator decrypts them only to hand them to a daemon in tmpfs or to
//! send cluster secrets to the peer, which re-encrypts them with its own
//! key.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sparewall_config::Document;

use crate::Error;
use crate::coordinator::Coordinator;
use crate::store::write_atomic;
use crate::system::System;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretClass {
    /// Never leaves this node.
    Node,
    /// Shared by both nodes of a pair, synced through the tunnel.
    Cluster,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretInfo {
    pub name: String,
    pub class: SecretClass,
    pub version: u64,
    pub updated: String,
}

/// A cluster secret in transit to the peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedSecret {
    pub info: SecretInfo,
    pub value: Vec<u8>,
}

pub fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

/// The cluster secret holding the `admin` account's password hash (or
/// [`sparewall_config::identity::LOCKED_PASSWORD`]). Locking stores a new
/// version rather than deleting it, so the peer follows.
pub const ADMIN_PASSWORD: &str = "admin-password";

/// The secret holding a remote-access instance's server private key.
pub fn vpn_secret(instance: &str) -> String {
    format!("vpn-{instance}")
}

/// The remote-access peers with a preshared key: `(instance, peer,
/// secret name)`.
pub fn vpn_psk_refs(doc: &Document) -> Vec<(String, String, String)> {
    let mut v = Vec::new();
    for (name, vpn) in &doc.vpn {
        for (peer, p) in &vpn.peers {
            if let Some(r) = &p.preshared_key {
                let secret = r.strip_prefix("secret:").unwrap_or(r);
                v.push((name.clone(), peer.clone(), secret.to_string()));
            }
        }
    }
    v
}

/// Write an encrypted secret and its metadata into a state directory.
pub fn store_encrypted(state_dir: &Path, info: &SecretInfo, blob: &[u8]) -> Result<(), Error> {
    let dir = state_dir.join("secrets");
    fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    let p = dir.join(format!("{}.cred", info.name));
    write_atomic(&p, blob).map_err(|e| Error::io(&p, e))?;
    let m = dir.join(format!("{}.json", info.name));
    write_atomic(&m, &serde_json::to_vec_pretty(info).expect("json")).map_err(|e| Error::io(&m, e))
}

impl<S: System> Coordinator<S> {
    fn secrets_dir(&self) -> PathBuf {
        self.store().root().join("secrets")
    }

    pub fn secret_list(&self) -> Result<Vec<SecretInfo>, Error> {
        let dir = self.secrets_dir();
        let Ok(rd) = fs::read_dir(&dir) else {
            return Ok(vec![]);
        };
        let mut out: Vec<SecretInfo> = rd
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
            .filter_map(|e| serde_json::from_slice(&fs::read(e.path()).ok()?).ok())
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub fn secret_info(&self, name: &str) -> Result<Option<SecretInfo>, Error> {
        let p = self.secrets_dir().join(format!("{name}.json"));
        match fs::read(&p) {
            Ok(b) => serde_json::from_slice(&b)
                .map(Some)
                .map_err(|e| Error::Internal(format!("{}: {e}", p.display()))),
            Err(_) => Ok(None),
        }
    }

    /// Store a secret (a new version if it exists).
    pub fn secret_set(
        &mut self,
        name: &str,
        value: &[u8],
        class: SecretClass,
    ) -> Result<SecretInfo, Error> {
        let version = self.secret_info(name)?.map_or(1, |i| i.version + 1);
        self.secret_put(
            SecretInfo {
                name: name.to_string(),
                class,
                version,
                updated: jiff::Timestamp::now().to_string(),
            },
            value,
        )
    }

    fn secret_put(&mut self, info: SecretInfo, value: &[u8]) -> Result<SecretInfo, Error> {
        if !name_ok(&info.name) {
            return Err(Error::Validation(vec![format!(
                "secret names: letters, digits, '-', '_' and '.', at most 64: {:?}",
                info.name
            )]));
        }
        let blob = self.system().encrypt(&info.name, value)?;
        store_encrypted(self.store().root(), &info, &blob)?;
        tracing::info!(name = %info.name, version = info.version, "stored secret");
        Ok(info)
    }

    /// Decrypt a secret (never exposed through the API).
    pub fn secret_get(&mut self, name: &str) -> Result<Option<Vec<u8>>, Error> {
        let p = self.secrets_dir().join(format!("{name}.cred"));
        match fs::read(&p) {
            Ok(blob) => self.system().decrypt(name, &blob).map(Some),
            Err(_) => Ok(None),
        }
    }

    pub fn secret_delete(&mut self, name: &str) -> Result<bool, Error> {
        let dir = self.secrets_dir();
        let existed = dir.join(format!("{name}.json")).exists();
        let _ = fs::remove_file(dir.join(format!("{name}.cred")));
        let _ = fs::remove_file(dir.join(format!("{name}.json")));
        Ok(existed)
    }

    /// Cluster secrets, decrypted, to send to the peer.
    pub fn cluster_secrets(&mut self) -> Result<Vec<SharedSecret>, Error> {
        let mut out = Vec::new();
        for info in self.secret_list()? {
            if info.class == SecretClass::Cluster
                && let Some(value) = self.secret_get(&info.name)?
            {
                out.push(SharedSecret { info, value });
            }
        }
        Ok(out)
    }

    /// Store cluster secrets from the peer, keeping newer local versions.
    /// When both nodes made the same version independently (each applied
    /// the pairing document), both keep the one created first. Returns the
    /// names that changed.
    pub fn receive_secrets(&mut self, secrets: Vec<SharedSecret>) -> Result<Vec<String>, Error> {
        let mut changed = Vec::new();
        for s in secrets {
            if s.info.class != SecretClass::Cluster {
                continue;
            }
            let take = match self.secret_info(&s.info.name)? {
                None => true,
                Some(have) if have.version < s.info.version => true,
                Some(have) if have.version == s.info.version && s.info.updated < have.updated => {
                    self.secret_get(&s.info.name)?.as_deref() != Some(s.value.as_slice())
                }
                _ => false,
            };
            if take {
                changed.push(s.info.name.clone());
                self.secret_put(s.info, &s.value)?;
            }
        }
        Ok(changed)
    }

    /// Store the identity's seeded password hash as the admin password,
    /// at version 1, unless one exists: a later `sparewall passwd` is a
    /// higher version, so a seed never undoes it.
    pub fn seed_admin_password(&mut self) -> Result<(), Error> {
        let Some(hash) = self.identity().password_hash.clone() else {
            return Ok(());
        };
        if self.secret_info(ADMIN_PASSWORD)?.is_some() {
            return Ok(());
        }
        self.secret_set(ADMIN_PASSWORD, hash.as_bytes(), SecretClass::Cluster)?;
        tracing::info!("stored the seeded admin password");
        Ok(())
    }

    /// Set the admin account's password from the secret, if there is one.
    /// Without one the account stays as installed: SSH keys only.
    pub fn apply_admin_password(&mut self) -> Result<(), Error> {
        let Some(v) = self.secret_get(ADMIN_PASSWORD)? else {
            return Ok(());
        };
        let hash = String::from_utf8(v).unwrap_or_default();
        if !sparewall_config::identity::password_hash_ok(&hash) {
            return Err(Error::Validation(vec![format!(
                "the {ADMIN_PASSWORD} secret is not a password hash"
            )]));
        }
        self.system().set_admin_password(&hash)?;
        tracing::info!(
            locked = hash == sparewall_config::identity::LOCKED_PASSWORD,
            "set the admin password"
        );
        Ok(())
    }

    /// Generate the server key of every remote-access instance that lacks
    /// one. Only the node accepting a change does this; a pushed
    /// generation never generates keys, so both nodes share one.
    pub fn ensure_vpn_keys(&mut self, doc: &Document) -> Result<(), Error> {
        for name in doc.vpn.keys() {
            let secret = vpn_secret(name);
            if self.secret_info(&secret)?.is_none() {
                let (private, public) = self.system().wg_keypair()?;
                self.secret_set(&secret, private.as_bytes(), SecretClass::Cluster)?;
                tracing::info!(instance = %name, public, "generated the remote-access server key");
            }
        }
        Ok(())
    }

    /// After a remote-access key changed: install it and recreate the
    /// WireGuard interface, since networkd reads keys only at creation.
    pub fn refresh_vpn_keys(&mut self, changed: &[String]) -> Result<(), Error> {
        let Some(doc) = self.active_document()? else {
            return Ok(());
        };
        self.install_vpn_keys(&doc)?;
        let psks = vpn_psk_refs(&doc);
        for name in doc.vpn.keys() {
            let psk_changed = psks
                .iter()
                .any(|(i, _, secret)| i == name && changed.contains(secret));
            if changed.contains(&vpn_secret(name)) || psk_changed {
                self.system().netdev_recreate(name)?;
            }
        }
        Ok(())
    }

    /// Preshared keys the document references but the store lacks:
    /// `(instance, peer, secret name)`. Those peers cannot connect.
    pub fn missing_vpn_psks(
        &mut self,
        doc: &Document,
    ) -> Result<Vec<(String, String, String)>, Error> {
        let mut v = Vec::new();
        for r in vpn_psk_refs(doc) {
            if self.secret_info(&r.2)?.is_none() {
                v.push(r);
            }
        }
        Ok(v)
    }

    /// Hand the remote-access server keys to networkd (in tmpfs).
    pub fn install_vpn_keys(&mut self, doc: &Document) -> Result<(), Error> {
        for name in doc.vpn.keys() {
            match self.secret_get(&vpn_secret(name))? {
                Some(key) => self.system().install_key(
                    &sparewall_render::vpn_key_file(name),
                    &key,
                    "systemd-network",
                )?,
                None => {
                    tracing::warn!(instance = %name, "no server key yet for the remote-access VPN")
                }
            }
        }
        for (name, peer, secret) in vpn_psk_refs(doc) {
            match self.secret_get(&secret)? {
                Some(key) => self.system().install_key(
                    &sparewall_render::vpn_psk_file(&name, &peer),
                    &key,
                    "systemd-network",
                )?,
                None => {
                    tracing::warn!(instance = %name, peer, secret, "no preshared key yet for the remote-access peer")
                }
            }
        }
        Ok(())
    }

    /// The server public key of a remote-access instance.
    pub fn vpn_public_key(&mut self, instance: &str) -> Result<Option<String>, Error> {
        match self.secret_get(&vpn_secret(instance))? {
            Some(k) => {
                let private = String::from_utf8_lossy(&k).to_string();
                self.system().wg_public(&private).map(Some)
            }
            None => Ok(None),
        }
    }

    /// A WireGuard client configuration for one peer. The client keeps its
    /// own private key; the config has a placeholder for it.
    pub fn vpn_client_config(
        &mut self,
        instance: Option<&str>,
        peer: &str,
        port: Option<u16>,
    ) -> Result<String, Error> {
        let doc = self
            .active_document()?
            .ok_or_else(|| Error::Validation(vec!["no configuration applied".into()]))?;
        let (name, vpn) = match instance {
            Some(i) => doc
                .vpn
                .get_key_value(i)
                .ok_or_else(|| Error::Validation(vec![format!("no VPN instance {i:?}")]))?,
            None => doc
                .vpn
                .iter()
                .find(|(_, v)| v.peers.contains_key(peer))
                .ok_or_else(|| {
                    Error::Validation(vec![format!("no VPN instance has a peer {peer:?}")])
                })?,
        };
        let p = vpn
            .peers
            .get(peer)
            .ok_or_else(|| Error::Validation(vec![format!("vpn.{name}.peers has no {peer:?}")]))?;
        let server = self
            .vpn_public_key(name)?
            .ok_or_else(|| Error::Validation(vec![format!("vpn {name} has no server key yet")]))?;
        // The listen port, or one of the extra ports it is also reached on.
        let port = match port {
            None => vpn.listen_port,
            Some(p) if p == vpn.listen_port || vpn.extra_ports.contains(&p) => p,
            Some(p) => {
                return Err(Error::Validation(vec![format!(
                    "vpn {name} is not reached on port {p}: its listen_port is {}, extra_ports {:?}",
                    vpn.listen_port, vpn.extra_ports
                )]));
            }
        };
        let allowed = if vpn.client_allowed_ips.is_empty() {
            "0.0.0.0/0".to_string()
        } else {
            vpn.client_allowed_ips.join(", ")
        };
        let mut s = format!(
            "# Sparewall remote access: {name}, peer {peer}\n[Interface]\n\
             PrivateKey = <this client's private key: wg genkey>\nAddress = {}\n",
            p.addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
        if !vpn.dns.is_empty() {
            s.push_str(&format!(
                "DNS = {}\n",
                vpn.dns
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let psk = match &p.preshared_key {
            Some(r) => {
                let secret = r.strip_prefix("secret:").unwrap_or(r);
                let k = self.secret_get(secret)?.ok_or_else(|| {
                    Error::Validation(vec![format!(
                        "vpn.{name}.peers.{peer}: its preshared key {secret:?} is not set"
                    )])
                })?;
                format!("PresharedKey = {}\n", String::from_utf8_lossy(&k).trim())
            }
            None => String::new(),
        };
        s.push_str(&format!(
            "\n[Peer]\nPublicKey = {server}\n{psk}Endpoint = {}:{}\nAllowedIPs = {allowed}\n\
             # Keeps NAT mappings open while idle; it does not shorten the outage\n# after a failover (see the operations guide).\nPersistentKeepalive = 25\n",
            vpn.endpoint, port
        ));
        Ok(s)
    }
}
