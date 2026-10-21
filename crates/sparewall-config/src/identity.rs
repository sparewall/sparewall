//! The minimal node identity supplied at install time (design: Bootstrap).
//!
//! It arrives as systemd credentials on VMs (`sparewall.identity`, JSON or
//! YAML) or from a seed file on physical machines, and is recorded under
//! `/var/lib/sparewall/identity.json` at first boot.

use std::net::Ipv4Addr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::model::Cidr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// This node's name; selects its values in the shared document, and
    /// is its hostname.
    pub node: String,
    /// Admin SSH public keys, installed for the `admin` user.
    #[serde(default)]
    pub ssh_keys: Vec<String>,
    /// The management port: the only interface bootstrap mode brings up.
    pub management: BootstrapPort,
    /// A crypt(3) hash for the `admin` account's console password, the
    /// break-glass path before the network is right. Stored as the
    /// `admin-password` cluster secret at first boot, unless one exists;
    /// `sparewall passwd` replaces it later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapPort {
    /// Permanent MAC address (or udev path) of the management NIC.
    pub nic: String,
    /// 802.1Q VLAN of management on that NIC, if tagged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// Static address; omit to use DHCP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Cidr>,
    /// Default gateway with a static address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Ipv4Addr>,
    /// DNS servers with a static address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv4Addr>,
}

impl Identity {
    /// Check the identity on its own.
    pub fn check(&self) -> Result<(), String> {
        use crate::validate::{mac_ok, node_name_ok, udev_path_ok};
        if !node_name_ok(&self.node) {
            return Err(format!("invalid node name {:?}", self.node));
        }
        let m = &self.management;
        if !mac_ok(&m.nic) && !udev_path_ok(&m.nic) {
            return Err(format!(
                "management.nic {:?} is not a MAC address or udev path",
                m.nic
            ));
        }
        if let Some(v) = m.vlan
            && !(1..=4094).contains(&v)
        {
            return Err("management.vlan must be 1-4094".into());
        }
        if m.address.is_none() && (m.gateway.is_some() || !m.dns.is_empty()) {
            return Err("management.gateway and dns need a static address".into());
        }
        if let Some(h) = &self.password_hash
            && (h == LOCKED_PASSWORD || !password_hash_ok(h))
        {
            return Err("password_hash must be a crypt(3) hash ($y$..., $6$...)".into());
        }
        Ok(())
    }
}

/// The `admin-password` value that locks the account: no password works.
pub const LOCKED_PASSWORD: &str = "!";

/// Whether a value may be stored as the admin password: a crypt(3) hash
/// (`$id$...`, as shadow holds it), or [`LOCKED_PASSWORD`]. Nothing that
/// could break the shadow line or a command line.
pub fn password_hash_ok(v: &str) -> bool {
    v == LOCKED_PASSWORD
        || (v.starts_with('$')
            && v.len() <= 512
            && v[1..].contains('$')
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || "$./=,-".contains(c)))
}
