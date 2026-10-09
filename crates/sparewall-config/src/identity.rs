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
    /// This node's name; selects its values in the shared document.
    pub node: String,
    /// Admin SSH public keys, installed for the `admin` user.
    #[serde(default)]
    pub ssh_keys: Vec<String>,
    /// The management port: the only interface bootstrap mode brings up.
    pub management: BootstrapPort,
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
        use crate::validate::{mac_ok, udev_path_ok};
        if !self
            .node
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            || !self.node.starts_with(|c: char| c.is_ascii_lowercase())
        {
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
        Ok(())
    }
}
