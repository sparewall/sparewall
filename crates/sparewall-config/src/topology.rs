//! Derived facts about a document: interface names, zone membership, subnets.

use std::collections::BTreeMap;

use ipnet::Ipv4Net;

use crate::model::{Document, Network, NetworkRole};

/// Name of the WireGuard interface for the pair's sync tunnel.
pub const SYNC_TUNNEL_IFACE: &str = "swsync";
/// Default UDP port of the sync tunnel.
pub const SYNC_TUNNEL_PORT: u16 = 51871;
/// The built-in zone for traffic to and from the firewall itself.
pub const SELF_ZONE: &str = "self";
/// Interface names the coordinator reserves.
pub const RESERVED_IFACES: &[&str] = &["lo", SYNC_TUNNEL_IFACE];

impl Document {
    /// True for an HA pair, false for a standalone node.
    pub fn is_pair(&self) -> bool {
        self.cluster.nodes.len() == 2
    }

    /// The other node of a pair.
    pub fn peer_of(&self, node: &str) -> Option<&str> {
        if !self.is_pair() {
            return None;
        }
        self.cluster
            .nodes
            .iter()
            .map(String::as_str)
            .find(|n| *n != node)
    }

    /// The kernel interface a network lives on: its own VLAN interface, or
    /// the port interface for the port's untagged network.
    pub fn network_iface<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        let net = self.networks.get(name)?;
        Some(if net.vlan.is_some() { name } else { &net.port })
    }

    /// The zone a network belongs to.
    pub fn zone_of_network(&self, network: &str) -> Option<&str> {
        self.zones
            .iter()
            .find(|(_, z)| z.networks.iter().any(|n| n == network))
            .map(|(name, _)| name.as_str())
    }

    /// Interfaces in a zone: its networks' interfaces plus any remote-access
    /// VPN interfaces assigned to it.
    pub fn zone_ifaces(&self, zone: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Some(z) = self.zones.get(zone) {
            for n in &z.networks {
                if let Some(i) = self.network_iface(n) {
                    out.push(i.to_string());
                }
            }
        }
        for (name, vpn) in &self.vpn {
            if vpn.zone == zone {
                out.push(name.clone());
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// The subnet of a network as seen from `node`: from the node's own
    /// address, else from the gateway address.
    pub fn subnet(&self, network: &str, node: &str) -> Option<Ipv4Net> {
        let net = self.networks.get(network)?;
        net.addresses
            .get(node)
            .or(net.vip.as_ref())
            .map(|c| c.0.trunc())
    }

    /// Any subnet of a network, regardless of node.
    pub fn any_subnet(&self, network: &str) -> Option<Ipv4Net> {
        let net = self.networks.get(network)?;
        net.vip
            .as_ref()
            .or_else(|| net.addresses.values().next())
            .map(|c| c.0.trunc())
    }

    /// Networks with a given role.
    pub fn networks_with_role(
        &self,
        role: NetworkRole,
    ) -> impl Iterator<Item = (&String, &Network)> {
        self.networks.iter().filter(move |(_, n)| n.role == role)
    }

    /// The network that contains `addr`, if any.
    pub fn network_containing(&self, addr: std::net::Ipv4Addr) -> Option<&str> {
        self.networks
            .keys()
            .find(|n| self.any_subnet(n).is_some_and(|s| s.contains(&addr)))
            .map(String::as_str)
    }

    /// Parse `"from->to"`.
    pub fn split_pair(key: &str) -> Option<(&str, &str)> {
        let (a, b) = key.split_once("->")?;
        let (a, b) = (a.trim(), b.trim());
        (!a.is_empty() && !b.is_empty()).then_some((a, b))
    }

    /// Port roles used on a node, by role name.
    pub fn node_ports(&self, node: &str) -> BTreeMap<&str, &crate::model::Port> {
        self.ports
            .get(node)
            .map(|m| m.iter().map(|(k, v)| (k.as_str(), v)).collect())
            .unwrap_or_default()
    }
}
