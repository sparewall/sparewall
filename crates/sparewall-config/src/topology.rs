//! Derived facts about a document: interface names, zone membership, subnets.

use std::collections::BTreeMap;

use ipnet::Ipv4Net;

use crate::model::{Document, Ipv6Mode, Match, MatchItem, Network, NetworkRole, ObjectKind};

/// Name of the WireGuard interface for the pair's sync tunnel.
pub const SYNC_TUNNEL_IFACE: &str = "swsync";
/// Default UDP port of the sync tunnel.
pub const SYNC_TUNNEL_PORT: u16 = 51871;
/// The built-in zone for traffic to and from the firewall itself.
pub const SELF_ZONE: &str = "self";
/// The public side of a pair's WAN with private node addresses (#54,
/// #176): a macvlan with the VRRP virtual MAC, so the ISP sees one MAC
/// whichever node is the master. A leased WAN's is up on the master only
/// (it runs the DHCP client); a static block's is up on both nodes and
/// carries the gateway addresses and the public route on the master.
pub const LEASE_IFACE: &str = "swwan";
/// The mark WireGuard puts on its own packets in a pair with site-to-site
/// peers, and the routing table marked packets use (#148): keepalived fills
/// it on the master with routes from the gateway address, so the master's
/// handshakes leave from it; on the backup it is empty, and the output
/// chain drops them.
pub const VPN_FWMARK: u32 = 0x5357;
pub const VPN_TABLE: u32 = 5357;
/// The first routing table of the VPN clients (#149), one each in name
/// order, and the priorities of the rules that send the routed networks'
/// traffic there (two per network: the main table without its default
/// route first, then the client's).
pub const VPN_CLIENT_TABLE: u32 = 5360;
pub const VPN_CLIENT_RULE_PRIORITY: u32 = 2000;
/// Interface names the coordinator reserves.
pub const RESERVED_IFACES: &[&str] = &["lo", SYNC_TUNNEL_IFACE, LEASE_IFACE];
/// The name prefix of the macvlans that carry a pair's inside networks'
/// IPv6 gateway (#215), `swgw<vrid>`: see [`Document::ipv6_gateway_iface`].
pub const IPV6_GATEWAY_IFACE_PREFIX: &str = "swgw";
/// A pair's inside networks' IPv6 gateway address (#215): link-local, as
/// RFC 5798 has a VRRP router's first IPv6 address, so a new prefix
/// changes nothing for hosts' default router.
pub const IPV6_GATEWAY: std::net::Ipv6Addr = std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

/// Whether the coordinator reserves an interface name: one of
/// [`RESERVED_IFACES`], or `swgw` and a number.
pub fn reserved_iface(name: &str) -> bool {
    RESERVED_IFACES.contains(&name)
        || name
            .strip_prefix(IPV6_GATEWAY_IFACE_PREFIX)
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

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
                if self.vmac_wan(n) {
                    out.push(LEASE_IFACE.to_string());
                }
                out.extend(self.ipv6_gateway_iface(n));
            }
        }
        for (name, vpn) in &self.vpn {
            if vpn.zone == zone {
                out.push(name.clone());
            }
        }
        for (name, c) in &self.vpn_clients {
            if c.zone == zone {
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

    /// For a pair's WAN whose gateway address lies outside the nodes' own
    /// subnet (#54), that private subnet: the nodes hold private
    /// addresses, and the master holds the public ones and the default
    /// route.
    pub fn split_wan(&self, network: &str) -> Option<Ipv4Net> {
        let net = self.networks.get(network)?;
        if !self.is_pair() || net.role != NetworkRole::Wan || net.dhcp_client {
            return None;
        }
        let vip = net.vip.as_ref()?;
        let private = net.addresses.values().next()?.0.trunc();
        (!private.contains(&vip.0.addr())).then_some(private)
    }

    /// A VPN client's routing table.
    pub fn vpn_client_table(&self, client: &str) -> Option<u32> {
        self.vpn_clients
            .keys()
            .position(|k| k == client)
            .map(|i| VPN_CLIENT_TABLE + i as u32)
    }

    /// The VPN client a network's traffic leaves through, if any.
    pub fn vpn_client_of(&self, network: &str) -> Option<&str> {
        self.vpn_clients
            .iter()
            .find(|(_, c)| c.route.networks.iter().any(|n| n == network))
            .map(|(k, _)| k.as_str())
    }

    /// Whether any VPN has a site-to-site peer (one with an endpoint).
    pub fn has_site_peers(&self) -> bool {
        self.vpn
            .values()
            .any(|v| v.peers.values().any(|p| p.endpoint.is_some()))
    }

    /// The WANs with a static gateway address and gateway, whose routes
    /// from that address the master puts in [`VPN_TABLE`] in a pair with
    /// site-to-site peers (#148).
    pub fn site_source_wans(&self) -> Vec<&str> {
        if !self.is_pair() || !self.has_site_peers() {
            return vec![];
        }
        self.networks
            .iter()
            .filter(|(_, n)| {
                n.role == NetworkRole::Wan
                    && !n.dhcp_client
                    && n.vip.is_some()
                    && n.gateway.is_some()
            })
            .map(|(k, _)| k.as_str())
            .collect()
    }

    /// For a pair's WAN with one DHCP lease for the pair (#54), the
    /// nodes' private subnet: the master runs the DHCP client on
    /// [`LEASE_IFACE`], with the VRRP virtual MAC of the network's `vrid`.
    pub fn leased_wan(&self, network: &str) -> Option<Ipv4Net> {
        let net = self.networks.get(network)?;
        if !self.is_pair() || net.role != NetworkRole::Wan || !net.dhcp_client {
            return None;
        }
        net.vrid?;
        Some(net.addresses.values().next()?.0.trunc())
    }

    /// Whether a network is a pair's WAN with private node addresses
    /// whose public side is [`LEASE_IFACE`] (#176): a leased one, or a
    /// static block that keeps `vmac` (#194).
    pub fn vmac_wan(&self, network: &str) -> bool {
        let vmac = self.networks.get(network).is_some_and(|n| n.vmac);
        (vmac && self.split_wan(network).is_some()) || self.leased_wan(network).is_some()
    }

    /// The interface a network's public addresses are on: [`LEASE_IFACE`]
    /// for a pair's WAN with private node addresses (unless a static
    /// block turns `vmac` off), else the network's own.
    pub fn public_iface<'a>(&'a self, network: &'a str) -> Option<&'a str> {
        if self.vmac_wan(network) {
            Some(LEASE_IFACE)
        } else {
            self.network_iface(network)
        }
    }

    /// The VRRP virtual MAC of a VRRP ID (RFC 5798).
    pub fn vrrp_mac(vrid: u8) -> String {
        format!("00:00:5e:00:01:{vrid:02x}")
    }

    /// The IPv6 VRRP virtual MAC of a VRRP ID (RFC 5798).
    pub fn vrrp6_mac(vrid: u8) -> String {
        format!("00:00:5e:00:02:{vrid:02x}")
    }

    /// For a pair's inside network with IPv6 (#215), the macvlan that
    /// carries its IPv6 gateway: [`IPV6_GATEWAY`], with the network's IPv6
    /// VRRP virtual MAC, up on the master only. The router advertisements
    /// leave from it, and hosts' IPv6 arrives on it. Named
    /// `swgw<vrid>`, since a network's name may already be 15 bytes.
    pub fn ipv6_gateway_iface(&self, network: &str) -> Option<String> {
        let net = self.networks.get(network)?;
        if !self.is_pair()
            || net.ipv6.is_none()
            || matches!(net.role, NetworkRole::Wan | NetworkRole::Sync)
        {
            return None;
        }
        Some(format!("{IPV6_GATEWAY_IFACE_PREFIX}{}", net.vrid?))
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

    /// Whether any network routes IPv6 (#212): without one, the ruleset
    /// drops IPv6 but link-local neighbour discovery, as before.
    pub fn routes_ipv6(&self) -> bool {
        self.networks.values().any(|n| n.ipv6.is_some())
    }

    /// The interfaces of the networks with IPv6 (a WAN's own link and its
    /// lease link; an inside network's own and, in a pair, its IPv6
    /// gateway's), sorted.
    pub fn ipv6_ifaces(&self) -> Vec<String> {
        self.ipv6_ifaces_where(|_, _| true)
    }

    /// The IPv6 networks' interfaces for which `pick(network, its mode)`.
    pub fn ipv6_ifaces_where(&self, pick: impl Fn(&Network, Ipv6Mode) -> bool) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for (name, n) in &self.networks {
            let Some(v6) = &n.ipv6 else { continue };
            if !pick(n, v6.mode) {
                continue;
            }
            v.extend(self.network_iface(name).map(str::to_string));
            if n.role == NetworkRole::Wan {
                v.extend(self.public_iface(name).map(str::to_string));
            }
            v.extend(self.ipv6_gateway_iface(name));
        }
        v.sort();
        v.dedup();
        v
    }

    /// An address match's items by family: IPv4 ones, then IPv6 ones.
    /// An `@object` goes by its type; anything else by how it parses.
    pub fn split_families(&self, m: &Match) -> (Vec<String>, Vec<String>) {
        let items: Vec<String> = match m {
            Match::Number(n) => vec![n.to_string()],
            Match::Text(s) => vec![s.clone()],
            Match::List(l) => l
                .iter()
                .map(|i| match i {
                    MatchItem::Number(n) => n.to_string(),
                    MatchItem::Text(s) => s.clone(),
                })
                .collect(),
        };
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for i in items {
            let six = match i.strip_prefix('@') {
                Some(o) => self
                    .objects
                    .get(o)
                    .is_some_and(|o| o.kind == ObjectKind::Ipv6),
                None => crate::validate::ipv6_element_ok(&i),
            };
            if six { v6.push(i) } else { v4.push(i) }
        }
        (v4, v6)
    }

    /// Port roles used on a node, by role name.
    pub fn node_ports(&self, node: &str) -> BTreeMap<&str, &crate::model::Port> {
        self.ports
            .get(node)
            .map(|m| m.iter().map(|(k, v)| (k.as_str(), v)).collect())
            .unwrap_or_default()
    }
}
