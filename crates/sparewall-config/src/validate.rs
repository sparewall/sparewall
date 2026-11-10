//! Semantic checks beyond what the schema can express.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

use crate::model::*;
use crate::providers::{self, Role};
use crate::topology::{SELF_ZONE, reserved_iface};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warning,
    Error,
}

/// One validation finding, located by document path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub severity: Severity,
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// Run every semantic check. The document is acceptable if no issue has
/// [`Severity::Error`].
pub fn validate(doc: &Document) -> Vec<Issue> {
    run(doc, true)
}

/// The checks for a generation kept in history but not run: everything
/// but the rejection of settings not built yet, which earlier versions
/// accepted. A peer's history may hold such a generation; activating one
/// still needs [`validate`].
pub fn validate_history(doc: &Document) -> Vec<Issue> {
    run(doc, false)
}

fn run(doc: &Document, activation: bool) -> Vec<Issue> {
    let mut v = Validator {
        doc,
        issues: Vec::new(),
    };
    v.schema();
    v.cluster();
    v.ports();
    v.networks();
    v.networks_ipv6();
    v.management();
    v.zones();
    v.objects();
    v.policy();
    v.forwards();
    v.held_addresses();
    v.raw();
    v.dhcp();
    v.dns();
    v.logging();
    v.ntp();
    v.vpn();
    v.tls();
    v.secrets();
    if activation {
        v.unbuilt();
    }
    v.issues
        .sort_by(|a, b| b.severity.cmp(&a.severity).then(a.path.cmp(&b.path)));
    v.issues
}

/// Errors only, formatted.
pub fn errors(issues: &[Issue]) -> Vec<String> {
    issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .map(ToString::to_string)
        .collect()
}

/// Warnings only, formatted.
pub fn warnings(issues: &[Issue]) -> Vec<String> {
    issues
        .iter()
        .filter(|i| i.severity == Severity::Warning)
        .map(ToString::to_string)
        .collect()
}

struct Validator<'a> {
    doc: &'a Document,
    issues: Vec<Issue>,
}

fn ident_ok(s: &str, max: usize, extra: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
        && s.len() <= max
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(c))
}

/// Node names: lowercase letters, digits and '-', at most 31 bytes. A
/// node's name is its hostname too, so it is a DNS label: it starts with
/// a letter and does not end with '-'.
pub fn node_name_ok(s: &str) -> bool {
    ident_ok(s, 31, "-") && !s.ends_with('-')
}

/// Interface-name rules: lowercase, starts with a letter, at most 15 bytes.
pub fn iface_name_ok(s: &str) -> bool {
    ident_ok(s, 15, "-_")
}

/// Zone and object names become nft chain and set names.
pub fn nft_name_ok(s: &str) -> bool {
    ident_ok(s, 31, "_")
}

/// Certificate names become file and secret names (`tls-<name>`, lego's
/// `certificates/<name>.crt`): lowercase, a letter first, no separators.
pub fn cert_name_ok(s: &str) -> bool {
    ident_ok(s, 63, "-_")
}

pub fn mac_ok(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// A udev `ID_PATH`, e.g. `pci-0000:01:00.0`.
pub fn udev_path_ok(s: &str) -> bool {
    !s.is_empty()
        && s.contains('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || ":.-_+".contains(c))
        && !mac_ok(s)
}

pub fn wg_key_ok(s: &str) -> bool {
    s.len() == 44
        && s.ends_with('=')
        && s[..43]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
}

/// Parse `a.b.c.d-e.f.g.h`.
pub fn parse_range(s: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let (a, b) = s.split_once('-')?;
    let (a, b): (Ipv4Addr, Ipv4Addr) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
    (u32::from(a) <= u32::from(b)).then_some((a, b))
}

/// An IPv4 match element: address, prefix or range.
pub fn ipv4_element_ok(s: &str) -> bool {
    s.parse::<Ipv4Addr>().is_ok() || s.parse::<Ipv4Net>().is_ok() || parse_range(s).is_some()
}

/// Parse `2001:db8::1-2001:db8::ff`.
pub fn parse_range6(s: &str) -> Option<(Ipv6Addr, Ipv6Addr)> {
    let (a, b) = s.split_once('-')?;
    let (a, b): (Ipv6Addr, Ipv6Addr) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
    (u128::from(a) <= u128::from(b)).then_some((a, b))
}

/// An IPv6 match element: address, prefix or range.
pub fn ipv6_element_ok(s: &str) -> bool {
    s.parse::<Ipv6Addr>().is_ok() || s.parse::<Ipv6Net>().is_ok() || parse_range6(s).is_some()
}

/// A host's suffix in a network's /64 (`::20`): an IPv6 address whose
/// first 64 bits are zero, and which is not zero itself.
pub fn suffix_ok(s: &str) -> bool {
    s.parse::<Ipv6Addr>()
        .is_ok_and(|a| u128::from(a) >> 64 == 0 && u128::from(a) != 0)
}

/// An address an IPv6 prefix or host may use: not unspecified, loopback,
/// link-local or multicast.
fn ipv6_routable(a: Ipv6Addr) -> bool {
    !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || a.is_unicast_link_local())
}

/// The address families a rule's match allows: each is IPv4, IPv6, or
/// both (no address match at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Families {
    v4: bool,
    v6: bool,
}

impl Families {
    const BOTH: Families = Families { v4: true, v6: true };
    const NONE: Families = Families {
        v4: false,
        v6: false,
    };
    fn and(self, o: Families) -> Families {
        Families {
            v4: self.v4 && o.v4,
            v6: self.v6 && o.v6,
        }
    }
    fn or(self, o: Families) -> Families {
        Families {
            v4: self.v4 || o.v4,
            v6: self.v6 || o.v6,
        }
    }
    fn name(self) -> &'static str {
        match (self.v4, self.v6) {
            (true, true) => "IPv4 and IPv6",
            (true, false) => "IPv4",
            (false, true) => "IPv6",
            (false, false) => "no family",
        }
    }
}

/// A port match element: number or `low-high`.
pub fn port_element_ok(item: &MatchItem) -> bool {
    match item {
        MatchItem::Number(n) => (1..=65535).contains(n),
        MatchItem::Text(s) => match s.split_once('-') {
            Some((a, b)) => matches!(
                (a.parse::<u16>(), b.parse::<u16>()),
                (Ok(a), Ok(b)) if a >= 1 && a <= b
            ),
            None => s.parse::<u16>().is_ok_and(|n| n >= 1),
        },
    }
}

pub fn limit_ok(s: &str) -> bool {
    let mut words = s.split_whitespace();
    let rate_ok = words
        .next()
        .and_then(|r| r.split_once('/'))
        .is_some_and(|(n, unit)| {
            n.parse::<u32>().is_ok() && matches!(unit, "second" | "minute" | "hour" | "day")
        });
    let rest: Vec<&str> = words.collect();
    rate_ok
        && match rest.as_slice() {
            [] => true,
            ["burst", n] => n.parse::<u32>().is_ok(),
            _ => false,
        }
}

const KNOWN_PROTOS: &[&str] = &[
    "tcp", "udp", "icmp", "icmpv6", "sctp", "gre", "esp", "ah", "vrrp", "igmp",
];

impl Validator<'_> {
    fn err(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.issues.push(Issue {
            severity: Severity::Error,
            path: path.into(),
            message: msg.into(),
        });
    }

    fn warn(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.issues.push(Issue {
            severity: Severity::Warning,
            path: path.into(),
            message: msg.into(),
        });
    }

    fn nodes(&self) -> &[String] {
        &self.doc.cluster.nodes
    }

    fn is_node(&self, n: &str) -> bool {
        self.nodes().iter().any(|x| x == n)
    }

    fn schema(&mut self) {
        // Older revisions are read too: `schema` is the oldest revision that
        // reads the document, and documents written before revisions were
        // tracked may name an older one than the fields they use (#168).
        if !(1..=SCHEMA_VERSION).contains(&self.doc.schema) {
            self.err(
                "schema",
                format!(
                    "the document needs schema revision {}; this release reads revisions 1 to {SCHEMA_VERSION}: upgrade it first",
                    self.doc.schema
                ),
            );
        }
    }

    fn cluster(&mut self) {
        let c = &self.doc.cluster;
        match c.nodes.len() {
            1 | 2 => {}
            n => self.err(
                "cluster.nodes",
                format!("must list one or two nodes, not {n}"),
            ),
        }
        let mut seen = BTreeSet::new();
        for (i, n) in c.nodes.iter().enumerate() {
            if !node_name_ok(n) {
                self.err(
                    format!("cluster.nodes[{i}]"),
                    format!(
                        "invalid node name {n:?}: use at most 31 lowercase letters, digits and '-', starting with a letter and not ending with '-'"
                    ),
                );
            }
            if !seen.insert(n) {
                self.err(
                    format!("cluster.nodes[{i}]"),
                    format!("duplicate node {n:?}"),
                );
            }
        }
        let pair = self.doc.is_pair();
        match (&c.sync_network, pair) {
            (None, true) => self.err("cluster.sync_network", "an HA pair needs a sync network"),
            (Some(_), false) => self.err(
                "cluster.sync_network",
                "a standalone node has no sync network; remove it or add a second node",
            ),
            (Some(s), true) => match self.doc.networks.get(s) {
                None => self.err("cluster.sync_network", format!("no network named {s:?}")),
                // The sync tunnel may share an ordinary network, a two-NIC
                // pair's LAN (#177): what it carries is inside WireGuard,
                // which drops anything not from the peer's key. Not the
                // WAN.
                Some(n) if n.role == NetworkRole::Wan => self.err(
                    "cluster.sync_network",
                    format!("network {s:?} is the WAN: sync over a network of role sync, management or service"),
                ),
                Some(n) if c.nodes.iter().any(|node| !n.addresses.contains_key(node)) => self.err(
                    "cluster.sync_network",
                    format!("network {s:?} needs an address for each node, the tunnel's endpoints"),
                ),
                _ => {}
            },
            (None, false) => {}
        }
        for (n, key) in &c.sync_keys {
            if !self.is_node(n) {
                self.err(format!("cluster.sync_keys.{n}"), "not a cluster node");
            }
            if !wg_key_ok(key) {
                self.err(
                    format!("cluster.sync_keys.{n}"),
                    "not a WireGuard public key (44 base64 characters)",
                );
            }
        }
        if !pair && !c.sync_keys.is_empty() {
            self.warn("cluster.sync_keys", "ignored on a standalone node");
        }
        if let Some(vrrp) = &c.vrrp {
            if !pair {
                self.warn("cluster.vrrp", "ignored on a standalone node");
            }
            for n in vrrp.priority.keys() {
                if !self.is_node(n) {
                    self.err(format!("cluster.vrrp.priority.{n}"), "not a cluster node");
                }
            }
            if let Some(cs) = vrrp.advert_interval_cs
                && !(1..=4095).contains(&cs)
            {
                self.err("cluster.vrrp.advert_interval_cs", "must be 1-4095");
            }
            match vrrp.preempt_delay_s {
                Some(d) if !(1..=1000).contains(&d) => {
                    self.err("cluster.vrrp.preempt_delay_s", "must be 1-1000");
                }
                Some(d) => self.warn(
                    "cluster.vrrp.preempt_delay_s",
                    format!(
                        "the higher-priority node takes the gateway addresses back {d}s after it is up: the pair may bounce if it flaps"
                    ),
                ),
                None => {}
            }
        }
        if let Some(ct) = &c.conntrack
            && let Some(t) = ct.tcp_established_timeout
            && t < 300
        {
            self.err(
                "cluster.conntrack.tcp_established_timeout",
                "must be at least 300 seconds",
            );
        }
    }

    fn ports(&mut self) {
        let doc = self.doc;
        for (node, ports) in &doc.ports {
            if !self.is_node(node) {
                self.err(format!("ports.{node}"), "not a cluster node");
            }
            let mut hw: BTreeMap<&str, String> = BTreeMap::new();
            for (role, port) in ports {
                let p = format!("ports.{node}.{role}");
                if !iface_name_ok(role) || reserved_iface(role) {
                    self.err(
                        &p,
                        "port role names become interface names: lowercase, start with a letter, at most 15 characters, not reserved",
                    );
                }
                match (&port.nic, &port.bond) {
                    (Some(nic), None) => {
                        if !mac_ok(nic) && !udev_path_ok(nic) {
                            self.err(
                                format!("{p}.nic"),
                                "must be a MAC address or a udev path like pci-0000:01:00.0",
                            );
                        }
                        if let Some(prev) = hw.insert(nic, role.clone()) {
                            self.err(
                                format!("{p}.nic"),
                                format!("NIC already used by port {prev:?}"),
                            );
                        }
                    }
                    (None, Some(bond)) => {
                        if bond.members.is_empty() {
                            self.err(
                                format!("{p}.bond.members"),
                                "a bond needs at least one member",
                            );
                        }
                        for (i, m) in bond.members.iter().enumerate() {
                            if !mac_ok(m) && !udev_path_ok(m) {
                                self.err(
                                    format!("{p}.bond.members[{i}]"),
                                    "must be a MAC address or a udev path",
                                );
                            }
                            if let Some(prev) = hw.insert(m, role.clone()) {
                                self.err(
                                    format!("{p}.bond.members[{i}]"),
                                    format!("NIC already used by port {prev:?}"),
                                );
                            }
                        }
                        if bond.lacp_rate.is_some() && bond.mode != BondMode::Lacp {
                            self.err(
                                format!("{p}.bond.lacp_rate"),
                                "only valid with mode 802.3ad",
                            );
                        }
                        if let Some(pr) = &bond.primary {
                            if bond.mode != BondMode::ActiveBackup {
                                self.err(
                                    format!("{p}.bond.primary"),
                                    "only valid with mode active-backup",
                                );
                            }
                            if !bond.members.contains(pr) {
                                self.err(format!("{p}.bond.primary"), "must be one of the members");
                            }
                        }
                        if let Some(h) = &bond.hash_policy
                            && !["layer2", "layer3+4", "layer2+3", "encap2+3", "encap3+4"]
                                .contains(&h.as_str())
                        {
                            self.err(
                                format!("{p}.bond.hash_policy"),
                                format!("unknown hash policy {h:?}"),
                            );
                        }
                    }
                    _ => self.err(&p, "set exactly one of nic or bond"),
                }
                if let Some(m) = port.mtu
                    && !(576..=9216).contains(&m)
                {
                    self.err(format!("{p}.mtu"), "must be 576-9216");
                }
            }
        }
        // Every node binds every port role that networks use.
        let used: BTreeSet<&str> = doc.networks.values().map(|n| n.port.as_str()).collect();
        for node in self.nodes().to_vec() {
            for role in &used {
                if !doc.ports.get(&node).is_some_and(|p| p.contains_key(*role)) {
                    self.err(
                        format!("ports.{node}"),
                        format!(
                            "port role {role:?} is used by a network but not bound on node {node:?}"
                        ),
                    );
                }
            }
        }
    }

    fn networks(&mut self) {
        let doc = self.doc;
        let pair = doc.is_pair();
        let mut vlans: BTreeMap<(&str, Option<u16>), &str> = BTreeMap::new();
        let mut vrids: BTreeMap<u8, &str> = BTreeMap::new();
        let roles: BTreeSet<&str> = doc
            .ports
            .values()
            .flat_map(|m| m.keys())
            .map(String::as_str)
            .collect();
        let mut subnets: Vec<(Ipv4Net, &str)> = Vec::new();
        let mut wans = 0;
        for (name, net) in &doc.networks {
            let p = format!("networks.{name}");
            if !iface_name_ok(name) || reserved_iface(name) {
                self.err(&p, "network names become interface names: lowercase, start with a letter, at most 15 characters, not reserved");
            }
            if net.vlan.is_some() && roles.contains(name.as_str()) {
                self.err(&p, "a VLAN network cannot share its name with a port role");
            }
            if doc.vpn.contains_key(name) || doc.vpn_clients.contains_key(name) {
                self.err(&p, "name is already used by a VPN instance");
            }
            if !roles.contains(net.port.as_str()) && !doc.ports.is_empty() {
                self.err(
                    format!("{p}.port"),
                    format!("no port role {:?} on any node", net.port),
                );
            }
            if let Some(v) = net.vlan
                && !(1..=4094).contains(&v)
            {
                self.err(format!("{p}.vlan"), "must be 1-4094");
            }
            if let Some(prev) = vlans.insert((net.port.as_str(), net.vlan), name) {
                let what = net
                    .vlan
                    .map_or("the untagged network".to_string(), |v| format!("VLAN {v}"));
                self.err(
                    &p,
                    format!("{what} on port {:?} is already network {prev:?}", net.port),
                );
            }
            if net.role == NetworkRole::Wan {
                wans += 1;
            }
            // Addresses.
            for n in net.addresses.keys() {
                if !self.is_node(n) {
                    self.err(format!("{p}.addresses.{n}"), "not a cluster node");
                }
            }
            if net.dhcp_client {
                if !matches!(net.role, NetworkRole::Wan | NetworkRole::Management) {
                    self.err(
                        format!("{p}.dhcp_client"),
                        "only WAN and management networks can use a DHCP client",
                    );
                }
                let leased = pair && net.role == NetworkRole::Wan && !net.addresses.is_empty();
                if leased {
                    // One lease for the pair (#54): private node
                    // addresses, the lease on the master's virtual MAC.
                    self.node_addresses(&p, net);
                    if net.vrid.is_none() {
                        self.err(
                            format!("{p}.vrid"),
                            "a leased WAN with node addresses needs a VRRP ID, for its virtual MAC",
                        );
                    }
                    if net.vip.is_some() {
                        self.err(
                            format!("{p}.vip"),
                            "the lease is the public address of a leased WAN",
                        );
                    }
                } else if !net.addresses.is_empty() {
                    self.err(
                        format!("{p}.dhcp_client"),
                        "use either addresses or dhcp_client, not both (in a pair, a WAN may have both: one lease for the pair)",
                    );
                } else if pair && net.role == NetworkRole::Wan && net.vip.is_none() {
                    self.warn(format!("{p}.dhcp_client"), "each node leases its own address: failover changes the public address (give the nodes private addresses and a vrid for one lease for the pair)");
                }
            } else {
                self.node_addresses(&p, net);
            }
            let mut subnet: Option<Ipv4Net> = None;
            for (n, a) in &net.addresses {
                let s = a.0.trunc();
                if a.0.addr() == s.network() && a.0.prefix_len() < 31 {
                    self.err(
                        format!("{p}.addresses.{n}"),
                        "is the network address of its subnet",
                    );
                }
                match subnet {
                    None => subnet = Some(s),
                    Some(prev) if prev != s => self.err(
                        format!("{p}.addresses.{n}"),
                        format!("not in the same subnet as the other nodes ({prev})"),
                    ),
                    _ => {}
                }
            }
            let mut own: BTreeSet<Ipv4Addr> = BTreeSet::new();
            for a in net.addresses.values() {
                if !own.insert(a.0.addr()) {
                    self.err(
                        format!("{p}.addresses"),
                        format!("{} is used by both nodes", a.0.addr()),
                    );
                }
            }
            // A pair's static WAN may put its public addresses (the gateway
            // address, its extras and the ISP's gateway) in a subnet of
            // their own, the nodes holding private addresses (#54).
            let mut public: Option<Ipv4Net> = None;
            if let Some(vip) = &net.vip {
                if net.role == NetworkRole::Sync {
                    self.err(
                        format!("{p}.vip"),
                        "the sync network has no gateway address",
                    );
                }
                if let Some(s) = subnet
                    && vip.0.trunc() != s
                {
                    let v = vip.0.trunc();
                    let overlaps = v.contains(&s.network()) || s.contains(&v.network());
                    if pair && net.role == NetworkRole::Wan && !overlaps {
                        public = Some(v);
                        if vip.0.prefix_len() < 31
                            && (vip.0.addr() == v.network() || vip.0.addr() == v.broadcast())
                        {
                            self.err(
                                format!("{p}.vip"),
                                "is the network or broadcast address of its subnet",
                            );
                        }
                    } else if pair && net.role == NetworkRole::Wan {
                        self.err(
                            format!("{p}.vip"),
                            format!("{v} overlaps the nodes' subnet {s} without being it"),
                        );
                    } else {
                        self.err(
                            format!("{p}.vip"),
                            format!("not in the network's subnet {s}"),
                        );
                    }
                }
                if own.contains(&vip.0.addr()) {
                    self.err(
                        format!("{p}.vip"),
                        "must differ from the nodes' own addresses",
                    );
                }
                subnet = subnet.or(Some(vip.0.trunc()));
                if pair && net.vrid.is_none() {
                    self.err(
                        format!("{p}.vrid"),
                        "a gateway address in a pair needs a VRRP ID",
                    );
                }
            } else if net.vrid.is_some() && doc.leased_wan(name).is_none() {
                self.err(
                    format!("{p}.vrid"),
                    "a VRRP ID needs a gateway address (vip)",
                );
            }
            if !net.vmac && doc.split_wan(name).is_none() {
                self.err(
                    format!("{p}.vmac"),
                    "only a pair's WAN with private node addresses and a static block (vip) chooses its MAC",
                );
            }
            if let Some(id) = net.vrid {
                if id == 0 {
                    self.err(format!("{p}.vrid"), "must be 1-255");
                }
                if let Some(prev) = vrids.insert(id, name) {
                    self.err(
                        format!("{p}.vrid"),
                        format!("VRRP ID {id} is already used by network {prev:?}"),
                    );
                }
            }
            match (net.gateway, public) {
                (Some(_), _) if net.dhcp_client => {
                    self.err(format!("{p}.gateway"), "a DHCP client learns its gateway");
                }
                // The master's default route; the backup's leaves
                // through the master.
                (Some(gw), Some(s)) => {
                    if !s.contains(&gw) {
                        self.err(
                            format!("{p}.gateway"),
                            format!("not inside the gateway address's subnet {s}"),
                        );
                    } else if net
                        .vip
                        .iter()
                        .chain(&net.extra_vips)
                        .any(|v| v.0.addr() == gw)
                    {
                        self.err(format!("{p}.gateway"), "is one of the pair's own addresses");
                    }
                }
                (None, Some(s)) => self.err(
                    format!("{p}.gateway"),
                    format!("a WAN with private node addresses needs the ISP's gateway, in {s}"),
                ),
                (Some(gw), None) => {
                    if let Some(s) = subnet
                        && !s.contains(&gw)
                    {
                        self.err(format!("{p}.gateway"), format!("not inside {s}"));
                    }
                }
                (None, None) => {}
            }
            if let Some(s) = subnet {
                subnets.push((s, name));
            }
            if let Some(s) = public {
                subnets.push((s, name));
            }
            if let Some(m) = net.mtu
                && !(576..=9216).contains(&m)
            {
                self.err(format!("{p}.mtu"), "must be 576-9216");
            }
            if net.role == NetworkRole::Sync && !pair {
                self.err(&p, "a standalone node has no sync network");
            }
            if net.cake.is_some() && net.role != NetworkRole::Wan {
                self.warn(format!("{p}.cake"), "CAKE shaping is meant for the WAN");
            }
        }
        if wans > 1 {
            self.err("networks", "only one WAN network is supported");
        }
        // The lease follows the VRRP master.
        for name in doc.networks.keys() {
            if doc.leased_wan(name).is_some()
                && !doc
                    .networks
                    .values()
                    .any(|n| n.vip.is_some() && n.vrid.is_some())
            {
                self.err(
                    format!("networks.{name}.dhcp_client"),
                    "a leased WAN follows the master: some network needs a gateway address (vip)",
                );
            }
        }
        for (i, (a, an)) in subnets.iter().enumerate() {
            for (b, bn) in &subnets[i + 1..] {
                if a.contains(b) || b.contains(a) {
                    self.err(
                        format!("networks.{bn}"),
                        format!("subnet {b} overlaps network {an:?} ({a})"),
                    );
                }
            }
        }
    }

    /// Every node has an address on a statically addressed network.
    /// `networks.<name>.ipv6` (#211): the mode the role allows, the fields
    /// the mode takes, prefixes that do not overlap, and a delegated
    /// prefix to take subnets from.
    fn networks_ipv6(&mut self) {
        let doc = self.doc;
        let mut subnet_ids: BTreeMap<u16, &str> = BTreeMap::new();
        let mut prefixes: Vec<(Ipv6Net, &str)> = Vec::new();
        let delegating: Vec<(&str, Option<u8>)> = doc
            .networks
            .iter()
            .filter_map(|(n, net)| {
                let v6 = net.ipv6.as_ref()?;
                (net.role == NetworkRole::Wan && v6.mode == Ipv6Mode::Dhcpv6)
                    .then_some((n.as_str(), v6.prefix_length))
            })
            .collect();
        for (name, net) in &doc.networks {
            let Some(v6) = &net.ipv6 else { continue };
            let p = format!("networks.{name}.ipv6");
            let wan = net.role == NetworkRole::Wan;
            let mode = format!("{:?}", v6.mode).to_lowercase();
            match (net.role, v6.mode) {
                (NetworkRole::Sync, _) => {
                    self.err(&p, "the sync network is IPv4 only");
                    continue;
                }
                (NetworkRole::Wan, Ipv6Mode::Delegated) => {
                    self.err(format!("{p}.mode"), "a WAN takes dhcpv6, ra or static");
                }
                (_, Ipv6Mode::Dhcpv6 | Ipv6Mode::Ra) if !wan => {
                    self.err(
                        format!("{p}.mode"),
                        "an inside network takes delegated or static",
                    );
                }
                _ => {}
            }
            let only = |v: &mut Self, field: &str, set: bool, modes: &[Ipv6Mode], what: &str| {
                if set && !modes.contains(&v6.mode) {
                    v.err(format!("{p}.{field}"), format!("{what}, not {mode}"));
                }
            };
            only(
                self,
                "prefix_length",
                v6.prefix_length.is_some(),
                &[Ipv6Mode::Dhcpv6],
                "for mode dhcpv6",
            );
            only(
                self,
                "subnet_id",
                v6.subnet_id.is_some(),
                &[Ipv6Mode::Delegated],
                "for mode delegated",
            );
            only(
                self,
                "prefix",
                v6.prefix.is_some(),
                &[Ipv6Mode::Static],
                "for mode static",
            );
            let static_wan = wan && v6.mode == Ipv6Mode::Static;
            if !v6.addresses.is_empty() && !static_wan {
                self.err(
                    format!("{p}.addresses"),
                    "for a static WAN; on an inside network the node's address comes from the prefix",
                );
            }
            if v6.gateway.is_some() && !static_wan {
                self.err(format!("{p}.gateway"), "for a static WAN");
            }
            if v6.vip.is_some() && !(static_wan && doc.is_pair()) {
                self.err(format!("{p}.vip"), "for a pair's static WAN");
            }
            if doc.is_pair() {
                self.pair_ipv6(name, net, v6);
            }
            if let Some(dns) = &v6.dns {
                if wan {
                    self.err(
                        format!("{p}.dns"),
                        "for an inside network's router advertisements",
                    );
                }
                let mut seen = BTreeSet::new();
                for (i, a) in dns.iter().enumerate() {
                    if !ipv6_routable(*a) {
                        self.err(
                            format!("{p}.dns[{i}]"),
                            "not a routable address (link-local, multicast, loopback or ::)",
                        );
                    }
                    if !seen.insert(a) {
                        self.err(format!("{p}.dns[{i}]"), format!("{a} is listed twice"));
                    }
                }
            }
            if let Some(l) = v6.prefix_length
                && !(48..=64).contains(&l)
            {
                self.err(format!("{p}.prefix_length"), "48 to 64");
            }
            match v6.mode {
                Ipv6Mode::Delegated => {
                    let Some(id) = v6.subnet_id else {
                        self.err(format!("{p}.subnet_id"), "a delegated network needs one");
                        continue;
                    };
                    if let Some(prev) = subnet_ids.insert(id, name) {
                        self.err(
                            format!("{p}.subnet_id"),
                            format!("subnet {id} is also network {prev:?}'s"),
                        );
                    }
                    match delegating.as_slice() {
                        [] => self.err(
                            format!("{p}.mode"),
                            "no WAN has ipv6 mode dhcpv6 to delegate a prefix",
                        ),
                        // An invalid length is reported at the WAN. With
                        // none, the WAN asks for the default (#248).
                        [(_, asked)]
                            if (48..=64).contains(&asked.unwrap_or(DEFAULT_PREFIX_LENGTH))
                                && u32::from(id)
                                    >> (64 - asked.unwrap_or(DEFAULT_PREFIX_LENGTH))
                                    != 0 =>
                        {
                            let len = asked.unwrap_or(DEFAULT_PREFIX_LENGTH);
                            let default = if asked.is_none() {
                                ", the default the WAN asks for when its prefix_length is unset,"
                                    .to_string()
                            } else {
                                String::new()
                            };
                            self.err(
                                format!("{p}.subnet_id"),
                                match 1u32 << (64 - len) {
                                    1 => "a /64 is one subnet, 0".to_string(),
                                    n => format!(
                                        "a /{len}{default} has {n} subnets (0 to {})",
                                        n - 1
                                    ),
                                },
                            )
                        }
                        _ => {}
                    }
                }
                Ipv6Mode::Static => {
                    let Some(Prefix6(px)) = v6.prefix else {
                        self.err(format!("{p}.prefix"), "a static network needs one");
                        continue;
                    };
                    if px.addr() != px.network() {
                        self.err(
                            format!("{p}.prefix"),
                            format!("has host bits set; the prefix is {}", px.trunc()),
                        );
                    }
                    if !ipv6_routable(px.network()) {
                        self.err(
                            format!("{p}.prefix"),
                            "not a routable prefix (link-local, multicast or loopback)",
                        );
                    }
                    if !wan && px.prefix_len() != 64 {
                        self.err(
                            format!("{p}.prefix"),
                            "an inside network's prefix is a /64, for SLAAC",
                        );
                    }
                    if wan && px.prefix_len() > 127 {
                        self.err(format!("{p}.prefix"), "a WAN link needs at least a /127");
                    }
                    for (q, other) in &prefixes {
                        if q.contains(&px) || px.contains(q) {
                            self.err(
                                format!("{p}.prefix"),
                                format!("overlaps network {other:?}'s {q}"),
                            );
                        }
                    }
                    prefixes.push((px.trunc(), name));
                    if wan && doc.is_pair() {
                        // The WAN's address is the vip, which moves with the
                        // gateway; the nodes take none of their own.
                        if !v6.addresses.is_empty() {
                            self.err(
                                format!("{p}.addresses"),
                                "on a pair the WAN's IPv6 address is the vip; the nodes take none of their own",
                            );
                        }
                        match v6.vip {
                            None => self.err(
                                format!("{p}.vip"),
                                "a pair's static WAN needs one: the address that moves with the gateway",
                            ),
                            Some(a) if !px.contains(&a) || a == px.network() => self.err(
                                format!("{p}.vip"),
                                format!("not a host in {}", px.trunc()),
                            ),
                            Some(a) if Some(a) == v6.gateway => self.err(
                                format!("{p}.vip"),
                                "is the upstream router's address",
                            ),
                            _ => {}
                        }
                    }
                    if wan && !doc.is_pair() {
                        let mut seen: BTreeMap<Ipv6Addr, &str> = BTreeMap::new();
                        for node in &doc.cluster.nodes {
                            match v6.addresses.get(node) {
                                None => self.err(
                                    format!("{p}.addresses"),
                                    format!("no address for node {node:?}"),
                                ),
                                Some(a) => {
                                    if !px.contains(a) || *a == px.network() {
                                        self.err(
                                            format!("{p}.addresses.{node}"),
                                            format!("not a host in {}", px.trunc()),
                                        );
                                    }
                                    if let Some(prev) = seen.insert(*a, node.as_str()) {
                                        let prev = prev.to_string();
                                        self.err(
                                            format!("{p}.addresses.{node}"),
                                            format!("also node {prev:?}'s"),
                                        );
                                    }
                                }
                            }
                        }
                        for node in v6.addresses.keys() {
                            if !self.is_node(node) {
                                self.err(
                                    format!("{p}.addresses.{node}"),
                                    format!("no node named {node:?}"),
                                );
                            }
                        }
                    }
                    if wan {
                        match v6.gateway {
                            None => self.err(
                                format!("{p}.gateway"),
                                "a static WAN needs the upstream router",
                            ),
                            Some(g) if !(px.contains(&g) || g.is_unicast_link_local()) => self.err(
                                format!("{p}.gateway"),
                                format!("neither in {} nor link-local", px.trunc()),
                            ),
                            _ => {}
                        }
                    }
                }
                Ipv6Mode::Dhcpv6 | Ipv6Mode::Ra => {}
            }
        }
    }

    /// What IPv6 in a pair needs (#215), beyond what any node's does.
    ///
    /// - **The WAN:** DHCPv6 and router advertisements need the pair's
    ///   one DHCP lease, whose link (the virtual MAC) is up on the master
    ///   only, so one client asks, with one DUID. A static block's link is
    ///   up on both nodes: IPv6 there is static, with a `vip`. A WAN on
    ///   the nodes' own MACs (`vmac: false`) takes no IPv6.
    /// - **An inside network:** its IPv6 gateway (`fe80::1`) has the
    ///   network's VRRP virtual MAC for IPv6, so it needs a `vrid`.
    fn pair_ipv6(&mut self, name: &str, net: &Network, v6: &NetworkIpv6) {
        let doc = self.doc;
        let p = format!("networks.{name}.ipv6");
        if net.role == NetworkRole::Wan {
            if doc.split_wan(name).is_some() && !net.vmac {
                self.err(
                    &p,
                    "a pair's WAN on the nodes' own MACs (vmac: false) is IPv4 only",
                );
                return;
            }
            // Only a WAN on the virtual MAC carries IPv6 (#247): a static
            // block with private node addresses, or the one DHCP lease.
            if !doc.vmac_wan(name) {
                self.err(
                    &p,
                    "in a pair, IPv6 on the WAN needs it on the virtual MAC: a static block with \
                     private node addresses (and a vip), or the one DHCP lease (dhcp_client and \
                     a vrid); public node addresses in the gateway's subnet, or each node \
                     leasing its own, are IPv4 only",
                );
                return;
            }
            if matches!(v6.mode, Ipv6Mode::Dhcpv6 | Ipv6Mode::Ra) && doc.leased_wan(name).is_none()
            {
                self.err(
                    format!("{p}.mode"),
                    "in a pair, DHCPv6 and router advertisements need the WAN's one DHCP lease \
                     (dhcp_client and a vrid), whose link follows the master; a static block takes \
                     mode static, with a vip",
                );
            }
        } else if net.vrid.is_none() {
            self.err(
                &p,
                "in a pair, an inside network's IPv6 gateway needs the network's vrid, for its virtual MAC",
            );
        }
    }

    /// IPv6 is in the schema (#211) before all of it is rendered. Hosts
    /// by suffix in a delegated prefix are not built yet, and management
    /// over IPv6 is a choice for later: until then a document that uses
    /// them is refused, rather than run as if it did not.
    fn unbuilt_ipv6(&mut self) {
        let doc = self.doc;
        // Hosts by suffix in a delegated prefix need the node to follow
        // the prefix as it runs, which is not built yet.
        for (oname, o) in &doc.objects {
            for net in o.suffixes.keys() {
                if doc
                    .networks
                    .get(net)
                    .and_then(|n| n.ipv6.as_ref())
                    .is_some_and(|v| v.mode == Ipv6Mode::Delegated)
                {
                    self.err(
                        format!("objects.{oname}.suffixes.{net}"),
                        "hosts by suffix in a delegated prefix are not built yet; use a static prefix, or their addresses",
                    );
                }
            }
        }
        if let Some(m) = &doc.management.sources
            && !doc.split_families(m).1.is_empty()
        {
            self.err(
                "management.sources",
                "management over IPv6 is not built yet: the anti-lockout rule is IPv4's",
            );
        }
    }

    fn node_addresses(&mut self, p: &str, net: &Network) {
        for n in self.nodes().to_vec() {
            if !net.addresses.contains_key(&n) {
                self.err(
                    format!("{p}.addresses"),
                    format!("no address for node {n:?}"),
                );
            }
        }
    }

    fn management(&mut self) {
        let m = &self.doc.management;
        match self.doc.networks.get(&m.network) {
            None => self.err(
                "management.network",
                format!("no network named {:?}", m.network),
            ),
            Some(n) if n.role != NetworkRole::Management => self.err(
                "management.network",
                format!("network {:?} must have role management", m.network),
            ),
            _ => {}
        }
        let count = self.doc.networks_with_role(NetworkRole::Management).count();
        if count > 1 {
            self.err("networks", "only one network may have role management");
        }
        if !m.anti_lockout {
            self.warn(
                "management.anti_lockout",
                "the anti-lockout rule is disabled",
            );
        }
        if m.ssh.password {
            self.warn(
                "management.ssh.password",
                "SSH accepts the admin password as well as keys",
            );
        }
        if let Some(src) = &m.sources {
            self.check_addr_match_any("management.sources", src);
        } else if self
            .doc
            .zones
            .values()
            .any(|z| z.networks.contains(&m.network))
        {
            // An ordinary network that also manages the node (#177).
            self.warn(
                "management.sources",
                format!(
                    "every host on network {:?} reaches the node's SSH and HTTPS: \
                     limit that with management.sources",
                    m.network
                ),
            );
        }
    }

    fn zones(&mut self) {
        let doc = self.doc;
        let mut member: BTreeMap<&str, &str> = BTreeMap::new();
        for (name, z) in &doc.zones {
            let p = format!("zones.{name}");
            if name == SELF_ZONE {
                self.err(&p, "the self zone is built in");
                continue;
            }
            if !nft_name_ok(name) {
                self.err(
                    &p,
                    "zone names: lowercase letters, digits and '_', at most 31 characters",
                );
            }
            for (i, n) in z.networks.iter().enumerate() {
                match doc.networks.get(n) {
                    None => self.err(
                        format!("{p}.networks[{i}]"),
                        format!("no network named {n:?}"),
                    ),
                    Some(net) if net.role == NetworkRole::Sync => self.err(
                        format!("{p}.networks[{i}]"),
                        "the sync network cannot be in a zone",
                    ),
                    _ => {}
                }
                if let Some(prev) = member.insert(n, name) {
                    self.err(
                        format!("{p}.networks[{i}]"),
                        format!("network {n:?} is already in zone {prev:?}"),
                    );
                }
            }
            if z.networks.is_empty()
                && !doc.vpn.values().any(|v| &v.zone == name)
                && !doc.vpn_clients.values().any(|c| &c.zone == name)
            {
                self.warn(&p, "zone has no networks");
            }
        }
        for (name, net) in &doc.networks {
            if net.role != NetworkRole::Sync
                && !member.contains_key(name.as_str())
                && net.role != NetworkRole::Management
            {
                self.warn(format!("networks.{name}"), "network is in no zone, so it can only reach the firewall through the anti-lockout rule");
            }
        }
    }

    fn zone_exists(&self, z: &str) -> bool {
        z == SELF_ZONE || self.doc.zones.contains_key(z)
    }

    fn objects(&mut self) {
        let doc = self.doc;
        for (name, o) in &doc.objects {
            let p = format!("objects.{name}");
            if !nft_name_ok(name) {
                self.err(
                    &p,
                    "object names: lowercase letters, digits and '_', at most 31 characters",
                );
            }
            let fixed = !o.elements.is_empty() || !o.suffixes.is_empty();
            match (&o.dynamic, fixed) {
                (Some(_), true) => self.err(&p, "a dynamic object has no static elements"),
                (None, false) => self.warn(&p, "object is empty"),
                _ => {}
            }
            if let Some(d) = &o.dynamic {
                match (o.kind, doc.networks.get(&d.network)) {
                    (ObjectKind::Port, _) => {
                        self.err(format!("{p}.dynamic"), "a port object cannot be dynamic")
                    }
                    (_, None) => self.err(
                        format!("{p}.dynamic.network"),
                        format!("no network named {:?}", d.network),
                    ),
                    (ObjectKind::Ipv6, Some(n)) if n.ipv6.is_none() => self.err(
                        format!("{p}.dynamic.network"),
                        format!("network {:?} has no IPv6 (networks.{0}.ipv6)", d.network),
                    ),
                    (ObjectKind::Ipv6, Some(_))
                        if d.source == DynamicKind::Address
                            && doc.ipv6_gateway_iface(&d.network).is_some() =>
                    {
                        self.err(
                            format!("{p}.dynamic.source"),
                            "in a pair, the nodes take no IPv6 address on an inside network (its \
                             gateway is fe80::1); use source: prefix",
                        )
                    }
                    _ => {}
                }
            }
            if !o.suffixes.is_empty() && o.kind != ObjectKind::Ipv6 {
                self.err(format!("{p}.suffixes"), "only ipv6 objects have suffixes");
            }
            for (net, sfx) in &o.suffixes {
                let sp = format!("{p}.suffixes.{net}");
                match doc.networks.get(net).and_then(|n| n.ipv6.as_ref()) {
                    None if !doc.networks.contains_key(net) => {
                        self.err(&sp, format!("no network named {net:?}"))
                    }
                    Some(v6) if v6.mode == Ipv6Mode::Delegated || v6.mode == Ipv6Mode::Static => {}
                    _ => self.err(
                        &sp,
                        "the network needs an IPv6 prefix of its own (ipv6.mode delegated or static)",
                    ),
                }
                if sfx.is_empty() {
                    self.err(&sp, "empty list");
                }
                for (i, x) in sfx.iter().enumerate() {
                    if !suffix_ok(x) {
                        self.err(
                            format!("{sp}[{i}]"),
                            format!("{x:?} is not a suffix: an address in the last 64 bits, such as ::20"),
                        );
                    }
                }
            }
            for (i, e) in o.elements.iter().enumerate() {
                let ok = match o.kind {
                    ObjectKind::Ipv4 => matches!(e, MatchItem::Text(s) if ipv4_element_ok(s)),
                    ObjectKind::Ipv6 => matches!(e, MatchItem::Text(s) if ipv6_element_ok(s)),
                    ObjectKind::Port => port_element_ok(e),
                };
                if !ok {
                    self.err(
                        format!("{p}.elements[{i}]"),
                        format!("not a valid {:?} element", o.kind).to_lowercase(),
                    );
                }
            }
        }
    }

    /// An IPv4-only address match: a forward's.
    fn check_addr_match(&mut self, p: &str, m: &Match) {
        let f = self.check_addr_match_any(p, m);
        if f.v6 {
            self.err(p, "IPv4 only: forwards and NAT are IPv4's");
        }
    }

    /// An address match of either family, and the families it holds.
    fn check_addr_match_any(&mut self, p: &str, m: &Match) -> Families {
        let items: Vec<MatchItem> = match m {
            Match::Number(n) => vec![MatchItem::Number(*n)],
            Match::Text(s) => vec![MatchItem::Text(s.clone())],
            Match::List(l) => l.clone(),
        };
        if items.is_empty() {
            self.err(p, "empty list");
        }
        let mut fam = Families::NONE;
        for it in items {
            match it {
                MatchItem::Text(s) if s.starts_with('@') => {
                    let name = &s[1..];
                    match self.doc.objects.get(name).map(|o| o.kind) {
                        None => self.err(p, format!("no object named {name:?}")),
                        Some(ObjectKind::Ipv4) => fam.v4 = true,
                        Some(ObjectKind::Ipv6) => fam.v6 = true,
                        Some(ObjectKind::Port) => {
                            self.err(p, format!("object {name:?} is not of type ipv4 or ipv6"))
                        }
                    }
                }
                MatchItem::Text(s) if ipv4_element_ok(&s) => fam.v4 = true,
                MatchItem::Text(s) if ipv6_element_ok(&s) => fam.v6 = true,
                _ => self.err(
                    p,
                    "expected an IPv4 or IPv6 address, prefix, range or @object",
                ),
            }
        }
        fam
    }

    /// The families of an address match, without reporting anything (its
    /// problems are reported where it is checked).
    fn families_quiet(&self, m: &Match) -> Families {
        let items: Vec<MatchItem> = match m {
            Match::Number(n) => vec![MatchItem::Number(*n)],
            Match::Text(s) => vec![MatchItem::Text(s.clone())],
            Match::List(l) => l.clone(),
        };
        let mut fam = Families::NONE;
        for it in items {
            if let MatchItem::Text(s) = it {
                let f = match s.strip_prefix('@') {
                    Some(n) => match self.doc.objects.get(n).map(|o| o.kind) {
                        Some(ObjectKind::Ipv4) => Families {
                            v4: true,
                            v6: false,
                        },
                        Some(ObjectKind::Ipv6) => Families {
                            v4: false,
                            v6: true,
                        },
                        _ => Families::NONE,
                    },
                    None if ipv4_element_ok(&s) => Families {
                        v4: true,
                        v6: false,
                    },
                    None if ipv6_element_ok(&s) => Families {
                        v4: false,
                        v6: true,
                    },
                    None => Families::NONE,
                };
                fam = fam.or(f);
            }
        }
        fam
    }

    fn check_port_match(&mut self, p: &str, m: &Match) {
        let items: Vec<MatchItem> = match m {
            Match::Number(n) => vec![MatchItem::Number(*n)],
            Match::Text(s) => vec![MatchItem::Text(s.clone())],
            Match::List(l) => l.clone(),
        };
        if items.is_empty() {
            self.err(p, "empty list");
        }
        for it in items {
            match &it {
                MatchItem::Text(s) if s.starts_with('@') => {
                    self.check_ref(p, &s[1..], ObjectKind::Port)
                }
                _ if port_element_ok(&it) => {}
                _ => self.err(p, "expected a port, a low-high range or @object"),
            }
        }
    }

    fn check_ref(&mut self, p: &str, name: &str, kind: ObjectKind) {
        match self.doc.objects.get(name) {
            None => self.err(p, format!("no object named {name:?}")),
            Some(o) if o.kind != kind => self.err(
                p,
                format!("object {name:?} is not of type {kind:?}").to_lowercase(),
            ),
            _ => {}
        }
    }

    fn policy(&mut self) {
        let doc = self.doc;
        for (key, pol) in &doc.policy {
            let p = format!("policy.'{key}'");
            let Some((from, to)) = Document::split_pair(key) else {
                self.err(&p, "policy keys look like \"from->to\"");
                continue;
            };
            for z in [from, to] {
                if !self.zone_exists(z) {
                    self.err(&p, format!("no zone named {z:?}"));
                }
            }
            if from == SELF_ZONE && to == SELF_ZONE {
                self.err(&p, "self->self is not filtered");
            }
            if pol.nat.is_some() && from == SELF_ZONE {
                self.err(
                    format!("{p}.nat"),
                    "the firewall's own traffic already leaves from its own address",
                );
            }
            if pol.nat.is_some() && to == SELF_ZONE {
                self.err(
                    format!("{p}.nat"),
                    "NAT does not apply to traffic to the firewall itself",
                );
            }
            let mut orders: BTreeMap<u32, &str> = BTreeMap::new();
            for (rname, r) in &pol.rules {
                let rp = format!("{p}.rules.{rname}");
                if !rname
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
                {
                    self.err(&rp, "rule names: letters, digits, '-', '_' and '.'");
                }
                if let Some(prev) = orders.insert(r.order, rname) {
                    self.err(
                        format!("{rp}.order"),
                        format!("order {} is also used by rule {prev:?}", r.order),
                    );
                }
                self.check_rule(&rp, r);
            }
        }
    }

    fn check_rule(&mut self, rp: &str, r: &Rule) {
        let proto = r.proto.as_deref();
        if let Some(pr) = proto
            && !KNOWN_PROTOS.contains(&pr)
        {
            self.err(
                format!("{rp}.proto"),
                format!(
                    "unknown protocol {pr:?}; use one of {}",
                    KNOWN_PROTOS.join(", ")
                ),
            );
        }
        let has_ports = matches!(proto, Some("tcp" | "udp" | "sctp"));
        for (field, m) in [("sport", &r.sport), ("dport", &r.dport)] {
            if let Some(m) = m {
                if !has_ports {
                    self.err(format!("{rp}.{field}"), "ports need proto tcp, udp or sctp");
                }
                self.check_port_match(&format!("{rp}.{field}"), m);
            }
        }
        // The families the rule applies to: those its addresses and its
        // protocol all allow (#211). A rule with none of them is both.
        let mut fam = Families::BOTH;
        for (field, m) in [("src", &r.src), ("dst", &r.dst)] {
            if let Some(m) = m {
                fam = fam.and(self.check_addr_match_any(&format!("{rp}.{field}"), m));
            }
        }
        let by_proto = match proto {
            Some("icmp") => Families {
                v4: true,
                v6: false,
            },
            Some("icmpv6") => Families {
                v4: false,
                v6: true,
            },
            _ => Families::BOTH,
        };
        if fam != Families::NONE && fam.and(by_proto) == Families::NONE {
            self.err(
                rp,
                format!(
                    "its addresses are {} and proto {} is the other family's",
                    fam.name(),
                    proto.unwrap_or_default()
                ),
            );
        } else if fam == Families::NONE && r.src.is_some() && r.dst.is_some() {
            // Each side has a family, but not the same one.
            let side = |m: &Option<Match>, v: &mut Self| {
                m.as_ref().map_or(Families::BOTH, |m| v.families_quiet(m))
            };
            let (a, b) = (side(&r.src, self), side(&r.dst, self));
            if a != Families::NONE && b != Families::NONE {
                self.err(
                    rp,
                    format!(
                        "src is {} and dst {}: no packet is both",
                        a.name(),
                        b.name()
                    ),
                );
            }
        }
        if !r.icmp_type.is_empty() && !matches!(proto, Some("icmp" | "icmpv6")) {
            self.err(format!("{rp}.icmp_type"), "needs proto icmp or icmpv6");
        }
        for t in &r.icmp_type {
            if !t.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
                self.err(
                    format!("{rp}.icmp_type"),
                    format!("invalid ICMP type {t:?}"),
                );
            }
        }
        if let Some(l) = &r.limit
            && !limit_ok(l)
        {
            self.err(
                format!("{rp}.limit"),
                "expected e.g. 10/second or 100/minute burst 20",
            );
        }
    }

    fn forwards(&mut self) {
        let doc = self.doc;
        for (name, f) in &doc.forwards {
            let p = format!("forwards.{name}");
            let from = f.from.as_deref().unwrap_or("wan");
            if !doc.zones.contains_key(from) {
                self.err(format!("{p}.from"), format!("no zone named {from:?}"));
            }
            if !matches!(f.proto.as_str(), "tcp" | "udp") {
                self.err(format!("{p}.proto"), "must be tcp or udp");
            }
            self.check_port_match(&format!("{p}.dport"), &f.dport);
            if f.to_port.is_some() && !matches!(f.dport, Match::Number(_)) {
                self.err(format!("{p}.to_port"), "to_port needs a single dport");
            }
            if let Some(m) = &f.src {
                self.check_addr_match(&format!("{p}.src"), m);
            }
            if let Some(m) = &f.dst {
                self.check_addr_match(&format!("{p}.dst"), m);
            }
            match doc
                .network_containing(f.to)
                .and_then(|n| doc.zone_of_network(n))
            {
                None => self.err(
                    format!("{p}.to"),
                    "not inside any network that belongs to a zone",
                ),
                Some(z) if z == from => {
                    self.err(format!("{p}.to"), "forwards into the zone they arrive from")
                }
                _ => {}
            }
            if !f.hairpin.is_empty() && f.dst.is_none() {
                self.err(
                    format!("{p}.hairpin"),
                    "needs dst: the outside address inside clients connect to",
                );
            }
            for (i, z) in f.hairpin.iter().enumerate() {
                let hp = format!("{p}.hairpin[{i}]");
                if z == SELF_ZONE {
                    self.err(hp, "the firewall itself cannot be a hairpin zone");
                } else if !doc.zones.contains_key(z) {
                    self.err(hp, format!("no zone named {z:?}"));
                } else if z == from {
                    self.err(hp, "the forward already applies from this zone");
                } else if f.hairpin[..i].contains(z) {
                    self.err(hp, "listed twice");
                }
            }
        }
    }

    /// Extra gateway addresses, and the addresses NAT translates to: an
    /// `snat` target, or a forward's literal `dst`, inside a static
    /// network must be an address some node holds there, or it would
    /// silently go nowhere.
    fn held_addresses(&mut self) {
        let doc = self.doc;
        let mut seen: BTreeMap<Ipv4Addr, String> = BTreeMap::new();
        for (name, net) in &doc.networks {
            for a in net.addresses.values().chain(net.vip.iter()) {
                seen.entry(a.0.addr()).or_insert_with(|| name.clone());
            }
        }
        for (name, net) in &doc.networks {
            for (i, x) in net.extra_vips.iter().enumerate() {
                let p = format!("networks.{name}.extra_vips[{i}]");
                let Some(vip) = &net.vip else {
                    self.err(p, "extra gateway addresses need a gateway address (vip)");
                    continue;
                };
                if x.0.trunc() != vip.0.trunc() {
                    self.err(
                        p,
                        format!("not in the gateway address's subnet {}", vip.0.trunc()),
                    );
                } else if x.0.addr() == vip.0.trunc().network()
                    || x.0.addr() == vip.0.trunc().broadcast()
                {
                    self.err(p, "is the network or broadcast address of its subnet");
                } else if let Some(other) = seen.insert(x.0.addr(), name.clone()) {
                    self.err(
                        p,
                        format!("{} is already used on network {other}", x.0.addr()),
                    );
                }
            }
        }
        let held = |a: Ipv4Addr| -> Option<bool> {
            let net = doc.networks.values().find(|n| {
                n.vip
                    .iter()
                    .chain(n.addresses.values())
                    .any(|c| c.0.trunc().contains(&a))
            })?;
            Some(
                net.vip
                    .iter()
                    .chain(&net.extra_vips)
                    .chain(net.addresses.values())
                    .any(|c| c.0.addr() == a),
            )
        };
        for (key, pol) in &doc.policy {
            if let Some(Nat::Snat { snat }) = &pol.nat
                && held(*snat) == Some(false)
            {
                self.err(
                    format!("policy.{key}.nat.snat"),
                    format!("no node holds {snat}: add it to the network's extra_vips"),
                );
            }
        }
        for (name, f) in &doc.forwards {
            let literal: Vec<&str> = match &f.dst {
                Some(Match::Text(t)) => vec![t.as_str()],
                Some(Match::List(items)) => items
                    .iter()
                    .filter_map(|i| match i {
                        MatchItem::Text(t) => Some(t.as_str()),
                        MatchItem::Number(_) => None,
                    })
                    .collect(),
                _ => vec![],
            };
            for t in literal {
                if let Ok(a) = t.trim_end_matches("/32").parse::<Ipv4Addr>()
                    && held(a) == Some(false)
                {
                    self.err(
                        format!("forwards.{name}.dst"),
                        format!("no node holds {a}: add it to the network's extra_vips"),
                    );
                }
            }
        }
    }

    fn raw(&mut self) {
        let doc = self.doc;
        let mut orders: BTreeMap<(String, u32), &str> = BTreeMap::new();
        for (name, r) in &doc.raw {
            let p = format!("raw.{name}");
            if !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            {
                self.err(&p, "raw entry names: letters, digits, '-', '_' and '.'");
            }
            let point = match &r.at {
                RawAt::Pair { pair, position } => {
                    if !doc.policy.contains_key(pair) {
                        self.err(format!("{p}.at.pair"), format!("no policy for {pair:?}"));
                    }
                    format!("{pair}/{position:?}")
                }
                RawAt::Hook { hook } => format!("{hook:?}"),
            };
            if let Some(prev) = orders.insert((point, r.order), name) {
                self.err(
                    format!("{p}.order"),
                    format!("order {} at this point is also used by {prev:?}", r.order),
                );
            }
            if r.nft.trim().is_empty() {
                self.err(format!("{p}.nft"), "empty statement");
            }
            if r.nft.contains(['\n', ';', '#']) {
                self.err(
                    format!("{p}.nft"),
                    "one statement per entry: no newlines, ';' or '#'",
                );
            }
        }
    }

    fn dhcp(&mut self) {
        let doc = self.doc;
        let Some(d) = &doc.dhcp else { return };
        self.provider(Role::Dhcp, "dhcp.provider".into(), d.provider.as_deref());
        for (name, dn) in &d.networks {
            let p = format!("dhcp.{name}");
            let Some(net) = doc.networks.get(name) else {
                self.err(&p, format!("no network named {name:?}"));
                continue;
            };
            if matches!(net.role, NetworkRole::Wan | NetworkRole::Sync) {
                self.err(&p, "DHCP is not served on WAN or sync networks");
            }
            let Some(subnet) = doc.any_subnet(name) else {
                self.err(&p, "the network has no addresses");
                continue;
            };
            let mut taken: BTreeSet<Ipv4Addr> =
                net.addresses.values().map(|a| a.0.addr()).collect();
            taken.extend(net.vip.iter().chain(&net.extra_vips).map(|v| v.0.addr()));
            match parse_range(&dn.pool) {
                None => self.err(
                    format!("{p}.pool"),
                    "expected first-last, e.g. 192.0.2.100-192.0.2.199",
                ),
                Some((a, b)) => {
                    if !subnet.contains(&a)
                        || !subnet.contains(&b)
                        || a == subnet.network()
                        || b == subnet.broadcast()
                    {
                        self.err(
                            format!("{p}.pool"),
                            format!("not inside the usable range of {subnet}"),
                        );
                    }
                    for t in &taken {
                        if (u32::from(a)..=u32::from(b)).contains(&u32::from(*t)) {
                            self.err(
                                format!("{p}.pool"),
                                format!("contains the firewall's address {t}"),
                            );
                        }
                    }
                }
            }
            let mut macs = BTreeSet::new();
            for (rname, r) in &dn.reservations {
                let rp = format!("{p}.reservations.{rname}");
                if !mac_ok(&r.mac) {
                    self.err(format!("{rp}.mac"), "not a MAC address");
                }
                if !macs.insert(r.mac.to_ascii_lowercase()) {
                    self.err(format!("{rp}.mac"), "MAC address reserved twice");
                }
                if !subnet.contains(&r.address) {
                    self.err(format!("{rp}.address"), format!("not inside {subnet}"));
                }
                if !taken.insert(r.address) {
                    self.err(format!("{rp}.address"), "address already used");
                }
            }
        }
    }

    fn dns(&mut self) {
        let doc = self.doc;
        let Some(d) = &doc.dns else { return };
        self.provider(Role::Dns, "dns.provider".into(), d.provider.as_deref());
        for (i, n) in d.networks.iter().enumerate() {
            match doc.networks.get(n) {
                None => self.err(
                    format!("dns.networks[{i}]"),
                    format!("no network named {n:?}"),
                ),
                Some(net) if net.role == NetworkRole::Wan => self.err(
                    format!("dns.networks[{i}]"),
                    "the resolver never serves the WAN",
                ),
                _ => {}
            }
        }
    }

    /// Settings the schema reserves for features not built yet. Accepting
    /// them would suggest they take effect.
    /// Check a role's provider against the table: it must exist, and in a
    /// pair be able to run in one. One not built yet is left to
    /// [`Self::unbuilt`], so history that names it stays readable.
    fn provider(&mut self, role: Role, path: String, name: Option<&str>) {
        let Some(name) = name else { return };
        let built = providers::names(role)
            .into_iter()
            .filter(|n| providers::find(role, n).is_some_and(|p| p.built))
            .collect::<Vec<_>>()
            .join(", ");
        match providers::find(role, name) {
            // Any other name is a lego provider code (`gcloud`,
            // `cloudflare`, `route53`...); lego checks it when it runs.
            None if role == Role::AcmeDns => {
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                {
                    self.err(
                        path,
                        format!("{name:?} is neither rfc2136 nor a lego provider code"),
                    );
                }
            }
            None => self.err(path, format!("unknown provider {name:?}; use {built}")),
            Some(p) if !p.ha && self.doc.is_pair() => self.err(
                path,
                format!("{name} cannot run in an HA pair; use {built}"),
            ),
            Some(_) => {}
        }
    }

    fn logging(&mut self) {
        let Some(r) = self.doc.logging.as_ref().and_then(|l| l.remote.as_ref()) else {
            return;
        };
        self.provider(
            Role::LogForwarding,
            "logging.remote.provider".into(),
            r.provider.as_deref(),
        );
        let p = "logging.remote";
        if providers::chosen(self.doc, Role::LogForwarding) != Some("syslog") {
            if r.protocol.is_some() {
                self.err(
                    format!("{p}.protocol"),
                    "only the syslog provider takes a protocol",
                );
            }
            if r.ca.is_some() {
                self.err(format!("{p}.ca"), "only the syslog provider takes a CA");
            }
            if r.certificate.is_some() {
                self.err(
                    format!("{p}.certificate"),
                    "only the syslog provider takes a client certificate",
                );
            }
            return;
        }
        let protocol = r.protocol.as_deref().unwrap_or("udp");
        if !["udp", "tcp", "relp"].contains(&protocol) {
            self.err(
                format!("{p}.protocol"),
                format!("unknown protocol {protocol:?}; use udp, tcp or relp"),
            );
        }
        if r.tls && protocol == "udp" {
            self.err(
                format!("{p}.tls"),
                "TLS needs protocol tcp or relp; syslog over UDP is never encrypted",
            );
        }
        if let Some(ca) = &r.ca {
            if !r.tls {
                self.err(format!("{p}.ca"), "a CA is for tls: true");
            }
            if !ca.contains("-----BEGIN CERTIFICATE-----") {
                self.err(format!("{p}.ca"), "not a PEM certificate");
            }
        }
        if r.certificate.is_some() && !r.tls {
            self.err(
                format!("{p}.certificate"),
                "a client certificate is for tls: true",
            );
        }
        if protocol == "relp" && r.tls && r.certificate.is_none() {
            self.err(
                format!("{p}.certificate"),
                "RELP over TLS needs a client certificate: without one, librelp \
                 offers only anonymous TLS, which collectors refuse",
            );
        }
        if syslog_target(&r.destination).is_none() {
            self.err(
                format!("{p}.destination"),
                "for syslog, a host name or address, with an optional :port \
                 (an IPv6 address in brackets)",
            );
        }
    }

    fn unbuilt(&mut self) {
        let doc = self.doc;
        let mut chosen: Vec<(Role, String, &str)> = Vec::new();
        if let Some(n) = doc.dhcp.as_ref().and_then(|d| d.provider.as_deref()) {
            chosen.push((Role::Dhcp, "dhcp.provider".into(), n));
        }
        if let Some(n) = doc.dns.as_ref().and_then(|d| d.provider.as_deref()) {
            chosen.push((Role::Dns, "dns.provider".into(), n));
        }
        if let Some(n) = doc
            .logging
            .as_ref()
            .and_then(|l| l.remote.as_ref())
            .and_then(|r| r.provider.as_deref())
        {
            chosen.push((Role::LogForwarding, "logging.remote.provider".into(), n));
        }
        for (name, c) in doc.tls.iter().flat_map(|t| &t.certificates) {
            if let Some(d) = c.acme.as_ref().and_then(|a| a.dns.as_ref()) {
                chosen.push((
                    Role::AcmeDns,
                    format!("tls.certificates.{name}.acme.dns.provider"),
                    &d.provider,
                ));
            }
        }
        for (role, path, name) in chosen {
            let unbuilt = providers::find(role, name).is_some_and(|p| !p.built);
            if unbuilt {
                let default = providers::chosen_default(role);
                self.err(
                    path,
                    format!("the {name} provider is not built yet; use {default}"),
                );
            }
        }
        for name in doc.provider_options.keys() {
            self.err(
                format!("provider_options.{name}"),
                "provider passthrough options are not supported yet",
            );
        }
        self.unbuilt_ipv6();
        if let Some(m) = &doc.metrics {
            let local = m.mode == MetricsMode::Local;
            if let Some(r) = &m.retention {
                if !prometheus_duration(r) {
                    self.err(
                        "metrics.retention",
                        format!("{r:?} is not a duration such as 15d, 12h or 1y"),
                    );
                } else if !local {
                    self.warn(
                        "metrics.retention",
                        "retention applies to mode: local, which is not set",
                    );
                }
            }
            if let Some(r) = &m.retention_size {
                if !prometheus_size(r) {
                    self.err(
                        "metrics.retention_size",
                        format!("{r:?} is not a size such as 512MB or 2GB"),
                    );
                } else if !local {
                    self.warn(
                        "metrics.retention_size",
                        "retention_size applies to mode: local, which is not set",
                    );
                }
            }
        }
        if let Some(b) = &doc.backup
            && let Some(r) = &b.retention
        {
            if b.repository.is_none() {
                self.warn(
                    "backup.retention",
                    "retention applies to backup.repository, which is not set",
                );
            }
            // Rules that keep nothing would forget every snapshot.
            if r.enabled && r.keep_flags().is_empty() {
                self.err(
                    "backup.retention",
                    "keeps nothing: set a keep rule (last, hourly, daily, weekly, monthly, yearly) above 0, \
                     or enabled: false to keep every snapshot",
                );
            }
        }
        if let Some(u) = &doc.updates {
            let windowed = u.mode == Some(UpdateMode::Windowed);
            match u.window.as_deref() {
                None if windowed => self.err(
                    "updates.window",
                    "mode: windowed needs a window (a systemd calendar expression, e.g. \"Sun *-*-* 03:00\")",
                ),
                // systemd parses the rest when the change is checked.
                Some(w) if w.trim().is_empty() || w.contains(['\n', '\r']) => {
                    self.err("updates.window", "must be one systemd calendar expression")
                }
                Some(_) if !windowed => self.warn(
                    "updates.window",
                    "the window is used only with mode: windowed",
                ),
                _ => {}
            }
            if let Some(m) = u.window_minutes
                && !(1..=1440).contains(&m)
            {
                self.err("updates.window_minutes", "must be 1-1440");
            }
            if windowed && u.channel.as_deref() == Some("testing") {
                self.warn(
                    "updates.channel",
                    "scheduled upgrades on testing install every passing build of main unattended",
                );
            }
        }
    }

    fn ntp(&mut self) {
        let doc = self.doc;
        let Some(n) = &doc.ntp else { return };
        for (i, s) in n.serve.iter().enumerate() {
            match doc.networks.get(s) {
                None => self.err(format!("ntp.serve[{i}]"), format!("no network named {s:?}")),
                Some(net) if net.role == NetworkRole::Wan => {
                    self.err(format!("ntp.serve[{i}]"), "time is not served on the WAN")
                }
                _ => {}
            }
        }
    }

    fn vpn(&mut self) {
        let doc = self.doc;
        let mut ports = BTreeSet::new();
        for (name, v) in &doc.vpn {
            let p = format!("vpn.{name}");
            if !iface_name_ok(name) || reserved_iface(name) {
                self.err(&p, "VPN names become interface names: lowercase, start with a letter, at most 15 characters");
            }
            if !ports.insert(v.listen_port) || doc.cluster.sync_port == Some(v.listen_port) {
                self.err(format!("{p}.listen_port"), "port already in use");
            }
            for (i, &port) in v.extra_ports.iter().enumerate() {
                let ep = format!("{p}.extra_ports[{i}]");
                if port == 0 {
                    self.err(ep, "not a port");
                } else if !ports.insert(port) || doc.cluster.sync_port == Some(port) {
                    self.err(ep, "port already in use by a VPN");
                } else if let Some(what) = wan_udp_user(doc, port) {
                    self.err(ep, format!("{what} already uses UDP {port} on the WAN"));
                }
            }
            if !doc.zones.contains_key(&v.zone) {
                self.err(format!("{p}.zone"), format!("no zone named {:?}", v.zone));
            }
            if v.addresses.is_empty() {
                self.err(format!("{p}.addresses"), "the tunnel needs an address");
            }
            let mut used: BTreeSet<Ipv4Addr> = v.addresses.iter().map(|a| a.0.addr()).collect();
            for (pn, peer) in &v.peers {
                let pp = format!("{p}.peers.{pn}");
                if !wg_key_ok(&peer.public_key) {
                    self.err(
                        format!("{pp}.public_key"),
                        "not a WireGuard public key (44 base64 characters)",
                    );
                }
                for a in &peer.addresses {
                    if !v
                        .addresses
                        .iter()
                        .any(|t| t.0.trunc().contains(&a.0.addr()))
                        && peer.endpoint.is_none()
                    {
                        self.err(
                            format!("{pp}.addresses"),
                            format!("{a} is outside the tunnel's subnet"),
                        );
                    }
                    if !used.insert(a.0.addr()) {
                        self.err(
                            format!("{pp}.addresses"),
                            format!("{} is already used", a.0.addr()),
                        );
                    }
                }
                if let Some(k) = peer.keepalive
                    && !(1..=3600).contains(&k)
                {
                    self.err(
                        format!("{pp}.keepalive"),
                        "seconds between keepalives, 1 to 3600",
                    );
                }
                if let Some(e) = &peer.endpoint
                    && wg_endpoint(e).is_none()
                {
                    self.err(
                        format!("{pp}.endpoint"),
                        format!("{e:?} is not host:port, with an IPv4 address or a DNS name"),
                    );
                }
            }
        }
        self.routed_through_peers();
        self.vpn_clients();
        // In a pair, the master's handshakes leave from the gateway
        // address of the one WAN, static, through routes keepalived adds
        // (#148). Elsewhere (a WAN leased by DHCP, or several) nothing
        // would keep the backup from starting them too.
        if doc.is_pair() && doc.has_site_peers() {
            let wans: Vec<&str> = doc
                .networks_with_role(NetworkRole::Wan)
                .map(|(n, _)| n.as_str())
                .collect();
            if wans.len() != 1 || doc.site_source_wans().len() != 1 {
                self.err(
                    "vpn",
                    format!(
                        "site-to-site peers in a pair need exactly one WAN, with static addresses, \
                         a gateway address (vip) and a gateway; this pair has {}",
                        if wans.is_empty() {
                            "none".to_string()
                        } else {
                            wans.join(", ")
                        }
                    ),
                );
            }
        }
    }

    /// WireGuard clients (#149).
    fn vpn_clients(&mut self) {
        let doc = self.doc;
        let mut routed: BTreeMap<&str, &str> = BTreeMap::new();
        for (name, c) in &doc.vpn_clients {
            let p = format!("vpn_clients.{name}");
            if !iface_name_ok(name) || reserved_iface(name) {
                self.err(&p, "VPN client names become interface names: lowercase, start with a letter, at most 15 characters");
            }
            if doc.vpn.contains_key(name) {
                self.err(&p, "name is already used by a VPN instance");
            }
            if !doc.zones.contains_key(&c.zone) {
                self.err(format!("{p}.zone"), format!("no zone named {:?}", c.zone));
            } else if doc.zones[&c.zone]
                .networks
                .iter()
                .any(|n| c.route.networks.contains(n))
            {
                self.err(
                    format!("{p}.zone"),
                    "the tunnel's zone cannot hold the networks it routes",
                );
            }
            if c.addresses.is_empty() {
                self.err(
                    format!("{p}.addresses"),
                    "the tunnel needs the address the service assigned",
                );
            }
            if !wg_key_ok(&c.peer.public_key) {
                self.err(
                    format!("{p}.peer.public_key"),
                    "not a WireGuard public key (44 base64 characters)",
                );
            }
            if wg_endpoint(&c.peer.endpoint).is_none() {
                self.err(
                    format!("{p}.peer.endpoint"),
                    format!(
                        "{:?} is not host:port, with an IPv4 address or a DNS name",
                        c.peer.endpoint
                    ),
                );
            }
            if let Some(k) = c.peer.keepalive
                && !(1..=3600).contains(&k)
            {
                self.err(
                    format!("{p}.peer.keepalive"),
                    "seconds between keepalives, 1 to 3600",
                );
            }
            if c.route.networks.is_empty() {
                // A client for everything would take the node's own
                // default route, and its way to the endpoint with it.
                self.err(
                    format!("{p}.route.networks"),
                    "name the networks whose traffic leaves through the tunnel",
                );
            }
            for (i, n) in c.route.networks.iter().enumerate() {
                let np = format!("{p}.route.networks[{i}]");
                match doc.networks.get(n) {
                    None => self.err(np, format!("no network named {n:?}")),
                    Some(net) if matches!(net.role, NetworkRole::Wan | NetworkRole::Sync) => {
                        self.err(np, "only the networks behind the node are routed")
                    }
                    Some(net) => {
                        if let Some(prev) = routed.insert(n.as_str(), name.as_str()) {
                            self.err(np.clone(), format!("{n:?} already leaves through {prev:?}"));
                        }
                        // The tunnel is IPv4: the network's IPv6 cannot
                        // take it.
                        if net.ipv6.is_some() {
                            self.warn(
                                np,
                                if c.route.kill_switch {
                                    format!("{n:?} has IPv6, which the tunnel does not carry: the kill switch drops it, so its hosts have no IPv6 beyond the node")
                                } else {
                                    format!("{n:?} has IPv6, which the tunnel does not carry: it leaves through the WAN, around the tunnel")
                                },
                            );
                        }
                    }
                }
            }
            if !c.route.kill_switch {
                self.warn(
                    format!("{p}.route.kill_switch"),
                    "while the tunnel is down, the routed networks' traffic may leave through the WAN",
                );
            }
        }
    }

    /// The networks behind site-to-site peers (their addresses outside the
    /// tunnel) are routed through the tunnel: none may be, or overlap, a
    /// local network, a tunnel's subnet or another peer's network, or be
    /// the default route.
    fn routed_through_peers(&mut self) {
        let doc = self.doc;
        let mut taken: Vec<(String, ipnet::Ipv4Net)> = Vec::new();
        for n in doc.networks.keys() {
            for node in &doc.cluster.nodes {
                if let Some(s) = doc.subnet(n, node) {
                    taken.push((format!("network {n}"), s));
                }
            }
        }
        for (name, v) in &doc.vpn {
            for a in &v.addresses {
                taken.push((format!("vpn {name}'s tunnel"), a.0.trunc()));
            }
        }
        for (name, v) in &doc.vpn {
            for (pn, peer) in v.peers.iter().filter(|(_, p)| p.endpoint.is_some()) {
                let pp = format!("vpn.{name}.peers.{pn}.addresses");
                for a in &peer.addresses {
                    let net = a.0.trunc();
                    if v.addresses.iter().any(|t| t.0.trunc().contains(&net)) {
                        continue;
                    }
                    if net.prefix_len() == 0 {
                        self.err(&pp, "a site-to-site peer cannot take the default route");
                        continue;
                    }
                    if let Some((what, _)) = taken
                        .iter()
                        .find(|(_, t)| t.contains(&net.network()) || net.contains(&t.network()))
                    {
                        let what = what.clone();
                        self.err(&pp, format!("{net} overlaps {what}"));
                    }
                    taken.push((format!("vpn.{name}.peers.{pn}"), net));
                }
            }
        }
    }

    fn tls(&mut self) {
        let doc = self.doc;
        let Some(t) = &doc.tls else { return };
        for (name, c) in &t.certificates {
            let p = format!("tls.certificates.{name}");
            if !cert_name_ok(name) {
                self.err(
                    &p,
                    "a certificate name is lowercase letters, digits, '-' and '_', \
                     starting with a letter",
                );
            }
            if c.names.is_empty() {
                self.err(
                    format!("{p}.names"),
                    "a certificate needs at least one name",
                );
            }
            for (i, n) in c.names.iter().enumerate() {
                let host = n.strip_prefix("*.").unwrap_or(n);
                let ok = host.contains('.')
                    && host.split('.').all(|l| {
                        !l.is_empty()
                            && l.len() <= 63
                            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                    });
                if !ok {
                    self.err(
                        format!("{p}.names[{i}]"),
                        format!("{n:?} is not a DNS name"),
                    );
                }
            }
            let Some(a) = &c.acme else { continue };
            if !a.directory.starts_with("https://") {
                self.err(format!("{p}.acme.directory"), "must be an https:// URL");
            }
            match a.challenge.as_deref().unwrap_or("dns-01") {
                "dns-01" => match &a.dns {
                    None => self.err(format!("{p}.acme.dns"), "dns-01 needs a DNS provider"),
                    Some(d) => {
                        self.provider(
                            Role::AcmeDns,
                            format!("{p}.acme.dns.provider"),
                            Some(&d.provider),
                        );
                        if d.credentials.is_none() {
                            self.err(
                                format!("{p}.acme.dns.credentials"),
                                "needs a secret:<name> reference",
                            );
                        }
                        if d.provider != "rfc2136" {
                            // lego's settings are environment variables.
                            for k in d.options.keys() {
                                let env = k.starts_with(|c: char| c.is_ascii_uppercase())
                                    && k.chars().all(|c| {
                                        c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'
                                    });
                                if !env {
                                    self.err(
                                        format!("{p}.acme.dns.options.{k}"),
                                        "a lego provider's options are its environment \
                                         variables, e.g. GCE_PROJECT",
                                    );
                                }
                            }
                        }
                        if d.provider == "rfc2136" && !d.options.contains_key("server") {
                            self.err(
                                format!("{p}.acme.dns.options.server"),
                                "rfc2136 needs the primary server, host[:port]",
                            );
                        }
                    }
                },
                "http-01" => {
                    self.warn(format!("{p}.acme.challenge"), "http-01 is not built in yet")
                }
                other => self.err(
                    format!("{p}.acme.challenge"),
                    format!("unknown challenge {other:?}"),
                ),
            }
        }
    }

    fn secrets(&mut self) {
        let doc = self.doc;
        let mut refs: Vec<(String, &str)> = Vec::new();
        if let Some(t) = &doc.tls {
            for (n, c) in &t.certificates {
                if let Some(a) = &c.acme {
                    if let Some(d) = &a.dns
                        && let Some(cr) = &d.credentials
                    {
                        refs.push((format!("tls.certificates.{n}.acme.dns.credentials"), cr));
                    }
                    if let Some(e) = &a.eab {
                        refs.push((format!("tls.certificates.{n}.acme.eab.hmac"), &e.hmac));
                    }
                }
            }
        }
        if let Some(b) = &doc.backup
            && let Some(c) = &b.credentials
        {
            refs.push(("backup.credentials".into(), c));
        }
        if let Some(c) = doc
            .logging
            .as_ref()
            .and_then(|l| l.remote.as_ref())
            .and_then(|r| r.certificate.as_ref())
        {
            refs.push(("logging.remote.certificate".into(), c));
        }
        for (name, v) in &doc.vpn {
            for (peer, p) in &v.peers {
                if let Some(k) = &p.preshared_key {
                    refs.push((format!("vpn.{name}.peers.{peer}.preshared_key"), k));
                }
            }
        }
        for (name, c) in &doc.vpn_clients {
            refs.push((format!("vpn_clients.{name}.private_key"), &c.private_key));
            if let Some(k) = &c.peer.preshared_key {
                refs.push((format!("vpn_clients.{name}.peer.preshared_key"), k));
            }
        }
        for (p, r) in refs {
            let ok = r.strip_prefix("secret:").is_some_and(|n| {
                !n.is_empty()
                    && n.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            });
            if !ok {
                self.err(
                    p,
                    "secrets are referenced as secret:<name>, never written into the document",
                );
            }
        }
    }
}

/// What else takes UDP `port` on a WAN network, if anything: a forward
/// from a zone with a WAN network, or DNS or NTP served there.
fn wan_udp_user(doc: &Document, port: u16) -> Option<String> {
    let wan: Vec<&String> = doc
        .networks_with_role(NetworkRole::Wan)
        .map(|(n, _)| n)
        .collect();
    let wan_zone = |z: &str| wan.iter().any(|n| doc.zone_of_network(n) == Some(z));
    for (name, f) in &doc.forwards {
        if f.proto == "udp"
            && wan_zone(f.from.as_deref().unwrap_or("wan"))
            && match_has_port(doc, &f.dport, port)
        {
            return Some(format!("forwards.{name}"));
        }
    }
    if port == 53
        && let Some(d) = &doc.dns
        && d.enabled
        && d.networks.iter().any(|n| wan.contains(&n))
    {
        return Some("dns".into());
    }
    if port == 123
        && let Some(n) = &doc.ntp
        && n.serve.iter().any(|s| wan.contains(&s))
    {
        return Some("ntp".into());
    }
    None
}

/// Whether a port match includes `port`: numbers, `a-b` ranges, lists
/// and `@object` port sets.
fn match_has_port(doc: &Document, m: &Match, port: u16) -> bool {
    fn text(doc: &Document, t: &str, port: u16) -> bool {
        let port = u32::from(port);
        if let Some(obj) = t.strip_prefix('@') {
            return doc.objects.get(obj).is_some_and(|o| {
                o.elements.iter().any(|e| match e {
                    MatchItem::Number(n) => *n == port,
                    MatchItem::Text(t) => text(doc, t, port as u16),
                })
            });
        }
        match t.split_once('-') {
            Some((a, b)) => match (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                (Ok(a), Ok(b)) => (a..=b).contains(&port),
                _ => false,
            },
            None => t.trim().parse::<u32>() == Ok(port),
        }
    }
    match m {
        Match::Number(n) => *n == u32::from(port),
        Match::Text(t) => text(doc, t, port),
        Match::List(items) => items.iter().any(|i| match i {
            MatchItem::Number(n) => *n == u32::from(port),
            MatchItem::Text(t) => text(doc, t, port),
        }),
    }
}

/// A WireGuard peer's endpoint, `host:port`: its host (an IPv4 address or
/// a DNS name) and port.
pub fn wg_endpoint(v: &str) -> Option<(&str, u16)> {
    let (host, port) = v.rsplit_once(':')?;
    let port: u16 = port.parse().ok().filter(|p| *p > 0)?;
    let name_ok = host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        });
    // A dotted quad that does not parse is not a name either.
    let dotted = host.chars().all(|c| c.is_ascii_digit() || c == '.');
    let ok = if dotted {
        host.parse::<std::net::Ipv4Addr>().is_ok()
    } else {
        name_ok
    };
    ok.then_some((host, port))
}

/// A Prometheus duration that is not zero: units from the largest down,
/// each at most once (`15d`, `1d12h`, `90m`, `1y`).
pub fn prometheus_duration(v: &str) -> bool {
    const UNITS: &[&str] = &["y", "w", "d", "h", "m", "s", "ms"];
    let mut rest = v;
    let mut next = 0;
    let mut any = false;
    while !rest.is_empty() {
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if digits == 0 || digits > 9 {
            return false;
        }
        let (n, after) = rest.split_at(digits);
        let Some(u) = UNITS[next..]
            .iter()
            .position(|u| after.starts_with(u) && !(*u == "m" && after.starts_with("ms")))
        else {
            return false;
        };
        any |= n.bytes().any(|b| b != b'0');
        rest = &after[UNITS[next + u].len()..];
        next += u + 1;
    }
    any
}

/// A Prometheus size: a whole number, not zero, and a unit (`512MB`,
/// `2GB`).
pub fn prometheus_size(v: &str) -> bool {
    let digits = v.len() - v.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    (1..=12).contains(&digits)
        && v[..digits].bytes().any(|b| b != b'0')
        && ["B", "KB", "MB", "GB", "TB", "PB", "EB"].contains(&&v[digits..])
}

/// A syslog destination's host and port, if it is `host`, `host:port` or
/// `[v6]:port` (no scheme, no path). The port, when absent, is the
/// protocol's default, which the renderer fills in.
pub fn syslog_target(dest: &str) -> Option<(&str, Option<u16>)> {
    let (host, port) = if let Some(rest) = dest.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        h.parse::<std::net::Ipv6Addr>().ok()?;
        match tail {
            "" => (h, None),
            t => (h, Some(t.strip_prefix(':')?)),
        }
    } else {
        match dest.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (dest, None),
        }
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-.:".contains(c));
    if !host_ok {
        return None;
    }
    let port = match port {
        Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p != 0)?),
        None => None,
    };
    Some((host, port))
}
