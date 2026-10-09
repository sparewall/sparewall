//! Semantic checks beyond what the schema can express.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::model::*;
use crate::topology::{RESERVED_IFACES, SELF_ZONE};

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
    let mut v = Validator {
        doc,
        issues: Vec::new(),
    };
    v.schema();
    v.cluster();
    v.ports();
    v.networks();
    v.management();
    v.zones();
    v.objects();
    v.policy();
    v.forwards();
    v.raw();
    v.dhcp();
    v.dns();
    v.ntp();
    v.vpn();
    v.tls();
    v.secrets();
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

/// Interface-name rules: lowercase, starts with a letter, at most 15 bytes.
pub fn iface_name_ok(s: &str) -> bool {
    ident_ok(s, 15, "-_")
}

/// Zone and object names become nft chain and set names.
pub fn nft_name_ok(s: &str) -> bool {
    ident_ok(s, 31, "_")
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
    "tcp", "udp", "icmp", "sctp", "gre", "esp", "ah", "vrrp", "igmp",
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
        if self.doc.schema != SCHEMA_VERSION {
            self.err(
                "schema",
                format!(
                    "schema version {} is not supported (this coordinator reads {SCHEMA_VERSION})",
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
            if !ident_ok(n, 31, "-") {
                self.err(
                    format!("cluster.nodes[{i}]"),
                    format!("invalid node name {n:?}: use lowercase letters, digits and '-'"),
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
                Some(n) if n.role != NetworkRole::Sync => self.err(
                    "cluster.sync_network",
                    format!("network {s:?} must have role sync"),
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
                if !iface_name_ok(role) || RESERVED_IFACES.contains(&role.as_str()) {
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
            if !iface_name_ok(name) || RESERVED_IFACES.contains(&name.as_str()) {
                self.err(&p, "network names become interface names: lowercase, start with a letter, at most 15 characters, not reserved");
            }
            if net.vlan.is_some() && roles.contains(name.as_str()) {
                self.err(&p, "a VLAN network cannot share its name with a port role");
            }
            if doc.vpn.contains_key(name) {
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
                if !net.addresses.is_empty() {
                    self.err(
                        format!("{p}.dhcp_client"),
                        "use either addresses or dhcp_client, not both",
                    );
                }
                if pair && net.role == NetworkRole::Wan && net.vip.is_none() {
                    self.warn(format!("{p}.dhcp_client"), "a DHCP WAN in a pair has no shared gateway address; failover changes the public address");
                }
            } else {
                for n in self.nodes().to_vec() {
                    if !net.addresses.contains_key(&n) {
                        self.err(
                            format!("{p}.addresses"),
                            format!("no address for node {n:?}"),
                        );
                    }
                }
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
                    self.err(
                        format!("{p}.vip"),
                        format!("not in the network's subnet {s}"),
                    );
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
            } else if net.vrid.is_some() {
                self.err(
                    format!("{p}.vrid"),
                    "a VRRP ID needs a gateway address (vip)",
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
            if let Some(gw) = net.gateway {
                if net.dhcp_client {
                    self.err(format!("{p}.gateway"), "a DHCP client learns its gateway");
                } else if let Some(s) = subnet
                    && !s.contains(&gw)
                {
                    self.err(format!("{p}.gateway"), format!("not inside {s}"));
                }
            }
            if let Some(s) = subnet {
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
            if z.networks.is_empty() && !doc.vpn.values().any(|v| &v.zone == name) {
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
            match (&o.dynamic, o.elements.is_empty()) {
                (Some(_), false) => self.err(&p, "a dynamic object has no static elements"),
                (None, true) => self.warn(&p, "object is empty"),
                _ => {}
            }
            if let Some(d) = &o.dynamic {
                if o.kind != ObjectKind::Ipv4 {
                    self.err(format!("{p}.dynamic"), "only ipv4 objects can be dynamic");
                }
                if !doc.networks.contains_key(&d.network) {
                    self.err(
                        format!("{p}.dynamic.network"),
                        format!("no network named {:?}", d.network),
                    );
                }
            }
            for (i, e) in o.elements.iter().enumerate() {
                let ok = match o.kind {
                    ObjectKind::Ipv4 => matches!(e, MatchItem::Text(s) if ipv4_element_ok(s)),
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

    fn check_addr_match(&mut self, p: &str, m: &Match) {
        let items: Vec<MatchItem> = match m {
            Match::Number(n) => vec![MatchItem::Number(*n)],
            Match::Text(s) => vec![MatchItem::Text(s.clone())],
            Match::List(l) => l.clone(),
        };
        if items.is_empty() {
            self.err(p, "empty list");
        }
        for it in items {
            match it {
                MatchItem::Text(s) if s.starts_with('@') => {
                    self.check_ref(p, &s[1..], ObjectKind::Ipv4)
                }
                MatchItem::Text(s) if ipv4_element_ok(&s) => {}
                _ => self.err(p, "expected an IPv4 address, prefix, range or @object"),
            }
        }
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
        for (field, m) in [("src", &r.src), ("dst", &r.dst)] {
            if let Some(m) = m {
                self.check_addr_match(&format!("{rp}.{field}"), m);
            }
        }
        if !r.icmp_type.is_empty() && proto != Some("icmp") {
            self.err(format!("{rp}.icmp_type"), "needs proto icmp");
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
        let provider = d.provider.as_deref().unwrap_or("kea");
        match provider {
            "kea" => {}
            "networkd" if doc.is_pair() => self.err(
                "dhcp.provider",
                "the networkd DHCP server has no HA; use kea for a pair",
            ),
            "networkd" => {}
            other => self.err(
                "dhcp.provider",
                format!("unknown DHCP provider {other:?}; use kea or networkd"),
            ),
        }
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
            taken.extend(net.vip.iter().map(|v| v.0.addr()));
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
        if let Some(pv) = &d.provider
            && pv != "unbound"
        {
            self.err(
                "dns.provider",
                format!("unknown DNS provider {pv:?}; use unbound"),
            );
        }
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
            if !iface_name_ok(name) || RESERVED_IFACES.contains(&name.as_str()) {
                self.err(&p, "VPN names become interface names: lowercase, start with a letter, at most 15 characters");
            }
            if !ports.insert(v.listen_port) || doc.cluster.sync_port == Some(v.listen_port) {
                self.err(format!("{p}.listen_port"), "port already in use");
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
            }
        }
    }

    fn tls(&mut self) {
        let doc = self.doc;
        let Some(t) = &doc.tls else { return };
        for (name, c) in &t.certificates {
            let p = format!("tls.certificates.{name}");
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
                        if d.credentials.is_none() {
                            self.err(
                                format!("{p}.acme.dns.credentials"),
                                "needs a secret:<name> reference",
                            );
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
