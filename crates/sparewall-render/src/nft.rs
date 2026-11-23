//! The `inet sparewall` table (design: "Firewall: zones plus raw rules").
//!
//! The rendered script holds only the table body. At activation the nft
//! adapter prepends a prelude, computed from the live table, that flushes
//! and deletes the coordinator-owned chains and sets, except the sets
//! networkd fills (`Meta::preserved_sets`), so one `nft -f` transaction
//! swaps the whole policy without `flush ruleset`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use sparewall_config::identity::Identity;
use sparewall_config::model::*;
use sparewall_config::topology::{SELF_ZONE, SYNC_TUNNEL_IFACE, SYNC_TUNNEL_PORT};

use crate::{Error, Rendered, Subsystem};

pub const TABLE: &str = "sparewall";
pub const SCRIPT: &str = "sparewall.nft";
/// TCP ports the anti-lockout rule keeps open from management.
pub const ANTI_LOCKOUT_PORTS: &[u16] = &[22, 443];

fn q(s: &str) -> String {
    format!("\"{s}\"")
}

fn set_lit<I: IntoIterator<Item = String>>(items: I) -> String {
    let v: Vec<String> = items.into_iter().collect();
    if v.len() == 1 {
        v.into_iter().next().unwrap()
    } else {
        format!("{{ {} }}", v.join(", "))
    }
}

fn ifset(ifaces: &[String]) -> String {
    set_lit(ifaces.iter().map(|i| q(i)))
}

fn match_items(m: &Match) -> Vec<String> {
    let item = |i: &MatchItem| match i {
        MatchItem::Number(n) => n.to_string(),
        MatchItem::Text(s) => s.clone(),
    };
    match m {
        Match::Number(n) => vec![n.to_string()],
        Match::Text(s) => vec![s.clone()],
        Match::List(l) => l.iter().map(item).collect(),
    }
}

fn match_expr(m: &Match) -> String {
    set_lit(match_items(m))
}

/// Addresses as nft can match them: an anonymous set can't hold a named
/// one (#259), so the literals together are one match and each `@object`
/// is a match of its own. A packet matches the list when it matches any of
/// them, so a rule renders a line for each (see [`rule_lines`]).
fn addr_groups(items: Vec<String>) -> Vec<String> {
    let (objects, literals): (Vec<String>, Vec<String>) =
        items.into_iter().partition(|i| i.starts_with('@'));
    let mut groups = Vec::new();
    if !literals.is_empty() {
        groups.push(set_lit(literals));
    }
    groups.extend(objects);
    groups
}

/// Every pairing of a source and a destination match, either of which may
/// be absent (`[None]`).
fn cross(src: &[Option<String>], dst: &[Option<String>]) -> Vec<(Option<String>, Option<String>)> {
    src.iter()
        .flat_map(|s| dst.iter().map(move |d| (s.clone(), d.clone())))
        .collect()
}

fn limit_expr(l: &str) -> String {
    let mut words = l.split_whitespace();
    let rate = words.next().unwrap_or_default();
    let rest: Vec<&str> = words.collect();
    match rest.as_slice() {
        ["burst", n] => format!("limit rate {rate} burst {n} packets"),
        _ => format!("limit rate {rate}"),
    }
}

fn verdict(a: Action) -> &'static str {
    match a {
        Action::Accept => "accept",
        Action::Drop => "drop",
        Action::Reject => "reject",
    }
}

fn log_group(doc: &Document) -> u16 {
    doc.logging.as_ref().and_then(|l| l.group).unwrap_or(0)
}

/// Chain name for a zone pair.
pub fn pair_chain(from: &str, to: &str) -> String {
    match (from, to) {
        (f, SELF_ZONE) => format!("in_{f}"),
        (SELF_ZONE, t) => format!("out_{t}"),
        (f, t) => format!("fwd_{f}_{t}"),
    }
}

struct Script {
    sets: String,
    chains: Vec<(String, String)>,
}

impl Script {
    fn chain(&mut self, name: &str, body: String) {
        self.chains.push((name.to_string(), body));
    }

    fn build(self) -> String {
        let mut s = String::from(crate::HEADER);
        writeln!(s, "table inet {TABLE} {{").unwrap();
        s.push_str(&self.sets);
        for (name, body) in self.chains {
            writeln!(s, "\tchain {name} {{").unwrap();
            for line in body.lines() {
                writeln!(s, "\t\t{line}").unwrap();
            }
            writeln!(s, "\t}}").unwrap();
        }
        s.push_str("}\n");
        s
    }
}

/// A rule's lines: one without addresses, or one per family its
/// addresses and protocol allow (#211, #212), each with that family's
/// addresses (`ip saddr`, `ip6 saddr`), and within a family one per pairing
/// of its source and destination matches ([`addr_groups`], #259).
/// Splitting doesn't change what matches: every line has the rule's
/// verdict, a packet is of one family, and one that matches a line ends
/// there. A `limit` would be each line's, so validation refuses one on a
/// rule that needs more than a line per family.
fn rule_lines(doc: &Document, pair: &str, name: &str, r: &Rule) -> Vec<String> {
    if r.src.is_none() && r.dst.is_none() {
        return vec![rule_line(doc, pair, name, r, None, None)];
    }
    let split = |m: &Option<Match>| m.as_ref().map(|m| doc.split_families(m));
    let (src, dst) = (split(&r.src), split(&r.dst));
    let proto = r.proto.as_deref();
    let mut lines = Vec::new();
    for (six, fam, other) in [(false, "ip", "icmpv6"), (true, "ip6", "icmp")] {
        let pick = |m: &Option<(Vec<String>, Vec<String>)>| -> Option<Option<Vec<String>>> {
            match m {
                None => Some(None),
                Some((v4, v6)) => {
                    let items = if six { v6 } else { v4 };
                    (!items.is_empty()).then(|| Some(items.clone()))
                }
            }
        };
        let (Some(s), Some(d)) = (pick(&src), pick(&dst)) else {
            continue;
        };
        if proto == Some(other) {
            continue;
        }
        let addr = |dir: &str, items: Option<Vec<String>>| -> Vec<Option<String>> {
            match items {
                None => vec![None],
                Some(i) => addr_groups(i)
                    .into_iter()
                    .map(|g| Some(format!("{fam} {dir} {g}")))
                    .collect(),
            }
        };
        for (s, d) in cross(&addr("saddr", s), &addr("daddr", d)) {
            lines.push(rule_line(doc, pair, name, r, s, d));
        }
    }
    lines
}

/// One rendered rule line, with its source and destination matches.
fn rule_line(
    doc: &Document,
    pair: &str,
    name: &str,
    r: &Rule,
    src: Option<String>,
    dst: Option<String>,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    let proto = r.proto.as_deref();
    let has_ports = r.sport.is_some() || r.dport.is_some();
    match proto {
        Some(p) if has_ports => {
            // `tcp dport` implies the protocol.
            if let Some(s) = &r.sport {
                parts.push(format!("{p} sport {}", match_expr(s)));
            }
            if let Some(d) = &r.dport {
                parts.push(format!("{p} dport {}", match_expr(d)));
            }
        }
        Some("icmp" | "icmpv6") if !r.icmp_type.is_empty() => {}
        Some(p) => parts.push(format!("meta l4proto {p}")),
        None => {}
    }
    // Addresses go first for readability.
    let mut addr: Vec<String> = src.into_iter().chain(dst).collect();
    addr.append(&mut parts);
    let mut parts = addr;
    if !r.icmp_type.is_empty() {
        parts.push(format!(
            "{} type {}",
            if proto == Some("icmpv6") {
                "icmpv6"
            } else {
                "icmp"
            },
            set_lit(r.icmp_type.iter().cloned())
        ));
    }
    if let Some(l) = &r.limit {
        parts.push(limit_expr(l));
    }
    parts.push("counter".into());
    if r.log {
        parts.push(format!(
            "log group {} prefix {}",
            log_group(doc),
            q(&format!("{pair}:{name} "))
        ));
    }
    parts.push(verdict(r.action).into());
    parts.push(format!("comment {}", q(&format!("rule:{pair}:{name}"))));
    parts.join(" ")
}

fn raw_line(name: &str, e: &RawEntry) -> String {
    format!("{} comment {}", e.nft.trim(), q(&format!("raw:{name}")))
}

fn sorted_raw(doc: &Document, pred: impl Fn(&RawAt) -> bool) -> Vec<(&String, &RawEntry)> {
    let mut v: Vec<_> = doc.raw.iter().filter(|(_, e)| pred(&e.at)).collect();
    v.sort_by_key(|(n, e)| (e.order, n.as_str()));
    v
}

fn raw_at_hook(doc: &Document, hook: RawHook) -> String {
    sorted_raw(doc, |a| matches!(a, RawAt::Hook { hook: h } if *h == hook))
        .into_iter()
        .map(|(n, e)| raw_line(n, e) + "\n")
        .collect()
}

fn raw_at_pair(doc: &Document, pair: &str, pos: RawPosition) -> String {
    sorted_raw(
        doc,
        |a| matches!(a, RawAt::Pair { pair: p, position } if p == pair && *position == pos),
    )
    .into_iter()
    .map(|(n, e)| raw_line(n, e) + "\n")
    .collect()
}

const CT_STATE: &str = "ct state vmap { established : accept, related : accept, invalid : drop }\n";
const IPV6_LINK_LOCAL: &str = "meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert, mld-listener-query, mld2-listener-report } ip6 saddr fe80::/10 accept comment \"ipv6-link-local\"\n";

/// Addresses (elements) of a dynamic object fed from a statically
/// addressed network.
fn static_dynamic_elements(doc: &Document, node: &str, d: &DynamicSource) -> Vec<String> {
    let Some(net) = doc.networks.get(&d.network) else {
        return vec![];
    };
    let mut out = BTreeSet::new();
    match d.source {
        DynamicKind::Address => {
            if let Some(a) = net.addresses.get(node) {
                out.insert(a.0.addr().to_string());
            }
            for v in net.vip.iter().chain(&net.extra_vips) {
                out.insert(v.0.addr().to_string());
            }
        }
        DynamicKind::Prefix => {
            if let Some(s) = doc.subnet(&d.network, node) {
                out.insert(s.to_string());
            }
        }
    }
    out.into_iter().collect()
}

/// A network's prefix, when the document states it (`ipv6.mode: static`).
fn static_ipv6_prefix(doc: &Document, network: &str) -> Option<ipnet::Ipv6Net> {
    let v6 = doc.networks.get(network)?.ipv6.as_ref()?;
    match (v6.mode, v6.prefix) {
        (Ipv6Mode::Static, Some(p)) => Some(p.0.trunc()),
        _ => None,
    }
}

/// The host with suffix `x` in prefix `p`.
fn in_prefix(p: ipnet::Ipv6Net, x: std::net::Ipv6Addr) -> std::net::Ipv6Addr {
    std::net::Ipv6Addr::from(u128::from(p.network()) | u128::from(x))
}

/// Suffixes as addresses in prefix `p`; one that does not parse (which
/// validation refuses) is left out.
fn suffixes_in(p: ipnet::Ipv6Net, sfx: &[String]) -> impl Iterator<Item = String> + '_ {
    sfx.iter().filter_map(move |x| {
        let x: std::net::Ipv6Addr = x.parse().ok()?;
        Some(in_prefix(p, x).to_string())
    })
}

/// Whether a static `ipv6` object names hosts by suffix on a delegated
/// network, whose prefix only the running node knows (#245).
pub fn follows_delegated_prefix(doc: &Document, o: &Object) -> bool {
    o.kind == ObjectKind::Ipv6
        && o.dynamic.is_none()
        && o.suffixes.keys().any(|net| {
            doc.networks
                .get(net)
                .and_then(|n| n.ipv6.as_ref())
                .is_some_and(|v| v.mode == Ipv6Mode::Delegated)
        })
}

/// A static `ipv6` object's elements that the document states: its own,
/// and its hosts by suffix in static prefixes.
fn ipv6_static_elements(doc: &Document, o: &Object) -> Vec<String> {
    let mut e: Vec<String> = o
        .elements
        .iter()
        .map(|e| match e {
            MatchItem::Text(s) => s.clone(),
            MatchItem::Number(n) => n.to_string(),
        })
        .collect();
    for (net, sfx) in &o.suffixes {
        if let Some(p) = static_ipv6_prefix(doc, net) {
            e.extend(suffixes_in(p, sfx));
        }
    }
    e
}

/// What the coordinator keeps in the sets of objects that name hosts by
/// suffix on a delegated network (#245), by set name: the object's
/// static elements, and each suffix in each of its network's /64s in
/// `in_use` (by network, as `2001:db8:0:1::/64`).
pub fn suffix_sets(
    doc: &Document,
    in_use: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, BTreeSet<String>> {
    doc.objects
        .iter()
        .filter(|(_, o)| follows_delegated_prefix(doc, o))
        .map(|(name, o)| {
            let mut want: BTreeSet<String> = ipv6_static_elements(doc, o).into_iter().collect();
            for (net, sfx) in &o.suffixes {
                if static_ipv6_prefix(doc, net).is_some() {
                    continue;
                }
                for p in in_use.get(net).into_iter().flatten() {
                    if let Ok(p) = p.parse::<ipnet::Ipv6Net>() {
                        want.extend(suffixes_in(p.trunc(), sfx));
                    }
                }
            }
            (name.clone(), want)
        })
        .collect()
}

/// An ipv6 dynamic object's elements when the document states them: a
/// static network's prefix, or a static WAN's own address. `None` when
/// they are learned at run time.
fn ipv6_dynamic_elements(doc: &Document, node: &str, d: &DynamicSource) -> Option<Vec<String>> {
    let net = doc.networks.get(&d.network)?;
    let v6 = net.ipv6.as_ref()?;
    let prefix = static_ipv6_prefix(doc, &d.network)?;
    match d.source {
        DynamicKind::Prefix => Some(vec![prefix.to_string()]),
        // A pair's static WAN: its address is the vip, on the master
        // (#215).
        DynamicKind::Address if net.role == NetworkRole::Wan => Some(
            v6.addresses
                .get(node)
                .or(v6.vip.as_ref())
                .map(|a| a.to_string())
                .into_iter()
                .collect(),
        ),
        // A pair's inside network: the nodes take no address there
        // (validation refuses one).
        DynamicKind::Address if doc.is_pair() => Some(vec![]),
        // An inside network's: the node is ::1 in its /64 (#214).
        DynamicKind::Address => Some(vec![crate::networkd::node_in_prefix(prefix).to_string()]),
    }
}

/// A pair's WAN with private node addresses (#54), static or leased,
/// as `node` sees it.
struct PrivateWan<'a> {
    /// The network's own link: the private addresses and VRRP.
    link: &'a str,
    /// The link the public side is on: the macvlan with the virtual MAC,
    /// or the network's own for a static block without it (#194).
    public: &'a str,
    /// The private subnet.
    private: ipnet::Ipv4Net,
    /// The static block's gateway address; `None` for a leased WAN.
    vip: Option<std::net::Ipv4Addr>,
    /// The peer's private address.
    peer: std::net::Ipv4Addr,
}

fn private_wans<'a>(doc: &'a Document, node: &str) -> Vec<PrivateWan<'a>> {
    doc.networks
        .iter()
        .filter_map(|(name, n)| {
            let (private, vip) = match (doc.split_wan(name), doc.leased_wan(name)) {
                (Some(p), _) => (p, Some(n.vip?.0.addr())),
                (None, Some(p)) => (p, None),
                (None, None) => return None,
            };
            let peer = n.addresses.get(doc.peer_of(node)?)?;
            Some(PrivateWan {
                link: doc.network_iface(name)?,
                public: doc.public_iface(name)?,
                private,
                vip,
                peer: peer.0.addr(),
            })
        })
        .collect()
}

/// The zones a forward applies from: its `from`, then its hairpin zones.
fn forward_zones(f: &Forward) -> impl Iterator<Item = &str> {
    std::iter::once(f.from.as_deref().unwrap_or("wan")).chain(f.hairpin.iter().map(String::as_str))
}

/// The port a forwarded connection reaches the server on.
fn forward_port(f: &Forward) -> String {
    match f.to_port {
        Some(p) => p.to_string(),
        None => match_expr(&f.dport),
    }
}

/// Forwards reflected for clients on the server's own network: the
/// forward, that network's interface, and the firewall's address there
/// (the gateway address, which moves with the gateway in a pair).
fn same_network_hairpins<'a>(
    doc: &'a Document,
    node: &str,
) -> Vec<(&'a String, &'a Forward, String, std::net::Ipv4Addr)> {
    doc.forwards
        .iter()
        .filter_map(|(name, f)| {
            let net = doc.network_containing(f.to)?;
            let zone = doc.zone_of_network(net)?;
            if !f.hairpin.iter().any(|z| z == zone) {
                return None;
            }
            let n = doc.networks.get(net)?;
            let gw = n.vip.as_ref().or_else(|| n.addresses.get(node))?.0.addr();
            Some((name, f, doc.network_iface(net)?.to_string(), gw))
        })
        .collect()
}

/// A network whose DNS is intercepted (#73).
struct Intercept<'a> {
    network: &'a str,
    iface: String,
    /// The firewall's address on the network: the gateway address in a
    /// pair.
    gateway: std::net::Ipv4Addr,
    /// Where queries go: `to`, or the gateway address (the firewall's own
    /// resolver, which listens there).
    target: std::net::Ipv4Addr,
    /// `to`, a resolver of the site's own.
    to: Option<std::net::Ipv4Addr>,
    /// `to` is on the intercepted network itself.
    same_network: bool,
    ipv6: bool,
    block_dot: bool,
}

fn dns_intercepts<'a>(doc: &'a Document, node: &str) -> Vec<Intercept<'a>> {
    let Some(d) = &doc.dns else { return vec![] };
    d.intercept
        .iter()
        .filter_map(|(n, x)| {
            let iface = doc.network_iface(n)?.to_string();
            let gateway = crate::kea::gateway_addr(doc, n, node)?;
            Some(Intercept {
                network: n,
                iface,
                gateway,
                target: x.to.unwrap_or(gateway),
                to: x.to,
                same_network: x
                    .to
                    .is_some_and(|t| doc.network_containing(t) == Some(n.as_str())),
                ipv6: doc.networks.get(n).is_some_and(|net| net.ipv6.is_some()),
                block_dot: x.blocks_dot(),
            })
        })
        .collect()
}

/// What an intercepted network may not send on (#73), before the state
/// rule, so that a flow conntrack knew before the interception, which
/// the DNAT never sees again, stops too:
///
/// - DNS forwarded anywhere but to the chosen resolver, untranslated: a
///   query the interception would have redirected, from before it;
/// - DNS over IPv6, when the resolver is one of the site's own (an IPv4
///   address), so clients ask over IPv4;
/// - DNS over TLS and QUIC (853), unless kept, so clients fall back to
///   plain DNS.
///
/// The resolver's own queries, from its address, are its upstream's.
fn intercept_refusals(intercepts: &[Intercept]) -> String {
    let mut out = String::new();
    let reject = "counter reject with icmpx type admin-prohibited";
    for x in intercepts {
        let i = q(&x.iface);
        let c = |what: &str| q(&format!("dns-intercept:{}:{what}", x.network));
        match x.to {
            None => writeln!(
                out,
                "iifname {i} meta l4proto {{ tcp, udp }} th dport 53 ct status != dnat {reject} comment {}",
                c("bypass")
            )
            .unwrap(),
            Some(t) => {
                writeln!(
                    out,
                    "iifname {i} ip saddr != {t} ip daddr != {t} meta l4proto {{ tcp, udp }} th dport 53 ct status != dnat {reject} comment {}",
                    c("bypass")
                )
                .unwrap();
                if x.ipv6 {
                    writeln!(
                        out,
                        "iifname {i} meta nfproto ipv6 meta l4proto {{ tcp, udp }} th dport 53 {reject} comment {}",
                        c("ipv6")
                    )
                    .unwrap();
                }
            }
        }
        if x.block_dot {
            match x.to {
                None => writeln!(
                    out,
                    "iifname {i} meta l4proto {{ tcp, udp }} th dport 853 {reject} comment {}",
                    c("dot")
                )
                .unwrap(),
                Some(t) => {
                    // Matched by its address, which only IPv4 has.
                    writeln!(
                        out,
                        "iifname {i} meta nfproto ipv4 ip saddr != {t} meta l4proto {{ tcp, udp }} th dport 853 {reject} comment {}",
                        c("dot")
                    )
                    .unwrap();
                    if x.ipv6 {
                        writeln!(
                            out,
                            "iifname {i} meta nfproto ipv6 meta l4proto {{ tcp, udp }} th dport 853 {reject} comment {}",
                            c("dot")
                        )
                        .unwrap();
                    }
                }
            }
        }
    }
    out
}

pub(crate) fn render(doc: &Document, node: &str, out: &mut Rendered) -> Result<(), Error> {
    let pair = doc.is_pair();
    // With a network that routes IPv6 (#212), the rules that are IPv4's
    // say so; without one, the ruleset is as before IPv6 (and IPv6 is
    // dropped but link-local neighbour discovery).
    let v6 = doc.routes_ipv6();
    let v4_only = if v6 { "meta nfproto ipv4 " } else { "" };
    let mut sc = Script {
        sets: String::new(),
        chains: Vec::new(),
    };

    // --- named sets ---------------------------------------------------------
    for (name, o) in &doc.objects {
        let (ty, elements): (&str, Vec<String>) = match (&o.kind, &o.dynamic) {
            (ObjectKind::Ipv4, Some(d)) => {
                let dhcp = doc.networks.get(&d.network).is_some_and(|n| n.dhcp_client);
                if dhcp {
                    out.meta.preserved_sets.push(name.clone());
                    if let Some(i) = doc.public_iface(&d.network) {
                        out.meta.set_links.insert(name.clone(), i.to_string());
                    }
                    ("ipv4_addr", vec![])
                } else {
                    ("ipv4_addr", static_dynamic_elements(doc, node, d))
                }
            }
            (ObjectKind::Ipv4, None) => (
                "ipv4_addr",
                o.elements
                    .iter()
                    .map(|e| match e {
                        MatchItem::Text(s) => s.clone(),
                        MatchItem::Number(n) => n.to_string(),
                    })
                    .collect(),
            ),
            (ObjectKind::Ipv6, Some(d)) => match ipv6_dynamic_elements(doc, node, d) {
                Some(e) => ("ipv6_addr", e),
                // Learned at run time (DHCPv6, SLAAC, a delegated prefix):
                // networkd fills it, as a lease does an ipv4 one (#213,
                // #214). A pair's delegated network's, the coordinator
                // (#215): networkd fills sets from the node's address
                // there, which a pair's nodes do not take.
                None => {
                    out.meta.preserved_sets.push(name.clone());
                    if doc.ipv6_gateway_iface(&d.network).is_none()
                        && let Some(i) = doc.public_iface(&d.network)
                    {
                        out.meta.set_links.insert(name.clone(), i.to_string());
                    }
                    ("ipv6_addr", vec![])
                }
            },
            (ObjectKind::Ipv6, None) => {
                // Hosts by suffix in a delegated prefix: the coordinator
                // adds them as the prefix changes (#245), so a reload
                // keeps what it added.
                if follows_delegated_prefix(doc, o) {
                    out.meta.preserved_sets.push(name.clone());
                }
                ("ipv6_addr", ipv6_static_elements(doc, o))
            }
            (ObjectKind::Port, _) => (
                "inet_service",
                o.elements
                    .iter()
                    .map(|e| match e {
                        MatchItem::Text(s) => s.clone(),
                        MatchItem::Number(n) => n.to_string(),
                    })
                    .collect(),
            ),
        };
        write!(
            sc.sets,
            "\tset {name} {{\n\t\ttype {ty}\n\t\tflags interval\n\t\tauto-merge\n"
        )
        .unwrap();
        if !elements.is_empty() {
            writeln!(sc.sets, "\t\telements = {{ {} }}", elements.join(", ")).unwrap();
        }
        sc.sets.push_str("\t}\n");
    }

    // --- zones ----------------------------------------------------------------
    let zone_ifs: BTreeMap<&str, Vec<String>> = doc
        .zones
        .keys()
        .map(|z| (z.as_str(), doc.zone_ifaces(z)))
        .collect();
    let mut policies: Vec<(&str, &str, String, Policy)> = doc
        .policy
        .iter()
        .filter_map(|(k, p)| Document::split_pair(k).map(|(a, b)| (a, b, k.clone(), p.clone())))
        .collect();
    // A forward implies its zone pair: without a policy, the pair gets a
    // chain that accepts only the forwarded connections.
    for f in doc.forwards.values() {
        let Some(to) = doc
            .network_containing(f.to)
            .and_then(|n| doc.zone_of_network(n))
        else {
            continue;
        };
        for from in forward_zones(f) {
            // Within one zone, a pair chain is reached only between two of
            // its interfaces (same_network_hairpins covers the one).
            if from == to && zone_ifs.get(to).is_none_or(|i| i.len() < 2) {
                continue;
            }
            if !policies.iter().any(|(a, b, _, _)| *a == from && *b == to) {
                policies.push((
                    from,
                    to,
                    format!("{from}->{to}"),
                    Policy {
                        action: Action::Drop,
                        log: false,
                        nat: None,
                        rules: Default::default(),
                    },
                ));
            }
        }
    }
    policies.sort_by_key(|(a, b, _, _)| (*a, *b));

    // --- prerouting -----------------------------------------------------------
    // VRRP adverts are never tracked, in either direction (#174): the
    // node's own would otherwise match the WAN egress SNAT and leave with
    // the gateway address as their source, which their checksum covers, so
    // the peer rejects them. A tracked flow keeps its NAT for as long as
    // adverts refresh it, so excluding them from the SNAT alone would not
    // undo it on a running pair; an untracked packet is never NATed. Input
    // accepts them by protocol (`infra:vrrp`), not by state.
    let vrrp_notrack = if pair {
        "ip protocol vrrp notrack comment \"infra:vrrp-notrack\"\n"
    } else {
        ""
    };
    sc.chain(
        "prerouting_raw",
        format!(
            "type filter hook prerouting priority raw; policy accept;\n{vrrp_notrack}{}",
            raw_at_hook(doc, RawHook::PreroutingRaw)
        ),
    );
    if pair {
        sc.chain(
            "output_raw",
            format!("type filter hook output priority raw; policy accept;\n{vrrp_notrack}"),
        );
    }

    let mut dnat = String::from("type nat hook prerouting priority dstnat; policy accept;\n");
    for (name, f) in &doc.forwards {
        for from in forward_zones(f) {
            let ifs = zone_ifs.get(from).cloned().unwrap_or_default();
            if ifs.is_empty() {
                continue;
            }
            let comment = if f.hairpin.iter().any(|z| z == from) {
                format!("forward:{name}:hairpin")
            } else {
                format!("forward:{name}")
            };
            let to = match f.to_port {
                Some(p) => format!("{}:{p}", f.to),
                None => f.to.to_string(),
            };
            let addr = |dir: &str, m: &Option<Match>| -> Vec<Option<String>> {
                match m {
                    None => vec![None],
                    Some(m) => addr_groups(match_items(m))
                        .into_iter()
                        .map(|g| Some(format!("ip {dir} {g}")))
                        .collect(),
                }
            };
            for (s, d) in cross(&addr("saddr", &f.src), &addr("daddr", &f.dst)) {
                let mut parts = vec![format!("iifname {}", ifset(&ifs))];
                parts.extend(s);
                parts.extend(d);
                parts.push(format!("{} dport {}", f.proto, match_expr(&f.dport)));
                parts.push("counter".into());
                parts.push(format!("dnat ip to {to}"));
                parts.push(format!("comment {}", q(&comment)));
                dnat.push_str(&parts.join(" "));
                dnat.push('\n');
            }
        }
    }
    // Remote access on more ports: to the listen port, for the gateway
    // address only. In a pair that is the WAN gateway address, kept as the
    // destination (`redirect` would use the node's own address, and the
    // output chain sends remote-access replies only from the gateway
    // address); standalone, any of the firewall's own addresses.
    for (name, vpn) in &doc.vpn {
        if vpn.extra_ports.is_empty() {
            continue;
        }
        let ports = match_expr(&Match::List(
            vpn.extra_ports
                .iter()
                .map(|p| MatchItem::Number(u32::from(*p)))
                .collect(),
        ));
        for (net, n) in doc.networks_with_role(NetworkRole::Wan) {
            let Some(i) = doc.public_iface(net) else {
                continue;
            };
            // A pair's lease is on the master's lease link, as a
            // standalone node's is on the WAN.
            let leased = doc.leased_wan(net).is_some();
            let target = match (pair && !leased, n.vip) {
                (true, Some(vip)) => format!(
                    "ip daddr {a} udp dport {ports} counter dnat ip to {a}:{}",
                    vpn.listen_port,
                    a = vip.0.addr()
                ),
                (true, None) => continue,
                (false, _) => format!(
                    "{v4_only}fib daddr type local udp dport {ports} counter redirect to :{}",
                    vpn.listen_port
                ),
            };
            writeln!(
                dnat,
                "iifname {} {target} comment {}",
                q(i),
                q(&format!("vpn-{name}:extra-ports"))
            )
            .unwrap();
        }
    }
    // DNS interception (#73): a query for any server goes to the chosen
    // resolver. A resolver of the site's own sends its own queries out
    // through the same network, so its address is left alone. Over IPv6
    // the firewall's resolver listens on every address, so a redirect to
    // the address the query came to the node on will do.
    let intercepts = dns_intercepts(doc, node);
    for x in &intercepts {
        let comment = q(&format!("dns-intercept:{}", x.network));
        let own = match x.to {
            Some(t) => format!(" ip saddr != {t}"),
            None => String::new(),
        };
        writeln!(
            dnat,
            "iifname {i}{own} ip daddr != {t} meta l4proto {{ tcp, udp }} th dport 53 counter dnat ip to {t} comment {comment}",
            i = q(&x.iface),
            t = x.target
        )
        .unwrap();
        if x.ipv6 && x.to.is_none() {
            writeln!(
                dnat,
                "iifname {i} meta nfproto ipv6 meta l4proto {{ tcp, udp }} th dport 53 fib daddr type != local counter redirect comment {comment}",
                i = q(&x.iface)
            )
            .unwrap();
        }
    }
    sc.chain("prerouting_nat", dnat);

    // --- input ----------------------------------------------------------------
    let mut input = String::from("type filter hook input priority filter; policy drop;\n");
    // The sync tunnel's addresses carry the peer API and Kea HA, which
    // trust whoever reaches them: only WireGuard (the peer's key) may.
    // First, before conntrack state, zone policy and raw rules, so no
    // configuration can open them from another interface.
    let tunnel_net = pair
        .then(|| crate::networkd::sync_tunnel_addr(doc, node))
        .flatten()
        .map(|n| n.trunc());
    if let Some(net) = tunnel_net {
        writeln!(
            input,
            "iifname != {{ \"lo\", {} }} ip daddr {net} drop comment \"infra:sync-isolation\"",
            q(SYNC_TUNNEL_IFACE)
        )
        .unwrap();
    }
    // IPv6 on a link without it is dropped before the state rule, so a
    // flow conntrack knows (begun before a network lost its IPv6, say)
    // cannot carry on there either (#212).
    if v6 {
        input.push_str(&ipv6_input_early(doc));
        input.push_str(&dns_served_only(doc));
    }
    input.push_str(CT_STATE);
    input.push_str("iifname \"lo\" accept\n");
    let mgmt_if = doc
        .network_iface(&doc.management.network)
        .map(str::to_string);
    if doc.management.anti_lockout
        && let Some(m) = &mgmt_if
    {
        // Narrowed to management.sources, where the management network is
        // also an ordinary one (#177), a line per family it names (#246).
        // IPv6 sources only where the management network has IPv6:
        // elsewhere they match nothing, as validation says. A node with no
        // IPv6 at all drops IPv6 only after this rule, so a line here
        // would admit them. Unset, every host there reaches the node over
        // either family, IPv6 where the network has it or, on a node with
        // no IPv6 at all, by link-local address, as before IPv6 (#212).
        let ports = set_lit(ANTI_LOCKOUT_PORTS.iter().map(u16::to_string));
        let mut line = |from: String| {
            writeln!(
                input,
                "iifname {}{from} tcp dport {ports} accept comment \"anti-lockout\"",
                q(m)
            )
            .unwrap();
        };
        match &doc.management.sources {
            None => line(String::new()),
            Some(s) => {
                let (four, six) = doc.split_families(s);
                for g in addr_groups(four) {
                    line(format!(" ip saddr {g}"));
                }
                let mgmt_v6 = doc
                    .networks
                    .get(&doc.management.network)
                    .is_some_and(|n| n.ipv6.is_some());
                if mgmt_v6 {
                    for g in addr_groups(six) {
                        line(format!(" ip6 saddr {g}"));
                    }
                }
            }
        }
    }
    if !v6 {
        input.push_str(IPV6_LINK_LOCAL);
        input.push_str("meta nfproto ipv6 drop\n");
    }
    input.push_str("icmp type echo-request limit rate over 50/second burst 100 packets drop comment \"icmp-flood\"\n");
    if v6 {
        input.push_str("icmpv6 type echo-request limit rate over 50/second burst 100 packets drop comment \"icmpv6-flood\"\n");
    }
    // Infrastructure the firewall itself needs.
    if pair {
        let vrrp_ifs: Vec<String> = out.meta.vip_links.clone();
        if !vrrp_ifs.is_empty() {
            writeln!(
                input,
                "iifname {} ip protocol vrrp accept comment \"infra:vrrp\"",
                ifset(&vrrp_ifs)
            )
            .unwrap();
        }
        if let Some(sync) = doc.cluster.sync_network.as_deref()
            && let Some(peer) = doc.peer_of(node)
            && let Some(peer_addr) = doc.networks.get(sync).and_then(|n| n.addresses.get(peer))
            && let Some(sync_if) = doc.network_iface(sync)
        {
            writeln!(
                input,
                "iifname {} ip saddr {} udp dport {} accept comment \"infra:sync-tunnel\"",
                q(sync_if),
                peer_addr.0.addr(),
                doc.cluster.sync_port.unwrap_or(SYNC_TUNNEL_PORT)
            )
            .unwrap();
            writeln!(
                input,
                "iifname {} accept comment \"infra:sync-peer\"",
                q(SYNC_TUNNEL_IFACE)
            )
            .unwrap();
            // A network of its own carries nothing else to the node; one
            // shared with the LAN (#177) carries everything else too.
            if doc
                .networks
                .get(sync)
                .is_some_and(|n| n.role == NetworkRole::Sync)
            {
                writeln!(
                    input,
                    "iifname {} drop comment \"infra:sync-isolation\"",
                    q(sync_if)
                )
                .unwrap();
            }
        }
    }
    for (name, net) in &doc.networks {
        if net.dhcp_client
            && let Some(i) = doc.public_iface(name)
        {
            writeln!(
                input,
                "iifname {} udp sport 67 udp dport 68 accept comment \"infra:dhcp-client\"",
                q(i)
            )
            .unwrap();
        }
    }
    // DHCPv6 replies to the WAN's client: to the node only, and only on a
    // WAN that asks (#212). A reply answers a multicast solicit, which
    // conntrack cannot pair it with.
    let dhcpv6 = doc.ipv6_ifaces_where(|n, m| n.role == NetworkRole::Wan && m == Ipv6Mode::Dhcpv6);
    if !dhcpv6.is_empty() {
        writeln!(
            input,
            "iifname {} udp sport 547 udp dport 546 accept comment \"infra:dhcpv6-client\"",
            ifset(&dhcpv6)
        )
        .unwrap();
    }
    // A forward's outside address and ports belong to the server behind
    // it. Its own zones are DNATed before input; from any other zone the
    // node would answer itself (the coordinator's HTTPS, say), so refuse.
    for (name, f) in &doc.forwards {
        let Some(d) = &f.dst else { continue };
        let how = if f.proto == "tcp" {
            " with tcp reset"
        } else {
            ""
        };
        for d in addr_groups(match_items(d)) {
            writeln!(
                input,
                "ip daddr {d} {} dport {} counter reject{how} comment {}",
                f.proto,
                match_expr(&f.dport),
                q(&format!("forward:{name}:not-here"))
            )
            .unwrap();
        }
    }
    service_rules(doc, &mut input);
    input.push_str(&raw_at_hook(doc, RawHook::Input));
    let mut in_map: Vec<String> = Vec::new();
    for (from, to, _, _) in &policies {
        if *to == SELF_ZONE && *from != SELF_ZONE {
            for i in zone_ifs.get(from).into_iter().flatten() {
                in_map.push(format!("{} : jump {}", q(i), pair_chain(from, to)));
            }
        }
    }
    if !in_map.is_empty() {
        writeln!(input, "iifname vmap {{ {} }}", in_map.join(", ")).unwrap();
    }
    input.push_str("counter comment \"default:input\"\n");
    sc.chain("input", input);

    // --- forward --------------------------------------------------------------
    let mut fwd = String::from("type filter hook forward priority filter; policy drop;\n");
    if tunnel_net.is_some() {
        // Nothing is routed into or out of the sync tunnel.
        writeln!(
            fwd,
            "iifname {t} drop comment \"infra:sync-isolation\"\noifname {t} drop comment \"infra:sync-isolation\"",
            t = q(SYNC_TUNNEL_IFACE)
        )
        .unwrap();
    }
    fwd.push_str(&raw_at_hook(doc, RawHook::Forward));
    // A VPN client's kill switch (#149): its networks' traffic never
    // leaves through the WAN, so while the tunnel is down it goes nowhere.
    // Before the state rule, so that a flow that began through the WAN
    // (the tunnel was down) does not carry on there.
    let mut wan_ifs: Vec<String> = Vec::new();
    for (n, _) in doc.networks_with_role(NetworkRole::Wan) {
        wan_ifs.extend(doc.network_iface(n).map(str::to_string));
        wan_ifs.extend(doc.public_iface(n).map(str::to_string));
    }
    wan_ifs.sort();
    wan_ifs.dedup();
    for (name, c) in doc.vpn_clients.iter().filter(|(_, c)| c.route.kill_switch) {
        let from: Vec<String> = c
            .route
            .networks
            .iter()
            .filter_map(|n| doc.network_iface(n).map(str::to_string))
            .collect();
        if from.is_empty() || wan_ifs.is_empty() {
            continue;
        }
        writeln!(
            fwd,
            "iifname {} oifname {} counter drop comment {}",
            ifset(&from),
            ifset(&wan_ifs),
            q(&format!("vpn-client-{name}:kill-switch"))
        )
        .unwrap();
    }
    if !doc.vpn.is_empty() || !doc.vpn_clients.is_empty() {
        // Clamp MSS to the tunnels' smaller MTU.
        let vpn_ifs: Vec<String> = doc
            .vpn
            .keys()
            .chain(doc.vpn_clients.keys())
            .cloned()
            .collect();
        writeln!(
            fwd,
            "oifname {} tcp flags syn tcp option maxseg size set rt mtu comment \"vpn-mss\"",
            ifset(&vpn_ifs)
        )
        .unwrap();
    }
    if v6 {
        // Before the state rule, as on input. ICMPv6 errors for forwarded
        // flows (Packet Too Big, which path MTU discovery needs, and the
        // rest RFC 4890 asks for) are then conntrack's `related`, on the
        // links with IPv6 only.
        fwd.push_str(&ipv6_off(doc, "iifname", &[]));
        fwd.push_str(&ipv6_off(doc, "oifname", &[]));
    }
    fwd.push_str(&intercept_refusals(&intercepts));
    fwd.push_str(CT_STATE);
    if !v6 {
        fwd.push_str("meta nfproto ipv6 drop\n");
    }
    // On a WAN with private node addresses the backup's own traffic
    // leaves through the master (#54).
    // It arrives on the WAN's own link and leaves by the macvlan with the
    // virtual MAC, or by the same link without it (#194).
    for w in private_wans(doc, node) {
        writeln!(
            fwd,
            "iifname {} oifname {} ip saddr {} counter accept comment \"infra:peer-egress\"",
            q(w.link),
            q(w.public),
            w.peer
        )
        .unwrap();
    }
    // Intercepted DNS (#73): the site chose the resolver, so the queries
    // sent to it may pass whatever the zone policy says.
    for x in &intercepts {
        if let Some(t) = x.to {
            writeln!(
                fwd,
                "iifname {} ip daddr {t} meta l4proto {{ tcp, udp }} th dport 53 ct status dnat counter accept comment {}",
                q(&x.iface),
                q(&format!("dns-intercept:{}:forward", x.network))
            )
            .unwrap();
        }
    }
    let mut fwd_map: Vec<String> = Vec::new();
    for (from, to, _, _) in &policies {
        if *from == SELF_ZONE || *to == SELF_ZONE {
            continue;
        }
        for i in zone_ifs.get(from).into_iter().flatten() {
            for o in zone_ifs.get(to).into_iter().flatten() {
                if i != o {
                    fwd_map.push(format!(
                        "{} . {} : jump {}",
                        q(i),
                        q(o),
                        pair_chain(from, to)
                    ));
                }
            }
        }
    }
    // A client reflected to a server on its own network leaves by the
    // interface it came in on, which the zone map does not dispatch.
    for (name, f, iface, _) in same_network_hairpins(doc, node) {
        writeln!(
            fwd,
            "iifname {i} oifname {i} ip daddr {} {} dport {} ct status dnat counter accept comment {}",
            f.to,
            f.proto,
            forward_port(f),
            q(&format!("forward:{name}:hairpin")),
            i = q(&iface)
        )
        .unwrap();
    }
    if !fwd_map.is_empty() {
        writeln!(fwd, "iifname . oifname vmap {{ {} }}", fwd_map.join(", ")).unwrap();
    }
    fwd.push_str("counter comment \"default:forward\"\n");
    sc.chain("forward", fwd);

    // --- output ---------------------------------------------------------------
    let mut output = String::from("type filter hook output priority filter; policy accept;\n");
    if pair {
        // WireGuard only from the gateway address. A node that just gave
        // it up still holds its clients' sessions; a reply from its own
        // address would make a client roam to it and lose the tunnel when
        // that node goes (WireGuard follows the source of any
        // authenticated packet). The backup's handshakes to site-to-site
        // peers stop here too: the master's leave from the gateway
        // address, its default route's source on the macvlan that holds
        // it (#148).
        for (net, n) in doc.networks_with_role(NetworkRole::Wan) {
            let (Some(vip), Some(own), Some(public)) =
                (n.vip, doc.network_iface(net), doc.public_iface(net))
            else {
                continue;
            };
            // Both links: the gateway address's (the macvlan on a WAN
            // with private node addresses, #176), and the network's own,
            // by which a backup's replies would leave through its peer.
            let mut ifs = vec![own.to_string(), public.to_string()];
            ifs.sort();
            ifs.dedup();
            for (name, vpn) in &doc.vpn {
                writeln!(
                    output,
                    "oifname {} udp sport {} ip saddr != {} drop comment {}",
                    ifset(&ifs),
                    vpn.listen_port,
                    vip.0.addr(),
                    q(&format!("vpn-{name}:gateway-address-only"))
                )
                .unwrap();
            }
        }
    }
    let mut out_map: Vec<String> = Vec::new();
    for (from, to, _, _) in &policies {
        if *from == SELF_ZONE {
            for o in zone_ifs.get(to).into_iter().flatten() {
                out_map.push(format!("{} : jump {}", q(o), pair_chain(from, to)));
            }
        }
    }
    if !out_map.is_empty() {
        writeln!(output, "oifname vmap {{ {} }}", out_map.join(", ")).unwrap();
    }
    sc.chain("output", output);

    // --- postrouting ----------------------------------------------------------
    let mut post = String::from("type nat hook postrouting priority srcnat; policy accept;\n");
    post.push_str(&raw_at_hook(doc, RawHook::Postrouting));
    // The nodes' private addresses never reach the ISP: the master's
    // own traffic and the backup's, which it forwards, take the gateway
    // address. On the backup everything outside leaves via the peer, so
    // nothing matches there.
    // Only the master sends by the macvlan with the virtual MAC: its own
    // traffic and its peer's take the gateway address, or the leased one.
    for w in private_wans(doc, node) {
        let to = match w.vip {
            Some(vip) => format!("snat ip to {vip}"),
            None => "masquerade".into(),
        };
        // Without the virtual MAC (#194) the public side is the WAN's own
        // link, which also carries the private subnet and the backup's
        // traffic through its peer: only what leaves for the upstream
        // takes the gateway address.
        let only_out = if w.public == w.link {
            format!(" ip daddr != {} rt ip nexthop != {}", w.private, w.peer)
        } else {
            String::new()
        };
        writeln!(
            post,
            "oifname {} ip saddr {}{only_out} counter {to} comment \"infra:wan-egress\"",
            q(w.public),
            w.private
        )
        .unwrap();
    }
    // A VPN client's service knows only the tunnel address it assigned.
    for (name, c) in &doc.vpn_clients {
        if let Some(a) = c.addresses.first() {
            writeln!(
                post,
                "oifname {} counter snat ip to {} comment {}",
                q(name),
                a.0.addr(),
                q(&format!("vpn-client-{name}:source"))
            )
            .unwrap();
        }
    }
    // The server would answer a client on its own network directly, past
    // the reverse translation: make the firewall the source.
    for (name, f, iface, gw) in same_network_hairpins(doc, node) {
        writeln!(
            post,
            "iifname {i} oifname {i} ip daddr {} {} dport {} ct status dnat counter snat ip to {gw} comment {}",
            f.to,
            f.proto,
            forward_port(f),
            q(&format!("forward:{name}:hairpin")),
            i = q(&iface)
        )
        .unwrap();
    }
    // A resolver on the intercepted network itself would answer the
    // client directly, from its own address, which the client never
    // asked: make the firewall the source, as for a forward's hairpin.
    for x in intercepts.iter().filter(|x| x.same_network) {
        writeln!(
            post,
            "iifname {i} oifname {i} ip daddr {t} meta l4proto {{ tcp, udp }} th dport 53 ct status dnat counter snat ip to {gw} comment {}",
            q(&format!("dns-intercept:{}:hairpin", x.network)),
            i = q(&x.iface),
            t = x.target,
            gw = x.gateway
        )
        .unwrap();
    }
    for (from, to, key, pol) in &policies {
        let Some(nat) = &pol.nat else { continue };
        let (Some(fi), Some(ti)) = (zone_ifs.get(from), zone_ifs.get(to)) else {
            continue;
        };
        if fi.is_empty() || ti.is_empty() {
            continue;
        }
        let target = match nat {
            Nat::Snat { snat } => format!("snat ip to {snat}"),
            Nat::Mode(NatMode::Masquerade) => {
                // Masquerade picks the node's own primary address; when the
                // outbound network has a gateway address, use it so flows
                // survive a failover.
                let vip = doc
                    .zones
                    .get(*to)
                    .into_iter()
                    .flat_map(|z| &z.networks)
                    .find_map(|n| doc.networks.get(n).and_then(|n| n.vip));
                match vip {
                    Some(v) if pair => format!("snat ip to {}", v.0.addr()),
                    _ => "masquerade".to_string(),
                }
            }
        };
        // No NAT for IPv6 (#211): `masquerade` alone would take both.
        writeln!(
            post,
            "iifname {} oifname {} {v4_only}counter {target} comment {}",
            ifset(fi),
            ifset(ti),
            q(&format!("nat:{key}"))
        )
        .unwrap();
    }
    sc.chain("postrouting_nat", post);

    // --- zone-pair chains -----------------------------------------------------
    for (from, to, key, pol) in &policies {
        let mut body = String::new();
        body.push_str(&raw_at_pair(doc, key, RawPosition::Before));
        let mut rules: Vec<(&String, &Rule)> = pol.rules.iter().collect();
        rules.sort_by_key(|(n, r)| (r.order, n.as_str()));
        for (name, r) in rules {
            for line in rule_lines(doc, key, name, r) {
                body.push_str(&line);
                body.push('\n');
            }
        }
        // Accept DNATed connections that forwards send into this pair.
        if *to != SELF_ZONE && *from != SELF_ZONE {
            for (fname, f) in &doc.forwards {
                let fto = doc
                    .network_containing(f.to)
                    .and_then(|n| doc.zone_of_network(n));
                if forward_zones(f).any(|z| z == *from) && fto == Some(*to) {
                    let port = forward_port(f);
                    let log = if f.log {
                        format!(
                            " log group {} prefix {}",
                            log_group(doc),
                            q(&format!("forward:{fname} "))
                        )
                    } else {
                        String::new()
                    };
                    writeln!(
                        body,
                        "ip daddr {} {} dport {port} ct status dnat counter{log} accept comment {}",
                        f.to,
                        f.proto,
                        q(&format!("forward:{fname}"))
                    )
                    .unwrap();
                }
            }
        }
        body.push_str(&raw_at_pair(doc, key, RawPosition::After));
        let log = if pol.log {
            format!(
                " log group {} prefix {}",
                log_group(doc),
                q(&format!("{key}:default "))
            )
        } else {
            String::new()
        };
        writeln!(
            body,
            "counter{log} {} comment {}",
            verdict(pol.action),
            q(&format!("default:{key}"))
        )
        .unwrap();
        sc.chain(&pair_chain(from, to), body);
    }

    out.add(Subsystem::Nft, SCRIPT, sc.build());
    out.meta.preserved_sets.sort();
    Ok(())
}

/// IPv6 to the node, before the state rule, when a network routes it
/// (#212): neighbour discovery on every link, and MLD; router
/// solicitations from the inside networks with IPv6, and router
/// advertisements only from a WAN that learns from them; then nothing
/// more on a link without IPv6 (but loopback). Echo is the policies'.
///
/// Before the state rule because conntrack tracks none of these: it
/// makes no connection for neighbour discovery's types, so they are
/// `invalid` to it, and the state rule would drop them (#213).
///
/// Neighbour discovery must come from the link (hop limit 255) with code
/// 0, and never from a multicast address; an advertisement never from the
/// unspecified one, which only duplicate address detection's solicitations
/// use (RFC 4861, 7.1). The kernel checks the rest of each message (its
/// options, a solicitation from `::` being to a solicited-node address)
/// before acting on it.
fn ipv6_input_early(doc: &Document) -> String {
    let mut s = String::from(
        "icmpv6 type nd-neighbor-solicit icmpv6 code 0 ip6 hoplimit 255 ip6 saddr != ff00::/8 accept comment \"ipv6-nd\"\n\
         icmpv6 type nd-neighbor-advert icmpv6 code 0 ip6 hoplimit 255 ip6 saddr != { ::, ff00::/8 } accept comment \"ipv6-nd\"\n\
         icmpv6 type { mld-listener-query, mld2-listener-report } ip6 saddr fe80::/10 accept comment \"ipv6-mld\"\n",
    );
    let inside = doc.ipv6_ifaces_where(|n, _| n.role != NetworkRole::Wan);
    if !inside.is_empty() {
        writeln!(
            s,
            "iifname {} icmpv6 type nd-router-solicit icmpv6 code 0 ip6 hoplimit 255 accept comment \"ipv6-router-solicit\"",
            ifset(&inside)
        )
        .unwrap();
    }
    let ra = doc.ipv6_ifaces_where(|n, m| {
        n.role == NetworkRole::Wan && matches!(m, Ipv6Mode::Dhcpv6 | Ipv6Mode::Ra)
    });
    if !ra.is_empty() {
        writeln!(
            s,
            "iifname {} icmpv6 type nd-router-advert icmpv6 code 0 ip6 saddr fe80::/10 ip6 hoplimit 255 accept comment \"ipv6-router-advert\"",
            ifset(&ra)
        )
        .unwrap();
    }
    s.push_str(&ipv6_off(doc, "iifname", &["lo"]));
    s
}

/// Drop IPv6 to or from (`dir`: `iifname`, `oifname`) any interface
/// without it, but `also`.
fn ipv6_off(doc: &Document, dir: &str, also: &[&str]) -> String {
    let mut ifs: Vec<String> = also.iter().map(|i| i.to_string()).collect();
    ifs.extend(doc.ipv6_ifaces());
    format!(
        "meta nfproto ipv6 {dir} != {} drop comment \"ipv6-off\"\n",
        set_lit(ifs.iter().map(|i| q(i)))
    )
}

/// The interfaces the node's resolver serves: the served networks', and
/// the remote-access instances that name the node's tunnel address as
/// their DNS server.
fn dns_ifaces(doc: &Document) -> Vec<String> {
    let Some(d) = doc.dns.as_ref().filter(|d| d.enabled) else {
        return vec![];
    };
    let nets: Vec<&String> = if d.networks.is_empty() {
        doc.dhcp.iter().flat_map(|x| x.networks.keys()).collect()
    } else {
        d.networks.iter().collect()
    };
    let mut v: Vec<String> = Vec::new();
    for n in nets {
        v.extend(doc.network_iface(n).map(str::to_string));
        // A pair's hosts ask over IPv6 at the gateway address, on its
        // link (#215).
        v.extend(doc.ipv6_gateway_iface(n));
    }
    v.sort();
    v.dedup();
    for (name, vpn) in &doc.vpn {
        if vpn
            .dns
            .iter()
            .any(|d| vpn.addresses.iter().any(|a| a.0.addr() == *d))
        {
            v.push(name.clone());
        }
    }
    v
}

/// Over IPv6 Unbound allows any source where a prefix is delegated, so
/// no policy may open its port from another interface (#214); its IPv4
/// access control already refuses them. Before the state rule, so a flow
/// conntrack knows from before cannot carry on either.
fn dns_served_only(doc: &Document) -> String {
    let v = dns_ifaces(doc);
    if v.is_empty() || !crate::unbound::serves_ipv6(doc) {
        return String::new();
    }
    let mut only: Vec<String> = vec!["lo".into()];
    only.extend(v);
    format!(
        "meta nfproto ipv6 meta l4proto {{ tcp, udp }} th dport 53 iifname != {} drop comment \"service:dns-served-only\"\n",
        ifset(&only)
    )
}

/// Input rules for services the document turns on.
fn service_rules(doc: &Document, input: &mut String) {
    let ifs = |nets: &mut dyn Iterator<Item = &String>| -> Vec<String> {
        let mut v: Vec<String> = nets
            .filter_map(|n| doc.network_iface(n).map(str::to_string))
            .collect();
        v.sort();
        v.dedup();
        v
    };
    if let Some(d) = &doc.dhcp {
        let v = ifs(&mut d.networks.keys());
        if !v.is_empty() {
            writeln!(
                input,
                "iifname {} udp dport 67 accept comment \"service:dhcp\"",
                ifset(&v)
            )
            .unwrap();
        }
    }
    let v = dns_ifaces(doc);
    if !v.is_empty() {
        writeln!(
            input,
            "iifname {} meta l4proto {{ tcp, udp }} th dport 53 accept comment \"service:dns\"",
            ifset(&v)
        )
        .unwrap();
    }
    if let Some(n) = &doc.ntp {
        let v = ifs(&mut n.serve.iter());
        if !v.is_empty() {
            writeln!(
                input,
                "iifname {} udp dport 123 accept comment \"service:ntp\"",
                ifset(&v)
            )
            .unwrap();
        }
    }
    // The WAN's own links, and its public side where that is the
    // macvlan with the virtual MAC (#54, #176): the VPN endpoint is a
    // public address.
    let mut wan_ifs = ifs(&mut doc.networks_with_role(NetworkRole::Wan).map(|(n, _)| n));
    for (n, _) in doc.networks_with_role(NetworkRole::Wan) {
        wan_ifs.extend(doc.public_iface(n).map(str::to_string));
    }
    wan_ifs.sort();
    wan_ifs.dedup();
    for (name, vpn) in &doc.vpn {
        if !wan_ifs.is_empty() {
            writeln!(
                input,
                "iifname {} udp dport {} accept comment {}",
                ifset(&wan_ifs),
                vpn.listen_port,
                q(&format!("service:vpn-{name}"))
            )
            .unwrap();
        }
    }
}

pub(crate) fn render_bootstrap(id: &Identity, out: &mut Rendered) {
    let mgmt = crate::networkd::bootstrap_iface(id);
    let mut sc = Script {
        sets: String::new(),
        chains: Vec::new(),
    };
    let mut input = String::from("type filter hook input priority filter; policy drop;\n");
    input.push_str(CT_STATE);
    input.push_str("iifname \"lo\" accept\n");
    writeln!(
        input,
        "iifname {} tcp dport {} accept comment \"anti-lockout\"",
        q(mgmt),
        set_lit(ANTI_LOCKOUT_PORTS.iter().map(u16::to_string))
    )
    .unwrap();
    writeln!(
        input,
        "iifname {} icmp type echo-request limit rate 10/second accept comment \"bootstrap:ping\"",
        q(mgmt)
    )
    .unwrap();
    if id.management.address.is_none() {
        writeln!(
            input,
            "iifname {} udp sport 67 udp dport 68 accept comment \"infra:dhcp-client\"",
            q(mgmt)
        )
        .unwrap();
    }
    input.push_str(IPV6_LINK_LOCAL);
    input.push_str("counter comment \"default:input\"\n");
    sc.chain("input", input);
    sc.chain(
        "forward",
        "type filter hook forward priority filter; policy drop;\ncounter comment \"default:forward\"\n".into(),
    );
    sc.chain(
        "output",
        "type filter hook output priority filter; policy accept;\n".into(),
    );
    out.add(Subsystem::Nft, SCRIPT, sc.build());
}
