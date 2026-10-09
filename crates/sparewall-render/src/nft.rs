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

/// One rendered rule line.
fn rule_line(doc: &Document, pair: &str, name: &str, r: &Rule) -> String {
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
        Some("icmp") if !r.icmp_type.is_empty() => {}
        Some(p) => parts.push(format!("meta l4proto {p}")),
        None => {}
    }
    // Addresses go first for readability.
    let mut addr = Vec::new();
    if let Some(s) = &r.src {
        addr.push(format!("ip saddr {}", match_expr(s)));
    }
    if let Some(d) = &r.dst {
        addr.push(format!("ip daddr {}", match_expr(d)));
    }
    addr.append(&mut parts);
    let mut parts = addr;
    if !r.icmp_type.is_empty() {
        parts.push(format!(
            "icmp type {}",
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
            if let Some(v) = &net.vip {
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

pub(crate) fn render(doc: &Document, node: &str, out: &mut Rendered) -> Result<(), Error> {
    let pair = doc.is_pair();
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
                    if let Some(i) = doc.network_iface(&d.network) {
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
        let from = f.from.as_deref().unwrap_or("wan");
        let Some(to) = doc
            .network_containing(f.to)
            .and_then(|n| doc.zone_of_network(n))
        else {
            continue;
        };
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
    policies.sort_by_key(|(a, b, _, _)| (*a, *b));

    // --- prerouting -----------------------------------------------------------
    sc.chain(
        "prerouting_raw",
        format!(
            "type filter hook prerouting priority raw; policy accept;\n{}",
            raw_at_hook(doc, RawHook::PreroutingRaw)
        ),
    );

    let mut dnat = String::from("type nat hook prerouting priority dstnat; policy accept;\n");
    for (name, f) in &doc.forwards {
        let from = f.from.as_deref().unwrap_or("wan");
        let ifs = zone_ifs.get(from).cloned().unwrap_or_default();
        if ifs.is_empty() {
            continue;
        }
        let mut parts = vec![format!("iifname {}", ifset(&ifs))];
        if let Some(s) = &f.src {
            parts.push(format!("ip saddr {}", match_expr(s)));
        }
        if let Some(d) = &f.dst {
            parts.push(format!("ip daddr {}", match_expr(d)));
        }
        parts.push(format!("{} dport {}", f.proto, match_expr(&f.dport)));
        parts.push("counter".into());
        let to = match f.to_port {
            Some(p) => format!("{}:{p}", f.to),
            None => f.to.to_string(),
        };
        parts.push(format!("dnat ip to {to}"));
        parts.push(format!("comment {}", q(&format!("forward:{name}"))));
        dnat.push_str(&parts.join(" "));
        dnat.push('\n');
    }
    sc.chain("prerouting_nat", dnat);

    // --- input ----------------------------------------------------------------
    let mut input = String::from("type filter hook input priority filter; policy drop;\n");
    input.push_str(CT_STATE);
    input.push_str("iifname \"lo\" accept\n");
    let mgmt_if = doc
        .network_iface(&doc.management.network)
        .map(str::to_string);
    if doc.management.anti_lockout
        && let Some(m) = &mgmt_if
    {
        writeln!(
            input,
            "iifname {} tcp dport {} accept comment \"anti-lockout\"",
            q(m),
            set_lit(ANTI_LOCKOUT_PORTS.iter().map(u16::to_string))
        )
        .unwrap();
    }
    input.push_str(IPV6_LINK_LOCAL);
    input.push_str("meta nfproto ipv6 drop\n");
    input.push_str("icmp type echo-request limit rate over 50/second burst 100 packets drop comment \"icmp-flood\"\n");
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
            writeln!(
                input,
                "iifname {} drop comment \"infra:sync-isolation\"",
                q(sync_if)
            )
            .unwrap();
        }
    }
    for (name, net) in &doc.networks {
        if net.dhcp_client
            && let Some(i) = doc.network_iface(name)
        {
            writeln!(
                input,
                "iifname {} udp sport 67 udp dport 68 accept comment \"infra:dhcp-client\"",
                q(i)
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
    fwd.push_str(&raw_at_hook(doc, RawHook::Forward));
    if !doc.vpn.is_empty() {
        // Clamp MSS to the tunnels' smaller MTU.
        let vpn_ifs: Vec<String> = doc.vpn.keys().cloned().collect();
        writeln!(
            fwd,
            "oifname {} tcp flags syn tcp option maxseg size set rt mtu comment \"vpn-mss\"",
            ifset(&vpn_ifs)
        )
        .unwrap();
    }
    fwd.push_str(CT_STATE);
    fwd.push_str("meta nfproto ipv6 drop\n");
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
    if !fwd_map.is_empty() {
        writeln!(fwd, "iifname . oifname vmap {{ {} }}", fwd_map.join(", ")).unwrap();
    }
    fwd.push_str("counter comment \"default:forward\"\n");
    sc.chain("forward", fwd);

    // --- output ---------------------------------------------------------------
    let mut output = String::from("type filter hook output priority filter; policy accept;\n");
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
        writeln!(
            post,
            "iifname {} oifname {} counter {target} comment {}",
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
            body.push_str(&rule_line(doc, key, name, r));
            body.push('\n');
        }
        // Accept DNATed connections that forwards send into this pair.
        if *to != SELF_ZONE && *from != SELF_ZONE {
            for (fname, f) in &doc.forwards {
                let ffrom = f.from.as_deref().unwrap_or("wan");
                let fto = doc
                    .network_containing(f.to)
                    .and_then(|n| doc.zone_of_network(n));
                if ffrom == *from && fto == Some(*to) {
                    let port = match f.to_port {
                        Some(p) => p.to_string(),
                        None => match_expr(&f.dport),
                    };
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
    if let Some(d) = &doc.dns
        && d.enabled
    {
        let v = if d.networks.is_empty() {
            ifs(&mut doc.dhcp.iter().flat_map(|x| x.networks.keys()))
        } else {
            ifs(&mut d.networks.iter())
        };
        let mut v = v;
        for (name, vpn) in &doc.vpn {
            if vpn
                .dns
                .iter()
                .any(|d| vpn.addresses.iter().any(|a| a.0.addr() == *d))
            {
                v.push(name.clone());
            }
        }
        if !v.is_empty() {
            writeln!(
                input,
                "iifname {} meta l4proto {{ tcp, udp }} th dport 53 accept comment \"service:dns\"",
                ifset(&v)
            )
            .unwrap();
        }
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
    let wan_ifs = ifs(&mut doc.networks_with_role(NetworkRole::Wan).map(|(n, _)| n));
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
