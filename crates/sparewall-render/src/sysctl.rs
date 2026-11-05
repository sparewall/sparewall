//! Kernel settings (design: "Performance and sizing").

use std::fmt::Write;

use sparewall_config::model::Document;
use sparewall_config::topology::LEASE_IFACE;

use crate::{Rendered, Subsystem};

pub const FILE: &str = "90-sparewall.conf";

/// Established-TCP conntrack timeout when the document sets none (the
/// kernel default of 5 days lets dead entries fill the table).
pub const DEFAULT_TCP_ESTABLISHED_TIMEOUT: u32 = 86_400;

fn common(s: &mut String, ipv6_forwarding: bool) {
    s.push_str("net.ipv4.conf.all.forwarding = 1\n");
    // IPv6 is routed once an inside network has it (#213, #214); the WAN
    // keeps learning from router advertisements, which networkd handles
    // itself whether or not the node forwards.
    writeln!(
        s,
        "net.ipv6.conf.all.forwarding = {}",
        u8::from(ipv6_forwarding)
    )
    .unwrap();
    // A new master must pick up mid-stream connections.
    s.push_str("net.netfilter.nf_conntrack_tcp_loose = 1\n");
    s.push_str("net.ipv4.conf.all.send_redirects = 0\n");
    s.push_str("net.ipv4.conf.all.accept_redirects = 0\n");
    s.push_str("net.ipv4.conf.all.accept_source_route = 0\n");
    s.push_str("net.ipv4.icmp_echo_ignore_broadcasts = 1\n");
}

pub(crate) fn render(doc: &Document, _node: &str, out: &mut Rendered) {
    let mut s = String::from(crate::HEADER);
    // In a pair, a WAN's IPv6 alone turns forwarding on too, so the key
    // changes in the same step that enables IPv6 on the static block's
    // macvlan, while it is still off (see below).
    let inside_v6 = if doc.is_pair() {
        doc.routes_ipv6()
    } else {
        doc.networks
            .values()
            .any(|n| n.ipv6.is_some() && n.role != sparewall_config::model::NetworkRole::Wan)
    };
    common(&mut s, inside_v6);
    let ct = doc.cluster.conntrack.as_ref();
    if let Some(max) = ct.and_then(|c| c.max) {
        writeln!(s, "net.netfilter.nf_conntrack_max = {max}").unwrap();
    }
    if let Some(b) = ct.and_then(|c| c.buckets) {
        writeln!(s, "net.netfilter.nf_conntrack_buckets = {b}").unwrap();
    }
    let est = ct
        .and_then(|c| c.tcp_established_timeout)
        .unwrap_or(DEFAULT_TCP_ESTABLISHED_TIMEOUT);
    writeln!(
        s,
        "net.netfilter.nf_conntrack_tcp_timeout_established = {est}"
    )
    .unwrap();
    // Interfaces carrying gateway addresses answer ARP only for addresses
    // on the interface asked, from a matching source.
    // On a WAN with private node addresses that is both the network's
    // own link, which must not answer for the gateway addresses with the
    // node's own MAC, and the macvlan with the virtual MAC that carries
    // them (#176).
    let mut ifs: Vec<String> = Vec::new();
    for (name, n) in &doc.networks {
        if n.vip.is_none() && !doc.vmac_wan(name) {
            continue;
        }
        ifs.extend(doc.network_iface(name).map(str::to_string));
        ifs.extend(doc.public_iface(name).map(str::to_string));
    }
    ifs.sort();
    ifs.dedup();
    for i in &ifs {
        writeln!(s, "net.ipv4.conf.{i}.arp_ignore = 1").unwrap();
        writeln!(s, "net.ipv4.conf.{i}.arp_announce = 2").unwrap();
    }
    // The virtual MAC is the master's alone: the backup's macvlan, up but
    // with no address, must send nothing, IPv6 included. With IPv6 on
    // that WAN (#215), a leased one's link is down on the backup, and
    // networkd runs IPv6 on the master's. A static block's is up on both
    // nodes, so it joins no multicast group the kernel would report from
    // the virtual MAC: no link-local address (so no solicited-node
    // group), and not a router there (so not all-routers). These follow
    // the global forwarding key above, which resets every interface's
    // whenever it is written; the coordinator writes no key whose value is
    // unchanged, and enables IPv6 here last. keepalived adds the master's
    // `vip`.
    if let Some((name, _)) = doc.networks.iter().find(|(n, _)| doc.vmac_wan(n)) {
        let v6 = doc.networks[name].ipv6.is_some();
        if v6 && doc.leased_wan(name).is_none() {
            writeln!(s, "net.ipv6.conf.{LEASE_IFACE}.addr_gen_mode = 1").unwrap();
            writeln!(s, "net.ipv6.conf.{LEASE_IFACE}.forwarding = 0").unwrap();
        }
        writeln!(
            s,
            "net.ipv6.conf.{LEASE_IFACE}.disable_ipv6 = {}",
            u8::from(!v6)
        )
        .unwrap();
    }
    // A pair's IPv6 gateway links (#215) carry no IPv4 address, and must
    // never answer ARP from the IPv6 virtual MAC for the node's others.
    for n in doc.networks.keys() {
        if let Some(gw) = doc.ipv6_gateway_iface(n) {
            writeln!(s, "net.ipv4.conf.{gw}.arp_ignore = 8").unwrap();
        }
    }
    out.add(Subsystem::Sysctl, FILE, s);
}

pub(crate) fn render_bootstrap(out: &mut Rendered) {
    let mut s = String::from(crate::HEADER);
    // Bootstrap mode forwards nothing.
    s.push_str("net.ipv4.conf.all.forwarding = 0\n");
    s.push_str("net.ipv6.conf.all.forwarding = 0\n");
    s.push_str("net.ipv4.conf.all.send_redirects = 0\n");
    s.push_str("net.ipv4.conf.all.accept_redirects = 0\n");
    out.add(Subsystem::Sysctl, FILE, s);
}
