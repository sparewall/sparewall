//! Kernel settings (design: "Performance and sizing").

use std::fmt::Write;

use sparewall_config::model::Document;
use sparewall_config::topology::LEASE_IFACE;

use crate::{Rendered, Subsystem};

pub const FILE: &str = "90-sparewall.conf";

/// Established-TCP conntrack timeout when the document sets none (the
/// kernel default of 5 days lets dead entries fill the table).
pub const DEFAULT_TCP_ESTABLISHED_TIMEOUT: u32 = 86_400;

fn common(s: &mut String) {
    s.push_str("net.ipv4.conf.all.forwarding = 1\n");
    s.push_str("net.ipv6.conf.all.forwarding = 0\n");
    // A new master must pick up mid-stream connections.
    s.push_str("net.netfilter.nf_conntrack_tcp_loose = 1\n");
    s.push_str("net.ipv4.conf.all.send_redirects = 0\n");
    s.push_str("net.ipv4.conf.all.accept_redirects = 0\n");
    s.push_str("net.ipv4.conf.all.accept_source_route = 0\n");
    s.push_str("net.ipv4.icmp_echo_ignore_broadcasts = 1\n");
}

pub(crate) fn render(doc: &Document, _node: &str, out: &mut Rendered) {
    let mut s = String::from(crate::HEADER);
    common(&mut s);
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
    // with no address, must send nothing, IPv6 included.
    if doc.networks.keys().any(|n| doc.vmac_wan(n)) {
        writeln!(s, "net.ipv6.conf.{LEASE_IFACE}.disable_ipv6 = 1").unwrap();
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
