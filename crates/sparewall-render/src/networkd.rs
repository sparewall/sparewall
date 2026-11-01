//! systemd-networkd `.link`, `.netdev` and `.network` files (design:
//! "Networking with systemd-networkd" and "Port shapes").
//!
//! Interfaces are named after port roles and networks: a port's interface
//! is its role name, a VLAN network's interface is the network name.

use ipnet::Ipv4Net;
use sparewall_config::identity::Identity;
use sparewall_config::model::*;
use sparewall_config::topology::{LEASE_IFACE, SYNC_TUNNEL_IFACE, SYNC_TUNNEL_PORT};
use sparewall_config::validate::mac_ok;

use crate::ini::Ini;
use crate::{Error, KEY_DIR, Rendered, SYNC_KEY_RUNTIME, Subsystem};

/// Interface name of the management port in bootstrap mode.
pub const BOOTSTRAP_PORT: &str = "mgmt0";
/// Interface name of the tagged management VLAN in bootstrap mode.
pub const BOOTSTRAP_VLAN: &str = "mgmt";
/// Metric of the WAN default route (static or leased).
pub const WAN_METRIC: u32 = 100;
/// Metric of a pair node's default route via its peer on a WAN with
/// private node addresses: above the master's public route, below a
/// management network's (1024).
pub const PEER_EGRESS_METRIC: u32 = 200;

fn match_hw(ini: &mut Ini, nic: &str) {
    if mac_ok(nic) {
        ini.set("PermanentMACAddress", nic.to_ascii_lowercase());
    } else {
        ini.set("Path", nic);
    }
}

/// The sync tunnel address of a node: link-local, by position in
/// `cluster.nodes`.
pub fn sync_tunnel_addr(doc: &Document, node: &str) -> Option<Ipv4Net> {
    let idx = doc.cluster.nodes.iter().position(|n| n == node)?;
    Some(Ipv4Net::new([169, 254, 77, idx as u8 + 1].into(), 30).expect("valid prefix"))
}

pub(crate) fn render(doc: &Document, node: &str, out: &mut Rendered) -> Result<(), Error> {
    let pair = doc.is_pair();
    let ports = doc.node_ports(node);
    for (role, port) in &ports {
        let nets: Vec<(&String, &Network)> = doc
            .networks
            .iter()
            .filter(|(_, n)| n.port == *role)
            .collect();
        match (&port.nic, &port.bond) {
            (Some(nic), _) => {
                let mut link = Ini::new();
                link.section("Match");
                match_hw(&mut link, nic);
                link.section("Link").set("Name", role);
                link.opt("MTUBytes", port.mtu);
                if let Some(o) = &port.offload {
                    link.yes_no("GenericReceiveOffload", o.gro)
                        .yes_no("GenericSegmentationOffload", o.gso)
                        .yes_no("TCPSegmentationOffload", o.tso)
                        .yes_no("ReceiveChecksumOffload", o.rx_checksum)
                        .yes_no("TransmitChecksumOffload", o.tx_checksum);
                }
                out.add(
                    Subsystem::Networkd,
                    format!("10-sparewall-{role}.link"),
                    link.build(),
                );
            }
            (None, Some(bond)) => {
                let mut nd = Ini::new();
                nd.section("NetDev").set("Name", role).set("Kind", "bond");
                nd.opt("MTUBytes", port.mtu);
                nd.section("Bond").set(
                    "Mode",
                    match bond.mode {
                        BondMode::Lacp => "802.3ad",
                        BondMode::ActiveBackup => "active-backup",
                    },
                );
                nd.opt(
                    "LACPTransmitRate",
                    bond.lacp_rate.map(|r| match r {
                        LacpRate::Slow => "slow",
                        LacpRate::Fast => "fast",
                    }),
                );
                nd.opt("TransmitHashPolicy", bond.hash_policy.as_deref());
                nd.set("MIIMonitorSec", bond.miimon.as_deref().unwrap_or("100ms"));
                out.meta.bonds.insert(role.to_string(), bond.members.len());
                out.add(
                    Subsystem::Networkd,
                    format!("10-sparewall-{role}.netdev"),
                    nd.build(),
                );
                for (i, m) in bond.members.iter().enumerate() {
                    let mut mn = Ini::new();
                    mn.section("Match");
                    match_hw(&mut mn, m);
                    mn.section("Network").set("Bond", role);
                    if bond.primary.as_deref() == Some(m.as_str()) {
                        mn.set("PrimarySlave", "yes");
                    }
                    out.add(
                        Subsystem::Networkd,
                        format!("10-sparewall-{role}-m{i}.network"),
                        mn.build(),
                    );
                }
            }
            (None, None) => return Err(Error::Invalid(format!("port {role} has no hardware"))),
        }

        // The port's own .network: VLANs riding on it, plus its untagged
        // network if it has one.
        let mut pn = Ini::new();
        pn.section("Match").set("Name", role);
        let untagged = nets.iter().find(|(_, n)| n.vlan.is_none());
        pn.section("Link");
        pn.opt("MTUBytes", port.mtu);
        if untagged.is_none() {
            pn.set("RequiredForOnline", "carrier");
        }
        pn.section("Network");
        for (name, _) in nets.iter().filter(|(_, n)| n.vlan.is_some()) {
            pn.set("VLAN", name);
        }
        pn.set("LLDP", "yes").set("EmitLLDP", "nearest-bridge");
        match untagged {
            Some((name, net)) => network_body(&mut pn, doc, node, name, net, pair),
            None => {
                pn.set("LinkLocalAddressing", "no");
                pn.set("IPv6AcceptRA", "no");
            }
        }
        out.add(
            Subsystem::Networkd,
            format!("20-sparewall-{role}.network"),
            pn.build(),
        );
        // A port carrying only the sync network is replication-only; one
        // that also carries other networks (a shared trunk) carries traffic.
        if !nets.is_empty() && nets.iter().all(|(_, n)| n.role == NetworkRole::Sync) {
            out.meta.replication_links.push(role.to_string());
        } else {
            out.meta.required_links.push(role.to_string());
        }
    }

    for (name, net) in doc.networks.iter().filter(|(_, n)| n.vlan.is_some()) {
        let mut nd = Ini::new();
        nd.section("NetDev").set("Name", name).set("Kind", "vlan");
        nd.opt("MTUBytes", net.mtu);
        nd.section("VLAN").set("Id", net.vlan.expect("filtered"));
        out.add(
            Subsystem::Networkd,
            format!("30-sparewall-{name}.netdev"),
            nd.build(),
        );
        let mut nn = Ini::new();
        nn.section("Match").set("Name", name);
        nn.section("Link");
        nn.opt("MTUBytes", net.mtu);
        nn.section("Network");
        network_body(&mut nn, doc, node, name, net, pair);
        out.add(
            Subsystem::Networkd,
            format!("30-sparewall-{name}.network"),
            nn.build(),
        );
        if net.role == NetworkRole::Sync {
            out.meta.replication_links.push(name.clone());
        } else {
            out.meta.required_links.push(name.clone());
        }
    }

    for (name, net) in &doc.networks {
        if pair && net.vip.is_some() {
            let iface = doc.network_iface(name).expect("exists");
            out.meta.vip_links.push(iface.to_string());
        }
    }

    if pair {
        sync_tunnel(doc, node, out);
    }
    for (name, net) in &doc.networks {
        if doc.vmac_wan(name) {
            vmac_link(doc, name, net, out);
        }
    }
    for (name, vpn) in &doc.vpn {
        remote_access(name, vpn, out);
    }
    out.meta.required_links.sort();
    out.meta.required_links.dedup();
    out.meta.replication_links.sort();
    out.meta.replication_links.dedup();
    out.meta.vip_links.sort();
    out.meta.vip_links.dedup();
    Ok(())
}

/// `[Network]` (already opened) and later sections for one network.
fn network_body(ini: &mut Ini, doc: &Document, node: &str, name: &str, net: &Network, pair: bool) {
    if let Some(a) = net.addresses.get(node) {
        ini.set("Address", a);
    }
    // A standalone node holds the gateway address statically; in a pair it
    // belongs to keepalived.
    if let Some(vip) = &net.vip
        && !pair
        // A held node claims no gateway address, nor the extras that move
        // with it (cluster.hold).
        && !doc.cluster.hold
    {
        ini.set("Address", vip);
        for a in &net.extra_vips {
            ini.set("Address", a);
        }
    }
    if pair && net.role != NetworkRole::Sync {
        // networkd must not remove addresses and routes keepalived added,
        // on any link that may carry them, even with no gateway address
        // now: a change that takes one away (or makes the WAN leased)
        // reloads networkd before keepalived, and on the master the
        // stripped addresses would fail the pair over (#78).
        ini.set("KeepConfiguration", "yes");
    }
    let leased = doc.leased_wan(name).is_some();
    if doc.vmac_wan(name) {
        // The public side is on the macvlan with the virtual MAC: the
        // pair's one lease, or the static block's gateway addresses.
        ini.set("MACVLAN", LEASE_IFACE);
    }
    if net.dhcp_client && !leased {
        ini.set("DHCP", "ipv4");
    }
    for d in &net.dns {
        ini.set("DNS", d);
    }
    ini.set("LinkLocalAddressing", "ipv6");
    ini.set("IPv6AcceptRA", "no");
    if matches!(
        net.role,
        NetworkRole::Service | NetworkRole::Management | NetworkRole::Sync
    ) {
        ini.set("IPv4ReversePathFilter", "strict");
    }
    if let Some(lldp) = net.lldp {
        let v = if lldp { "yes" } else { "no" };
        ini.set("LLDP", v);
        ini.set("EmitLLDP", if lldp { "nearest-bridge" } else { "no" });
    }
    if doc.split_wan(name).is_some() || leased {
        // The public default route is the master's only (keepalived's, or
        // the lease's on the macvlan). Both nodes route via the peer's
        // private address with a higher metric, which the backup alone
        // uses: its own traffic leaves through the master. A held pair has
        // no master, and the two would only bounce such traffic between
        // them.
        if !doc.cluster.hold
            && let Some(peer) = doc.peer_of(node).and_then(|p| net.addresses.get(p))
        {
            ini.section("Route")
                .set("Gateway", peer.0.addr())
                .set("Metric", PEER_EGRESS_METRIC);
        }
    } else if let Some(gw) = net.gateway {
        ini.section("Route").set("Gateway", gw).set(
            "Metric",
            if net.role == NetworkRole::Wan {
                WAN_METRIC
            } else {
                1024
            },
        );
    }
    if net.dhcp_client && !leased {
        dhcp_client(ini, doc, name, net);
    }
    if let Some(cake) = &net.cake {
        ini.section("CAKE")
            .set("Parent", "root")
            .set("Bandwidth", &cake.bandwidth);
    }
}

/// The `[DHCPv4]` section of a network's DHCP client.
fn dhcp_client(ini: &mut Ini, doc: &Document, name: &str, net: &Network) {
    ini.section("DHCPv4")
        .set("UseDNS", "yes")
        .set("SendHostname", "no")
        .set(
            "RouteMetric",
            if net.role == NetworkRole::Wan {
                WAN_METRIC
            } else {
                1024
            },
        );
    // Dynamic objects filled from this network's leased address.
    let sets: Vec<String> = doc
        .objects
        .iter()
        .filter_map(|(oname, o)| {
            let d = o.dynamic.as_ref()?;
            (d.network == name).then(|| {
                let src = match d.source {
                    DynamicKind::Address => "address",
                    DynamicKind::Prefix => "prefix",
                };
                format!("{src}:inet:sparewall:{oname}")
            })
        })
        .collect();
    if !sets.is_empty() {
        ini.set("NFTSet", sets.join(" "));
    }
}

/// The public side of a pair's WAN with private node addresses (#54,
/// #176): a macvlan with the VRRP virtual MAC on the WAN link, so the ISP
/// sees one MAC whichever node is the master.
///
/// - **One lease for the pair:** it runs the DHCP client. networkd
///   leaves it down (`ActivationPolicy=manual`); the coordinator brings
///   it up on the master only, so the ISP also sees one client ID.
/// - **A static block:** keepalived puts the gateway addresses and the
///   public default route on it. It is up on both nodes, since the
///   kernel refuses a route on a link that is down and keepalived adds
///   it the moment it becomes master. The backup's has no address and no
///   IPv6, so it never sends a frame from the virtual MAC.
fn vmac_link(doc: &Document, name: &str, net: &Network, out: &mut Rendered) {
    let Some(vrid) = net.vrid else { return };
    let leased = doc.leased_wan(name).is_some();
    let mut nd = Ini::new();
    nd.section("NetDev")
        .set("Name", LEASE_IFACE)
        .set("Kind", "macvlan")
        .set("MACAddress", Document::vrrp_mac(vrid))
        .set(
            "Description",
            if leased {
                "Sparewall pair WAN lease"
            } else {
                "Sparewall pair WAN gateway addresses"
            },
        );
    nd.section("MACVLAN").set("Mode", "bridge");
    out.add(
        Subsystem::Networkd,
        format!("40-sparewall-{LEASE_IFACE}.netdev"),
        nd.build(),
    );
    let mut nn = Ini::new();
    nn.section("Match").set("Name", LEASE_IFACE);
    if !leased {
        nn.section("Link").set("RequiredForOnline", "no");
        // Nothing of its own: keepalived's addresses and route, which
        // networkd keeps.
        nn.section("Network")
            .set("LinkLocalAddressing", "no")
            .set("IPv6AcceptRA", "no")
            .set("KeepConfiguration", "yes");
        out.add(
            Subsystem::Networkd,
            format!("40-sparewall-{LEASE_IFACE}.network"),
            nn.build(),
        );
        return;
    }
    nn.section("Link")
        .set("ActivationPolicy", "manual")
        .set("RequiredForOnline", "no");
    nn.section("Network")
        .set("DHCP", "ipv4")
        .set("LinkLocalAddressing", "no")
        .set("IPv6AcceptRA", "no");
    dhcp_client(&mut nn, doc, name, net);
    // The same client ID from either node, and the lease kept for the
    // next master when this one stops.
    nn.set("ClientIdentifier", "mac").set("SendRelease", "no");
    out.add(
        Subsystem::Networkd,
        format!("40-sparewall-{LEASE_IFACE}.network"),
        nn.build(),
    );
}

fn sync_tunnel(doc: &Document, node: &str, out: &mut Rendered) {
    let Some(peer) = doc.peer_of(node) else {
        return;
    };
    let Some(peer_key) = doc.cluster.sync_keys.get(peer) else {
        // Not paired yet: the tunnel comes up once both keys are in the
        // document.
        return;
    };
    let Some(sync_net) = doc.cluster.sync_network.as_deref() else {
        return;
    };
    let Some(peer_addr) = doc
        .networks
        .get(sync_net)
        .and_then(|n| n.addresses.get(peer))
    else {
        return;
    };
    let port = doc.cluster.sync_port.unwrap_or(SYNC_TUNNEL_PORT);
    let mut nd = Ini::new();
    nd.section("NetDev")
        .set("Name", SYNC_TUNNEL_IFACE)
        .set("Kind", "wireguard")
        .set("Description", "Sparewall pair sync tunnel");
    nd.section("WireGuard")
        .set("PrivateKeyFile", SYNC_KEY_RUNTIME)
        .set("ListenPort", port);
    let peer_tunnel = sync_tunnel_addr(doc, peer).expect("peer is a node");
    nd.section("WireGuardPeer")
        .set("PublicKey", peer_key)
        .set("Endpoint", format!("{}:{port}", peer_addr.0.addr()))
        .set("AllowedIPs", format!("{}/32", peer_tunnel.addr()))
        .set("PersistentKeepalive", 5);
    out.add(
        Subsystem::Networkd,
        format!("40-sparewall-{SYNC_TUNNEL_IFACE}.netdev"),
        nd.build(),
    );
    let mut nn = Ini::new();
    nn.section("Match").set("Name", SYNC_TUNNEL_IFACE);
    nn.section("Link").set("RequiredForOnline", "no");
    nn.section("Network")
        .set(
            "Address",
            sync_tunnel_addr(doc, node).expect("node is a node"),
        )
        .set("LinkLocalAddressing", "no")
        .set("IPv6AcceptRA", "no");
    out.add(
        Subsystem::Networkd,
        format!("40-sparewall-{SYNC_TUNNEL_IFACE}.network"),
        nn.build(),
    );
}

fn remote_access(name: &str, vpn: &Vpn, out: &mut Rendered) {
    let mut nd = Ini::new();
    nd.section("NetDev")
        .set("Name", name)
        .set("Kind", "wireguard")
        .set("Description", format!("Sparewall remote-access VPN {name}"));
    nd.section("WireGuard")
        .set(
            "PrivateKeyFile",
            format!("{KEY_DIR}/{}", crate::vpn_key_file(name)),
        )
        .set("ListenPort", vpn.listen_port);
    for (pname, peer) in &vpn.peers {
        nd.section("WireGuardPeer")
            .set("PublicKey", &peer.public_key)
            .set(
                "AllowedIPs",
                peer.addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        nd.opt("Endpoint", peer.endpoint.as_deref());
        if peer.preshared_key.is_some() {
            nd.set(
                "PresharedKeyFile",
                format!("{KEY_DIR}/{}", crate::vpn_psk_file(name, pname)),
            );
        }
    }
    out.add(
        Subsystem::Networkd,
        format!("50-sparewall-{name}.netdev"),
        nd.build(),
    );
    let mut nn = Ini::new();
    nn.section("Match").set("Name", name);
    nn.section("Link").set("RequiredForOnline", "no");
    nn.section("Network");
    for a in &vpn.addresses {
        nn.set("Address", a);
    }
    nn.set("LinkLocalAddressing", "no")
        .set("IPv6AcceptRA", "no");
    out.add(
        Subsystem::Networkd,
        format!("50-sparewall-{name}.network"),
        nn.build(),
    );
}

pub(crate) fn render_bootstrap(id: &Identity, out: &mut Rendered) {
    let m = &id.management;
    let mut link = Ini::new();
    link.section("Match");
    match_hw(&mut link, &m.nic);
    link.section("Link").set("Name", BOOTSTRAP_PORT);
    out.add(
        Subsystem::Networkd,
        format!("10-sparewall-{BOOTSTRAP_PORT}.link"),
        link.build(),
    );

    let addressing = |ini: &mut Ini| {
        match &m.address {
            Some(a) => {
                ini.set("Address", a);
                for d in &m.dns {
                    ini.set("DNS", d);
                }
            }
            None => {
                ini.set("DHCP", "ipv4");
            }
        }
        ini.set("LinkLocalAddressing", "ipv6")
            .set("IPv6AcceptRA", "no");
        if let Some(gw) = m.gateway {
            ini.section("Route").set("Gateway", gw);
        }
    };

    let mut pn = Ini::new();
    pn.section("Match").set("Name", BOOTSTRAP_PORT);
    pn.section("Network");
    pn.set("LLDP", "yes").set("EmitLLDP", "nearest-bridge");
    match m.vlan {
        Some(vlan) => {
            pn.set("VLAN", BOOTSTRAP_VLAN)
                .set("LinkLocalAddressing", "no")
                .set("IPv6AcceptRA", "no");
            let mut nd = Ini::new();
            nd.section("NetDev")
                .set("Name", BOOTSTRAP_VLAN)
                .set("Kind", "vlan");
            nd.section("VLAN").set("Id", vlan);
            out.add(
                Subsystem::Networkd,
                format!("30-sparewall-{BOOTSTRAP_VLAN}.netdev"),
                nd.build(),
            );
            let mut nn = Ini::new();
            nn.section("Match").set("Name", BOOTSTRAP_VLAN);
            nn.section("Network");
            addressing(&mut nn);
            out.add(
                Subsystem::Networkd,
                format!("30-sparewall-{BOOTSTRAP_VLAN}.network"),
                nn.build(),
            );
            out.meta.required_links.push(BOOTSTRAP_VLAN.into());
        }
        None => addressing(&mut pn),
    }
    out.add(
        Subsystem::Networkd,
        format!("20-sparewall-{BOOTSTRAP_PORT}.network"),
        pn.build(),
    );
    out.meta.required_links.push(BOOTSTRAP_PORT.into());
    out.meta.required_links.sort();
}

/// The interface management traffic arrives on in bootstrap mode.
pub fn bootstrap_iface(id: &Identity) -> &'static str {
    if id.management.vlan.is_some() {
        BOOTSTRAP_VLAN
    } else {
        BOOTSTRAP_PORT
    }
}
