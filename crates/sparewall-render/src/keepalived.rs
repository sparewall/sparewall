//! keepalived for a pair (design: "keepalived").
//!
//! Every gateway address is a VRRPv3 instance in one sync group, so they
//! move together. All instances start as BACKUP with `nopreempt`, so the
//! pair does not bounce when the preferred node returns (unless
//! `cluster.vrrp.preempt_delay_s` asks for automatic failback); `sparewall
//! failover` moves them on request, through the `sparewall_yield` track
//! script. The health check
//! uses weight 0: a *failed* coordinator health puts the instances in
//! FAULT (with `nopreempt`, lowering priority would not move them), and
//! `fall`/`rise` give a hold-down so a briefly failing check cannot flap.

use std::fmt::Write;

use sparewall_config::model::Document;

use crate::{CheckSpec, Rendered, Service, Subsystem};

pub const UNIT: &str = "keepalived.service";
pub const CONF: &str = "keepalived.conf";
/// keepalived's runtime directory (labelled for it); the file is installed here.
pub const DIR: &str = "/run/keepalived";
/// Where keepalived reports state changes to the coordinator.
/// Where the notify script reports state changes to the coordinator.
pub const FIFO: &str = "/run/sparewall/keepalived.fifo";
/// keepalived's notify script (unconfined under SELinux by its location;
/// keepalived itself may neither create nor open the coordinator's FIFO).
pub const NOTIFY_SCRIPT: &str = "/usr/libexec/keepalived/sparewall-notify";
/// The track script (unconfined under SELinux by its location).
pub const HEALTH_SCRIPT: &str = "/usr/libexec/keepalived/sparewall-health";
/// A track script that always fails, for `cluster.hold`: every instance
/// stays in FAULT and claims no address.
pub const HELD_SCRIPT: &str = "/usr/libexec/keepalived/sparewall-held";
/// A track script that fails while [`YIELD_FILE`] asks this node to hand
/// over the gateway addresses (`sparewall failover`).
pub const YIELD_SCRIPT: &str = "/usr/libexec/keepalived/sparewall-yield";
/// Present while the coordinator makes this node yield; ignored once
/// older than [`YIELD_MAX_S`], so a coordinator that dies mid-failover
/// cannot leave the node in FAULT.
pub const YIELD_FILE: &str = "/run/sparewall/failover-yield";
pub const YIELD_MAX_S: u64 = 120;
pub const SYNC_GROUP: &str = "SPAREWALL";
pub const DEFAULT_PRIORITY: [u8; 2] = [150, 100];

pub fn instance_name(network: &str) -> String {
    format!("VI_{network}")
}

/// A node's VRRP priority: `cluster.vrrp.priority`, else the default for
/// its place in `cluster.nodes`.
pub fn priority(doc: &Document, node: &str) -> u8 {
    let idx = doc
        .cluster
        .nodes
        .iter()
        .position(|n| n == node)
        .unwrap_or(0);
    doc.cluster
        .vrrp
        .as_ref()
        .and_then(|v| v.priority.get(node).copied())
        .unwrap_or(DEFAULT_PRIORITY[idx.min(1)])
}

/// The node the operator sized for the job: the higher priority (the
/// first listed, on a tie).
pub fn preferred(doc: &Document) -> Option<&str> {
    let mut best: Option<&str> = None;
    for n in &doc.cluster.nodes {
        if best.is_none_or(|b| priority(doc, n) > priority(doc, b)) {
            best = Some(n);
        }
    }
    best
}

pub(crate) fn render(doc: &Document, node: &str, out: &mut Rendered) {
    if !doc.is_pair() {
        return;
    }
    let peer = doc.peer_of(node).expect("pair");
    let vrrp = doc.cluster.vrrp.as_ref();
    let priority = priority(doc, node);
    let preempt = match vrrp.and_then(|v| v.preempt_delay_s) {
        Some(d) => format!("preempt_delay {d}"),
        None => "nopreempt".into(),
    };
    let advert = f64::from(vrrp.and_then(|v| v.advert_interval_cs).unwrap_or(100)) / 100.0;
    let unicast = vrrp.and_then(|v| v.unicast).unwrap_or(false);
    let vmac = vrrp.and_then(|v| v.use_vmac).unwrap_or(false);

    let mut s = String::from(crate::HEADER);
    writeln!(
        s,
        "global_defs {{\n    router_id {node}\n    vrrp_version 3\n    enable_script_security\n    \
         script_user root\n    vrrp_garp_master_refresh 60\n}}\n"
    )
    .unwrap();
    writeln!(
        s,
        "vrrp_script sparewall_health {{\n    script \"{HEALTH_SCRIPT}\"\n    \
         interval 2\n    timeout 5\n    fall 3\n    rise 2\n}}\n"
    )
    .unwrap();
    writeln!(
        s,
        "vrrp_script sparewall_yield {{\n    script \"{YIELD_SCRIPT}\"\n    \
         interval 1\n    fall 1\n    rise 1\n}}\n"
    )
    .unwrap();
    let hold = doc.cluster.hold;
    if hold {
        writeln!(
            s,
            "vrrp_script sparewall_held {{\n    script \"{HELD_SCRIPT}\"\n    \
             interval 2\n    fall 1\n    rise 1\n}}\n"
        )
        .unwrap();
    }
    let instances: Vec<(&String, &sparewall_config::model::Network)> = doc
        .networks
        .iter()
        .filter(|(_, n)| n.vip.is_some() && n.vrid.is_some())
        .collect();
    if instances.is_empty() {
        return;
    }
    // keepalived rejects a sync group of one.
    if instances.len() > 1 {
        writeln!(s, "vrrp_sync_group {SYNC_GROUP} {{\n    group {{").unwrap();
        for (name, _) in &instances {
            writeln!(s, "        {}", instance_name(name)).unwrap();
        }
        writeln!(s, "    }}\n    notify \"{NOTIFY_SCRIPT}\"\n}}\n").unwrap();
    }
    for (name, net) in &instances {
        let iface = doc.network_iface(name).expect("exists");
        let port = &net.port;
        writeln!(s, "vrrp_instance {} {{", instance_name(name)).unwrap();
        writeln!(s, "    state BACKUP\n    {preempt}\n    interface {iface}").unwrap();
        writeln!(s, "    virtual_router_id {}", net.vrid.expect("filtered")).unwrap();
        writeln!(s, "    priority {priority}\n    advert_int {advert}").unwrap();
        s.push_str("    garp_master_delay 1\n");
        if vmac {
            s.push_str("    use_vmac\n    vmac_xmit_base\n");
        }
        if unicast
            && let (Some(own), Some(other)) = (net.addresses.get(node), net.addresses.get(peer))
        {
            writeln!(
                s,
                "    unicast_src_ip {}\n    unicast_peer {{\n        {}\n    }}",
                own.0.addr(),
                other.0.addr()
            )
            .unwrap();
        }
        // keepalived tracks the instance's own interface already; add the
        // port a VLAN rides on.
        if port != iface {
            writeln!(s, "    track_interface {{\n        {port}\n    }}").unwrap();
        }
        s.push_str("    track_script {\n        sparewall_health\n        sparewall_yield\n");
        if hold {
            s.push_str("        sparewall_held\n");
        }
        s.push_str("    }\n");
        writeln!(s, "    notify \"{NOTIFY_SCRIPT}\"").unwrap();
        // An instance a reload removes reports DELETED, not FAULT (the
        // default), which would read as this node's role.
        s.push_str("    notify_deleted\n");
        // Extra gateway addresses ride in the same instance, so they move
        // in the same step.
        s.push_str("    virtual_ipaddress {\n");
        for a in net.vip.iter().chain(&net.extra_vips) {
            writeln!(s, "        {a} dev {iface}").unwrap();
        }
        s.push_str("    }\n");
        // A WAN with private node addresses: the public default route
        // moves with the public addresses (#54).
        if doc.split_wan(name).is_some()
            && let Some(gw) = net.gateway
        {
            writeln!(
                s,
                "    virtual_routes {{\n        0.0.0.0/0 via {gw} dev {iface} metric {} onlink\n    }}",
                crate::networkd::WAN_METRIC
            )
            .unwrap();
        }
        s.push_str("}\n\n");
    }
    let mut links: Vec<String> = Vec::new();
    for (name, net) in &instances {
        links.push(doc.network_iface(name).expect("exists").to_string());
        links.push(net.port.clone());
    }
    links.sort();
    links.dedup();
    out.add(Subsystem::Keepalived, CONF, s);
    out.meta.services.insert(
        "vrrp".into(),
        Service {
            provider: "keepalived".into(),
            unit: UNIT.into(),
            subsystem: Subsystem::Keepalived,
            reload: true,
            // keepalived insists the interfaces exist; check in a private
            // network namespace holding dummy links of the same names.
            check: Some(CheckSpec {
                container: None,
                mount: DIR.into(),
                command: vec![
                    "unshare".into(),
                    "--net".into(),
                    "sh".into(),
                    "-ec".into(),
                    format!(
                        "for i in {}; do ip link add \"$i\" type dummy; ip link set \"$i\" multicast on up; done; \
                         exec keepalived --config-test --use-file {DIR}/{CONF}",
                        links.join(" ")
                    ),
                ],
                overrides: Default::default(),
            }),
        },
    );
}
