//! keepalived for a pair (design: "keepalived").
//!
//! Every gateway address is a VRRPv3 instance in one sync group, so they
//! move together. All instances start as BACKUP with `nopreempt`, so the
//! pair does not bounce when the preferred node returns. The health check
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
pub const SYNC_GROUP: &str = "SPAREWALL";
pub const DEFAULT_PRIORITY: [u8; 2] = [150, 100];

pub fn instance_name(network: &str) -> String {
    format!("VI_{network}")
}

pub(crate) fn render(doc: &Document, node: &str, out: &mut Rendered) {
    if !doc.is_pair() {
        return;
    }
    let peer = doc.peer_of(node).expect("pair");
    let vrrp = doc.cluster.vrrp.as_ref();
    let idx = doc
        .cluster
        .nodes
        .iter()
        .position(|n| n == node)
        .unwrap_or(0);
    let priority = vrrp
        .and_then(|v| v.priority.get(node).copied())
        .unwrap_or(DEFAULT_PRIORITY[idx.min(1)]);
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
        writeln!(s, "    state BACKUP\n    nopreempt\n    interface {iface}").unwrap();
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
        s.push_str("    track_script {\n        sparewall_health\n    }\n");
        writeln!(s, "    notify \"{NOTIFY_SCRIPT}\"").unwrap();
        writeln!(
            s,
            "    virtual_ipaddress {{\n        {} dev {iface}\n    }}\n}}\n",
            net.vip.expect("filtered")
        )
        .unwrap();
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
