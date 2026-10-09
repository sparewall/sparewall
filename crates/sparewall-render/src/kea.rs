//! Kea DHCPv4 (design: "Service providers", default DHCPv4 provider).
//!
//! Kea runs in a container on the host network, reading
//! `/etc/kea/kea-dhcp4.conf` from the rendered `dhcp/` directory. Kea 3.x
//! only accepts a control socket under `/run/kea` and lease files under
//! `/var/lib/kea`.

use std::net::Ipv4Addr;

use serde_json::{Value, json};
use sparewall_config::model::{DhcpHa, Document};

use crate::networkd::sync_tunnel_addr;
use crate::{CheckSpec, Error, Rendered, Service, Subsystem};

pub const UNIT: &str = "sparewall-kea.service";
pub const CONTAINER: &str = "sparewall-kea";
pub const CONF: &str = "kea-dhcp4.conf";
pub const HOOKS: &str = "/usr/lib64/kea/hooks";
/// HA listener port on the sync tunnel.
pub const HA_PORT: u16 = 8647;
pub const DEFAULT_LEASE_TIME: u32 = 86_400;

/// A stable Kea subnet ID for a network: its VLAN ID, or a hash of its name
/// above the VLAN range. Leases are keyed by subnet ID, so it must not
/// change when other networks are added.
pub fn subnet_id(name: &str, vlan: Option<u16>) -> u32 {
    if let Some(v) = vlan {
        return u32::from(v);
    }
    // FNV-1a.
    let mut h: u32 = 0x811c_9dc5;
    for b in name.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    5000 + h % 1_000_000
}

/// The address clients use as their router and resolver on a network.
pub fn gateway_addr(doc: &Document, network: &str, node: &str) -> Option<Ipv4Addr> {
    let net = doc.networks.get(network)?;
    net.vip
        .as_ref()
        .or_else(|| net.addresses.get(node))
        .map(|c| c.0.addr())
}

fn dns_served(doc: &Document, network: &str) -> bool {
    match &doc.dns {
        Some(d) if d.enabled => {
            d.networks.is_empty()
                && doc
                    .dhcp
                    .as_ref()
                    .is_some_and(|x| x.networks.contains_key(network))
                || d.networks.iter().any(|n| n == network)
        }
        _ => false,
    }
}

pub(crate) fn render(doc: &Document, node: &str, out: &mut Rendered) -> Result<(), Error> {
    let Some(dhcp) = &doc.dhcp else { return Ok(()) };
    if dhcp.networks.is_empty() || dhcp.provider.as_deref().unwrap_or("kea") != "kea" {
        return Ok(());
    }
    let pair = doc.is_pair();
    let mut interfaces = Vec::new();
    let mut subnets = Vec::new();
    for (name, dn) in &dhcp.networks {
        let net = doc
            .networks
            .get(name)
            .ok_or_else(|| Error::Invalid(format!("dhcp.{name}: no such network")))?;
        let iface = doc.network_iface(name).expect("exists");
        let subnet = doc
            .subnet(name, node)
            .ok_or_else(|| Error::Invalid(format!("dhcp.{name}: network has no subnet")))?;
        // In a pair each Kea binds to its node's own address, not the
        // gateway address that moves.
        interfaces.push(match (pair, net.addresses.get(node)) {
            (true, Some(a)) => format!("{iface}/{}", a.0.addr()),
            _ => iface.to_string(),
        });
        let gw = gateway_addr(doc, name, node);
        let opts = dn.options.as_ref();
        let mut option_data = Vec::new();
        if let Some(r) = opts.and_then(|o| o.router).or(gw) {
            option_data.push(json!({"name": "routers", "data": r.to_string()}));
        }
        let dns: Vec<String> = match opts.map(|o| &o.dns).filter(|d| !d.is_empty()) {
            Some(d) => d.iter().map(ToString::to_string).collect(),
            None if dns_served(doc, name) => gw.iter().map(ToString::to_string).collect(),
            None => vec![],
        };
        if !dns.is_empty() {
            option_data.push(json!({"name": "domain-name-servers", "data": dns.join(", ")}));
        }
        let ntp: Vec<String> = match opts.map(|o| &o.ntp).filter(|d| !d.is_empty()) {
            Some(d) => d.iter().map(ToString::to_string).collect(),
            None if doc
                .ntp
                .as_ref()
                .is_some_and(|n| n.serve.iter().any(|s| s == name)) =>
            {
                gw.iter().map(ToString::to_string).collect()
            }
            None => vec![],
        };
        if !ntp.is_empty() {
            option_data.push(json!({"name": "ntp-servers", "data": ntp.join(", ")}));
        }
        let domain = opts
            .and_then(|o| o.domain.clone())
            .or_else(|| doc.dns.as_ref().and_then(|d| d.domain.clone()));
        if let Some(d) = &domain {
            option_data.push(json!({"name": "domain-name", "data": d}));
        }
        let (first, last) = sparewall_config::validate::parse_range(&dn.pool)
            .ok_or_else(|| Error::Invalid(format!("dhcp.{name}.pool: invalid range")))?;
        let reservations: Vec<Value> = dn
            .reservations
            .iter()
            .map(|(rname, r)| {
                json!({
                    "hw-address": r.mac.to_ascii_lowercase(),
                    "ip-address": r.address.to_string(),
                    "hostname": r.hostname.clone().unwrap_or_else(|| rname.clone()),
                })
            })
            .collect();
        let mut s = json!({
            "id": subnet_id(name, net.vlan),
            // No "interface": Kea selects directly connected subnets by the
            // receiving interface's address, and naming one makes the config
            // test fail for a VLAN that does not exist yet.
            "subnet": subnet.to_string(),
            "pools": [{"pool": format!("{first} - {last}")}],
            "option-data": option_data,
            "reservations": reservations,
        });
        if let Some(lt) = dn.lease_time {
            s["valid-lifetime"] = json!(lt);
        }
        subnets.push(s);
    }
    subnets.sort_by_key(|s| s["id"].as_u64());

    let mut hooks = vec![json!({"library": format!("{HOOKS}/libdhcp_lease_cmds.so")})];
    let ha = pair && dhcp.ha.unwrap_or(DhcpHa::HotStandby) == DhcpHa::HotStandby;
    if ha {
        let peers: Vec<Value> = doc
            .cluster
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let addr = sync_tunnel_addr(doc, n).expect("node").addr();
                json!({
                    "name": n,
                    "url": format!("http://{addr}:{HA_PORT}/"),
                    "role": if i == 0 { "primary" } else { "standby" },
                    "auto-failover": true,
                })
            })
            .collect();
        hooks.push(json!({
            "library": format!("{HOOKS}/libdhcp_ha.so"),
            "parameters": {"high-availability": [{
                "this-server-name": node,
                "mode": "hot-standby",
                "heartbeat-delay": 10000,
                "max-response-delay": 60000,
                "max-ack-delay": 5000,
                "max-unacked-clients": 5,
                "peers": peers,
            }]},
        }));
    }
    let conf = json!({
        "Dhcp4": {
            "interfaces-config": {
                "interfaces": interfaces,
                "dhcp-socket-type": "raw",
                "service-sockets-require-all": false,
                "service-sockets-max-retries": 60,
                "service-sockets-retry-wait-time": 5000,
            },
            "control-sockets": [{"socket-type": "unix", "socket-name": "kea4-ctrl-socket"}],
            "lease-database": {
                "type": "memfile",
                "persist": true,
                "name": "/var/lib/kea/kea-leases4.csv",
                "lfc-interval": 3600,
            },
            "valid-lifetime": dhcp.lease_time.unwrap_or(DEFAULT_LEASE_TIME),
            "authoritative": true,
            "subnet4": subnets,
            "hooks-libraries": hooks,
            "loggers": [{
                "name": "kea-dhcp4",
                "output-options": [{"output": "stdout", "pattern": "%-5p %m\n"}],
                "severity": "INFO",
            }],
        }
    });
    let mut text = serde_json::to_string_pretty(&conf).expect("json");
    text.push('\n');
    out.add(Subsystem::Dhcp, CONF, text);
    // Kea's config test insists every listed interface exists; check the
    // same configuration listening on all of them.
    let mut check_conf = conf.clone();
    check_conf["Dhcp4"]["interfaces-config"]["interfaces"] = json!(["*"]);
    let mut check_text = serde_json::to_string_pretty(&check_conf).expect("json");
    check_text.push('\n');
    out.meta.services.insert(
        "dhcp".into(),
        Service {
            provider: "kea".into(),
            unit: UNIT.into(),
            subsystem: Subsystem::Dhcp,
            reload: true,
            check: Some(CheckSpec {
                container: Some(CONTAINER.into()),
                mount: "/etc/kea".into(),
                command: vec!["kea-dhcp4".into(), "-t".into(), format!("/etc/kea/{CONF}")],
                overrides: [(CONF.to_string(), check_text)].into(),
            }),
        },
    );
    Ok(())
}
