//! Unbound, the default recursive resolver (design: "Defaults in detail").
//!
//! Bound to the gateway addresses of the networks it serves (`ip-freebind`
//! lets a pair's standby bind addresses it does not hold yet); local
//! records come from DHCP reservations and `dns.records`.

use std::collections::BTreeSet;
use std::fmt::Write;

use sparewall_config::model::Document;

use crate::kea::gateway_addr;
use crate::{CheckSpec, Error, Rendered, Service, Subsystem};

pub const UNIT: &str = "sparewall-unbound.service";
pub const CONTAINER: &str = "sparewall-unbound";
pub const CONF: &str = "unbound.conf";

/// Networks the resolver serves: `dns.networks`, or every DHCP network.
pub fn served_networks(doc: &Document) -> Vec<String> {
    let Some(d) = doc.dns.as_ref().filter(|d| d.enabled) else {
        return vec![];
    };
    if d.networks.is_empty() {
        doc.dhcp
            .iter()
            .flat_map(|x| x.networks.keys().cloned())
            .collect()
    } else {
        d.networks.clone()
    }
}

pub(crate) fn render(doc: &Document, node: &str, out: &mut Rendered) -> Result<(), Error> {
    let Some(dns) = doc.dns.as_ref().filter(|d| d.enabled) else {
        return Ok(());
    };
    if dns.provider.as_deref().unwrap_or("unbound") != "unbound" {
        return Ok(());
    }
    let mut s = String::from(crate::HEADER);
    s.push_str("server:\n");
    let mut listen: BTreeSet<String> = BTreeSet::new();
    let mut allow: BTreeSet<String> = BTreeSet::new();
    for n in served_networks(doc) {
        if let Some(a) = gateway_addr(doc, &n, node) {
            listen.insert(a.to_string());
        }
        if let Some(sub) = doc.subnet(&n, node) {
            allow.insert(sub.to_string());
        }
    }
    for vpn in doc.vpn.values() {
        for a in &vpn.addresses {
            if vpn.dns.contains(&a.0.addr()) {
                listen.insert(a.0.addr().to_string());
                allow.insert(a.0.trunc().to_string());
            }
        }
    }
    listen.insert("127.0.0.1".into());
    for l in &listen {
        writeln!(s, "    interface: {l}").unwrap();
    }
    s.push_str(
        "    ip-freebind: yes\n    do-ip6: no\n    port: 53\n\
         \x20   access-control: 0.0.0.0/0 refuse\n    access-control: 127.0.0.0/8 allow\n",
    );
    for a in &allow {
        writeln!(s, "    access-control: {a} allow").unwrap();
    }
    s.push_str(
        "    username: \"unbound\"\n    directory: \"/etc/unbound\"\n    chroot: \"\"\n\
         \x20   pidfile: \"\"\n    use-syslog: no\n    logfile: \"\"\n    log-time-ascii: yes\n\
         \x20   verbosity: 1\n    hide-identity: yes\n    hide-version: yes\n\
         \x20   qname-minimisation: yes\n    harden-glue: yes\n    harden-dnssec-stripped: yes\n\
         \x20   use-caps-for-id: no\n    prefetch: yes\n    so-reuseport: yes\n\
         \x20   auto-trust-anchor-file: \"/var/lib/unbound/root.key\"\n",
    );
    if let Some(domain) = &dns.domain {
        let d = domain.trim_end_matches('.');
        writeln!(s, "    private-domain: \"{d}\"").unwrap();
        writeln!(s, "    local-zone: \"{d}.\" static").unwrap();
        let mut records: Vec<(String, String)> = Vec::new();
        for dn in doc.dhcp.iter().flat_map(|x| x.networks.values()) {
            for (rname, r) in &dn.reservations {
                let host = r.hostname.clone().unwrap_or_else(|| rname.clone());
                records.push((host, r.address.to_string()));
            }
        }
        for (name, addr) in &dns.records {
            records.push((name.trim_end_matches('.').to_string(), addr.to_string()));
        }
        records.sort();
        records.dedup();
        for (host, addr) in records {
            let fqdn = if host.contains('.') {
                host
            } else {
                format!("{host}.{d}")
            };
            writeln!(s, "    local-data: \"{fqdn}. IN A {addr}\"").unwrap();
            writeln!(s, "    local-data-ptr: \"{addr} {fqdn}.\"").unwrap();
        }
    } else {
        for (name, addr) in &dns.records {
            let n = name.trim_end_matches('.');
            writeln!(s, "    local-data: \"{n}. IN A {addr}\"").unwrap();
        }
    }
    s.push_str(
        "\nremote-control:\n    control-enable: yes\n    control-interface: /run/unbound/control.sock\n",
    );
    if !dns.forwarders.is_empty() {
        s.push_str("\nforward-zone:\n    name: \".\"\n");
        for f in &dns.forwarders {
            writeln!(s, "    forward-addr: {f}").unwrap();
        }
    }
    out.add(Subsystem::Dns, CONF, s);
    out.meta.services.insert(
        "dns".into(),
        Service {
            provider: "unbound".into(),
            unit: UNIT.into(),
            subsystem: Subsystem::Dns,
            reload: true,
            check: Some(CheckSpec {
                container: Some(CONTAINER.into()),
                mount: "/etc/unbound".into(),
                command: vec!["unbound-checkconf".into(), format!("/etc/unbound/{CONF}")],
                overrides: Default::default(),
            }),
        },
    );
    Ok(())
}
