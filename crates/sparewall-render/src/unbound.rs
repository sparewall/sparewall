//! Unbound, the default recursive resolver (design: "Defaults in detail").
//!
//! Bound to the gateway addresses of the networks it serves (`ip-freebind`
//! lets a pair's standby bind addresses it does not hold yet); local
//! records come from DHCP reservations and `dns.records`.

use std::collections::BTreeSet;
use std::fmt::Write;

use sha2::{Digest, Sha256};

use sparewall_config::model::{Document, Ipv6Mode};
use sparewall_config::passthrough;
use sparewall_config::providers::{self, Role};

use crate::kea::gateway_addr;
use crate::{CheckSpec, Error, Rendered, Service, Subsystem};

pub const UNIT: &str = "sparewall-unbound.service";
pub const CONTAINER: &str = "sparewall-unbound";
pub const CONF: &str = "unbound.conf";
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `dns.tls_ca`, beside the configuration (#356).
pub const TLS_CA: &str = "tls-ca.pem";

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

/// Whether Unbound answers over IPv6: a served network has IPv6 (#214;
/// in a pair, #215, at the gateway address `fe80::1`). It then listens
/// on every address, and a delegated prefix cannot be named in its access
/// control, so the firewall keeps every other interface from its port
/// (nft `service:dns-served-only`).
pub fn serves_ipv6(doc: &Document) -> bool {
    doc.dns.as_ref().is_some_and(|d| d.enabled)
        && providers::chosen(doc, Role::Dns) == Some("unbound")
        && served_networks(doc)
            .iter()
            .any(|n| doc.networks.get(n).is_some_and(|x| x.ipv6.is_some()))
}

pub(crate) fn render(doc: &Document, node: &str, out: &mut Rendered) -> Result<(), Error> {
    let Some(dns) = doc.dns.as_ref().filter(|d| d.enabled) else {
        return Ok(());
    };
    if providers::chosen(doc, Role::Dns) != Some("unbound") {
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
    // IPv6 where a served network has it (#214): on every address, since
    // a delegated network's change with the prefix, and the
    // advertisements name the node by its link-local address there. The
    // firewall drops IPv6 DNS from every other interface, whatever the
    // policies say (`service:dns-served-only`).
    let v6: Vec<&sparewall_config::model::NetworkIpv6> = served_networks(doc)
        .iter()
        .filter_map(|n| doc.networks.get(n)?.ipv6.as_ref())
        .collect();
    if !v6.is_empty() {
        listen.insert("::0".into());
    }
    for l in &listen {
        writeln!(s, "    interface: {l}").unwrap();
    }
    writeln!(
        s,
        "    ip-freebind: yes\n    do-ip6: {}\n    port: 53\n\
         \x20   access-control: 0.0.0.0/0 refuse\n    access-control: 127.0.0.0/8 allow",
        if v6.is_empty() { "no" } else { "yes" }
    )
    .unwrap();
    for a in &allow {
        writeln!(s, "    access-control: {a} allow").unwrap();
    }
    // Each filtered network's queries are answered by its view (#74), by
    // their source: its IPv4 subnet, and a static IPv6 prefix. A
    // delegated prefix can't be named, so IPv6 queries there are not
    // filtered.
    let views = sparewall_config::filters::views(doc);
    for v in &views {
        for n in &v.networks {
            if let Some(sub) = doc.subnet(n, node) {
                writeln!(s, "    access-control-view: {sub} {}", v.name).unwrap();
            }
            if let Some(p) = doc
                .networks
                .get(n)
                .and_then(|x| x.ipv6.as_ref())
                .filter(|x| x.mode == Ipv6Mode::Static)
                .and_then(|x| x.prefix)
            {
                writeln!(s, "    access-control-view: {} {}", p.0.trunc(), v.name).unwrap();
            }
        }
    }
    if !v6.is_empty() {
        let statics: BTreeSet<String> = v6
            .iter()
            .filter_map(|n| match (n.mode, n.prefix) {
                (Ipv6Mode::Static, Some(p)) => Some(p.0.trunc().to_string()),
                _ => None,
            })
            .collect();
        if statics.len() < v6.len() {
            // A delegated prefix is whatever the ISP delegates.
            s.push_str("    access-control: ::0/0 allow\n");
        } else {
            s.push_str("    access-control: ::0/0 refuse\n    access-control: ::1 allow\n    access-control: fe80::/10 allow\n");
            for p in statics {
                writeln!(s, "    access-control: {p} allow").unwrap();
            }
        }
    }
    s.push_str(
        "    username: \"unbound\"\n    directory: \"/etc/unbound\"\n    chroot: \"\"\n\
         \x20   pidfile: \"\"\n    use-syslog: no\n    logfile: \"\"\n    log-time-ascii: yes\n\
         \x20   verbosity: 1\n    hide-identity: yes\n    hide-version: yes\n\
         \x20   qname-minimisation: yes\n    harden-glue: yes\n    harden-dnssec-stripped: yes\n\
         \x20   use-caps-for-id: no\n    prefetch: yes\n    so-reuseport: yes\n\
         \x20   auto-trust-anchor-file: \"/var/lib/unbound/root.key\"\n",
    );
    // Forwarders over TLS (#356): each certificate verified against the
    // forwarder's name, by the system trust store and `dns.tls_ca`.
    let tls = !dns.tls_forwarders.is_empty();
    if tls {
        s.push_str("    tls-system-cert: yes\n");
        if let Some(ca) = &dns.tls_ca {
            writeln!(s, "    tls-cert-bundle: \"/etc/unbound/{TLS_CA}\"").unwrap();
            let mut pem = ca.trim_end().to_string();
            pem.push('\n');
            out.add(Subsystem::Dns, TLS_CA, pem);
        }
    }
    // Passthrough options (#143), after Sparewall's own: Unbound takes
    // the last value of a single-valued option, so these can change the
    // defaults above (`prefetch`, say). Validation has refused what
    // Sparewall must set, and unbound-checkconf checks the rest.
    let passthrough = passthrough::unbound(doc);
    if let Some(o) = passthrough {
        s.push_str(&passthrough::unbound_server(o));
    }
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
    } else if tls {
        // No fallback to plain DNS: with every forwarder unreachable over
        // TLS, names don't resolve, and health says so (`dns-tls`).
        s.push_str("\nforward-zone:\n    name: \".\"\n    forward-tls-upstream: yes\n");
        for f in dns.tls_forwarders.values() {
            for a in &f.addresses {
                writeln!(s, "    forward-addr: {a}@{}#{}", f.port(), f.name).unwrap();
            }
        }
    }
    if let Some(o) = passthrough {
        s.push_str(&passthrough::unbound_zones(o));
    }
    // The views' blocked names are fetched by sparewalld into a dotfile
    // each (an apply leaves dotfiles alone); a glob that matches nothing
    // until then, so the resolver starts without them. Names the view
    // allows are resolved as usual, though a list blocks a parent; a
    // name that's in no zone of the view's falls to the global ones
    // (`view-first`), so local names still resolve.
    for v in &views {
        writeln!(s, "\nview:\n    name: \"{}\"\n    view-first: yes", v.name).unwrap();
        let mut allow: BTreeSet<String> = BTreeSet::new();
        for f in &v.filters {
            if let Some(x) = dns.filters.get(f) {
                allow.extend(
                    x.allow
                        .iter()
                        .map(|a| sparewall_config::filters::normalize(a)),
                );
            }
        }
        for a in allow {
            writeln!(s, "    local-zone: \"{a}.\" transparent").unwrap();
        }
        let file = sparewall_config::filters::view_file(&v.name);
        let (stem, last) = file.split_at(file.len() - 1);
        writeln!(s, "    include: \"/etc/unbound/{stem}[{last}]\"").unwrap();
    }
    out.add(Subsystem::Dns, CONF, s);
    out.meta.services.insert(
        "dns".into(),
        Service {
            provider: "unbound".into(),
            unit: UNIT.into(),
            subsystem: Subsystem::Dns,
            reload: true,
            restart_key: tls.then(|| {
                let mut h = Sha256::new();
                h.update(dns.tls_ca.as_deref().unwrap_or_default());
                format!("tls:{}", hex(&h.finalize()))
            }),
            management: false,
            check: Some(check_spec()),
        },
    );
    Ok(())
}

/// Unbound's config test, in its container, with the files at
/// `/etc/unbound`. `sparewall-run@` accepts this check and no other for
/// Unbound (#279).
pub fn check_spec() -> CheckSpec {
    CheckSpec {
        container: Some(CONTAINER.into()),
        mount: "/etc/unbound".into(),
        command: vec!["unbound-checkconf".into(), format!("/etc/unbound/{CONF}")],
        overrides: Default::default(),
    }
}
