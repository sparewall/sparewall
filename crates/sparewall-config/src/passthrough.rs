//! Provider passthrough (`provider_options`, #143): settings passed
//! straight into a provider's own configuration, for what the neutral
//! schema doesn't cover (design: "Rules that keep providers swappable").
//!
//! Two providers take them:
//!
//! - **Kea:** keys merged into the rendered `Dhcp4` object, and under
//!   `networks.<network>`, keys merged into that network's `subnet4`
//!   entry (`option-data` there is added to Sparewall's own).
//! - **Unbound:** `server` options added to its `server:` clause, and
//!   `forward-zone` and `stub-zone` clauses of its own.
//!
//! Keys Sparewall sets itself are refused, as overriding them would break
//! HA, leases, the control socket, or the firewall's view of what the
//! daemon listens on. The rest is the daemon's to check: the merged file
//! goes through the provider's config test (`kea-dhcp4 -t`,
//! `unbound-checkconf`) in every dry run and apply. Options for a
//! provider the document doesn't use are ignored with a warning, so
//! switching providers keeps them for switching back.

use serde_json::{Map, Value};

use crate::model::Document;
use crate::pointer::name as seg;
use crate::providers::{self, Role};

pub const KEA: &str = "kea";
pub const UNBOUND: &str = "unbound";

/// Kea's key for options added to one network's subnet.
pub const KEA_NETWORKS: &str = "networks";

/// The providers that take passthrough options.
pub const PROVIDERS: &[&str] = &[KEA, UNBOUND];

/// `Dhcp4` keys Sparewall sets, with what to do instead.
pub const KEA_OWNED: &[(&str, &str)] = &[
    (
        "interfaces-config",
        "Sparewall binds Kea to the DHCP networks' interfaces",
    ),
    (
        "control-socket",
        "Sparewall manages Kea over its control socket",
    ),
    (
        "control-sockets",
        "Sparewall manages Kea over its control socket",
    ),
    ("lease-database", "Sparewall keeps Kea's leases"),
    (
        "hosts-database",
        "reservations come from dhcp.<network>.reservations",
    ),
    (
        "hosts-databases",
        "reservations come from dhcp.<network>.reservations",
    ),
    ("config-control", "Sparewall writes Kea's configuration"),
    (
        "hooks-libraries",
        "Sparewall loads Kea's hooks (HA, lease commands, ping check)",
    ),
    ("loggers", "Sparewall sends Kea's log to the journal"),
    (
        "subnet4",
        "subnets come from dhcp.<network>; add to one under networks.<network>",
    ),
    (
        "shared-networks",
        "subnets come from dhcp.<network>; add to one under networks.<network>",
    ),
    ("valid-lifetime", "set dhcp.lease_time"),
    (
        "authoritative",
        "Sparewall sets it (off while cluster.hold is on)",
    ),
];

/// Subnet keys Sparewall sets, with what to do instead.
pub const KEA_SUBNET_OWNED: &[(&str, &str)] = &[
    ("id", "Sparewall numbers the subnets"),
    ("subnet", "the subnet is the network's"),
    ("pools", "set dhcp.<network>.pool"),
    ("reservations", "set dhcp.<network>.reservations"),
    ("valid-lifetime", "set dhcp.<network>.lease_time"),
    ("user-context", "Sparewall uses it for the ping check"),
    (
        "interface",
        "Kea picks the subnet by the receiving interface",
    ),
];

/// DHCP options Sparewall sets on a network's subnet, by name and code,
/// with the setting that sets them: Kea's config test takes a second
/// one there, and which a client then gets isn't clear.
pub const KEA_SUBNET_OPTIONS: &[(&str, u64, &str)] = &[
    ("routers", 3, "dhcp.<network>.options.router"),
    ("domain-name-servers", 6, "dhcp.<network>.options.dns"),
    ("domain-name", 15, "dhcp.<network>.options.domain"),
    ("ntp-servers", 42, "dhcp.<network>.options.ntp"),
];

/// Unbound clauses that may be given.
pub const UNBOUND_CLAUSES: &[&str] = &["server", "forward-zone", "stub-zone"];

/// `server:` options Sparewall sets while `dns.tls_forwarders` is in use
/// (#356): which certificates the forwarders' are verified against.
pub const UNBOUND_TLS_OWNED: &[(&str, &str)] = &[
    ("tls-cert-bundle", "set dns.tls_ca"),
    (
        "tls-system-cert",
        "Sparewall trusts the system store for dns.tls_forwarders",
    ),
    (
        "tls-win-cert",
        "Sparewall trusts the system store for dns.tls_forwarders",
    ),
];

/// `server:` options Sparewall sets, with what to do instead. One ending
/// in `*` is a family: `interface*` takes `interface-action` and the
/// rest, any of which could open the resolver to another interface.
pub const UNBOUND_OWNED: &[(&str, &str)] = &[
    (
        "interface*",
        "Unbound listens on the served networks' gateways",
    ),
    // Unbound's alias for `interface` (util/configlexer.lex, 1.26).
    (
        "ip-address",
        "Unbound listens on the served networks' gateways",
    ),
    ("port", "Unbound listens on port 53"),
    (
        "ip-freebind",
        "Sparewall sets it for the pair's gateway addresses",
    ),
    ("do-ip4", "Sparewall sets it from the served networks"),
    ("do-ip6", "Sparewall sets it from the served networks"),
    (
        "access-control*",
        "dns.networks and dns.filters decide who it answers, and how",
    ),
    ("username", "the container runs Unbound as its own user"),
    ("directory", "the container's layout is fixed"),
    ("chroot", "the container's layout is fixed"),
    ("pidfile", "the container's layout is fixed"),
    ("logfile", "Sparewall sends Unbound's log to the journal"),
    ("use-syslog", "Sparewall sends Unbound's log to the journal"),
    (
        "auto-trust-anchor-file",
        "Sparewall keeps the root trust anchor",
    ),
    ("module-config", "Sparewall sets Unbound's modules"),
];

/// Unbound options that read other files, refused anywhere: the options
/// go here instead.
pub const UNBOUND_INCLUDES: &[&str] = &["include", "include-toplevel"];

/// A problem with a passthrough entry, at its path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub path: String,
    pub message: String,
    /// Only a warning: the options are ignored, not wrong.
    pub warning: bool,
}

/// Whether the document uses Kea for DHCP on some network.
pub fn kea_used(doc: &Document) -> bool {
    doc.dhcp.as_ref().is_some_and(|d| !d.networks.is_empty())
        && providers::chosen(doc, Role::Dhcp) == Some(KEA)
}

/// Whether the document runs Unbound.
pub fn unbound_used(doc: &Document) -> bool {
    doc.dns.as_ref().is_some_and(|d| d.enabled)
        && providers::chosen(doc, Role::Dns) == Some(UNBOUND)
}

/// Kea's options, where Kea runs.
pub fn kea(doc: &Document) -> Option<&Map<String, Value>> {
    doc.provider_options
        .get(KEA)
        .and_then(Value::as_object)
        .filter(|_| kea_used(doc))
}

/// Unbound's options, where Unbound runs.
pub fn unbound(doc: &Document) -> Option<&Map<String, Value>> {
    doc.provider_options
        .get(UNBOUND)
        .and_then(Value::as_object)
        .filter(|_| unbound_used(doc))
}

/// Merge Kea's options into the rendered `Dhcp4` object, and each
/// network's into its subnet (`subnets`: each network's entry, by name).
/// Validation has refused the keys Sparewall sets.
pub fn kea_merge(
    opts: &Map<String, Value>,
    dhcp4: &mut Map<String, Value>,
    subnets: &mut [(&str, Value)],
) {
    for (k, v) in opts {
        if k == KEA_NETWORKS {
            for (net, o) in v.as_object().into_iter().flatten() {
                let s = subnets.iter_mut().find(|(n, _)| n == net).map(|(_, s)| s);
                let (Some(s), Some(o)) = (s, o.as_object()) else {
                    continue;
                };
                for (k, v) in o {
                    match (k.as_str(), s.get_mut(k), v) {
                        ("option-data", Some(Value::Array(ours)), Value::Array(more)) => {
                            ours.extend(more.iter().cloned());
                        }
                        _ => s[k] = v.clone(),
                    }
                }
            }
        } else {
            dhcp4.insert(k.clone(), v.clone());
        }
    }
}

/// An Unbound value as it's written: a boolean as yes or no, a string as
/// given (quote it in the string where Unbound wants quotes).
fn unbound_value(v: &Value) -> Option<String> {
    match v {
        Value::Bool(b) => Some(if *b { "yes" } else { "no" }.into()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// An Unbound clause's options as lines, indented: a list gives the
/// option once per item.
fn unbound_lines(opts: &Map<String, Value>, out: &mut String) {
    for (k, v) in opts {
        let items: Vec<&Value> = match v {
            Value::Array(a) => a.iter().collect(),
            v => vec![v],
        };
        for i in items {
            if let Some(s) = unbound_value(i) {
                out.push_str(&format!("    {k}: {s}\n"));
            }
        }
    }
}

/// Unbound's `server:` options, as lines for its `server:` clause.
pub fn unbound_server(opts: &Map<String, Value>) -> String {
    let mut s = String::new();
    if let Some(o) = opts.get("server").and_then(Value::as_object) {
        unbound_lines(o, &mut s);
    }
    s
}

/// Unbound's `forward-zone` and `stub-zone` clauses, each starting with
/// a blank line.
pub fn unbound_zones(opts: &Map<String, Value>) -> String {
    let mut s = String::new();
    for clause in ["forward-zone", "stub-zone"] {
        for z in opts
            .get(clause)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(z) = z.as_object() else { continue };
            s.push_str(&format!("\n{clause}:\n"));
            // The name first, as Unbound's own examples have it.
            if let Some(n) = z.get("name").and_then(unbound_value) {
                s.push_str(&format!("    name: {n}\n"));
            }
            let mut rest = z.clone();
            rest.remove("name");
            unbound_lines(&rest, &mut s);
        }
    }
    s
}

/// The problems with the document's passthrough options.
pub fn check(doc: &Document) -> Vec<Problem> {
    let mut c = Checker::default();
    for (name, v) in &doc.provider_options {
        let at = format!("provider_options.{}", seg(name));
        if !PROVIDERS.contains(&name.as_str()) {
            let known = providers::PROVIDERS.iter().any(|p| p.name == name);
            c.err(
                &at,
                if known {
                    format!(
                        "the {name} provider takes no passthrough options; {} do",
                        PROVIDERS.join(" and ")
                    )
                } else {
                    format!(
                        "no provider is named {name}; {} take passthrough options",
                        PROVIDERS.join(" and ")
                    )
                },
            );
            continue;
        }
        let Some(o) = v.as_object() else {
            c.err(&at, "must be an object of the provider's own settings");
            continue;
        };
        match name.as_str() {
            KEA => {
                c.kea(doc, &at, o);
                if !o.is_empty() && !kea_used(doc) {
                    c.warn(&at, "ignored: no network's DHCP is served by Kea");
                }
            }
            _ => {
                c.unbound(doc, &at, o);
                if !o.is_empty() && !unbound_used(doc) {
                    c.warn(&at, "ignored: the resolver is off or is not Unbound");
                }
            }
        }
    }
    c.0
}

#[derive(Default)]
struct Checker(Vec<Problem>);

impl Checker {
    fn err(&mut self, path: &str, message: impl Into<String>) {
        self.0.push(Problem {
            path: path.into(),
            message: message.into(),
            warning: false,
        });
    }

    fn warn(&mut self, path: &str, message: impl Into<String>) {
        self.0.push(Problem {
            path: path.into(),
            message: message.into(),
            warning: true,
        });
    }

    fn owned(&mut self, path: &str, key: &str, owned: &[(&str, &str)]) -> bool {
        let matches = |k: &str| match k.strip_suffix('*') {
            Some(family) => key.starts_with(family),
            None => k == key,
        };
        match owned.iter().find(|(k, _)| matches(k)) {
            Some((_, instead)) => {
                self.err(path, format!("Sparewall sets {key} itself: {instead}"));
                true
            }
            None => false,
        }
    }

    fn kea(&mut self, doc: &Document, at: &str, o: &Map<String, Value>) {
        for (k, v) in o {
            let path = format!("{at}.{}", seg(k));
            if k == "Dhcp4" {
                self.err(
                    &path,
                    "give Dhcp4's keys directly, without Dhcp4 around them",
                );
                continue;
            }
            // Kea would send each lease's name and address to a DHCP-DDNS
            // server: that egress is a feature of its own, not built.
            if k == "dhcp-ddns" {
                self.err(
                    &path,
                    "DHCP-to-DNS updates aren't built: this would send leases' names and \
                     addresses to another server",
                );
                continue;
            }
            if self.owned(&path, k, KEA_OWNED) || k != KEA_NETWORKS {
                continue;
            }
            let Some(nets) = v.as_object() else {
                self.err(&path, "must be an object of options by DHCP network name");
                continue;
            };
            let dhcp = doc.dhcp.as_ref();
            for (net, x) in nets {
                let p = format!("{path}.{}", seg(net));
                // Ignored where Kea isn't used, so kept for switching back.
                if kea_used(doc) && !dhcp.is_some_and(|d| d.networks.contains_key(net)) {
                    self.err(&p, format!("{net} is not a network under dhcp"));
                    continue;
                }
                let Some(x) = x.as_object() else {
                    self.err(&p, "must be an object of Kea subnet options");
                    continue;
                };
                for (k, v) in x {
                    let p = format!("{p}.{}", seg(k));
                    if self.owned(&p, k, KEA_SUBNET_OWNED) || k != "option-data" {
                        continue;
                    }
                    let Some(list) = v.as_array() else {
                        self.err(&p, "must be a list, as in Kea");
                        continue;
                    };
                    for (i, o) in list.iter().enumerate() {
                        let set = KEA_SUBNET_OPTIONS.iter().find(|(name, code, _)| {
                            o.get("name").and_then(Value::as_str) == Some(*name)
                                || o.get("code").and_then(Value::as_u64) == Some(*code)
                        });
                        if let Some((name, _, instead)) = set {
                            self.err(
                                &format!("{p}[{i}]"),
                                format!("Sparewall sets {name} on the network: set {instead}"),
                            );
                        }
                    }
                }
            }
        }
    }

    fn unbound(&mut self, doc: &Document, at: &str, o: &Map<String, Value>) {
        for (clause, v) in o {
            let path = format!("{at}.{}", seg(clause));
            match clause.as_str() {
                "server" => match v.as_object() {
                    Some(opts) => {
                        let tls = doc
                            .dns
                            .as_ref()
                            .is_some_and(|d| !d.tls_forwarders.is_empty());
                        let owned: Vec<(&str, &str)> = UNBOUND_OWNED
                            .iter()
                            .copied()
                            .chain(UNBOUND_TLS_OWNED.iter().copied().filter(|_| tls))
                            .collect();
                        self.unbound_opts(&path, opts, &owned)
                    }
                    None => self.err(&path, "must be an object of server: options"),
                },
                "forward-zone" | "stub-zone" => {
                    let Some(zones) = v.as_array() else {
                        self.err(&path, format!("must be a list of {clause} clauses"));
                        continue;
                    };
                    let mut names = Vec::new();
                    for (i, z) in zones.iter().enumerate() {
                        let p = format!("{path}[{i}]");
                        let Some(z) = z.as_object() else {
                            self.err(&p, "must be an object of the clause's options");
                            continue;
                        };
                        let name = z.get("name").and_then(Value::as_str);
                        let Some(name) = name.filter(|n| !n.trim_matches('"').is_empty()) else {
                            self.err(&p, "needs a name, the zone it applies to");
                            continue;
                        };
                        let bare = name
                            .trim_matches('"')
                            .trim_end_matches('.')
                            .to_ascii_lowercase();
                        if names.contains(&bare) {
                            self.err(&format!("{p}.name"), format!("{name} is named twice"));
                        }
                        let root = bare.is_empty();
                        if clause == "forward-zone" && root {
                            let by = doc.dns.as_ref().and_then(|d| {
                                if !d.forwarders.is_empty() {
                                    Some("dns.forwarders")
                                } else if !d.tls_forwarders.is_empty() {
                                    Some("dns.tls_forwarders")
                                } else {
                                    None
                                }
                            });
                            if let Some(by) = by {
                                self.err(
                                    &format!("{p}.name"),
                                    format!("{by} already forwards the root; give it there or here, not both"),
                                );
                            }
                        }
                        names.push(bare);
                        self.unbound_opts(&p, z, &[]);
                    }
                }
                _ => self.err(
                    &path,
                    format!(
                        "not an Unbound clause Sparewall passes through; use {}",
                        UNBOUND_CLAUSES.join(", ")
                    ),
                ),
            }
        }
    }

    fn unbound_opts(&mut self, at: &str, opts: &Map<String, Value>, owned: &[(&str, &str)]) {
        for (k, v) in opts {
            let path = format!("{at}.{}", seg(k));
            let well_formed = k
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && k.starts_with(|c: char| c.is_ascii_lowercase());
            if !well_formed {
                self.err(
                    &path,
                    "not an Unbound option name (lowercase, digits and -)",
                );
                continue;
            }
            if UNBOUND_INCLUDES.contains(&k.as_str()) {
                self.err(&path, "give the options here rather than a file of them");
                continue;
            }
            if self.owned(&path, k, owned) {
                continue;
            }
            let items: Vec<&Value> = match v {
                Value::Array(a) if !a.is_empty() => a.iter().collect(),
                Value::Array(_) => {
                    self.err(&path, "an empty list gives no value");
                    continue;
                }
                v => vec![v],
            };
            for i in items {
                match i {
                    Value::String(s) if s.trim().is_empty() => {
                        self.err(&path, "an empty value");
                    }
                    Value::String(s) if s.chars().any(char::is_control) => {
                        self.err(&path, "a value can't hold a line break or other control character");
                    }
                    Value::String(_) | Value::Bool(_) | Value::Number(_) => {}
                    _ => self.err(
                        &path,
                        "must be a string, number or yes/no, or a list of them for an option given more than once",
                    ),
                }
            }
        }
    }
}
