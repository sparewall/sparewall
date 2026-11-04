//! A link's IPv6 state as networkd describes it (#216): its global
//! addresses, the prefixes DHCPv6 delegated to it, and whether it has an
//! IPv6 default route. Read from `networkctl --json=short status`, which
//! prints networkd's `Describe` (`{"Interfaces": [...]}`).

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sparewall_config::Document;
use sparewall_config::model::{Ipv6Mode, NetworkRole};

use crate::health::{Check, Level};

const AF_INET6: i64 = 10;
const SCOPE_UNIVERSE: u64 = 0;
const RTN_UNICAST: u64 = 1;
const RT_TABLE_MAIN: u64 = 254;

/// One link's IPv6 state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkIpv6 {
    /// Global addresses (not link-local).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<Lifetimed>,
    /// Prefixes delegated to this link by DHCPv6 (IA_PD).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegated: Vec<Lifetimed>,
    /// The gateway of its IPv6 default route, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_gateway: Option<Ipv6Addr>,
}

/// An address or prefix (`2001:db8::1/64`), with the seconds left of its
/// lifetimes; `None` is forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lifetimed {
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_seconds: Option<u64>,
}

/// An IPv6 address from networkd's JSON: an array of 16 bytes.
fn addr6(v: &Value) -> Option<Ipv6Addr> {
    let bytes: Vec<u8> = v
        .as_array()?
        .iter()
        .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
        .collect::<Option<_>>()?;
    let octets: [u8; 16] = bytes.try_into().ok()?;
    Some(Ipv6Addr::from(octets))
}

/// Seconds left until a `CLOCK_BOOTTIME` timestamp in µs (networkd omits
/// an infinite one).
fn left(v: &Value, now_usec: u64) -> Option<u64> {
    v.as_u64().map(|t| t.saturating_sub(now_usec) / 1_000_000)
}

fn lifetimed(addr: Ipv6Addr, len: u64, o: &Value, now_usec: u64) -> Lifetimed {
    Lifetimed {
        address: format!("{addr}/{len}"),
        preferred_seconds: left(&o["PreferredLifetimeUSec"], now_usec),
        valid_seconds: left(&o["ValidLifetimeUSec"], now_usec),
    }
}

/// A link's IPv6 default route's gateway. networkd's routes from router
/// advertisements go through a nexthop object (`nhid`): the gateway is the
/// nexthop's, and with no interface of its own the route may be listed
/// only with the manager's routes, so look there too, by the nexthops this
/// link holds.
fn default_gateway(describe: &Value, link: &Value) -> Option<Ipv6Addr> {
    let nexthops: BTreeMap<u64, Option<Ipv6Addr>> = link["NextHops"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| Some((n["ID"].as_u64()?, addr6(&n["Gateway"]))))
        .collect();
    let is_default = |r: &&Value| {
        r["Family"].as_i64() == Some(AF_INET6)
            && r["DestinationPrefixLength"].as_u64() == Some(0)
            && r["Type"].as_u64().unwrap_or(RTN_UNICAST) == RTN_UNICAST
            && r["Table"].as_u64().unwrap_or(RT_TABLE_MAIN) == RT_TABLE_MAIN
    };
    let via = |r: &Value| -> Option<Ipv6Addr> {
        addr6(&r["Gateway"]).or_else(|| nexthops.get(&r["NextHopID"].as_u64()?).copied()?)
    };
    let own = link["Routes"].as_array().into_iter().flatten();
    let shared = describe["Routes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| {
            r["NextHopID"]
                .as_u64()
                .is_some_and(|id| nexthops.contains_key(&id))
        });
    own.chain(shared).filter(is_default).find_map(via)
}

/// Each link's IPv6 state, by name, from networkd's description, `now_usec`
/// being `CLOCK_BOOTTIME` in µs. Links with no IPv6 state are left out.
pub fn from_describe(describe: &Value, now_usec: u64) -> BTreeMap<String, LinkIpv6> {
    let mut out = BTreeMap::new();
    for link in describe["Interfaces"].as_array().into_iter().flatten() {
        let Some(name) = link["Name"].as_str() else {
            continue;
        };
        let mut s = LinkIpv6::default();
        for a in link["Addresses"].as_array().into_iter().flatten() {
            if a["Family"].as_i64() != Some(AF_INET6)
                || a["Scope"].as_u64().unwrap_or(SCOPE_UNIVERSE) != SCOPE_UNIVERSE
            {
                continue;
            }
            let (Some(addr), Some(len)) = (addr6(&a["Address"]), a["PrefixLength"].as_u64()) else {
                continue;
            };
            s.addresses.push(lifetimed(addr, len, a, now_usec));
        }
        for p in link["DHCPv6Client"]["Prefixes"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let (Some(addr), Some(len)) = (addr6(&p["Prefix"]), p["PrefixLength"].as_u64()) else {
                continue;
            };
            s.delegated.push(lifetimed(addr, len, p, now_usec));
        }
        s.default_gateway = default_gateway(describe, link);
        if s != LinkIpv6::default() {
            out.insert(name.to_string(), s);
        }
    }
    out
}

/// The prefix an inside network advertises, from the node's address in
/// it (`2001:db8:100:1::1/64` advertises `2001:db8:100:1::/64`).
fn prefix_of(address: &str) -> Option<String> {
    let (a, len) = address.split_once('/')?;
    let (a, len) = (a.parse::<Ipv6Addr>().ok()?, len.parse::<u32>().ok()?);
    let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
    Some(format!("{}/{len}", Ipv6Addr::from(u128::from(a) & mask)))
}

/// Each network with `ipv6`, by name: its interface and that interface's
/// state; an inside network also its advertised prefixes. `None` when no
/// network has IPv6.
pub fn status(doc: &Document, links: &BTreeMap<String, LinkIpv6>) -> Option<Value> {
    let mut out = serde_json::Map::new();
    for (name, net) in &doc.networks {
        let Some(v6) = &net.ipv6 else { continue };
        let Some(iface) = doc.network_iface(name) else {
            continue;
        };
        let st = links.get(iface).cloned().unwrap_or_default();
        let mut v = serde_json::to_value(&st).unwrap_or_else(|_| json!({}));
        v["iface"] = json!(iface);
        v["mode"] = serde_json::to_value(v6.mode).unwrap_or_default();
        if net.role != NetworkRole::Wan {
            // networkd drops the node's address in a withdrawn delegated
            // prefix; one it keeps deprecated (preferred lifetime spent)
            // is not advertised either.
            let prefixes: Vec<String> = st
                .addresses
                .iter()
                .filter(|a| a.preferred_seconds != Some(0))
                .filter_map(|a| prefix_of(&a.address))
                .collect();
            v["prefixes"] = json!(prefixes);
        }
        out.insert(name.clone(), v);
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

/// The `ipv6` health check, once a network has IPv6: degraded while a WAN
/// has no IPv6 default route, or a WAN that should delegate a prefix to
/// the inside networks has none. Degraded, never failed: IPv4 still
/// flows, so a pair should not move its gateway addresses over it.
pub fn health(doc: &Document, links: &BTreeMap<String, LinkIpv6>) -> Option<Check> {
    if !doc.networks.values().any(|n| n.ipv6.is_some()) {
        return None;
    }
    let delegated: Vec<&str> = doc
        .networks
        .iter()
        .filter(|(_, n)| {
            n.ipv6
                .as_ref()
                .is_some_and(|v| v.mode == Ipv6Mode::Delegated)
        })
        .map(|(name, _)| name.as_str())
        .collect();
    let (mut bad, mut good) = (Vec::new(), Vec::new());
    for (name, net) in &doc.networks {
        let Some(v6) = &net.ipv6 else { continue };
        if net.role != NetworkRole::Wan {
            continue;
        }
        let st = doc
            .network_iface(name)
            .and_then(|i| links.get(i))
            .cloned()
            .unwrap_or_default();
        match st.default_gateway {
            Some(g) => good.push(format!("{name}: default route via {g}")),
            None => bad.push(format!("{name}: no IPv6 default route")),
        }
        if v6.mode == Ipv6Mode::Dhcpv6 && !delegated.is_empty() {
            match st.delegated.first() {
                Some(p) => good.push(format!("{name}: {} delegated", p.address)),
                None => bad.push(format!(
                    "{name}: no delegated prefix, so {} {} no IPv6",
                    delegated.join(", "),
                    if delegated.len() == 1 { "has" } else { "have" }
                )),
            }
        }
    }
    Some(if !bad.is_empty() {
        Check::new("ipv6", Level::Degraded, bad.join("; "))
    } else if good.is_empty() {
        Check::new("ipv6", Level::Ok, "IPv6 on inside networks only")
    } else {
        Check::new("ipv6", Level::Ok, good.join("; "))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bytes(a: &str) -> Value {
        json!(a.parse::<Ipv6Addr>().unwrap().octets().to_vec())
    }

    #[test]
    fn reads_addresses_prefixes_and_the_default_route() {
        let now = 1_000_000_000; // 1000 s of boot time
        let d = json!({"Interfaces": [
            {"Name": "wan0",
             "Addresses": [
                {"Family": 10, "Address": bytes("2001:db8:ffff::100"), "PrefixLength": 128,
                 "Scope": 0, "PreferredLifetimeUSec": now + 90_000_000u64,
                 "ValidLifetimeUSec": now + 180_000_000u64},
                {"Family": 10, "Address": bytes("fe80::1"), "PrefixLength": 64, "Scope": 253},
                {"Family": 2, "Address": [203, 0, 113, 2], "PrefixLength": 29, "Scope": 0}],
             "DHCPv6Client": {"Prefixes": [
                {"Prefix": bytes("2001:db8:100::"), "PrefixLength": 56,
                 "PreferredLifetimeUSec": now + 1_800_000_000u64,
                 "ValidLifetimeUSec": now + 3_600_000_000u64}]},
             "Routes": [
                {"Family": 10, "Destination": bytes("::"), "DestinationPrefixLength": 0,
                 "Type": 7, "Table": 254},
                {"Family": 10, "Destination": bytes("::"), "DestinationPrefixLength": 0,
                 "Gateway": bytes("fe80::1"), "Type": 1, "Table": 254},
                {"Family": 2, "Destination": [0, 0, 0, 0], "DestinationPrefixLength": 0,
                 "Gateway": [203, 0, 113, 1], "Type": 1, "Table": 254}]},
            {"Name": "lan0",
             "Addresses": [
                {"Family": 10, "Address": bytes("2001:db8:100:1::1"), "PrefixLength": 64,
                 "Scope": 0}]},
            {"Name": "lo", "Addresses": [
                {"Family": 10, "Address": bytes("::1"), "PrefixLength": 128, "Scope": 254}]},
        ]});
        let s = from_describe(&d, now);
        assert_eq!(s.len(), 2, "{s:?}");
        let wan = &s["wan0"];
        assert_eq!(
            wan.addresses,
            vec![Lifetimed {
                address: "2001:db8:ffff::100/128".into(),
                preferred_seconds: Some(90),
                valid_seconds: Some(180),
            }]
        );
        assert_eq!(
            wan.delegated,
            vec![Lifetimed {
                address: "2001:db8:100::/56".into(),
                preferred_seconds: Some(1800),
                valid_seconds: Some(3600),
            }]
        );
        assert_eq!(wan.default_gateway, Some("fe80::1".parse().unwrap()));
        let lan = &s["lan0"];
        assert_eq!(lan.addresses[0].address, "2001:db8:100:1::1/64");
        assert_eq!(lan.addresses[0].valid_seconds, None);
        assert!(lan.delegated.is_empty() && lan.default_gateway.is_none());
    }

    fn doc(patch: Value) -> Document {
        let text = std::fs::read_to_string(format!(
            "{}/../../examples/two-nic.yaml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let d = sparewall_config::parse(&text, sparewall_config::Format::Yaml).unwrap();
        let mut v = sparewall_config::to_value(&d);
        sparewall_config::merge_patch(&mut v, &patch);
        sparewall_config::from_value(v).unwrap()
    }

    fn lt(a: &str) -> Lifetimed {
        Lifetimed {
            address: a.into(),
            preferred_seconds: Some(1800),
            valid_seconds: Some(3600),
        }
    }

    #[test]
    fn health_wants_a_default_route_and_a_prefix_to_delegate() {
        assert_eq!(health(&doc(json!({})), &BTreeMap::new()), None);
        let d = doc(json!({"networks": {
            "wan": {"ipv6": {"mode": "dhcpv6"}},
            "lan": {"ipv6": {"mode": "delegated", "subnet_id": 1}}}}));
        let c = health(&d, &BTreeMap::new()).unwrap();
        assert_eq!(c.level, Level::Degraded);
        assert_eq!(
            c.message,
            "wan: no IPv6 default route; wan: no delegated prefix, so lan has no IPv6"
        );
        let mut links = BTreeMap::new();
        links.insert(
            "wan0".to_string(),
            LinkIpv6 {
                addresses: vec![lt("2001:db8:ffff::100/128")],
                delegated: vec![lt("2001:db8:100::/56")],
                default_gateway: Some("fe80::1".parse().unwrap()),
            },
        );
        let c = health(&d, &links).unwrap();
        assert_eq!(c.level, Level::Ok);
        assert_eq!(
            c.message,
            "wan: default route via fe80::1; wan: 2001:db8:100::/56 delegated"
        );
        // An ra WAN delegates nothing, and nothing is asked of it.
        let d = doc(json!({"networks": {"wan": {"ipv6": {"mode": "ra"}}}}));
        links.get_mut("wan0").unwrap().delegated.clear();
        assert_eq!(health(&d, &links).unwrap().level, Level::Ok);
    }

    #[test]
    fn status_names_each_ipv6_network_and_what_it_advertises() {
        let d = doc(json!({"networks": {
            "wan": {"ipv6": {"mode": "dhcpv6"}},
            "lan": {"ipv6": {"mode": "delegated", "subnet_id": 1}}}}));
        let mut links = BTreeMap::new();
        links.insert(
            "lan0".to_string(),
            LinkIpv6 {
                addresses: vec![lt("2001:db8:100:1::1/64")],
                ..Default::default()
            },
        );
        let s = status(&d, &links).unwrap();
        assert_eq!(s["wan"]["iface"], "wan0");
        assert_eq!(s["wan"]["mode"], "dhcpv6");
        assert!(s["wan"].get("prefixes").is_none());
        assert_eq!(s["lan"]["prefixes"], json!(["2001:db8:100:1::/64"]));
        // Renumbering: an old address left deprecated is not advertised.
        links.get_mut("lan0").unwrap().addresses.push(Lifetimed {
            address: "2001:db8:200:1::1/64".into(),
            preferred_seconds: Some(0),
            valid_seconds: Some(600),
        });
        let s2 = status(&d, &links).unwrap();
        assert_eq!(s2["lan"]["prefixes"], json!(["2001:db8:100:1::/64"]));
        assert_eq!(s["lan"]["addresses"][0]["valid_seconds"], 3600);
        assert_eq!(status(&doc(json!({})), &links), None);
    }

    /// A default route from RAs, through a nexthop object, as networkd
    /// lists it: on the link, or with the manager's routes.
    #[test]
    fn a_default_route_through_a_nexthop() {
        let nh = json!([{"ID": 7, "Family": 10, "Gateway": bytes("fe80::ff:fe00:2106")}]);
        let route = json!({"Family": 10, "Destination": bytes("::"),
            "DestinationPrefixLength": 0, "NextHopID": 7, "Type": 1, "Table": 254});
        for d in [
            json!({"Interfaces": [{"Name": "wan0", "NextHops": nh, "Routes": [route]}]}),
            json!({"Interfaces": [{"Name": "wan0", "NextHops": nh},
                                  {"Name": "lan0", "NextHops": [{"ID": 8, "Family": 10}]}],
                   "Routes": [route]}),
        ] {
            let s = from_describe(&d, 0);
            assert_eq!(
                s["wan0"].default_gateway,
                Some("fe80::ff:fe00:2106".parse().unwrap()),
                "{d}"
            );
            assert!(!s.contains_key("lan0"), "{s:?}");
        }
    }

    #[test]
    fn a_lapsed_lifetime_is_zero_and_junk_is_skipped() {
        let d = json!({"Interfaces": [{"Name": "wan0",
            "DHCPv6Client": {"Prefixes": [
                {"Prefix": bytes("2001:db8:100::"), "PrefixLength": 56,
                 "PreferredLifetimeUSec": 5, "ValidLifetimeUSec": 5},
                {"Prefix": [1, 2, 3], "PrefixLength": 56}]}}]});
        let s = from_describe(&d, 1_000_000);
        assert_eq!(s["wan0"].delegated.len(), 1);
        assert_eq!(s["wan0"].delegated[0].valid_seconds, Some(0));
        assert!(from_describe(&json!({}), 0).is_empty());
    }
}
