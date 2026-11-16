//! The node's neighbour table and routes, per network (#263, part of
//! #181), read-only, from `ip -j`, each interface named by the network it
//! carries.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use sparewall_api::{FirewallError, Neighbour, Route};
use sparewall_config::Document;

fn invalid(msg: impl Into<String>) -> FirewallError {
    FirewallError::ValidationFailed {
        errors: vec![msg.into()],
    }
}

const TIMEOUT: Duration = Duration::from_secs(5);
/// Entries at most in a reply: a large table is cut, and says so.
pub const MAX_ENTRIES: usize = 4096;

/// Each interface's network, from the document: the network's own link,
/// a WAN's public one (a pair's lease link), and an inside network's IPv6
/// gateway link in a pair.
pub fn iface_networks(doc: &Document) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for name in doc.networks.keys() {
        let mut add = |i: Option<String>| {
            if let Some(i) = i {
                m.entry(i).or_insert_with(|| name.clone());
            }
        };
        add(doc.network_iface(name).map(str::to_string));
        add(doc.public_iface(name).map(str::to_string));
        add(doc.ipv6_gateway_iface(name));
    }
    m
}

/// The interfaces a filter by network keeps: every interface of that
/// network. An unknown network is refused.
pub fn ifaces_of(
    map: &BTreeMap<String, String>,
    doc: Option<&Document>,
    network: &str,
) -> Result<Vec<String>, FirewallError> {
    if !doc.is_some_and(|d| d.networks.contains_key(network)) {
        return Err(invalid(format!("network: no network named {network:?}")));
    }
    Ok(map
        .iter()
        .filter(|(_, n)| *n == network)
        .map(|(i, _)| i.clone())
        .collect())
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| {
        x.as_str()
            .map(str::to_string)
            .or_else(|| x.as_u64().map(|n| n.to_string()))
    })
}

/// Neighbours from `ip -j neigh show`.
pub fn neighbours(json: &Value, family: &str, map: &BTreeMap<String, String>) -> Vec<Neighbour> {
    json.as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| {
            let iface = s(n, "dev")?;
            Some(Neighbour {
                address: s(n, "dst")?,
                family: family.to_string(),
                network: map.get(&iface).cloned(),
                iface,
                mac: s(n, "lladdr"),
                state: n["state"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect(),
                router: n.get("router").is_some(),
            })
        })
        .collect()
}

/// Routes from `ip -j route show table all`, without the local table
/// (the node's own and broadcast addresses).
pub fn routes(json: &Value, family: &str, map: &BTreeMap<String, String>) -> Vec<Route> {
    json.as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["table"].as_str() != Some("local"))
        .filter_map(|r| {
            let iface = s(r, "dev");
            Some(Route {
                destination: s(r, "dst")?,
                family: family.to_string(),
                table: s(r, "table").unwrap_or_else(|| "main".into()),
                kind: s(r, "type").unwrap_or_else(|| "unicast".into()),
                gateway: s(r, "gateway"),
                network: iface.as_ref().and_then(|i| map.get(i).cloned()),
                iface,
                source: s(r, "prefsrc"),
                protocol: s(r, "protocol"),
                metric: r["metric"].as_i64(),
                expires: r["expires"].as_i64(),
                flags: r["flags"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect(),
            })
        })
        .collect()
}

/// `ip -j` with these arguments, parsed.
pub async fn ip_json(args: &[&str]) -> Result<Value, FirewallError> {
    let unavailable = |m: String| FirewallError::ServiceUnavailable {
        service: "ip".into(),
        message: m,
    };
    let child = tokio::process::Command::new("ip")
        .arg("-j")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| unavailable(format!("ip: {e}")))?;
    let out = tokio::time::timeout(TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| unavailable("ip took too long".into()))?
        .map_err(|e| unavailable(format!("ip: {e}")))?;
    if !out.status.success() {
        return Err(unavailable(format!(
            "ip: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    // An empty table prints nothing at all.
    if out.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Array(vec![]));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| unavailable(format!("ip: {e}")))
}

/// Which families: `4`, `6`, or both.
pub fn families(family: Option<&str>) -> Result<Vec<&'static str>, FirewallError> {
    match family {
        None => Ok(vec!["4", "6"]),
        Some("4" | "ipv4") => Ok(vec!["4"]),
        Some("6" | "ipv6") => Ok(vec!["6"]),
        Some(f) => Err(invalid(format!("family: 4 or 6, not {f:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn map() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("lan0".to_string(), "lan".to_string()),
            ("wan0".to_string(), "wan".to_string()),
        ])
    }

    #[test]
    fn neighbours_by_network() {
        let j = json!([
            {"dst": "192.168.1.10", "dev": "lan0", "lladdr": "52:54:00:00:00:10", "state": ["REACHABLE"]},
            {"dst": "203.0.113.1", "dev": "wan0", "state": ["FAILED"], "router": null},
            {"dst": "10.9.9.9", "dev": "wg9", "state": ["STALE"]},
            {"dev": "lan0"}
        ]);
        let n = neighbours(&j, "4", &map());
        assert_eq!(n.len(), 3);
        assert_eq!(n[0].network.as_deref(), Some("lan"));
        assert_eq!(n[0].mac.as_deref(), Some("52:54:00:00:00:10"));
        assert_eq!(n[1].state, ["FAILED"]);
        assert!(n[1].router && !n[0].router);
        assert_eq!(n[1].mac, None);
        assert_eq!(n[2].network, None);
    }

    #[test]
    fn routes_without_the_local_table() {
        let j = json!([
            {"dst": "default", "gateway": "203.0.113.1", "dev": "wan0", "protocol": "dhcp", "metric": 1024, "flags": []},
            {"dst": "192.168.1.0/24", "dev": "lan0", "protocol": "kernel", "scope": "link", "prefsrc": "192.168.1.1", "flags": ["linkdown"]},
            {"type": "local", "dst": "192.168.1.1", "table": "local", "dev": "lan0"},
            {"type": "unreachable", "dst": "10.0.0.0/8", "table": "100", "flags": []},
            {"dst": "2001:db8:1::/64", "dev": "wan0", "expires": 3500, "flags": []}
        ]);
        let r = routes(&j, "4", &map());
        assert_eq!(r.len(), 4);
        assert_eq!(r[0].table, "main");
        assert_eq!(r[0].gateway.as_deref(), Some("203.0.113.1"));
        assert_eq!(r[0].network.as_deref(), Some("wan"));
        assert_eq!(r[0].metric, Some(1024));
        assert_eq!(r[1].source.as_deref(), Some("192.168.1.1"));
        assert_eq!(r[1].flags, ["linkdown"]);
        assert_eq!(r[2].kind, "unreachable");
        assert_eq!(r[2].table, "100");
        assert_eq!(r[2].iface, None);
        assert_eq!(r[3].expires, Some(3500));
    }

    #[test]
    fn families_and_networks_are_checked() {
        assert_eq!(families(None).unwrap(), ["4", "6"]);
        assert_eq!(families(Some("ipv6")).unwrap(), ["6"]);
        assert!(families(Some("7")).is_err());
        let text = std::fs::read_to_string(format!(
            "{}/../../examples/two-nic.yaml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let doc = sparewall_config::parse(&text, sparewall_config::Format::Yaml).unwrap();
        let m = iface_networks(&doc);
        assert_eq!(m.get("lan0").map(String::as_str), Some("lan"));
        assert_eq!(m.get("wan0").map(String::as_str), Some("wan"));
        assert_eq!(ifaces_of(&m, Some(&doc), "lan").unwrap(), ["lan0"]);
        assert!(ifaces_of(&m, Some(&doc), "nope").is_err());
        assert!(ifaces_of(&m, None, "lan").is_err());
    }
}
