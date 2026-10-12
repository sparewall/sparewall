//! Verifying the live firewall against what was loaded (issue #5).
//!
//! Right after a generation's table is loaded, the coordinator records
//! the table as the kernel reports it (`nft -j`), normalized into named
//! components; health compares the live table with that record. What
//! legitimately changes at runtime is left out: counter values, rule and
//! set handles, and the elements of the sets networkd fills (`NFTSet=`).
//! Everything else (chains, their hooks and policies, every rule, the
//! static sets' elements) must match, so flushed, altered, added or
//! removed rules are caught even when the chain names are unchanged.

use std::collections::BTreeMap;

use serde_json::Value;

/// The table, by component: `table`, `chain <name>` (its definition),
/// `rules <chain>` (every rule, in order), `set <name>`, `map <name>`...
pub type Components = BTreeMap<String, Value>;

/// Remove a quota's consumption, keeping its configured limit. The kernel
/// lists `used`/`used_unit` only once something was used.
fn scrub_quota(q: &mut Value) {
    if let Some(o) = q.as_object_mut() {
        o.remove("used");
        o.remove("used_unit");
    }
}

/// Remove what changes at runtime: handles, counter values, quota
/// consumption, when a `last` statement last matched, and the time left
/// on set elements with a timeout.
fn scrub(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.remove("handle");
            m.remove("expires");
            if m.contains_key("packets") && m.contains_key("bytes") {
                m.insert("packets".into(), Value::from(0));
                m.insert("bytes".into(), Value::from(0));
            }
            if let Some(q) = m.get_mut("quota") {
                scrub_quota(q);
            }
            if m.contains_key("last") {
                m.insert("last".into(), Value::Null);
            }
            for x in m.values_mut() {
                scrub(x);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(scrub),
        _ => {}
    }
}

/// Normalize `nft -j list table` output. Elements of `preserved` sets are
/// dropped; other sets' elements are sorted (the kernel's listing order
/// is not part of the policy).
pub fn normalize(live: &Value, preserved: &[String]) -> Components {
    let mut out = Components::new();
    let mut rules: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for item in live["nftables"].as_array().into_iter().flatten() {
        let Some((kind, body)) = item.as_object().and_then(|o| o.iter().next()) else {
            continue;
        };
        if kind == "metainfo" {
            continue;
        }
        let mut body = body.clone();
        scrub(&mut body);
        if kind == "quota" {
            // A named quota object: the item itself is the quota.
            scrub_quota(&mut body);
        }
        let name = body["name"].as_str().unwrap_or_default().to_string();
        match kind.as_str() {
            "rule" => {
                let chain = body["chain"].as_str().unwrap_or_default().to_string();
                rules.entry(chain).or_default().push(body);
            }
            "set" | "map" => {
                if let Some(o) = body.as_object_mut() {
                    if preserved.contains(&name) {
                        o.remove("elem");
                    } else if let Some(Value::Array(e)) = o.get_mut("elem") {
                        e.sort_by_key(|x| x.to_string());
                    }
                }
                out.insert(format!("{kind} {name}"), body);
            }
            "table" => {
                out.insert("table".into(), body);
            }
            _ if name.is_empty() => {
                out.insert(kind.clone(), body);
            }
            _ => {
                out.insert(format!("{kind} {name}"), body);
            }
        }
    }
    for (chain, r) in rules {
        out.insert(format!("rules {chain}"), Value::Array(r));
    }
    out
}

/// What differs between the table as loaded and as it is now, or `None`.
pub fn drift(loaded: &Components, live: &Components) -> Option<String> {
    let mut missing = Vec::new();
    let mut unexpected = Vec::new();
    let mut changed = Vec::new();
    for (k, v) in loaded {
        match live.get(k) {
            None => missing.push(k.as_str()),
            Some(l) if l != v => changed.push(k.as_str()),
            Some(_) => {}
        }
    }
    for k in live.keys() {
        if !loaded.contains_key(k) {
            unexpected.push(k.as_str());
        }
    }
    let mut parts = Vec::new();
    for (what, list) in [
        ("missing", missing),
        ("changed", changed),
        ("unexpected", unexpected),
    ] {
        if !list.is_empty() {
            parts.push(format!("{what}: {}", list.join(", ")));
        }
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn table(rules: Value, admin: Value, wan: Value, packets: u64) -> Value {
        json!({"nftables": [
            {"metainfo": {"version": "1.1.1", "json_schema_version": 1}},
            {"table": {"family": "inet", "name": "sparewall", "handle": 3}},
            {"chain": {"family": "inet", "table": "sparewall", "name": "input", "handle": 1,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
            {"set": {"family": "inet", "name": "admin_nets", "table": "sparewall", "type": "ipv4_addr",
                     "handle": 4, "flags": ["interval"], "elem": admin}},
            {"set": {"family": "inet", "name": "wan_address", "table": "sparewall", "type": "ipv4_addr",
                     "handle": 5, "flags": ["interval"], "elem": wan}},
            {"rule": {"family": "inet", "table": "sparewall", "chain": "input", "handle": 7,
                      "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}},
                               {"counter": {"packets": packets, "bytes": packets * 60}},
                               {"accept": null}]}},
            {"rule": rules},
        ]})
    }

    fn ssh() -> Value {
        json!({"family": "inet", "table": "sparewall", "chain": "input", "handle": 8,
               "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
                        {"accept": null}]})
    }

    #[test]
    fn runtime_changes_are_not_drift() {
        let p = ["wan_address".to_string()];
        let loaded = normalize(&table(ssh(), json!(["10.0.99.0/24"]), json!([]), 0), &p);
        // Traffic, networkd filling its set, and new handles after a reload.
        let mut later = table(ssh(), json!(["10.0.99.0/24"]), json!(["203.0.113.7"]), 1234);
        later["nftables"][6]["rule"]["handle"] = json!(99);
        assert_eq!(drift(&loaded, &normalize(&later, &p)), None);
    }

    #[test]
    fn quota_use_is_not_drift_but_its_limit_is() {
        let rule = |quota: Value| {
            json!({"family": "inet", "table": "sparewall", "chain": "input",
                   "expr": [{"quota": quota}, {"accept": null}]})
        };
        let p: [String; 0] = [];
        let fresh = json!({"val": 100000, "val_unit": "bytes"});
        let loaded = normalize(&table(rule(fresh), json!([]), json!([]), 0), &p);
        let used = json!({"val": 100000, "val_unit": "bytes", "used": 336, "used_unit": "bytes"});
        assert_eq!(
            drift(
                &loaded,
                &normalize(&table(rule(used), json!([]), json!([]), 0), &p)
            ),
            None
        );
        let bigger = json!({"val": 200000, "val_unit": "bytes"});
        assert_eq!(
            drift(
                &loaded,
                &normalize(&table(rule(bigger), json!([]), json!([]), 0), &p)
            )
            .as_deref(),
            Some("changed: rules input")
        );
        // A named quota object, and other runtime-only fields.
        let named = |used: Option<u64>| {
            let mut q = json!({"family": "inet", "table": "sparewall", "name": "q", "bytes": 1000});
            if let Some(u) = used {
                q["used"] = json!(u);
            }
            json!({"nftables": [{"quota": q},
                {"rule": {"family": "inet", "table": "sparewall", "chain": "input",
                          "expr": [{"last": null}]}},
                {"set": {"family": "inet", "table": "sparewall", "name": "t",
                         "elem": [{"elem": {"val": "192.0.2.1", "timeout": 60, "expires": 60}}]}}]})
        };
        let loaded = normalize(&named(None), &p);
        let mut later = named(Some(700));
        later["nftables"][1]["rule"]["expr"][0] = json!({"last": {"used": 1234}});
        later["nftables"][2]["set"]["elem"][0]["elem"]["expires"] = json!(12);
        assert_eq!(drift(&loaded, &normalize(&later, &p)), None);
    }

    #[test]
    fn policy_changes_are_drift() {
        let p = ["wan_address".to_string()];
        let loaded = normalize(&table(ssh(), json!(["10.0.99.0/24"]), json!([]), 0), &p);
        // A rule altered in place.
        let mut altered = ssh();
        altered["expr"][1] = json!({"drop": null});
        let d = drift(
            &loaded,
            &normalize(&table(altered, json!(["10.0.99.0/24"]), json!([]), 0), &p),
        );
        assert_eq!(d.as_deref(), Some("changed: rules input"));
        // A static set's elements changed.
        let d = drift(
            &loaded,
            &normalize(&table(ssh(), json!(["0.0.0.0/0"]), json!([]), 0), &p),
        );
        assert_eq!(d.as_deref(), Some("changed: set admin_nets"));
        // Every rule flushed, the chain kept.
        let mut flushed = table(ssh(), json!(["10.0.99.0/24"]), json!([]), 0);
        let items = flushed["nftables"].as_array_mut().unwrap();
        items.retain(|i| i.get("rule").is_none());
        let d = drift(&loaded, &normalize(&flushed, &p));
        assert_eq!(d.as_deref(), Some("missing: rules input"));
        // An unexpected chain.
        let mut extra = table(ssh(), json!(["10.0.99.0/24"]), json!([]), 0);
        extra["nftables"].as_array_mut().unwrap().push(
            json!({"chain": {"family": "inet", "table": "sparewall", "name": "sneaky", "handle": 20}}),
        );
        let d = drift(&loaded, &normalize(&extra, &p));
        assert_eq!(d.as_deref(), Some("unexpected: chain sneaky"));
        // A chain's policy changed.
        let mut policy = table(ssh(), json!(["10.0.99.0/24"]), json!([]), 0);
        policy["nftables"][2]["chain"]["policy"] = json!("accept");
        let d = drift(&loaded, &normalize(&policy, &p));
        assert_eq!(d.as_deref(), Some("changed: chain input"));
    }
}
