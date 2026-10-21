use serde_json::json;

use super::*;
use crate::path::{combine, get, parse_assignment, parse_path, set_patch, unset_patch};

const STANDALONE: &str = include_str!("../../../examples/standalone.yaml");
const PAIR: &str = include_str!("../../../examples/pair.yaml");

fn load(text: &str) -> Document {
    parse(text, Format::Yaml).unwrap_or_else(|e| panic!("{e}"))
}

fn assert_valid(doc: &Document) {
    let issues = validate(doc);
    let errs = validate::errors(&issues);
    assert!(errs.is_empty(), "unexpected errors: {errs:#?}");
}

fn error_paths(doc: &Document) -> Vec<String> {
    validate(doc)
        .into_iter()
        .filter(|i| i.severity == Severity::Error)
        .map(|i| format!("{}: {}", i.path, i.message))
        .collect()
}

fn has_error(doc: &Document, needle: &str) -> bool {
    error_paths(doc).iter().any(|e| e.contains(needle))
}

#[test]
fn examples_are_valid() {
    assert_valid(&load(STANDALONE));
    assert_valid(&load(PAIR));
}

#[test]
fn hash_is_stable_across_key_order_and_format() {
    let doc = load(STANDALONE);
    let h = hash(&doc);
    // JSON export reparsed.
    let json = export(&doc, Format::Json);
    assert_eq!(hash(&parse(&json, Format::Json).unwrap()), h);
    // YAML export reparsed.
    let yaml = export(&doc, Format::Yaml);
    assert_eq!(hash(&parse(&yaml, Format::Yaml).unwrap()), h);
    // Reverse every object's key order.
    fn reverse(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut pairs: Vec<_> = m.iter().collect();
                pairs.reverse();
                let mut s = String::from("{");
                for (i, (k, v)) in pairs.into_iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str(&serde_json::to_string(k).unwrap());
                    s.push(':');
                    s.push_str(&reverse(v).to_string());
                }
                s.push('}');
                serde_json::from_str(&s).unwrap()
            }
            serde_json::Value::Array(a) => {
                serde_json::Value::Array(a.iter().map(reverse).collect())
            }
            other => other.clone(),
        }
    }
    let rev = reverse(&to_value(&doc));
    assert_eq!(hash(&from_value(rev).unwrap()), h);
}

#[test]
fn defaults_are_canonical() {
    // Stating a default explicitly hashes the same as omitting it.
    let doc = load(STANDALONE);
    let mut v = to_value(&doc);
    merge_patch(&mut v, &json!({"management": {"anti_lockout": true}}));
    assert_eq!(hash(&from_value(v).unwrap()), hash(&doc));
}

#[test]
fn export_is_idempotent() {
    for text in [STANDALONE, PAIR] {
        let doc = load(text);
        for f in [Format::Json, Format::Yaml] {
            let once = export(&doc, f);
            let twice = export(&parse(&once, f).unwrap(), f);
            assert_eq!(once, twice);
        }
    }
}

#[test]
fn yaml_is_1_2() {
    // YAML 1.1 would read `no` and `on` as booleans.
    let v = parse_value("a: no\nb: 10\nc: on\nd: true\n", Format::Yaml).unwrap();
    assert_eq!(v, json!({"a": "no", "b": 10, "c": "on", "d": true}));
    assert!(parse_value("a: 1\na: 2\n", Format::Yaml).is_err());
}

#[test]
fn type_errors_have_paths() {
    let mut v = to_value(&load(STANDALONE));
    v["networks"]["users"]["vlan"] = json!("twenty");
    let err = from_value(v).unwrap_err().to_string();
    assert!(err.starts_with("networks.users.vlan"), "{err}");
    let mut v = to_value(&load(STANDALONE));
    v["zones"]["users"]["bogus"] = json!(1);
    let err = from_value(v).unwrap_err().to_string();
    assert!(err.contains("bogus"), "{err}");
}

#[test]
fn paths_parse_and_format() {
    assert_eq!(
        parse_path("policy.'wan->self'.rules").unwrap(),
        ["policy", "wan->self", "rules"]
    );
    assert_eq!(parse_path("a.\"b.c\"").unwrap(), ["a", "b.c"]);
    assert_eq!(parse_path("").unwrap(), Vec::<String>::new());
    assert!(parse_path("a..b").is_err());
    assert!(parse_path("a.'b").is_err());
    let segs = ["policy", "wan->self", "rules"];
    assert_eq!(parse_path(&path::format_path(&segs)).unwrap(), segs);
}

#[test]
fn set_types_values_from_schema() {
    let (p, v) = parse_assignment("networks.users.vlan=20").unwrap();
    assert_eq!(p, ["networks", "users", "vlan"]);
    assert_eq!(v, json!(20));
    // A string field keeps a numeric-looking value as a string.
    let (_, v) = parse_assignment("dhcp.users.reservations.x.mac=52:54:00:00:00:01").unwrap();
    assert_eq!(v, json!("52:54:00:00:00:01"));
    let (_, v) = parse_assignment("vpn.rw.endpoint=1234").unwrap();
    assert_eq!(v, json!("1234"));
    let (_, v) = parse_assignment("networks.wan.dhcp_client=true").unwrap();
    assert_eq!(v, json!(true));
    let (_, v) = parse_assignment("cluster.nodes=[fw1, fw2]").unwrap();
    assert_eq!(v, json!(["fw1", "fw2"]));
    assert!(parse_assignment("networks.users.vlan=abc").is_err());
    // Untagged enums accept either form.
    let (_, v) = parse_assignment("policy.'a->b'.rules.r.dport=443").unwrap();
    assert_eq!(v, json!(443));
    let (_, v) = parse_assignment("policy.'a->b'.rules.r.dport=@web").unwrap();
    assert_eq!(v, json!("@web"));
}

#[test]
fn set_then_get_round_trips() {
    let doc = load(STANDALONE);
    let mut v = to_value(&doc);
    let patch = combine([
        set_patch(&["networks", "users", "vip"], json!("192.0.2.254/24")).unwrap(),
        set_patch(&["dhcp", "users", "pool"], json!("192.0.2.50-192.0.2.60")).unwrap(),
    ]);
    merge_patch(&mut v, &patch);
    let doc2 = from_value(v.clone()).unwrap();
    let v2 = to_value(&doc2);
    assert_eq!(
        get(&v2, &["networks", "users", "vip"]),
        Some(&json!("192.0.2.254/24"))
    );
    assert_eq!(
        get(&v2, &["dhcp", "users", "pool"]),
        Some(&json!("192.0.2.50-192.0.2.60"))
    );
    // Merging the same patch again changes nothing.
    let mut v3 = v2.clone();
    merge_patch(&mut v3, &patch);
    assert_eq!(v3, v2);
}

#[test]
fn unset_removes_map_entries() {
    let mut v = to_value(&load(PAIR));
    merge_patch(
        &mut v,
        &unset_patch(&["vpn", "roadwarrior", "peers", "alice-laptop"]).unwrap(),
    );
    let doc = from_value(v).unwrap();
    assert!(doc.vpn["roadwarrior"].peers.is_empty());
}

#[test]
fn json_patch_ops() {
    let mut v = to_value(&load(PAIR));
    json_patch(
        &mut v,
        &json!([
            {"op": "replace", "path": "/cluster/nodes/1", "value": "fw9"},
        ]),
    )
    .unwrap();
    assert_eq!(v["cluster"]["nodes"], json!(["fw1", "fw9"]));
    assert!(json_patch(&mut v, &json!([{"op": "remove", "path": "/nope"}])).is_err());
}

#[test]
fn diff_summary_lists_leaves() {
    let a = json!({"x": {"y": 1, "z": 2}, "k": 1});
    let b = json!({"x": {"y": 1, "z": 3}, "n": {"m": true}});
    assert_eq!(
        diff_summary(&a, &b),
        ["- k", "+ n = {\"m\":true}", "~ x.z = 3"]
    );
}

#[test]
fn explain_describes_fields() {
    let text = schema::explain(&["networks", "users"]).unwrap();
    assert!(text.contains("vlan"), "{text}");
    assert!(text.contains("802.1Q"), "{text}");
    let text = schema::explain(&["policy", "a->b", "action"]).unwrap();
    assert!(text.contains("accept | drop | reject"), "{text}");
    assert!(schema::explain(&["nope"]).is_none());
}

// --- semantic validation -------------------------------------------------

fn edit(text: &str, patch: serde_json::Value) -> Document {
    let mut v = to_value(&load(text));
    merge_patch(&mut v, &patch);
    from_value(v).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn rejects_sync_network_when_standalone() {
    let d = edit(STANDALONE, json!({"cluster": {"sync_network": "mgmt"}}));
    assert!(has_error(&d, "standalone node has no sync network"));
}

#[test]
fn pair_needs_vrid_and_sync() {
    let d = edit(PAIR, json!({"networks": {"users": {"vrid": null}}}));
    assert!(has_error(&d, "needs a VRRP ID"));
    let d = edit(PAIR, json!({"cluster": {"sync_network": null}}));
    assert!(has_error(&d, "needs a sync network"));
    let d = edit(PAIR, json!({"networks": {"wan": {"vrid": 20}}}));
    assert!(has_error(&d, "already used by network"));
}

#[test]
fn rejects_overlaps_and_bad_addresses() {
    let d = edit(
        STANDALONE,
        json!({"networks": {"guests": {"addresses": {"fw1": "192.0.2.5/25"}, "vip": "192.0.2.6/25"}}}),
    );
    assert!(has_error(&d, "overlaps"), "{:?}", error_paths(&d));
    let d = edit(
        STANDALONE,
        json!({"networks": {"users": {"vip": "192.0.3.1/24"}}}),
    );
    assert!(has_error(&d, "not in the network's subnet"));
    let d = edit(
        STANDALONE,
        json!({"networks": {"users": {"vip": "192.0.2.2/24"}}}),
    );
    assert!(has_error(&d, "must differ"));
}

#[test]
fn rejects_missing_references() {
    let d = edit(
        STANDALONE,
        json!({"zones": {"users": {"networks": ["nope"]}}}),
    );
    assert!(has_error(&d, "no network named \"nope\""));
    let d = edit(
        STANDALONE,
        json!({"policy": {"users->mars": {"action": "accept"}}}),
    );
    assert!(has_error(&d, "no zone named \"mars\""));
    let d = edit(
        STANDALONE,
        json!({"policy": {"wan->self": {"rules": {"x": {"order": 300, "proto": "tcp", "dport": "@nope", "action": "accept"}}}}}),
    );
    assert!(has_error(&d, "no object named \"nope\""));
    let d = edit(
        STANDALONE,
        json!({"policy": {"wan->self": {"rules": {"x": {"order": 300, "proto": "tcp", "src": "@web", "action": "accept"}}}}}),
    );
    assert!(has_error(&d, "is not of type ipv4"));
    let d = edit(
        STANDALONE,
        json!({"raw": {"r": {"at": {"pair": "wan->guests", "position": "after"}, "order": 1, "nft": "counter"}}}),
    );
    assert!(has_error(&d, "no policy for"));
}

#[test]
fn rejects_rule_mistakes() {
    let d = edit(
        STANDALONE,
        json!({"policy": {"wan->self": {"rules": {"dup": {"order": 100, "proto": "tcp", "dport": 1, "action": "accept"}}}}}),
    );
    assert!(has_error(&d, "order 100 is also used"));
    let d = edit(
        STANDALONE,
        json!({"policy": {"wan->self": {"rules": {"p": {"order": 5, "dport": 22, "action": "accept"}}}}}),
    );
    assert!(has_error(&d, "ports need proto"));
    let d = edit(
        STANDALONE,
        json!({"policy": {"wan->self": {"rules": {"p": {"order": 5, "proto": "tcp", "dport": "70000", "action": "accept"}}}}}),
    );
    assert!(has_error(&d, "expected a port"));
    let d = edit(
        STANDALONE,
        json!({"policy": {"wan->self": {"rules": {"p": {"order": 5, "proto": "icmp", "limit": "fast", "action": "accept"}}}}}),
    );
    assert!(has_error(&d, "expected e.g. 10/second"));
    let d = edit(
        STANDALONE,
        json!({"raw": {"evil": {"at": {"hook": "forward"}, "order": 1, "nft": "accept; flush ruleset"}}}),
    );
    assert!(has_error(&d, "one statement per entry"));
}

#[test]
fn rejects_dhcp_mistakes() {
    let d = edit(
        STANDALONE,
        json!({"dhcp": {"users": {"pool": "192.0.2.1-192.0.2.50"}}}),
    );
    assert!(has_error(&d, "contains the firewall's address"));
    let d = edit(
        STANDALONE,
        json!({"dhcp": {"users": {"pool": "10.1.1.1-10.1.1.2"}}}),
    );
    assert!(has_error(&d, "not inside the usable range"));
    let d = edit(
        STANDALONE,
        json!({"dhcp": {"wan": {"pool": "1.1.1.1-1.1.1.2"}}}),
    );
    assert!(has_error(&d, "not served on WAN"));
    let d = edit(PAIR, json!({"dhcp": {"provider": "networkd"}}));
    assert!(has_error(&d, "cannot run in an HA pair"));
    let d = edit(STANDALONE, json!({"dhcp": {"provider": "dnsmasq"}}));
    assert!(has_error(&d, "unknown provider \"dnsmasq\"; use kea"));
}

/// #10: a provider the table lists but this release does not build is
/// rejected (it used to validate and then render nothing), while stored
/// history naming it stays readable.
#[test]
fn rejects_providers_not_built_yet() {
    for (patch, path) in [
        (json!({"dhcp": {"provider": "networkd"}}), "dhcp.provider"),
        (
            json!({"logging": {"remote": {"provider": "syslog", "destination": "log.example:514"}}}),
            "logging.remote.provider",
        ),
    ] {
        let d = edit(STANDALONE, patch);
        let e = error_paths(&d);
        assert!(
            e.iter()
                .any(|e| e.starts_with(path) && e.contains("not built yet")),
            "{path}: {e:?}"
        );
        assert!(
            crate::validate::errors(&crate::validate::validate_history(&d)).is_empty(),
            "{path}: history stays readable"
        );
    }
    let d = edit(
        STANDALONE,
        json!({"logging": {"remote": {"provider": "fluentd", "destination": "x:1"}}}),
    );
    assert!(has_error(
        &d,
        "unknown provider \"fluentd\"; use journal-upload"
    ));
    // ACME DNS: any provider but rfc2136 is a lego provider code, whose
    // options are environment variables.
    let cert = |provider: &str, options: serde_json::Value| {
        json!({"tls": {"certificates": {"mgmt": {
            "names": ["fw.example.org"],
            "acme": {
                "directory": "https://acme.example/dir",
                "dns": {"provider": provider, "credentials": "secret:dns",
                        "options": options}
            }
        }}}})
    };
    let server = json!({"server": "ns.example:53"});
    assert!(!has_error(
        &edit(STANDALONE, cert("rfc2136", server.clone())),
        "provider"
    ));
    let d = edit(STANDALONE, cert("cloudflare", json!({})));
    assert!(
        error_paths(&d).iter().all(|e| !e.contains("acme")),
        "{:?}",
        error_paths(&d)
    );
    let d = edit(
        STANDALONE,
        cert("gcloud", json!({"GCE_PROJECT": "p", "server": "x"})),
    );
    assert!(has_error(&d, "options are its environment variables"));
    assert_eq!(
        error_paths(&d)
            .iter()
            .filter(|e| e.contains("acme"))
            .count(),
        1
    );
    let d = edit(STANDALONE, cert("Cloud Flare", json!({})));
    assert!(has_error(&d, "neither rfc2136 nor a lego provider code"));
}

/// Certificate names become file and secret names: no separators or
/// traversal (#38 review).
#[test]
fn rejects_certificate_names_that_are_not_plain() {
    for bad in ["../../etc/environment", "a/b", ".env", "Mgmt", "-x", ""] {
        let d = edit(
            STANDALONE,
            json!({"tls": {"certificates": {bad: {"names": ["fw.example.org"]}}}}),
        );
        assert!(
            has_error(&d, "a certificate name is lowercase letters"),
            "{bad:?}: {:?}",
            error_paths(&d)
        );
    }
    let d = edit(
        STANDALONE,
        json!({"tls": {"certificates": {"mgmt-2": {"names": ["fw.example.org"]}}}}),
    );
    assert!(!has_error(&d, "a certificate name"));
}

#[test]
fn rejects_port_mistakes() {
    let d = edit(
        PAIR,
        json!({"ports": {"fw2": {"uplink": {"bond": {"primary": "9c:6b:00:00:00:01"}}}}}),
    );
    assert!(has_error(&d, "only valid with mode active-backup"));
    let d = edit(PAIR, json!({"ports": {"fw2": null}}));
    assert!(has_error(&d, "not bound on node \"fw2\""));
    let d = edit(
        STANDALONE,
        json!({"ports": {"fw1": {"uplink": {"nic": "eth0"}}}}),
    );
    assert!(has_error(&d, "MAC address or a udev path"));
    let d = edit(
        STANDALONE,
        json!({"networks": {"averyveryverylongname": {"port": "uplink", "vlan": 50, "addresses": {"fw1": "10.5.0.1/24"}}}}),
    );
    assert!(has_error(&d, "at most 15 characters"));
}

#[test]
fn secrets_must_be_references() {
    let d = edit(
        STANDALONE,
        json!({"backup": {"enabled": true, "credentials": "hunter2"}}),
    );
    assert!(has_error(&d, "secret:<name>"));
    let d = edit(
        STANDALONE,
        json!({"backup": {"enabled": true, "credentials": "secret:restic-s3"}}),
    );
    assert_valid(&d);
    let psk = |k: &str| {
        edit(
            PAIR,
            json!({"vpn": {"roadwarrior": {"peers": {"alice-laptop": {"preshared_key": k}}}}}),
        )
    };
    let d = psk("8y4o0Hq9w1VQ0p2Zr0qYx3vJk7o5nT1mB2cD3eF4gH0=");
    assert!(has_error(
        &d,
        "vpn.roadwarrior.peers.alice-laptop.preshared_key"
    ));
    assert_valid(&psk("secret:psk-alice"));
}

#[test]
fn self_zone_is_reserved() {
    let d = edit(STANDALONE, json!({"zones": {"self": {"networks": []}}}));
    assert!(has_error(&d, "built in"));
}

#[test]
fn rejects_settings_not_built_yet() {
    let d = edit(
        STANDALONE,
        json!({"provider_options": {"kea": {"valid-lifetime": 600}}}),
    );
    assert!(has_error(
        &d,
        "provider_options.kea: provider passthrough options"
    ));
    let d = edit(STANDALONE, json!({"metrics": {"mode": "local"}}));
    assert!(has_error(&d, "metrics.mode: a local Prometheus"));
    let d = edit(
        STANDALONE,
        json!({"metrics": {"mode": "external", "retention": "15d"}}),
    );
    assert!(has_error(&d, "metrics.retention:"));
    let d = edit(STANDALONE, json!({"updates": {"mode": "windowed"}}));
    assert!(has_error(&d, "updates.mode: scheduled upgrades"));
    let d = edit(
        STANDALONE,
        json!({"updates": {"mode": "manual", "window": "Sun 03:00"}}),
    );
    assert!(has_error(&d, "updates.window:"));
    // What is built stays valid.
    for metrics in ["external", "off"] {
        assert_valid(&edit(STANDALONE, json!({"metrics": {"mode": metrics}})));
    }
    assert_valid(&edit(
        STANDALONE,
        json!({"updates": {"channel": "testing", "mode": "manual"}}),
    ));
    // History may hold them: earlier versions accepted them.
    let d = edit(
        STANDALONE,
        json!({"metrics": {"mode": "local", "retention": "15d"},
               "updates": {"mode": "windowed", "window": "Sun 03:00"},
               "provider_options": {"kea": {}}}),
    );
    assert_eq!(error_paths(&d).len(), 5, "{:?}", error_paths(&d));
    let history = validate::validate_history(&d);
    assert!(validate::errors(&history).is_empty(), "{history:?}");
}

/// #10: switching a role's provider away from one whose state the new one
/// cannot import warns; keeping it, or a role without state, does not.
#[test]
fn provider_switch_warns_about_lost_state() {
    use crate::providers::switch_warnings;
    let old = load(STANDALONE);
    let to_networkd = edit(STANDALONE, json!({"dhcp": {"provider": "networkd"}}));
    let w = switch_warnings(&old, &to_networkd);
    assert_eq!(
        w,
        [
            "dhcp.provider: switching from kea to networkd does not carry over Kea's lease database; it starts empty"
        ]
    );
    assert!(switch_warnings(&to_networkd, &to_networkd).is_empty());
    let named = edit(STANDALONE, json!({"dhcp": {"provider": "kea"}}));
    assert!(
        switch_warnings(&old, &named).is_empty(),
        "the default, named"
    );
}

#[test]
fn hairpin_needs_dst_and_inside_zones() {
    let hp = |v: serde_json::Value| edit(STANDALONE, json!({"forwards": {"web-server": v}}));
    // The example's own hairpin is valid.
    assert_valid(&hp(json!({"hairpin": ["users", "guests"]})));
    assert!(has_error(
        &hp(json!({"dst": null, "hairpin": ["users"]})),
        "needs dst"
    ));
    assert!(has_error(
        &hp(json!({"hairpin": ["self"]})),
        "cannot be a hairpin zone"
    ));
    assert!(has_error(&hp(json!({"hairpin": ["lab"]})), "no zone named"));
    assert!(has_error(
        &hp(json!({"hairpin": ["wan"]})),
        "already applies from"
    ));
    assert!(has_error(
        &hp(json!({"hairpin": ["users", "users"]})),
        "listed twice"
    ));
}

#[test]
fn vm_suite_documents_are_valid() {
    // The single-node VM suites' documents (the pair's carries key
    // placeholders, filled in at run time).
    for text in [
        include_str!("../../../tests/vm/site.yaml"),
        include_str!("../../../tests/vm/site-vlans.yaml"),
    ] {
        assert_valid(&load(text));
    }
}

#[test]
fn vpn_extra_ports_must_be_free() {
    let ports =
        |v: serde_json::Value| edit(PAIR, json!({"vpn": {"roadwarrior": {"extra_ports": v}}}));
    assert_valid(&ports(json!([53, 443])));
    assert!(has_error(&ports(json!([51820])), "already in use by a VPN"));
    assert!(has_error(
        &ports(json!([53, 53])),
        "already in use by a VPN"
    ));
    assert!(has_error(&ports(json!([0])), "not a port"));
    // A UDP forward from the WAN zone on that port, directly or by range.
    for dport in [json!(53), json!("50-60"), json!([443, 53])] {
        let d = edit(
            PAIR,
            json!({"vpn": {"roadwarrior": {"extra_ports": [53]}},
                   "forwards": {"dns-in": {"proto": "udp", "dport": dport, "to": "192.0.2.53"}}}),
        );
        assert!(
            has_error(&d, "forwards.dns-in already uses UDP 53"),
            "{dport}"
        );
    }
    // TCP does not collide.
    let d = edit(
        PAIR,
        json!({"vpn": {"roadwarrior": {"extra_ports": [443]}},
               "forwards": {"web": {"proto": "tcp", "dport": 443, "to": "192.0.2.80"}}}),
    );
    assert!(!has_error(&d, "already uses UDP"));
}

#[test]
fn extra_vips_are_checked_and_count_as_held() {
    let x = |v: serde_json::Value| edit(PAIR, json!({"networks": {"wan": {"extra_vips": v}}}));
    assert_valid(&x(json!(["203.0.113.5/29", "203.0.113.4/29"])));
    assert!(has_error(
        &x(json!(["198.51.100.5/29"])),
        "not in the gateway address's subnet"
    ));
    assert!(has_error(
        &x(json!(["203.0.113.5/29", "203.0.113.5/29"])),
        "already used on network wan"
    ));
    assert!(has_error(
        &x(json!(["203.0.113.1/29"])),
        "already used on network wan"
    ));
    assert!(has_error(
        &x(json!(["203.0.113.7/29"])),
        "network or broadcast"
    ));
    let d = edit(
        PAIR,
        json!({"networks": {"users": {"vip": null, "vrid": null, "extra_vips": ["192.0.2.9/24"]}}}),
    );
    assert!(has_error(&d, "need a gateway address"));

    // An SNAT target or forward destination inside a static network must
    // be held by some node: the gateway, an extra or a node address.
    let snat = |a: &str, extras: serde_json::Value| {
        edit(
            PAIR,
            json!({"networks": {"wan": {"extra_vips": extras}},
                   "policy": {"users->wan": {"nat": {"snat": a}}}}),
        )
    };
    assert_valid(&snat("203.0.113.5", json!(["203.0.113.5/29"])));
    assert_valid(&snat("203.0.113.1", json!(["203.0.113.5/29"])));
    assert!(has_error(
        &snat("203.0.113.4", json!(["203.0.113.5/29"])),
        "no node holds 203.0.113.4"
    ));
    // Outside every static network (a DHCP WAN's, say): not checked.
    assert_valid(&snat("100.64.0.9", json!(["203.0.113.5/29"])));
    let d = edit(PAIR, json!({"forwards": {"mail": {"dst": "203.0.113.4"}}}));
    assert!(has_error(&d, "forwards.mail.dst"));
}

#[test]
fn pair_wan_public_block_beside_private_node_addresses() {
    // The example: private node addresses, the public block on its own.
    let doc = load(PAIR);
    assert_eq!(
        doc.split_wan("wan").map(|s| s.to_string()).as_deref(),
        Some("10.0.10.0/24")
    );
    let wan = |v: serde_json::Value| edit(PAIR, json!({"networks": {"wan": v}}));
    assert!(has_error(
        &wan(json!({"gateway": null})),
        "needs the ISP's gateway"
    ));
    assert!(has_error(
        &wan(json!({"gateway": "10.0.10.1"})),
        "not inside the gateway address's subnet 203.0.113.0/29"
    ));
    assert!(has_error(
        &wan(json!({"gateway": "203.0.113.5"})),
        "one of the pair's own addresses"
    ));
    assert!(has_error(
        &wan(json!({"vip": "10.0.10.128/25"})),
        "overlaps the nodes' subnet"
    ));
    assert!(has_error(
        &wan(json!({"vip": "203.0.113.0/29", "extra_vips": []})),
        "network or broadcast"
    ));
    // The public subnet counts for overlaps with other networks.
    assert!(has_error(
        &edit(
            PAIR,
            json!({"networks": {"users": {
            "addresses": {"fw1": "203.0.113.2/29", "fw2": "203.0.113.3/29"},
            "vip": "203.0.113.4/29"}}})
        ),
        "overlaps network"
    ));
    // Public node addresses in the gateway address's subnet still work.
    let public = wan(json!({"addresses": {"fw1": "203.0.113.2/29", "fw2": "203.0.113.3/29"}}));
    assert_valid(&public);
    assert_eq!(public.split_wan("wan"), None);
    // Only a pair's WAN: elsewhere the gateway address stays in the subnet.
    assert!(has_error(
        &edit(
            PAIR,
            json!({"networks": {"users": {"vip": "198.18.0.1/24"}}})
        ),
        "not in the network's subnet"
    ));
    let standalone = edit(
        STANDALONE,
        json!({"networks": {"wan": {"dhcp_client": false, "addresses": {"fw1": "10.0.10.2/24"},
               "vip": "203.0.113.1/29", "gateway": "203.0.113.6"}}}),
    );
    assert!(has_error(&standalone, "not in the network's subnet"));
}

/// The pair example with one DHCP lease for the pair on its WAN.
fn leased_pair(extra: serde_json::Value) -> Document {
    let mut wan = json!({"dhcp_client": true, "vip": null, "extra_vips": [], "gateway": null});
    if let (Some(w), Some(e)) = (wan.as_object_mut(), extra.as_object()) {
        w.extend(e.clone());
    }
    edit(PAIR, json!({"networks": {"wan": wan}}))
}

#[test]
fn pair_wan_one_lease_for_the_pair() {
    let doc = leased_pair(json!({}));
    assert_valid(&doc);
    assert_eq!(
        doc.leased_wan("wan").map(|s| s.to_string()).as_deref(),
        Some("10.0.10.0/24")
    );
    assert_eq!(doc.split_wan("wan"), None);
    assert_eq!(Document::vrrp_mac(10), "00:00:5e:00:01:0a");
    assert!(has_error(
        &leased_pair(json!({"vrid": null})),
        "needs a VRRP ID"
    ));
    assert!(has_error(
        &leased_pair(json!({"vip": "203.0.113.1/29"})),
        "the lease is the public address"
    ));
    assert!(has_error(
        &leased_pair(json!({"addresses": {"fw2": null}})),
        "no address for node \"fw2\""
    ));
    // The lease follows the VRRP master: some network needs a vip.
    let d = edit(
        PAIR,
        json!({"networks": {
            "wan": {"dhcp_client": true, "vip": null, "extra_vips": [], "gateway": null},
            "users": {"vip": null, "vrid": null}}}),
    );
    assert!(has_error(&d, "follows the master"));
    // Standalone: a DHCP client and addresses are still exclusive.
    let d = edit(
        STANDALONE,
        json!({"networks": {"wan": {"addresses": {"fw1": "10.0.10.2/24"}}}}),
    );
    assert!(has_error(&d, "not both"));
}

#[test]
fn preempt_delay_is_bounded_and_warned_about() {
    let with = |d: u16| {
        let mut doc = load(PAIR);
        doc.cluster
            .vrrp
            .get_or_insert_with(|| serde_json::from_value(json!({})).unwrap())
            .preempt_delay_s = Some(d);
        validate(&doc)
    };
    let at = |issues: Vec<Issue>, sev: Severity| {
        issues
            .iter()
            .any(|i| i.path == "cluster.vrrp.preempt_delay_s" && i.severity == sev)
    };
    assert!(at(with(0), Severity::Error));
    assert!(at(with(1001), Severity::Error));
    assert!(!at(with(300), Severity::Error));
    assert!(at(with(300), Severity::Warning));
}
