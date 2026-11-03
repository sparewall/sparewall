use serde_json::json;

use super::*;
use crate::path::{combine, get, parse_assignment, parse_path, set_patch, unset_patch};

const STANDALONE: &str = include_str!("../../../examples/standalone.yaml");
const PAIR: &str = include_str!("../../../examples/pair.yaml");
const TWO_NIC: &str = include_str!("../../../examples/two-nic.yaml");
const TWO_NIC_PAIR: &str = include_str!("../../../examples/two-nic-pair.yaml");

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

fn warnings(doc: &Document) -> Vec<String> {
    validate::warnings(&validate(doc))
}

fn has_error(doc: &Document, needle: &str) -> bool {
    error_paths(doc).iter().any(|e| e.contains(needle))
}

#[test]
fn examples_are_valid() {
    assert_valid(&load(STANDALONE));
    assert_valid(&load(PAIR));
    assert_valid(&load(TWO_NIC));
    assert_valid(&load(TWO_NIC_PAIR));
    // The two-NIC examples name their admin, so nothing to warn about.
    for d in [load(TWO_NIC), load(TWO_NIC_PAIR)] {
        assert!(
            !warnings(&d)
                .iter()
                .any(|w| w.starts_with("management.sources")),
            "{:?}",
            warnings(&d)
        );
    }
}

/// #177: the management network may be an ordinary one, in a zone; then
/// who reaches the node is worth saying, and the sync tunnel may share it.
#[test]
fn management_and_sync_on_the_lan() {
    let mut open_lan = load(TWO_NIC);
    open_lan.management.sources = None;
    assert_valid(&open_lan);
    assert!(warnings(&open_lan).iter().any(|w| w.starts_with(
        "management.sources: every host on network \"lan\" reaches the node's SSH and HTTPS"
    )));
    // A dedicated management network, in no zone: nothing to warn about.
    assert!(
        !warnings(&load(STANDALONE))
            .iter()
            .any(|w| w.starts_with("management.sources"))
    );
    assert!(has_error(
        &edit(
            TWO_NIC,
            json!({"management": {"sources": ["not-an-address"]}})
        ),
        "management.sources: expected an IPv4 or IPv6 address"
    ));
    assert!(has_error(
        &edit(TWO_NIC, json!({"management": {"sources": ["@nowhere"]}})),
        "management.sources"
    ));
    // Sync over the WAN is refused, and over a network without both
    // nodes' addresses.
    assert!(has_error(
        &edit(TWO_NIC_PAIR, json!({"cluster": {"sync_network": "wan"}})),
        "cluster.sync_network: network \"wan\" is the WAN"
    ));
    assert!(has_error(
        &edit(
            TWO_NIC_PAIR,
            json!({"networks": {"lan": {"addresses": {"fw2": null}}}})
        ),
        "cluster.sync_network: network \"lan\" needs an address for each node"
    ));
    // The usual dedicated sync network still works.
    assert_valid(&load(PAIR));
    // A new field: revision 3.
    assert_eq!(
        crate::schema::revision(&serde_json::to_value(load(TWO_NIC)).unwrap()),
        3
    );
    assert!(crate::schema::revision(&serde_json::to_value(&open_lan).unwrap()) < 3);
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
    let path = "dhcp.provider";
    let d = edit(STANDALONE, json!({"dhcp": {"provider": "networkd"}}));
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
    let d = edit(
        STANDALONE,
        json!({"logging": {"remote": {"provider": "fluentd", "destination": "x:1"}}}),
    );
    assert!(has_error(
        &d,
        "unknown provider \"fluentd\"; use journal-upload, syslog"
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
    // What is built stays valid.
    for metrics in ["external", "local", "off"] {
        assert_valid(&edit(STANDALONE, json!({"metrics": {"mode": metrics}})));
    }
    assert_valid(&edit(
        STANDALONE,
        json!({"updates": {"channel": "testing", "mode": "manual"}}),
    ));
    // History may hold them: earlier versions accepted them.
    let d = edit(STANDALONE, json!({"provider_options": {"kea": {}}}));
    assert_eq!(error_paths(&d).len(), 1, "{:?}", error_paths(&d));
    let history = validate::validate_history(&d);
    assert!(validate::errors(&history).is_empty(), "{history:?}");
}

/// A local Prometheus (#145): retention and its size in Prometheus's
/// units, which apply only to it; the document then needs revision 4.
#[test]
fn local_metrics() {
    let m = |v: serde_json::Value| edit(STANDALONE, json!({"metrics": v}));
    let d = m(json!({"mode": "local", "retention": "30d", "retention_size": "2GB"}));
    assert_valid(&d);
    assert!(warnings(&d).is_empty(), "{:?}", warnings(&d));
    for r in ["15d", "1d12h", "90m", "1y", "500ms", "2w3d"] {
        assert!(validate::prometheus_duration(r), "{r}");
    }
    for r in [
        "", "15", "d", "0d", "12h1d", "1d1d", "15 d", "1.5d", "-1d", "1M",
    ] {
        assert!(!validate::prometheus_duration(r), "{r}");
    }
    for r in ["512MB", "2GB", "1TB", "100B"] {
        assert!(validate::prometheus_size(r), "{r}");
    }
    for r in ["", "2G", "0GB", "2 GB", "2gb", "GB", "1.5GB", "2GiB"] {
        assert!(!validate::prometheus_size(r), "{r}");
    }
    assert!(has_error(
        &m(json!({"mode": "local", "retention": "two weeks"})),
        "metrics.retention: \"two weeks\" is not a duration"
    ));
    assert!(has_error(
        &m(json!({"mode": "local", "retention_size": "2G"})),
        "metrics.retention_size: \"2G\" is not a size"
    ));
    // Without the local Prometheus they do nothing.
    let d = m(json!({"mode": "external", "retention": "30d", "retention_size": "2GB"}));
    assert_valid(&d);
    let w = warnings(&d);
    assert!(
        w.iter()
            .any(|w| w.starts_with("metrics.retention: retention applies to mode: local"))
            && w.iter().any(|w| w.starts_with("metrics.retention_size:")),
        "{w:?}"
    );
    let rev = |v: serde_json::Value| crate::schema::revision(&serde_json::json!({"metrics": v}));
    assert_eq!(rev(json!({"mode": "local"})), 4);
    assert_eq!(rev(json!({"mode": "external"})), 1);
    assert_eq!(rev(json!({"mode": "external", "retention_size": "1GB"})), 4);
}

/// Scheduled upgrades (#84): a window is required with `windowed`, used
/// only with it, and its length bounded; systemd checks the expression
/// itself when the change is applied.
#[test]
fn windowed_upgrades() {
    let w = |u: serde_json::Value| edit(STANDALONE, json!({"updates": u}));
    let d = w(json!({"mode": "windowed", "window": "Sun *-*-* 03:00"}));
    assert_valid(&d);
    assert!(warnings(&d).is_empty(), "{:?}", warnings(&d));
    assert!(has_error(
        &w(json!({"mode": "windowed"})),
        "updates.window: mode: windowed needs a window"
    ));
    assert!(has_error(
        &w(json!({"mode": "windowed", "window": " "})),
        "updates.window: must be one systemd calendar expression"
    ));
    assert!(has_error(
        &w(json!({"mode": "windowed", "window": "Sun\n03:00"})),
        "updates.window: must be one"
    ));
    let manual = w(json!({"mode": "manual", "window": "Sun 03:00"}));
    assert_valid(&manual);
    assert!(
        warnings(&manual)
            .iter()
            .any(|m| m.starts_with("updates.window: the window is used only"))
    );
    for bad in [0, 1441] {
        assert!(has_error(
            &w(json!({"mode": "windowed", "window": "daily", "window_minutes": bad})),
            "updates.window_minutes: must be 1-1440"
        ));
    }
    assert_valid(&w(
        json!({"mode": "windowed", "window": "daily", "window_minutes": 120}),
    ));
    let testing = w(json!({"mode": "windowed", "window": "daily", "channel": "testing"}));
    assert_valid(&testing);
    assert!(
        warnings(&testing)
            .iter()
            .any(|m| m.starts_with("updates.channel: scheduled upgrades on testing"))
    );
    // `windowed` is new in revision 3 (0.3.x rejects it as not built), as
    // is window_minutes; `manual` and `window` are revision 1.
    let rev = |d: &Document| crate::schema::revision(&serde_json::to_value(d).unwrap());
    assert_eq!(rev(&d), 3);
    assert_eq!(rev(&manual), 1);
    assert_eq!(
        rev(&w(
            json!({"mode": "windowed", "window": "daily", "window_minutes": 90})
        )),
        3
    );
}

/// Backup retention (#140): restic's keep rules, a default with a
/// repository, never nothing.
#[test]
fn backup_retention() {
    use crate::model::Retention;
    let b = |v: serde_json::Value| edit(STANDALONE, json!({"backup": v}));
    let with_repo = b(json!({"enabled": true, "repository": "/srv/restic"}));
    assert_valid(&with_repo);
    assert_eq!(
        with_repo.backup.as_ref().unwrap().effective_retention(),
        Some(Retention::default_policy())
    );
    assert_eq!(
        Retention::default_policy().keep_flags(),
        [
            "--keep-hourly=48",
            "--keep-daily=30",
            "--keep-weekly=12",
            "--keep-monthly=24"
        ]
    );
    let custom = b(json!({"enabled": true, "repository": "/srv/restic",
        "retention": {"last": 10, "daily": 7, "yearly": 0}}));
    assert_valid(&custom);
    assert_eq!(
        custom
            .backup
            .as_ref()
            .unwrap()
            .effective_retention()
            .unwrap()
            .keep_flags(),
        ["--keep-last=10", "--keep-daily=7"]
    );
    let off =
        b(json!({"enabled": true, "repository": "/srv/restic", "retention": {"enabled": false}}));
    assert_valid(&off);
    assert_eq!(off.backup.as_ref().unwrap().effective_retention(), None);
    // No repository: nothing to forget in.
    let local = b(json!({"enabled": true}));
    assert_eq!(local.backup.as_ref().unwrap().effective_retention(), None);
    assert!(
        warnings(&b(json!({"enabled": true, "retention": {"daily": 7}})))
            .iter()
            .any(|w| w.starts_with("backup.retention: retention applies to backup.repository"))
    );
    for keeps_nothing in [json!({}), json!({"daily": 0, "last": 0})] {
        assert!(has_error(
            &b(json!({"enabled": true, "repository": "/srv/restic", "retention": keeps_nothing})),
            "backup.retention: keeps nothing"
        ));
    }
    // A new field: revision 3.
    assert_eq!(
        crate::schema::revision(&serde_json::to_value(&custom).unwrap()),
        3
    );
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

/// Site-to-site peers (#148): a `host:port` endpoint, a keepalive, and
/// networks behind them that overlap nothing local, no tunnel and no
/// other peer's.
#[test]
fn site_to_site_peers() {
    const KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const KEY2: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";
    let site = |peer: serde_json::Value| {
        edit(
            PAIR,
            json!({"vpn": {"roadwarrior": {"peers": {"office-b": peer}}}}),
        )
    };
    let peer = |endpoint: &str, addresses: serde_json::Value| json!({"public_key": KEY2, "endpoint": endpoint, "addresses": addresses, "keepalive": 25});
    let d = site(peer(
        "office-b.example.net:51821",
        json!(["10.99.0.20/32", "192.168.20.0/24"]),
    ));
    assert_valid(&d);
    assert_eq!(
        crate::schema::revision(&serde_json::to_value(&d).unwrap()),
        4
    );
    assert_valid(&site(peer(
        "198.51.100.7:51821",
        json!(["10.99.0.20/32", "172.16.0.0/16"]),
    )));
    for e in [
        "office-b.example.net",
        "198.51.100.7",
        "1.2.3:51821",
        "-x.example:1",
        ":51821",
        "a.example:0",
        "[2001:db8::1]:51821",
    ] {
        assert!(
            has_error(
                &site(peer(e, json!(["10.99.0.20/32"]))),
                "office-b.endpoint"
            ),
            "{e}"
        );
    }
    assert!(has_error(
        &site(json!({"public_key": KEY2, "addresses": ["10.99.0.20/32"], "keepalive": 0})),
        "office-b.keepalive: seconds between keepalives"
    ));
    // The networks behind it: not a local one, a tunnel's, another
    // peer's, or everything.
    for (net, what) in [
        ("192.0.2.0/25", "overlaps network users"),
        ("10.99.0.0/16", "overlaps vpn roadwarrior's tunnel"),
        ("0.0.0.0/0", "cannot take the default route"),
    ] {
        let d = site(peer(
            "office-b.example.net:51821",
            json!(["10.99.0.20/32", net]),
        ));
        assert!(
            has_error(
                &d,
                &format!(
                    "vpn.roadwarrior.peers.office-b.addresses: {}",
                    if net == "0.0.0.0/0" { "" } else { net }
                )
            ) && has_error(&d, what),
            "{net}: {:?}",
            validate::errors(&validate::validate(&d))
        );
    }
    let d = edit(
        PAIR,
        json!({"vpn": {"roadwarrior": {"peers": {
            "office-b": peer("b.example.net:51821", json!(["10.99.0.20/32", "192.168.20.0/24"])),
            "office-c": {"public_key": KEY, "endpoint": "c.example.net:51821",
                         "addresses": ["10.99.0.21/32", "192.168.20.128/25"]},
        }}}}),
    );
    assert!(has_error(
        &d,
        "office-c.addresses: 192.168.20.128/25 overlaps vpn.roadwarrior.peers.office-b"
    ));
    // In a pair, only with one static WAN with a gateway address and a
    // gateway: not a WAN leased by DHCP, none, or two.
    let one = site(peer("b.example.net:51821", json!(["10.99.0.20/32"])));
    let mut leased = serde_json::to_value(&one).unwrap();
    let wan = leased["networks"]["wan"].as_object_mut().unwrap();
    for k in ["vip", "gateway", "extra_vips"] {
        wan.remove(k);
    }
    wan.insert("dhcp_client".into(), json!(true));
    wan.insert("vrid".into(), json!(10));
    let leased: Document = serde_json::from_value(leased).unwrap();
    assert!(
        has_error(
            &leased,
            "vpn: site-to-site peers in a pair need exactly one WAN"
        ),
        "{:?}",
        validate::errors(&validate::validate(&leased))
    );
    let mut none = serde_json::to_value(&one).unwrap();
    none["networks"]["wan"]["role"] = json!("service");
    let none: Document = serde_json::from_value(none).unwrap();
    assert!(
        has_error(&none, "this pair has none"),
        "{:?}",
        validate::errors(&validate::validate(&none))
    );
    // A road warrior's addresses stay inside the tunnel.
    assert!(has_error(
        &site(json!({"public_key": KEY2, "addresses": ["192.168.20.0/24"]})),
        "is outside the tunnel's subnet"
    ));
}

/// A WireGuard client (#149): the networks it routes, its keys as
/// secrets, its endpoint and keepalive.
#[test]
fn vpn_clients() {
    const KEY: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";
    let client = |c: serde_json::Value| {
        edit(
            PAIR,
            json!({"vpn_clients": {"egress": c}, "zones": {"egress": {}}}),
        )
    };
    let base = || {
        json!({"private_key": "secret:provider-key", "addresses": ["10.64.12.34/32"],
               "zone": "egress",
               "peer": {"public_key": KEY, "endpoint": "nl1.provider.example:51820"},
               "dns": ["10.64.0.1"], "route": {"networks": ["users"]}})
    };
    let d = client(base());
    assert_valid(&d);
    assert!(warnings(&d).is_empty(), "{:?}", warnings(&d));
    assert_eq!(
        crate::schema::revision(&serde_json::to_value(&d).unwrap()),
        4
    );
    let with = |path: &str, v: serde_json::Value| {
        let mut c = base();
        let mut at = &mut c;
        let parts: Vec<&str> = path.split('.').collect();
        for p in &parts[..parts.len() - 1] {
            at = &mut at[*p];
        }
        at[parts[parts.len() - 1]] = v;
        client(c)
    };
    for (path, v, msg) in [
        (
            "private_key",
            json!("aGVsbG8="),
            "vpn_clients.egress.private_key: secrets are referenced",
        ),
        (
            "peer.preshared_key",
            json!("plain"),
            "vpn_clients.egress.peer.preshared_key: secrets",
        ),
        (
            "peer.public_key",
            json!("nope"),
            "vpn_clients.egress.peer.public_key: not a WireGuard",
        ),
        (
            "peer.endpoint",
            json!("nl1.provider.example"),
            "vpn_clients.egress.peer.endpoint",
        ),
        (
            "peer.keepalive",
            json!(0),
            "vpn_clients.egress.peer.keepalive",
        ),
        ("addresses", json!([]), "vpn_clients.egress.addresses"),
        ("zone", json!("nowhere"), "vpn_clients.egress.zone: no zone"),
        (
            "zone",
            json!("users"),
            "vpn_clients.egress.zone: the tunnel's zone cannot hold",
        ),
        (
            "route.networks",
            json!([]),
            "vpn_clients.egress.route.networks: name the networks",
        ),
        (
            "route.networks",
            json!(["wan"]),
            "route.networks[0]: only the networks behind",
        ),
        (
            "route.networks",
            json!(["nope"]),
            "route.networks[0]: no network named",
        ),
    ] {
        let d = with(path, v);
        assert!(
            has_error(&d, msg),
            "{path}: {:?}",
            validate::errors(&validate::validate(&d))
        );
    }
    let d = with("route.kill_switch", json!(false));
    assert_valid(&d);
    assert!(
        warnings(&d)
            .iter()
            .any(|w| w.starts_with("vpn_clients.egress.route.kill_switch"))
    );
    // A network leaves through one client.
    let d = edit(
        PAIR,
        json!({"vpn_clients": {"egress": base(), "other": base()}, "zones": {"egress": {}}}),
    );
    assert!(has_error(&d, "\"users\" already leaves through \"egress\""));
    // Names are interfaces: not a network's or a VPN instance's.
    let d = edit(
        PAIR,
        json!({"vpn_clients": {"roadwarrior": base()}, "zones": {"egress": {}}}),
    );
    assert!(has_error(
        &d,
        "vpn_clients.roadwarrior: name is already used"
    ));
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

#[test]
fn vmac_only_on_a_static_block_with_private_node_addresses() {
    // The pair example's WAN is one (#194).
    let off = edit(PAIR, json!({"networks": {"wan": {"vmac": false}}}));
    assert_valid(&off);
    assert!(!off.vmac_wan("wan"));
    assert_eq!(off.public_iface("wan"), Some("wan"));
    assert_eq!(
        crate::schema::revision(&serde_json::to_value(&off).unwrap()),
        3
    );
    // The default needs nothing newer.
    assert!(crate::schema::revision(&serde_json::to_value(edit(PAIR, json!({}))).unwrap()) < 3);
    let on = edit(PAIR, json!({}));
    assert!(on.vmac_wan("wan"));
    assert_eq!(on.public_iface("wan"), Some(crate::topology::LEASE_IFACE));
    // Anywhere else it is refused: public node addresses, a leased WAN,
    // another network, a standalone node.
    let msg = "chooses its MAC";
    assert!(has_error(
        &edit(
            PAIR,
            json!({"networks": {"wan": {"vmac": false,
                "addresses": {"fw1": "203.0.113.2/29", "fw2": "203.0.113.3/29"}}}})
        ),
        msg
    ));
    assert!(has_error(&leased_pair(json!({"vmac": false})), msg));
    assert!(has_error(
        &edit(PAIR, json!({"networks": {"users": {"vmac": false}}})),
        msg
    ));
    assert!(has_error(
        &edit(STANDALONE, json!({"networks": {"wan": {"vmac": false}}})),
        msg
    ));
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

#[test]
fn node_names_are_hostnames() {
    use crate::identity::{BootstrapPort, Identity};
    let id = |node: &str| Identity {
        node: node.into(),
        ssh_keys: vec![],
        management: BootstrapPort {
            nic: "52:54:00:aa:00:01".into(),
            vlan: None,
            address: None,
            gateway: None,
            dns: vec![],
        },
        password_hash: None,
    };
    let long = format!("fw{}", "1".repeat(29));
    for good in ["fw1", "edge-a", long.as_str()] {
        assert!(id(good).check().is_ok(), "{good}");
        let mut doc = load(STANDALONE);
        doc.cluster.nodes = vec![good.into()];
        assert!(!has_error(&doc, "invalid node name"), "{good}");
    }
    let too_long = format!("{long}1");
    for bad in ["fw1-", "1fw", "Fw1", "fw_1", "fw.1", "", too_long.as_str()] {
        assert!(id(bad).check().is_err(), "{bad:?}");
        let mut doc = load(STANDALONE);
        doc.cluster.nodes = vec![bad.into()];
        assert!(has_error(&doc, "invalid node name"), "{bad:?}");
    }
}

/// Forwarding to a syslog collector with rsyslog (#147).
#[test]
fn syslog_forwarding() {
    let r = |v: serde_json::Value| edit(STANDALONE, json!({"logging": {"remote": v}}));
    let rev = |d: &Document| crate::schema::revision(&serde_json::to_value(d).unwrap());
    let udp = r(json!({"provider": "syslog", "destination": "logs.example.org"}));
    assert_valid(&udp);
    assert_eq!(rev(&udp), 4, "syslog is new in revision 4");
    for dest in [
        "10.0.0.5:1514",
        "[2001:db8::5]:6514",
        "[2001:db8::5]",
        "logs",
    ] {
        assert_valid(&r(
            json!({"provider": "syslog", "destination": dest, "protocol": "tcp"}),
        ));
    }
    for dest in [
        "udp://logs:514",
        "logs:0",
        "logs:x",
        "",
        "[logs]:514",
        "a b",
    ] {
        assert!(
            has_error(
                &r(json!({"provider": "syslog", "destination": dest})),
                "logging.remote.destination: for syslog, a host name or address"
            ),
            "{dest:?}"
        );
    }
    assert!(has_error(
        &r(json!({"provider": "syslog", "destination": "logs", "protocol": "gelf"})),
        "logging.remote.protocol: unknown protocol \"gelf\""
    ));
    assert!(has_error(
        &r(json!({"provider": "syslog", "destination": "logs", "tls": true})),
        "logging.remote.tls: TLS needs protocol tcp or relp"
    ));
    const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    let relp = r(
        json!({"provider": "syslog", "destination": "logs", "protocol": "relp",
                        "tls": true, "ca": PEM, "certificate": "secret:log-client"}),
    );
    assert_valid(&relp);
    assert_eq!(rev(&relp), 4);
    assert!(has_error(
        &r(json!({"provider": "syslog", "destination": "logs", "protocol": "relp", "tls": true})),
        "logging.remote.certificate: RELP over TLS needs a client certificate"
    ));
    assert_valid(&r(
        json!({"provider": "syslog", "destination": "logs", "protocol": "relp"}),
    ));
    assert_valid(&r(
        json!({"provider": "syslog", "destination": "logs", "protocol": "tcp", "tls": true,
               "certificate": "secret:log-client"}),
    ));
    assert!(has_error(
        &r(
            json!({"provider": "syslog", "destination": "logs", "protocol": "tcp", "tls": true,
                  "certificate": "-----BEGIN PRIVATE KEY-----"})
        ),
        "logging.remote.certificate: secrets are referenced as secret:<name>"
    ));
    assert!(has_error(
        &r(
            json!({"provider": "syslog", "destination": "logs", "protocol": "tcp",
                  "certificate": "secret:log-client"})
        ),
        "logging.remote.certificate: a client certificate is for tls: true"
    ));
    assert!(has_error(
        &r(json!({"provider": "syslog", "destination": "logs", "protocol": "tcp", "ca": PEM})),
        "logging.remote.ca: a CA is for tls: true"
    ));
    assert!(has_error(
        &r(
            json!({"provider": "syslog", "destination": "logs", "protocol": "tcp", "tls": true,
                  "ca": "not a certificate"})
        ),
        "logging.remote.ca: not a PEM certificate"
    ));
    // journal-upload takes neither.
    let ju = |extra: serde_json::Value| {
        let mut v = json!({"destination": "https://logs:19532"});
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        r(v)
    };
    assert_valid(&ju(json!({})));
    assert!(has_error(
        &ju(json!({"protocol": "tcp"})),
        "logging.remote.protocol: only the syslog provider takes a protocol"
    ));
    assert!(has_error(
        &ju(json!({"ca": PEM})),
        "logging.remote.ca: only the syslog provider takes a CA"
    ));
    assert!(has_error(
        &ju(json!({"certificate": "secret:log-client"})),
        "logging.remote.certificate: only the syslog provider takes a client certificate"
    ));
}

/// IPv6 in the document (#211), checked as a document kept in history is:
/// everything but the refusal of what is not built yet.
fn history_errors(doc: &Document) -> Vec<String> {
    validate::validate_history(doc)
        .into_iter()
        .filter(|i| i.severity == Severity::Error)
        .map(|i| format!("{}: {}", i.path, i.message))
        .collect()
}

fn history_error(doc: &Document, needle: &str) -> bool {
    let e = history_errors(doc);
    e.iter().any(|e| e.contains(needle)) || {
        eprintln!("no {needle:?} in {e:#?}");
        false
    }
}

/// A two-NIC box whose WAN asks for a delegated prefix, and whose LAN
/// takes subnet 1 of it.
fn v6(patch: serde_json::Value) -> Document {
    let mut v = to_value(&edit(
        TWO_NIC,
        json!({"networks": {
            "wan": {"ipv6": {"mode": "dhcpv6", "prefix_length": 56}},
            "lan": {"ipv6": {"mode": "delegated", "subnet_id": 1}},
        }}),
    ));
    merge_patch(&mut v, &patch);
    from_value(v).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn ipv6_networks_take_the_modes_their_role_allows() {
    assert_eq!(history_errors(&v6(json!({}))), Vec::<String>::new());
    // A standalone node's WAN (#213) and inside networks (#214) activate
    // IPv6; a pair waits for #215.
    assert_valid(&v6(json!({})));
    // Hosts by suffix in a delegated prefix are not built yet; in a
    // static one they are.
    let d = v6(json!({"objects": {"nas": {"type": "ipv6", "suffixes": {"lan": ["::20"]}}}}));
    assert!(has_error(
        &d,
        "objects.nas.suffixes.lan: hosts by suffix in a delegated prefix are not built yet"
    ));
    let d = v6(json!({
        "networks": {"lan": {"ipv6": {"mode": "static", "subnet_id": null, "prefix": "2001:db8:0:1::/64"}}},
        "objects": {"nas": {"type": "ipv6", "suffixes": {"lan": ["::20"]}}},
    }));
    assert_valid(&d);
    let wan_only = edit(
        TWO_NIC,
        json!({"networks": {"wan": {"ipv6": {"mode": "dhcpv6"}}}}),
    );
    assert_valid(&wan_only);
    let mut v = to_value(&load(PAIR));
    merge_patch(
        &mut v,
        &json!({"networks": {"wan": {"ipv6": {"mode": "ra"}}}}),
    );
    assert!(has_error(
        &from_value(v).unwrap(),
        "networks.wan.ipv6: IPv6 in a pair is not built yet (#215)"
    ));

    let d = v6(
        json!({"networks": {"wan": {"ipv6": {"mode": "delegated", "prefix_length": null, "subnet_id": 0}}}}),
    );
    assert!(history_error(
        &d,
        "networks.wan.ipv6.mode: a WAN takes dhcpv6, ra or static"
    ));
    let d = v6(json!({"networks": {"lan": {"ipv6": {"mode": "ra", "subnet_id": null}}}}));
    assert!(history_error(
        &d,
        "networks.lan.ipv6.mode: an inside network takes delegated or static"
    ));
    // A delegated network needs a WAN that asks for a prefix.
    let d = v6(json!({"networks": {"wan": {"ipv6": {"mode": "ra", "prefix_length": null}}}}));
    assert!(history_error(
        &d,
        "networks.lan.ipv6.mode: no WAN has ipv6 mode dhcpv6"
    ));
    let d = v6(json!({"networks": {"lan": {"ipv6": {"subnet_id": null}}}}));
    assert!(history_error(
        &d,
        "networks.lan.ipv6.subnet_id: a delegated network needs one"
    ));
    // A /56 has 256 subnets.
    let d = v6(json!({"networks": {"lan": {"ipv6": {"subnet_id": 256}}}}));
    assert!(history_error(&d, "a /56 has 256 subnets (0 to 255)"));
    let d = v6(
        json!({"networks": {"wan": {"ipv6": {"prefix_length": 64}}, "lan": {"ipv6": {"subnet_id": 1}}}}),
    );
    assert!(history_error(&d, "a /64 is one subnet, 0"));
    let d = v6(json!({"networks": {"wan": {"ipv6": {"prefix_length": 40}}}}));
    assert!(history_error(
        &d,
        "networks.wan.ipv6.prefix_length: 48 to 64"
    ));
    // A length out of range is an error, never a panic, with a delegated
    // network counting subnets in it.
    for len in [0, 47, 65, 128, 255] {
        let d = v6(json!({"networks": {"wan": {"ipv6": {"prefix_length": len}}}}));
        assert!(
            history_error(&d, "networks.wan.ipv6.prefix_length: 48 to 64"),
            "{len}"
        );
    }
    // Fields for another mode.
    let d = v6(json!({"networks": {"lan": {"ipv6": {"prefix_length": 60}}}}));
    assert!(history_error(
        &d,
        "networks.lan.ipv6.prefix_length: for mode dhcpv6, not delegated"
    ));
    let d = v6(json!({"networks": {"lan": {"ipv6": {"prefix": "2001:db8:1::/64"}}}}));
    assert!(history_error(
        &d,
        "networks.lan.ipv6.prefix: for mode static, not delegated"
    ));
}

#[test]
fn two_networks_cannot_share_a_subnet_or_a_prefix() {
    let mut v = to_value(&load(PAIR));
    merge_patch(
        &mut v,
        &json!({"networks": {
            "wan": {"ipv6": {"mode": "dhcpv6"}},
            "users": {"ipv6": {"mode": "delegated", "subnet_id": 3}},
            "mgmt": {"ipv6": {"mode": "delegated", "subnet_id": 3}},
        }}),
    );
    let d = from_value(v.clone()).unwrap();
    assert!(history_error(&d, "subnet 3 is also network"));
    merge_patch(
        &mut v,
        &json!({"networks": {
            "users": {"ipv6": {"mode": "static", "subnet_id": null, "prefix": "2001:db8:0:1::/64"}},
            "mgmt": {"ipv6": {"mode": "static", "subnet_id": null, "prefix": "2001:db8:0:1::/64"}},
        }}),
    );
    let d = from_value(v.clone()).unwrap();
    assert!(history_error(&d, "overlaps network"));
    merge_patch(
        &mut v,
        &json!({"networks": {"users": {"ipv6": {"prefix": "2001:db8:0:2::/64"}}}}),
    );
    let d = from_value(v).unwrap();
    assert_eq!(history_errors(&d), Vec::<String>::new());
}

#[test]
fn a_static_ipv6_network_states_its_prefix() {
    let st = |lan: serde_json::Value| v6(json!({"networks": {"lan": {"ipv6": lan}}}));
    let base = json!({"mode": "static", "subnet_id": null, "prefix": "2001:db8:0:1::/64"});
    assert_eq!(history_errors(&st(base.clone())), Vec::<String>::new());
    let mut b = base.clone();
    b["prefix"] = "2001:db8:0:1::/60".into();
    assert!(history_error(&st(b), "an inside network's prefix is a /64"));
    let mut b = base.clone();
    b["prefix"] = "2001:db8:0:1::5/64".into();
    assert!(history_error(
        &st(b),
        "has host bits set; the prefix is 2001:db8:0:1::/64"
    ));
    let mut b = base.clone();
    b["prefix"] = "fe80::/64".into();
    assert!(history_error(&st(b), "not a routable prefix"));
    let mut b = base.clone();
    b["gateway"] = "fe80::1".into();
    assert!(history_error(
        &st(b),
        "networks.lan.ipv6.gateway: for a static WAN"
    ));
    let mut b = base;
    b["addresses"] = json!({"fw1": "2001:db8:0:1::1"});
    assert!(history_error(
        &st(b),
        "networks.lan.ipv6.addresses: for a static WAN"
    ));
    // A static WAN: each node's address in the prefix, and a gateway.
    let wan = |w: serde_json::Value| {
        let mut v = to_value(&edit(TWO_NIC, json!({"networks": {"wan": {"ipv6": w}}})));
        merge_patch(&mut v, &json!({}));
        from_value(v).unwrap()
    };
    let ok = json!({"mode": "static", "prefix": "2001:db8:ffff::/64",
        "addresses": {"fw1": "2001:db8:ffff::2"}, "gateway": "fe80::1"});
    assert_eq!(history_errors(&wan(ok.clone())), Vec::<String>::new());
    let mut w = ok.clone();
    w["gateway"] = "2001:db8:ffff::1".into();
    assert_eq!(history_errors(&wan(w)), Vec::<String>::new());
    let mut w = ok.clone();
    w["gateway"] = "2001:db8:eeee::1".into();
    assert!(history_error(
        &wan(w),
        "networks.wan.ipv6.gateway: neither in 2001:db8:ffff::/64 nor link-local"
    ));
    let mut w = ok.clone();
    w["gateway"] = serde_json::Value::Null;
    assert!(history_error(
        &wan(w),
        "a static WAN needs the upstream router"
    ));
    let mut w = ok.clone();
    w["addresses"] = json!({"fw1": "2001:db8:eeee::2"});
    assert!(history_error(
        &wan(w),
        "networks.wan.ipv6.addresses.fw1: not a host in 2001:db8:ffff::/64"
    ));
    let mut w = ok;
    w["addresses"] = json!({"fw9": "2001:db8:ffff::2"});
    let d = wan(w);
    assert!(history_error(&d, "no address for node \"fw1\""));
    assert!(history_error(
        &d,
        "networks.wan.ipv6.addresses.fw9: no node named \"fw9\""
    ));
}

#[test]
fn the_sync_network_stays_ipv4() {
    let d = load(PAIR);
    let sync = d.cluster.sync_network.clone().unwrap();
    let mut v = to_value(&d);
    merge_patch(
        &mut v,
        &json!({"networks": {sync.clone(): {"ipv6": {"mode": "static", "prefix": "2001:db8:9::/64"}}}}),
    );
    let d: Document = from_value(v).unwrap();
    assert!(history_error(
        &d,
        &format!("networks.{sync}.ipv6: the sync network is IPv4 only")
    ));
}

#[test]
fn ipv6_objects_and_suffixes() {
    let obj = |o: serde_json::Value| v6(json!({"objects": {"o": o}}));
    let ok = |o: serde_json::Value| {
        assert_eq!(history_errors(&obj(o.clone())), Vec::<String>::new(), "{o}")
    };
    ok(
        json!({"type": "ipv6", "elements": ["2001:db8::1", "2001:db8:1::/48", "2001:db8::10-2001:db8::20"]}),
    );
    ok(json!({"type": "ipv6", "suffixes": {"lan": ["::20", "::a00:27ff:fe4e:66a1"]}}));
    ok(json!({"type": "ipv6", "elements": ["2001:db8::1"], "suffixes": {"lan": ["::20"]}}));
    ok(json!({"type": "ipv6", "dynamic": {"network": "wan"}}));
    ok(json!({"type": "ipv6", "dynamic": {"network": "lan", "source": "prefix"}}));
    assert!(history_error(
        &obj(json!({"type": "ipv6", "elements": ["10.0.0.1"]})),
        "objects.o.elements[0]: not a valid ipv6 element"
    ));
    assert!(history_error(
        &obj(json!({"type": "ipv4", "elements": ["2001:db8::1"]})),
        "objects.o.elements[0]: not a valid ipv4 element"
    ));
    assert!(history_error(
        &obj(json!({"type": "ipv4", "suffixes": {"lan": ["::20"]}})),
        "only ipv6 objects have suffixes"
    ));
    assert!(history_error(
        &obj(json!({"type": "ipv6", "suffixes": {"lan": ["2001:db8::20"]}})),
        "objects.o.suffixes.lan[0]: \"2001:db8::20\" is not a suffix"
    ));
    assert!(history_error(
        &obj(json!({"type": "ipv6", "suffixes": {"lan": ["::"]}})),
        "is not a suffix"
    ));
    assert!(history_error(
        &obj(json!({"type": "ipv6", "suffixes": {"lan": []}})),
        "objects.o.suffixes.lan: empty list"
    ));
    assert!(history_error(
        &obj(json!({"type": "ipv6", "suffixes": {"nope": ["::1"]}})),
        "no network named \"nope\""
    ));
    // A WAN's address is not the site's own prefix: no suffixes in it.
    assert!(history_error(
        &obj(json!({"type": "ipv6", "suffixes": {"wan": ["::1"]}})),
        "needs an IPv6 prefix of its own"
    ));
    assert!(history_error(
        &obj(json!({"type": "ipv6", "dynamic": {"network": "lan"}, "suffixes": {"lan": ["::1"]}})),
        "a dynamic object has no static elements"
    ));
    assert!(history_error(
        &obj(json!({"type": "port", "dynamic": {"network": "lan"}})),
        "a port object cannot be dynamic"
    ));
    // Without IPv6 on the network, an ipv6 object cannot follow it.
    let d = edit(
        TWO_NIC,
        json!({"objects": {"o": {"type": "ipv6", "dynamic": {"network": "lan"}}}}),
    );
    assert!(history_error(&d, "network \"lan\" has no IPv6"));
    // The firewall renders them (#212): only the networks' IPv6 is
    // refused at activation.
    let d = edit(
        TWO_NIC,
        json!({"objects": {"o": {"type": "ipv6", "elements": ["2001:db8::1"]}}}),
    );
    assert_valid(&d);
}

/// A rule applies to the families its addresses and protocol allow (#211).
#[test]
fn a_rule_takes_the_families_of_its_addresses() {
    let rule = |r: serde_json::Value| {
        let mut r = r;
        r["order"] = 900.into();
        r["action"] = "accept".into();
        v6(json!({
            "objects": {
                "h4": {"type": "ipv4", "elements": ["192.168.1.20"]},
                "h6": {"type": "ipv6", "suffixes": {"lan": ["::20"]}},
                "p": {"type": "port", "elements": [22]},
            },
            "policy": {"wan->lan": {"action": "drop", "rules": {"r": r}}},
        }))
    };
    let ok = |r: serde_json::Value| {
        assert_eq!(
            history_errors(&rule(r.clone())),
            Vec::<String>::new(),
            "{r}"
        )
    };
    ok(json!({"proto": "tcp", "dport": 22}));
    ok(json!({"dst": "2001:db8::/32"}));
    ok(json!({"dst": ["@h4", "@h6"], "proto": "tcp", "dport": "@p"}));
    ok(json!({"src": "2001:db8::1", "dst": "@h6"}));
    ok(json!({"dst": ["192.168.1.20", "2001:db8::20"], "src": "10.0.0.0/8"}));
    ok(json!({"proto": "icmpv6", "icmp_type": ["echo-request"], "dst": "@h6"}));
    ok(json!({"proto": "icmpv6"}));
    ok(json!({"proto": "icmp", "dst": ["@h4", "@h6"]}));
    let bad = |r: serde_json::Value, needle: &str| {
        assert!(history_error(&rule(r.clone()), needle), "{r}");
    };
    bad(
        json!({"src": "10.0.0.1", "dst": "@h6"}),
        "policy.'wan->lan'.rules.r: src is IPv4 and dst IPv6: no packet is both",
    );
    bad(
        json!({"proto": "icmp", "dst": "@h6"}),
        "its addresses are IPv6 and proto icmp is the other family's",
    );
    bad(
        json!({"proto": "icmpv6", "src": "10.0.0.1"}),
        "its addresses are IPv4 and proto icmpv6 is the other family's",
    );
    bad(
        json!({"proto": "tcp", "icmp_type": ["echo-request"]}),
        "needs proto icmp or icmpv6",
    );
    bad(
        json!({"dst": "@p"}),
        "object \"p\" is not of type ipv4 or ipv6",
    );
    bad(
        json!({"dst": "2001:db8::zz"}),
        "expected an IPv4 or IPv6 address",
    );
    // The firewall renders them (#212): a policy with IPv6 activates.
    let d = edit(
        TWO_NIC,
        json!({"policy": {"wan->lan": {"action": "drop", "rules": {
            "a": {"order": 100, "dst": "2001:db8::/32", "action": "accept"},
            "b": {"order": 200, "proto": "icmpv6", "icmp_type": ["echo-request"], "action": "accept"},
        }}}}),
    );
    assert_valid(&d);
    // Management stays IPv4's for now.
    let d = edit(
        TWO_NIC,
        json!({"management": {"sources": ["192.168.1.10", "2001:db8::10"]}}),
    );
    assert!(has_error(
        &d,
        "management.sources: management over IPv6 is not built yet"
    ));
}

/// Forwards and NAT stay IPv4: opening a port to an inside IPv6 host is a
/// policy, with no NAT (#211).
#[test]
fn forwards_stay_ipv4() {
    let d = v6(
        json!({"forwards": {"web": {"proto": "tcp", "dport": 443, "to": "192.168.1.20",
        "src": "2001:db8::/32"}}}),
    );
    assert!(history_error(&d, "forwards.web.src: IPv4 only"));
    let d = v6(json!({
        "objects": {"h6": {"type": "ipv6", "elements": ["2001:db8::1"]}},
        "forwards": {"web": {"proto": "tcp", "dport": 443, "to": "192.168.1.20", "src": "@h6"}}}));
    assert!(history_error(&d, "forwards.web.src: IPv4 only"));
}

/// The fields survive `get` and `set`, as text the CLI takes.
#[test]
fn ipv6_settings_by_path() {
    let mut v = to_value(&load(TWO_NIC));
    for a in [
        "networks.lan.ipv6.mode=delegated",
        "networks.lan.ipv6.subnet_id=2",
        "objects.nas.type=ipv6",
        r#"objects.nas.suffixes.lan=["::20"]"#,
    ] {
        let (path, value) = parse_assignment(a).unwrap_or_else(|e| panic!("{a}: {e}"));
        merge_patch(&mut v, &set_patch(&path, value).unwrap());
    }
    let d = from_value(v.clone()).unwrap();
    let lan = d.networks["lan"].ipv6.as_ref().unwrap();
    assert_eq!(
        (lan.mode, lan.subnet_id),
        (model::Ipv6Mode::Delegated, Some(2))
    );
    assert_eq!(
        get(&v, &["networks", "lan", "ipv6", "subnet_id"]),
        Some(&json!(2))
    );
    assert_eq!(d.objects["nas"].suffixes["lan"], vec!["::20".to_string()]);
}
