//! Snapshot tests from documents to rendered files, plus a real `nft -c`
//! check of every ruleset in an unprivileged user and network namespace.

use std::io::Write;
use std::process::{Command, Stdio};

use sparewall_config::identity::{BootstrapPort, Identity};
use sparewall_config::{Format, parse, validate};
use sparewall_render::{Rendered, Subsystem, nft, render, render_bootstrap};

fn example(name: &str) -> sparewall_config::Document {
    let path = format!("{}/../../examples/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap();
    let doc = parse(&text, Format::Yaml).unwrap();
    let errs = validate::errors(&validate(&doc));
    assert!(errs.is_empty(), "{errs:#?}");
    doc
}

fn snapshot(name: &str, r: &Rendered) {
    for (path, content) in &r.files {
        let snap = format!("{name}__{}", path.replace('/', "__"));
        insta::assert_snapshot!(snap, content);
    }
    insta::assert_yaml_snapshot!(format!("{name}__meta"), r.meta);
}

/// `nft -c -f` in a fresh user+network namespace, or `None` when the
/// sandbox cannot create one (then the test only checks snapshots).
fn nft_check(script: &str) -> Option<Result<(), String>> {
    let probe = Command::new("unshare")
        .args(["-rn", "true"])
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if !probe.success() || Command::new("nft").arg("--version").output().is_err() {
        eprintln!("skipping nft check: no unprivileged namespaces or nft");
        return None;
    }
    let mut child = Command::new("unshare")
        .args(["-rn", "nft", "-c", "-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    Some(if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    })
}

fn assert_nft_ok(r: &Rendered) {
    let script = &r.files[&format!("nftables/{}", nft::SCRIPT)];
    if let Some(Err(e)) = nft_check(script) {
        panic!("nft rejected the ruleset:\n{e}\n---\n{script}");
    }
}

#[test]
fn standalone() {
    let doc = example("standalone.yaml");
    let r = render(&doc, "fw1").unwrap();
    snapshot("standalone_fw1", &r);
    assert_nft_ok(&r);
}

#[test]
fn pair_both_nodes() {
    let doc = example("pair.yaml");
    for node in ["fw1", "fw2"] {
        let r = render(&doc, node).unwrap();
        snapshot(&format!("pair_{node}"), &r);
        assert_nft_ok(&r);
    }
}

/// The pair example with both sync keys: paired, with its tunnel.
fn paired() -> sparewall_config::Document {
    let mut doc = example("pair.yaml");
    doc.cluster.sync_keys.insert(
        "fw1".into(),
        "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=".into(),
    );
    doc.cluster.sync_keys.insert(
        "fw2".into(),
        "ZmVkY2JhWllYV1ZVVFNSUVBPTk1MS0pJSEdGRURDQkE=".into(),
    );
    doc
}

fn kea_ha(conf: &serde_json::Value) -> bool {
    conf["Dhcp4"]["hooks-libraries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["library"].as_str().unwrap().ends_with("libdhcp_ha.so"))
}

#[test]
fn kea_waits_for_the_pair() {
    // Unpaired (the example has no sync keys): no tunnel, so no HA, whose
    // listener binds the tunnel address; and nothing offered, so that two
    // unpaired nodes do not both hand out the same pool.
    let conf = kea_conf(&example("pair.yaml"));
    assert!(!kea_ha(&conf));
    assert_eq!(conf["Dhcp4"]["authoritative"], false);
    for s in conf["Dhcp4"]["subnet4"].as_array().unwrap() {
        assert!(s["pools"].as_array().unwrap().is_empty(), "{s}");
    }
    // Only the peer's key (the node's own is missing): still unpaired.
    let mut doc = paired();
    doc.cluster.sync_keys.remove("fw1");
    let conf = kea_conf(&doc);
    assert!(!kea_ha(&conf));
    assert_eq!(conf["Dhcp4"]["authoritative"], false);
    // HA off: the operator's choice, served without waiting.
    let mut doc = example("pair.yaml");
    doc.dhcp.as_mut().unwrap().ha = Some(sparewall_config::model::DhcpHa::Off);
    let conf = kea_conf(&doc);
    assert!(!kea_ha(&conf));
    assert_eq!(conf["Dhcp4"]["authoritative"], true);
    // Paired: HA over the tunnel, and the pools offered.
    let conf = kea_conf(&paired());
    assert!(kea_ha(&conf));
    assert_eq!(conf["Dhcp4"]["authoritative"], true);
    assert!(
        conf["Dhcp4"]["subnet4"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| !s["pools"].as_array().unwrap().is_empty())
    );
}

#[test]
fn pair_with_sync_keys_renders_tunnel() {
    let doc = paired();
    let r = render(&doc, "fw1").unwrap();
    let nd = &r.files["network/40-sparewall-swsync.netdev"];
    assert!(
        nd.contains("PublicKey=ZmVkY2JhWllYV1ZVVFNSUVBPTk1MS0pJSEdGRURDQkE="),
        "{nd}"
    );
    assert!(nd.contains("Endpoint=10.255.0.2:51871"), "{nd}");
    assert!(nd.contains("AllowedIPs=169.254.77.2/32"), "{nd}");
    let nn = &r.files["network/40-sparewall-swsync.network"];
    assert!(nn.contains("Address=169.254.77.1/30"), "{nn}");
    insta::assert_snapshot!(
        "paired_fw1__conntrackd",
        r.files["conntrackd/conntrackd.conf"]
    );
    assert!(r.meta.services.contains_key("conntrack-sync"));
    assert_nft_ok(&r);
}

#[test]
fn bootstrap_untagged_and_tagged() {
    let mut id = Identity {
        node: "fw1".into(),
        ssh_keys: vec!["ssh-ed25519 AAAA test".into()],
        password_hash: None,
        management: BootstrapPort {
            nic: "52:54:00:aa:00:01".into(),
            vlan: None,
            address: None,
            gateway: None,
            dns: vec![],
        },
    };
    let r = render_bootstrap(&id);
    snapshot("bootstrap_dhcp", &r);
    assert_nft_ok(&r);
    id.management.vlan = Some(99);
    id.management.address = Some(sparewall_config::model::Cidr(
        "10.0.99.2/24".parse().unwrap(),
    ));
    id.management.gateway = Some("10.0.99.1".parse().unwrap());
    let r = render_bootstrap(&id);
    snapshot("bootstrap_vlan_static", &r);
    assert_nft_ok(&r);
}

#[test]
fn changed_subsystems() {
    let doc = example("standalone.yaml");
    let a = render(&doc, "fw1").unwrap();
    let mut doc2 = doc.clone();
    doc2.policy.get_mut("wan->self").unwrap().action = sparewall_config::model::Action::Reject;
    let b = render(&doc2, "fw1").unwrap();
    assert_eq!(a.changed(&b), vec![Subsystem::Nft]);
    let mut doc3 = doc.clone();
    doc3.networks.get_mut("users").unwrap().mtu = Some(1400);
    let c = render(&doc3, "fw1").unwrap();
    assert_eq!(a.changed(&c), vec![Subsystem::Networkd]);
}

#[test]
fn web_runs_only_when_enabled() {
    let mut doc = example("standalone.yaml");
    let off = render(&doc, "fw1").unwrap();
    assert!(!off.meta.services.contains_key("web"));
    doc.management.web = true;
    let on = render(&doc, "fw1").unwrap();
    assert_eq!(on.meta.services["web"].unit, sparewall_render::web::UNIT);
    // No files of its own, and no new rules: HTTPS is already open where
    // the health endpoints are.
    assert_eq!(off.files, on.files);
}

#[test]
fn unknown_node_is_rejected() {
    let doc = example("standalone.yaml");
    assert!(render(&doc, "fw9").is_err());
}

#[test]
fn single_gateway_pair_has_no_sync_group() {
    let mut doc = example("pair.yaml");
    let wan = doc.networks.get_mut("wan").unwrap();
    wan.vip = None;
    wan.vrid = None;
    let r = render(&doc, "fw1").unwrap();
    let ka = &r.files["keepalived/keepalived.conf"];
    assert!(!ka.contains("vrrp_sync_group"), "{ka}");
    assert!(ka.contains("vrrp_instance VI_users"), "{ka}");
}

/// Issue #6: links that carry only replication are kept apart from the
/// ones carrying traffic, so their loss degrades health instead of
/// failing it.
#[test]
fn replication_links_are_separate() {
    // Sync as a VLAN on the shared uplink: the uplink carries traffic.
    let r = render(&example("pair.yaml"), "fw1").unwrap();
    assert_eq!(r.meta.replication_links, ["sync"]);
    assert!(r.meta.required_links.contains(&"uplink".to_string()));
    assert!(!r.meta.required_links.contains(&"sync".to_string()));

    // Sync on a dedicated port, tagged or untagged: the port too is
    // replication-only.
    let text = std::fs::read_to_string(format!(
        "{}/../../examples/pair.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    for vlan in [Some(4000), None] {
        let mut v = sparewall_config::parse_value(&text, Format::Yaml).unwrap();
        v["ports"]["fw1"]["syncp"] = serde_json::json!({"nic": "52:54:00:aa:00:09"});
        v["ports"]["fw2"]["syncp"] = serde_json::json!({"nic": "9c:6b:00:00:00:09"});
        v["networks"]["sync"]["port"] = serde_json::json!("syncp");
        v["networks"]["sync"]["vlan"] = serde_json::to_value(vlan).unwrap();
        let doc = sparewall_config::from_value(v).unwrap();
        let errs = validate::errors(&validate(&doc));
        assert!(errs.is_empty(), "{errs:#?}");
        let r = render(&doc, "fw1").unwrap();
        let want: &[&str] = if vlan.is_some() {
            &["sync", "syncp"]
        } else {
            &["syncp"]
        };
        assert_eq!(r.meta.replication_links, want, "vlan {vlan:?}");
        for l in want {
            assert!(!r.meta.required_links.contains(&l.to_string()), "{l}");
        }
        assert!(r.meta.required_links.contains(&"uplink".to_string()));
    }
}

#[test]
fn vpn_peer_preshared_key() {
    let mut doc = example("pair.yaml");
    let peer = doc
        .vpn
        .get_mut("roadwarrior")
        .unwrap()
        .peers
        .get_mut("alice-laptop")
        .unwrap();
    peer.preshared_key = Some("secret:psk-alice".into());
    let r = render(&doc, "fw1").unwrap();
    let netdev = &r.files[&format!(
        "{}/50-sparewall-roadwarrior.netdev",
        Subsystem::Networkd.dir()
    )];
    let line = format!(
        "PresharedKeyFile={}/{}",
        sparewall_render::KEY_DIR,
        sparewall_render::vpn_psk_file("roadwarrior", "alice-laptop")
    );
    assert!(netdev.contains(&line), "{netdev}");
    // Never the key itself, nor the secret's name.
    assert!(!netdev.contains("psk-alice\n"), "{netdev}");
}

#[test]
fn vpn_extra_ports_standalone_redirect() {
    let mut doc = example("standalone.yaml");
    doc.vpn.insert(
        "roadwarrior".into(),
        serde_json::from_value(serde_json::json!({
            "listen_port": 51820,
            "extra_ports": [53],
            "endpoint": "vpn.example.org",
            "addresses": ["10.99.0.1/24"],
            "zone": "users",
        }))
        .unwrap(),
    );
    let r = render(&doc, "fw1").unwrap();
    let nft = &r.files[&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT)];
    assert!(
        nft.contains(
            "iifname \"wan\" fib daddr type local udp dport 53 counter redirect to :51820 comment \"vpn-roadwarrior:extra-ports\""
        ),
        "{nft}"
    );
    assert_nft_ok(&r);
}

#[test]
fn extra_vips_standalone_are_static_addresses() {
    let mut doc = example("standalone.yaml");
    let users = doc.networks.get_mut("users").unwrap();
    users.extra_vips = vec![serde_json::from_value(serde_json::json!("192.0.2.5/24")).unwrap()];
    let r = render(&doc, "fw1").unwrap();
    let (_, network) = r
        .files
        .iter()
        .find(|(p, c)| p.ends_with(".network") && c.contains("Address=192.0.2.1/24"))
        .expect("the users .network file");
    assert!(network.contains("Address=192.0.2.5/24"), "{network}");
}

#[test]
fn pair_wan_with_public_node_addresses_routes_on_both() {
    // The pair example's WAN with public node addresses: each node has
    // its own default route, and keepalived moves none.
    let mut doc = example("pair.yaml");
    let wan = doc.networks.get_mut("wan").unwrap();
    wan.addresses = serde_json::from_value(
        serde_json::json!({"fw1": "203.0.113.2/29", "fw2": "203.0.113.3/29"}),
    )
    .unwrap();
    let r = render(&doc, "fw1").unwrap();
    let ka = &r.files[&format!(
        "{}/{}",
        Subsystem::Keepalived.dir(),
        sparewall_render::keepalived::CONF
    )];
    assert!(!ka.contains("virtual_routes"), "{ka}");
    let network = &r.files[&format!("{}/30-sparewall-wan.network", Subsystem::Networkd.dir())];
    assert!(
        network.contains("[Route]\nGateway=203.0.113.6\nMetric=100\n"),
        "{network}"
    );
    let nft = &r.files[&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT)];
    assert!(!nft.contains("infra:wan-egress"), "{nft}");
    assert!(!nft.contains("infra:peer-egress"), "{nft}");
    assert_nft_ok(&r);
}

fn kea_conf(doc: &sparewall_config::Document) -> serde_json::Value {
    let r = render(doc, "fw1").unwrap();
    let text = &r.files[&format!("{}/kea-dhcp4.conf", Subsystem::Dhcp.dir())];
    serde_json::from_str(text).unwrap()
}

fn ping_hook(conf: &serde_json::Value) -> Option<serde_json::Value> {
    conf["Dhcp4"]["hooks-libraries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| {
            h["library"]
                .as_str()
                .unwrap()
                .ends_with("libdhcp_ping_check.so")
        })
        .cloned()
}

fn subnet_ping(conf: &serde_json::Value, subnet: &str) -> Option<bool> {
    conf["Dhcp4"]["subnet4"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["subnet"] == subnet)
        .unwrap()["user-context"]["ping-check"]["enable-ping-check"]
        .as_bool()
}

#[test]
fn ping_check_default_and_overrides() {
    // On by default; the example turns it off for guests only.
    let mut doc = example("standalone.yaml");
    let conf = kea_conf(&doc);
    assert_eq!(
        ping_hook(&conf).unwrap()["parameters"]["enable-ping-check"],
        true
    );
    assert_eq!(subnet_ping(&conf, "192.0.2.0/24"), None);
    assert_eq!(subnet_ping(&conf, "198.51.100.0/24"), Some(false));

    // Off by default, on for one network: loaded, enabled there only.
    let dhcp = doc.dhcp.as_mut().unwrap();
    dhcp.ping_check = Some(false);
    dhcp.networks.get_mut("users").unwrap().ping_check = Some(true);
    dhcp.networks.get_mut("guests").unwrap().ping_check = None;
    let conf = kea_conf(&doc);
    assert_eq!(
        ping_hook(&conf).unwrap()["parameters"]["enable-ping-check"],
        false
    );
    assert_eq!(subnet_ping(&conf, "192.0.2.0/24"), Some(true));
    assert_eq!(subnet_ping(&conf, "198.51.100.0/24"), None);

    // Off everywhere: not loaded at all (Kea cannot start without its
    // ICMP socket, so nothing should depend on it).
    doc.dhcp
        .as_mut()
        .unwrap()
        .networks
        .get_mut("users")
        .unwrap()
        .ping_check = None;
    assert!(ping_hook(&kea_conf(&doc)).is_none());
}

#[test]
fn kea_binds_one_address_per_interface() {
    // Standalone, beside the gateway address: the node's own address.
    let mut doc = example("standalone.yaml");
    let users = doc.networks.get_mut("users").unwrap();
    assert!(users.vip.is_some());
    let own = users.addresses["fw1"].0.addr();
    let iface = doc.network_iface("users").unwrap().to_string();
    let bound = |doc: &sparewall_config::Document| {
        kea_conf(doc)["Dhcp4"]["interfaces-config"]["interfaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    assert!(
        bound(&doc).contains(&format!("{iface}/{own}")),
        "{:?}",
        bound(&doc)
    );
    assert!(
        bound(&doc).iter().all(|i| i.contains('/')),
        "{:?}",
        bound(&doc)
    );
    // Only the gateway address: that one.
    let users = doc.networks.get_mut("users").unwrap();
    users.addresses.clear();
    let vip = users.vip.as_ref().unwrap().0.addr();
    assert!(
        bound(&doc).contains(&format!("{iface}/{vip}")),
        "{:?}",
        bound(&doc)
    );
}

#[test]
fn hold_claims_no_gateway_address() {
    // A pair: keepalived runs, but every instance also tracks a script
    // that always fails, so all stay in FAULT.
    let mut doc = paired();
    doc.cluster.hold = true;
    let r = render(&doc, "fw1").unwrap();
    let ka = &r.files[&format!(
        "{}/{}",
        Subsystem::Keepalived.dir(),
        sparewall_render::keepalived::CONF
    )];
    assert!(ka.contains("vrrp_script sparewall_held"), "{ka}");
    let instances = ka.matches("vrrp_instance ").count();
    assert!(instances > 0);
    assert_eq!(
        ka.matches("        sparewall_held\n").count(),
        instances,
        "{ka}"
    );
    // Kea knows the subnets (HA runs) but offers nothing, and does not
    // NAK the clients of the server it sits beside.
    let kea: serde_json::Value =
        serde_json::from_str(&r.files[&format!("{}/kea-dhcp4.conf", Subsystem::Dhcp.dir())])
            .unwrap();
    assert_eq!(kea["Dhcp4"]["authoritative"], false);
    assert!(kea_ha(&kea));
    // On a WAN with private node addresses, no route via the peer: with
    // no master it would bounce between the two.
    let wan = &r.files[&format!("{}/30-sparewall-wan.network", Subsystem::Networkd.dir())];
    assert!(!wan.contains("[Route]"), "{wan}");
    for s in kea["Dhcp4"]["subnet4"].as_array().unwrap() {
        assert!(s["pools"].as_array().unwrap().is_empty(), "{s}");
        assert!(s["reservations"].as_array().unwrap().is_empty(), "{s}");
    }

    // Standalone: neither the gateway address nor an extra one is
    // installed.
    let mut doc = example("standalone.yaml");
    let users = doc.networks.get_mut("users").unwrap();
    users.extra_vips = vec![serde_json::from_value(serde_json::json!("192.0.2.5/24")).unwrap()];
    let installed = |doc: &sparewall_config::Document, a: &str| {
        render(doc, "fw1")
            .unwrap()
            .files
            .values()
            .any(|c| c.contains(&format!("Address={a}")))
    };
    assert!(installed(&doc, "192.0.2.1/24"));
    assert!(installed(&doc, "192.0.2.5/24"));
    doc.cluster.hold = true;
    assert!(!installed(&doc, "192.0.2.1/24"));
    assert!(!installed(&doc, "192.0.2.5/24"));
}

#[test]
fn pair_wan_one_lease_on_the_master() {
    // The pair example's WAN with one DHCP lease for the pair (#54).
    let mut doc = example("pair.yaml");
    let wan = doc.networks.get_mut("wan").unwrap();
    wan.dhcp_client = true;
    wan.vip = None;
    wan.extra_vips.clear();
    wan.gateway = None;
    doc.objects.insert(
        "wan_address".into(),
        serde_json::from_value(serde_json::json!({"type": "ipv4", "dynamic": {"network": "wan"}}))
            .unwrap(),
    );
    let r = render(&doc, "fw1").unwrap();
    let file = |name: &str| r.files[&format!("{}/{name}", Subsystem::Networkd.dir())].clone();
    // The WAN itself: the private address, the macvlan, the route via the
    // peer, and no DHCP client.
    let base = file("30-sparewall-wan.network");
    assert!(base.contains("Address=10.0.10.2/24\n"), "{base}");
    assert!(base.contains("MACVLAN=swwan\n"), "{base}");
    assert!(
        base.contains("[Route]\nGateway=10.0.10.3\nMetric=200\n"),
        "{base}"
    );
    assert!(!base.contains("DHCP"), "{base}");
    // No gateway address now, but switching to the lease must not strip
    // the old one from under keepalived on the master (#78).
    assert!(base.contains("KeepConfiguration=yes\n"), "{base}");
    // The lease link: the VRRP virtual MAC, down until the coordinator
    // brings it up on the master, one client ID, the lease kept.
    let nd = file("40-sparewall-swwan.netdev");
    assert!(nd.contains("Kind=macvlan\n"), "{nd}");
    assert!(nd.contains("MACAddress=00:00:5e:00:01:0a\n"), "{nd}");
    let nn = file("40-sparewall-swwan.network");
    for line in [
        "ActivationPolicy=manual\n",
        "DHCP=ipv4\n",
        "ClientIdentifier=mac\n",
        "SendRelease=no\n",
        "RouteMetric=100\n",
        "NFTSet=address:inet:sparewall:wan_address\n",
    ] {
        assert!(nn.contains(line), "{line}: {nn}");
    }
    // No keepalived instance, route or address for the WAN.
    let ka = &r.files[&format!(
        "{}/{}",
        Subsystem::Keepalived.dir(),
        sparewall_render::keepalived::CONF
    )];
    assert!(!ka.contains("VI_wan"), "{ka}");
    let nft = &r.files[&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT)];
    for line in [
        "iifname \"swwan\" udp sport 67 udp dport 68 accept comment \"infra:dhcp-client\"",
        "iifname \"wan\" oifname \"swwan\" ip saddr 10.0.10.3 counter accept comment \"infra:peer-egress\"",
        "oifname \"swwan\" ip saddr 10.0.10.0/24 counter masquerade comment \"infra:wan-egress\"",
        "iifname \"users\" oifname { \"swwan\", \"wan\" } counter masquerade comment \"nat:users->wan\"",
        "iifname \"swwan\" fib daddr type local udp dport { 53, 443 } counter redirect to :51820 comment \"vpn-roadwarrior:extra-ports\"",
    ] {
        assert!(nft.contains(line), "{line}\n{nft}");
    }
    assert_eq!(
        r.meta.set_links.get("wan_address").map(String::as_str),
        Some("swwan")
    );
    assert_nft_ok(&r);
    // Held, there is no master: no route via the peer either.
    doc.cluster.hold = true;
    let r = render(&doc, "fw1").unwrap();
    let base = &r.files[&format!("{}/30-sparewall-wan.network", Subsystem::Networkd.dir())];
    assert!(!base.contains("[Route]"), "{base}");
}

#[test]
fn forward_destination_refused_from_other_zones() {
    // #102: a zone the forward does not apply from (mgmt here) reaching
    // the forward's outside address and port must not get the node's own
    // service there: refused in input, before any zone's ->self rules.
    let doc = example("standalone.yaml");
    let r = render(&doc, "fw1").unwrap();
    let nft = &r.files[&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT)];
    let input = &nft[nft.find("chain input").unwrap()..];
    let reject = input
        .find("ip daddr @wan_address tcp dport @web counter reject with tcp reset comment \"forward:web-server:not-here\"")
        .unwrap_or_else(|| panic!("{input}"));
    let dispatch = input.find("iifname vmap").unwrap();
    assert!(reject < dispatch, "{input}");
    assert_nft_ok(&r);
}

#[test]
fn failback_is_on_request_unless_a_preempt_delay_is_set() {
    use sparewall_render::keepalived::{preferred, priority};
    let ka = |doc: &sparewall_config::Document| {
        render(doc, "fw1").unwrap().files["keepalived/keepalived.conf"].clone()
    };
    // Default: never preempt; every instance tracks the failover yield.
    let mut doc = paired();
    let conf = ka(&doc);
    let instances = conf.matches("vrrp_instance ").count();
    assert!(instances > 0);
    assert_eq!(conf.matches("    nopreempt\n").count(), instances, "{conf}");
    assert!(!conf.contains("preempt_delay"), "{conf}");
    assert!(conf.contains("vrrp_script sparewall_yield"), "{conf}");
    assert_eq!(
        conf.matches("        sparewall_yield\n").count(),
        instances,
        "{conf}"
    );
    // Opted in: preempt after the delay instead.
    doc.cluster
        .vrrp
        .get_or_insert_with(|| serde_json::from_value(serde_json::json!({})).unwrap())
        .preempt_delay_s = Some(300);
    let conf = ka(&doc);
    assert_eq!(
        conf.matches("    preempt_delay 300\n").count(),
        instances,
        "{conf}"
    );
    assert!(!conf.contains("nopreempt"), "{conf}");
    // The preferred node: the higher priority, the first listed on a tie.
    assert_eq!(preferred(&doc), Some("fw1"));
    let v = doc.cluster.vrrp.as_mut().unwrap();
    v.priority.insert("fw2".into(), 200);
    assert_eq!(priority(&doc, "fw2"), 200);
    assert_eq!(preferred(&doc), Some("fw2"));
}
