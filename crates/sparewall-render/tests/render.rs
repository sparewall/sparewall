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

/// VRRP adverts are never tracked, so the WAN egress SNAT cannot rewrite
/// a node's own adverts (#174): one rule in each direction, at raw
/// priority, on a pair only.
#[test]
fn vrrp_is_untracked_in_a_pair() {
    let rule = "ip protocol vrrp notrack comment \"infra:vrrp-notrack\"";
    let nft = |doc: &sparewall_config::Document, node: &str| {
        render(doc, node).unwrap().files[&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT)]
            .clone()
    };
    let pair = nft(&example("pair.yaml"), "fw1");
    assert!(pair.contains("infra:wan-egress"), "{pair}");
    for chain in ["prerouting_raw", "output_raw"] {
        let body = pair.split(&format!("chain {chain} {{")).nth(1).unwrap();
        let body = &body[..body.find("\n\t}").unwrap()];
        assert!(body.contains("priority raw;"), "{chain}: {body}");
        assert!(body.contains(rule), "{chain}: {body}");
    }
    let standalone = nft(&example("standalone.yaml"), "fw1");
    assert!(!standalone.contains("vrrp"), "{standalone}");
    assert!(!standalone.contains("output_raw"), "{standalone}");
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

/// A site-to-site peer (#148): its keepalive, and routes through the
/// tunnel for its networks; a road warrior gets neither.
#[test]
fn vpn_site_to_site_peer() {
    use sparewall_config::model::{Cidr, VpnPeer};
    let mut doc = example("pair.yaml");
    doc.vpn.get_mut("roadwarrior").unwrap().peers.insert(
        "office-b".into(),
        VpnPeer {
            public_key: "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=".into(),
            addresses: vec![
                Cidr("10.99.0.20/32".parse().unwrap()),
                Cidr("192.168.20.0/24".parse().unwrap()),
            ],
            endpoint: Some("office-b.example.net:51821".into()),
            keepalive: Some(25),
            preshared_key: None,
        },
    );
    let errs = validate::errors(&validate(&doc));
    assert!(errs.is_empty(), "{errs:#?}");
    let r = render(&doc, "fw2").unwrap();
    let netdev = &r.files[&format!(
        "{}/50-sparewall-roadwarrior.netdev",
        Subsystem::Networkd.dir()
    )];
    let peers: Vec<&str> = netdev.split("[WireGuardPeer]").skip(1).collect();
    let site = peers
        .iter()
        .find(|p| p.contains("Endpoint=office-b.example.net:51821"))
        .expect("the site's peer");
    assert!(
        site.contains("AllowedIPs=10.99.0.20/32,192.168.20.0/24"),
        "{site}"
    );
    assert!(site.contains("PersistentKeepalive=25"), "{site}");
    assert!(site.contains("RouteTable=main"), "{site}");
    // In a pair, WireGuard's packets route from the gateway address,
    // through a table only the master's keepalived fills.
    assert!(netdev.contains("FirewallMark=21335"), "{netdev}");
    let network = &r.files[&format!(
        "{}/50-sparewall-roadwarrior.network",
        Subsystem::Networkd.dir()
    )];
    assert!(
        network.contains("[RoutingPolicyRule]\nFirewallMark=21335\nTable=5357\n"),
        "{network}"
    );
    let ka = r
        .files
        .iter()
        .find(|(p, _)| p.ends_with("keepalived.conf"))
        .unwrap()
        .1;
    assert!(
        ka.contains("0.0.0.0/0 via 203.0.113.6 dev swwan src 203.0.113.1 table 5357 onlink"),
        "{ka}"
    );
    assert!(
        ka.contains("203.0.113.0/29 dev swwan src 203.0.113.1 table 5357"),
        "{ka}"
    );
    let alice = peers.iter().find(|p| !p.contains("Endpoint=")).unwrap();
    assert!(
        !alice.contains("RouteTable") && !alice.contains("PersistentKeepalive"),
        "{alice}"
    );
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

#[test]
fn pair_wan_static_block_without_the_virtual_mac() {
    // `vmac: false` (#194): the gateway addresses and the public route go
    // on the WAN's own link, on the nodes' own MACs, as before #176.
    let mut doc = example("pair.yaml");
    doc.networks.get_mut("wan").unwrap().vmac = false;
    let r = render(&doc, "fw1").unwrap();
    assert!(
        !r.files.keys().any(|p| p.contains("swwan")),
        "{:?}",
        r.files.keys()
    );
    let base = &r.files[&format!("{}/30-sparewall-wan.network", Subsystem::Networkd.dir())];
    assert!(!base.contains("MACVLAN"), "{base}");
    let ka = &r.files[&format!(
        "{}/{}",
        Subsystem::Keepalived.dir(),
        sparewall_render::keepalived::CONF
    )];
    assert!(!ka.contains("swwan"), "{ka}");
    assert!(ka.contains("        203.0.113.1/29 dev wan\n"), "{ka}");
    assert!(ka.contains("        203.0.113.5/29 dev wan\n"), "{ka}");
    assert!(
        ka.contains("0.0.0.0/0 via 203.0.113.6 dev wan metric 100 onlink"),
        "{ka}"
    );
    let sysctl = &r.files[&format!("{}/90-sparewall.conf", Subsystem::Sysctl.dir())];
    assert!(!sysctl.contains("swwan"), "{sysctl}");
    assert!(
        sysctl.contains("net.ipv4.conf.wan.arp_ignore = 1\n"),
        "{sysctl}"
    );
    let nft = &r.files[&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT)];
    assert!(!nft.contains("swwan"), "{nft}");
    for want in [
        "iifname \"wan\" oifname \"wan\" ip saddr 10.0.10.3 counter accept comment \"infra:peer-egress\"",
        "oifname \"wan\" ip saddr 10.0.10.0/24 ip daddr != 10.0.10.0/24 rt ip nexthop != 10.0.10.3 counter snat ip to 203.0.113.1 comment \"infra:wan-egress\"",
    ] {
        assert!(nft.contains(want), "{want}\n{nft}");
    }
    assert_nft_ok(&r);

    // The default keeps the virtual MAC.
    doc.networks.get_mut("wan").unwrap().vmac = true;
    let r = render(&doc, "fw1").unwrap();
    let ka = &r.files[&format!(
        "{}/{}",
        Subsystem::Keepalived.dir(),
        sparewall_render::keepalived::CONF
    )];
    assert!(ka.contains("        203.0.113.1/29 dev swwan\n"), "{ka}");
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
    // The lease link is down on the backup by design: tracking it would
    // hold the backup in FAULT, and it could never become the master.
    assert!(!ka.contains("swwan"), "{ka}");
    let nft = &r.files[&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT)];
    for line in [
        "iifname \"swwan\" udp sport 67 udp dport 68 accept comment \"infra:dhcp-client\"",
        "iifname \"wan\" oifname \"swwan\" ip saddr 10.0.10.3 counter accept comment \"infra:peer-egress\"",
        "oifname \"swwan\" ip saddr 10.0.10.0/24 counter masquerade comment \"infra:wan-egress\"",
        "iifname \"users\" oifname { \"swwan\", \"wan\" } counter masquerade comment \"nat:users->wan\"",
        "iifname \"swwan\" fib daddr type local udp dport { 53, 443 } counter redirect to :51820 comment \"vpn-roadwarrior:extra-ports\"",
        // The listen port itself, on the leased address.
        "iifname { \"swwan\", \"wan\" } udp dport 51820 accept comment \"service:vpn-roadwarrior\"",
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

/// #177: a two-NIC box with no VLANs. The LAN is the management network
/// too: its zone policy applies, management.sources narrows the
/// anti-lockout rule; in a pair it carries the sync tunnel as well, and
/// the isolation rule of a dedicated sync network is left out.
#[test]
fn two_nic_without_vlans() {
    let doc = example("two-nic.yaml");
    let issues = sparewall_config::validate::validate(&doc);
    assert!(
        sparewall_config::validate::errors(&issues).is_empty(),
        "{issues:?}"
    );
    let r = render(&doc, "fw1").unwrap();
    let nft = &r.files[&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT)];
    for want in [
        "iifname \"lan0\" ip saddr 192.168.1.10 tcp dport { 22, 443 } accept comment \"anti-lockout\"",
        "iifname \"lan0\" udp dport 67 accept comment \"service:dhcp\"",
        "iifname . oifname vmap { \"lan0\" . \"wan0\" : jump fwd_lan_wan }",
        "counter drop comment \"default:lan->self\"",
    ] {
        assert!(nft.contains(want), "{want}\n{nft}");
    }
    // The anti-lockout rule comes before the zone's drop.
    assert!(nft.find("anti-lockout").unwrap() < nft.find("jump in_lan").unwrap());
    assert!(
        !r.files.keys().any(|p| p.contains(".netdev")),
        "no VLANs: {:?}",
        r.files.keys()
    );
    assert_nft_ok(&r);

    let pair = example("two-nic-pair.yaml");
    let issues = sparewall_config::validate::validate(&pair);
    assert!(
        sparewall_config::validate::errors(&issues).is_empty(),
        "{issues:?}"
    );
    let mut pair = pair;
    pair.cluster.sync_keys = [
        (
            "fw1".to_string(),
            "4f5a3fNaOVfb56yjOv1jvWdAoGXT6O/4N+ySwjjQhW8=".to_string(),
        ),
        (
            "fw2".to_string(),
            "kJt7Ms2Qy07Mh7z6IFkjWlTZ6x5xlZyMfLy9JQ+Y0Ho=".to_string(),
        ),
    ]
    .into();
    let r = render(&pair, "fw1").unwrap();
    let nft = &r.files[&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT)];
    assert!(
        nft.contains("iifname \"lan0\" ip saddr 192.168.1.3 udp dport 51871 accept comment \"infra:sync-tunnel\""),
        "{nft}"
    );
    // The tunnel stays isolated; the LAN link itself is not dropped.
    assert!(
        !nft.contains("iifname \"lan0\" drop comment \"infra:sync-isolation\""),
        "{nft}"
    );
    assert!(
        nft.contains("iifname \"swsync\" drop comment \"infra:sync-isolation\""),
        "{nft}"
    );
    let tunnel = &r.files[&format!("{}/40-sparewall-swsync.netdev", Subsystem::Networkd.dir())];
    assert!(tunnel.contains("Endpoint=192.168.1.3:51871"), "{tunnel}");
    assert!(
        r.meta.required_links.contains(&"lan0".to_string()),
        "{:?}",
        r.meta
    );
    assert!(
        !r.meta.replication_links.contains(&"lan0".to_string()),
        "{:?}",
        r.meta
    );
    assert_nft_ok(&r);
}

/// `logging.remote.provider: syslog` (#147): rsyslog reads the journal and
/// forwards it over the chosen protocol; journal-upload no longer runs.
#[test]
fn syslog_forwarding() {
    use sparewall_config::model::{Logging, RemoteLog};
    use sparewall_render::logging::{SYSLOG_CA, SYSLOG_CONF, SYSLOG_UNIT, UPLOAD_CONF};
    let with = |remote: RemoteLog| {
        let mut doc = example("standalone.yaml");
        doc.logging = Some(Logging {
            group: None,
            connections: false,
            remote: Some(remote),
        });
        let errs = validate::errors(&validate(&doc));
        assert!(errs.is_empty(), "{errs:#?}");
        render(&doc, "fw1").unwrap()
    };
    let remote = |protocol: Option<&str>, tls: bool, ca: Option<&str>| RemoteLog {
        provider: Some("syslog".into()),
        destination: "logs.example.org".into(),
        protocol: protocol.map(Into::into),
        tls,
        ca: ca.map(Into::into),
        // RELP over TLS needs one; plain TCP over TLS works without.
        certificate: (protocol == Some("relp")).then(|| "secret:log-client".into()),
    };
    let file = |r: &Rendered, name: &str| {
        r.files
            .iter()
            .find(|(p, _)| p.ends_with(&format!("/{name}")))
            .map(|(_, c)| c.clone())
    };

    let udp = with(remote(None, false, None));
    let conf = file(&udp, SYSLOG_CONF).expect("rsyslog.conf");
    assert!(conf.contains(r#"type="omfwd""#) && conf.contains(r#"protocol="udp""#));
    assert!(conf.contains(r#"port="514""#));
    assert!(!conf.contains("StreamDriver"));
    assert_eq!(udp.meta.services["log-forwarding"].unit, SYSLOG_UNIT);
    assert!(file(&udp, UPLOAD_CONF).is_none());
    assert!(file(&udp, SYSLOG_CA).is_none());

    let tls = with(remote(Some("tcp"), true, None));
    let conf = file(&tls, SYSLOG_CONF).unwrap();
    assert!(conf.contains(r#"port="6514""#));
    assert!(conf.contains(r#"StreamDriverPermittedPeers="logs.example.org""#));
    assert!(conf.contains(r#"StreamDriver.CAFile="/etc/pki/tls/certs/ca-bundle.crt""#));
    assert!(!conf.contains("StreamDriver.CertFile"));

    const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
    let relp = with(remote(Some("relp"), true, Some(PEM)));
    let conf = file(&relp, SYSLOG_CONF).unwrap();
    assert!(conf.contains(r#"tls.caCert="/run/sparewall/logging/syslog-ca.pem""#));
    assert!(conf.contains(r#"tls.myPrivKey="/run/sparewall/secrets/syslog-client.key""#));
    assert_eq!(file(&relp, SYSLOG_CA).unwrap(), format!("{PEM}\n"));
    insta::assert_snapshot!("syslog_relp_tls", conf);
}

/// A local Prometheus (#145): rendered only with `metrics.mode: local`,
/// scraping this node's coordinator over loopback, with the document's
/// retention or the defaults; a management service, reloaded on change
/// and checked with promtool.
#[test]
fn local_metrics() {
    use sparewall_config::model::{Metrics, MetricsMode};
    use sparewall_render::metrics::{CONF, UNIT};
    let with = |m: Option<Metrics>| {
        let mut doc = example("pair.yaml");
        doc.metrics = m;
        let errs = validate::errors(&validate(&doc));
        assert!(errs.is_empty(), "{errs:#?}");
        render(&doc, "fw2").unwrap()
    };
    let conf = |r: &Rendered| r.files.get(&format!("metrics/{CONF}")).cloned();
    let mode = |mode| Metrics {
        mode,
        retention: None,
        retention_size: None,
    };
    for m in [
        None,
        Some(mode(MetricsMode::External)),
        Some(mode(MetricsMode::Off)),
    ] {
        let r = with(m);
        assert!(conf(&r).is_none());
        assert!(!r.meta.services.contains_key("metrics"));
    }
    let r = with(Some(mode(MetricsMode::Local)));
    let c = conf(&r).expect("prometheus.yml");
    assert!(c.contains("      time: 15d\n      size: 1GB\n"), "{c}");
    assert!(c.contains("targets: [\"127.0.0.1:443\"]"), "{c}");
    assert!(c.contains("instance: fw2"), "{c}");
    let s = &r.meta.services["metrics"];
    assert_eq!(s.unit, UNIT);
    assert!(s.management && s.reload);
    assert_eq!(s.check.as_ref().unwrap().command[0], "promtool");
    let r = with(Some(Metrics {
        retention: Some("30d".into()),
        retention_size: Some("512MB".into()),
        ..mode(MetricsMode::Local)
    }));
    insta::assert_snapshot!("local_metrics", conf(&r).unwrap());
}

/// A WireGuard client (#149): its netdev and table, the rules for the
/// routed networks, the kill switch and source, the routed networks'
/// DNS; in a pair, up on the master only.
#[test]
fn vpn_client() {
    use sparewall_config::model::{Cidr, VpnClient, VpnClientPeer, VpnClientRoute, Zone};
    let with = |example_file: &str, kill_switch: bool| {
        let mut doc = example(example_file);
        let routed = if doc.networks.contains_key("users") {
            "users"
        } else {
            "lan"
        };
        doc.zones.insert("egress".into(), Zone { networks: vec![] });
        doc.vpn_clients.insert(
            "egress".into(),
            VpnClient {
                private_key: "secret:provider-key".into(),
                addresses: vec![Cidr("10.64.12.34/32".parse().unwrap())],
                zone: "egress".into(),
                peer: VpnClientPeer {
                    public_key: "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=".into(),
                    endpoint: "nl1.provider.example:51820".into(),
                    keepalive: None,
                    preshared_key: None,
                },
                dns: vec!["10.64.0.1".parse().unwrap()],
                route: VpnClientRoute {
                    networks: vec![routed.into()],
                    kill_switch,
                },
            },
        );
        let errs = validate::errors(&validate(&doc));
        assert!(errs.is_empty(), "{errs:#?}");
        (render(&doc, "fw1").unwrap(), doc)
    };
    let (r, doc) = with("pair.yaml", true);
    let f = |name: &str| r.files[&format!("{}/{name}", Subsystem::Networkd.dir())].clone();
    let netdev = f("50-sparewall-egress.netdev");
    for line in [
        "PrivateKeyFile=/run/systemd/network/sparewall-vpnc-egress.key",
        "AllowedIPs=0.0.0.0/0",
        "Endpoint=nl1.provider.example:51820",
        "PersistentKeepalive=25",
        "RouteTable=5360",
    ] {
        assert!(netdev.contains(line), "{line}: {netdev}");
    }
    let network = f("50-sparewall-egress.network");
    assert!(network.contains("ActivationPolicy=manual"), "{network}");
    let users = doc.network_iface("users").unwrap();
    assert!(
        network.contains(&format!(
            "[RoutingPolicyRule]\nIncomingInterface={users}\nTable=main\nSuppressPrefixLength=0\nPriority=2000\n"
        )),
        "{network}"
    );
    assert!(
        network.contains(&format!(
            "[RoutingPolicyRule]\nIncomingInterface={users}\nTable=5360\nPriority=2001\n"
        )),
        "{network}"
    );
    let nft = r
        .files
        .iter()
        .find(|(p, _)| p.ends_with("sparewall.nft"))
        .unwrap()
        .1;
    assert!(
        nft.contains(&format!(
            "iifname \"{users}\" oifname {{ \"swwan\", \"wan\" }} counter drop comment \"vpn-client-egress:kill-switch\""
        )),
        "{nft}"
    );
    assert!(
        nft.contains(
            "oifname \"egress\" counter snat ip to 10.64.12.34 comment \"vpn-client-egress:source\""
        ),
        "{nft}"
    );
    let kea = r
        .files
        .iter()
        .find(|(p, _)| p.ends_with("kea-dhcp4.conf"))
        .unwrap()
        .1;
    assert!(kea.contains("\"data\": \"10.64.0.1\""), "{kea}");
    // Without the kill switch; and standalone, always up.
    let (r, _) = with("pair.yaml", false);
    assert!(!r.files.values().any(|c| c.contains("kill-switch")));
    let (r, _) = with("standalone.yaml", true);
    let network = &r.files[&format!("{}/50-sparewall-egress.network", Subsystem::Networkd.dir())];
    assert!(!network.contains("ActivationPolicy"), "{network}");
}

/// A two-NIC box whose WAN asks for a prefix by DHCPv6, with a static /64
/// on a second inside network (#212): a document validation keeps in
/// history (activating IPv6 on networks waits for #213 and #214).
fn ipv6_two_nic() -> sparewall_config::Document {
    let text = std::fs::read_to_string(format!(
        "{}/../../examples/two-nic.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut v = sparewall_config::to_value(&parse(&text, Format::Yaml).unwrap());
    sparewall_config::merge_patch(
        &mut v,
        &serde_json::json!({
            "ports": {"fw1": {"lab0": {"nic": "52:54:00:aa:00:03"}}},
            "networks": {
                "wan": {"ipv6": {"mode": "dhcpv6", "prefix_length": 56}},
                "lan": {"ipv6": {"mode": "delegated", "subnet_id": 1}},
                "lab": {"port": "lab0", "addresses": {"fw1": "192.168.2.1/24"},
                    "ipv6": {"mode": "static", "prefix": "2001:db8:0:2::/64"}},
            },
            "zones": {"lab": {"networks": ["lab"]}},
            "objects": {
                "nas": {"type": "ipv6", "elements": ["2001:db8:ffff::5"],
                    "suffixes": {"lab": ["::20"], "lan": ["::30"]}},
                "nas4": {"type": "ipv4", "elements": ["192.168.2.20"]},
                "wan6": {"type": "ipv6", "dynamic": {"network": "wan"}},
                "lab6": {"type": "ipv6", "dynamic": {"network": "lab", "source": "prefix"}},
            },
            "policy": {
                "lab->wan": {"action": "accept", "nat": "masquerade"},
                "wan->lab": {"action": "drop", "rules": {
                    "nas-https": {"order": 100, "proto": "tcp", "dport": 443,
                        "dst": ["@nas4", "@nas"], "action": "accept"},
                    "ping6": {"order": 200, "proto": "icmpv6",
                        "icmp_type": ["echo-request"], "action": "accept"},
                    "ping4": {"order": 300, "proto": "icmp",
                        "icmp_type": ["echo-request"], "action": "accept"},
                    "ssh": {"order": 400, "proto": "tcp", "dport": 22, "action": "drop"},
                    "doc6": {"order": 500, "src": ["198.51.100.0/24", "2001:db8:beef::/48"],
                        "dst": "2001:db8:0:2::/64", "action": "reject"},
                }},
            },
        }),
    );
    let doc = sparewall_config::from_value(v).unwrap();
    let errs = validate::errors(&sparewall_config::validate::validate_history(&doc));
    assert!(errs.is_empty(), "{errs:#?}");
    doc
}

#[test]
fn ipv6_firewall() {
    let doc = ipv6_two_nic();
    let r = render(&doc, "fw1").unwrap();
    let nft = &r.files[&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT)];
    insta::assert_snapshot!("ipv6_two_nic_fw1__nft", nft);
    for want in [
        // Objects: static elements, a static prefix's hosts by suffix (a
        // delegated one's waits for the prefix, #214), and dynamic ones.
        "elements = { 2001:db8:ffff::5, 2001:db8:0:2::20 }",
        "elements = { 2001:db8:0:2::/64 }",
        // Neighbour discovery everywhere, router solicitations from the
        // inside, advertisements from the WAN that learns from them.
        "icmpv6 type nd-neighbor-solicit icmpv6 code 0 ip6 hoplimit 255 ip6 saddr != ff00::/8 accept comment \"ipv6-nd\"",
        "icmpv6 type nd-neighbor-advert icmpv6 code 0 ip6 hoplimit 255 ip6 saddr != { ::, ff00::/8 } accept comment \"ipv6-nd\"",
        "iifname { \"lab0\", \"lan0\" } icmpv6 type nd-router-solicit icmpv6 code 0 ip6 hoplimit 255 accept",
        "iifname \"wan0\" icmpv6 type nd-router-advert icmpv6 code 0 ip6 saddr fe80::/10 ip6 hoplimit 255 accept",
        "meta nfproto ipv6 iifname != { \"lo\", \"lab0\", \"lan0\", \"wan0\" } drop comment \"ipv6-off\"",
        "meta nfproto ipv6 iifname != { \"lab0\", \"lan0\", \"wan0\" } drop comment \"ipv6-off\"",
        "meta nfproto ipv6 oifname != { \"lab0\", \"lan0\", \"wan0\" } drop comment \"ipv6-off\"",
        "iifname \"wan0\" udp sport 547 udp dport 546 accept comment \"infra:dhcpv6-client\"",
        "icmpv6 type echo-request limit rate over 50/second burst 100 packets drop comment \"icmpv6-flood\"",
        // Management and NAT stay IPv4.
        "iifname \"lan0\" meta nfproto ipv4 ip saddr 192.168.1.10 tcp dport { 22, 443 } accept comment \"anti-lockout\"",
        "iifname \"lab0\" oifname \"wan0\" meta nfproto ipv4 counter masquerade comment \"nat:lab->wan\"",
        // A rule per family its addresses allow.
        "ip daddr @nas4 tcp dport 443 counter accept comment \"rule:wan->lab:nas-https\"",
        "ip6 daddr @nas tcp dport 443 counter accept comment \"rule:wan->lab:nas-https\"",
        "icmpv6 type echo-request counter accept comment \"rule:wan->lab:ping6\"",
        "icmp type echo-request counter accept comment \"rule:wan->lab:ping4\"",
        "tcp dport 22 counter drop comment \"rule:wan->lab:ssh\"",
        "ip6 saddr 2001:db8:beef::/48 ip6 daddr 2001:db8:0:2::/64 counter reject comment \"rule:wan->lab:doc6\"",
    ] {
        assert!(nft.contains(want), "{want}\n{nft}");
    }
    // The IPv4 source of a rule whose destination is IPv6 only is no line
    // of its own; nor does the old blanket drop remain.
    assert!(!nft.contains("198.51.100.0/24"), "{nft}");
    assert!(!nft.contains("meta nfproto ipv6 drop\n"), "{nft}");
    // IPv6 on a link without it is dropped before the state rule, in
    // input and forward, so not even a flow conntrack knows carries on.
    for chain in ["chain input {", "chain forward {"] {
        let body = &nft[nft.find(chain).unwrap()..];
        let body = &body[..body.find("\n\t}").unwrap()];
        let off = body
            .find("ipv6-off")
            .unwrap_or_else(|| panic!("{chain}: no ipv6-off"));
        let state = body.find("ct state vmap").unwrap();
        assert!(
            off < state,
            "{chain}: ipv6-off after the state rule\n{body}"
        );
        // And neighbour discovery and router solicitations and
        // advertisements before both, in input: conntrack makes no
        // connection for them, so the state rule would drop them as
        // invalid (#213).
        if chain == "chain input {" {
            for nd in ["ipv6-nd", "ipv6-router-solicit", "ipv6-router-advert"] {
                assert!(body.find(nd).unwrap() < off, "{nd}\n{body}");
            }
        }
    }
    // The ipv6 dynamic object a lease fills is kept across activations.
    assert!(
        r.meta.preserved_sets.contains(&"wan6".to_string()),
        "{:?}",
        r.meta
    );
    assert_nft_ok(&r);
}

/// A standalone node's WAN with IPv6 (#213), from the two-NIC example.
fn ipv6_wan(ipv6: serde_json::Value) -> Rendered {
    let text = std::fs::read_to_string(format!(
        "{}/../../examples/two-nic.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut v = sparewall_config::to_value(&parse(&text, Format::Yaml).unwrap());
    sparewall_config::merge_patch(
        &mut v,
        &serde_json::json!({
            "networks": {"wan": {"ipv6": ipv6}},
            "objects": {
                "wan6": {"type": "ipv6", "dynamic": {"network": "wan"}},
                "wan6net": {"type": "ipv6", "dynamic": {"network": "wan", "source": "prefix"}},
            },
        }),
    );
    let doc = sparewall_config::from_value(v).unwrap();
    let errs = validate::errors(&validate(&doc));
    assert!(errs.is_empty(), "{errs:#?}");
    let r = render(&doc, "fw1").unwrap();
    assert_nft_ok(&r);
    r
}

fn wan_network(r: &Rendered) -> &str {
    let (_, f) = r
        .files
        .iter()
        .find(|(p, _)| p.starts_with("network/") && p.ends_with("-wan0.network"))
        .unwrap_or_else(|| panic!("no WAN .network in {:?}", r.files.keys()));
    f
}

#[test]
fn ipv6_wan_dhcpv6() {
    let r = ipv6_wan(serde_json::json!({"mode": "dhcpv6"}));
    let wan = wan_network(&r);
    insta::assert_snapshot!("ipv6_wan_dhcpv6__wan", wan);
    for want in [
        "IPv6AcceptRA=yes",
        "[IPv6AcceptRA]\nDHCPv6Client=always\nUseDNS=yes\nRouteMetric=100\nNFTSet=address:inet:sparewall:wan6 prefix:inet:sparewall:wan6net\n",
        "[DHCPv6]\nDUIDType=link-layer\nUseDelegatedPrefix=yes\nPrefixDelegationHint=::/56\nUseDNS=yes\nSendHostname=no\nNFTSet=address:inet:sparewall:wan6\n",
    ] {
        assert!(wan.contains(want), "{want:?}\n{wan}");
    }
    assert!(!wan.contains("IPv6AcceptRA=no"), "{wan}");
    // A WAN alone routes nothing: forwarding stays off until an inside
    // network has IPv6 (#214).
    let sysctl = &r.files[&format!("{}/90-sparewall.conf", Subsystem::Sysctl.dir())];
    assert!(
        sysctl.contains("net.ipv6.conf.all.forwarding = 0"),
        "{sysctl}"
    );
    // The sets the DHCPv6 client and the RAs fill are kept.
    for s in ["wan6", "wan6net"] {
        assert!(
            r.meta.preserved_sets.contains(&s.to_string()),
            "{:?}",
            r.meta
        );
    }
    // A /60, asked for.
    let r = ipv6_wan(serde_json::json!({"mode": "dhcpv6", "prefix_length": 60}));
    assert!(wan_network(&r).contains("PrefixDelegationHint=::/60"));
}

#[test]
fn ipv6_wan_ra_and_static() {
    let r = ipv6_wan(serde_json::json!({"mode": "ra"}));
    let wan = wan_network(&r);
    assert!(wan.contains("IPv6AcceptRA=yes"), "{wan}");
    assert!(wan.contains("[IPv6AcceptRA]\nDHCPv6Client=no\n"), "{wan}");
    assert!(!wan.contains("[DHCPv6]"), "{wan}");

    let r = ipv6_wan(
        serde_json::json!({"mode": "static", "prefix": "2001:db8:ffff::/64",
        "addresses": {"fw1": "2001:db8:ffff::2"}, "gateway": "fe80::1"}),
    );
    let wan = wan_network(&r);
    assert!(wan.contains("Address=2001:db8:ffff::2/64"), "{wan}");
    assert!(wan.contains("IPv6AcceptRA=no"), "{wan}");
    assert!(
        wan.contains("[Route]\nGateway=fe80::1\nMetric=100\n"),
        "{wan}"
    );
    // The document states the address and prefix: elements, not a fill.
    let nft = &r.files[&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT)];
    assert!(nft.contains("elements = { 2001:db8:ffff::2 }"), "{nft}");
    assert!(nft.contains("elements = { 2001:db8:ffff::/64 }"), "{nft}");
}

/// Inside networks with IPv6 (#214): the two-NIC example's LAN takes
/// subnet 1 of the WAN's delegated prefix, and a lab a static /64.
fn ipv6_inside() -> Rendered {
    let text = std::fs::read_to_string(format!(
        "{}/../../examples/two-nic.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut v = sparewall_config::to_value(&parse(&text, Format::Yaml).unwrap());
    sparewall_config::merge_patch(
        &mut v,
        &serde_json::json!({
            "ports": {"fw1": {"lab0": {"nic": "52:54:00:aa:00:03"}}},
            "networks": {
                "wan": {"ipv6": {"mode": "dhcpv6"}},
                "lan": {"ipv6": {"mode": "delegated", "subnet_id": 1}},
                "lab": {"port": "lab0", "addresses": {"fw1": "192.168.2.1/24"},
                    "ipv6": {"mode": "static", "prefix": "2001:db8:0:2::/64"}},
            },
            "zones": {"lab": {"networks": ["lab"]}},
            "dhcp": {"lab": {"pool": "192.168.2.100-192.168.2.199"}},
            "objects": {
                "lan6": {"type": "ipv6", "dynamic": {"network": "lan", "source": "prefix"}},
                "fw6": {"type": "ipv6", "dynamic": {"network": "lab"}},
                "nas": {"type": "ipv6", "suffixes": {"lab": ["::20"]}},
            },
        }),
    );
    let doc = sparewall_config::from_value(v).unwrap();
    let errs = validate::errors(&validate(&doc));
    assert!(errs.is_empty(), "{errs:#?}");
    let r = render(&doc, "fw1").unwrap();
    assert_nft_ok(&r);
    r
}

fn network_file<'a>(r: &'a Rendered, link: &str) -> &'a str {
    r.files
        .iter()
        .find(|(p, _)| p.starts_with("network/") && p.ends_with(&format!("-{link}.network")))
        .map(|(_, f)| f.as_str())
        .unwrap_or_else(|| panic!("no {link}.network in {:?}", r.files.keys()))
}

#[test]
fn ipv6_inside_networks() {
    let r = ipv6_inside();
    let lan = network_file(&r, "lan0");
    insta::assert_snapshot!("ipv6_inside__lan", lan);
    for want in [
        "DHCPPrefixDelegation=yes\nIPv6SendRA=yes\n",
        "IPv6AcceptRA=no",
        // The node serves DNS on the LAN: named by its link-local address,
        // which a new prefix does not change; the search domain is DHCP's.
        "[IPv6SendRA]\nEmitDNS=yes\nDNS=_link_local\nEmitDomains=yes\nDomains=home.arpa\n",
        "[DHCPPrefixDelegation]\nUplinkInterface=wan0\nSubnetId=0x1\nAnnounce=yes\nAssign=yes\nToken=static:::1\nNFTSet=prefix:inet:sparewall:lan6\n",
    ] {
        assert!(lan.contains(want), "{want:?}\n{lan}");
    }
    let lab = network_file(&r, "lab0");
    for want in [
        "Address=2001:db8:0:2::1/64",
        "IPv6SendRA=yes",
        "[IPv6SendRA]\nEmitDNS=yes\nDNS=2001:db8:0:2::1\n",
        "[IPv6Prefix]\nPrefix=2001:db8:0:2::/64\n",
    ] {
        assert!(lab.contains(want), "{want:?}\n{lab}");
    }
    assert!(!lab.contains("DHCPPrefixDelegation"), "{lab}");
    // The node routes IPv6 now.
    let sysctl = &r.files[&format!("{}/90-sparewall.conf", Subsystem::Sysctl.dir())];
    assert!(
        sysctl.contains("net.ipv6.conf.all.forwarding = 1"),
        "{sysctl}"
    );
    // Unbound answers over IPv6 on every address (a delegated network's
    // change), to whoever the firewall lets through.
    let unbound = r
        .files
        .iter()
        .find(|(p, _)| p.ends_with("unbound.conf"))
        .map(|(_, f)| f.as_str())
        .unwrap();
    for want in [
        "interface: ::0\n",
        "do-ip6: yes\n",
        "access-control: ::0/0 allow\n",
    ] {
        assert!(unbound.contains(want), "{want:?}\n{unbound}");
    }
    // Objects: the lab's own address and a host by suffix are elements;
    // the LAN's prefix is networkd's to fill.
    let nft = &r.files[&format!("{}/{}", Subsystem::Nft.dir(), nft::SCRIPT)];
    assert!(nft.contains("elements = { 2001:db8:0:2::1 }"), "{nft}");
    assert!(nft.contains("elements = { 2001:db8:0:2::20 }"), "{nft}");
    assert!(
        r.meta.preserved_sets.contains(&"lan6".to_string()),
        "{:?}",
        r.meta
    );
}

/// With only static prefixes, Unbound allows just them, link-local and
/// loopback.
#[test]
fn ipv6_unbound_static_only() {
    let text = std::fs::read_to_string(format!(
        "{}/../../examples/two-nic.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut v = sparewall_config::to_value(&parse(&text, Format::Yaml).unwrap());
    sparewall_config::merge_patch(
        &mut v,
        &serde_json::json!({"networks": {"lan": {"ipv6": {"mode": "static", "prefix": "2001:db8:0:1::/64"}}}}),
    );
    let doc = sparewall_config::from_value(v).unwrap();
    let r = render(&doc, "fw1").unwrap();
    let unbound = r
        .files
        .iter()
        .find(|(p, _)| p.ends_with("unbound.conf"))
        .map(|(_, f)| f.as_str())
        .unwrap();
    assert!(
        unbound.contains("    access-control: ::0/0 refuse\n    access-control: ::1 allow\n    access-control: fe80::/10 allow\n    access-control: 2001:db8:0:1::/64 allow\n"),
        "{unbound}"
    );
    assert!(!unbound.contains("::0/0 allow"), "{unbound}");
}

/// The router advertisements name the node as the resolver only where
/// DHCPv4 does (#214): not without `dns`, and not where the network's DHCP
/// options name other servers (a directory's, say), so IPv6 never sends
/// clients past them.
#[test]
fn ipv6_ras_name_the_node_only_where_dhcp_does() {
    let lan = |patch: serde_json::Value| {
        let text = std::fs::read_to_string(format!(
            "{}/../../examples/two-nic.yaml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let mut v = sparewall_config::to_value(&parse(&text, Format::Yaml).unwrap());
        sparewall_config::merge_patch(
            &mut v,
            &serde_json::json!({"networks": {
                "wan": {"ipv6": {"mode": "dhcpv6"}},
                "lan": {"ipv6": {"mode": "delegated", "subnet_id": 1}},
            }}),
        );
        sparewall_config::merge_patch(&mut v, &patch);
        let doc = sparewall_config::from_value(v).unwrap();
        let r = render(&doc, "fw1").unwrap();
        network_file(&r, "lan0").to_string()
    };
    assert!(lan(serde_json::json!({})).contains("EmitDNS=yes\nDNS=_link_local\n"));
    // No resolver on the node.
    let f = lan(serde_json::json!({"dns": null}));
    assert!(f.contains("[IPv6SendRA]\nEmitDNS=no\n"), "{f}");
    // The node resolves, but DHCP hands the LAN other servers.
    let f = lan(
        serde_json::json!({"dhcp": {"lan": {"options": {"dns": ["192.168.1.5", "192.168.1.6"]}}}}),
    );
    assert!(f.contains("[IPv6SendRA]\nEmitDNS=no\n"), "{f}");
    assert!(!f.contains("DNS=_link_local"), "{f}");
}
