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

#[test]
fn pair_with_sync_keys_renders_tunnel() {
    let mut doc = example("pair.yaml");
    doc.cluster.sync_keys.insert(
        "fw1".into(),
        "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=".into(),
    );
    doc.cluster.sync_keys.insert(
        "fw2".into(),
        "ZmVkY2JhWllYV1ZVVFNSUVBPTk1MS0pJSEdGRURDQkE=".into(),
    );
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
