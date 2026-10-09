//! The apply/confirm/rollback state machine against a fake system.

use serde_json::{Value, json};
use sparewall_config::identity::{BootstrapPort, Identity};
use sparewall_core::system::Fake;
use sparewall_core::{ApplyOptions, Coordinator, Error, Event, Level, Store};

fn identity() -> Identity {
    Identity {
        node: "fw1".into(),
        ssh_keys: vec![],
        management: BootstrapPort {
            nic: "52:54:00:aa:00:01".into(),
            vlan: None,
            address: None,
            gateway: None,
            dns: vec![],
        },
    }
}

fn example() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/standalone.yaml"
    ))
    .unwrap();
    sparewall_config::parse_value(&text, sparewall_config::Format::Yaml).unwrap()
}

struct T {
    _dir: tempfile::TempDir,
    c: Coordinator<Fake>,
}

fn setup() -> T {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let mut c = Coordinator::new(store, Fake::default(), identity());
    c.boot(false).unwrap();
    T { _dir: dir, c }
}

fn opts(base: u64, confirm: Option<u32>) -> ApplyOptions {
    ApplyOptions {
        base,
        confirm_seconds: confirm,
        author: "test".into(),
        dry_run: false,
    }
}

#[test]
fn boots_into_bootstrap() {
    let mut t = setup();
    assert_eq!(t.c.active().unwrap(), 0);
    let body = t.c.system().nft_body.clone().unwrap();
    assert!(body.contains("anti-lockout"), "{body}");
    assert!(t.c.system().network.contains_key("10-sparewall-mgmt0.link"));
    let h = t.c.health().unwrap();
    assert_eq!(h.check("generation").unwrap().level, Level::Degraded);
    assert_eq!(h.check("nft").unwrap().level, Level::Ok);
}

#[test]
fn apply_confirm_and_history() {
    let mut t = setup();
    let r = t.c.apply(example(), &opts(0, Some(120))).unwrap();
    assert_eq!(r.generation.id, 1);
    assert_eq!(r.generation.base, Some(0));
    assert!(r.changed.contains(&"nftables".to_string()));
    assert!(!r.diff.is_empty());
    let st = t.c.state().unwrap();
    assert_eq!((st.active, st.confirmed), (1, 0));
    assert!(st.pending.is_some());
    assert_eq!(
        t.c.health().unwrap().check("confirm").unwrap().level,
        Level::Degraded
    );
    t.c.confirm(1).unwrap();
    let st = t.c.state().unwrap();
    assert_eq!((st.active, st.confirmed, st.pending), (1, 1, None));
    assert_eq!(t.c.history(None).unwrap().len(), 1);
    let ev = t.c.drain_events();
    assert!(matches!(
        ev[0],
        Event::Applied {
            id: 1,
            pending: true,
            ..
        }
    ));
    assert_eq!(ev[1], Event::Confirmed { id: 1 });
}

#[test]
fn stale_base_conflicts() {
    let mut t = setup();
    t.c.apply(example(), &opts(0, None)).unwrap();
    let mut v = example();
    v["policy"]["wan->self"]["action"] = json!("reject");
    match t.c.apply(v, &opts(0, None)) {
        Err(Error::Conflict { current: 1 }) => {}
        other => panic!("expected conflict, got {other:?}"),
    }
}

#[test]
fn unchanged_document_is_a_noop() {
    let mut t = setup();
    t.c.apply(example(), &opts(0, None)).unwrap();
    let r = t.c.apply(example(), &opts(1, None)).unwrap();
    assert!(r.unchanged);
    assert_eq!(r.generation.id, 1);
    assert_eq!(t.c.history(None).unwrap().len(), 1);
}

#[test]
fn missed_confirm_reverts() {
    let mut t = setup();
    t.c.apply(example(), &opts(0, None)).unwrap();
    let mut v = example();
    v["policy"]["wan->self"]["action"] = json!("reject");
    t.c.apply(v, &opts(1, Some(60))).unwrap();
    assert_eq!(t.c.active().unwrap(), 2);
    let now = jiff::Timestamp::now().as_second();
    assert_eq!(t.c.tick(now).unwrap(), None);
    assert_eq!(t.c.tick(now + 61).unwrap(), Some(1));
    let st = t.c.state().unwrap();
    assert_eq!((st.active, st.confirmed, st.pending), (1, 1, None));
    let body = t.c.system().nft_body.clone().unwrap();
    assert!(
        body.contains("counter drop comment \"default:wan->self\""),
        "{body}"
    );
}

#[test]
fn first_apply_unconfirmed_returns_to_bootstrap() {
    let mut t = setup();
    t.c.apply(example(), &opts(0, Some(30))).unwrap();
    let now = jiff::Timestamp::now().as_second();
    assert_eq!(t.c.tick(now + 31).unwrap(), Some(0));
    assert_eq!(t.c.active().unwrap(), 0);
    assert!(
        t.c.system()
            .nft_body
            .as_ref()
            .unwrap()
            .contains("bootstrap:ping")
    );
}

#[test]
fn stacked_pending_changes_revert_to_last_confirmed() {
    let mut t = setup();
    t.c.apply(example(), &opts(0, None)).unwrap();
    let mut v = example();
    v["policy"]["wan->self"]["action"] = json!("reject");
    t.c.apply(v.clone(), &opts(1, Some(60))).unwrap();
    v["policy"]["users->wan"]["action"] = json!("drop");
    t.c.apply(v, &opts(2, Some(60))).unwrap();
    assert!(matches!(t.c.confirm(2), Err(Error::NotPending(2))));
    let now = jiff::Timestamp::now().as_second();
    assert_eq!(t.c.tick(now + 61).unwrap(), Some(1));
}

#[test]
fn reboot_during_window_reverts() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut c = Coordinator::new(
            Store::open(dir.path()).unwrap(),
            Fake::default(),
            identity(),
        );
        c.boot(false).unwrap();
        c.apply(example(), &opts(0, None)).unwrap();
        let mut v = example();
        v["policy"]["wan->self"]["action"] = json!("reject");
        c.apply(v, &opts(1, Some(600))).unwrap();
    }
    let mut c = Coordinator::new(
        Store::open(dir.path()).unwrap(),
        Fake::default(),
        identity(),
    );
    assert_eq!(c.boot(false).unwrap(), 1);
    assert!(c.state().unwrap().pending.is_none());
    assert!(matches!(
        c.drain_events()[0],
        Event::RolledBack { to: 1, from: 2, .. }
    ));
}

#[test]
fn rollback_to_base_and_to_id() {
    let mut t = setup();
    t.c.apply(example(), &opts(0, None)).unwrap();
    let mut v = example();
    v["policy"]["wan->self"]["action"] = json!("reject");
    t.c.apply(v, &opts(1, None)).unwrap();
    let g = t.c.rollback(None).unwrap();
    assert_eq!(g.id, 1);
    assert_eq!(t.c.active().unwrap(), 1);
    let g = t.c.rollback(Some(2)).unwrap();
    assert_eq!(g.id, 2);
    assert!(matches!(t.c.rollback(Some(9)), Err(Error::NotFound(9))));
    // A new change after a rollback gets a fresh id and records its base.
    let mut v = example();
    v["policy"]["users->wan"]["action"] = json!("reject");
    let r = t.c.apply(v, &opts(2, None)).unwrap();
    assert_eq!((r.generation.id, r.generation.base), (3, Some(2)));
}

#[test]
fn merge_and_patch() {
    let mut t = setup();
    t.c.apply(example(), &opts(0, None)).unwrap();
    let r =
        t.c.merge(
            &json!({"networks": {"users": {"mtu": 1400}}}),
            &opts(1, None),
        )
        .unwrap();
    assert_eq!(r.changed, ["network"]);
    let r =
        t.c.patch(
            &json!([{"op": "replace", "path": "/policy/wan->self/action", "value": "reject"}]),
            &opts(2, None),
        )
        .unwrap();
    assert_eq!(r.changed, ["nftables"]);
    assert_eq!(r.diff, ["~ policy.'wan->self'.action = \"reject\""]);
}

#[test]
fn validation_and_dry_run_failures_change_nothing() {
    let mut t = setup();
    let mut v = example();
    v["zones"]["users"]["networks"] = json!(["nope"]);
    assert!(matches!(
        t.c.apply(v, &opts(0, None)),
        Err(Error::Validation(_))
    ));
    let mut v = example();
    v["cluster"]["nodes"] = json!(["fw2"]);
    v["ports"] = json!({"fw2": {"uplink": {"nic": "52:54:00:aa:00:01"}}});
    v["networks"]["mgmt"]["addresses"] = json!({"fw2": "10.0.99.2/24"});
    v["networks"]["users"]["addresses"] = json!({"fw2": "192.0.2.2/24"});
    v["networks"]["guests"]["addresses"] = json!({"fw2": "198.51.100.2/24"});
    match t.c.apply(v, &opts(0, None)) {
        Err(Error::Validation(e)) => {
            assert!(e[0].contains("this node (fw1) is not listed"), "{e:?}")
        }
        other => panic!("{other:?}"),
    }
    t.c.system().fail_nft_check = Some("syntax error".into());
    assert!(matches!(
        t.c.apply(example(), &opts(0, None)),
        Err(Error::Check(_))
    ));
    assert_eq!(t.c.active().unwrap(), 0);
    assert!(t.c.history(None).unwrap().is_empty());
}

#[test]
fn failed_activation_restores_previous() {
    let mut t = setup();
    t.c.apply(example(), &opts(0, None)).unwrap();
    t.c.system().fail_nft_load = Some("kernel says no".into());
    let mut v = example();
    v["policy"]["wan->self"]["action"] = json!("reject");
    assert!(matches!(t.c.apply(v, &opts(1, None)), Err(Error::Apply(_))));
    assert_eq!(t.c.active().unwrap(), 1);
    assert!(matches!(
        t.c.drain_events().last(),
        Some(Event::ApplyFailed { id: 2, .. })
    ));
}

#[test]
fn dry_run_saves_nothing() {
    let mut t = setup();
    let mut o = opts(0, None);
    o.dry_run = true;
    let r = t.c.apply(example(), &o).unwrap();
    assert!(r.dry_run);
    assert_eq!(r.generation.id, 1);
    assert_eq!(t.c.active().unwrap(), 0);
    assert!(t.c.history(None).unwrap().is_empty());
}

#[test]
fn provider_check_failure_blocks_apply() {
    let mut t = setup();
    t.c.system().fail_service_check = Some("kea says no".into());
    match t.c.apply(example(), &opts(0, None)) {
        Err(Error::Check(m)) => assert!(m.contains("kea") && m.contains("kea says no"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(t.c.active().unwrap(), 0);
}

#[test]
fn services_follow_generations() {
    let mut t = setup();
    // Bootstrap runs only chrony.
    assert_eq!(t.c.system().running, ["chronyd.service"]);
    t.c.apply(example(), &opts(0, Some(30))).unwrap();
    assert_eq!(
        t.c.system().running,
        [
            "chronyd.service",
            "sparewall-kea.service",
            "sparewall-unbound.service"
        ]
    );
    let dhcp = &t.c.system().installed[&sparewall_render::Subsystem::Dhcp];
    assert!(dhcp["kea-dhcp4.conf"].contains("192.0.2.100 - 192.0.2.199"));
    let h = t.c.health().unwrap();
    assert_eq!(h.check("services").unwrap().level, Level::Ok);
    // A DHCP-only change reloads with "dhcp" changed.
    t.c.confirm(1).unwrap();
    t.c.merge(&json!({"dhcp": {"lease_time": 7200}}), &opts(1, None))
        .unwrap();
    let last = t.c.system().log.last().unwrap().clone();
    assert!(last.ends_with("changed dhcp"), "{last}");
    // Back to bootstrap: the providers stop.
    t.c.rollback(Some(0)).unwrap();
    assert_eq!(t.c.system().running, ["chronyd.service"]);
}

#[test]
fn backup_and_restore_drill() {
    let mut t = setup();
    t.c.apply(example(), &opts(0, None)).unwrap();
    t.c.merge(
        &json!({"networks": {"users": {"mtu": 1400}}}),
        &opts(1, None),
    )
    .unwrap();
    let out = tempfile::tempdir().unwrap();
    let leases = out.path().join("leases.csv");
    std::fs::write(&leases, "address,hwaddr\n192.0.2.100,52:54:00:00:00:01\n").unwrap();
    let src = sparewall_core::backup::Sources {
        leases: leases.clone(),
        out_dir: out.path().join("backups"),
        image_digest: Some("ghcr.io/sparewall/sparewall@sha256:abc".into()),
    };
    let (bundle, digest) = t.c.backup(&src, 20).unwrap();
    assert_eq!(digest.len(), 64);
    let m = sparewall_core::backup::manifest(&bundle).unwrap();
    assert_eq!(
        (m.active, m.generations.clone(), m.leases),
        (2, vec![1, 2], true)
    );

    // Both nodes lost: restore onto a fresh state directory.
    let fresh = tempfile::tempdir().unwrap();
    let restored_leases = fresh.path().join("kea-leases4.csv");
    sparewall_core::backup::restore(&bundle, fresh.path(), Some(&restored_leases)).unwrap();
    assert!(
        std::fs::read_to_string(&restored_leases)
            .unwrap()
            .contains("192.0.2.100")
    );
    let mut c = Coordinator::new(
        Store::open(fresh.path()).unwrap(),
        Fake::default(),
        identity(),
    );
    assert_eq!(c.boot(false).unwrap(), 2);
    assert_eq!(
        c.document_value(2).unwrap()["networks"]["users"]["mtu"],
        1400
    );
    assert_eq!(
        c.health().unwrap().check("applied").unwrap().level,
        Level::Ok
    );
    // Older generations come back too, and re-render on demand.
    let g = c.rollback(None).unwrap();
    assert_eq!(g.id, 1);
    assert_eq!(c.history(None).unwrap().len(), 2);
}

fn pair_example() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/pair.yaml"
    ))
    .unwrap();
    sparewall_config::parse_value(&text, sparewall_config::Format::Yaml).unwrap()
}

fn pair_node(name: &str) -> T {
    let dir = tempfile::tempdir().unwrap();
    let mut id = identity();
    id.node = name.into();
    let mut c = Coordinator::new(Store::open(dir.path()).unwrap(), Fake::default(), id);
    c.boot(false).unwrap();
    T { _dir: dir, c }
}

#[test]
fn pair_push_conflict_and_sync_from() {
    use sparewall_core::pair::{SyncState, push_plan, sync_state};
    let mut a = pair_node("fw1");
    let mut b = pair_node("fw2");
    a.c.apply(pair_example(), &opts(0, None)).unwrap();
    let mut v = pair_example();
    v["networks"]["users"]["mtu"] = json!(1400);
    a.c.apply(v.clone(), &opts(1, None)).unwrap();

    // b is two generations behind; push them in order.
    let (va, vb) = (a.c.view().unwrap(), b.c.view().unwrap());
    assert_eq!(sync_state(&va, Some(&vb)), SyncState::PeerBehind);
    for id in push_plan(&va, vb.active, &vb.desired).unwrap() {
        let g = a.c.generation(id).unwrap();
        b.c.receive(&g, a.c.document_value(id).unwrap()).unwrap();
    }
    assert_eq!(b.c.active().unwrap(), 2);
    assert_eq!(
        sync_state(&a.c.view().unwrap(), Some(&b.c.view().unwrap())),
        SyncState::InSync
    );
    // Pushing the same generation again is harmless.
    b.c.receive(&a.c.generation(2).unwrap(), a.c.document_value(2).unwrap())
        .unwrap();

    // Both sides change while apart: generation 3 differs.
    v["networks"]["users"]["mtu"] = json!(1300);
    a.c.apply(v.clone(), &opts(2, None)).unwrap();
    v["networks"]["users"]["mtu"] = json!(1200);
    b.c.apply(v, &opts(2, None)).unwrap();
    let (va, vb) = (a.c.view().unwrap(), b.c.view().unwrap());
    assert_eq!(sync_state(&va, Some(&vb)), SyncState::Diverged);
    let g3 = a.c.generation(3).unwrap();
    assert!(matches!(
        b.c.receive(&g3, a.c.document_value(3).unwrap()),
        Err(Error::Conflict { current: 3 })
    ));
    // `sync --from fw1` on fw2: fw2's own generation 3 is set aside.
    b.c.adopt(&g3, a.c.document_value(3).unwrap()).unwrap();
    assert_eq!(
        sync_state(&a.c.view().unwrap(), Some(&b.c.view().unwrap())),
        SyncState::InSync
    );
    assert_eq!(
        b.c.document_value(3).unwrap()["networks"]["users"]["mtu"],
        1300
    );
    let aside: Vec<_> = std::fs::read_dir(b.c.store().root().join("generations"))
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.starts_with("3.diverged-"))
        .collect();
    assert_eq!(aside.len(), 1);
    // A tampered push is refused.
    let mut bad = a.c.generation(3).unwrap();
    bad.id = 4;
    bad.base = Some(3);
    bad.hash = "0".repeat(64);
    assert!(matches!(
        b.c.receive(&bad, a.c.document_value(3).unwrap()),
        Err(Error::Validation(_))
    ));
}

#[test]
fn vpn_keys_and_client_config() {
    let mut a = pair_node("fw1");
    a.c.apply(pair_example(), &opts(0, None)).unwrap();
    assert!(
        a.c.system()
            .runtime_keys
            .contains_key("vpn-roadwarrior.key")
    );
    let cfg = a.c.vpn_client_config(None, "alice-laptop").unwrap();
    assert!(cfg.contains("Endpoint = vpn.example.org:51820"), "{cfg}");
    assert!(cfg.contains("Address = 10.99.0.10/32"), "{cfg}");
    // The key is generated once; a peer receives it rather than making one.
    let shared = a.c.cluster_secrets().unwrap();
    assert_eq!(shared.len(), 1);
    let mut b = pair_node("fw2");
    assert_eq!(b.c.receive_secrets(shared).unwrap(), 1);
    b.c.receive(&a.c.generation(1).unwrap(), a.c.document_value(1).unwrap())
        .unwrap();
    assert_eq!(b.c.system().keys_made, 0);
    assert_eq!(
        b.c.vpn_public_key("roadwarrior").unwrap(),
        a.c.vpn_public_key("roadwarrior").unwrap()
    );
}
