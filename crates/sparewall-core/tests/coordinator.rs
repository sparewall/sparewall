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
