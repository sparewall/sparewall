//! The apply/confirm/rollback state machine against a fake system.

use serde_json::{Value, json};
use sparewall_config::identity::{BootstrapPort, Identity};
use sparewall_core::Generation;
use sparewall_core::system::Fake;
use sparewall_core::{ApplyOptions, Coordinator, Error, Event, Level, PeerGate, Store};

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
        note: None,
        stage_sync_link: false,
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
fn rollback_is_a_new_generation() {
    let mut t = setup();
    t.c.apply(example(), &opts(0, None)).unwrap();
    let h1 = t.c.generation(1).unwrap().hash;
    let mut v = example();
    v["policy"]["wan->self"]["action"] = json!("reject");
    t.c.apply(v, &opts(1, None)).unwrap();
    let h2 = t.c.generation(2).unwrap().hash;

    // Back to the base: generation 1's document as generation 3, on top
    // of 2, which stays in history.
    let g = t.c.rollback(None, "admin").unwrap();
    assert_eq!((g.id, g.base, &g.hash), (3, Some(2), &h1));
    assert_eq!(g.author, "admin");
    assert_eq!(g.summary[0], "rollback to generation 1");
    assert_eq!(t.c.active().unwrap(), 3);
    assert_eq!(t.c.state().unwrap().confirmed, 3);
    assert_eq!(
        t.c.document_value(3).unwrap()["policy"]["wan->self"]["action"],
        t.c.document_value(1).unwrap()["policy"]["wan->self"]["action"]
    );
    let ids: Vec<u64> = t.c.history(None).unwrap().iter().map(|g| g.id).collect();
    assert_eq!(ids, [3, 2, 1]);
    assert!(matches!(
        t.c.drain_events().last(),
        Some(Event::RolledBack { to: 3, from: 2, .. })
    ));

    // To an explicit id, and back again: each is a new generation.
    let g = t.c.rollback(Some(2), "admin").unwrap();
    assert_eq!((g.id, g.base, &g.hash), (4, Some(3), &h2));
    // Rolling back to what is already running changes nothing.
    let g = t.c.rollback(Some(2), "admin").unwrap();
    assert_eq!(g.id, 4);
    assert!(matches!(
        t.c.rollback(Some(9), "admin"),
        Err(Error::NotFound(9))
    ));
    // A new change after a rollback gets a fresh id and records its base.
    let mut v = example();
    v["policy"]["users->wan"]["action"] = json!("reject");
    let r = t.c.apply(v, &opts(4, None)).unwrap();
    assert_eq!((r.generation.id, r.generation.base), (5, Some(4)));
}

#[test]
fn rollback_discards_a_pending_change() {
    let mut t = setup();
    t.c.apply(example(), &opts(0, None)).unwrap();
    let mut v = example();
    v["policy"]["wan->self"]["action"] = json!("reject");
    t.c.apply(v.clone(), &opts(1, None)).unwrap();
    v["policy"]["users->wan"]["action"] = json!("reject");
    t.c.apply(v, &opts(2, Some(600))).unwrap();
    // The unconfirmed change never left this node: returning to its
    // revert target is no new generation.
    let g = t.c.rollback(None, "admin").unwrap();
    assert_eq!(g.id, 2);
    assert_eq!(t.c.active().unwrap(), 2);
    assert!(t.c.state().unwrap().pending.is_none());
    // Past the revert target, the rest is a new generation.
    let mut v = example();
    v["networks"]["users"]["mtu"] = json!(1400);
    t.c.apply(v, &opts(2, Some(600))).unwrap();
    let g = t.c.rollback(Some(1), "admin").unwrap();
    assert_eq!((g.id, g.base), (5, Some(2)));
    assert_eq!(g.hash, t.c.generation(1).unwrap().hash);
    assert!(t.c.state().unwrap().pending.is_none());
}

/// Issue #5: the live firewall drifts after a successful apply (rules
/// flushed, chains kept). Health, the applied hash and pair sync all see
/// it; reloading the generation (what a sparewalld restart does) clears it.
#[test]
fn live_firewall_drift_fails_readiness() {
    let mut t = setup();
    t.c.apply(example(), &opts(0, None)).unwrap();
    let h = t.c.health().unwrap();
    assert_eq!(h.check("nft").unwrap().level, Level::Ok);
    assert_eq!(h.check("applied").unwrap().level, Level::Ok);
    let desired = t.c.generation(1).unwrap().hash;
    assert_eq!(t.c.hashes().unwrap().1.as_deref(), Some(desired.as_str()));

    // Every rule removed, every chain kept.
    let body = t.c.system().nft_body.clone().unwrap();
    let flushed: String = body
        .lines()
        .filter(|l| {
            let l = l.trim();
            l.is_empty()
                || l.starts_with("chain ")
                || l.starts_with("type ")
                || l == "}"
                || l.starts_with("table ")
                || l.starts_with("set ")
        })
        .map(|l| format!("{l}\n"))
        .collect();
    t.c.system().nft_body = Some(flushed);
    let h = t.c.health().unwrap();
    assert_eq!(h.level, Level::Failed);
    let nft = h.check("nft").unwrap();
    assert_eq!(nft.level, Level::Failed);
    assert!(
        nft.message
            .contains("differs from what generation 1 loaded"),
        "{}",
        nft.message
    );
    assert_eq!(h.check("applied").unwrap().level, Level::Failed);
    // Config sync reports the node as not running its configuration.
    assert_eq!(t.c.hashes().unwrap().1, None);
    assert_eq!(t.c.view().unwrap().applied, None);
    let mut peer = t.c.view().unwrap();
    peer.node = "fw2".into();
    peer.applied = Some(desired);
    assert!(matches!(
        sparewall_core::pair::sync_state(&t.c.view().unwrap(), Some(&peer)),
        sparewall_core::pair::SyncState::ApplyFailed { .. }
    ));

    // Any later change reloads the drifted table, even one that does not
    // touch the firewall.
    let mut v = example();
    v["dhcp"]["lease_time"] = json!(7200);
    t.c.apply(v, &opts(1, None)).unwrap();
    let h = t.c.health().unwrap();
    assert_eq!(h.check("nft").unwrap().level, Level::Ok, "{h:?}");
    assert_eq!(h.check("applied").unwrap().level, Level::Ok);

    // The table gone entirely.
    t.c.system().nft_body = None;
    let nft = t.c.health().unwrap().check("nft").unwrap().clone();
    assert!(nft.message.contains("not loaded"), "{}", nft.message);

    // Reloading the generation restores it.
    t.c.boot(false).unwrap();
    let h = t.c.health().unwrap();
    assert_eq!(h.check("nft").unwrap().level, Level::Ok);
    assert_eq!(h.check("applied").unwrap().level, Level::Ok);
    assert_eq!(
        t.c.hashes().unwrap().1,
        Some(t.c.generation(2).unwrap().hash)
    );
}

/// The table loads but cannot be read back right after (a listing error,
/// or no table listed): the node must not claim a verified activation,
/// and must not later learn a possibly drifted table as its baseline.
/// Only a reload verifies it again (review of #17).
#[test]
fn unverifiable_load_fails_closed() {
    for mode in ["error", "absent"] {
        let mut t = setup();
        t.c.apply(example(), &opts(0, None)).unwrap();
        let set_broken = |t: &mut T, on: bool| {
            if mode == "error" {
                t.c.system().fail_nft_json = on.then(|| "nft: listing failed".to_string());
            } else {
                t.c.system().hide_nft_json = on;
            }
        };
        // A later load (here, a firewall change) whose read-back fails.
        set_broken(&mut t, true);
        let mut v = example();
        v["policy"]["wan->self"]["action"] = json!("reject");
        t.c.apply(v, &opts(1, None)).unwrap();
        let check = |t: &mut T| {
            let h = t.c.health().unwrap();
            // The fake has no links; only these two checks matter here.
            (
                h.check("nft").unwrap().level,
                h.check("nft").unwrap().message.clone(),
                h.check("applied").unwrap().level,
            )
        };
        let (level, msg, applied) = check(&mut t);
        assert_eq!(level, Level::Failed, "{mode}");
        assert_eq!(applied, Level::Failed, "{mode}");
        assert!(
            msg.contains("cannot verify the live firewall"),
            "{mode}: {msg}"
        );
        assert_eq!(t.c.hashes().unwrap().1, None, "{mode}");

        // Reads work again: still not verified, nothing learned from the
        // live table, and tampering now is not mistaken for the baseline.
        set_broken(&mut t, false);
        assert_eq!(
            check(&mut t).0,
            Level::Failed,
            "{mode}: blessed on recovery"
        );
        t.c.system().nft_body = Some("table inet sparewall {\n}\n".into());
        let (level, msg, _) = check(&mut t);
        assert_eq!(level, Level::Failed, "{mode}");
        assert!(msg.contains("cannot verify"), "{mode}: {msg}");
        assert_eq!(t.c.hashes().unwrap().1, None, "{mode}");

        // A reload records a trusted baseline; drift is detected from it.
        t.c.boot(false).unwrap();
        let (level, msg, applied) = check(&mut t);
        assert_eq!((level, applied), (Level::Ok, Level::Ok), "{mode}: {msg}");
        assert!(t.c.hashes().unwrap().1.is_some(), "{mode}");
        t.c.system().nft_body = Some("table inet sparewall {\n}\n".into());
        let (level, msg, _) = check(&mut t);
        assert_eq!(level, Level::Failed, "{mode}");
        assert!(msg.contains("live ruleset differs"), "{mode}: {msg}");
    }
}

/// Issue #6: losing a replication-only link degrades health (it never
/// fails it, which would put keepalived in FAULT and move the gateway
/// addresses); losing a link that carries traffic still fails it.
/// Sync on its own port, `syncp`, on both nodes.
fn dedicated_sync_port(v: &mut Value) {
    v["ports"]["fw1"]["syncp"] = json!({"nic": "52:54:00:aa:00:09"});
    v["ports"]["fw2"]["syncp"] = json!({"nic": "9c:6b:00:00:00:09"});
    v["networks"]["sync"]["port"] = json!("syncp");
}

/// Issue #19: replication-link health across sync topologies. Losing a
/// link that carries only replication degrades health (the pair stops
/// replicating, the gateway addresses stay); losing one that carries
/// traffic fails it; restoring either returns to ok.
#[test]
fn replication_link_loss_degrades_health() {
    struct Case {
        name: &'static str,
        edit: fn(&mut Value),
        /// The links classified as replication-only.
        replication: &'static [&'static str],
    }
    let cases = [
        Case {
            name: "tagged sync on the shared trunk",
            edit: |_| {},
            replication: &["sync"],
        },
        Case {
            name: "tagged sync on a dedicated port",
            edit: dedicated_sync_port,
            replication: &["sync", "syncp"],
        },
        Case {
            name: "untagged sync on a dedicated port",
            edit: |v| {
                dedicated_sync_port(v);
                v["networks"]["sync"]["vlan"] = Value::Null;
            },
            replication: &["syncp"],
        },
        Case {
            name: "untagged sync on a dedicated active-backup bond",
            edit: |v| {
                for (node, macs) in [
                    ("fw1", ["52:54:00:aa:00:09", "52:54:00:aa:00:0a"]),
                    ("fw2", ["9c:6b:00:00:00:09", "9c:6b:00:00:00:0a"]),
                ] {
                    v["ports"][node]["syncb"] =
                        json!({"bond": {"members": macs, "mode": "active-backup"}});
                }
                v["networks"]["sync"]["port"] = json!("syncb");
                v["networks"]["sync"]["vlan"] = Value::Null;
            },
            replication: &["syncb"],
        },
        Case {
            // The trunk's own interface carries sync and the service VLANs:
            // it is required, so there is nothing replication-only.
            name: "untagged sync sharing the service trunk",
            edit: |v| {
                v["networks"]["sync"]["vlan"] = Value::Null;
            },
            replication: &[],
        },
    ];
    let meta = |t: &mut T| {
        sparewall_render::render(
            &sparewall_config::from_value(t.c.document_value(t.c.active().unwrap()).unwrap())
                .unwrap(),
            "fw1",
        )
        .unwrap()
        .meta
    };
    let all_up = |t: &mut T| {
        let m = meta(t);
        for l in m.required_links.iter().chain(&m.replication_links) {
            t.c.system().links.insert(l.clone(), "up".into());
        }
    };
    let levels = |t: &mut T| {
        let h = t.c.health().unwrap();
        (
            h.check("links").unwrap().level,
            h.check("replication").map(|c| c.level),
            h.level,
        )
    };
    let message =
        |t: &mut T, check: &str| t.c.health().unwrap().check(check).unwrap().message.clone();
    for case in cases {
        let name = case.name;
        let mut t = pair_node("fw1");
        let mut v = pair_example();
        (case.edit)(&mut v);
        t.c.apply(v, &opts(0, None))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let m = meta(&mut t);
        assert_eq!(m.replication_links, case.replication, "{name}");
        assert!(m.required_links.contains(&"uplink".to_string()), "{name}");
        for l in case.replication {
            assert!(!m.required_links.contains(&l.to_string()), "{name}: {l}");
        }
        let ok = (
            Level::Ok,
            (!case.replication.is_empty()).then_some(Level::Ok),
            Level::Ok,
        );
        all_up(&mut t);
        assert_eq!(levels(&mut t), ok, "{name}");

        for l in case.replication {
            for (state, said) in [(Some("down"), "is down"), (None, "is missing")] {
                match state {
                    Some(s) => t.c.system().links.insert(l.to_string(), s.into()),
                    None => t.c.system().links.remove(*l),
                };
                assert_eq!(
                    levels(&mut t),
                    (Level::Ok, Some(Level::Degraded), Level::Degraded),
                    "{name}: {l} {said}"
                );
                let msg = message(&mut t, "replication");
                assert!(msg.contains(&format!("{l} {said}")), "{name}: {msg}");
                all_up(&mut t);
                assert_eq!(levels(&mut t), ok, "{name}: {l} restored");
            }
        }

        // The trunk carries traffic: losing it fails health, and any
        // separate replication links still report on their own.
        for (state, said) in [(Some("down"), "is down"), (None, "is missing")] {
            match state {
                Some(s) => t.c.system().links.insert("uplink".into(), s.into()),
                None => t.c.system().links.remove("uplink"),
            };
            assert_eq!(
                levels(&mut t),
                (Level::Failed, ok.1, Level::Failed),
                "{name}: uplink {said}"
            );
            let msg = message(&mut t, "links");
            assert!(msg.contains(&format!("uplink {said}")), "{name}: {msg}");
            all_up(&mut t);
            assert_eq!(levels(&mut t), ok, "{name}: uplink restored");
        }
    }
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
            "sparewall-ulogd.service",
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
    t.c.rollback(Some(0), "admin").unwrap();
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
    use sparewall_core::secrets::SecretClass;
    t.c.secret_set("vpn-office", b"the vpn key", SecretClass::Cluster)
        .unwrap();
    t.c.secret_set("local", b"never leaves", SecretClass::Node)
        .unwrap();
    // Without a backup password the secrets stay out of the bundle.
    let (bundle, _) = t.c.backup(&src, 20).unwrap();
    assert!(
        sparewall_core::backup::manifest(&bundle)
            .unwrap()
            .secrets
            .is_empty()
    );
    std::fs::remove_file(&bundle).unwrap();
    t.c.secret_set("backup-password", b"hunter2", SecretClass::Cluster)
        .unwrap();
    let (bundle, digest) = t.c.backup(&src, 20).unwrap();
    assert_eq!(digest.len(), 64);
    let m = sparewall_core::backup::manifest(&bundle).unwrap();
    assert_eq!(
        (m.active, m.generations.clone(), m.leases),
        (2, vec![1, 2], true)
    );
    assert_eq!(m.secrets, ["backup-password", "vpn-office"]);

    // Both nodes lost: restore onto a fresh state directory. A wrong
    // password changes nothing.
    let fresh = tempfile::tempdir().unwrap();
    let restored_leases = fresh.path().join("kea-leases4.csv");
    let r = sparewall_core::backup::restore(
        &bundle,
        fresh.path(),
        Some(&restored_leases),
        Some(b"hunter3"),
    );
    assert!(r.is_err());
    assert!(!fresh.path().join("state.json").exists());
    let (_, secrets) = sparewall_core::backup::restore(
        &bundle,
        fresh.path(),
        Some(&restored_leases),
        Some(b"hunter2"),
    )
    .unwrap();
    let mut fake = Fake::default();
    for s in &secrets {
        use sparewall_core::System;
        let blob = fake.encrypt(&s.info.name, &s.value).unwrap();
        sparewall_core::secrets::store_encrypted(fresh.path(), &s.info, &blob).unwrap();
    }
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
        c.secret_get("vpn-office").unwrap().as_deref(),
        Some(&b"the vpn key"[..])
    );
    assert_eq!(c.secret_get("local").unwrap(), None);
    assert_eq!(
        c.health().unwrap().check("applied").unwrap().level,
        Level::Ok
    );
    // Older generations come back too, and re-render on demand.
    let g = c.rollback(None, "admin").unwrap();
    assert_eq!((g.id, &g.hash), (3, &c.generation(1).unwrap().hash));
    assert_eq!(c.history(None).unwrap().len(), 3);
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
        b.c.receive(&g, a.c.document_value(id).unwrap(), PeerGate::Immediate)
            .unwrap();
    }
    assert_eq!(b.c.active().unwrap(), 2);
    assert_eq!(
        sync_state(&a.c.view().unwrap(), Some(&b.c.view().unwrap())),
        SyncState::InSync
    );
    // Pushing the same generation again is harmless.
    b.c.receive(
        &a.c.generation(2).unwrap(),
        a.c.document_value(2).unwrap(),
        PeerGate::Immediate,
    )
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
        b.c.receive(&g3, a.c.document_value(3).unwrap(), PeerGate::Immediate),
        Err(Error::Conflict { current: 3 })
    ));
    // `sync --from fw1` on fw2: fw2's own generation 3 is set aside.
    b.c.adopt(&g3, a.c.document_value(3).unwrap(), PeerGate::Immediate)
        .unwrap();
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
        b.c.receive(&bad, a.c.document_value(3).unwrap(), PeerGate::Immediate),
        Err(Error::Validation(_))
    ));
}

/// One background sync pass from `from` towards `to`, as sparewalld does
/// it: push only when `to` is behind; only the last generation runs there.
/// Returns the state `from` saw.
fn sync_pass(from: &mut T, to: &mut T) -> sparewall_core::pair::SyncState {
    use sparewall_core::pair::{SyncState, push_plan, sync_state};
    let (vf, vt) = (from.c.view().unwrap(), to.c.view().unwrap());
    let state = sync_state(&vf, Some(&vt));
    if state == SyncState::PeerBehind {
        let plan = push_plan(&vf, vt.active, &vt.desired).unwrap();
        let last = *plan.last().unwrap();
        for id in plan {
            let g = from.c.generation(id).unwrap();
            let v = from.c.document_value(id).unwrap();
            if id == last {
                to.c.receive(&g, v, PeerGate::Immediate).unwrap();
            } else {
                to.c.receive_history(&g, v).unwrap();
            }
        }
    }
    state
}

/// Issue #4: both nodes confirm generation 2, one rolls back, and
/// background sync must carry the rollback to the peer rather than push
/// generation 2 back. Either node may roll back.
#[test]
fn pair_rollback_is_not_undone_by_sync() {
    use sparewall_core::pair::{SyncState, sync_state};
    for roller in ["fw1", "fw2"] {
        let mut a = pair_node("fw1");
        let mut b = pair_node("fw2");
        a.c.apply(pair_example(), &opts(0, None)).unwrap();
        let mut v = pair_example();
        v["networks"]["users"]["mtu"] = json!(1400);
        a.c.apply(v, &opts(1, None)).unwrap();
        sync_pass(&mut a, &mut b);
        assert_eq!(b.c.active().unwrap(), 2);
        let h1 = a.c.generation(1).unwrap().hash;

        let (r, other) = if roller == "fw1" {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        let g = r.c.rollback(None, "admin").unwrap();
        assert_eq!((g.id, &g.hash), (3, &h1), "{roller}");
        // Both directions of background sync, several times over.
        for _ in 0..3 {
            assert_ne!(
                sync_pass(other, r),
                SyncState::PeerBehind,
                "{roller}: the peer pushed"
            );
            sync_pass(r, other);
        }
        for n in [&*r, &*other] {
            assert_eq!(n.c.active().unwrap(), 3, "{roller}");
            assert_eq!(n.c.generation(3).unwrap().hash, h1, "{roller}");
            assert!(
                n.c.document_value(3).unwrap()["networks"]["users"]
                    .get("mtu")
                    .is_none()
            );
            // The rolled-back configuration stays in history.
            assert_eq!(
                n.c.history(None)
                    .unwrap()
                    .iter()
                    .map(|g| g.id)
                    .collect::<Vec<_>>(),
                [3, 2, 1],
                "{roller}"
            );
        }
        assert_eq!(
            sync_state(&a.c.view().unwrap(), Some(&b.c.view().unwrap())),
            SyncState::InSync,
            "{roller}"
        );
    }
}

/// The peer misses a change, then the rollback of it: the content the peer
/// runs is already right, but its history is not, so it is still behind.
/// It catches up without ever running the rolled-back generation, and a
/// later ordinary change on it is no divergence (review of #16).
#[test]
fn pair_rollback_of_a_change_the_peer_missed() {
    use sparewall_core::pair::{SyncState, sync_state};
    let mut a = pair_node("fw1");
    let mut b = pair_node("fw2");
    a.c.apply(pair_example(), &opts(0, None)).unwrap();
    sync_pass(&mut a, &mut b);
    assert_eq!(b.c.active().unwrap(), 1);
    // b is away while a makes generation 2 and rolls it back.
    let mut v = pair_example();
    v["networks"]["users"]["mtu"] = json!(1400);
    a.c.apply(v, &opts(1, None)).unwrap();
    a.c.rollback(None, "admin").unwrap();
    assert_eq!(a.c.active().unwrap(), 3);
    let (va, vb) = (a.c.view().unwrap(), b.c.view().unwrap());
    assert_eq!(va.desired, vb.desired, "same content");
    assert_eq!(sync_state(&va, Some(&vb)), SyncState::PeerBehind);
    assert_eq!(sync_state(&vb, Some(&va)), SyncState::LocalBehind);

    b.c.drain_events();
    let installed_before = b.c.system().log.len();
    sync_pass(&mut a, &mut b);
    assert_eq!(b.c.active().unwrap(), 3);
    let ids: Vec<u64> = b.c.history(None).unwrap().iter().map(|g| g.id).collect();
    assert_eq!(ids, [3, 2, 1], "b has the whole history");
    // Generation 2 was stored, never run.
    for e in b.c.drain_events() {
        assert!(!matches!(e, Event::Applied { id: 2, .. }), "{e:?}");
    }
    // Generations 1 and 3 have the same content, so going from 1 to 3
    // reloads nothing; running 2 on the way (an MTU change) would have.
    assert!(
        !b.c.system().log[installed_before..]
            .iter()
            .any(|l| l.starts_with("networkd")),
        "b ran the rolled-back generation: {:?}",
        &b.c.system().log[installed_before..]
    );
    assert_eq!(
        sync_state(&a.c.view().unwrap(), Some(&b.c.view().unwrap())),
        SyncState::InSync
    );

    // An ordinary change on b afterwards is pushed to a, not divergence.
    let mut v = b.c.document_value(3).unwrap();
    v["networks"]["users"]["mtu"] = json!(1300);
    b.c.apply(v, &opts(3, None)).unwrap();
    assert_eq!(sync_pass(&mut b, &mut a), SyncState::PeerBehind);
    assert_eq!(a.c.active().unwrap(), 4);
    assert_eq!(
        sync_state(&a.c.view().unwrap(), Some(&b.c.view().unwrap())),
        SyncState::InSync
    );
}

/// Nodes that applied the same document independently, with unrelated
/// histories, stay in sync (how a pair is formed).
#[test]
fn same_content_with_unrelated_histories_is_in_sync() {
    use sparewall_core::pair::{SyncState, sync_state};
    let mut a = pair_node("fw1");
    let mut b = pair_node("fw2");
    let mut v = pair_example();
    v["networks"]["users"]["mtu"] = json!(1400);
    a.c.apply(v, &opts(0, None)).unwrap();
    a.c.apply(pair_example(), &opts(1, None)).unwrap();
    b.c.apply(pair_example(), &opts(0, None)).unwrap();
    assert_eq!(
        sync_state(&a.c.view().unwrap(), Some(&b.c.view().unwrap())),
        SyncState::InSync
    );
}

/// A rollback made while the peer was away is an ordinary change: it
/// reaches the peer when it returns, unless the peer changed too, which
/// is divergence for `sync --from` to resolve.
#[test]
fn pair_rollback_with_the_peer_away() {
    use sparewall_core::pair::{SyncState, sync_state};
    let mut a = pair_node("fw1");
    let mut b = pair_node("fw2");
    a.c.apply(pair_example(), &opts(0, None)).unwrap();
    let mut v = pair_example();
    v["networks"]["users"]["mtu"] = json!(1400);
    a.c.apply(v, &opts(1, None)).unwrap();
    sync_pass(&mut a, &mut b);

    // b was away; when it returns it takes the rollback.
    a.c.rollback(None, "admin").unwrap();
    assert_eq!(sync_pass(&mut a, &mut b), SyncState::PeerBehind);
    assert_eq!(b.c.active().unwrap(), 3);

    // Both change while apart: a rolls back, b makes another change.
    a.c.rollback(Some(2), "admin").unwrap();
    let mut v = b.c.document_value(3).unwrap();
    v["networks"]["users"]["mtu"] = json!(1300);
    b.c.apply(v, &opts(3, None)).unwrap();
    assert_eq!(
        sync_state(&a.c.view().unwrap(), Some(&b.c.view().unwrap())),
        SyncState::Diverged
    );
    // Nothing merges by itself; an admin picks a side.
    for _ in 0..2 {
        sync_pass(&mut a, &mut b);
        sync_pass(&mut b, &mut a);
    }
    assert_ne!(
        a.c.generation(4).unwrap().hash,
        b.c.generation(4).unwrap().hash
    );
    let g = a.c.generation(4).unwrap();
    b.c.adopt(&g, a.c.document_value(4).unwrap(), PeerGate::Immediate)
        .unwrap();
    assert_eq!(
        sync_state(&a.c.view().unwrap(), Some(&b.c.view().unwrap())),
        SyncState::InSync
    );
}

/// Two paired nodes both running generation 1; `a` has made generation
/// 2, which changes the firewall, links and a provider, and `b` has not
/// received it yet.
fn peers_with_change() -> (T, T, Generation, Value) {
    let mut a = pair_node("fw1");
    let mut b = pair_node("fw2");
    a.c.apply(pair_example(), &opts(0, None)).unwrap();
    let g1 = a.c.generation(1).unwrap();
    b.c.receive(&g1, a.c.document_value(1).unwrap(), PeerGate::Immediate)
        .unwrap();
    let mut v = pair_example();
    v["policy"]["wan->self"]["action"] = json!("reject");
    v["networks"]["users"]["mtu"] = json!(1400);
    v["dhcp"]["lease_time"] = json!(7200);
    a.c.apply(v, &opts(1, None)).unwrap();
    let g2 = a.c.generation(2).unwrap();
    let v2 = a.c.document_value(2).unwrap();
    (a, b, g2, v2)
}

/// What `b` runs: its firewall script, networkd files and providers.
fn running(t: &mut T) -> (Option<String>, String, Vec<String>) {
    let s = t.c.system();
    (
        s.nft_body.clone(),
        format!("{:?}", s.network),
        s.running.clone(),
    )
}

/// Issue #7: a peer generation that fails partway through activation
/// (after the firewall loaded, or links changed, or at the provider
/// reload) leaves the previous generation running, and is rejected
/// rather than retried into the same failure.
#[test]
fn failed_peer_activation_restores_the_previous_generation() {
    for stage in ["nft load", "link changes", "provider reload"] {
        let (mut a, mut b, g2, v2) = peers_with_change();
        let before = running(&mut b);
        let fail = Some(format!("injected failure at {stage}"));
        // A transient failure partway through: restoring generation 1 works.
        b.c.system().fail_once = true;
        match stage {
            "nft load" => b.c.system().fail_nft_load = fail,
            "link changes" => b.c.system().fail_networkd_apply = fail,
            _ => b.c.system().fail_services_apply = fail,
        }
        let e =
            b.c.receive(&g2, v2.clone(), PeerGate::PeerConfirms)
                .unwrap_err();
        assert!(e.to_string().contains("injected failure"), "{stage}: {e}");
        assert_eq!(b.c.active().unwrap(), 1, "{stage}");
        assert!(b.c.state().unwrap().pending.is_none(), "{stage}");
        // Back on generation 1 everywhere, and the failure cleared itself.
        assert!(
            b.c.system().fail_nft_load.is_none()
                && b.c.system().fail_networkd_apply.is_none()
                && b.c.system().fail_services_apply.is_none()
        );
        assert_eq!(
            running(&mut b),
            before,
            "{stage}: generation 1 not restored"
        );
        let h = b.c.health().unwrap();
        assert_eq!(h.check("applied").unwrap().level, Level::Ok, "{stage}");
        let r = h.check("peer-generation").unwrap();
        assert_eq!(r.level, Level::Degraded, "{stage}");
        assert!(
            r.message.contains("activating it failed"),
            "{stage}: {}",
            r.message
        );

        // The same generation is refused without another attempt.
        let tries = b.c.system().log.len();
        let e =
            b.c.receive(&g2, v2.clone(), PeerGate::PeerConfirms)
                .unwrap_err();
        assert!(e.to_string().contains("was rejected here"), "{stage}: {e}");
        assert_eq!(b.c.system().log.len(), tries, "{stage}: activated again");

        // A newer generation replaces it (2 goes to history, 3 runs).
        let mut v = v2.clone();
        v["dhcp"]["lease_time"] = json!(3600);
        a.c.apply(v, &opts(2, None)).unwrap();
        b.c.receive_history(&g2, v2.clone()).unwrap();
        let g3 = a.c.generation(3).unwrap();
        b.c.receive(&g3, a.c.document_value(3).unwrap(), PeerGate::PeerConfirms)
            .unwrap();
        b.c.confirm_received(3).unwrap();
        assert_eq!(b.c.active().unwrap(), 3, "{stage}");
        assert!(b.c.state().unwrap().rejected.is_none(), "{stage}");
    }
}

/// A gated generation runs pending, is not reported applied (the pair
/// is "applying"), and is confirmed by the pusher.
#[test]
fn peer_generation_waits_for_the_pushers_confirmation() {
    use sparewall_core::pair::{SyncState, sync_state};
    let (mut a, mut b, g2, v2) = peers_with_change();
    b.c.receive(&g2, v2, PeerGate::PeerConfirms).unwrap();
    let st = b.c.state().unwrap();
    assert_eq!(st.active, 2);
    assert_eq!(st.confirmed, 1);
    let p = st.pending.unwrap();
    assert!(p.from_peer);
    assert_eq!(p.revert_to, 1);
    let vb = b.c.view().unwrap();
    assert_eq!((vb.applied, vb.applying), (None, true));
    assert_eq!(
        sync_state(&a.c.view().unwrap(), Some(&b.c.view().unwrap())),
        SyncState::Applying
    );
    let h = b.c.health().unwrap();
    assert!(
        h.check("confirm")
            .unwrap()
            .message
            .contains("unless the peer confirms it"),
        "{h:?}"
    );
    b.c.confirm_received(2).unwrap();
    // A repeated confirmation is fine.
    b.c.confirm_received(2).unwrap();
    let st = b.c.state().unwrap();
    assert_eq!((st.active, st.confirmed, st.pending), (2, 2, None));
    assert_eq!(
        sync_state(&a.c.view().unwrap(), Some(&b.c.view().unwrap())),
        SyncState::InSync
    );
}

/// The pusher never confirms (the change cut the sync tunnel): at the
/// deadline the receiver returns to the previous generation and rejects
/// the pushed one.
#[test]
fn unconfirmed_peer_generation_reverts_at_its_deadline() {
    let (_a, mut b, g2, v2) = peers_with_change();
    let before = running(&mut b);
    b.c.receive(&g2, v2.clone(), PeerGate::PeerConfirms)
        .unwrap();
    let deadline = b.c.state().unwrap().pending.unwrap().deadline;
    assert_eq!(b.c.tick(deadline - 1).unwrap(), None);
    assert_eq!(b.c.tick(deadline).unwrap(), Some(1));
    let st = b.c.state().unwrap();
    assert_eq!((st.active, st.confirmed, st.pending), (1, 1, None));
    assert_eq!(running(&mut b), before);
    assert!(
        st.rejected
            .unwrap()
            .reason
            .contains("did not confirm it in time")
    );
    assert!(
        b.c.receive(&g2, v2.clone(), PeerGate::PeerConfirms)
            .is_err()
    );
    // An explicit sync retries it.
    b.c.adopt(&g2, v2, PeerGate::PeerConfirms).unwrap();
    assert_eq!(b.c.active().unwrap(), 2);
    b.c.confirm_received(2).unwrap();
}

/// The receiver's daemon restarts during the window: the revert deadline
/// is in the persisted state, and booting returns to the previous
/// generation; the pusher then pushes again (not rejected).
#[test]
fn restart_during_the_window_reverts_and_allows_a_retry() {
    let (_a, mut b, g2, v2) = peers_with_change();
    b.c.receive(&g2, v2.clone(), PeerGate::PeerConfirms)
        .unwrap();
    let mut id = identity();
    id.node = "fw2".into();
    let mut c = Coordinator::new(Store::open(b._dir.path()).unwrap(), Fake::default(), id);
    assert_eq!(c.boot(false).unwrap(), 1);
    let st = c.state().unwrap();
    assert_eq!((st.active, st.pending, st.rejected), (1, None, None));
    c.receive(&g2, v2, PeerGate::PeerConfirms).unwrap();
    c.confirm_received(2).unwrap();
    assert_eq!(c.state().unwrap().confirmed, 2);
}

/// Confirmation needs the generation to fail no health check that did
/// not fail before it ran (here, a required link it adds never appears);
/// until then it stays pending, and reverts at the deadline.
#[test]
fn peer_generation_that_breaks_health_is_not_confirmed() {
    let mut a = pair_node("fw1");
    let mut b = pair_node("fw2");
    a.c.apply(pair_example(), &opts(0, None)).unwrap();
    b.c.receive(
        &a.c.generation(1).unwrap(),
        a.c.document_value(1).unwrap(),
        PeerGate::Immediate,
    )
    .unwrap();
    // Every link generation 1 needs is up on b.
    let r = sparewall_render::render(
        &sparewall_config::from_value(b.c.document_value(1).unwrap()).unwrap(),
        "fw2",
    )
    .unwrap();
    for l in r
        .meta
        .required_links
        .iter()
        .chain(&r.meta.replication_links)
    {
        b.c.system().links.insert(l.clone(), "up".into());
    }
    assert_eq!(
        b.c.health().unwrap().check("links").unwrap().level,
        Level::Ok
    );
    let mut v = pair_example();
    v["networks"]["lab"] = json!({"port": "uplink", "vlan": 30,
        "addresses": {"fw1": "198.51.100.2/24", "fw2": "198.51.100.3/24"}});
    v["zones"]["lab"] = json!({"networks": ["lab"]});
    a.c.apply(v, &opts(1, None)).unwrap();
    b.c.receive(
        &a.c.generation(2).unwrap(),
        a.c.document_value(2).unwrap(),
        PeerGate::PeerConfirms,
    )
    .unwrap();
    let e = b.c.confirm_received(2).unwrap_err();
    assert!(e.to_string().contains("link lab"), "{e}");
    assert!(b.c.state().unwrap().pending.is_some(), "still pending");
    let deadline = b.c.state().unwrap().pending.unwrap().deadline;
    assert_eq!(b.c.tick(deadline).unwrap(), Some(1));
    assert!(b.c.state().unwrap().rejected.is_some());
}

/// Mark every link generation `id` needs on `t` up, except `down`.
fn links_up_except(t: &mut T, id: u64, down: &[&str]) {
    let r = sparewall_render::render(
        &sparewall_config::from_value(t.c.document_value(id).unwrap()).unwrap(),
        t.c.node(),
    )
    .unwrap();
    for l in r
        .meta
        .required_links
        .iter()
        .chain(&r.meta.replication_links)
    {
        let state = if down.contains(&l.as_str()) {
            "down"
        } else {
            "up"
        };
        t.c.system().links.insert(l.clone(), state.into());
    }
}

/// `b` runs generation 1 from `a`; `a` has generation 2, made from
/// `change` applied to the pair example.
fn peers_with(change: impl Fn(&mut Value)) -> (T, T, Generation, Value) {
    let mut a = pair_node("fw1");
    let mut b = pair_node("fw2");
    a.c.apply(pair_example(), &opts(0, None)).unwrap();
    b.c.receive(
        &a.c.generation(1).unwrap(),
        a.c.document_value(1).unwrap(),
        PeerGate::Immediate,
    )
    .unwrap();
    let mut v = pair_example();
    change(&mut v);
    a.c.apply(v, &opts(1, None)).unwrap();
    let g2 = a.c.generation(2).unwrap();
    let v2 = a.c.document_value(2).unwrap();
    (a, b, g2, v2)
}

fn add_lab(v: &mut Value) {
    v["networks"]["lab"] = json!({"port": "uplink", "vlan": 30,
        "addresses": {"fw1": "198.51.100.2/24", "fw2": "198.51.100.3/24"}});
    v["zones"]["lab"] = json!({"networks": ["lab"]});
}

/// A link already down when the generation ran does not excuse a new
/// one: the gate compares failed resources, not check names (review of
/// #20).
#[test]
fn a_known_fault_does_not_hide_a_new_one() {
    let (_a, mut b, g2, v2) = peers_with(add_lab);
    links_up_except(&mut b, 1, &["wan"]);
    assert_eq!(
        b.c.health().unwrap().check("links").unwrap().level,
        Level::Failed
    );
    b.c.receive(&g2, v2, PeerGate::PeerConfirms).unwrap();
    // wan recovers; lab, which generation 2 needs, never appears.
    b.c.system().links.insert("wan".into(), "up".into());
    let msg =
        b.c.health()
            .unwrap()
            .check("links")
            .unwrap()
            .message
            .clone();
    assert_eq!(msg, "lab is missing");
    let e = b.c.confirm_received(2).unwrap_err();
    assert!(e.to_string().contains("link lab"), "{e}");
    let st = b.c.state().unwrap();
    assert_eq!((st.confirmed, st.pending.is_some()), (1, true));
}

/// An unchanged fault from before is tolerated: a change can still land
/// on a node with a link down.
#[test]
fn an_unchanged_fault_is_tolerated() {
    let (_a, mut b, g2, v2) = peers_with(|v| v["dhcp"]["lease_time"] = json!(7200));
    links_up_except(&mut b, 1, &["wan"]);
    b.c.receive(&g2, v2, PeerGate::PeerConfirms).unwrap();
    assert_eq!(
        b.c.health().unwrap().check("links").unwrap().level,
        Level::Failed
    );
    b.c.confirm_received(2).unwrap();
    assert_eq!(b.c.state().unwrap().confirmed, 2);
}

/// Status, metrics and health agree with the peer view: a pushed
/// generation is not applied before the peer confirms it, is after, and
/// after a timeout the previous generation is (review of #20).
#[test]
fn status_and_metrics_wait_for_the_peers_confirmation() {
    let applied_metric = |t: &mut T| {
        t.c.metrics()
            .unwrap()
            .lines()
            .find_map(|l| {
                l.strip_prefix("sparewall_config_applied ")
                    .map(str::to_string)
            })
            .unwrap()
    };
    for outcome in ["confirmed", "timed out"] {
        let (_a, mut b, g2, v2) = peers_with(|v| v["dhcp"]["lease_time"] = json!(7200));
        let h1 = b.c.generation(1).unwrap().hash;
        links_up_except(&mut b, 1, &[]);
        b.c.receive(&g2, v2, PeerGate::PeerConfirms).unwrap();
        assert_eq!(b.c.hashes().unwrap().1, None, "{outcome}");
        assert_eq!(applied_metric(&mut b), "0", "{outcome}");
        let h = b.c.health().unwrap();
        let applied = h.check("applied").unwrap();
        assert_eq!(applied.level, Level::Degraded, "{outcome}");
        assert!(
            applied.message.contains("awaiting its confirmation"),
            "{}",
            applied.message
        );
        // Waiting is not a failure (it would block its own confirmation
        // and lower VRRP priority).
        assert_ne!(h.level, Level::Failed, "{outcome}: {h:?}");
        if outcome == "confirmed" {
            b.c.confirm_received(2).unwrap();
            assert_eq!(b.c.hashes().unwrap().1, Some(g2.hash.clone()));
            assert_eq!(applied_metric(&mut b), "1");
            assert_eq!(
                b.c.health().unwrap().check("applied").unwrap().level,
                Level::Ok
            );
        } else {
            let deadline = b.c.state().unwrap().pending.unwrap().deadline;
            b.c.tick(deadline).unwrap();
            assert_eq!(b.c.hashes().unwrap().1, Some(h1));
            assert_eq!(applied_metric(&mut b), "1");
            assert_eq!(
                b.c.health().unwrap().check("applied").unwrap().level,
                Level::Ok
            );
        }
    }
}

#[test]
fn vpn_keys_and_client_config() {
    let mut a = pair_node("fw1");
    a.c.apply(pair_example(), &opts(0, None)).unwrap();
    // The key is installed exactly where the rendered netdev reads it
    // (they once disagreed, and networkd never created the interface).
    let netdev = &a.c.system().network["50-sparewall-roadwarrior.netdev"];
    let path = netdev
        .lines()
        .find_map(|l| l.strip_prefix("PrivateKeyFile="))
        .unwrap()
        .to_string();
    let file = path
        .strip_prefix(&format!("{}/", sparewall_render::KEY_DIR))
        .unwrap();
    assert!(
        a.c.system().runtime_keys.contains_key(file),
        "netdev reads {path}; installed: {:?}",
        a.c.system().runtime_keys.keys().collect::<Vec<_>>()
    );
    let cfg = a.c.vpn_client_config(None, "alice-laptop").unwrap();
    assert!(cfg.contains("Endpoint = vpn.example.org:51820"), "{cfg}");
    assert!(cfg.contains("Address = 10.99.0.10/32"), "{cfg}");
    // The key is generated once; a peer receives it rather than making one.
    let shared = a.c.cluster_secrets().unwrap();
    assert_eq!(shared.len(), 1);
    let mut b = pair_node("fw2");
    assert_eq!(b.c.receive_secrets(shared).unwrap(), ["vpn-roadwarrior"]);
    b.c.receive(
        &a.c.generation(1).unwrap(),
        a.c.document_value(1).unwrap(),
        PeerGate::Immediate,
    )
    .unwrap();
    assert_eq!(b.c.system().keys_made, 0);
    assert_eq!(
        b.c.vpn_public_key("roadwarrior").unwrap(),
        a.c.vpn_public_key("roadwarrior").unwrap()
    );
}

#[test]
fn tokens_create_check_revoke() {
    use sparewall_core::tokens::Role;
    let mut t = setup();
    let (tok, info) = t.c.token_create("prom", Role::Monitor, Some(90)).unwrap();
    assert!(tok.starts_with("swt_") && !info.hash.contains(&tok));
    assert_eq!(t.c.token_check(&tok).unwrap(), Some(Role::Monitor));
    assert!(t.c.tokens().unwrap()[0].last_used.is_some());
    assert_eq!(t.c.token_check("swt_nope").unwrap(), None);
    assert!(t.c.token_create("prom", Role::Admin, None).is_err());
    assert!(t.c.token_revoke("prom").unwrap());
    assert_eq!(t.c.token_check(&tok).unwrap(), None);
}

/// Settings earlier versions accepted and this one rejects (issue #9),
/// as patches to the pair example, with the path each is rejected at.
fn unbuilt_settings() -> Vec<(Value, &'static str)> {
    vec![
        (
            json!({"provider_options": {"kea": {"valid-lifetime": 600}}}),
            "provider_options.kea",
        ),
        (json!({"metrics": {"mode": "local"}}), "metrics.mode"),
        (
            json!({"metrics": {"mode": "external", "retention": "15d"}}),
            "metrics.retention",
        ),
        (json!({"updates": {"mode": "windowed"}}), "updates.mode"),
        (
            json!({"updates": {"mode": "manual", "window": "Sun 03:00"}}),
            "updates.window",
        ),
    ]
}

/// A generation as an earlier version stored it, bypassing validation.
fn legacy(id: u64, base: u64, patch: &Value) -> (Generation, Value) {
    let mut v = pair_example();
    for (k, x) in patch.as_object().unwrap() {
        v[k] = x.clone();
    }
    let doc = sparewall_config::from_value(v.clone()).unwrap();
    let g = Generation {
        id,
        hash: sparewall_config::hash(&doc),
        base: Some(base),
        schema: 1,
        author: "old version".into(),
        created: "2026-01-01T00:00:00Z".into(),
        summary: vec![],
    };
    (g, v)
}

fn store_legacy(t: &T, g: &Generation, v: &Value) {
    let doc = sparewall_config::from_value(v.clone()).unwrap();
    let rendered = sparewall_render::render(&doc, t.c.node()).unwrap();
    t.c.store().save(g, &doc, &rendered).unwrap();
}

/// Issue #9 review: a generation stored before the upgrade (in history,
/// or pushed and then rolled back) is checked as this version would
/// before a push or `sync --from` runs it, and nothing changes when it
/// is refused.
#[test]
fn stored_generations_are_checked_before_they_run() {
    for (patch, path) in unbuilt_settings() {
        let (_a, mut b, _, _) = peers_with_change();
        let (g2, v2) = legacy(2, 1, &patch);
        store_legacy(&b, &g2, &v2);
        let before = running(&mut b);
        for gate in [PeerGate::PeerConfirms, PeerGate::Immediate] {
            let r = b.c.receive(&g2, v2.clone(), gate);
            assert!(
                matches!(&r, Err(Error::Validation(e)) if e.iter().any(|m| m.starts_with(path))),
                "{path}: {r:?}"
            );
            let r = b.c.adopt(&g2, v2.clone(), gate);
            assert!(
                matches!(&r, Err(Error::Validation(e)) if e.iter().any(|m| m.starts_with(path))),
                "{path}: {r:?}"
            );
            let st = b.c.state().unwrap();
            assert_eq!(
                (st.active, st.confirmed, st.pending),
                (1, 1, None),
                "{path}"
            );
            assert_eq!(running(&mut b), before, "{path}");
        }
    }
}

/// Issue #9 review: a peer behind by a legacy generation the other node
/// has since repaired catches up through it, keeping it in history
/// without running it.
#[test]
fn legacy_history_does_not_block_catch_up() {
    for (patch, path) in unbuilt_settings() {
        let (_a, mut b, _, _) = peers_with_change();
        let (g2, v2) = legacy(2, 1, &patch);
        b.c.receive_history(&g2, v2).unwrap();
        // The repaired descendant runs.
        let mut v3 = pair_example();
        v3["networks"]["users"]["mtu"] = json!(1400);
        let doc3 = sparewall_config::from_value(v3.clone()).unwrap();
        let g3 = Generation {
            id: 3,
            hash: sparewall_config::hash(&doc3),
            base: Some(2),
            ..g2.clone()
        };
        b.c.receive(&g3, v3, PeerGate::Immediate)
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        let st = b.c.state().unwrap();
        assert_eq!((st.active, st.confirmed), (3, 3), "{path}");
        assert_eq!(b.c.generation(2).unwrap().hash, g2.hash, "{path}");
    }
}

/// Generations stored here under `<id>.<why>-<hash>`.
fn set_aside_names(t: &T, why: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(t.c.store().root().join("generations"))
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.contains(&format!(".{why}-")))
        .collect();
    v.sort();
    v
}

/// Issue #24: a local change that failed to activate never ran, so it
/// leaves history and its id, and the peer's next change (numbered the
/// same) is accepted rather than refused as a conflict forever.
#[test]
fn failed_apply_does_not_block_the_peer() {
    use sparewall_core::pair::{SyncState, push_plan, sync_state};
    let mut a = pair_node("fw1");
    let mut b = pair_node("fw2");
    a.c.apply(pair_example(), &opts(0, None)).unwrap();
    let g1 = a.c.generation(1).unwrap();
    b.c.receive(&g1, a.c.document_value(1).unwrap(), PeerGate::Immediate)
        .unwrap();

    // The same failing change twice on b: both attempts are kept aside.
    let mut v = pair_example();
    v["networks"]["users"]["mtu"] = json!(1400);
    for _ in 0..2 {
        b.c.system().fail_networkd_apply = Some("networkd says no".into());
        b.c.system().fail_once = true;
        assert!(matches!(
            b.c.apply(v.clone(), &opts(1, None)),
            Err(Error::Apply(_))
        ));
        assert_eq!(b.c.active().unwrap(), 1);
    }
    let ids = |t: &T| -> Vec<u64> { t.c.history(None).unwrap().iter().map(|g| g.id).collect() };
    assert_eq!(ids(&b), [1]);
    let aside = set_aside_names(&b, "failed");
    assert_eq!(aside.len(), 2, "{aside:?}");
    assert!(
        aside.iter().all(|n| n.starts_with("2.failed-")),
        "{aside:?}"
    );

    // a's next change is also generation 2.
    v["networks"]["users"]["mtu"] = json!(1300);
    a.c.apply(v, &opts(1, None)).unwrap();
    let (va, vb) = (a.c.view().unwrap(), b.c.view().unwrap());
    assert_eq!(sync_state(&va, Some(&vb)), SyncState::PeerBehind);
    for id in push_plan(&va, vb.active, &vb.desired).unwrap() {
        b.c.receive(
            &a.c.generation(id).unwrap(),
            a.c.document_value(id).unwrap(),
            PeerGate::Immediate,
        )
        .unwrap();
    }
    assert_eq!(b.c.active().unwrap(), 2);
    assert_eq!(
        b.c.document_value(2).unwrap()["networks"]["users"]["mtu"],
        1300
    );
    assert_eq!(
        sync_state(&a.c.view().unwrap(), Some(&b.c.view().unwrap())),
        SyncState::InSync
    );
}

/// Issue #24: a crash after activating a change but before `state.json`
/// named it comes back on the previous generation, with the change on
/// disk. The peer's generations with the same ids replace it, whether
/// pushed as history or to run.
#[test]
fn generation_left_by_a_crash_does_not_block_the_peer() {
    let mut a = pair_node("fw1");
    let mut b = pair_node("fw2");
    a.c.apply(pair_example(), &opts(0, None)).unwrap();
    let g1 = a.c.generation(1).unwrap();
    b.c.receive(&g1, a.c.document_value(1).unwrap(), PeerGate::Immediate)
        .unwrap();

    // b applies generation 2 and "crashes" before recording it.
    let state = b.c.store().root().join("state.json");
    let before = std::fs::read(&state).unwrap();
    let mut v = pair_example();
    v["networks"]["users"]["mtu"] = json!(1400);
    b.c.apply(v.clone(), &opts(1, None)).unwrap();
    std::fs::write(&state, before).unwrap();
    let id = b.c.identity().clone();
    b.c = Coordinator::new(Store::open(b._dir.path()).unwrap(), Fake::default(), id);
    assert_eq!(b.c.boot(false).unwrap(), 1);
    assert!(b.c.store().exists(2));

    // a makes generations 2 and 3; b stores 2 as history and runs 3.
    for mtu in [1300, 1200] {
        v["networks"]["users"]["mtu"] = json!(mtu);
        let base = a.c.active().unwrap();
        a.c.apply(v.clone(), &opts(base, None)).unwrap();
    }
    let g2 = a.c.generation(2).unwrap();
    b.c.receive_history(&g2, a.c.document_value(2).unwrap())
        .unwrap();
    let g3 = a.c.generation(3).unwrap();
    b.c.receive(&g3, a.c.document_value(3).unwrap(), PeerGate::Immediate)
        .unwrap();
    assert_eq!(b.c.active().unwrap(), 3);
    assert_eq!(b.c.generation(2).unwrap().hash, g2.hash);
    assert_eq!(set_aside_names(&b, "diverged").len(), 1);
    assert_eq!(b.c.lineage().unwrap(), a.c.lineage().unwrap());
}

/// A generation this node ran or confirmed is never replaced by a push
/// with the same id: that is divergence, resolved only by `sync --from`.
#[test]
fn a_generation_that_ran_still_conflicts() {
    let mut a = pair_node("fw1");
    let mut b = pair_node("fw2");
    a.c.apply(pair_example(), &opts(0, None)).unwrap();
    let g1 = a.c.generation(1).unwrap();
    b.c.receive(&g1, a.c.document_value(1).unwrap(), PeerGate::Immediate)
        .unwrap();
    let mut v = pair_example();
    v["networks"]["users"]["mtu"] = json!(1400);
    b.c.apply(v.clone(), &opts(1, None)).unwrap();
    v["networks"]["users"]["mtu"] = json!(1300);
    a.c.apply(v, &opts(1, None)).unwrap();
    let g2 = a.c.generation(2).unwrap();
    for r in [
        b.c.receive(&g2, a.c.document_value(2).unwrap(), PeerGate::Immediate),
        b.c.receive_history(&g2, a.c.document_value(2).unwrap()),
    ] {
        assert!(matches!(r, Err(Error::Conflict { current: 2 })), "{r:?}");
    }
    assert_eq!(
        b.c.document_value(2).unwrap()["networks"]["users"]["mtu"],
        1400
    );

    // Review of #27: the metadata is the peer's word. A push numbered as
    // the active generation and naming it as its own base must not pass
    // as coming after it, nor any id not above its base.
    let network = b.c.system().network.clone();
    let lineage = b.c.lineage().unwrap();
    for (id, base) in [(2, 2), (3, 3), (3, 4)] {
        let mut bad = g2.clone();
        bad.id = id;
        bad.base = Some(base);
        let v = a.c.document_value(2).unwrap();
        for r in [
            b.c.receive(&bad, v.clone(), PeerGate::PeerConfirms),
            b.c.receive_history(&bad, v.clone()),
        ] {
            assert!(
                matches!(r, Err(Error::Conflict { current: 2 })),
                "{id}/{base}: {r:?}"
            );
        }
    }
    assert_eq!(b.c.state().unwrap().active, 2);
    assert_eq!(b.c.lineage().unwrap(), lineage);
    assert_eq!(
        b.c.document_value(2).unwrap()["networks"]["users"]["mtu"],
        1400
    );
    assert_eq!(b.c.system().network, network);
    assert!(set_aside_names(&b, "diverged").is_empty());
}

/// Review of #27: a push to run, gated by the peer, replaces a crash
/// leftover with its id directly, and stays pending until confirmed. One
/// that fails validation leaves the leftover where it was.
#[test]
fn gated_push_replaces_a_crash_leftover() {
    let mut a = pair_node("fw1");
    let mut b = pair_node("fw2");
    a.c.apply(pair_example(), &opts(0, None)).unwrap();
    let g1 = a.c.generation(1).unwrap();
    b.c.receive(&g1, a.c.document_value(1).unwrap(), PeerGate::Immediate)
        .unwrap();
    let state = b.c.store().root().join("state.json");
    let before = std::fs::read(&state).unwrap();
    let mut v = pair_example();
    v["networks"]["users"]["mtu"] = json!(1400);
    b.c.apply(v.clone(), &opts(1, None)).unwrap();
    std::fs::write(&state, before).unwrap();
    let id = b.c.identity().clone();
    b.c = Coordinator::new(Store::open(b._dir.path()).unwrap(), Fake::default(), id);
    assert_eq!(b.c.boot(false).unwrap(), 1);
    let leftover = b.c.generation(2).unwrap().hash;

    v["networks"]["users"]["mtu"] = json!(1300);
    a.c.apply(v, &opts(1, None)).unwrap();
    let g2 = a.c.generation(2).unwrap();
    // Content that does not match the hash: refused, leftover kept.
    let mut wrong = a.c.document_value(2).unwrap();
    wrong["networks"]["users"]["mtu"] = json!(1200);
    assert!(matches!(
        b.c.receive(&g2, wrong, PeerGate::PeerConfirms),
        Err(Error::Validation(_))
    ));
    assert_eq!(b.c.generation(2).unwrap().hash, leftover);
    assert!(set_aside_names(&b, "diverged").is_empty());

    b.c.receive(&g2, a.c.document_value(2).unwrap(), PeerGate::PeerConfirms)
        .unwrap();
    let st = b.c.state().unwrap();
    assert_eq!((st.active, st.confirmed), (2, 1));
    assert!(st.pending.is_some_and(|p| p.from_peer && p.id == 2));
    assert_eq!(b.c.generation(2).unwrap().hash, g2.hash);
    assert_eq!(set_aside_names(&b, "diverged").len(), 1);
    b.c.confirm_received(2).unwrap();
    assert_eq!(b.c.state().unwrap().confirmed, 2);
}

/// Make every `state.json` write fail (its temporary file is a
/// directory) until the returned guard is dropped.
fn break_state_writes(t: &T) -> impl Drop + use<> {
    struct Guard(std::path::PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    let p = t.c.store().root().join(".state.json.tmp");
    std::fs::create_dir(&p).unwrap();
    Guard(p)
}

/// Issue #28: a local change that ran but could not be recorded in
/// `state.json` is undone like a failed activation, so the node runs
/// what `state.json` says and no change outlives it unrecorded.
#[test]
fn failed_state_commit_restores_the_recorded_generation() {
    let (mut a, _b, _, v2) = peers_with_change();
    // a runs 2; make 3 on top of it, which cannot be recorded.
    let before = running(&mut a);
    let applied = a.c.applied().unwrap();
    let mut v3 = v2.clone();
    v3["networks"]["users"]["mtu"] = json!(1300);
    v3["policy"]["wan->self"]["action"] = json!("drop");
    a.c.drain_events();
    {
        let _broken = break_state_writes(&a);
        let r = a.c.apply(v3.clone(), &opts(2, Some(60)));
        assert!(matches!(r, Err(Error::Io { .. })), "{r:?}");
    }
    let st = a.c.state().unwrap();
    assert_eq!((st.active, st.confirmed, st.pending), (2, 2, None));
    assert_eq!(running(&mut a), before);
    assert_eq!(a.c.applied().unwrap(), applied);
    assert!(matches!(
        a.c.drain_events().last(),
        Some(Event::ApplyFailed { id: 3, .. })
    ));
    assert_eq!(set_aside_names(&a, "failed").len(), 1);
    assert!(!a.c.store().exists(3));
    // Once writes work again, the same change goes through.
    let r = a.c.apply(v3, &opts(2, Some(60))).unwrap();
    assert_eq!(r.generation.id, 3);
    assert_eq!(a.c.state().unwrap().pending.map(|p| p.id), Some(3));
}

/// Issue #28: the peer's generation, run but not recorded, is undone
/// and the push fails, so the peer pushes it again later; it is not
/// left running behind a `state.json` naming the previous one.
#[test]
fn failed_state_commit_undoes_the_peers_generation() {
    for gate in [PeerGate::Immediate, PeerGate::PeerConfirms] {
        let (_a, mut b, g2, v2) = peers_with_change();
        let before = running(&mut b);
        b.c.drain_events();
        {
            let _broken = break_state_writes(&b);
            let r = b.c.receive(&g2, v2.clone(), gate);
            assert!(matches!(r, Err(Error::Io { .. })), "{gate:?}: {r:?}");
        }
        let st = b.c.state().unwrap();
        // The rejection could not be recorded either: nothing blocks a retry.
        assert_eq!(
            (st.active, st.pending, st.rejected),
            (1, None, None),
            "{gate:?}"
        );
        assert_eq!(running(&mut b), before, "{gate:?}");
        assert!(matches!(
            b.c.drain_events().last(),
            Some(Event::ApplyFailed { id: 2, .. })
        ));
        b.c.receive(&g2, v2, gate).unwrap();
        assert_eq!(b.c.active().unwrap(), 2, "{gate:?}");
    }
}

/// Fail the syncs of `dir` numbered in `calls` (1 = its first sync from
/// now), calling `then` on each failure; every sync is logged.
fn fail_syncs(
    t: &T,
    dir: std::path::PathBuf,
    calls: &'static [usize],
    then: impl Fn() + Send + 'static,
) -> std::sync::Arc<std::sync::Mutex<Vec<std::path::PathBuf>>> {
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = log.clone();
    let mut n = 0;
    t.c.store().inject_sync_faults(move |d| {
        seen.lock().unwrap().push(d.to_path_buf());
        if d != dir {
            return false;
        }
        n += 1;
        let fail = calls.contains(&n);
        if fail {
            then();
        }
        fail
    });
    log
}

/// Review of #30: syncing the state directory can fail after the rename
/// put the new record in place. The node must end up running what the
/// readable record names, and keep every generation a record may name.
#[test]
fn state_sync_failure_after_the_rename() {
    // (failed syncs of the state directory, re-record fails before its
    // rename, expected active, generation 3 kept)
    let cases: [(&'static [usize], bool, u64, bool); 3] = [
        // The previous record is written back: 3 is unreferenced.
        (&[1], false, 2, false),
        // Written back, but its sync fails too: 3 may still be on disk.
        (&[1, 2], false, 2, true),
        // Not written back: the new record stands and keeps running.
        (&[1], true, 3, true),
    ];
    for (calls, block_rerecord, active, kept) in cases {
        let (mut a, _b, _, v2) = peers_with_change();
        let at_2 = running(&mut a);
        let mut v3 = v2.clone();
        v3["networks"]["users"]["mtu"] = json!(1300);
        v3["policy"]["wan->self"]["action"] = json!("drop");
        let root = a.c.store().root().to_path_buf();
        let tmp = root.join(".state.json.tmp");
        fail_syncs(&a, root.clone(), calls, move || {
            if block_rerecord {
                std::fs::create_dir(&tmp).unwrap();
            }
        });
        let case = format!("{calls:?} {block_rerecord}");
        let r = a.c.apply(v3, &opts(2, Some(60)));
        assert!(matches!(r, Err(Error::Io { .. })), "{case}: {r:?}");
        a.c.store().inject_sync_faults(|_| false);
        let _ = std::fs::remove_dir(root.join(".state.json.tmp"));

        let st = a.c.state().unwrap();
        assert_eq!(st.active, active, "{case}");
        assert_eq!(a.c.store().exists(3), kept, "{case}");
        assert!(a.c.health().is_ok(), "{case}");
        if active == 2 {
            assert_eq!(running(&mut a), at_2, "{case}");
            assert_eq!(
                a.c.applied().unwrap(),
                Some(a.c.generation(2).unwrap().hash)
            );
        } else {
            assert_eq!(st.pending.map(|p| p.id), Some(3), "{case}");
            assert_ne!(running(&mut a), at_2, "{case}");
        }
        // A restart comes back on 2 (a pending 3 reverts), never bootstrap.
        let id = a.c.identity().clone();
        let mut c = Coordinator::new(Store::open(&root).unwrap(), Fake::default(), id);
        assert_eq!(c.boot(false).unwrap(), 2, "{case}");
    }
}

/// Review of #30: the same for the peer's generation, under both gates.
/// Rejected only once the previous record is back.
#[test]
fn peer_state_sync_failure_after_the_rename() {
    for gate in [PeerGate::Immediate, PeerGate::PeerConfirms] {
        for (block_rerecord, active) in [(false, 1), (true, 2)] {
            let case = format!("{gate:?} {block_rerecord}");
            let (_a, mut b, g2, v2) = peers_with_change();
            let at_1 = running(&mut b);
            let root = b.c.store().root().to_path_buf();
            let tmp = root.join(".state.json.tmp");
            fail_syncs(&b, root.clone(), &[1], move || {
                if block_rerecord {
                    std::fs::create_dir(&tmp).unwrap();
                }
            });
            let r = b.c.receive(&g2, v2.clone(), gate);
            assert!(matches!(r, Err(Error::Io { .. })), "{case}: {r:?}");
            b.c.store().inject_sync_faults(|_| false);
            let _ = std::fs::remove_dir(root.join(".state.json.tmp"));

            let st = b.c.state().unwrap();
            assert_eq!(st.active, active, "{case}");
            assert!(b.c.store().exists(2), "{case}");
            assert!(b.c.health().is_ok(), "{case}");
            if active == 1 {
                assert_eq!(running(&mut b), at_1, "{case}");
                assert_eq!(st.rejected.map(|r| r.id), Some(2), "{case}");
            } else {
                assert_ne!(running(&mut b), at_1, "{case}");
                assert_eq!(st.rejected, None, "{case}");
            }
            let id = b.c.identity().clone();
            let mut c = Coordinator::new(Store::open(&root).unwrap(), Fake::default(), id);
            let expect = if gate == PeerGate::PeerConfirms {
                1
            } else {
                active
            };
            assert_eq!(c.boot(false).unwrap(), expect, "{case}");
        }
    }
}

/// Review of #30: a generation whose sync failed is synced again before
/// a state record names it, on whichever path the retry takes: a fresh
/// save over the empty directory left behind, or the cached generation.
#[test]
fn retried_push_syncs_the_generation_first() {
    // (directory whose sync fails, which of its syncs)
    for (dir, call) in [("generations", 1), ("generations/2", 3)] {
        let (_a, mut b, g2, v2) = peers_with_change();
        let root = b.c.store().root().to_path_buf();
        fail_syncs(
            &b,
            root.join(dir),
            if call == 1 { &[1] } else { &[3] },
            || {},
        );
        let r = b.c.receive(&g2, v2.clone(), PeerGate::Immediate);
        assert!(matches!(r, Err(Error::Io { .. })), "{dir}: {r:?}");
        assert_eq!(b.c.active().unwrap(), 1, "{dir}");

        let log = fail_syncs(&b, root.join("none"), &[], || {});
        b.c.receive(&g2, v2, PeerGate::Immediate).unwrap();
        assert_eq!(b.c.active().unwrap(), 2, "{dir}");
        let log = log.lock().unwrap();
        let first = |p: &std::path::Path| log.iter().position(|d| d == p);
        let state = first(&root).expect("the state was recorded");
        for d in [root.join("generations/2"), root.join("generations")] {
            let at = first(&d).unwrap_or_else(|| panic!("{dir}: {} not synced", d.display()));
            assert!(at < state, "{dir}: {} synced after the state", d.display());
        }
    }
}

/// The pair example, paired: both nodes' sync keys are set.
fn paired_example() -> Value {
    let mut v = pair_example();
    v["cluster"]["sync_keys"] = json!({
        "fw1": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
        "fw2": "M6astOdmoOXA9wbbSh6itjkcHKGdkoDSy01sGZ68FVw=",
    });
    v
}

/// Two nodes in sync at generation 1 of the paired example.
fn synced_pair() -> (T, T) {
    let mut a = pair_node("fw1");
    let mut b = pair_node("fw2");
    a.c.apply(paired_example(), &opts(0, None)).unwrap();
    let g1 = a.c.generation(1).unwrap();
    b.c.receive(&g1, a.c.document_value(1).unwrap(), PeerGate::Immediate)
        .unwrap();
    (a, b)
}

/// The pair example with the sync tunnel on other addresses.
fn moved_sync_link() -> Value {
    let mut v = paired_example();
    v["networks"]["sync"]["addresses"] = json!({"fw1": "10.255.1.1/30", "fw2": "10.255.1.2/30"});
    v
}

fn staging(base: u64, confirm: Option<u32>) -> ApplyOptions {
    ApplyOptions {
        stage_sync_link: true,
        ..opts(base, confirm)
    }
}

/// #25: a change to the sync link is stored, not run; other changes,
/// and any change without a pair, run as before.
#[test]
fn sync_link_changes_are_staged() {
    let (mut a, _b) = synced_pair();
    let before = running(&mut a);
    let r = a.c.apply(moved_sync_link(), &staging(1, Some(60))).unwrap();
    assert!(r.staged);
    assert_eq!(r.generation.id, 2);
    assert_eq!(a.c.state().unwrap().active, 1);
    assert!(a.c.store().exists(2));
    assert_eq!(running(&mut a), before);
    a.c.discard_staged(2).unwrap();
    assert!(!a.c.store().exists(2));
    assert_eq!(set_aside_names(&a, "unsent").len(), 1);

    // Other changes, and sync-link changes without the flag, just run.
    for (v, o) in [
        (
            {
                let mut v = paired_example();
                v["networks"]["users"]["mtu"] = json!(1400);
                v
            },
            staging(1, None),
        ),
        (moved_sync_link(), opts(2, None)),
    ] {
        let r = a.c.apply(v, &o).unwrap();
        assert!(!r.staged);
        assert_eq!(a.c.active().unwrap(), r.generation.id);
    }

    // Standalone: nothing to stage.
    let mut t = setup();
    t.c.apply(example(), &opts(0, None)).unwrap();
    let mut v = example();
    v["networks"]["users"]["mtu"] = json!(1400);
    assert!(!t.c.apply(v, &staging(1, None)).unwrap().staged);
}

/// What the daemon's sync loop does on an in-doubt node `b` once it
/// reaches `a`: if `a` has decided (nothing pending), do as it did.
fn follow(b: &mut T, a: &mut T) {
    let Some((id, hash, _)) = b.c.in_doubt().unwrap() else {
        return;
    };
    if a.c.state().unwrap().pending.is_some() {
        return;
    }
    let kept = a.c.lineage().unwrap().contains(&(id, hash));
    b.c.resolve_in_doubt(kept).unwrap();
}

/// `a` stages the sync-link move, `b` runs it pending (pushed through the
/// old link), then `a` runs it with `window`.
fn moving_link(window: u32) -> (T, T) {
    let (mut a, mut b) = synced_pair();
    let r =
        a.c.apply(moved_sync_link(), &staging(1, Some(window)))
            .unwrap();
    assert!(r.staged);
    b.c.receive(
        &r.generation,
        a.c.document_value(2).unwrap(),
        PeerGate::PeerConfirms,
    )
    .unwrap();
    a.c.activate_staged(2, window).unwrap();
    (a, b)
}

fn at(t: &T) -> (u64, u64, bool) {
    let st = t.c.state().unwrap();
    (st.active, st.confirmed, st.pending.is_some())
}

/// #25: the peer confirms the change over the new link but stays in
/// doubt; this node decides once the peer has and (with a window) the
/// admin has, in either order, and the peer follows.
#[test]
fn sync_link_change_kept_once_both_agree() {
    for admin in [None, Some("first"), Some("last")] {
        let window = if admin.is_some() { 60 } else { 0 };
        let (mut a, mut b) = moving_link(window);
        let p = a.c.state().unwrap().pending.unwrap();
        assert!(p.peer_gate && p.needs_admin == admin.is_some(), "{admin:?}");
        let msg =
            a.c.health()
                .unwrap()
                .check("confirm")
                .unwrap()
                .message
                .clone();
        assert!(msg.contains("over the new sync link"), "{msg}");

        if admin == Some("first") {
            a.c.confirm(2).unwrap();
            assert_eq!(at(&a), (2, 1, true), "{admin:?}");
        }
        // The peer's confirmation prepares it; it does not decide.
        b.c.confirm_received(2).unwrap();
        b.c.confirm_received(2).unwrap();
        assert_eq!(at(&b), (2, 1, true), "{admin:?}");
        assert!(b.c.in_doubt().unwrap().is_some());
        follow(&mut b, &mut a);
        assert_eq!(at(&b), (2, 1, true), "{admin:?}: a has not decided");

        a.c.peer_confirmed(2).unwrap();
        if admin == Some("last") {
            assert_eq!(at(&a), (2, 1, true));
            follow(&mut b, &mut a);
            assert_eq!(at(&b), (2, 1, true), "the admin can still veto");
            a.c.confirm(2).unwrap();
        }
        assert_eq!(at(&a), (2, 2, false), "{admin:?}");
        follow(&mut b, &mut a);
        assert_eq!(at(&b), (2, 2, false), "{admin:?}");
        assert!(b.c.in_doubt().unwrap().is_none());
        a.c.peer_confirmed(2).unwrap();
    }
}

/// Review of #34: the peer confirmed first but the admin never does.
/// This node reverts at its deadline; the peer, in doubt, never reverts
/// on its own deadline but follows: both end on the old link.
#[test]
fn admin_veto_reverts_both_nodes() {
    let (mut a, mut b) = moving_link(60);
    b.c.confirm_received(2).unwrap();
    a.c.peer_confirmed(2).unwrap();
    let a_deadline = a.c.state().unwrap().pending.unwrap().deadline;
    let b_deadline = b.c.state().unwrap().pending.unwrap().deadline;
    assert_eq!(b.c.tick(b_deadline.max(a_deadline) + 600).unwrap(), None);
    assert_eq!(a.c.tick(a_deadline).unwrap(), Some(1));
    follow(&mut b, &mut a);
    assert_eq!((at(&a), at(&b)), ((1, 1, false), (1, 1, false)));
}

/// Review of #34: the peer prepared but its reply was lost, or this node
/// restarted before deciding: this node reverts (at its deadline, or at
/// boot) and the in-doubt peer follows instead of keeping the change.
#[test]
fn lost_reply_or_restart_reverts_both_nodes() {
    for restart in [false, true] {
        let (mut a, mut b) = moving_link(0);
        b.c.confirm_received(2).unwrap();
        // a never learns: no peer_confirmed.
        if restart {
            let id = a.c.identity().clone();
            let root = a.c.store().root().to_path_buf();
            a.c = Coordinator::new(Store::open(&root).unwrap(), Fake::default(), id);
            assert_eq!(a.c.boot(false).unwrap(), 1);
        } else {
            let d = a.c.state().unwrap().pending.unwrap().deadline;
            assert_eq!(a.c.tick(d).unwrap(), Some(1));
        }
        follow(&mut b, &mut a);
        assert_eq!(
            (at(&a), at(&b)),
            ((1, 1, false), (1, 1, false)),
            "{restart}"
        );
    }
}

/// Review of #34: an in-doubt node keeps its doubt across a restart,
/// looks for the peer on the other link (only the sync link differs, and
/// health is degraded, not failed), and still follows the decision.
#[test]
fn in_doubt_survives_restart_and_switches_links() {
    let (mut a, mut b) = moving_link(0);
    b.c.confirm_received(2).unwrap();
    let id = b.c.identity().clone();
    let root = b.c.store().root().to_path_buf();
    b.c = Coordinator::new(Store::open(&root).unwrap(), Fake::default(), id);
    assert_eq!(b.c.boot(false).unwrap(), 2);
    assert!(
        b.c.in_doubt()
            .unwrap()
            .is_some_and(|(id, _, old)| id == 2 && !old)
    );
    let new_link = b.c.live_document().unwrap().unwrap();

    b.c.alternate_in_doubt().unwrap();
    assert!(b.c.in_doubt().unwrap().is_some_and(|(_, _, old)| old));
    assert_eq!(
        sparewall_config::to_value(&b.c.live_document().unwrap().unwrap()),
        a.c.document_value(1).unwrap()
    );
    let h = b.c.health().unwrap().check("applied").unwrap().clone();
    assert_eq!(h.level, Level::Degraded, "{}", h.message);
    assert!(h.message.contains("old link"), "{}", h.message);
    b.c.alternate_in_doubt().unwrap();
    assert_eq!(b.c.live_document().unwrap().unwrap(), new_link);
    b.c.alternate_in_doubt().unwrap();

    // a keeps it; b, on the old link, switches back and keeps it too.
    let sync_address = |t: &mut T| {
        let net = format!("{:?}", t.c.system().network);
        (net.contains("10.255.0.2/30"), net.contains("10.255.1.2/30"))
    };
    assert_eq!(sync_address(&mut b), (true, false), "on the old link");
    a.c.peer_confirmed(2).unwrap();
    follow(&mut b, &mut a);
    assert_eq!(sync_address(&mut b), (false, true), "back on the new link");
    assert_eq!(
        b.c.applied().unwrap(),
        Some(a.c.generation(2).unwrap().hash)
    );
    assert_eq!((at(&a), at(&b)), ((2, 2, false), (2, 2, false)));
    assert_eq!(
        sparewall_config::to_value(&b.c.live_document().unwrap().unwrap()),
        a.c.document_value(2).unwrap()
    );
}

/// Review of #34: a change only to a node's port carrying the sync
/// network (its NIC, a bond member) is a sync-link change; a pending
/// change blocks one; and one must change nothing else.
#[test]
fn sync_link_detection_and_limits() {
    let (mut a, _b) = synced_pair();
    for (what, edit) in [
        (
            "nic",
            Box::new(|v: &mut Value| {
                v["ports"]["fw1"]["uplink"]["nic"] = json!("52:54:00:aa:00:99");
            }) as Box<dyn Fn(&mut Value)>,
        ),
        (
            "bond member",
            Box::new(|v: &mut Value| {
                v["ports"]["fw2"]["uplink"]["bond"]["members"][1] = json!("9c:6b:00:00:00:09");
            }),
        ),
    ] {
        let mut v = paired_example();
        edit(&mut v);
        let r = a.c.apply(v, &staging(1, None)).unwrap();
        assert!(r.staged, "{what}");
        a.c.discard_staged(r.generation.id).unwrap();
    }

    let mut mixed = moved_sync_link();
    mixed["networks"]["users"]["mtu"] = json!(1400);
    let e = a.c.apply(mixed, &staging(1, None)).unwrap_err();
    assert!(e.to_string().contains("must change nothing else"), "{e}");

    let mut v = paired_example();
    v["networks"]["users"]["mtu"] = json!(1400);
    let r = a.c.apply(v, &staging(1, Some(60))).unwrap();
    let e =
        a.c.apply(moved_sync_link(), &staging(r.generation.id, None))
            .unwrap_err();
    assert!(e.to_string().contains("is pending"), "{e}");
    let st = a.c.state().unwrap();
    assert_eq!(
        (st.active, st.pending.map(|p| p.id)),
        (r.generation.id, Some(r.generation.id))
    );
}

/// #25: if the new link never works, the peer reverts at its deadline
/// and this node at its later one: both are back on the old link.
#[test]
fn sync_link_change_reverts_on_both_without_the_peer() {
    let (mut a, mut b) = synced_pair();
    a.c.apply(moved_sync_link(), &staging(1, None)).unwrap();
    let g2 = a.c.generation(2).unwrap();
    b.c.receive(&g2, a.c.document_value(2).unwrap(), PeerGate::PeerConfirms)
        .unwrap();
    a.c.activate_staged(2, 0).unwrap();
    let peer_deadline = b.c.state().unwrap().pending.unwrap().deadline;
    let our_deadline = a.c.state().unwrap().pending.unwrap().deadline;
    assert_eq!(b.c.tick(peer_deadline).unwrap(), Some(1));
    assert_eq!(a.c.tick(peer_deadline).unwrap(), None);
    assert_eq!(a.c.tick(our_deadline).unwrap(), Some(1));
    for t in [&a, &b] {
        let st = t.c.state().unwrap();
        assert_eq!((st.active, st.confirmed, st.pending), (1, 1, None));
    }
    assert_eq!(
        a.c.document_value(1).unwrap()["networks"]["sync"],
        paired_example()["networks"]["sync"]
    );
}

/// #25: a change made here between staging and running the sync-link
/// change wins; the staged one is set aside. A rollback across a
/// sync-link change is staged like any other.
#[test]
fn staged_sync_link_change_yields_and_rollback_stages() {
    let (mut a, _b) = synced_pair();
    a.c.apply(moved_sync_link(), &staging(1, None)).unwrap();
    let mut v = paired_example();
    v["networks"]["users"]["mtu"] = json!(1400);
    let r = a.c.apply(v, &opts(1, None)).unwrap();
    assert_eq!(r.generation.id, 3);
    assert!(matches!(
        a.c.activate_staged(2, 0),
        Err(Error::Conflict { current: 3 })
    ));
    assert!(!a.c.store().exists(2));
    assert_eq!(a.c.active().unwrap(), 3);

    // Now move the link properly, then roll it back.
    let (mut a2, mut b2) = synced_pair();
    a2.c.apply(moved_sync_link(), &staging(1, None)).unwrap();
    let g2 = a2.c.generation(2).unwrap();
    b2.c.receive(&g2, a2.c.document_value(2).unwrap(), PeerGate::PeerConfirms)
        .unwrap();
    a2.c.activate_staged(2, 0).unwrap();
    b2.c.confirm_received(2).unwrap();
    a2.c.peer_confirmed(2).unwrap();
    let (g, staged) = a2.c.rollback_staging(None, "admin", true).unwrap();
    assert!(staged);
    assert_eq!((g.id, a2.c.active().unwrap()), (3, 2));
}
