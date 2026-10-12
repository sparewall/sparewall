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
#[test]
fn replication_link_loss_degrades_health() {
    let all_up = |t: &mut T| {
        let r = sparewall_render::render(
            &sparewall_config::from_value(t.c.document_value(t.c.active().unwrap()).unwrap())
                .unwrap(),
            "fw1",
        )
        .unwrap();
        for l in r
            .meta
            .required_links
            .iter()
            .chain(&r.meta.replication_links)
        {
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
    let mut t = pair_node("fw1");
    // Sync as a VLAN on the shared uplink.
    t.c.apply(pair_example(), &opts(0, None)).unwrap();
    all_up(&mut t);
    assert_eq!(levels(&mut t), (Level::Ok, Some(Level::Ok), Level::Ok));
    for (what, state) in [("down", Some("down")), ("deleted", None)] {
        match state {
            Some(s) => t.c.system().links.insert("sync".into(), s.into()),
            None => t.c.system().links.remove("sync"),
        };
        assert_eq!(
            levels(&mut t),
            (Level::Ok, Some(Level::Degraded), Level::Degraded),
            "sync VLAN {what}"
        );
        all_up(&mut t);
    }
    // The shared trunk carries traffic: losing it fails health.
    t.c.system().links.insert("uplink".into(), "down".into());
    assert_eq!(levels(&mut t).0, Level::Failed);
    assert_eq!(levels(&mut t).2, Level::Failed);
    all_up(&mut t);

    // Sync on a dedicated port: the port's loss degrades too.
    let mut v = pair_example();
    v["ports"]["fw1"]["syncp"] = json!({"nic": "52:54:00:aa:00:09"});
    v["ports"]["fw2"]["syncp"] = json!({"nic": "9c:6b:00:00:00:09"});
    v["networks"]["sync"]["port"] = json!("syncp");
    t.c.apply(v, &opts(1, None)).unwrap();
    all_up(&mut t);
    assert_eq!(levels(&mut t), (Level::Ok, Some(Level::Ok), Level::Ok));
    t.c.system().links.insert("syncp".into(), "down".into());
    t.c.system().links.insert("sync".into(), "down".into());
    assert_eq!(
        levels(&mut t),
        (Level::Ok, Some(Level::Degraded), Level::Degraded)
    );
    let msg =
        t.c.health()
            .unwrap()
            .check("replication")
            .unwrap()
            .message
            .clone();
    assert!(msg.contains("syncp is down"), "{msg}");
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
    assert!(e.to_string().contains("links"), "{e}");
    assert!(b.c.state().unwrap().pending.is_some(), "still pending");
    let deadline = b.c.state().unwrap().pending.unwrap().deadline;
    assert_eq!(b.c.tick(deadline).unwrap(), Some(1));
    assert!(b.c.state().unwrap().rejected.is_some());
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
