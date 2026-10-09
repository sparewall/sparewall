//! The Linux adapter's nft loading against a real kernel, in a private
//! user and network namespace (design, "To prove in the lab": networkd's
//! NFTSet= elements must survive a ruleset reload).
//!
//! Each test re-runs itself under `unshare -rn`; it is skipped where
//! unprivileged namespaces or nft are unavailable.

use std::process::Command;

use sparewall_config::{Format, parse};
use sparewall_core::System;
use sparewall_core::linux::Linux;

const INSIDE: &str = "SPAREWALL_TEST_IN_NETNS";

/// Run the named test inside a namespace; returns false when already
/// inside (so the caller should do the work).
fn reexec(name: &str) -> bool {
    if std::env::var_os(INSIDE).is_some() {
        return false;
    }
    let ok = Command::new("unshare")
        .args(["-rn", "true"])
        .status()
        .is_ok_and(|s| s.success())
        && Command::new("nft").arg("--version").output().is_ok();
    if !ok {
        eprintln!("skipping {name}: no unprivileged namespaces or nft");
        return true;
    }
    let exe = std::env::current_exe().unwrap();
    let out = Command::new("unshare")
        .arg("-rn")
        .arg(exe)
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(INSIDE, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "inner test failed:\n{stdout}\n{stderr}"
    );
    true
}

fn nft(args: &[&str]) -> String {
    let out = Command::new("nft").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "nft {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn rendered(text: &str) -> (String, Vec<String>) {
    let doc = parse(text, Format::Yaml).unwrap();
    let r = sparewall_render::render(&doc, "fw1").unwrap();
    (
        r.files["nftables/sparewall.nft"].clone(),
        r.meta.preserved_sets,
    )
}

fn example() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/standalone.yaml"
    ))
    .unwrap()
}

#[test]
fn reload_keeps_networkd_set_elements() {
    if reexec("reload_keeps_networkd_set_elements") {
        return;
    }
    let mut sys = Linux::default();
    let (body, preserved) = rendered(&example());
    assert_eq!(preserved, ["wan_address"]);
    assert_eq!(sys.nft_chains().unwrap(), None);
    let created = sys.nft_load(&body, &preserved).unwrap();
    assert_eq!(created, ["wan_address"], "first load creates the set");

    // networkd adds the leased address.
    nft(&[
        "add",
        "element",
        "inet",
        "sparewall",
        "wan_address",
        "{ 203.0.113.77 }",
    ]);

    // Reload a changed policy: chains are rebuilt, the element stays, and a
    // set nobody preserves is replaced.
    let changed = example().replace(
        "guests->users: { action: drop, log: true }",
        "guests->users: { action: reject }",
    );
    let (body2, preserved2) = rendered(&changed);
    sys.nft_check(&body2, &preserved2).unwrap();
    let created = sys.nft_load(&body2, &preserved2).unwrap();
    assert!(created.is_empty(), "set already existed: {created:?}");
    let set = nft(&["list", "set", "inet", "sparewall", "wan_address"]);
    assert!(set.contains("203.0.113.77"), "element lost:\n{set}");
    let chain = nft(&["list", "chain", "inet", "sparewall", "fwd_guests_users"]);
    assert!(chain.contains("reject"), "{chain}");
    assert!(!chain.contains("log group"), "{chain}");
    let admin = nft(&["list", "set", "inet", "sparewall", "admin_nets"]);
    assert!(admin.contains("10.0.99.0/24"), "{admin}");

    // Removing a chain and a set between generations works too.
    let fewer = changed.replace("  guests->users: { action: reject }\n", "");
    let (body3, preserved3) = rendered(&fewer);
    sys.nft_load(&body3, &preserved3).unwrap();
    let chains = sys.nft_chains().unwrap().unwrap();
    assert!(
        !chains.contains(&"fwd_guests_users".to_string()),
        "{chains:?}"
    );
    assert!(nft(&["list", "set", "inet", "sparewall", "wan_address"]).contains("203.0.113.77"));
}

#[test]
fn bad_script_changes_nothing() {
    if reexec("bad_script_changes_nothing") {
        return;
    }
    let mut sys = Linux::default();
    let (body, preserved) = rendered(&example());
    sys.nft_load(&body, &preserved).unwrap();
    let before = nft(&["list", "table", "inet", "sparewall"]);
    let broken = body.replace("counter comment \"default:input\"", "counter frobnicate");
    assert!(sys.nft_check(&broken, &preserved).is_err());
    assert!(sys.nft_load(&broken, &preserved).is_err());
    assert_eq!(
        nft(&["list", "table", "inet", "sparewall"]),
        before,
        "a failed load must be atomic"
    );
}

#[test]
fn bootstrap_to_full_and_back() {
    if reexec("bootstrap_to_full_and_back") {
        return;
    }
    let mut sys = Linux::default();
    let id = sparewall_config::identity::Identity {
        node: "fw1".into(),
        ssh_keys: vec![],
        management: sparewall_config::identity::BootstrapPort {
            nic: "52:54:00:aa:00:01".into(),
            vlan: None,
            address: None,
            gateway: None,
            dns: vec![],
        },
    };
    let boot = sparewall_render::render_bootstrap(&id);
    let boot_body = &boot.files["nftables/sparewall.nft"];
    sys.nft_load(boot_body, &boot.meta.preserved_sets).unwrap();
    let (body, preserved) = rendered(&example());
    sys.nft_load(&body, &preserved).unwrap();
    sys.nft_load(boot_body, &boot.meta.preserved_sets).unwrap();
    let t = nft(&["list", "table", "inet", "sparewall"]);
    assert!(
        t.contains("bootstrap:ping") && !t.contains("wan_address"),
        "{t}"
    );
}
