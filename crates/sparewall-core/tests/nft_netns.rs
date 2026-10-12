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

/// Real nft for the firewall, a fake for the rest: what a coordinator
/// needs to load and verify rules in a namespace.
struct RealNft {
    nft: Linux,
    rest: sparewall_core::system::Fake,
}

impl System for RealNft {
    fn nft_check(&mut self, body: &str, preserved: &[String]) -> Result<(), sparewall_core::Error> {
        self.nft.nft_check(body, preserved)
    }
    fn nft_load(
        &mut self,
        body: &str,
        preserved: &[String],
    ) -> Result<Vec<String>, sparewall_core::Error> {
        self.nft.nft_load(body, preserved)
    }
    fn nft_chains(&mut self) -> Result<Option<Vec<String>>, sparewall_core::Error> {
        self.nft.nft_chains()
    }
    fn nft_json(&mut self) -> Result<Option<serde_json::Value>, sparewall_core::Error> {
        self.nft.nft_json()
    }
    fn networkd_apply(
        &mut self,
        old: &sparewall_core::system::Files,
        new: &sparewall_core::system::Files,
        early: bool,
    ) -> Result<(), sparewall_core::Error> {
        self.rest.networkd_apply(old, new, early)
    }
    fn networkd_reconfigure(&mut self, links: &[String]) -> Result<(), sparewall_core::Error> {
        self.rest.networkd_reconfigure(links)
    }
    fn sysctl_apply(&mut self, content: &str) -> Result<(), sparewall_core::Error> {
        self.rest.sysctl_apply(content)
    }
    fn link_states(&mut self) -> std::collections::BTreeMap<String, String> {
        self.rest.link_states()
    }
    fn install_files(
        &mut self,
        sub: sparewall_render::Subsystem,
        files: &sparewall_core::system::Files,
    ) -> Result<(), sparewall_core::Error> {
        self.rest.install_files(sub, files)
    }
    fn service_check(
        &mut self,
        spec: &sparewall_render::CheckSpec,
        files: &sparewall_core::system::Files,
    ) -> Result<(), sparewall_core::Error> {
        self.rest.service_check(spec, files)
    }
    fn services_apply(
        &mut self,
        meta: &sparewall_render::Meta,
        changed: &[sparewall_render::Subsystem],
    ) -> Result<(), sparewall_core::Error> {
        self.rest.services_apply(meta, changed)
    }
    fn unit_states(&mut self, units: &[String]) -> std::collections::BTreeMap<String, String> {
        self.rest.unit_states(units)
    }
    fn proc_sys(&mut self, key: &str) -> Option<String> {
        self.rest.proc_sys(key)
    }
    fn sync_public_key(&mut self) -> Result<String, sparewall_core::Error> {
        self.rest.sync_public_key()
    }
    fn encrypt(&mut self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>, sparewall_core::Error> {
        self.rest.encrypt(name, plaintext)
    }
    fn decrypt(&mut self, name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, sparewall_core::Error> {
        self.rest.decrypt(name, ciphertext)
    }
    fn wg_keypair(&mut self) -> Result<(String, String), sparewall_core::Error> {
        self.rest.wg_keypair()
    }
    fn wg_public(&mut self, private: &str) -> Result<String, sparewall_core::Error> {
        self.rest.wg_public(private)
    }
    fn install_key(
        &mut self,
        file: &str,
        content: &[u8],
        group: &str,
    ) -> Result<(), sparewall_core::Error> {
        self.rest.install_key(file, content, group)
    }
    fn netdev_recreate(&mut self, name: &str) -> Result<(), sparewall_core::Error> {
        self.rest.netdev_recreate(name)
    }
}

/// Issue #5 against the real kernel: change the live rules without
/// touching the chain names, and readiness fails; legitimate runtime
/// changes (networkd's set elements, counters) do not; a reload recovers.
#[test]
fn live_rule_drift_fails_readiness() {
    use sparewall_core::{Coordinator, Level};
    if reexec("live_rule_drift_fails_readiness") {
        return;
    }
    let (_dir, mut c) = applied(sparewall_config::parse_value(&example(), Format::Yaml).unwrap());
    let ready = |c: &mut Coordinator<RealNft>| {
        let h = c.health().unwrap();
        (h.level, h.check("nft").unwrap().message.clone())
    };
    assert_eq!(ready(&mut c).0, Level::Ok, "{:?}", c.health().unwrap());

    // Legitimate runtime changes: networkd fills its set, traffic counts.
    nft(&[
        "add",
        "element",
        "inet",
        "sparewall",
        "wan_address",
        "{ 203.0.113.77 }",
    ]);
    sh("ip link set lo up; ping -c 2 -W 1 127.0.0.1 >/dev/null || true");
    assert_eq!(ready(&mut c).0, Level::Ok, "runtime changes are not drift");

    let tamper: &[(&str, &str, &str)] = &[
        (
            "flush the input rules, keep the chain",
            "flush chain inet sparewall input",
            "rules input",
        ),
        (
            "an unexpected rule",
            "insert rule inet sparewall input accept",
            "rules input",
        ),
        (
            "a chain's policy",
            "chain inet sparewall input { policy accept ; }",
            "chain input",
        ),
        (
            "a static set's elements",
            "add element inet sparewall admin_nets { 0.0.0.0/1 }",
            "set admin_nets",
        ),
        (
            "an unexpected chain",
            "add chain inet sparewall sneaky",
            "chain sneaky",
        ),
        (
            "the whole table",
            "delete table inet sparewall",
            "not loaded",
        ),
    ];
    for (what, cmd, expect) in tamper {
        sh(&format!("nft '{cmd}'"));
        let (level, msg) = ready(&mut c);
        assert_eq!(level, Level::Failed, "{what}: readiness still ok");
        assert!(msg.contains(expect), "{what}: {msg}");
        assert_eq!(
            c.hashes().unwrap().1,
            None,
            "{what}: still reported applied"
        );
        // Reloading the generation (as a sparewalld restart does) repairs it.
        c.boot(false).unwrap();
        assert_eq!(
            ready(&mut c).0,
            Level::Ok,
            "{what}: not repaired by a reload"
        );
    }
}

/// A coordinator with real nft (and everything else faked) that has
/// applied `doc` in this namespace.
fn applied(doc: serde_json::Value) -> (tempfile::TempDir, sparewall_core::Coordinator<RealNft>) {
    use sparewall_core::{ApplyOptions, Coordinator, Store};
    let dir = tempfile::tempdir().unwrap();
    let mut rest = sparewall_core::system::Fake::default();
    let r = sparewall_render::render(&sparewall_config::from_value(doc.clone()).unwrap(), "fw1")
        .unwrap();
    for l in &r.meta.required_links {
        rest.links.insert(l.clone(), "up".into());
    }
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
    let mut c = Coordinator::new(
        Store::open(dir.path()).unwrap(),
        RealNft {
            nft: Linux::default(),
            rest,
        },
        id,
    );
    c.boot(false).unwrap();
    c.apply(
        doc,
        &ApplyOptions {
            base: 0,
            author: "test".into(),
            ..Default::default()
        },
    )
    .unwrap();
    (dir, c)
}

/// Traffic using up part of a quota is not drift; changing the quota's
/// limit is (review of #17).
#[test]
fn quota_use_is_not_drift() {
    use sparewall_core::Level;
    if reexec("quota_use_is_not_drift") {
        return;
    }
    let mut doc = sparewall_config::parse_value(&example(), Format::Yaml).unwrap();
    sparewall_config::merge_patch(
        &mut doc,
        &serde_json::json!({"raw": {"quota-review": {
            "at": {"hook": "prerouting-raw"}, "order": 10,
            "nft": "ip protocol icmp quota 100000 bytes accept"}}}),
    );
    let (_dir, mut c) = applied(doc);
    let nft_check = |c: &mut sparewall_core::Coordinator<RealNft>| {
        let h = c.health().unwrap();
        let n = h.check("nft").unwrap().clone();
        (n.level, n.message)
    };
    assert_eq!(nft_check(&mut c).0, Level::Ok);
    sh("ip link set lo up; ping -c 2 -W 1 127.0.0.1 >/dev/null");
    let chain = nft(&["list", "chain", "inet", "sparewall", "prerouting_raw"]);
    assert!(
        chain.contains("used"),
        "the quota counted nothing:\n{chain}"
    );
    let (level, msg) = nft_check(&mut c);
    assert_eq!(level, Level::Ok, "quota use counted as drift: {msg}");
    assert!(c.hashes().unwrap().1.is_some());

    // The configured limit changed in place.
    sh(
        "h=$(nft -a list chain inet sparewall prerouting_raw | sed -n 's/.*quota.*# handle //p'); \
        nft replace rule inet sparewall prerouting_raw handle $h ip protocol icmp quota 200000 bytes accept",
    );
    let (level, msg) = nft_check(&mut c);
    assert_eq!(
        level,
        Level::Failed,
        "a changed quota limit was not detected"
    );
    assert!(msg.contains("changed: rules prerouting_raw"), "{msg}");
}

fn sh(cmd: &str) {
    let st = Command::new("sh").args(["-ec", cmd]).status().unwrap();
    assert!(st.success(), "{cmd}");
}
