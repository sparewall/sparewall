//! Two sparewalld instances (fake system adapters) as an HA pair, talking
//! over their sync-tunnel addresses inside a private network namespace.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const INSIDE: &str = "SPAREWALL_TEST_IN_NETNS";

fn reexec(name: &str) -> bool {
    if std::env::var_os(INSIDE).is_some() {
        return false;
    }
    let ok = Command::new("unshare")
        .args(["-rn", "true"])
        .status()
        .is_ok_and(|s| s.success());
    if !ok || bin("sparewalld").is_none() {
        eprintln!("skipping {name}: no unprivileged namespaces, or sparewalld not built");
        return true;
    }
    let out = Command::new("unshare")
        .arg("-rn")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(INSIDE, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "inner test failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    true
}

fn bin(name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_BIN_EXE_sparewall"))
        .parent()?
        .join(name);
    p.exists().then_some(p)
}

struct Node {
    name: &'static str,
    dir: PathBuf,
    child: Option<Child>,
}

impl Node {
    fn new(root: &Path, name: &'static str) -> Node {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("id.yaml"),
            format!("node: {name}\nmanagement: {{ nic: \"52:54:00:aa:00:01\" }}\n"),
        )
        .unwrap();
        let mut n = Node {
            name,
            dir,
            child: None,
        };
        n.start();
        n
    }

    fn start(&mut self) {
        let log = std::fs::File::create(self.dir.join("log")).unwrap();
        let child = Command::new(bin("sparewalld").unwrap())
            .arg("--state")
            .arg(self.dir.join("state"))
            .arg("--socket")
            .arg(self.dir.join("fw.sock"))
            .arg("--identity")
            .arg(self.dir.join("id.yaml"))
            .args(["--fake-system", "--https", "off"])
            .env("SPAREWALL_LOG", "info")
            .stderr(log)
            .spawn()
            .unwrap();
        let sock = self.dir.join("fw.sock");
        let t0 = Instant::now();
        while !sock.exists() {
            assert!(
                t0.elapsed() < Duration::from_secs(10),
                "{} did not start",
                self.name
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        self.child = Some(child);
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_file(self.dir.join("fw.sock"));
    }

    fn sw(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sparewall"))
            .args(args)
            .env("SPAREWALL_SOCKET", self.dir.join("fw.sock"))
            .env("XDG_CONFIG_HOME", &self.dir)
            .env_remove("SSH_CONNECTION")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let o = self.sw(args);
        assert!(
            o.status.success(),
            "{}: sparewall {args:?}: {}\n--- log\n{}",
            self.name,
            String::from_utf8_lossy(&o.stderr),
            std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
        );
        String::from_utf8(o.stdout).unwrap()
    }

    fn status(&self) -> serde_json::Value {
        serde_json::from_str(&self.ok(&["status", "-o", "json"])).unwrap()
    }

    /// Wait until `f` holds for this node's status.
    fn wait(&self, what: &str, f: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        let t0 = Instant::now();
        loop {
            let s = self.status();
            if f(&s) {
                return s;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(40),
                "{}: timed out waiting for {what}: {}\n--- log\n{}",
                self.name,
                s["sync"],
                std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

fn pair_doc(root: &Path) -> PathBuf {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/pair.yaml"
    ))
    .unwrap();
    let keys = "  sync_keys:\n    fw1: \"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=\"\n    fw2: \"ZmVkY2JhWllYV1ZVVFNSUVBPTk1MS0pJSEdGRURDQkE=\"\n";
    let text = text.replacen(
        "  sync_network: sync\n",
        &format!("  sync_network: sync\n{keys}"),
        1,
    );
    let p = root.join("pair.yaml");
    std::fs::write(&p, text).unwrap();
    p
}

#[test]
fn pair_pushes_refuses_and_catches_up() {
    if reexec("pair_pushes_refuses_and_catches_up") {
        return;
    }
    // The sync-tunnel addresses networkd would put on swsync.
    for a in ["169.254.77.1/30", "169.254.77.2/30"] {
        assert!(
            Command::new("ip")
                .args(["addr", "add", a, "dev", "lo"])
                .status()
                .unwrap()
                .success()
        );
    }
    assert!(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    let root = tempfile::tempdir().unwrap();
    let doc = pair_doc(root.path());
    let doc = doc.to_str().unwrap();
    let fw1 = Node::new(root.path(), "fw1");
    let mut fw2 = Node::new(root.path(), "fw2");

    // Pairing: the same document applied on each node.
    fw1.ok(&["apply", "-f", doc, "--confirm", "0"]);
    fw2.ok(&["apply", "-f", doc, "--confirm", "0"]);
    fw1.wait("in sync", |s| s["sync"]["state"] == "in-sync");
    fw2.wait("in sync", |s| s["sync"]["state"] == "in-sync");

    // Each node generated a VPN server key when it applied the pairing
    // document; they converge on the first one.
    let config = |n: &Node| n.ok(&["vpn", "client-config", "alice-laptop"]);
    let t0 = Instant::now();
    while config(&fw1) != config(&fw2) {
        assert!(
            t0.elapsed() < Duration::from_secs(40),
            "VPN keys did not converge"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(config(&fw1).contains("Endpoint = vpn.example.org:51820"));

    // A new cluster secret reaches the peer; values never come back out.
    let mut set = Command::new(env!("CARGO_BIN_EXE_sparewall"))
        .args(["secret", "set", "dns-tsig"])
        .env("SPAREWALL_SOCKET", fw1.dir.join("fw.sock"))
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        set.stdin.take().unwrap().write_all(b"hunter2\n").unwrap();
    }
    assert!(set.wait().unwrap().success());
    let t0 = Instant::now();
    while !fw2.ok(&["secret", "list"]).contains("dns-tsig") {
        assert!(
            t0.elapsed() < Duration::from_secs(40),
            "secret did not reach fw2"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(
        !fw2.ok(&["secret", "list", "-o", "json"])
            .contains("hunter2")
    );

    // A change on fw1 reaches fw2 with the same generation id.
    fw1.ok(&["set", "networks.users.mtu=1400", "--confirm", "0"]);
    let s = fw2.wait("generation 2", |s| s["sync"]["active"] == 2);
    assert_eq!(
        s["sync"]["desired_hash"],
        fw1.status()["sync"]["desired_hash"]
    );
    assert_eq!(fw2.ok(&["get", "networks.users.mtu"]).trim(), "1400");

    // A change waiting for confirmation is not pushed until confirmed.
    fw1.ok(&[
        "set",
        "networks.users.mtu=1300",
        "--confirm",
        "60",
        "--no-prompt",
    ]);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(fw2.status()["sync"]["active"], 2);
    fw1.ok(&["confirm"]);
    fw2.wait("generation 3", |s| s["sync"]["active"] == 3);

    // With the peer down, changes need --allow-diverge.
    fw2.stop();
    fw1.wait("peer unreachable", |s| {
        s["sync"]["state"] == "peer-unreachable"
    });
    let o = fw1.sw(&["set", "networks.users.mtu=1200", "--confirm", "0"]);
    assert_eq!(
        o.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    fw1.ok(&[
        "set",
        "networks.users.mtu=1200",
        "--confirm",
        "0",
        "--allow-diverge",
    ]);

    // When it returns, it is behind and catches up.
    fw2.start();
    fw2.wait("catch-up", |s| {
        s["sync"]["active"] == 4 && s["sync"]["state"] == "in-sync"
    });
    assert_eq!(fw2.ok(&["get", "networks.users.mtu"]).trim(), "1200");
    let h: serde_json::Value = serde_json::from_str(&fw2.ok(&["history", "-o", "json"])).unwrap();
    assert_eq!(h[0]["id"], 4);

    // A rollback on either node becomes the pair's configuration, and
    // background sync does not undo it (#4).
    fw2.ok(&["rollback"]);
    fw1.wait("the rollback from fw2", |s| s["sync"]["active"] == 5);
    // Several sync passes later, both still run it.
    std::thread::sleep(Duration::from_secs(12));
    for n in [&fw1, &fw2] {
        let s = n.wait("in sync on the rollback", |s| {
            s["sync"]["state"] == "in-sync"
        });
        assert_eq!(s["sync"]["active"], 5, "{}", n.name);
        assert_eq!(
            n.ok(&["get", "networks.users.mtu"]).trim(),
            "1300",
            "{}",
            n.name
        );
    }
    let h: serde_json::Value = serde_json::from_str(&fw1.ok(&["history", "-o", "json"])).unwrap();
    assert_eq!(h[0]["summary"][0], "rollback to generation 3");
    assert_eq!(h[1]["id"], 4, "the rolled-back generation stays in history");
    fw1.ok(&["rollback", "4"]);
    fw2.wait("the rollback from fw1", |s| {
        s["sync"]["active"] == 6 && s["sync"]["state"] == "in-sync"
    });
    assert_eq!(fw2.ok(&["get", "networks.users.mtu"]).trim(), "1200");

    // With the peer down, a rollback needs --allow-diverge like any change,
    // but discarding an unconfirmed change (which never left) does not.
    fw2.stop();
    fw1.wait("peer unreachable", |s| {
        s["sync"]["state"] == "peer-unreachable"
    });
    assert_eq!(fw1.sw(&["rollback"]).status.code(), Some(5));
    fw1.ok(&[
        "set",
        "networks.users.mtu=1100",
        "--confirm",
        "60",
        "--no-prompt",
        "--allow-diverge",
    ]);
    fw1.ok(&["rollback"]);
    assert_eq!(fw1.status()["sync"]["active"], 6);
    assert_eq!(fw1.ok(&["get", "networks.users.mtu"]).trim(), "1200");

    // Still apart: fw1 makes a change and rolls it back. fw2 already runs
    // that content, but not that history; on its return it catches up
    // (storing generation 8 without running it; the discarded pending change
    // took 7), and a later change on
    // fw2 is an ordinary push, not divergence.
    fw1.ok(&[
        "set",
        "networks.users.mtu=1000",
        "--confirm",
        "0",
        "--allow-diverge",
    ]);
    fw1.ok(&["rollback", "--allow-diverge"]);
    assert_eq!(fw1.status()["sync"]["active"], 9);
    fw2.start();
    fw2.wait("catch-up to the rollback", |s| {
        s["sync"]["active"] == 9 && s["sync"]["state"] == "in-sync"
    });
    let h: serde_json::Value = serde_json::from_str(&fw2.ok(&["history", "-o", "json"])).unwrap();
    assert_eq!((&h[0]["id"], &h[1]["id"]), (&9.into(), &8.into()));
    assert_eq!(fw2.ok(&["get", "networks.users.mtu"]).trim(), "1200");
    fw2.ok(&["set", "networks.users.mtu=900", "--confirm", "0"]);
    fw1.wait("fw2's change", |s| {
        s["sync"]["active"] == 10 && s["sync"]["state"] == "in-sync"
    });
    assert_eq!(fw1.ok(&["get", "networks.users.mtu"]).trim(), "900");
}
