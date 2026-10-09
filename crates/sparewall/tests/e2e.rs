//! The CLI against a real sparewalld (with its fake system adapter) over
//! the Varlink socket.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

struct Daemon {
    child: Child,
    dir: tempfile::TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bin(name: &str) -> Option<PathBuf> {
    let cli = PathBuf::from(env!("CARGO_BIN_EXE_sparewall"));
    let p = cli.parent()?.join(name);
    p.exists().then_some(p)
}

fn start() -> Option<Daemon> {
    let Some(d) = bin("sparewalld") else {
        eprintln!("skipping: build sparewalld first (cargo test --workspace)");
        return None;
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("id.yaml"),
        "node: fw1\nmanagement: { nic: \"52:54:00:aa:00:01\" }\n",
    )
    .unwrap();
    let child = Command::new(d)
        .arg("--state")
        .arg(dir.path().join("state"))
        .arg("--socket")
        .arg(dir.path().join("fw.sock"))
        .arg("--identity")
        .arg(dir.path().join("id.yaml"))
        .arg("--fake-system")
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let sock = dir.path().join("fw.sock");
    let t0 = Instant::now();
    while !sock.exists() {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "daemon did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Some(Daemon { child, dir })
}

fn sw(d: &Daemon, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sparewall"))
        .args(args)
        .env("SPAREWALL_SOCKET", d.dir.path().join("fw.sock"))
        .env("XDG_CONFIG_HOME", d.dir.path())
        .env_remove("SSH_CONNECTION")
        .output()
        .unwrap()
}

fn ok(d: &Daemon, args: &[&str]) -> String {
    let o = sw(d, args);
    assert!(
        o.status.success(),
        "sparewall {args:?} failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap()
}

fn example() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/standalone.yaml")
        .display()
        .to_string()
}

#[test]
fn apply_set_get_rollback() {
    let Some(d) = start() else { return };
    ok(&d, &["apply", "-f", &example(), "--confirm", "0"]);
    ok(
        &d,
        &[
            "set",
            "networks.users.mtu=1400",
            "policy.users->wan.log=true",
        ],
    );
    assert_eq!(ok(&d, &["get", "networks.users.mtu"]).trim(), "1400");
    let h = ok(&d, &["history", "-o", "json"]);
    let h: serde_json::Value = serde_json::from_str(&h).unwrap();
    assert_eq!(h.as_array().unwrap().len(), 2);
    assert_eq!(h[0]["summary"][0], "+ networks.users.mtu = 1400");
    ok(&d, &["rollback"]);
    assert_eq!(
        sw(&d, &["get", "networks.users.mtu"]).status.code(),
        Some(2)
    );
    // Export round-trips through apply as a no-op.
    let exported = d.dir.path().join("export.yaml");
    std::fs::write(&exported, ok(&d, &["export"])).unwrap();
    let o = sw(&d, &["apply", "-f", exported.to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("No change"));
}

#[test]
fn validation_errors_exit_3() {
    let Some(d) = start() else { return };
    ok(&d, &["apply", "-f", &example(), "--confirm", "0"]);
    let o = sw(&d, &["set", "zones.users.networks=[nope]"]);
    assert_eq!(o.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&o.stderr).contains("no network named \"nope\""));
    let o = sw(&d, &["set", "networks.users.vlan=abc"]);
    assert_eq!(o.status.code(), Some(3));
}

#[test]
fn unconfirmed_change_reverts() {
    let Some(d) = start() else { return };
    ok(&d, &["apply", "-f", &example(), "--confirm", "0"]);
    let o = ok(
        &d,
        &[
            "set",
            "networks.users.mtu=1300",
            "--confirm",
            "1",
            "--no-prompt",
        ],
    );
    let _ = o;
    let s: serde_json::Value = serde_json::from_str(&ok(&d, &["status", "-o", "json"])).unwrap();
    assert_eq!(s["sync"]["pending"]["id"], 2);
    std::thread::sleep(Duration::from_millis(2500));
    let s: serde_json::Value = serde_json::from_str(&ok(&d, &["status", "-o", "json"])).unwrap();
    assert_eq!(s["sync"]["active"], 1);
    assert!(s["sync"]["pending"].is_null());
}

#[test]
fn confirm_keeps_change() {
    let Some(d) = start() else { return };
    ok(&d, &["apply", "-f", &example(), "--confirm", "0"]);
    ok(
        &d,
        &[
            "set",
            "networks.users.mtu=1300",
            "--confirm",
            "60",
            "--no-prompt",
        ],
    );
    ok(&d, &["confirm"]);
    let s: serde_json::Value = serde_json::from_str(&ok(&d, &["status", "-o", "json"])).unwrap();
    assert_eq!(
        (
            s["sync"]["active"].as_u64(),
            s["sync"]["confirmed"].as_u64()
        ),
        (Some(2), Some(2))
    );
}
