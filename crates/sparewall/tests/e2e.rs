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
    start_in(tempfile::tempdir().unwrap())
}

/// Start a daemon whose state is `<dir>/state`.
fn start_in(dir: tempfile::TempDir) -> Option<Daemon> {
    let Some(d) = bin("sparewalld") else {
        eprintln!("skipping: build sparewalld first (cargo test --workspace)");
        return None;
    };
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
        .arg("--api-socket")
        .arg(dir.path().join("api.sock"))
        .arg("--identity")
        .arg(dir.path().join("id.yaml"))
        .arg("--fake-system")
        .arg("--motd")
        .arg(dir.path().join("motd"))
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

/// With `SPAREWALL_TOKEN`, the CLI works through the restricted socket
/// with the token's role (#11).
#[test]
fn tokens_on_the_restricted_socket() {
    let Some(d) = start() else { return };
    let token = |name: &str, role: &str| {
        ok(&d, &["token", "create", name, "--role", role, "-q"])
            .trim()
            .to_string()
    };
    let (viewer, operator) = (token("ro", "viewer"), token("ci", "operator"));
    let as_token = |t: &str, args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sparewall"))
            .args(args)
            .env("SPAREWALL_SOCKET", d.dir.path().join("api.sock"))
            .env("SPAREWALL_TOKEN", t)
            .env("XDG_CONFIG_HOME", d.dir.path())
            .env_remove("SSH_CONNECTION")
            .output()
            .unwrap()
    };
    let o = as_token(&viewer, &["apply", "-f", &example(), "--confirm", "0"]);
    assert_eq!(o.status.code(), Some(6), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("needs the operator role"),
        "{o:?}"
    );
    let o = as_token(&operator, &["apply", "-f", &example(), "--confirm", "0"]);
    assert!(o.status.success(), "{o:?}");
    let o = as_token(&viewer, &["history", "-o", "json"]);
    let h: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(h[0]["author"], "token ci");
    let o = as_token("swt_wrong", &["status"]);
    assert_eq!(o.status.code(), Some(6), "{o:?}");
    // The token commands themselves are an admin's.
    let o = as_token(&operator, &["token", "list"]);
    assert_eq!(o.status.code(), Some(6), "{o:?}");
}

/// `sparewall user` adds, lists, changes and removes users.
#[test]
fn users_add_list_and_remove() {
    let Some(d) = start() else { return };
    let o = sw_stdin(&d, &["user", "add", "alice", "--role", "operator"], "pw\n");
    assert!(o.status.success(), "{o:?}");
    let o = sw_stdin(&d, &["user", "add", "alice"], "pw\n");
    assert_eq!(o.status.code(), Some(2), "exists: {o:?}");
    let users = |d: &Daemon| -> serde_json::Value {
        serde_json::from_str(&ok(d, &["user", "list", "-o", "json"])).unwrap()
    };
    let u = users(&d);
    assert_eq!(u[1]["name"], "alice");
    assert_eq!(
        (u[1]["role"].as_str(), u[1]["locked"].as_bool()),
        (Some("operator"), Some(false))
    );
    ok(&d, &["user", "role", "alice", "viewer"]);
    ok(&d, &["user", "passwd", "alice", "--lock"]);
    let u = users(&d);
    assert_eq!(
        (u[1]["role"].as_str(), u[1]["locked"].as_bool()),
        (Some("viewer"), Some(true))
    );
    ok(&d, &["user", "remove", "alice"]);
    assert_eq!(users(&d).as_array().unwrap().len(), 1);
    assert_eq!(
        sw(&d, &["user", "passwd", "alice", "--lock"]).status.code(),
        Some(2)
    );
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

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn sw_stdin(d: &Daemon, args: &[&str], input: &str) -> Output {
    use std::io::Write;
    let mut c = Command::new(env!("CARGO_BIN_EXE_sparewall"))
        .args(args)
        .env("SPAREWALL_SOCKET", d.dir.path().join("fw.sock"))
        .env("XDG_CONFIG_HOME", d.dir.path())
        .env_remove("SSH_CONNECTION")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    c.wait_with_output().unwrap()
}

/// Back up to a restic repository, lose the node, restore from the
/// repository onto a fresh state directory.
#[test]
fn backup_to_restic_and_restore() {
    if !have("restic") {
        eprintln!("skipping: restic is not installed");
        return;
    }
    let Some(d) = start() else { return };
    let repo = d.dir.path().join("repo");
    ok(&d, &["apply", "-f", &example(), "--confirm", "0"]);
    for (name, value) in [("backup-password", "correct horse"), ("dns-key", "s3cret")] {
        let o = sw_stdin(&d, &["secret", "set", name], value);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    ok(
        &d,
        &[
            "set",
            "backup.enabled=true",
            &format!("backup.repository={}", repo.display()),
            "networks.users.mtu=1400",
        ],
    );
    let o = sw(&d, &["backup"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "{err}");
    assert!(err.contains("snapshot"), "{err}");

    // The node is gone; a new one restores from the repository.
    let fresh = tempfile::tempdir().unwrap();
    let pw = fresh.path().join("pw");
    std::fs::write(&pw, "wrong\n").unwrap();
    let restore = |pw: &Path| {
        Command::new(env!("CARGO_BIN_EXE_sparewall"))
            .args(["restore", "--fake-system", "--node", "fw1", "--repository"])
            .arg(&repo)
            .arg("--password-file")
            .arg(pw)
            .arg("--state")
            .arg(fresh.path().join("state"))
            .arg("--leases")
            .arg(fresh.path().join("leases.csv"))
            .output()
            .unwrap()
    };
    let o = restore(&pw);
    assert!(!o.status.success());
    std::fs::write(&pw, "correct horse\n").unwrap();
    let o = restore(&pw);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "{err}");
    assert!(err.contains("2 secrets"), "{err}");
    drop(d);

    let d = start_in(fresh).unwrap();
    assert_eq!(ok(&d, &["get", "networks.users.mtu"]).trim(), "1400");
    let secrets = ok(&d, &["secret", "list"]);
    assert!(
        secrets.contains("backup-password") && secrets.contains("dns-key"),
        "{secrets}"
    );
}

#[test]
fn init_from_a_seed_file() {
    let dir = tempfile::tempdir().unwrap();
    let init = |file: &str, text: &str| {
        let seed = dir.path().join(file);
        std::fs::write(&seed, text).unwrap();
        let out = dir.path().join("identity.json");
        let _ = std::fs::remove_file(&out);
        let o = Command::new(env!("CARGO_BIN_EXE_sparewall"))
            .args(["init", "--from"])
            .arg(&seed)
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap();
        (o, std::fs::read_to_string(&out).ok())
    };
    let (o, written) = init(
        "sparewall-identity.yaml",
        "node: fw1\nssh_keys: [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ci\"]\nmanagement: { nic: \"52:54:00:aa:00:01\", vlan: 99 }\n",
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_str(&written.unwrap()).unwrap();
    assert_eq!(
        (&v["node"], &v["management"]["vlan"]),
        (&"fw1".into(), &99.into())
    );

    // A broken identity is refused and nothing is written.
    let (o, written) = init("bad.json", r#"{"node": "fw1"}"#);
    assert_eq!(
        o.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(written.is_none());

    // --from stands alone.
    let o = Command::new(env!("CARGO_BIN_EXE_sparewall"))
        .args(["init", "--from", "x.yaml", "--node", "fw1"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
}

/// A fake `ssh` first in PATH: SCRIPT runs with ssh's arguments.
fn fake_ssh(dir: &Path, script: &str) -> std::ffi::OsString {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let ssh = bin.join("ssh");
    std::fs::write(&ssh, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut path = bin.into_os_string();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    path
}

#[test]
fn over_ssh_through_the_bridge() {
    let Some(d) = start() else { return };
    // Stands in for `ssh host sudo -n sparewall bridge`.
    let path = fake_ssh(
        d.dir.path(),
        &format!(
            "exec '{}' --socket '{}' bridge",
            env!("CARGO_BIN_EXE_sparewall"),
            d.dir.path().join("fw.sock").display()
        ),
    );
    let o = Command::new(env!("CARGO_BIN_EXE_sparewall"))
        .args(["--host", "admin@fw1", "status"])
        .env("PATH", path)
        .env("XDG_CONFIG_HOME", d.dir.path())
        .env_remove("SPAREWALL_SOCKET")
        .env_remove("SSH_CONNECTION")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("fw1"));
}

#[test]
fn ssh_stderr_does_not_stall_the_relay() {
    let Some(d) = start() else { return };
    // Far more than a pipe holds, before ssh's stdout carries anything.
    let path = fake_ssh(
        d.dir.path(),
        &format!(
            "head -c 1000000 /dev/zero | tr '\\0' x >&2; echo >&2\n\
             exec '{}' --socket '{}' bridge",
            env!("CARGO_BIN_EXE_sparewall"),
            d.dir.path().join("fw.sock").display()
        ),
    );
    let o = Command::new(env!("CARGO_BIN_EXE_sparewall"))
        .args(["--host", "admin@fw1", "status"])
        .env("PATH", path)
        .env("XDG_CONFIG_HOME", d.dir.path())
        .env_remove("SPAREWALL_SOCKET")
        .env_remove("SSH_CONNECTION")
        .output()
        .unwrap();
    assert!(o.status.success());
    assert!(o.stderr.len() > 1_000_000);
    assert!(String::from_utf8_lossy(&o.stdout).contains("fw1"));
}

#[test]
fn unknown_host_key_hint() {
    let dir = tempfile::tempdir().unwrap();
    let path = fake_ssh(
        dir.path(),
        "echo 'Host key verification failed.' >&2; exit 255",
    );
    let o = Command::new(env!("CARGO_BIN_EXE_sparewall"))
        .args(["--host", "admin@fw1", "status"])
        .env("PATH", path)
        .env("XDG_CONFIG_HOME", dir.path())
        .env_remove("SPAREWALL_SOCKET")
        .env_remove("SSH_CONNECTION")
        .output()
        .unwrap();
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    let (ssh, hint) = (
        err.find("Host key verification failed.").expect(&err),
        err.find("`ssh admin@fw1` once").expect(&err),
    );
    assert!(ssh < hint, "{err}");
}

#[test]
fn reconnects_after_the_change_cuts_the_session() {
    let Some(d) = start() else { return };
    // The second session carries the apply (the first reads the current
    // generation): it reaches the node, but the reply is lost and the
    // session ends, as when the change renames the management port.
    let path = fake_ssh(
        d.dir.path(),
        &format!(
            "n=$(($(cat '{dir}/n' 2>/dev/null || echo 0) + 1)); echo $n > '{dir}/n'\n\
             if [ $n = 2 ]; then timeout 2 '{cli}' --socket '{sock}' bridge >/dev/null; exit 255; fi\n\
             exec '{cli}' --socket '{sock}' bridge",
            dir = d.dir.path().display(),
            cli = env!("CARGO_BIN_EXE_sparewall"),
            sock = d.dir.path().join("fw.sock").display()
        ),
    );
    let o = Command::new(env!("CARGO_BIN_EXE_sparewall"))
        .args(["--host", "admin@fw1", "apply", "-f", &example()])
        .args(["--confirm", "60", "--no-prompt"])
        .env("PATH", path)
        .env("XDG_CONFIG_HOME", d.dir.path())
        .env_remove("SPAREWALL_SOCKET")
        .env_remove("SSH_CONNECTION")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "{err}");
    assert!(err.contains("connection was lost"), "{err}");
    assert!(
        err.contains("Reconnected: generation 1; it reverts in"),
        "{err}"
    );
    let s = ok(&d, &["status", "-o", "json"]);
    let s: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(s["sync"]["pending"]["id"], 1);
}

#[test]
fn reconnect_does_not_claim_another_change() {
    let Some(d) = start() else { return };
    // The session carrying this apply is lost before the node sees it,
    // and meanwhile someone else applies a different document: the CLI
    // must not offer to keep that one as its own.
    let other = d.dir.path().join("other.yaml");
    let text = std::fs::read_to_string(example()).unwrap();
    assert!(text.contains("lease_time: 3600"));
    std::fs::write(&other, text.replace("lease_time: 3600", "lease_time: 1800")).unwrap();
    let path = fake_ssh(
        d.dir.path(),
        &format!(
            "n=$(($(cat '{dir}/n' 2>/dev/null || echo 0) + 1)); echo $n > '{dir}/n'\n\
             if [ $n = 2 ]; then '{cli}' --socket '{sock}' apply -f '{other}' --confirm 60 --no-prompt -q; exit 255; fi\n\
             exec '{cli}' --socket '{sock}' bridge",
            dir = d.dir.path().display(),
            cli = env!("CARGO_BIN_EXE_sparewall"),
            sock = d.dir.path().join("fw.sock").display(),
            other = other.display(),
        ),
    );
    let o = Command::new(env!("CARGO_BIN_EXE_sparewall"))
        .args(["--host", "admin@fw1", "apply", "-f", &example()])
        .args(["--confirm", "60", "--no-prompt"])
        .env("PATH", path)
        .env("XDG_CONFIG_HOME", d.dir.path())
        .env_remove("SPAREWALL_SOCKET")
        .env_remove("SSH_CONNECTION")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success(), "{err}");
    assert!(err.contains("generation 1 is not this change"), "{err}");
    assert!(!err.contains("Reconnected: generation"), "{err}");
}

#[test]
fn login_banner_follows_health() {
    let Some(d) = start() else { return };
    let motd = d.dir.path().join("motd");
    let wait_for = |want: &str| {
        let t0 = Instant::now();
        loop {
            let text = std::fs::read_to_string(&motd).unwrap_or_default();
            if text.contains(want) {
                return text;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(20),
                "no {want:?} in: {text}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    };
    let text = wait_for("Sparewall fw1: bootstrap, generation 0");
    assert!(text.contains("bootstrap mode"), "{text}");
    ok(
        &d,
        &["apply", "-f", &example(), "--confirm", "60", "--no-prompt"],
    );
    wait_for("generation 1 (pending confirmation)");
    ok(&d, &["confirm", "1"]);
    let text = wait_for("generation 1, health");
    assert!(text.contains("(as of "), "{text}");
}

#[test]
fn admin_password_set_and_locked() {
    let Some(d) = start() else { return };
    let version = |d: &Daemon| -> Option<u64> {
        let l: serde_json::Value =
            serde_json::from_str(&ok(d, &["secret", "list", "-o", "json"])).unwrap();
        l.as_array()?
            .iter()
            .find(|s| s["name"] == "admin-password")?["version"]
            .as_u64()
    };
    assert_eq!(version(&d), None);
    let o = sw_stdin(&d, &["passwd"], "correct horse\n");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(version(&d), Some(1));
    // Only a hash is stored: anything else through `secret set` is refused.
    let o = sw_stdin(&d, &["secret", "set", "admin-password"], "correct horse\n");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("sparewall passwd"));
    // Deleting would not reach the peer: locking is a new version.
    let o = sw(&d, &["secret", "delete", "admin-password"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("passwd --lock"));
    ok(&d, &["passwd", "--lock"]);
    assert_eq!(version(&d), Some(2));
}
