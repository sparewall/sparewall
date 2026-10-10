//! The real system adapter. It shells out to `nft`, `networkctl`, `udevadm`
//! and `ip` rather than reimplementing their netlink protocols (design:
//! "Adapters for everything else").

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::Value;
use sparewall_render::nft::TABLE;
use sparewall_render::{CheckSpec, Meta, Subsystem};

use crate::Error;
use crate::store::write_atomic;
use crate::system::{Files, System};

pub struct Linux {
    /// Where networkd reads runtime configuration.
    pub network_dir: PathBuf,
    /// Distribution `.network` files to mask (e.g. `89-ethernet.network`,
    /// which would run DHCP on every unclaimed NIC).
    pub vendor_network_dir: PathBuf,
    pub proc_sys: PathBuf,
    pub sys_class_net: PathBuf,
    /// Where provider files are installed, one directory per subsystem.
    pub runtime_dir: PathBuf,
    /// Where Quadlet files naming provider images live.
    pub quadlet_dir: PathBuf,
    /// The sync tunnel's private key (readable by systemd-network).
    pub sync_key: PathBuf,
    /// Services started so far. The first start is the coordinator's own
    /// startup, which must not wait for a provider (one waiting for
    /// network-online, say): those starts are queued, not awaited.
    pub started: bool,
}

/// Daemons confined by SELinux read their configuration from their own
/// runtime directory, which carries their label; the rest use
/// `/run/sparewall/<subsystem>`.
pub fn install_dir(sub: Subsystem) -> Option<&'static str> {
    match sub {
        Subsystem::Ntp => Some(sparewall_render::chrony::DIR),
        Subsystem::Keepalived => Some(sparewall_render::keepalived::DIR),
        _ => None,
    }
}

/// The SELinux type a confined daemon needs on its configuration when it
/// has no labelled runtime directory of its own.
pub fn install_label(sub: Subsystem) -> Option<&'static str> {
    match sub {
        Subsystem::Conntrackd => Some("conntrackd_conf_t"),
        _ => None,
    }
}

/// Provider units the coordinator may start; any not wanted by the live
/// generation are stopped.
pub const PROVIDER_UNITS: &[&str] = &[
    "sparewall-kea.service",
    "sparewall-unbound.service",
    "keepalived.service",
    "conntrackd.service",
    "sparewall-ulogd.service",
    "systemd-journal-upload.service",
];

impl Default for Linux {
    fn default() -> Self {
        Linux {
            network_dir: "/run/systemd/network".into(),
            vendor_network_dir: "/usr/lib/systemd/network".into(),
            proc_sys: "/proc/sys".into(),
            sys_class_net: "/sys/class/net".into(),
            runtime_dir: "/run/sparewall".into(),
            quadlet_dir: "/usr/share/containers/systemd".into(),
            sync_key: sparewall_render::SYNC_KEY_FILE.into(),
            started: false,
        }
    }
}

/// Run a command, feeding `stdin`, and return stdout; stderr becomes the
/// error.
fn run(cmd: &str, args: &[&str], stdin: Option<&str>) -> Result<String, Error> {
    tracing::debug!(cmd, ?args, "running");
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Apply(format!("cannot run {cmd}: {e}")))?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("piped")
            .write_all(input.as_bytes())
            .map_err(|e| Error::Apply(format!("{cmd}: {e}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| Error::Apply(format!("{cmd}: {e}")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(Error::Apply(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Where commands for `sparewall-run@.service` are spooled (root only).
pub const RUN_SPOOL: &str = "/run/sparewall/run";

#[derive(serde::Serialize, serde::Deserialize)]
struct Spooled {
    argv: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SpoolResult {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run a command outside this service's sandbox. Under systemd it runs as
/// the oneshot `sparewall-run@<id>.service` (podman, unshare and bootc need
/// what the coordinator's sandbox forbids); elsewhere it runs directly.
pub fn host_run(cmd: &str, args: &[&str]) -> Result<String, Error> {
    let under_systemd = std::env::var_os("INVOCATION_ID").is_some()
        && std::path::Path::new("/run/systemd/system").exists()
        && std::env::var_os("SPAREWALL_NO_HOST_RUN").is_none();
    if !under_systemd {
        return run(cmd, args, None);
    }
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = format!(
        "{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let dir = PathBuf::from(RUN_SPOOL);
    fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    let job = dir.join(format!("{id}.json"));
    let out = dir.join(format!("{id}.out.json"));
    let mut argv = vec![cmd.to_string()];
    argv.extend(args.iter().map(|a| a.to_string()));
    write_atomic(&job, &serde_json::to_vec(&Spooled { argv }).expect("json"))
        .map_err(|e| Error::io(&job, e))?;
    // A oneshot unit: `systemctl start` returns when it has finished.
    let started = run(
        "systemctl",
        &["start", &format!("sparewall-run@{id}.service")],
        None,
    );
    let result = fs::read(&out);
    let _ = fs::remove_file(&job);
    let _ = fs::remove_file(&out);
    let r: SpoolResult = match result {
        Ok(b) => {
            serde_json::from_slice(&b).map_err(|e| Error::Apply(format!("run result: {e}")))?
        }
        Err(_) => {
            started?;
            return Err(Error::Apply(format!(
                "{cmd}: no result from sparewall-run@{id}"
            )));
        }
    };
    if r.code == 0 {
        Ok(r.stdout)
    } else {
        Err(Error::Apply(format!(
            "{cmd} {}: {}",
            args.join(" "),
            r.stderr.trim()
        )))
    }
}

/// The body of `sparewall-run@<id>.service`: run a spooled command and
/// record its result.
pub fn run_spooled(id: &str) -> Result<(), Error> {
    if !id.chars().all(|c| c.is_ascii_digit() || c == '-') {
        return Err(Error::Validation(vec![format!("bad job id {id:?}")]));
    }
    let dir = PathBuf::from(RUN_SPOOL);
    let job = dir.join(format!("{id}.json"));
    let j: Spooled = serde_json::from_slice(&fs::read(&job).map_err(|e| Error::io(&job, e))?)
        .map_err(|e| Error::Internal(e.to_string()))?;
    let (cmd, args) = j
        .argv
        .split_first()
        .ok_or_else(|| Error::Internal("empty job".into()))?;
    let o = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Error::Apply(format!("{cmd}: {e}")))?;
    let r = SpoolResult {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    };
    let out = dir.join(format!("{id}.out.json"));
    write_atomic(&out, &serde_json::to_vec(&r).expect("json")).map_err(|e| Error::io(&out, e))
}

/// What the live `inet sparewall` table holds.
#[derive(Debug, Default)]
struct LiveTable {
    exists: bool,
    chains: Vec<String>,
    /// Set name to whether it is compatible with a networkd-filled set
    /// (ipv4_addr with the interval flag).
    sets: BTreeMap<String, bool>,
    maps: Vec<String>,
}

fn live_table() -> Result<LiveTable, Error> {
    let out = match run("nft", &["-j", "list", "table", "inet", TABLE], None) {
        Ok(o) => o,
        Err(Error::Apply(msg))
            if msg.contains("No such file") || msg.contains("does not exist") =>
        {
            return Ok(LiveTable::default());
        }
        Err(e) => return Err(e),
    };
    parse_live_table(&out)
}

fn parse_live_table(json: &str) -> Result<LiveTable, Error> {
    let v: Value = serde_json::from_str(json).map_err(|e| Error::Apply(format!("nft -j: {e}")))?;
    let mut t = LiveTable {
        exists: true,
        ..Default::default()
    };
    for item in v["nftables"].as_array().into_iter().flatten() {
        if let Some(c) = item.get("chain") {
            if let Some(n) = c["name"].as_str() {
                t.chains.push(n.to_string());
            }
        } else if let Some(s) = item.get("set") {
            let name = s["name"].as_str().unwrap_or_default().to_string();
            let flags: Vec<&str> = match &s["flags"] {
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                Value::String(f) => vec![f.as_str()],
                _ => vec![],
            };
            let compatible = s["type"].as_str() == Some("ipv4_addr") && flags.contains(&"interval");
            t.sets.insert(name, compatible);
        } else if let Some(m) = item.get("map")
            && let Some(n) = m["name"].as_str()
        {
            t.maps.push(n.to_string());
        }
    }
    Ok(t)
}

/// Statements that clear the coordinator-owned parts of the live table so
/// the new body can be loaded in the same transaction. Sets in `preserved`
/// survive (with their elements) when compatible.
fn prelude(live: &LiveTable, preserved: &[String]) -> (String, Vec<String>) {
    let mut s = String::new();
    if !live.exists {
        let created = preserved.to_vec();
        return (s, created);
    }
    for c in &live.chains {
        s.push_str(&format!("flush chain inet {TABLE} {c}\n"));
    }
    for c in &live.chains {
        s.push_str(&format!("delete chain inet {TABLE} {c}\n"));
    }
    for m in &live.maps {
        s.push_str(&format!("delete map inet {TABLE} {m}\n"));
    }
    let mut created = Vec::new();
    for (name, compatible) in &live.sets {
        if !(preserved.contains(name) && *compatible) {
            s.push_str(&format!("delete set inet {TABLE} {name}\n"));
        }
    }
    for p in preserved {
        if !live.sets.get(p).copied().unwrap_or(false) {
            created.push(p.clone());
        }
    }
    (s, created)
}

/// `[Section] Key=` values from an INI file.
fn ini_values<'a>(content: &'a str, section: &str, key: &str) -> Vec<&'a str> {
    let mut cur = "";
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            cur = s;
        } else if cur == section
            && let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            out.push(v.trim());
        }
    }
    out
}

impl Linux {
    fn ifaces(&self) -> Vec<String> {
        fs::read_dir(&self.sys_class_net)
            .map(|d| {
                d.filter_map(|e| e.ok()?.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Current interface name for a permanent MAC address or udev path.
    fn find_iface(&self, nic: &str) -> Option<String> {
        if sparewall_config::validate::mac_ok(nic) {
            let out = run("ip", &["-j", "-d", "link", "show"], None).ok()?;
            let v: Value = serde_json::from_str(&out).ok()?;
            let want = nic.to_ascii_lowercase();
            v.as_array()?.iter().find_map(|l| {
                let perm = l
                    .get("permaddr")
                    .or_else(|| l.get("address"))
                    .and_then(Value::as_str)?;
                (perm.eq_ignore_ascii_case(&want))
                    .then(|| l["ifname"].as_str().map(str::to_string))?
            })
        } else {
            self.ifaces().into_iter().find(|i| {
                run(
                    "udevadm",
                    &["info", "-q", "property", &format!("/sys/class/net/{i}")],
                    None,
                )
                .is_ok_and(|p| p.lines().any(|l| l == format!("ID_PATH={nic}")))
            })
        }
    }

    /// Apply a `.link` file to a running device: udev renames only devices
    /// that are down, so take it down first when the name must change.
    fn apply_link(&self, content: &str) -> Result<(), Error> {
        let Some(name) = ini_values(content, "Link", "Name")
            .first()
            .map(|s| s.to_string())
        else {
            return Ok(());
        };
        let nic = ini_values(content, "Match", "PermanentMACAddress")
            .first()
            .or(ini_values(content, "Match", "Path").first())
            .map(|s| s.to_string());
        let Some(nic) = nic else { return Ok(()) };
        let Some(cur) = self.find_iface(&nic) else {
            tracing::warn!(nic, "no device for .link file yet");
            return Ok(());
        };
        let dev = format!("/sys/class/net/{cur}");
        if cur != name {
            tracing::info!(from = cur, to = name, "renaming interface");
            run("ip", &["link", "set", "dev", &cur, "down"], None)?;
        }
        run(
            "udevadm",
            &["trigger", "--action=add", "--settle", &dev],
            None,
        )?;
        if cur != name && !self.sys_class_net.join(&name).exists() {
            // udev left it alone (another rule won): rename directly.
            run("ip", &["link", "set", "dev", &cur, "name", &name], None)?;
        }
        Ok(())
    }
}

impl System for Linux {
    fn nft_check(&mut self, body: &str, preserved: &[String]) -> Result<(), Error> {
        let (pre, _) = prelude(&live_table()?, preserved);
        run("nft", &["-c", "-f", "-"], Some(&format!("{pre}{body}")))
            .map(|_| ())
            .map_err(|e| Error::Check(e.to_string()))
    }

    fn nft_load(&mut self, body: &str, preserved: &[String]) -> Result<Vec<String>, Error> {
        let (pre, created) = prelude(&live_table()?, preserved);
        run("nft", &["-f", "-"], Some(&format!("{pre}{body}")))?;
        Ok(created)
    }

    fn nft_chains(&mut self) -> Result<Option<Vec<String>>, Error> {
        let t = live_table()?;
        Ok(t.exists.then_some(t.chains))
    }

    fn networkd_apply(&mut self, old: &Files, new: &Files, early: bool) -> Result<(), Error> {
        let dir = &self.network_dir.clone();
        fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
        // networkd's copy of the sync tunnel key.
        if new
            .values()
            .any(|c| c.contains(sparewall_render::SYNC_KEY_RUNTIME))
            && let Ok(key) = fs::read(&self.sync_key)
        {
            let name = std::path::Path::new(sparewall_render::SYNC_KEY_RUNTIME)
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned();
            self.install_key(&name, &key, "systemd-network")?;
        }
        for (name, content) in new {
            let p = dir.join(name);
            if fs::read_to_string(&p).ok().as_deref() != Some(content) {
                write_atomic(&p, content.as_bytes()).map_err(|e| Error::io(&p, e))?;
            }
        }
        // Only the document configures links: mask the vendor's .network
        // files with /dev/null symlinks in /run, leaving /etc for
        // emergency overrides.
        if let Ok(rd) = fs::read_dir(&self.vendor_network_dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let mask = dir.join(&name);
                if name.ends_with(".network")
                    && !new.contains_key(&name)
                    && fs::symlink_metadata(&mask).is_err()
                {
                    std::os::unix::fs::symlink("/dev/null", &mask)
                        .map_err(|err| Error::io(&mask, err))?;
                }
            }
        }
        // Remove our files that are no longer rendered, including leftovers
        // from an interrupted apply.
        for e in fs::read_dir(dir).map_err(|e| Error::io(dir, e))?.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.contains("-sparewall-") && !new.contains_key(&name) {
                fs::remove_file(e.path()).map_err(|err| Error::io(&e.path(), err))?;
            }
        }
        if early {
            // udevd may already have loaded its link configuration, and it
            // notices new files only every few seconds: make the coldplug
            // that follows apply ours. Best effort; udevd reads them when
            // it starts anyway.
            if new.keys().any(|n| n.ends_with(".link"))
                && let Err(e) = run("udevadm", &["control", "--reload", "--timeout=30"], None)
            {
                tracing::warn!(error = %e, "cannot ask udevd to reload");
            }
            return Ok(());
        }
        // .link files: rename and re-apply link settings.
        let links_changed: Vec<&String> = new
            .iter()
            .filter(|(n, c)| n.ends_with(".link") && old.get(*n) != Some(*c))
            .map(|(_, c)| c)
            .collect();
        if !links_changed.is_empty() {
            run("udevadm", &["control", "--reload"], None)?;
            for c in links_changed {
                self.apply_link(c)?;
            }
        }
        // networkd never updates an existing netdev on reload: delete the
        // ones that changed or went away so they are recreated.
        let mut delete: BTreeSet<String> = BTreeSet::new();
        for (n, c) in old.iter().filter(|(n, _)| n.ends_with(".netdev")) {
            if new.get(n) != Some(c) {
                delete.extend(
                    ini_values(c, "NetDev", "Name")
                        .into_iter()
                        .map(String::from),
                );
            }
        }
        let existing: BTreeSet<String> = self.ifaces().into_iter().collect();
        let delete: Vec<String> = delete
            .into_iter()
            .filter(|d| existing.contains(d))
            .collect();
        if !delete.is_empty() {
            let mut args = vec!["delete"];
            args.extend(delete.iter().map(String::as_str));
            run("networkctl", &args, None)?;
        }
        run("networkctl", &["reload"], None)?;
        Ok(())
    }

    fn networkd_reconfigure(&mut self, links: &[String]) -> Result<(), Error> {
        let mut args = vec!["reconfigure"];
        args.extend(links.iter().map(String::as_str));
        run("networkctl", &args, None).map(|_| ())
    }

    fn sysctl_apply(&mut self, content: &str) -> Result<(), Error> {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let p: PathBuf = self.proc_sys.join(k.trim().replace('.', "/"));
            match fs::write(&p, v.trim()) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::debug!(key = k.trim(), "sysctl not present yet");
                }
                Err(e) => return Err(Error::io(&p, e)),
            }
        }
        Ok(())
    }

    fn link_states(&mut self) -> BTreeMap<String, String> {
        self.ifaces()
            .into_iter()
            .map(|i| {
                let s = fs::read_to_string(self.sys_class_net.join(&i).join("operstate"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "unknown".into());
                (i, s)
            })
            .collect()
    }

    fn install_files(&mut self, sub: Subsystem, files: &Files) -> Result<(), Error> {
        let (dir, shared) = match install_dir(sub) {
            Some(d) => (PathBuf::from(d), true),
            None => (self.runtime_dir.join(sub.dir()), false),
        };
        fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
        for (name, content) in files {
            let p = dir.join(name);
            write_atomic(&p, content.as_bytes()).map_err(|e| Error::io(&p, e))?;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o644))
                .map_err(|e| Error::io(&p, e))?;
        }
        if shared {
            // A confined daemon reads only files with its own label.
            let _ = run("restorecon", &["-R", &dir.display().to_string()], None);
            return Ok(());
        }
        if let Some(label) = install_label(sub) {
            for name in files.keys() {
                let p = dir.join(name).display().to_string();
                let _ = run("chcon", &["-t", label, &p], None);
            }
        }
        for e in fs::read_dir(&dir)
            .map_err(|e| Error::io(&dir, e))?
            .flatten()
        {
            let name = e.file_name().to_string_lossy().into_owned();
            if !files.contains_key(&name) && !name.starts_with('.') {
                let _ = fs::remove_file(e.path());
            }
        }
        Ok(())
    }

    fn service_check(&mut self, spec: &CheckSpec, files: &Files) -> Result<(), Error> {
        let dir =
            self.runtime_dir
                .join("check")
                .join(format!("{}-{}", std::process::id(), files.len()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
        for (name, content) in files {
            let content = spec.overrides.get(name).unwrap_or(content);
            let p = dir.join(name);
            fs::write(&p, content).map_err(|e| Error::io(&p, e))?;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o644))
                .map_err(|e| Error::io(&p, e))?;
        }
        let d = dir.display().to_string();
        // Under systemd the checks run as transient units, outside this
        // service's sandbox (podman and unshare need what it forbids).
        let wrap = |cmd: &str, args: &[&str]| host_run(cmd, args);
        let result = match &spec.container {
            Some(container) => match self.quadlet_image(container) {
                Some(image) => {
                    let vol = format!("{d}:{}:ro", spec.mount);
                    let mut args = vec![
                        // Bound images live in bootc's store.
                        "--storage-opt=additionalimagestore=/usr/lib/bootc/storage",
                        "run",
                        "--rm",
                        "--network=none",
                        "--read-only",
                        "--pull=never",
                        "--security-opt",
                        "label=disable",
                        "-v",
                        &vol,
                        &image,
                    ];
                    args.extend(spec.command.iter().map(String::as_str));
                    wrap("podman", &args).map(|_| ())
                }
                None => {
                    tracing::warn!(container, "no image for the config check; skipping it");
                    Ok(())
                }
            },
            None => {
                // Host checker: point its paths at the scratch copy.
                let args: Vec<String> = spec
                    .command
                    .iter()
                    .skip(1)
                    .map(|a| a.replace(&spec.mount, &d))
                    .collect();
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                wrap(&spec.command[0], &args).map(|_| ())
            }
        };
        let _ = fs::remove_dir_all(&dir);
        result.map_err(|e| Error::Check(e.to_string()))
    }

    fn services_apply(&mut self, meta: &Meta, changed: &[Subsystem]) -> Result<(), Error> {
        let startup = !std::mem::replace(&mut self.started, true);
        // Providers bind to links networkd may still be creating.
        if !startup {
            self.wait_links(&meta.required_links, std::time::Duration::from_secs(30));
        }
        let wanted: BTreeSet<&str> = meta.services.values().map(|s| s.unit.as_str()).collect();
        for unit in PROVIDER_UNITS.iter().filter(|u| !wanted.contains(*u)) {
            if self.unit_active(unit) {
                tracing::info!(unit, "stopping service");
                run("systemctl", &["stop", unit], None)?;
            }
        }
        for svc in meta.services.values() {
            let unit = svc.unit.as_str();
            if !self.unit_active(unit) {
                tracing::info!(unit, startup, "starting service");
                if startup {
                    run("systemctl", &["start", "--no-block", unit], None)?;
                } else {
                    run("systemctl", &["start", unit], None)?;
                }
            } else if changed.contains(&svc.subsystem) {
                let verb = if svc.reload {
                    "reload-or-restart"
                } else {
                    "restart"
                };
                tracing::info!(unit, verb, "configuration changed");
                run("systemctl", &[verb, unit], None)?;
            }
        }
        Ok(())
    }

    fn nft_json(&mut self) -> Result<Option<Value>, Error> {
        Linux::nft_json_table()
    }

    fn encrypt(&mut self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let out = Command::new("systemd-creds")
            .args([
                "encrypt",
                "--with-key=auto",
                &format!("--name={name}"),
                "-",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                c.stdin.take().expect("piped").write_all(plaintext)?;
                c.wait_with_output()
            })
            .map_err(|e| Error::Apply(format!("systemd-creds: {e}")))?;
        if !out.status.success() {
            return Err(Error::Apply(format!(
                "systemd-creds encrypt {name}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(out.stdout)
    }

    fn decrypt(&mut self, name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let out = Command::new("systemd-creds")
            .args(["decrypt", &format!("--name={name}"), "-", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                c.stdin.take().expect("piped").write_all(ciphertext)?;
                c.wait_with_output()
            })
            .map_err(|e| Error::Apply(format!("systemd-creds: {e}")))?;
        if !out.status.success() {
            return Err(Error::Apply(format!(
                "systemd-creds decrypt {name}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(out.stdout)
    }

    fn wg_keypair(&mut self) -> Result<(String, String), Error> {
        let private = run("wg", &["genkey"], None)?.trim().to_string();
        let public = self.wg_public(&private)?;
        Ok((private, public))
    }

    fn wg_public(&mut self, private: &str) -> Result<String, Error> {
        Ok(run("wg", &["pubkey"], Some(private.trim()))?
            .trim()
            .to_string())
    }

    fn netdev_recreate(&mut self, name: &str) -> Result<(), Error> {
        if self.sys_class_net.join(name).exists() {
            run("networkctl", &["delete", name], None)?;
        }
        run("networkctl", &["reload"], None).map(|_| ())
    }

    fn install_key(&mut self, file: &str, content: &[u8], group: &str) -> Result<(), Error> {
        // WireGuard keys go where networkd may read them (see KEY_DIR).
        let dir = PathBuf::from(sparewall_render::KEY_DIR);
        fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
        let p = dir.join(file);
        write_atomic(&p, content).map_err(|e| Error::io(&p, e))?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).map_err(|e| Error::io(&p, e))?;
        run("chgrp", &[group, &p.display().to_string()], None)?;
        Ok(())
    }

    fn sync_public_key(&mut self) -> Result<String, Error> {
        let key = &self.sync_key;
        if !key.exists() {
            let private = run("wg", &["genkey"], None)?;
            if let Some(d) = key.parent() {
                fs::create_dir_all(d).map_err(|e| Error::io(d, e))?;
            }
            write_atomic(key, private.trim().as_bytes()).map_err(|e| Error::io(key, e))?;
            // The master copy is root's; networkd gets a copy in /run.
            fs::set_permissions(key, fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::io(key, e))?;
            tracing::info!(path = %key.display(), "generated the sync-tunnel key");
        }
        let private = fs::read_to_string(key).map_err(|e| Error::io(key, e))?;
        Ok(run("wg", &["pubkey"], Some(private.trim()))?
            .trim()
            .to_string())
    }

    fn proc_sys(&mut self, key: &str) -> Option<String> {
        fs::read_to_string(self.proc_sys.join(key))
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn unit_states(&mut self, units: &[String]) -> BTreeMap<String, String> {
        units
            .iter()
            .map(|u| {
                let state = Command::new("systemctl")
                    .args(["is-active", u])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_else(|_| "unknown".into());
                (u.clone(), state)
            })
            .collect()
    }
}

impl Linux {
    pub fn nft_json_table() -> Result<Option<Value>, Error> {
        match run("nft", &["-j", "list", "table", "inet", TABLE], None) {
            Ok(out) => serde_json::from_str(&out)
                .map(Some)
                .map_err(|e| Error::Apply(format!("nft -j: {e}"))),
            Err(Error::Apply(m)) if m.contains("No such file") || m.contains("does not exist") => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn wait_links(&self, links: &[String], timeout: std::time::Duration) {
        let t0 = std::time::Instant::now();
        loop {
            let missing: Vec<&String> = links
                .iter()
                .filter(|l| !self.sys_class_net.join(l).exists())
                .collect();
            if missing.is_empty() {
                return;
            }
            if t0.elapsed() > timeout {
                tracing::warn!(?missing, "links still missing; starting services anyway");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    fn unit_active(&self, unit: &str) -> bool {
        Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .status()
            .is_ok_and(|s| s.success())
    }

    /// The image a Quadlet `.container` file runs.
    fn quadlet_image(&self, container: &str) -> Option<String> {
        let text =
            fs::read_to_string(self.quadlet_dir.join(format!("{container}.container"))).ok()?;
        ini_values(&text, "Container", "Image")
            .first()
            .map(|s| s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prelude_keeps_compatible_preserved_sets() {
        let json = r#"{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"sparewall"}},
          {"set":{"family":"inet","name":"wan_address","table":"sparewall","type":"ipv4_addr","flags":["interval"]}},
          {"set":{"family":"inet","name":"old_static","table":"sparewall","type":"ipv4_addr","flags":["interval"]}},
          {"set":{"family":"inet","name":"bad_type","table":"sparewall","type":"ipv4_addr"}},
          {"chain":{"family":"inet","table":"sparewall","name":"input"}},
          {"chain":{"family":"inet","table":"sparewall","name":"in_wan"}}]}"#;
        let live = parse_live_table(json).unwrap();
        let (pre, created) = prelude(
            &live,
            &[
                "wan_address".to_string(),
                "bad_type".to_string(),
                "new_dyn".to_string(),
            ],
        );
        assert_eq!(
            pre,
            "flush chain inet sparewall input\nflush chain inet sparewall in_wan\n\
             delete chain inet sparewall input\ndelete chain inet sparewall in_wan\n\
             delete set inet sparewall bad_type\ndelete set inet sparewall old_static\n"
        );
        assert_eq!(created, ["bad_type", "new_dyn"]);
    }

    #[test]
    fn prelude_for_absent_table() {
        let (pre, created) = prelude(&LiveTable::default(), &["x".to_string()]);
        assert!(pre.is_empty());
        assert_eq!(created, ["x"]);
    }

    #[test]
    fn ini_parsing() {
        let c = "[Match]\nPermanentMACAddress=52:54:00:aa:00:01\n\n[Link]\nName=uplink\n";
        assert_eq!(ini_values(c, "Link", "Name"), ["uplink"]);
        assert_eq!(
            ini_values(c, "Match", "PermanentMACAddress"),
            ["52:54:00:aa:00:01"]
        );
        assert!(ini_values(c, "Match", "Name").is_empty());
    }
}
