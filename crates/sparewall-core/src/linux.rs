//! The real system adapter. It shells out to `nft`, `networkctl`, `udevadm`
//! and `ip` rather than reimplementing their netlink protocols (design:
//! "Adapters for everything else").

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;
use sparewall_render::nft::TABLE;
use sparewall_render::{CheckSpec, Meta, Subsystem};

use crate::Error;
use crate::hostop::HostOp;
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
    /// Restarts are awaited, so that health does not see a provider
    /// mid-restart, which no unit sparewalld starts may therefore order
    /// after sparewalld (#164).
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
    sparewall_render::logging::SYSLOG_UNIT,
    sparewall_render::web::UNIT,
    sparewall_render::metrics::UNIT,
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

/// Whether `systemctl` failed because it lost its connection to the
/// manager, not because the job failed: systemd re-executes on SIGTERM,
/// and keepalived can send it one on a reload (its `script_killall` signals
/// `-getpgid(pid)`, which is PID 1 once a tracked script is gone).
pub fn manager_lost(err: &str) -> bool {
    [
        "D-Bus connection terminated",
        "Connection reset by peer",
        "Transport endpoint is not connected",
    ]
    .iter()
    .any(|m| err.contains(m))
}

/// `systemctl` on a unit, retried while the manager re-executes. The verbs
/// used here are idempotent, so a retry after a lost reply is safe.
fn systemctl(args: &[&str]) -> Result<String, Error> {
    let mut tries = 0;
    loop {
        match run("systemctl", args, None) {
            Err(Error::Apply(e)) if manager_lost(&e) && tries < 3 => {
                tries += 1;
                tracing::warn!(?args, error = e, "lost the service manager; retrying");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            r => return r,
        }
    }
}

/// Where commands for `sparewall-run@.service` are spooled (root only).
pub const RUN_SPOOL: &str = "/run/sparewall/run";

#[derive(serde::Serialize, serde::Deserialize)]
struct Spooled {
    op: crate::hostop::HostOp,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SpoolResult {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run an operation outside this service's sandbox (#279). Under systemd
/// it runs as the oneshot `sparewall-run@<id>.service` (podman, unshare
/// and bootc need what the coordinator's sandbox forbids), which checks it
/// again; elsewhere it runs directly.
pub fn host_op(op: &crate::hostop::HostOp) -> Result<String, Error> {
    // Checked here too, so a bad operation fails before it is spooled;
    // the run unit checks it again against its own directories.
    let argv = op.argv(None).map_err(Error::Apply)?;
    let (cmd, args) = argv.split_first().expect("an operation has a command");
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let under_systemd = std::env::var_os("INVOCATION_ID").is_some()
        && std::path::Path::new("/run/systemd/system").exists()
        && std::env::var_os("SPAREWALL_NO_HOST_RUN").is_none();
    if !under_systemd {
        return run(cmd, &args, None);
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
    write_atomic(
        &job,
        &serde_json::to_vec(&Spooled { op: op.clone() }).expect("json"),
    )
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

/// Encrypt a secret for this node with `systemd-creds` (TPM2-bound where
/// present).
pub fn creds_encrypt(name: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
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

/// The body of `sparewall-run@<id>.service`: run a spooled operation, if
/// it is one [`crate::hostop::HostOp`] allows, and record its result. A
/// job that is not, or whose arguments fail its checks, is refused and
/// logged, never run (#279).
pub fn run_spooled(id: &str) -> Result<(), Error> {
    run_spooled_in(
        std::path::Path::new(RUN_SPOOL),
        id,
        &crate::hostop::Roots::from_env(),
    )
}

fn run_spooled_in(
    dir: &std::path::Path,
    id: &str,
    roots: &crate::hostop::Roots,
) -> Result<(), Error> {
    if !id.chars().all(|c| c.is_ascii_digit() || c == '-') {
        return Err(Error::Validation(vec![format!("bad job id {id:?}")]));
    }
    let job = dir.join(format!("{id}.json"));
    let out = dir.join(format!("{id}.out.json"));
    let refuse = |why: String| {
        tracing::error!(job = id, "refused: {why}");
        let r = SpoolResult {
            code: -1,
            stdout: String::new(),
            stderr: format!("refused by sparewall-run: {why}"),
        };
        write_atomic(&out, &serde_json::to_vec(&r).expect("json"))
            .map_err(|e| Error::io(&out, e))?;
        Err(Error::Validation(vec![why]))
    };
    let bytes = fs::read(&job).map_err(|e| Error::io(&job, e))?;
    let j: Spooled = match serde_json::from_slice(&bytes) {
        Ok(j) => j,
        Err(e) => return refuse(format!("not an operation: {e}")),
    };
    let mut argv = match j.op.argv(Some(roots)) {
        Ok(a) => a,
        Err(e) => return refuse(e),
    };
    let prepared = match prepare(&j.op, id, roots, &mut argv) {
        Ok(p) => p,
        Err(e) => {
            return refuse(e);
        }
    };
    let (cmd, args) = argv.split_first().expect("an operation has a command");
    let o = Command::new(cmd).args(args).stdin(Stdio::null()).output();
    let finished = prepared.finish();
    let o = o.map_err(|e| Error::Apply(format!("{cmd}: {e}")))?;
    let mut r = SpoolResult {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    };
    if let Err(e) = finished {
        r.code = if r.code == 0 { -1 } else { r.code };
        r.stderr.push_str(&format!("\nsparewall-run: {e}"));
    }
    write_atomic(&out, &serde_json::to_vec(&r).expect("json")).map_err(|e| Error::io(&out, e))
}

/// What [`prepare`] set up for one job, finished after it runs. What is
/// private to the job is removed when this is dropped, so also when
/// `prepare` fails partway or the job's command cannot be run.
#[derive(Default)]
struct Prepared {
    /// Files and directories of the run unit's own, removed after.
    private: Vec<PathBuf>,
    /// lego's private data, copied back to the coordinator's after.
    lego: Option<(PathBuf, String)>,
}

impl Prepared {
    /// Copy lego's results back; dropping `self` then removes what was
    /// private to the job.
    fn finish(mut self) -> Result<(), String> {
        match self.lego.take() {
            Some((copy, data)) => {
                let from = crate::hostop::open_no_symlinks(&copy, DIR_FLAGS)?;
                let to = crate::hostop::open_no_symlinks(Path::new(&data), DIR_FLAGS)?;
                copy_tree(&from, &to, &mut COPY_BUDGET.clone(), 0)
                    .map_err(|e| format!("copying lego's data back: {e}"))
            }
            None => Ok(()),
        }
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        for p in self.private.iter().rev() {
            let _ = fs::remove_dir_all(p).or_else(|_| fs::remove_file(p));
        }
    }
}

const DIR_FLAGS: rustix::fs::OFlags =
    rustix::fs::OFlags::RDONLY.union(rustix::fs::OFlags::DIRECTORY);
/// The most lego's data may hold, copied either way (accounts and
/// certificates: kilobytes).
const COPY_BUDGET: u64 = 64 << 20;

/// What the run unit checks and sets up on disk before it runs an
/// operation, so that no path it uses can be redirected by a symbolic link
/// the coordinator plants, even mid-check: paths are opened with openat2
/// and `RESOLVE_NO_SYMLINKS`, and below that only relative to descriptors.
///
/// - A config check's directory is checked so; podman mounts it read-only
///   and unlabelled, for the provider's checker alone.
/// - lego's environment file is read through such a descriptor into a
///   copy in the private directory (root's alone: the coordinator cannot
///   write it), and its data is copied there too, regular files only.
///   lego, confined, works on that copy, relabelled for its container, and
///   [`Prepared::finish`] copies it back. So nothing podman mounts or
///   relabels is a path the coordinator can change.
fn prepare(
    op: &crate::hostop::HostOp,
    id: &str,
    roots: &crate::hostop::Roots,
    argv: &mut [String],
) -> Result<Prepared, String> {
    use crate::hostop::{HostOp, lego_mount, no_symlinks, open_no_symlinks};
    use rustix::fs::{Mode, OFlags};
    match op {
        HostOp::ConfigCheck { dir, .. } => {
            no_symlinks(Path::new(dir))?;
            Ok(Prepared::default())
        }
        HostOp::Lego { data, env_file, .. } => {
            let mut prepared = Prepared::default();
            let private = Path::new(&roots.private);
            fs::create_dir_all(private).map_err(|e| format!("{}: {e}", private.display()))?;
            let pfd = open_no_symlinks(private, DIR_FLAGS)?;
            rustix::fs::fchmod(&pfd, Mode::from_raw_mode(0o700))
                .map_err(|e| format!("{}: {e}", private.display()))?;

            // The environment file.
            let fd = open_no_symlinks(Path::new(env_file), OFlags::RDONLY | OFlags::NOFOLLOW)?;
            let mut f = fs::File::from(fd);
            if !f.metadata().map_err(|e| e.to_string())?.is_file() {
                return Err(format!("{env_file}: not a file"));
            }
            let mut env = Vec::new();
            std::io::Read::read_to_end(&mut std::io::Read::take(&mut f, 1 << 20), &mut env)
                .map_err(|e| e.to_string())?;
            let name = format!("{id}.env");
            let copy = private.join(&name);
            prepared.private.push(copy.clone());
            write_new_at(&pfd, &name, &env, 0o600)?;
            for a in argv.iter_mut().filter(|a| *a == env_file) {
                *a = copy.display().to_string();
            }

            // The data.
            let name = format!("{id}-lego");
            let copy = private.join(&name);
            let _ = fs::remove_dir_all(&copy);
            prepared.private.push(copy.clone());
            rustix::fs::mkdirat(&pfd, name.as_str(), Mode::from_raw_mode(0o700))
                .map_err(|e| format!("{}: {e}", copy.display()))?;
            let to = rustix::fs::openat(
                &pfd,
                name.as_str(),
                DIR_FLAGS | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| format!("{}: {e}", copy.display()))?;
            let from = open_no_symlinks(Path::new(data), DIR_FLAGS)?;
            copy_tree(&from, &to, &mut COPY_BUDGET.clone(), 0)
                .map_err(|e| format!("copying lego's data: {e}"))?;
            let mount = lego_mount(data);
            for a in argv.iter_mut().filter(|a| **a == mount) {
                *a = lego_mount(&copy.display().to_string());
            }
            prepared.lego = Some((copy, data.clone()));
            Ok(prepared)
        }
        _ => Ok(Prepared::default()),
    }
}

/// Write a new file `name` under the directory `dir`, replacing one there
/// (never following a link): under a temporary name, then renamed.
fn write_new_at(
    dir: &impl std::os::fd::AsFd,
    name: &str,
    bytes: &[u8],
    mode: rustix::fs::RawMode,
) -> Result<(), String> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    let tmp = format!(".{name}.sparewall-run");
    let _ = rustix::fs::unlinkat(dir, tmp.as_str(), AtFlags::empty());
    let fd = rustix::fs::openat(
        dir,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode),
    )
    .map_err(|e| format!("{name}: {e}"))?;
    let written = fs::File::from(fd)
        .write_all(bytes)
        .map_err(|e| format!("{name}: {e}"))
        .and_then(|()| {
            rustix::fs::renameat(dir, tmp.as_str(), dir, name).map_err(|e| format!("{name}: {e}"))
        });
    if written.is_err() {
        let _ = rustix::fs::unlinkat(dir, tmp.as_str(), AtFlags::empty());
    }
    written
}

/// Copy the directory `from` into `to`, both descriptors: regular files
/// and directories only (links and anything else are skipped), nothing
/// followed, at most `budget` bytes and eight levels deep. Files keep
/// their owner's permission bits only; directories are created 0700.
fn copy_tree(
    from: &impl std::os::fd::AsFd,
    to: &impl std::os::fd::AsFd,
    budget: &mut u64,
    depth: u32,
) -> Result<(), String> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    if depth > 8 {
        return Err("too deep".into());
    }
    let dir = rustix::fs::Dir::read_from(from).map_err(|e| e.to_string())?;
    for entry in dir {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." || name.ends_with(".sparewall-run") {
            continue;
        }
        let st = rustix::fs::statat(from, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| format!("{name}: {e}"))?;
        match FileType::from_raw_mode(st.st_mode) {
            FileType::Directory => {
                match rustix::fs::mkdirat(to, name.as_str(), Mode::from_raw_mode(0o700)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(format!("{name}: {e}")),
                }
                let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                let sub_from = rustix::fs::openat(from, name.as_str(), flags, Mode::empty())
                    .map_err(|e| format!("{name}: {e}"))?;
                let sub_to = rustix::fs::openat(to, name.as_str(), flags, Mode::empty())
                    .map_err(|e| format!("{name}: {e}"))?;
                copy_tree(&sub_from, &sub_to, budget, depth + 1)
                    .map_err(|e| format!("{name}/{e}"))?;
            }
            FileType::RegularFile => {
                let fd = rustix::fs::openat(
                    from,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|e| format!("{name}: {e}"))?;
                let mut f = fs::File::from(fd);
                if !f.metadata().map_err(|e| e.to_string())?.is_file() {
                    continue;
                }
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(
                    &mut std::io::Read::take(&mut f, *budget + 1),
                    &mut bytes,
                )
                .map_err(|e| format!("{name}: {e}"))?;
                if bytes.len() as u64 > *budget {
                    return Err("more data than lego keeps".into());
                }
                *budget -= bytes.len() as u64;
                write_new_at(to, &name, &bytes, (st.st_mode & 0o700) | 0o600)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// What the live `inet sparewall` table holds.
#[derive(Debug, Default)]
struct LiveTable {
    exists: bool,
    chains: Vec<String>,
    /// Set name to its type, when it has the interval flag that a
    /// preserved set has; `None` without it.
    sets: BTreeMap<String, Option<String>>,
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
            let ty = s["type"]
                .as_str()
                .filter(|_| flags.contains(&"interval"))
                .map(str::to_string);
            t.sets.insert(name, ty);
        } else if let Some(m) = item.get("map")
            && let Some(n) = m["name"].as_str()
        {
            t.maps.push(n.to_string());
        }
    }
    Ok(t)
}

/// The type `body` declares for set `name`, as the renderer writes it.
fn declared_type<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let at = body.find(&format!("\tset {name} {{\n"))?;
    body[at..]
        .lines()
        .nth(1)?
        .trim()
        .strip_prefix("type ")
        .map(str::trim)
}

/// Statements that clear the coordinator-owned parts of the live table so
/// `body` can be loaded in the same transaction. Sets in `preserved`
/// survive (with their elements) when the live one has the type `body`
/// declares, of either family, and the interval flag.
fn prelude(live: &LiveTable, body: &str, preserved: &[String]) -> (String, Vec<String>) {
    let keeps = |name: &String| {
        preserved.contains(name)
            && live
                .sets
                .get(name)
                .and_then(Option::as_deref)
                .is_some_and(|ty| declared_type(body, name) == Some(ty))
    };
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
    for name in live.sets.keys() {
        if !keeps(name) {
            s.push_str(&format!("delete set inet {TABLE} {name}\n"));
        }
    }
    for p in preserved {
        if !keeps(p) {
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
        let (pre, _) = prelude(&live_table()?, body, preserved);
        run("nft", &["-c", "-f", "-"], Some(&format!("{pre}{body}")))
            .map(|_| ())
            .map_err(|e| Error::Check(e.to_string()))
    }

    fn nft_load(&mut self, body: &str, preserved: &[String]) -> Result<Vec<String>, Error> {
        let (pre, created) = prelude(&live_table()?, body, preserved);
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
            // Only what changes: writing a key has effects of its own.
            // The global IPv6 forwarding key resets every interface's, and
            // with it the multicast groups a link joins, which a pair's
            // backup must not report from the virtual MAC (#215).
            if fs::read_to_string(&p).is_ok_and(|cur| cur.trim() == v.trim()) {
                continue;
            }
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

    fn bond_members(&mut self, bond: &str) -> Vec<(String, bool)> {
        let net = &self.sys_class_net;
        fs::read_to_string(net.join(bond).join("bonding/slaves"))
            .unwrap_or_default()
            .split_whitespace()
            .map(|m| {
                let up = fs::read_to_string(net.join(m).join("bonding_slave/mii_status"))
                    .is_ok_and(|s| s.trim() == "up");
                (m.to_string(), up)
            })
            .collect()
    }

    fn ipv6_links(&mut self) -> BTreeMap<String, crate::ipv6::LinkIpv6> {
        // networkd's lifetimes are CLOCK_BOOTTIME stamps.
        #[cfg(target_os = "linux")]
        let now_usec = {
            let t = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
            u64::try_from(t.tv_sec)
                .ok()
                .map(|s| s * 1_000_000 + u64::try_from(t.tv_nsec).unwrap_or(0) / 1000)
        };
        #[cfg(not(target_os = "linux"))]
        let now_usec: Option<u64> = None;
        let describe = run("networkctl", &["--json=short", "status"], None)
            .ok()
            .and_then(|o| serde_json::from_str::<serde_json::Value>(&o).ok());
        let mut links = match (describe, now_usec) {
            (Some(d), Some(now)) => crate::ipv6::from_describe(&d, now),
            _ => BTreeMap::new(),
        };
        if let Some(routes) = run(
            "ip",
            &["-j", "-6", "route", "show", "default", "table", "main"],
            None,
        )
        .ok()
        .and_then(|o| serde_json::from_str::<serde_json::Value>(&o).ok())
        {
            crate::ipv6::with_kernel_defaults(&mut links, &routes);
        }
        links
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
        // Under systemd the checks run outside this service's sandbox
        // (podman and unshare need what it forbids), as an operation
        // sparewall-run@ checks: only the renderer's own checks (#279).
        let image = match &spec.container {
            Some(container) => match self.quadlet_image(container) {
                Some(image) => Some(image),
                None => {
                    tracing::warn!(container, "no image for the config check; skipping it");
                    let _ = fs::remove_dir_all(&dir);
                    return Ok(());
                }
            },
            None => None,
        };
        let check = CheckSpec {
            overrides: Default::default(),
            ..spec.clone()
        };
        let result = host_op(&HostOp::ConfigCheck {
            spec: check,
            dir: dir.display().to_string(),
            image,
        })
        .map(|_| ());
        let _ = fs::remove_dir_all(&dir);
        result.map_err(|e| Error::Check(e.to_string()))
    }

    fn services_apply(&mut self, meta: &Meta, changed: &[Subsystem]) -> Result<(), Error> {
        let startup = !std::mem::replace(&mut self.started, true);
        // Providers bind to links networkd may still be creating.
        if !startup {
            // conntrackd and Kea HA use the tunnel over the replication links.
            let links: Vec<String> = meta
                .required_links
                .iter()
                .chain(&meta.replication_links)
                .cloned()
                .collect();
            self.wait_links(&links, std::time::Duration::from_secs(30));
        }
        let wanted: BTreeSet<&str> = meta.services.values().map(|s| s.unit.as_str()).collect();
        for unit in PROVIDER_UNITS.iter().filter(|u| !wanted.contains(*u)) {
            // Starting, or reloading, counts: stopped only once it is up,
            // it would be left running.
            if self.unit_running(unit) {
                tracing::info!(unit, "stopping service");
                systemctl(&["stop", unit])?;
            }
        }
        for svc in meta.services.values() {
            let unit = svc.unit.as_str();
            if !self.unit_active(unit) {
                tracing::info!(unit, startup, "starting service");
                if startup {
                    systemctl(&["start", "--no-block", unit])?;
                } else {
                    systemctl(&["start", unit])?;
                }
            } else if changed.contains(&svc.subsystem) {
                let verb = if svc.reload {
                    "reload-or-restart"
                } else {
                    "restart"
                };
                tracing::info!(unit, verb, "configuration changed");
                systemctl(&[verb, unit])?;
            }
        }
        Ok(())
    }

    fn nft_json(&mut self) -> Result<Option<Value>, Error> {
        Linux::nft_json_table()
    }

    fn encrypt(&mut self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        creds_encrypt(name, plaintext)
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

    fn wg_peers(&mut self, iface: &str) -> Result<Vec<crate::system::WgPeer>, Error> {
        if !self.sys_class_net.join(iface).exists() {
            return Ok(vec![]);
        }
        Ok(crate::system::parse_wg_dump(&run(
            "wg",
            &["show", iface, "dump"],
            None,
        )?))
    }

    fn wg_set_endpoint(
        &mut self,
        iface: &str,
        public_key: &str,
        endpoint: &str,
    ) -> Result<(), Error> {
        run(
            "wg",
            &["set", iface, "peer", public_key, "endpoint", endpoint],
            None,
        )
        .map(|_| ())
    }

    fn netdev_recreate(&mut self, name: &str) -> Result<(), Error> {
        if self.sys_class_net.join(name).exists() {
            run("networkctl", &["delete", name], None)?;
        }
        run("networkctl", &["reload"], None).map(|_| ())
    }

    fn set_admin_password(&mut self, hash: &str) -> Result<(), Error> {
        // usermod edits shadow as the account tools do, outside this
        // domain (sparewall-run@), so the policy grants no shadow access.
        host_op(&HostOp::SetAdminPassword { hash: hash.into() }).map(|_| ())
    }

    fn set_hostname(&mut self, name: &str) -> Result<bool, Error> {
        // uname needs no access to /proc; hostnamectl (through hostnamed)
        // reads and writes /etc/hostname outside this domain. Both must
        // match: a running name alone is lost at the next boot.
        if rustix::system::uname().nodename().to_bytes() == name.as_bytes()
            && host_op(&HostOp::Hostname)?.trim() == name
        {
            return Ok(false);
        }
        host_op(&HostOp::SetHostname { name: name.into() }).map(|_| true)
    }

    fn calendar_check(&mut self, expr: &str) -> Result<(), String> {
        // Outside this domain, as the scheduler's own reading of it is.
        host_op(&HostOp::CalendarNext {
            expr: expr.into(),
            base: None,
        })
        .map(|_| ())
        .map_err(|e| e.to_string())
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

    fn install_secret_file(&mut self, file: &str, content: Option<&[u8]>) -> Result<(), Error> {
        let dir = self.runtime_dir.join("secrets");
        let p = dir.join(file);
        let Some(content) = content else {
            return match fs::remove_file(&p) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Error::io(&p, e)),
                _ => Ok(()),
            };
        };
        fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::io(&dir, e))?;
        write_atomic(&p, content).map_err(|e| Error::io(&p, e))?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).map_err(|e| Error::io(&p, e))
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

    /// Whether a unit is anything but stopped (inactive or failed).
    fn unit_running(&self, unit: &str) -> bool {
        Command::new("systemctl")
            .args(["is-active", unit])
            .output()
            .is_ok_and(|o| {
                !matches!(
                    String::from_utf8_lossy(&o.stdout).trim(),
                    "inactive" | "failed" | "unknown" | ""
                )
            })
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
    use serde_json::json;

    /// The run unit copies lego's data through descriptors: links and
    /// anything but regular files are skipped on the way in, and on the
    /// way back a link where a directory belongs is refused and a link
    /// where a file belongs is replaced, never written through.
    #[test]
    fn lego_data_is_copied_without_following_links() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        let (src, dst, outside) = (
            t.path().join("src"),
            t.path().join("dst"),
            t.path().join("outside"),
        );
        for d in [&src, &dst, &outside] {
            fs::create_dir(d).unwrap();
        }
        fs::create_dir(src.join("certificates")).unwrap();
        fs::write(src.join("certificates/mgmt.crt"), "cert").unwrap();
        fs::write(src.join("ca.pem"), "ca").unwrap();
        symlink("/etc/hostname", src.join("leak")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            src.join("fifo").as_path(),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        fs::write(outside.join("victim"), "untouched").unwrap();
        symlink(outside.join("victim"), dst.join("ca.pem")).unwrap();

        let open = |p: &Path| crate::hostop::open_no_symlinks(p, DIR_FLAGS).unwrap();
        copy_tree(&open(&src), &open(&dst), &mut COPY_BUDGET.clone(), 0).unwrap();
        assert_eq!(
            fs::read_to_string(dst.join("certificates/mgmt.crt")).unwrap(),
            "cert"
        );
        assert_eq!(fs::read_to_string(dst.join("ca.pem")).unwrap(), "ca");
        assert!(
            !fs::symlink_metadata(dst.join("ca.pem"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(outside.join("victim")).unwrap(),
            "untouched"
        );
        assert!(!dst.join("leak").exists() && !dst.join("fifo").exists());

        // A link where a directory belongs.
        let dst2 = t.path().join("dst2");
        fs::create_dir(&dst2).unwrap();
        symlink(&outside, dst2.join("certificates")).unwrap();
        assert!(copy_tree(&open(&src), &open(&dst2), &mut COPY_BUDGET.clone(), 0).is_err());
        assert!(!outside.join("mgmt.crt").exists());

        // Too much.
        assert!(copy_tree(&open(&src), &open(&dst), &mut 3, 0).is_err());
    }

    /// lego's mount and environment file become the run unit's private
    /// copies, and what lego leaves there is copied back after.
    #[test]
    fn lego_runs_on_a_private_copy() {
        let t = tempfile::tempdir().unwrap();
        let roots = crate::hostop::Roots {
            state: t.path().join("state").display().to_string(),
            runtime: t.path().join("run").display().to_string(),
            private: t.path().join("private").display().to_string(),
            lego_image: Some("ghcr.io/sparewall/lego:sha-1".into()),
        };
        let data = roots.lego_data();
        fs::create_dir_all(&data).unwrap();
        fs::write(Path::new(&data).join("ca.pem"), "ca").unwrap();
        let env_file = format!("{}/lego/.env-1", roots.runtime);
        fs::create_dir_all(Path::new(&env_file).parent().unwrap()).unwrap();
        fs::write(&env_file, "SECRET=1\n").unwrap();
        let op = crate::hostop::HostOp::Lego {
            image: "ghcr.io/sparewall/lego:sha-1".into(),
            data: data.clone(),
            env_file: env_file.clone(),
            args: crate::hostop::lego_args(
                "mgmt",
                "https://acme.example/dir",
                "rfc2136",
                None,
                &["fw.example.org".into()],
            ),
        };
        let mut argv = op.argv(Some(&roots)).unwrap();
        let prepared = prepare(&op, "7-1", &roots, &mut argv).unwrap();
        let copy = Path::new(&roots.private).join("7-1-lego");
        assert!(argv.contains(&crate::hostop::lego_mount(&copy.display().to_string())));
        assert!(!argv.contains(&crate::hostop::lego_mount(&data)));
        let env_copy = Path::new(&roots.private).join("7-1.env");
        assert!(argv.contains(&env_copy.display().to_string()));
        assert_eq!(fs::read_to_string(&env_copy).unwrap(), "SECRET=1\n");
        assert_eq!(fs::read_to_string(copy.join("ca.pem")).unwrap(), "ca");

        // lego's work, in the copy.
        fs::create_dir(copy.join("certificates")).unwrap();
        fs::write(copy.join("certificates/mgmt.crt"), "new").unwrap();
        prepared.finish().unwrap();
        assert_eq!(
            fs::read_to_string(Path::new(&data).join("certificates/mgmt.crt")).unwrap(),
            "new"
        );
        assert!(
            !copy.exists() && !env_copy.exists(),
            "private copies removed"
        );

        // When copying the data fails partway, the environment copy and
        // what was copied are removed all the same.
        let deep = (0..10).fold(Path::new(&data).join("deep"), |p, i| p.join(i.to_string()));
        fs::create_dir_all(&deep).unwrap();
        let mut argv = op.argv(Some(&roots)).unwrap();
        assert!(prepare(&op, "7-2", &roots, &mut argv).is_err());
        assert_eq!(
            fs::read_dir(&roots.private).unwrap().count(),
            0,
            "nothing left in the private directory"
        );
    }

    /// sparewall-run@ runs operations only: a command line, or an
    /// operation whose arguments fail its checks, is refused with a result
    /// saying so, and nothing runs (#279).
    #[test]
    fn the_run_unit_refuses_anything_but_a_checked_operation() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let jobs = [
            (
                "1-0",
                json!({"argv": ["touch", marker.display().to_string()]}),
            ),
            (
                "1-1",
                json!({"op": {"op": "set-hostname", "name": "x; touch /tmp/y"}}),
            ),
            (
                "1-2",
                json!({"op": {"op": "timer-create", "unit": "sparewall-x",
                    "description": "x", "calendar": "daily",
                    "command": ["touch", marker.display().to_string()]}}),
            ),
        ];
        // lego, with every argument right but its environment file a link
        // to a file the coordinator should not have read as root.
        let (state, run) = (dir.path().join("state"), dir.path().join("run"));
        fs::create_dir_all(state.join("lego")).unwrap();
        fs::create_dir_all(run.join("lego")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", run.join("lego/.env-1")).unwrap();
        let lego = crate::hostop::HostOp::Lego {
            image: "ghcr.io/sparewall/lego:sha-1".into(),
            data: state.join("lego").display().to_string(),
            env_file: run.join("lego/.env-1").display().to_string(),
            args: crate::hostop::lego_args(
                "mgmt",
                "https://acme.example/dir",
                "rfc2136",
                None,
                &["fw.example.org".into()],
            ),
        };
        let jobs: Vec<(&str, serde_json::Value)> = jobs
            .into_iter()
            .chain([("1-3", json!({ "op": lego }))])
            .collect();
        for (id, job) in jobs {
            fs::write(
                dir.path().join(format!("{id}.json")),
                serde_json::to_vec(&job).unwrap(),
            )
            .unwrap();
            let roots = crate::hostop::Roots {
                state: dir.path().join("state").display().to_string(),
                runtime: dir.path().join("run").display().to_string(),
                private: dir.path().join("private").display().to_string(),
                lego_image: Some("ghcr.io/sparewall/lego:sha-1".into()),
            };
            assert!(run_spooled_in(dir.path(), id, &roots).is_err(), "{id}");
            let r: SpoolResult = serde_json::from_slice(
                &fs::read(dir.path().join(format!("{id}.out.json"))).unwrap(),
            )
            .unwrap();
            assert_eq!(r.code, -1, "{id}");
            assert!(
                r.stderr.starts_with("refused by sparewall-run"),
                "{id}: {}",
                r.stderr
            );
            if id == "1-3" {
                assert!(r.stderr.contains("a symbolic link"), "{}", r.stderr);
            }
        }
        assert!(!marker.exists(), "nothing ran");
    }

    /// Only keys whose value changes are written (#215): writing the
    /// global IPv6 forwarding key resets every interface's.
    #[test]
    fn sysctl_writes_only_what_changes() {
        let dir = tempfile::tempdir().unwrap();
        let all = dir.path().join("net/ipv6/conf/all");
        let swwan = dir.path().join("net/ipv6/conf/swwan");
        fs::create_dir_all(&all).unwrap();
        fs::create_dir_all(&swwan).unwrap();
        fs::write(all.join("forwarding"), "1\n").unwrap();
        fs::write(swwan.join("forwarding"), "1\n").unwrap();
        // Read-only: a write would fail the call.
        let ro = |p: &std::path::Path| {
            let mut perm = fs::metadata(p).unwrap().permissions();
            perm.set_readonly(true);
            fs::set_permissions(p, perm).unwrap();
        };
        ro(&all.join("forwarding"));
        let mut l = Linux {
            proc_sys: dir.path().into(),
            ..Default::default()
        };
        l.sysctl_apply(
            "# header\nnet.ipv6.conf.all.forwarding = 1\nnet.ipv6.conf.swwan.forwarding = 0\n\
             net.ipv6.conf.gone.forwarding = 0\n",
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(swwan.join("forwarding")).unwrap().trim(),
            "0"
        );
    }

    /// The units sparewalld starts, as the image ships them (unit file,
    /// Quadlet file, drop-ins), never order after or depend on
    /// sparewalld: it restarts them during its own start and waits, which
    /// would wait for a job queued behind that start (#164).
    #[test]
    fn units_sparewalld_starts_do_not_wait_for_it() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../image/files/usr");
        for unit in PROVIDER_UNITS {
            let mut files = Vec::new();
            let system = root.join("lib/systemd/system");
            files.push(system.join(unit));
            if let Ok(dir) = fs::read_dir(system.join(format!("{unit}.d"))) {
                files.extend(dir.flatten().map(|e| e.path()));
            }
            let quadlet = unit.strip_suffix(".service").unwrap_or(unit);
            files.push(root.join(format!("share/containers/systemd/{quadlet}.container")));
            let mut found = false;
            for f in files {
                let Ok(text) = fs::read_to_string(&f) else {
                    continue;
                };
                found = true;
                for line in text.lines().map(str::trim) {
                    let Some((key, value)) = line.split_once('=') else {
                        continue;
                    };
                    let ordering = ["After", "Requires", "BindsTo", "Requisite", "Upholds"];
                    assert!(
                        !(ordering.contains(&key.trim())
                            && value
                                .split_whitespace()
                                .any(|u| u.starts_with("sparewalld."))),
                        "{}: {line}",
                        f.display()
                    );
                }
            }
            assert!(found, "no unit file, Quadlet file or drop-in for {unit}");
        }
    }

    #[test]
    fn a_reexecuting_manager_is_retried_a_failed_job_is_not() {
        assert!(manager_lost(
            "systemctl reload-or-restart keepalived.service: D-Bus connection terminated while waiting for jobs.\nFailed to wait for response: Connection reset by peer"
        ));
        assert!(!manager_lost(
            "systemctl restart sparewall-kea.service: Job for sparewall-kea.service failed because the control process exited with error code."
        ));
    }

    #[test]
    fn prelude_keeps_compatible_preserved_sets() {
        let json = r#"{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"sparewall"}},
          {"set":{"family":"inet","name":"wan_address","table":"sparewall","type":"ipv4_addr","flags":["interval"]}},
          {"set":{"family":"inet","name":"wan6","table":"sparewall","type":"ipv6_addr","flags":["interval"]}},
          {"set":{"family":"inet","name":"flipped","table":"sparewall","type":"ipv4_addr","flags":["interval"]}},
          {"set":{"family":"inet","name":"old_static","table":"sparewall","type":"ipv4_addr","flags":["interval"]}},
          {"set":{"family":"inet","name":"bad_type","table":"sparewall","type":"ipv4_addr"}},
          {"chain":{"family":"inet","table":"sparewall","name":"input"}},
          {"chain":{"family":"inet","table":"sparewall","name":"in_wan"}}]}"#;
        let live = parse_live_table(json).unwrap();
        let set = |n: &str, ty: &str| {
            format!("\tset {n} {{\n\t\ttype {ty}\n\t\tflags interval\n\t\tauto-merge\n\t}}\n")
        };
        let body = [
            set("wan_address", "ipv4_addr"),
            set("wan6", "ipv6_addr"),
            set("flipped", "ipv6_addr"),
            set("bad_type", "ipv4_addr"),
            set("new_dyn", "ipv6_addr"),
        ]
        .concat();
        let (pre, created) = prelude(
            &live,
            &body,
            &[
                "wan_address".to_string(),
                "wan6".to_string(),
                "flipped".to_string(),
                "bad_type".to_string(),
                "new_dyn".to_string(),
            ],
        );
        assert_eq!(
            pre,
            "flush chain inet sparewall input\nflush chain inet sparewall in_wan\n\
             delete chain inet sparewall input\ndelete chain inet sparewall in_wan\n\
             delete set inet sparewall bad_type\ndelete set inet sparewall flipped\n\
             delete set inet sparewall old_static\n"
        );
        assert_eq!(created, ["flipped", "bad_type", "new_dyn"]);
    }

    #[test]
    fn prelude_for_absent_table() {
        let (pre, created) = prelude(&LiveTable::default(), "", &["x".to_string()]);
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
