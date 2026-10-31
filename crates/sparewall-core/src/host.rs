//! Host operations the daemon's orchestration needs beyond [`System`]:
//! conntrackd transitions, restic, systemd timers, RFC 2136 DNS updates
//! and lego. Each is a narrow trait at the level of the operation, with
//! its failure model in the signature, so the orchestration around it
//! (failover, backup, certificate challenges) is tested against fakes.
//! The implementations here run the real commands.
//!
//! [`System`]: crate::System

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::linux::host_run;

/// One conntrackd command in a VRRP transition (the primary-backup
/// sequence shipped with conntrack-tools).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackStep {
    /// `-c`: commit the external cache (the peer's state) to the kernel.
    Commit,
    /// `-f`: flush the internal and external caches.
    Flush,
    /// `-R`: resync the internal cache with the kernel table.
    Resync,
    /// `-B`: send a bulk update to the peer.
    BulkSend,
    /// `-n`: ask the peer for a full resync.
    RequestResync,
    /// `-t`: shorten kernel timers so stale entries expire.
    ShortenTimers,
}

impl ConntrackStep {
    pub fn flag(self) -> &'static str {
        match self {
            ConntrackStep::Commit => "-c",
            ConntrackStep::Flush => "-f",
            ConntrackStep::Resync => "-R",
            ConntrackStep::BulkSend => "-B",
            ConntrackStep::RequestResync => "-n",
            ConntrackStep::ShortenTimers => "-t",
        }
    }
}

/// conntrackd, the connection-state sync daemon.
pub trait Conntrackd: Send + Sync {
    /// Whether conntrackd is configured on this node (a pair).
    fn configured(&self) -> bool;
    /// Run one step; an error says why it failed.
    fn run(&self, step: ConntrackStep) -> Result<(), String>;
}

/// conntrackd through its command line, with the rendered configuration.
pub struct HostConntrackd {
    pub conf: PathBuf,
}

impl Conntrackd for HostConntrackd {
    fn configured(&self) -> bool {
        self.conf.exists()
    }

    fn run(&self, step: ConntrackStep) -> Result<(), String> {
        let out = Command::new("conntrackd")
            .arg("-C")
            .arg(&self.conf)
            .arg(step.flag())
            .output()
            .map_err(|e| format!("cannot run conntrackd: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }
}

/// A backup repository.
pub trait BackupRepository: Send + Sync {
    /// Whether the repository has been initialised.
    fn exists(&self) -> Result<bool, String>;
    fn init(&self) -> Result<(), String>;
    /// Store `bundle` as `filename` for `host`; returns the snapshot ID.
    fn backup(&self, bundle: &Path, filename: &str, host: &str) -> Result<String, String>;
}

/// A restic repository.
pub struct Restic {
    pub repository: String,
    pub password: Vec<u8>,
    /// Repository credentials (`AWS_ACCESS_KEY_ID` and the like).
    pub env: Vec<(String, String)>,
    pub cache: PathBuf,
}

impl Restic {
    fn run(&self, args: &[&str], stdin: Option<&Path>) -> Result<(i32, String), String> {
        let mut cmd = Command::new("restic");
        cmd.arg("--cache-dir")
            .arg(&self.cache)
            .args(args)
            .env("RESTIC_REPOSITORY", &self.repository)
            .env(
                "RESTIC_PASSWORD",
                String::from_utf8_lossy(&self.password).as_ref(),
            )
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| format!("restic: {e}"))?;
        if let Some(p) = stdin {
            let data = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let mut w = child.stdin.take().expect("piped");
            // A writer thread, so a full stdout pipe cannot deadlock us.
            let t = std::thread::spawn(move || w.write_all(&data));
            let out = child
                .wait_with_output()
                .map_err(|e| format!("restic: {e}"))?;
            let _ = t.join();
            return Ok(outcome(out));
        }
        Ok(outcome(
            child
                .wait_with_output()
                .map_err(|e| format!("restic: {e}"))?,
        ))
    }
}

fn outcome(out: Output) -> (i32, String) {
    let code = out.status.code().unwrap_or(-1);
    let text = if code == 0 { out.stdout } else { out.stderr };
    (code, String::from_utf8_lossy(&text).trim().to_string())
}

impl BackupRepository for Restic {
    fn exists(&self) -> Result<bool, String> {
        // A missing repository: exit code 10 since restic 0.17, only the
        // message before.
        match self.run(&["cat", "config"], None)? {
            (0, _) => Ok(true),
            (c, e) if c == 10 || e.contains("Is there a repository at the following location") => {
                Ok(false)
            }
            (_, e) => Err(format!("restic: {e}")),
        }
    }

    fn init(&self) -> Result<(), String> {
        match self.run(&["init"], None)? {
            (0, _) => Ok(()),
            (_, e) => Err(format!("restic init: {e}")),
        }
    }

    fn backup(&self, bundle: &Path, filename: &str, host: &str) -> Result<String, String> {
        match self.run(
            &[
                "backup",
                "--json",
                "--host",
                host,
                "--tag",
                "sparewall",
                "--stdin",
                "--stdin-filename",
                filename,
            ],
            Some(bundle),
        )? {
            (0, out) => Ok(out
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .find(|v| v["message_type"] == "summary")
                .and_then(|v| v["snapshot_id"].as_str().map(str::to_string))
                .unwrap_or_default()),
            (_, e) => Err(format!("restic backup: {e}")),
        }
    }
}

/// A calendar timer that runs a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerSpec {
    /// The unit name, without `.timer`.
    pub unit: String,
    pub description: String,
    /// A systemd calendar expression (`hourly`, `*-*-* 03:00`).
    pub calendar: String,
    pub command: Vec<String>,
}

/// Transient systemd timers.
pub trait Timers: Send + Sync {
    /// Stop and forget the timer and its service. A timer that does not
    /// exist is already removed; any other failure is returned.
    fn remove(&self, unit: &str) -> Result<(), String>;
    fn create(&self, timer: &TimerSpec) -> Result<(), String>;
}

/// Timers made with `systemd-run`, outside the daemon's sandbox.
pub struct SystemdTimers;

impl Timers for SystemdTimers {
    fn remove(&self, unit: &str) -> Result<(), String> {
        match host_run("systemctl", &["stop", &format!("{unit}.timer")]) {
            Err(e) if !e.to_string().contains("not loaded") => return Err(e.to_string()),
            _ => {}
        }
        // Only clears a failed state; nothing to report if there is none.
        let _ = host_run(
            "systemctl",
            &[
                "reset-failed",
                &format!("{unit}.timer"),
                &format!("{unit}.service"),
            ],
        );
        Ok(())
    }

    fn create(&self, t: &TimerSpec) -> Result<(), String> {
        let mut args = vec![
            format!("--unit={}", t.unit),
            format!("--description={}", t.description),
            format!("--on-calendar={}", t.calendar),
            "--timer-property=Persistent=yes".into(),
            "--timer-property=RandomizedDelaySec=5min".into(),
        ];
        args.extend(t.command.iter().cloned());
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        host_run("systemd-run", &args)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// A DNS zone that takes TXT updates, for ACME dns-01 challenges.
pub trait DnsZone: Send + Sync {
    /// Replace the TXT records at `record` with `value`.
    fn set_txt(&self, record: &str, value: &str) -> Result<(), String>;
    /// Remove the TXT records at `record`.
    fn delete_txt(&self, record: &str) -> Result<(), String>;
    /// The TXT values the authoritative server answers for `record`.
    fn txt(&self, record: &str) -> Result<Vec<String>, String>;
    /// The server, for messages.
    fn server(&self) -> &str;
}

/// lego, the ACME client that speaks to hosted DNS APIs (Google Cloud DNS,
/// Cloudflare, Route 53 and many more), for DNS-01 challenges the
/// coordinator cannot publish itself. It runs a whole order.
pub trait Lego: Send + Sync {
    /// Run `lego ARGS` with its data directory, `data`, at `/data` and the
    /// variables in `env_file` (credentials included) in its environment.
    fn run(&self, data: &Path, env_file: &Path, args: &[String]) -> Result<(), String>;
}

/// Where the image ships the lego image reference, as a Quadlet `.image`
/// unit that is also a logically bound image.
pub const LEGO_IMAGE_UNIT: &str = "/usr/share/containers/systemd/sparewall-lego.image";
/// bootc's store of logically bound images.
const BOUND_STORE: &str = "/usr/lib/bootc/storage";

/// lego in its provider image, run by podman outside the coordinator's
/// sandbox.
pub struct LegoContainer {
    pub image: String,
}

impl LegoContainer {
    /// The image the node ships (`SPAREWALL_LEGO_IMAGE` overrides it).
    pub fn shipped() -> Result<LegoContainer, String> {
        if let Ok(image) = std::env::var("SPAREWALL_LEGO_IMAGE") {
            return Ok(LegoContainer { image });
        }
        let unit = std::fs::read_to_string(LEGO_IMAGE_UNIT)
            .map_err(|e| format!("{LEGO_IMAGE_UNIT}: {e}"))?;
        unit.lines()
            .find_map(|l| l.trim().strip_prefix("Image="))
            .map(|i| LegoContainer {
                image: i.trim().to_string(),
            })
            .ok_or_else(|| format!("{LEGO_IMAGE_UNIT} names no image"))
    }
}

impl Lego for LegoContainer {
    fn run(&self, data: &Path, env_file: &Path, args: &[String]) -> Result<(), String> {
        let mut argv: Vec<String> = Vec::new();
        if Path::new(BOUND_STORE).is_dir() {
            argv.push(format!("--storage-opt=additionalimagestore={BOUND_STORE}"));
        }
        argv.extend(
            [
                "run",
                "--rm",
                "--pull=never",
                "--network=host",
                "--env-file",
            ]
            .map(String::from),
        );
        argv.push(env_file.display().to_string());
        argv.push("-v".into());
        argv.push(format!("{}:/data:Z", data.display()));
        argv.push(self.image.clone());
        argv.extend(args.iter().cloned());
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        host_run("podman", &argv)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// RFC 2136 dynamic updates with `nsupdate`, read back with `dig`.
pub struct Rfc2136 {
    /// `host` or `host:port`.
    pub server: String,
    pub zone: Option<String>,
    /// `algorithm:name:secret`, as `nsupdate -y` takes it.
    pub tsig: String,
}

impl Rfc2136 {
    fn update(&self, record: &str, value: Option<&str>) -> Result<(), String> {
        let mut script = format!("server {}\n", self.server.replace(':', " "));
        if let Some(z) = &self.zone {
            script.push_str(&format!("zone {z}\n"));
        }
        script.push_str(&format!("update delete {record}. TXT\n"));
        if let Some(v) = value {
            script.push_str(&format!("update add {record}. 60 TXT \"{v}\"\n"));
        }
        script.push_str("send\n");
        let mut child = Command::new("nsupdate")
            .args(["-y", &self.tsig])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("nsupdate: {e}"))?;
        child
            .stdin
            .take()
            .expect("piped")
            .write_all(script.as_bytes())
            .map_err(|e| format!("nsupdate: {e}"))?;
        let out = child
            .wait_with_output()
            .map_err(|e| format!("nsupdate: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "nsupdate: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

impl DnsZone for Rfc2136 {
    fn set_txt(&self, record: &str, value: &str) -> Result<(), String> {
        self.update(record, Some(value))
    }

    fn delete_txt(&self, record: &str) -> Result<(), String> {
        self.update(record, None)
    }

    fn txt(&self, record: &str) -> Result<Vec<String>, String> {
        let (host, port) = self.server.split_once(':').unwrap_or((&self.server, "53"));
        let out = Command::new("dig")
            .args(["+short", "-p", port, &format!("@{host}"), "TXT", record])
            .output()
            .map_err(|e| format!("dig: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "dig: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().trim_matches('"').to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }

    fn server(&self) -> &str {
        &self.server
    }
}

/// What an OS upgrade does on this node: stage an image, reboot, and hand
/// the gateway addresses over by stopping keepalived.
pub trait UpgradeHost: Send + Sync {
    /// Stage `image` for the next boot. Returns the staged image, or
    /// `None` when the node already runs the newest one.
    fn stage(&self, image: &str) -> Result<Option<String>, String>;
    /// Download `image` and stage it without queueing it: a reboot
    /// discards it until [`Self::apply_downloaded`] queues it. Returns the
    /// downloaded image, or `None` when the node already runs the newest
    /// one (#175).
    fn download(&self, image: &str) -> Result<Option<String>, String>;
    /// Queue what [`Self::download`] staged for the next boot, without the
    /// network.
    /// Reboot in a few seconds, after the caller's reply has gone out.
    fn apply_downloaded(&self) -> Result<(), String>;
    /// The booted image as `reference@digest`, if bootc says.
    fn booted(&self) -> Option<String>;
    fn reboot_soon(&self) -> Result<(), String>;
    /// Queue keepalived's stop without waiting for the job.
    fn stop_keepalived(&self) -> Result<(), String>;
    /// keepalived's `ActiveState` (`active`, `deactivating`, `inactive`…).
    fn keepalived_state(&self) -> Result<String, String>;
    fn start_keepalived(&self) -> Result<(), String>;
}

/// bootc and systemctl, outside the daemon's sandbox.
pub struct HostUpgrade;

fn host(cmd: &str, args: &[&str]) -> Result<String, String> {
    host_run(cmd, args).map_err(|e| e.to_string())
}

/// `bootc status` as JSON.
pub fn bootc_status() -> Option<serde_json::Value> {
    serde_json::from_str(&host("bootc", &["status", "--format=json"]).ok()?).ok()
}

/// The bootc command that stages `image`, given `bootc status`. `switch`
/// to a reference the node already tracks does nothing ("Image
/// specification is unchanged"), so a node that tracks it, with the
/// signature policy enforced, `upgrade`s instead (#116).
pub fn stage_args<'a>(status: Option<&serde_json::Value>, image: &'a str) -> Vec<&'a str> {
    let spec = status.map(|s| &s["spec"]["image"]);
    let tracked = spec.is_some_and(|s| {
        s["image"].as_str() == Some(image) && s["signature"].as_str() == Some("containerPolicy")
    });
    if tracked {
        vec!["upgrade"]
    } else {
        vec!["switch", "--enforce-container-sigpolicy", image]
    }
}

/// The staged image as `reference@digest`, if one is staged.
fn staged_image(image: &str) -> Result<Option<String>, String> {
    let st = bootc_status().ok_or("cannot read bootc status")?;
    let staged = &st["status"]["staged"]["image"];
    Ok(staged["imageDigest"]
        .as_str()
        .map(|d| format!("{}@{d}", staged["image"]["image"].as_str().unwrap_or(image))))
}

impl UpgradeHost for HostUpgrade {
    fn stage(&self, image: &str) -> Result<Option<String>, String> {
        host("bootc", &stage_args(bootc_status().as_ref(), image))?;
        staged_image(image)
    }

    fn download(&self, image: &str) -> Result<Option<String>, String> {
        let mut args = stage_args(bootc_status().as_ref(), image);
        args.insert(1, "--download-only");
        host("bootc", &args)?;
        staged_image(image)
    }

    fn apply_downloaded(&self) -> Result<(), String> {
        host("bootc", &["upgrade", "--from-downloaded"]).map(|_| ())
    }

    fn booted(&self) -> Option<String> {
        let st = bootc_status()?;
        let img = &st["status"]["booted"]["image"];
        Some(format!(
            "{}@{}",
            img["image"]["image"].as_str().unwrap_or_default(),
            img["imageDigest"].as_str()?
        ))
    }

    fn reboot_soon(&self) -> Result<(), String> {
        host(
            "systemd-run",
            &["--on-active=5s", "--", "systemctl", "reboot"],
        )
        .map(|_| ())
    }

    fn stop_keepalived(&self) -> Result<(), String> {
        host("systemctl", &["stop", "--no-block", "keepalived.service"]).map(|_| ())
    }

    fn keepalived_state(&self) -> Result<String, String> {
        host(
            "systemctl",
            &[
                "show",
                "--property=ActiveState",
                "--value",
                "keepalived.service",
            ],
        )
        .map(|s| s.trim().to_string())
    }

    fn start_keepalived(&self) -> Result<(), String> {
        host("systemctl", &["start", "keepalived.service"]).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const STABLE: &str = "ghcr.io/sparewall/sparewall:stable";

    fn status(image: &str, signature: &str) -> serde_json::Value {
        json!({"spec": {"image": {"image": image, "signature": signature, "transport": "registry"}}})
    }

    #[test]
    fn a_tracked_reference_is_upgraded() {
        let st = status(STABLE, "containerPolicy");
        assert_eq!(stage_args(Some(&st), STABLE), ["upgrade"]);
    }

    #[test]
    fn another_reference_is_switched_to() {
        let st = status(
            "ghcr.io/sparewall/sparewall:sha-f940ddacccb9",
            "containerPolicy",
        );
        assert_eq!(
            stage_args(Some(&st), STABLE),
            ["switch", "--enforce-container-sigpolicy", STABLE]
        );
    }

    #[test]
    fn a_tracked_reference_without_the_policy_is_switched_to() {
        // switch with the flag turns enforcement on.
        let st = status(STABLE, "insecure");
        assert_eq!(
            stage_args(Some(&st), STABLE),
            ["switch", "--enforce-container-sigpolicy", STABLE]
        );
        assert_eq!(
            stage_args(None, STABLE),
            ["switch", "--enforce-container-sigpolicy", STABLE]
        );
    }
}
