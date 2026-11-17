//! What the coordinator may have run as root outside its sandbox (#279).
//!
//! Some commands need what the coordinator's systemd sandbox and SELinux
//! domain forbid: bootc, podman, unshare, timers, the admin password, the
//! hostname. `sparewall-run@<id>.service` runs them, unconfined. It takes
//! one of these operations, never a command line: each builds its own
//! argv from arguments it has checked, and anything else is refused. So a
//! compromised coordinator can ask for these and only these, not for any
//! command as root.

use serde::{Deserialize, Serialize};
use sparewall_render::{CheckSpec, chrony, kea, keepalived, unbound};

/// An operation for `sparewall-run@`, with its arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum HostOp {
    /// `bootc status --format=json`.
    BootcStatus,
    /// `bootc upgrade --check`.
    BootcCheck,
    /// Stage an image: `bootc switch --enforce-container-sigpolicy IMAGE`,
    /// or `bootc upgrade` for the image the node already tracks
    /// (`image: None`), optionally `--download-only`.
    BootcStage {
        image: Option<String>,
        download_only: bool,
    },
    /// `bootc upgrade --from-downloaded`.
    BootcApplyDownloaded,
    /// `skopeo inspect --no-tags docker://IMAGE`.
    SkopeoInspect { image: String, timeout_s: u64 },
    /// Reboot in five seconds (a transient timer).
    RebootSoon,
    /// keepalived: stop (without waiting), start, or its `ActiveState`.
    Keepalived { action: UnitAction },
    /// Stop a `sparewall-*` timer.
    TimerStop { unit: String },
    /// Clear a `sparewall-*` timer's and service's failed state.
    TimerResetFailed { unit: String },
    /// A persistent `sparewall-*` timer running one of [`TIMER_JOBS`].
    TimerCreate {
        unit: String,
        description: String,
        calendar: String,
        command: Vec<String>,
    },
    /// The next elapse of a calendar expression, after `base` (seconds)
    /// or now.
    CalendarNext { expr: String, base: Option<i64> },
    /// lego in the image the node ships ([`lego_image`]), with `data` (the
    /// state directory's `lego`) at `/data`, the variables in `env_file`
    /// (under the runtime directory's `lego`, or `data`), and `args` that
    /// [`lego_args`] makes: one order, no hooks or other options.
    Lego {
        image: String,
        data: String,
        env_file: String,
        args: Vec<String>,
    },
    /// A provider's config check (one the renderer makes, see
    /// [`check_allowed`]) against the files in `dir`, under the runtime
    /// directory's `check`; in `image`, the provider's own, for a
    /// container check.
    ConfigCheck {
        spec: CheckSpec,
        dir: String,
        image: Option<String>,
    },
    /// `usermod -p HASH admin`.
    SetAdminPassword { hash: String },
    /// `hostnamectl hostname --static`.
    Hostname,
    /// `hostnamectl set-hostname NAME`.
    SetHostname { name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitAction {
    Stop,
    Start,
    State,
}

/// The commands a timer may run.
pub const TIMER_JOBS: &[&[&str]] = &[&["/usr/bin/sparewall", "backup", "--quiet"]];
/// bootc's store of logically bound images, where provider images live.
const BOUND_STORE: &str = "/usr/lib/bootc/storage";
/// Where the image ships the lego image reference, as a Quadlet `.image`
/// unit that is also a logically bound image (read-only, in `/usr`).
pub const LEGO_IMAGE_UNIT: &str = "/usr/share/containers/systemd/sparewall-lego.image";

/// The directories paths in an operation must be under, as the run unit
/// sees them (its own environment, not the spool's).
#[derive(Debug, Clone)]
pub struct Roots {
    /// The coordinator's state directory (`SPAREWALL_STATE`).
    pub state: String,
    /// The coordinator's runtime directory.
    pub runtime: String,
    /// Root's alone, where the run unit copies what it reads for a job:
    /// outside the coordinator's writable paths.
    pub private: String,
    /// The lego image, when not [`lego_image`]'s (tests).
    pub lego_image: Option<String>,
}

impl Roots {
    pub fn from_env() -> Roots {
        Roots {
            state: std::env::var("SPAREWALL_STATE")
                .ok()
                .filter(|s| s.starts_with('/'))
                .unwrap_or_else(|| "/var/lib/sparewall".into()),
            runtime: "/run/sparewall".into(),
            private: "/run/sparewall-run".into(),
            lego_image: None,
        }
    }

    pub fn lego_data(&self) -> String {
        format!("{}/lego", self.state)
    }

    fn lego_env_dirs(&self) -> [String; 2] {
        [format!("{}/lego", self.runtime), self.lego_data()]
    }

    fn check_dir(&self) -> String {
        format!("{}/check", self.runtime)
    }
}

impl HostOp {
    /// The command line, once every argument has been checked. `roots`
    /// are the directories its paths must be under, and the lego image
    /// must be the shipped one; `None` (no privilege boundary: run
    /// directly, in development) checks the rest only.
    pub fn argv(&self, roots: Option<&Roots>) -> Result<Vec<String>, String> {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        Ok(match self {
            HostOp::BootcStatus => v(&["bootc", "status", "--format=json"]),
            HostOp::BootcCheck => v(&["bootc", "upgrade", "--check"]),
            HostOp::BootcStage {
                image,
                download_only,
            } => {
                let mut a = match image {
                    Some(i) => {
                        image_ok(i)?;
                        v(&["bootc", "switch", "--enforce-container-sigpolicy", i])
                    }
                    None => v(&["bootc", "upgrade"]),
                };
                if *download_only {
                    a.insert(2, "--download-only".into());
                }
                a
            }
            HostOp::BootcApplyDownloaded => v(&["bootc", "upgrade", "--from-downloaded"]),
            HostOp::SkopeoInspect { image, timeout_s } => {
                image_ok(image)?;
                if !(1..=3600).contains(timeout_s) {
                    return Err(format!("timeout {timeout_s}s out of range"));
                }
                vec![
                    "skopeo".into(),
                    format!("--command-timeout={timeout_s}s"),
                    "inspect".into(),
                    "--no-tags".into(),
                    format!("docker://{image}"),
                ]
            }
            HostOp::RebootSoon => {
                v(&["systemd-run", "--on-active=5s", "--", "systemctl", "reboot"])
            }
            HostOp::Keepalived { action } => match action {
                UnitAction::Stop => v(&["systemctl", "stop", "--no-block", "keepalived.service"]),
                UnitAction::Start => v(&["systemctl", "start", "keepalived.service"]),
                UnitAction::State => v(&[
                    "systemctl",
                    "show",
                    "--property=ActiveState",
                    "--value",
                    "keepalived.service",
                ]),
            },
            HostOp::TimerStop { unit } => {
                unit_ok(unit)?;
                vec!["systemctl".into(), "stop".into(), format!("{unit}.timer")]
            }
            HostOp::TimerResetFailed { unit } => {
                unit_ok(unit)?;
                vec![
                    "systemctl".into(),
                    "reset-failed".into(),
                    format!("{unit}.timer"),
                    format!("{unit}.service"),
                ]
            }
            HostOp::TimerCreate {
                unit,
                description,
                calendar,
                command,
            } => {
                unit_ok(unit)?;
                text_ok("description", description)?;
                text_ok("calendar", calendar)?;
                if !TIMER_JOBS.iter().any(|j| j[..] == command[..]) {
                    return Err(format!("not a timer job: {command:?}"));
                }
                let mut a = vec![
                    "systemd-run".into(),
                    format!("--unit={unit}"),
                    format!("--description={description}"),
                    format!("--on-calendar={calendar}"),
                    "--timer-property=Persistent=yes".into(),
                    "--timer-property=RandomizedDelaySec=5min".into(),
                ];
                a.extend(command.iter().cloned());
                a
            }
            HostOp::CalendarNext { expr, base } => {
                text_ok("calendar", expr)?;
                let mut a = v(&["systemd-analyze", "calendar", "--iterations=1"]);
                if let Some(b) = base {
                    a.push(format!("--base-time=@{b}"));
                }
                // After "--", an expression is never taken for an option.
                a.push("--".into());
                a.push(expr.clone());
                a
            }
            HostOp::Lego {
                image,
                data,
                env_file,
                args,
            } => {
                image_ok(image)?;
                lego_args_allowed(args)?;
                if let Some(r) = roots {
                    let shipped = match &r.lego_image {
                        Some(i) => i.clone(),
                        None => lego_image()?,
                    };
                    if *image != shipped {
                        return Err(format!("lego runs in {shipped}, not {image}"));
                    }
                    if *data != r.lego_data() {
                        return Err(format!("lego's data is {}, not {data:?}", r.lego_data()));
                    }
                    if !r
                        .lego_env_dirs()
                        .iter()
                        .any(|d| path_under(d, env_file).is_ok())
                    {
                        return Err(format!("not a lego environment file: {env_file:?}"));
                    }
                }
                let mut a = vec!["podman".into()];
                if std::path::Path::new(BOUND_STORE).is_dir() {
                    a.push(format!("--storage-opt=additionalimagestore={BOUND_STORE}"));
                }
                a.extend(
                    [
                        "run",
                        "--rm",
                        "--pull=never",
                        "--network=host",
                        "--env-file",
                    ]
                    .map(String::from),
                );
                a.push(env_file.clone());
                a.push("-v".into());
                a.push(format!("{data}:/data:Z"));
                a.push(image.clone());
                a.extend(args.iter().cloned());
                a
            }
            HostOp::ConfigCheck { spec, dir, image } => {
                if let Some(r) = roots {
                    path_under(&r.check_dir(), dir)?;
                }
                check_allowed(spec)?;
                match (&spec.container, image) {
                    (Some(container), Some(image)) => {
                        image_ok(image)?;
                        provider_image_ok(container, image)?;
                        let mut a = vec![
                            "podman".into(),
                            format!("--storage-opt=additionalimagestore={BOUND_STORE}"),
                            "run".into(),
                            "--rm".into(),
                            "--network=none".into(),
                            "--read-only".into(),
                            "--pull=never".into(),
                            "--security-opt".into(),
                            "label=disable".into(),
                            "-v".into(),
                            format!("{dir}:{}:ro", spec.mount),
                            image.clone(),
                        ];
                        a.extend(spec.command.iter().cloned());
                        a
                    }
                    (None, None) => spec
                        .command
                        .iter()
                        .map(|a| a.replace(&spec.mount, dir))
                        .collect(),
                    _ => return Err("a container check needs an image, a host check none".into()),
                }
            }
            HostOp::SetAdminPassword { hash } => {
                if !sparewall_config::identity::password_hash_ok(hash) {
                    return Err("not a crypt(3) hash".into());
                }
                vec!["usermod".into(), "-p".into(), hash.clone(), "admin".into()]
            }
            HostOp::Hostname => v(&["hostnamectl", "hostname", "--static"]),
            HostOp::SetHostname { name } => {
                hostname_ok(name)?;
                vec!["hostnamectl".into(), "set-hostname".into(), name.clone()]
            }
        })
    }
}

/// Whether `spec` is one of the config checks the renderer makes: Kea's,
/// Unbound's and chrony's exactly, or keepalived's for some valid
/// interface names.
pub fn check_allowed(spec: &CheckSpec) -> Result<(), String> {
    let same = |want: CheckSpec| {
        want.container == spec.container && want.mount == spec.mount && want.command == spec.command
    };
    if same(kea::check_spec()) || same(unbound::check_spec()) || same(chrony::check_spec()) {
        return Ok(());
    }
    // keepalived's: rebuilt from the links its script names.
    let links = spec
        .command
        .get(4)
        .and_then(|s| s.strip_prefix(keepalived::CHECK_LINKS_START))
        .and_then(|s| s.split_once(keepalived::CHECK_LINKS_END))
        .map(|(l, _)| l.split(' ').map(str::to_string).collect::<Vec<_>>());
    if let Some(links) = links
        && links.iter().all(|l| ifname_ok(l))
        && same(keepalived::check_spec(&links))
    {
        return Ok(());
    }
    Err(format!("not a known config check: {:?}", spec.command))
}

/// lego's command line for one order: the single definition the
/// coordinator builds it with and the run unit checks it against.
pub fn lego_args(
    name: &str,
    server: &str,
    provider: &str,
    email: Option<&str>,
    domains: &[String],
) -> Vec<String> {
    let mut a: Vec<String> = [
        "--log.format",
        "text",
        "run",
        "--path",
        "/data",
        "--accept-tos",
        "--no-random-sleep",
        "--renew-force",
        "--force-cert-domains",
        "--server",
        server,
        "--dns",
        provider,
        "--cert.name",
        name,
    ]
    .map(String::from)
    .to_vec();
    if let Some(e) = email {
        a.extend(["--email".into(), e.to_string()]);
    }
    for d in domains {
        a.extend(["--domains".into(), d.clone()]);
    }
    a
}

/// Whether `args` are what [`lego_args`] makes for some checked values:
/// they are read back, each value checked, and rebuilt to compare, so no
/// other option (a hook that runs a command, say) gets through.
fn lego_args_allowed(args: &[String]) -> Result<(), String> {
    let refuse = || Err(format!("not a lego order: {args:?}"));
    let value = |a: &str| {
        !a.is_empty()
            && a.len() <= 1024
            && !a.starts_with('-')
            && !a.chars().any(|c| c.is_control() || c.is_whitespace())
    };
    let get = |flag: &str| -> Vec<&str> {
        args.windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].as_str())
            .collect()
    };
    let one = |flag: &str| match get(flag)[..] {
        [v] if value(v) => Some(v),
        _ => None,
    };
    let (Some(server), Some(provider), Some(name)) =
        (one("--server"), one("--dns"), one("--cert.name"))
    else {
        return refuse();
    };
    let email = match get("--email")[..] {
        [] => None,
        [e] if value(e) => Some(e),
        _ => return refuse(),
    };
    let domains: Vec<String> = get("--domains").into_iter().map(String::from).collect();
    let ok = (server.starts_with("https://") || server.starts_with("http://"))
        && provider
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        && !domains.is_empty()
        && domains.iter().all(|d| {
            let host = d.strip_prefix("*.").unwrap_or(d);
            value(d) && hostname_ok(host).is_ok()
        })
        && lego_args(name, server, provider, email, &domains) == args;
    if ok { Ok(()) } else { refuse() }
}

/// The lego image the node ships: `SPAREWALL_LEGO_IMAGE` (development),
/// else the `Image=` of [`LEGO_IMAGE_UNIT`].
pub fn lego_image() -> Result<String, String> {
    if let Ok(image) = std::env::var("SPAREWALL_LEGO_IMAGE") {
        return Ok(image);
    }
    let unit =
        std::fs::read_to_string(LEGO_IMAGE_UNIT).map_err(|e| format!("{LEGO_IMAGE_UNIT}: {e}"))?;
    unit.lines()
        .find_map(|l| l.trim().strip_prefix("Image="))
        .map(|i| i.trim().to_string())
        .ok_or_else(|| format!("{LEGO_IMAGE_UNIT} names no image"))
}

/// A provider's container check runs in that provider's image, nothing
/// else in the image store.
fn provider_image_ok(container: &str, image: &str) -> Result<(), String> {
    let repo = container
        .strip_prefix("sparewall-")
        .map(|p| format!("ghcr.io/sparewall/{p}"))
        .unwrap_or_default();
    let ok = image
        .strip_prefix(&repo)
        .is_some_and(|rest| rest.starts_with(':') || rest.starts_with('@'));
    if ok {
        Ok(())
    } else {
        Err(format!("{container} is checked in {repo}, not {image}"))
    }
}

/// That no component of `p`, an absolute path, is a symbolic link, and
/// that it exists: the run unit uses the path as root, and a link the
/// coordinator planted could point it anywhere.
pub fn no_symlinks(p: &std::path::Path) -> Result<(), String> {
    if !p.is_absolute() {
        return Err(format!("{}: not absolute", p.display()));
    }
    let mut at = std::path::PathBuf::from("/");
    for c in p.components().skip(1) {
        at.push(c);
        let m = std::fs::symlink_metadata(&at).map_err(|e| format!("{}: {e}", at.display()))?;
        if m.file_type().is_symlink() {
            return Err(format!("{}: a symbolic link", at.display()));
        }
    }
    Ok(())
}

/// An image reference: registry/path[:tag][@digest], nothing that could be
/// read as an option or carry anything else.
fn image_ok(r: &str) -> Result<(), String> {
    let ok = !r.is_empty()
        && r.len() <= 512
        && r.contains('/')
        && !r.starts_with(['-', '/', '.', ':', '@'])
        && r.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-/:@".contains(c));
    if ok {
        Ok(())
    } else {
        Err(format!("not an image reference: {r:?}"))
    }
}

/// A Sparewall unit name (without its suffix).
fn unit_ok(u: &str) -> Result<(), String> {
    let ok = u.len() <= 64
        && u.strip_prefix("sparewall-").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        });
    if ok {
        Ok(())
    } else {
        Err(format!("not a Sparewall unit: {u:?}"))
    }
}

/// One line of printable text that is not an option.
fn text_ok(what: &str, s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 512 || s.starts_with('-') || s.chars().any(char::is_control) {
        Err(format!("bad {what}: {s:?}"))
    } else {
        Ok(())
    }
}

/// An absolute path strictly below `root`, of plain components only (no
/// `..`, and none of the `:` or `,` that podman's `-v` reads as syntax).
fn path_under(root: &str, p: &str) -> Result<(), String> {
    let ok = p
        .strip_prefix(root)
        .and_then(|r| r.strip_prefix('/'))
        .is_some_and(|rest| {
            !rest.is_empty()
                && rest.split('/').all(|c| {
                    !c.is_empty()
                        && c != "."
                        && c != ".."
                        && c.chars()
                            .all(|ch| ch.is_ascii_alphanumeric() || "._-".contains(ch))
                })
        });
    if ok {
        Ok(())
    } else {
        Err(format!("not a path under {root}: {p:?}"))
    }
}

/// A Linux interface name.
fn ifname_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 15
        && !n.starts_with('-')
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// A hostname: dot-separated labels of letters, digits and hyphens.
fn hostname_ok(n: &str) -> Result<(), String> {
    let ok = !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if ok {
        Ok(())
    } else {
        Err(format!("not a hostname: {n:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> Roots {
        Roots {
            state: "/var/lib/sparewall".into(),
            runtime: "/run/sparewall".into(),
            private: "/run/sparewall-run".into(),
            lego_image: Some("ghcr.io/sparewall/lego:sha-1".into()),
        }
    }

    fn refused(op: HostOp) -> String {
        op.argv(Some(&roots())).expect_err("refused")
    }

    #[test]
    fn bootc_stage_builds_switch_or_upgrade() {
        let op = HostOp::BootcStage {
            image: Some("ghcr.io/sparewall/sparewall:stable".into()),
            download_only: true,
        };
        assert_eq!(
            op.argv(Some(&roots())).unwrap(),
            [
                "bootc",
                "switch",
                "--download-only",
                "--enforce-container-sigpolicy",
                "ghcr.io/sparewall/sparewall:stable"
            ]
        );
        let op = HostOp::BootcStage {
            image: None,
            download_only: false,
        };
        assert_eq!(op.argv(Some(&roots())).unwrap(), ["bootc", "upgrade"]);
        refused(HostOp::BootcStage {
            image: Some("--transport=dir".into()),
            download_only: false,
        });
        refused(HostOp::SkopeoInspect {
            image: "ghcr.io/x/y z".into(),
            timeout_s: 10,
        });
    }

    #[test]
    fn timers_run_only_known_jobs_as_sparewall_units() {
        let ok = HostOp::TimerCreate {
            unit: "sparewall-backup".into(),
            description: "Sparewall backup".into(),
            calendar: "daily".into(),
            command: TIMER_JOBS[0].iter().map(|s| s.to_string()).collect(),
        };
        assert!(ok.argv(Some(&roots())).unwrap().ends_with(&[
            "/usr/bin/sparewall".to_string(),
            "backup".into(),
            "--quiet".into()
        ]));
        let mut bad = ok.clone();
        if let HostOp::TimerCreate { command, .. } = &mut bad {
            *command = vec!["/bin/sh".into(), "-c".into(), "id".into()];
        }
        assert!(refused(bad).contains("not a timer job"));
        let mut bad = ok.clone();
        if let HostOp::TimerCreate { unit, .. } = &mut bad {
            *unit = "sshd".into();
        }
        refused(bad);
        let mut bad = ok;
        if let HostOp::TimerCreate { description, .. } = &mut bad {
            *description = "x\nExecStart=/bin/sh".into();
        }
        refused(bad);
        refused(HostOp::TimerStop {
            unit: "sparewall-../x".into(),
        });
    }

    #[test]
    fn calendar_expressions_are_never_options() {
        let a = HostOp::CalendarNext {
            expr: "Sun 03:00".into(),
            base: Some(10),
        }
        .argv(Some(&roots()))
        .unwrap();
        assert_eq!(
            a,
            [
                "systemd-analyze",
                "calendar",
                "--iterations=1",
                "--base-time=@10",
                "--",
                "Sun 03:00"
            ]
        );
        refused(HostOp::CalendarNext {
            expr: "--help".into(),
            base: None,
        });
    }

    fn order() -> Vec<String> {
        lego_args(
            "mgmt",
            "https://acme.example/dir",
            "gcloud",
            Some("ops@example.org"),
            &["fw.example.org".into(), "*.lan.example.org".into()],
        )
    }

    #[test]
    fn lego_mounts_only_its_own_data() {
        const DATA: &str = "/var/lib/sparewall/lego";
        let op = |data: &str, env: &str| HostOp::Lego {
            image: "ghcr.io/sparewall/lego:sha-1".into(),
            data: data.into(),
            env_file: env.into(),
            args: order(),
        };
        let a = op(DATA, "/run/sparewall/lego/.env-00ff")
            .argv(Some(&roots()))
            .unwrap();
        assert!(a.contains(&format!("{DATA}:/data:Z")));
        op(DATA, &format!("{DATA}/.env-00ff"))
            .argv(Some(&roots()))
            .unwrap();
        for data in ["/etc", "/var/lib/sparewall", &format!("{DATA}/../x")] {
            refused(op(data, "/run/sparewall/lego/.env-1"));
        }
        for env in [
            "/etc/shadow",
            "/run/sparewall/lego",
            "/run/sparewall/lego/../x",
            "/run/sparewall/lego/x:/etc",
        ] {
            refused(op(DATA, env));
        }
        // Another state directory moves both with it.
        let other = Roots {
            state: "/srv/sw".into(),
            ..roots()
        };
        op("/srv/sw/lego", "/srv/sw/lego/.env-1")
            .argv(Some(&other))
            .unwrap();
        // Only the shipped image: a provider image with no entrypoint
        // would run the arguments as its command.
        let mut kea = op(DATA, "/run/sparewall/lego/.env-1");
        if let HostOp::Lego { image, .. } = &mut kea {
            *image = "ghcr.io/sparewall/kea:sha-1".into();
        }
        assert!(refused(kea).contains("lego runs in"));
    }

    /// lego's arguments are one order as lego_args makes it: no other
    /// option, and no value that is one.
    #[test]
    fn lego_takes_one_order_and_nothing_else() {
        let op = |args: Vec<String>| HostOp::Lego {
            image: "ghcr.io/sparewall/lego:sha-1".into(),
            data: "/var/lib/sparewall/lego".into(),
            env_file: "/run/sparewall/lego/.env-1".into(),
            args,
        };
        op(order()).argv(Some(&roots())).unwrap();
        let mut hook = order();
        hook.extend(["--run-hook".into(), "sh -c id".into()]);
        refused(op(hook));
        let mut hook = order();
        hook.push("--run-hook=id".into());
        refused(op(hook));
        let shell: Vec<String> = ["/bin/sh", "-c", "id"].map(String::from).to_vec();
        refused(op(shell));
        let as_option = lego_args(
            "mgmt",
            "https://acme.example/dir",
            "--run-hook=id",
            None,
            &["fw.example.org".into()],
        );
        refused(op(as_option));
        let spaced = lego_args(
            "mgmt",
            "https://acme.example/dir",
            "gcloud",
            None,
            &["fw.example.org x".into()],
        );
        refused(op(spaced));
        let no_domains = lego_args("mgmt", "https://acme.example/dir", "gcloud", None, &[]);
        refused(op(no_domains));
    }

    /// No component of a path the run unit uses may be a link.
    #[test]
    fn symbolic_links_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("f"), "x").unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();
        assert!(no_symlinks(&real.join("f")).is_ok());
        assert!(no_symlinks(&dir.path().join("link").join("f")).is_err());
        assert!(no_symlinks(&dir.path().join("link")).is_err());
        assert!(no_symlinks(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn only_the_renderers_config_checks() {
        let dir = "/run/sparewall/check/1-0".to_string();
        for spec in [
            kea::check_spec(),
            unbound::check_spec(),
            chrony::check_spec(),
            keepalived::check_spec(&["eth0".into(), "wan.10".into()]),
        ] {
            let image = spec.container.as_ref().map(|c| {
                format!(
                    "ghcr.io/sparewall/{}:sha-1",
                    c.strip_prefix("sparewall-").unwrap()
                )
            });
            let op = HostOp::ConfigCheck {
                spec: spec.clone(),
                dir: dir.clone(),
                image,
            };
            let a = op.argv(Some(&roots())).unwrap();
            if spec.container.is_none() {
                assert!(a.iter().any(|x| x.contains(&dir)), "{a:?}");
            }
        }
        // A keepalived check whose links smuggle a command.
        let mut evil = keepalived::check_spec(&["eth0".into()]);
        evil.command[4] = evil.command[4].replace("eth0", "eth0; reboot;");
        assert!(check_allowed(&evil).is_err());
        let mut evil = chrony::check_spec();
        evil.command = vec!["sh".into(), "-c".into(), "id".into()];
        assert!(check_allowed(&evil).is_err());
        let mut evil = kea::check_spec();
        evil.command.push("--extra".into());
        assert!(check_allowed(&evil).is_err());
        // Kea's check in another image.
        assert!(
            refused(HostOp::ConfigCheck {
                spec: kea::check_spec(),
                dir: dir.clone(),
                image: Some("ghcr.io/sparewall/lego:sha-1".into()),
            })
            .contains("checked in ghcr.io/sparewall/kea")
        );
        // Outside the check directory.
        refused(HostOp::ConfigCheck {
            spec: chrony::check_spec(),
            dir: "/etc".into(),
            image: None,
        });
    }

    #[test]
    fn passwords_and_hostnames_are_checked() {
        refused(HostOp::SetAdminPassword {
            hash: "x:0:0::/root:/bin/sh".into(),
        });
        refused(HostOp::SetHostname { name: "-f".into() });
        refused(HostOp::SetHostname { name: "a b".into() });
        assert_eq!(
            HostOp::SetHostname {
                name: "fw1.example.net".into()
            }
            .argv(Some(&roots()))
            .unwrap(),
            ["hostnamectl", "set-hostname", "fw1.example.net"]
        );
    }

    /// The spool carries the operation, tagged, and reads back the same.
    #[test]
    fn operations_round_trip() {
        let op = HostOp::Keepalived {
            action: UnitAction::Stop,
        };
        let j = serde_json::to_string(&op).unwrap();
        assert_eq!(j, r#"{"op":"keepalived","action":"stop"}"#);
        assert_eq!(serde_json::from_str::<HostOp>(&j).unwrap(), op);
    }
}
