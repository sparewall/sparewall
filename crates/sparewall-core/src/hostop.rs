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
    /// lego in its image, with `data` ([`LEGO_DATA`]) at `/data` and the
    /// variables in `env_file`, a file under [`LEGO_ENV_DIRS`].
    Lego {
        image: String,
        data: String,
        env_file: String,
        args: Vec<String>,
    },
    /// A provider's config check (one the renderer makes, see
    /// [`check_allowed`]) against the files in `dir`, under
    /// [`CHECK_DIR`]; in `image` for a container check.
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
/// lego's data directory: the state directory's `lego`.
pub const LEGO_DATA: &str = "/var/lib/sparewall/lego";
/// Where lego's environment files are written: the runtime directory, or
/// the data directory where there is none.
pub const LEGO_ENV_DIRS: &[&str] = &["/run/sparewall/lego", LEGO_DATA];
/// Where config checks put the files they check.
pub const CHECK_DIR: &str = "/run/sparewall/check";
/// bootc's store of logically bound images, where provider images live.
const BOUND_STORE: &str = "/usr/lib/bootc/storage";

impl HostOp {
    /// The command line, once every argument has been checked.
    pub fn argv(&self) -> Result<Vec<String>, String> {
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
                if data != LEGO_DATA {
                    return Err(format!("lego's data is {LEGO_DATA}, not {data:?}"));
                }
                if !LEGO_ENV_DIRS
                    .iter()
                    .any(|d| path_under(d, env_file).is_ok())
                {
                    return Err(format!("not a lego environment file: {env_file:?}"));
                }
                // lego's own options, inside its container.
                for a in args {
                    if a.len() > 4096 || a.chars().any(char::is_control) {
                        return Err(format!("bad lego argument: {a:?}"));
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
                path_under(CHECK_DIR, dir)?;
                check_allowed(spec)?;
                match (&spec.container, image) {
                    (Some(_), Some(image)) => {
                        image_ok(image)?;
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

    fn refused(op: HostOp) -> String {
        op.argv().expect_err("refused")
    }

    #[test]
    fn bootc_stage_builds_switch_or_upgrade() {
        let op = HostOp::BootcStage {
            image: Some("ghcr.io/sparewall/sparewall:stable".into()),
            download_only: true,
        };
        assert_eq!(
            op.argv().unwrap(),
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
        assert_eq!(op.argv().unwrap(), ["bootc", "upgrade"]);
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
        assert!(ok.argv().unwrap().ends_with(&[
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
        .argv()
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

    #[test]
    fn lego_mounts_only_its_own_data() {
        let op = |data: &str, env: &str| HostOp::Lego {
            image: "ghcr.io/sparewall/lego:sha-1".into(),
            data: data.into(),
            env_file: env.into(),
            args: vec!["--accept-tos".into(), "--email=a@b.c".into(), "run".into()],
        };
        let a = op(LEGO_DATA, "/run/sparewall/lego/.env-00ff")
            .argv()
            .unwrap();
        assert!(a.contains(&format!("{LEGO_DATA}:/data:Z")));
        op(LEGO_DATA, &format!("{LEGO_DATA}/.env-00ff"))
            .argv()
            .unwrap();
        for data in ["/etc", "/var/lib/sparewall", &format!("{LEGO_DATA}/../x")] {
            refused(op(data, "/run/sparewall/lego/.env-1"));
        }
        for env in [
            "/etc/shadow",
            "/run/sparewall/lego",
            "/run/sparewall/lego/../x",
            "/run/sparewall/lego/x:/etc",
        ] {
            refused(op(LEGO_DATA, env));
        }
    }

    #[test]
    fn only_the_renderers_config_checks() {
        let dir = format!("{CHECK_DIR}/1-0");
        for spec in [
            kea::check_spec(),
            unbound::check_spec(),
            chrony::check_spec(),
            keepalived::check_spec(&["eth0".into(), "wan.10".into()]),
        ] {
            let image = spec
                .container
                .as_ref()
                .map(|_| "ghcr.io/sparewall/kea:sha-1".to_string());
            let op = HostOp::ConfigCheck {
                spec: spec.clone(),
                dir: dir.clone(),
                image,
            };
            let a = op.argv().unwrap();
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
            .argv()
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
