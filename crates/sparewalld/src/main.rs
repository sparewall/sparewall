//! sparewalld: the Sparewall coordinator.

mod access;
mod acme;
mod author;
mod backup;
mod dhcp_ha;
mod failover;
mod http;
#[cfg(test)]
mod isolation_tests;
mod lease;
mod motd;
mod peer;
mod reach;
mod rules;
mod seed;
mod selinux;
mod service;
mod upgrade;
mod varlink;
mod vrrp;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use serde_json::Value;
use sparewall_config::identity::Identity;
use sparewall_core::{Coordinator, Store, System};
use tokio::sync::broadcast;
use tracing_subscriber::prelude::*;

use crate::service::{Core, Firewall, with_core};

/// Where an install-time identity may be dropped (by a kickstart, or by
/// `sparewall init`) to be recorded at the next start.
const IDENTITY_DROP: &[&str] = &[
    "/etc/sparewall/identity.yaml",
    "/etc/sparewall/identity.json",
];
/// The admin account's home (`/home` is a symlink to it on bootc).
const ADMIN_HOME: &str = "/var/home/admin";
/// The systemd credential carrying the identity on VMs.
const IDENTITY_CREDENTIAL: &str = "sparewall.identity";

#[derive(Parser)]
#[command(version = sparewall_core::VERSION, about = "The Sparewall coordinator")]
struct Args {
    /// State directory (generations, identity, keys).
    #[arg(long, env = "SPAREWALL_STATE", default_value = "/var/lib/sparewall")]
    state: PathBuf,
    /// Varlink socket to listen on when not socket-activated.
    #[arg(long, env = "SPAREWALL_SOCKET", default_value = sparewall_api::SOCKET)]
    socket: PathBuf,
    /// The restricted socket, for unprivileged clients with a token.
    #[arg(long, env = "SPAREWALL_API_SOCKET", default_value = sparewall_api::API_SOCKET)]
    api_socket: PathBuf,
    /// Install the live generation's files and load the firewall, then exit.
    /// Runs before udev and networkd at boot.
    #[arg(long)]
    early: bool,
    /// Import a node identity (JSON or YAML) if none is recorded yet.
    #[arg(long)]
    identity: Option<PathBuf>,
    /// Address for the HTTPS health endpoints, or `off`.
    #[arg(long, env = "SPAREWALL_HTTPS", default_value = "[::]:443")]
    https: String,
    /// `sparewall-httpd`'s socket, which the HTTPS listener passes every
    /// path but the health endpoints to.
    #[arg(long, env = "SPAREWALL_WEB_SOCKET", default_value = sparewall_render::web::SOCKET)]
    web_socket: PathBuf,
    /// Run a spooled command (the body of sparewall-run@.service).
    #[arg(long, hide = true, value_name = "ID")]
    run: Option<String>,
    /// The login banner (pam_motd drop-in); default /run/motd.d/50-sparewall,
    /// none with a fake system.
    #[arg(long)]
    motd: Option<PathBuf>,
    /// Use an in-memory fake system instead of the real one (testing only).
    #[arg(long, hide = true, env = "SPAREWALL_FAKE_SYSTEM")]
    fake_system: bool,
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("SPAREWALL_LOG")
        .unwrap_or_else(|_| "info".into());
    let registry = tracing_subscriber::registry().with(filter);
    if std::env::var_os("JOURNAL_STREAM").is_some()
        && let Ok(journald) = tracing_journald::layer()
    {
        registry
            .with(journald.with_syslog_identifier("sparewalld".into()))
            .init();
        return;
    }
    registry
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();
}

fn read_identity(path: &Path) -> Result<Identity, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let format = sparewall_config::Format::detect(path.to_str(), &text);
    let v = sparewall_config::parse_value(&text, format).map_err(|e| e.to_string())?;
    let id: Identity = serde_json::from_value(v).map_err(|e| format!("{}: {e}", path.display()))?;
    id.check()?;
    Ok(id)
}

/// The recorded identity, or one supplied at install time (recorded now).
fn load_identity(store: &Store, args: &Args) -> Result<Option<Identity>, String> {
    if let Some(id) = store.identity().map_err(|e| e.to_string())? {
        return Ok(Some(id));
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    candidates.extend(args.identity.clone());
    if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        candidates.push(Path::new(&dir).join(IDENTITY_CREDENTIAL));
    }
    candidates.extend(IDENTITY_DROP.iter().map(PathBuf::from));
    if let Some(p) = candidates.into_iter().find(|p| p.exists()) {
        let id = read_identity(&p)?;
        store.set_identity(&id).map_err(|e| e.to_string())?;
        tracing::info!(node = %id.node, source = %p.display(), "recorded node identity");
        return Ok(Some(id));
    }
    Ok(None)
}

/// Install the identity's SSH keys for the `admin` account, in its
/// `~/.ssh/authorized_keys` (labelled for sshd by SELinux).
fn install_ssh_keys(home: &Path, id: &Identity) {
    let p = home.join(".ssh/authorized_keys");
    let mut keys = id.ssh_keys.join("\n");
    keys.push('\n');
    if std::fs::read_to_string(&p).ok().as_deref() != Some(keys.as_str()) {
        let r = sparewall_core::store::write_atomic(&p, keys.as_bytes());
        if let Err(e) = r {
            tracing::error!(error = %e, path = %p.display(), "cannot install admin SSH keys");
            return;
        }
        tracing::info!(keys = id.ssh_keys.len(), "installed admin SSH keys");
    }
    // Always enforce what sshd's StrictModes and SELinux expect, even if an
    // earlier boot left the file with the wrong owner or label.
    let ssh = home.join(".ssh");
    let steps: [(&str, Vec<String>); 3] = [
        (
            "chown",
            vec!["-R".into(), "admin:admin".into(), ssh.display().to_string()],
        ),
        ("chmod", vec!["0600".into(), p.display().to_string()]),
        ("restorecon", vec!["-R".into(), ssh.display().to_string()]),
    ];
    for (cmd, args) in steps {
        let ok = std::process::Command::new(cmd)
            .args(&args)
            .status()
            .is_ok_and(|s| s.success());
        if !ok && cmd != "restorecon" {
            tracing::error!(cmd, path = %p.display(), "cannot fix authorized_keys");
        }
    }
}

/// Bind a root-only Unix socket, replacing a stale one.
fn root_only(socket: &Path) -> Result<std::os::unix::net::UnixListener, String> {
    let _ = std::fs::remove_file(socket);
    std::os::unix::net::UnixListener::bind(socket)
        .and_then(|l| {
            std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
            l.set_nonblocking(true)?;
            Ok(l)
        })
        .map_err(|e| format!("{}: {e}", socket.display()))
}

/// Bind the restricted socket: open to every local user, since each call
/// on it needs a token (SELinux decides which domains may connect).
fn api_listener(socket: &Path) -> std::io::Result<tokio::net::UnixListener> {
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(socket);
    let l = std::os::unix::net::UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666))?;
    l.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(l)
}

fn listener(socket: &Path) -> std::io::Result<tokio::net::UnixListener> {
    let mut fds = listenfd::ListenFd::from_env();
    let std_listener = match fds.take_unix_listener(0)? {
        Some(l) => {
            tracing::info!("using socket-activated listener");
            l
        }
        None => {
            if let Some(dir) = socket.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let _ = std::fs::remove_file(socket);
            let l = std::os::unix::net::UnixListener::bind(socket)?;
            std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
            tracing::info!(path = %socket.display(), "listening");
            l
        }
    };
    std_listener.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(std_listener)
}

/// Revert expired confirm windows and feed the watchdog.
async fn ticker(core: Core, events: broadcast::Sender<Value>) {
    let watchdog = sd_notify::watchdog_enabled().is_some();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        let now = jiff::Timestamp::now().as_second();
        if let Err(e) = with_core(&core, &events, move |c| c.tick(now)).await {
            tracing::error!(error = %e, "confirm-window check failed");
        }
        if watchdog {
            let _ = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]);
        }
    }
}

fn main() -> std::process::ExitCode {
    init_logging();
    let args = Args::parse();
    match run(args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            eprintln!("sparewalld: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), String> {
    if let Some(id) = &args.run {
        return sparewall_core::linux::run_spooled(id).map_err(|e| e.to_string());
    }
    let store = Store::open(&args.state).map_err(|e| e.to_string())?;
    let identity = loop {
        match load_identity(&store, &args)? {
            Some(id) => break id,
            None if args.early => {
                tracing::warn!("no node identity yet; nothing to install");
                return Ok(());
            }
            None => {
                // Without an identity there is no management port to bring
                // up. Wait for one (`sparewall init` on the console).
                tracing::error!(
                    "no node identity: supply the {IDENTITY_CREDENTIAL} credential or run `sparewall init` on the console"
                );
                let _ = sd_notify::notify(&[sd_notify::NotifyState::Status(
                    "waiting for a node identity (sparewall init)",
                )]);
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    };
    let sys: Box<dyn System> = if args.fake_system {
        Box::new(sparewall_core::system::Fake::default())
    } else {
        Box::new(sparewall_core::linux::Linux::default())
    };
    // Not in early boot: the admin account and its home are created by
    // systemd-sysusers and systemd-tmpfiles, which may not have run yet.
    if !args.fake_system && !args.early {
        install_ssh_keys(Path::new(ADMIN_HOME), &identity);
    }
    let node = identity.node.clone();
    let mut coordinator = Coordinator::new(store, sys, identity);
    let rules = (!args.early).then(|| rules::bind(&args.socket.with_file_name("rules.sock")));
    let active = coordinator.boot(args.early).map_err(|e| e.to_string())?;
    tracing::info!(
        generation = active,
        early = args.early,
        "configuration installed"
    );
    if args.early {
        return Ok(());
    }
    // A failover this coordinator was making when it stopped is over.
    if !args.fake_system
        && let Err(e) = failover::Yield::default().clear()
    {
        tracing::error!("failover: {e}");
    }
    if let Err(e) = coordinator.apply_hostname() {
        tracing::error!(error = %e, "cannot set the hostname");
    }
    // The admin password: a seeded one is stored first, then whatever the
    // secret holds is set (again: a restore or reinstall brings it back).
    if let Err(e) = coordinator
        .seed_admin_password()
        .and_then(|()| coordinator.apply_admin_password())
    {
        tracing::error!(error = %e, "cannot set the admin password");
    }

    let core: Core = Arc::new(Mutex::new(coordinator));
    let (tx, _) = broadcast::channel::<Value>(256);
    let pair: peer::Pair = Default::default();
    let wake = Arc::new(tokio::sync::Notify::new());
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let motd = args
        .motd
        .clone()
        .or_else(|| (!args.fake_system).then(|| PathBuf::from(motd::PATH)));
    rt.block_on(async move {
        // Publish anything boot did (a revert of an unconfirmed change).
        let _ = with_core(&core, &tx, |_| Ok(())).await;
        let l = listener(&args.socket).map_err(|e| format!("socket: {e}"))?;
        let changes = service::Changes::default();
        let firewall = Firewall::new(
            core.clone(),
            tx.clone(),
            pair.clone(),
            wake.clone(),
            changes.clone(),
        );
        let server = varlink::serve(l, {
            let f = firewall.clone();
            move || f.clone()
        });
        // keepalived's health check, on a socket of its own (see
        // HEALTH_SOCKET).
        let health_socket = args.socket.with_file_name("org.sparewall.Health");
        let health_server = varlink::serve(
            tokio::net::UnixListener::from_std(root_only(&health_socket)?)
                .map_err(|e| e.to_string())?,
            {
                let f = firewall.clone();
                move || f.clone()
            },
        );
        // The restricted socket: each connection gets a session of its own.
        let api_server = async {
            let l = match api_listener(&args.api_socket) {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(path = %args.api_socket.display(), error = %e, "restricted socket unavailable");
                    return std::future::pending().await;
                }
            };
            let state = args.state.clone();
            varlink::serve(l, move || {
                let session = access::Session::default();
                access::Guard::new(firewall.restricted(session.clone()), session, state.clone())
            })
            .await
        };
        // The peer service, reached only through the sync-tunnel listener.
        let peer_socket = args.socket.with_file_name("org.sparewall.Peer");
        let peer_server = zlink::Server::new(
            zlink::tokio::unix::Listener::from(
                tokio::net::UnixListener::from_std(root_only(&peer_socket)?)
                    .map_err(|e| e.to_string())?,
            ),
            peer::PeerService::new(core.clone(), tx.clone(), wake.clone(), pair.clone(), changes),
        );
        let fifo = if args.fake_system {
            args.socket.with_file_name("keepalived.fifo")
        } else {
            std::path::PathBuf::from(sparewall_render::keepalived::FIFO)
        };
        if !args.fake_system {
            tokio::task::spawn_blocking(service::lookup_booted_image);
        }
        let _ = sd_notify::notify(&[
            sd_notify::NotifyState::Ready,
            sd_notify::NotifyState::Status("running"),
        ]);
        let https = async {
            if args.https == "off" {
                return std::future::pending::<()>().await;
            }
            let setup = async {
                let cert = http::self_signed(&args.state.join("tls"), &node)?;
                let _ = http::FINGERPRINT.set(cert.fingerprint());
                let tls = Arc::new(http::Tls::new(&cert)?);
                let l = tokio::net::TcpListener::bind(&args.https)
                    .await
                    .map_err(|e| format!("{}: {e}", args.https))?;
                tracing::info!(addr = %args.https, "serving HTTPS");
                Ok::<_, String>((l, tls))
            };
            match setup.await {
                Ok((l, tls)) => {
                    tokio::join!(
                        http::serve(
                            l,
                            tls.clone(),
                            core.clone(),
                            tx.clone(),
                            args.web_socket.clone()
                        ),
                        acme::acme_loop(core.clone(), tx.clone(), pair.clone(), tls),
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "health endpoints unavailable");
                    std::future::pending::<()>().await
                }
            }
        };
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| e.to_string())?;
        tokio::select! {
            r = server => r.map_err(|e| format!("varlink server: {e}")),
            () = ticker(core.clone(), tx.clone()) => Ok(()),
            () = async {
                if args.fake_system {
                    std::future::pending::<()>().await
                }
                backup::schedule_loop(core.clone(), tx.clone()).await
            } => Ok(()),
            () = dhcp_ha::takeover_loop(core.clone(), tx.clone(), pair.clone()) => Ok(()),
            () = https => Ok(()),
            r = peer_server.run() => r.map_err(|e| format!("peer server: {e}")),
            r = health_server => r.map_err(|e| format!("health server: {e}")),
            r = api_server => r.map_err(|e| format!("restricted socket: {e}")),
            () = peer::listener(
                core.clone(),
                tx.clone(),
                peer_socket.clone(),
                // A fake system has no tunnel interface (the tests put
                // both nodes' tunnel addresses on lo).
                (!args.fake_system)
                    .then(|| sparewall_config::topology::SYNC_TUNNEL_IFACE.to_string()),
            ) => Ok(()),
            () = peer::sync_loop(core.clone(), tx.clone(), pair.clone(), wake.clone()) => Ok(()),
            () = async {
                if args.fake_system {
                    std::future::pending::<()>().await
                }
                let creds = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
                seed::seed_loop(core.clone(), tx.clone(), args.state.clone(), seed::sources(creds.as_deref())).await
            } => Ok(()),
            () = async {
                // A fake system has no networks to probe.
                if args.fake_system {
                    std::future::pending::<()>().await
                }
                reach::probe_loop(core.clone(), tx.clone(), pair.clone()).await
            } => Ok(()),
            () = async {
                // A fake system has no links.
                if args.fake_system {
                    std::future::pending::<()>().await
                }
                lease::lease_loop(core.clone(), tx.clone(), pair.clone()).await
            } => Ok(()),
            () = async {
                // A fake system has no audit stream of its own.
                if args.fake_system {
                    std::future::pending::<()>().await
                }
                selinux::watch(core.clone(), tx.clone()).await
            } => Ok(()),
            () = async {
                match &motd {
                    Some(path) => motd::motd_loop(core.clone(), tx.clone(), pair.clone(), path.clone()).await,
                    None => std::future::pending::<()>().await,
                }
            } => Ok(()),
            () = vrrp::fifo_reader(pair.clone(), tx.clone(), fifo.clone(), vrrp::host_conntrackd()) => Ok(()),
            () = rules::listener(rules.flatten()) => Ok(()),
            _ = term.recv() => {
                tracing::info!("terminating");
                if let Some(path) = &motd {
                    motd::remove(path);
                }
                Ok(())
            }
            _ = tokio::signal::ctrl_c() => Ok(()),
        }
    })
}
