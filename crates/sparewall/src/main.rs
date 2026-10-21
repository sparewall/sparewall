//! sparewall: the command-line client for the Sparewall coordinator.

mod conn;

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use futures_util::{StreamExt, pin_mut};
use serde_json::{Value, json};
use sparewall_api::{
    ApplyReply, AuthProxy, ClusterProxy, FirewallError, FirewallProxy, Generation, SecretsProxy,
    UpgradeProxy, VpnProxy,
};
use sparewall_config::{Format, path};

use crate::conn::{Context, Contexts, Target};

/// A failure with its exit code.
#[derive(Debug)]
pub struct Fail {
    code: u8,
    message: String,
}

impl Fail {
    pub fn other(m: impl Into<String>) -> Self {
        Fail {
            code: 1,
            message: m.into(),
        }
    }
    pub fn usage(m: impl Into<String>) -> Self {
        Fail {
            code: 2,
            message: m.into(),
        }
    }
    pub fn invalid(m: impl Into<String>) -> Self {
        Fail {
            code: 3,
            message: m.into(),
        }
    }
    pub fn unreachable(m: impl Into<String>) -> Self {
        Fail {
            code: 5,
            message: m.into(),
        }
    }
}

impl From<zlink::Error> for Fail {
    fn from(e: zlink::Error) -> Self {
        Fail::unreachable(format!("connection: {e}"))
    }
}

impl From<FirewallError> for Fail {
    fn from(e: FirewallError) -> Self {
        let code = match e {
            FirewallError::ValidationFailed { .. } => 3,
            FirewallError::Conflict { .. } => 4,
            FirewallError::PeerUnreachable { .. } => 5,
            FirewallError::PermissionDenied { .. } => 6,
            _ => 1,
        };
        Fail {
            code,
            message: e.to_string(),
        }
    }
}

impl From<sparewall_config::Error> for Fail {
    fn from(e: sparewall_config::Error) -> Self {
        Fail::invalid(e.to_string())
    }
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq)]
enum Output {
    Yaml,
    Json,
    Table,
}

#[derive(Parser)]
#[command(
    name = "sparewall",
    version = sparewall_core::VERSION,
    about = "Manage a Sparewall firewall",
    after_help = "Exit codes: 0 ok, 1 error, 2 usage, 3 validation failed, 4 conflict, 5 unreachable"
)]
struct Cli {
    /// Coordinator socket (local use) [default: /run/sparewall/org.sparewall.Firewall].
    #[arg(long, global = true, env = "SPAREWALL_SOCKET")]
    socket: Option<PathBuf>,
    /// Reach a node over SSH (`user@host`), running `sparewall bridge` there.
    #[arg(short = 'H', long, global = true, env = "SPAREWALL_HOST")]
    host: Option<String>,
    /// Use a named context from ~/.config/sparewall/contexts.yaml.
    #[arg(short = 'c', long, global = true, env = "SPAREWALL_CONTEXT")]
    context: Option<String>,
    /// Output format.
    #[arg(short = 'o', long, global = true, value_enum)]
    output: Option<Output>,
    /// Print nothing but errors.
    #[arg(short, long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args, Clone)]
struct ChangeOpts {
    /// Revert unless confirmed within this many seconds (0: no window).
    /// Default 120 over SSH, 0 locally.
    #[arg(long)]
    confirm: Option<u32>,
    /// Validate and show the diff without applying.
    #[arg(long)]
    dry_run: bool,
    /// Don't ask whether to keep the change; leave it pending.
    #[arg(long)]
    no_prompt: bool,
    /// In a pair, accept the change even though the peer is unreachable
    /// (the pair is then diverged until `sparewall sync`).
    #[arg(long)]
    allow_diverge: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the document or a subtree.
    Get {
        path: Option<String>,
        /// Read an older generation.
        #[arg(long)]
        generation: Option<i64>,
    },
    /// Set values by path in one change: `networks.users.vlan=20`.
    Set {
        #[arg(required = true)]
        assignments: Vec<String>,
        #[command(flatten)]
        change: ChangeOpts,
    },
    /// Remove keys or map entries.
    Unset {
        #[arg(required = true)]
        paths: Vec<String>,
        #[command(flatten)]
        change: ChangeOpts,
    },
    /// Merge a partial document (JSON Merge Patch).
    Merge {
        #[arg(short, long)]
        file: String,
        #[command(flatten)]
        change: ChangeOpts,
    },
    /// Apply a whole document, replacing the current one.
    Apply {
        #[arg(short, long)]
        file: String,
        #[command(flatten)]
        change: ChangeOpts,
    },
    /// Apply RFC 6902 JSON Patch operations.
    Patch {
        #[arg(long = "type", default_value = "json")]
        kind: String,
        #[arg(short, long)]
        file: String,
        #[command(flatten)]
        change: ChangeOpts,
    },
    /// Show what a merge (or, with --replace, an apply) would change.
    Diff {
        #[arg(short, long)]
        file: String,
        #[arg(long)]
        replace: bool,
    },
    /// Edit the document or a subtree in $EDITOR; validate and apply on save.
    Edit {
        path: Option<String>,
        #[command(flatten)]
        change: ChangeOpts,
    },
    /// Describe a field from the schema.
    Explain { path: Option<String> },
    /// Validate a document without applying it.
    Validate {
        #[arg(short, long)]
        file: String,
    },
    /// Node, generation, links and health.
    Status,
    /// Health level and checks.
    Health {
        #[arg(short, long)]
        verbose: bool,
        #[command(subcommand)]
        cmd: Option<HealthCmd>,
    },
    /// List generations.
    History {
        #[arg(short = 'n', long)]
        limit: Option<i64>,
    },
    /// Keep a change that is waiting for confirmation.
    Confirm { id: Option<i64> },
    /// Return to a generation (default: the previous one).
    Rollback {
        id: Option<i64>,
        /// In a pair, roll back even though the peer is unreachable (the
        /// pair is then diverged until `sparewall sync`).
        #[arg(long)]
        allow_diverge: bool,
    },
    /// Resolve a diverged pair by taking one node's configuration.
    Sync {
        #[arg(long = "from")]
        from_node: String,
    },
    /// Print the canonical document.
    Export {
        #[arg(long)]
        generation: Option<i64>,
    },
    /// Write a backup bundle.
    Backup,
    /// Stream coordinator events.
    Events,
    /// Schema operations.
    #[command(subcommand)]
    Schema(SchemaCmd),
    /// The write-only secret store.
    #[command(subcommand)]
    Secret(SecretCmd),
    /// Set the `admin` account's console password on every node of the
    /// cluster (hashed here; only the hash is sent). SSH stays keys-only.
    Passwd {
        /// Remove the password: the account takes SSH keys only again.
        #[arg(long)]
        lock: bool,
    },
    /// Remote-access VPN.
    #[command(subcommand)]
    Vpn(VpnCmd),
    /// API tokens for scripts, monitoring and front ends.
    #[command(subcommand)]
    Token(TokenCmd),
    /// Manage named contexts (deployments reached over SSH).
    #[command(subcommand)]
    Context(ContextCmd),
    /// Record this node's install-time identity, and optionally a first
    /// configuration it applies by itself (run on the node as root).
    Init {
        /// Node name, e.g. fw1.
        #[arg(long, required_unless_present_any = ["from", "config"])]
        node: Option<String>,
        /// Management NIC: permanent MAC address or udev path.
        #[arg(long, required_unless_present_any = ["from", "config"])]
        mgmt_nic: Option<String>,
        #[arg(long)]
        mgmt_vlan: Option<u16>,
        /// Static management address (CIDR); default DHCP.
        #[arg(long)]
        mgmt_address: Option<String>,
        #[arg(long)]
        mgmt_gateway: Option<String>,
        /// Admin SSH public key (repeatable).
        #[arg(long = "ssh-key")]
        ssh_keys: Vec<String>,
        /// Take the whole identity from a JSON or YAML file instead (as on
        /// a seed stick).
        #[arg(long, value_name = "FILE", conflicts_with_all = ["node", "mgmt_nic", "mgmt_vlan", "mgmt_address", "mgmt_gateway", "ssh_keys"])]
        from: Option<PathBuf>,
        /// Where to write the identity.
        #[arg(long, default_value = "/etc/sparewall/identity.json")]
        out: PathBuf,
        /// A configuration document for the node to apply by itself while
        /// it is in bootstrap mode, confirming it once healthy.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Where to write the configuration.
        #[arg(long, default_value = "/etc/sparewall/config.json")]
        config_out: PathBuf,
    },
    /// Restore a backup bundle into the state directory (on the node, as
    /// root, with sparewalld stopped).
    Restore {
        /// The bundle.
        #[arg(short, long, required_unless_present = "repository")]
        file: Option<PathBuf>,
        /// Fetch the newest bundle of `--node` from this restic repository
        /// (repository credentials come from the environment, as for restic).
        #[arg(long, conflicts_with = "file")]
        repository: Option<String>,
        /// The node whose bundle to fetch (default: this node's name).
        #[arg(long, requires = "repository")]
        node: Option<String>,
        /// A file holding the backup password (default: a prompt).
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Restore without the cluster secrets.
        #[arg(long, conflicts_with = "password_file")]
        no_secrets: bool,
        /// Encrypt secrets as `sparewalld --fake-system` does (tests).
        #[arg(long, hide = true)]
        fake_system: bool,
        #[arg(long, default_value = "/var/lib/sparewall")]
        state: PathBuf,
        /// Where Kea's lease file goes.
        #[arg(
            long,
            default_value = "/var/lib/containers/storage/volumes/sparewall-kea-leases/_data/kea-leases4.csv"
        )]
        leases: PathBuf,
    },
    /// Generate shell completions.
    Completion { shell: clap_complete::Shell },
    /// Connect stdin/stdout to the local socket (used over SSH).
    #[command(hide = true)]
    Bridge,
    /// Move a pair's gateway addresses to one node (from either node).
    ///
    /// The pair never fails back by itself (nopreempt), so after both nodes
    /// restart, or a node is replaced, the smaller one may stay master.
    /// This hands the addresses over, as for a failed node, if the target
    /// is the backup, healthy, in sync and not held.
    Failover {
        /// The node to move them to; default the one with the higher VRRP
        /// priority.
        #[arg(long, value_name = "NODE")]
        to: Option<String>,
    },
    /// Rolling, health-gated OS upgrade (the master of a pair runs it).
    Upgrade {
        /// stable or testing; default the document's updates.channel.
        #[arg(long, conflicts_with = "image")]
        channel: Option<String>,
        /// A full image reference instead of a channel (a mirror, a pinned build).
        #[arg(long)]
        image: Option<String>,
        /// Only report whether a newer image is available.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand)]
enum SchemaCmd {
    /// Print the JSON Schema.
    Show,
    /// Migrate the document to the newest schema.
    Upgrade,
    /// Migrate the document to the previous schema.
    Downgrade,
}

#[derive(Subcommand)]
enum HealthCmd {
    /// Acknowledge a check that stays degraded until someone has seen it
    /// (selinux: denials for the coordinator).
    Ack { check: String },
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Store a secret, read from stdin (or a prompt). It cannot be read back.
    Set {
        name: String,
        /// Keep it on this node only instead of sharing it with the peer.
        #[arg(long)]
        node: bool,
    },
    /// List secret names and versions.
    List,
    /// Remove a secret.
    Delete { name: String },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Create a token; it is printed once.
    Create {
        name: String,
        /// monitor, viewer, operator or admin.
        #[arg(long, default_value = "viewer")]
        role: String,
        /// Lifetime, e.g. 90d (days).
        #[arg(long)]
        expires: Option<String>,
    },
    /// List tokens (never their values).
    List,
    /// Revoke a token at once.
    Revoke { name: String },
}

#[derive(Subcommand)]
enum VpnCmd {
    /// Print a WireGuard client configuration (and a QR code with
    /// --qr, using qrencode) for one peer.
    ClientConfig {
        peer: String,
        #[arg(long)]
        instance: Option<String>,
        /// Connect on this port instead of the listen port: one of the
        /// instance's `extra_ports`, for networks that block the other.
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        qr: bool,
    },
}

#[derive(Subcommand)]
enum ContextCmd {
    /// Add or replace a context.
    Add {
        name: String,
        /// SSH destination, e.g. admin@fw1.
        #[arg(long)]
        host: String,
        #[arg(long)]
        remote_command: Option<String>,
    },
    /// Make a context the default.
    Use { name: String },
    /// List contexts.
    List,
    /// Remove a context.
    Remove { name: String },
}

struct App {
    target: Target,
    output: Option<Output>,
    quiet: bool,
}

fn read_input(file: &str) -> Result<Value, Fail> {
    let text = if file == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| Fail::other(e.to_string()))?;
        s
    } else {
        std::fs::read_to_string(file).map_err(|e| Fail::usage(format!("{file}: {e}")))?
    };
    let format = Format::detect((file != "-").then_some(file), &text);
    Ok(sparewall_config::parse_value(&text, format)?)
}

/// This node's name, from the identity sparewalld recorded.
fn local_node(state: &Path) -> Result<String, Fail> {
    let p = state.join("identity.json");
    let v: serde_json::Value = std::fs::read(&p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| Fail::usage(format!("{}: no identity; pass --node", p.display())))?;
    v["node"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| Fail::usage("the identity names no node; pass --node"))
}

/// The newest bundle of `node` from a restic repository.
fn fetch_bundle(
    repository: &str,
    node: &str,
    password: Option<&str>,
) -> Result<tempfile::NamedTempFile, Fail> {
    let out = tempfile::NamedTempFile::new().map_err(|e| Fail::other(e.to_string()))?;
    let mut cmd = std::process::Command::new("restic");
    cmd.args([
        "-r",
        repository,
        "dump",
        "--host",
        node,
        "--tag",
        "sparewall",
        "latest",
    ])
    .arg(format!("/sparewall-{node}.tar.gz"))
    .stdout(out.reopen().map_err(|e| Fail::other(e.to_string()))?);
    if let Some(pw) = password {
        cmd.env("RESTIC_PASSWORD", pw);
    }
    let st = cmd
        .status()
        .map_err(|e| Fail::other(format!("restic: {e}")))?;
    if !st.success() {
        return Err(Fail::other(format!(
            "restic could not fetch the newest bundle of {node} from {repository}"
        )));
    }
    Ok(out)
}

/// A new password: asked twice without echo on a terminal, or read from
/// stdin.
fn read_new_password() -> Result<String, Fail> {
    if !std::io::stdin().is_terminal() {
        return read_secret("the admin password");
    }
    let first = read_secret("the new admin password")?;
    let again = read_secret("the new admin password again")?;
    if first != again {
        return Err(Fail::usage("the passwords do not match"));
    }
    Ok(first)
}

/// A SHA-512 crypt(3) hash, as shadow holds it. The salt is 16
/// characters, the most crypt(3) uses: a longer one would be cut short
/// when PAM re-hashes the password, and never match.
fn hash_password(password: &str) -> Result<String, Fail> {
    use sha_crypt::password_hash::CustomizedPasswordHasher;
    let mut salt = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|e| Fail::other(format!("random salt: {e}")))?;
    sha_crypt::ShaCrypt::SHA512
        .hash_password_customized(
            password.as_bytes(),
            &salt,
            None,
            None,
            sha_crypt::Params::RECOMMENDED,
        )
        .map(|h| h.to_string())
        .map_err(|e| Fail::other(format!("hashing the password: {e}")))
}

/// A secret from stdin, or a prompt without echo on a terminal.
fn read_secret(name: &str) -> Result<String, Fail> {
    let tty = std::io::stdin().is_terminal();
    if tty {
        eprint!("Value for {name}: ");
        let _ = std::process::Command::new("stty").arg("-echo").status();
    }
    let mut s = String::new();
    let r = if tty {
        std::io::stdin().read_line(&mut s).map(|_| ())
    } else {
        std::io::stdin().read_to_string(&mut s).map(|_| ())
    };
    if tty {
        let _ = std::process::Command::new("stty").arg("echo").status();
        eprintln!();
    }
    r.map_err(|e| Fail::other(e.to_string()))?;
    let v = s.strip_suffix('\n').unwrap_or(&s).to_string();
    if v.is_empty() {
        return Err(Fail::usage("empty secret"));
    }
    Ok(v)
}

fn print_value(v: &Value, output: Option<Output>) {
    match output {
        Some(Output::Json) => print!("{}", sparewall_config::format_value(v, Format::Json)),
        _ => match v {
            Value::String(s) => println!("{s}"),
            Value::Number(_) | Value::Bool(_) | Value::Null => println!("{v}"),
            _ => print!("{}", sparewall_config::format_value(v, Format::Yaml)),
        },
    }
}

fn short_hash(h: &str) -> &str {
    &h[..h.len().min(12)]
}

fn generation_line(g: &Generation) -> String {
    format!(
        "{:>5}  {:<12}  {:<20}  {:<9}  {}",
        g.id,
        short_hash(&g.hash),
        g.applied
            .split('.')
            .next()
            .unwrap_or(&g.applied)
            .replace('T', " "),
        if g.confirmed { "confirmed" } else { "pending" },
        g.author
    )
}

/// The hash the node gives the document a change request produces from
/// `config` (the active document), or None where the CLI cannot tell.
fn expected_hash(kind: &str, mut config: Value, body: &Value) -> Option<String> {
    match kind {
        "apply" => config = body.clone(),
        "merge" => sparewall_config::merge_patch(&mut config, body),
        "patch" => sparewall_config::json_patch(&mut config, body).ok()?,
        _ => return None,
    }
    sparewall_config::from_value(config)
        .ok()
        .map(|d| sparewall_config::hash(&d))
}

/// How long to keep reconnecting after a change cut the connection.
const RECONNECT_SECONDS: u64 = 60;

impl App {
    async fn conn(&self) -> Result<zlink::Connection<zlink::tokio::unix::Stream>, Fail> {
        conn::connect(&self.target).await
    }

    fn say(&self, s: impl AsRef<str>) {
        if !self.quiet {
            eprintln!("{}", s.as_ref());
        }
    }

    fn default_confirm(&self, c: &ChangeOpts) -> u32 {
        c.confirm.unwrap_or_else(|| {
            if self.target.is_remote() || std::env::var_os("SSH_CONNECTION").is_some() {
                120
            } else {
                0
            }
        })
    }

    async fn current(&self) -> Result<(Value, Generation), Fail> {
        let r = self.conn().await?.get_config(None).await??;
        Ok((r.config, r.generation))
    }

    /// Send a mutation and handle the confirm window.
    async fn change(&self, c: &ChangeOpts, kind: &str, body: Value) -> Result<(), Fail> {
        let (config, current) = self.current().await?;
        let window = if c.dry_run {
            None
        } else {
            Some(i64::from(self.default_confirm(c)))
        };
        let mut conn = self.conn().await?;
        let dry = Some(c.dry_run);
        let div = Some(c.allow_diverge);
        let sent = match kind {
            "apply" => conn.apply(&body, current.id, window, dry, div).await,
            "merge" => conn.merge(&body, current.id, window, dry, div).await,
            "patch" => conn.patch(&body, current.id, window, dry, div).await,
            _ => unreachable!(),
        };
        drop(conn);
        match sent {
            Ok(r) => self.report(&r?, c).await,
            // The connection went down with the change in flight: it may
            // have cut itself off (the first apply renames the management
            // port), and is then pending on the node.
            Err(e) if self.target.is_remote() && window.is_some_and(|w| w > 0) => {
                let expected = expected_hash(kind, config, &body);
                self.recover(e, &current, expected, c).await
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Reconnect after losing the connection mid-change, and find out
    /// whether the change is pending on the node. A generation found
    /// there is this change only if it extends `before` with the document
    /// the request produces (`expected`, its hash).
    async fn recover(
        &self,
        e: zlink::Error,
        before: &Generation,
        expected: Option<String>,
        c: &ChangeOpts,
    ) -> Result<(), Fail> {
        self.say(format!(
            "The connection was lost after the change was sent ({e}); reconnecting..."
        ));
        let lost = |m: String| {
            Fail::unreachable(format!(
                "{m}; the change may be pending on the node: reconnect, check \
                 `sparewall status` and `sparewall history`, and run \
                 `sparewall confirm <generation>` before it reverts"
            ))
        };
        let deadline = Instant::now() + Duration::from_secs(RECONNECT_SECONDS);
        let (s, mut conn) = loop {
            // Over SSH, a node that is not back yet fails the call, not
            // the connect.
            if let Ok(mut conn) = self.conn().await {
                match conn.status().await {
                    Ok(Ok(s)) => break (s, conn),
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => {}
                }
            }
            if Instant::now() >= deadline {
                return Err(lost(format!(
                    "could not reconnect within {RECONNECT_SECONDS}s"
                )));
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        };
        let active = s.sync["active"].as_i64().unwrap_or(0);
        let pending = s
            .sync
            .get("pending")
            .filter(|p| !p.is_null())
            .and_then(|p| Some((p["id"].as_i64()?, p["reverts_in"].as_u64()?)));
        let Some(expected) = expected else {
            return Err(lost(
                "reconnected, but cannot tell which change is this one".into(),
            ));
        };
        if expected == before.hash && pending.is_none() && active == before.id {
            self.say("Reconnected: the node already had this configuration.");
            return Ok(());
        }
        let candidate = match pending {
            Some((id, _)) if id > before.id => id,
            _ if active > before.id => active,
            _ => {
                return Err(Fail::other(format!(
                    "reconnected, but the change did not take effect: generation {active} is active"
                )));
            }
        };
        let g = conn.get_config(Some(candidate)).await??.generation;
        if g.base != Some(before.id) || g.hash != expected {
            return Err(lost(format!(
                "reconnected, but generation {candidate} is not this change (another \
                 change was made meanwhile?)"
            )));
        }
        drop(conn);
        match pending {
            Some((id, reverts_in)) if id == candidate => {
                self.keep(id, reverts_in, "Reconnected: generation", c)
                    .await
            }
            _ => {
                self.say(format!("Reconnected: generation {candidate} is active."));
                Ok(())
            }
        }
    }

    async fn report(&self, r: &ApplyReply, c: &ChangeOpts) -> Result<(), Fail> {
        if self.output == Some(Output::Json) {
            print_value(
                &serde_json::to_value(r).unwrap_or_default(),
                Some(Output::Json),
            );
        }
        for w in &r.warnings {
            self.say(format!("warning: {w}"));
        }
        if r.unchanged {
            self.say(format!(
                "No change: generation {} already has this configuration.",
                r.generation.id
            ));
            return Ok(());
        }
        if self.output != Some(Output::Json) && !self.quiet {
            for line in &r.diff {
                println!("{line}");
            }
        }
        if c.dry_run {
            self.say(format!(
                "Dry run: valid; would create generation {} (changes: {}).",
                r.generation.id,
                r.changed.join(", ")
            ));
            return Ok(());
        }
        let id = r.generation.id;
        if r.confirm_seconds == 0 {
            self.say(format!(
                "Applied generation {id} (changes: {}).",
                r.changed.join(", ")
            ));
            return Ok(());
        }
        self.keep(id, r.confirm_seconds.max(0) as u64, "Applied generation", c)
            .await
    }

    /// Generation ID is pending: ask whether to keep it, or say how to.
    async fn keep(&self, id: i64, seconds: u64, what: &str, c: &ChangeOpts) -> Result<(), Fail> {
        let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
        if c.no_prompt || !interactive || self.quiet {
            self.say(format!(
                "{what} {id}; it reverts in {seconds}s unless you run `sparewall confirm {id}`."
            ));
            return Ok(());
        }
        eprint!("{what} {id}. Keep it? It reverts in {seconds}s otherwise. [y/N] ");
        let _ = std::io::stderr().flush();
        let answer = tokio::time::timeout(
            Duration::from_secs(seconds.max(1)),
            tokio::task::spawn_blocking(|| {
                let mut s = String::new();
                let _ = std::io::stdin().read_line(&mut s);
                s
            }),
        )
        .await;
        match answer {
            Ok(Ok(s))
                if s.trim().eq_ignore_ascii_case("y") || s.trim().eq_ignore_ascii_case("yes") =>
            {
                // A fresh connection proves the node is still reachable.
                self.conn().await?.confirm(id).await??;
                self.say(format!("Confirmed generation {id}."));
                Ok(())
            }
            Ok(_) => {
                let g = self.conn().await?.rollback(None, None).await??;
                self.say(format!("Rolled back to generation {}.", g.generation.id));
                Ok(())
            }
            Err(_) => {
                eprintln!();
                Err(Fail::other(format!(
                    "not confirmed in time; generation {id} has been reverted"
                )))
            }
        }
    }

    async fn run(&self, cmd: Cmd) -> Result<(), Fail> {
        match cmd {
            Cmd::Get {
                path: p,
                generation,
            } => {
                let r = self.conn().await?.get_config(generation).await??;
                let segs = path::parse_path(p.as_deref().unwrap_or(""))?;
                let v = path::get(&r.config, &segs)
                    .ok_or_else(|| Fail::usage(format!("{} is not set", p.unwrap_or_default())))?;
                print_value(v, self.output);
            }
            Cmd::Set {
                assignments,
                change,
            } => {
                let mut patches = Vec::new();
                for a in &assignments {
                    let (segs, v) = path::parse_assignment(a)?;
                    patches.push(path::set_patch(&segs, v)?);
                }
                self.change(&change, "merge", path::combine(patches))
                    .await?;
            }
            Cmd::Unset { paths, change } => {
                let (doc, _) = self.current().await?;
                let mut patches = Vec::new();
                for p in &paths {
                    let segs = path::parse_path(p)?;
                    if path::get(&doc, &segs).is_none() {
                        return Err(Fail::usage(format!("{p} is not set")));
                    }
                    patches.push(path::unset_patch(&segs)?);
                }
                self.change(&change, "merge", path::combine(patches))
                    .await?;
            }
            Cmd::Merge { file, change } => {
                self.change(&change, "merge", read_input(&file)?).await?
            }
            Cmd::Apply { file, change } => {
                self.change(&change, "apply", read_input(&file)?).await?
            }
            Cmd::Patch { kind, file, change } => {
                if kind != "json" {
                    return Err(Fail::usage(
                        "only --type json (RFC 6902) is supported; use merge for merge patches",
                    ));
                }
                self.change(&change, "patch", read_input(&file)?).await?;
            }
            Cmd::Diff { file, replace } => {
                let c = ChangeOpts {
                    confirm: None,
                    dry_run: true,
                    no_prompt: true,
                    allow_diverge: true,
                };
                self.change(
                    &c,
                    if replace { "apply" } else { "merge" },
                    read_input(&file)?,
                )
                .await?;
            }
            Cmd::Edit { path: p, change } => self.edit(p, change).await?,
            Cmd::Explain { path: p } => {
                let segs = path::parse_path(p.as_deref().unwrap_or(""))?;
                let text = sparewall_config::schema::explain(&segs).ok_or_else(|| {
                    Fail::usage(format!("no such field: {}", p.unwrap_or_default()))
                })?;
                print!("{text}");
            }
            Cmd::Validate { file } => {
                let v = read_input(&file)?;
                // Local checks first, for a precise path in the message.
                sparewall_config::from_value(v.clone())?;
                let r = self.conn().await?.validate(&v).await??;
                for w in &r.warnings {
                    self.say(format!("warning: {w}"));
                }
                self.say("valid");
            }
            Cmd::Status => {
                let s = self.conn().await?.status().await??;
                match self.output {
                    Some(Output::Json) | Some(Output::Yaml) => {
                        print_value(&serde_json::to_value(&s).unwrap_or_default(), self.output)
                    }
                    _ => {
                        println!("node:        {}", s.node);
                        println!("role:        {}", s.role);
                        println!("generation:  {}", s.sync["active"]);
                        if let Some(peer) = s.sync["peer"].as_str() {
                            let reach = if s.sync["peer_reachable"].as_bool() == Some(true) {
                                format!("generation {}", s.sync["peer_active"])
                            } else {
                                "unreachable".to_string()
                            };
                            println!(
                                "pair:        {} with {peer} ({reach})",
                                s.sync["state"].as_str().unwrap_or("?")
                            );
                        }
                        if let Some(k) = s.sync["sync_public_key"].as_str() {
                            println!("sync key:    {k}");
                        }
                        if let Some(f) = s.tls["fingerprint"].as_str() {
                            println!("tls:         {f}");
                        }
                        if let Some(p) = s.sync.get("pending").filter(|p| !p.is_null()) {
                            println!(
                                "pending:     generation {} reverts in {}s",
                                p["id"], p["reverts_in"]
                            );
                        }
                        println!(
                            "desired:     {}",
                            short_hash(s.sync["desired_hash"].as_str().unwrap_or(""))
                        );
                        println!(
                            "applied:     {}",
                            short_hash(s.sync["applied_hash"].as_str().unwrap_or("-"))
                        );
                        println!("health:      {}", s.health["level"].as_str().unwrap_or("?"));
                        for c in s.health["checks"].as_array().into_iter().flatten() {
                            println!(
                                "  {:<10} {:<9} {}",
                                c["name"].as_str().unwrap_or(""),
                                c["level"].as_str().unwrap_or(""),
                                c["message"].as_str().unwrap_or("")
                            );
                        }
                        if let Some(ct) = s.conntrack.get("count").filter(|c| !c.is_null()) {
                            println!("conntrack:   {ct} / {}", s.conntrack["max"]);
                        }
                    }
                }
            }
            Cmd::Health {
                cmd: Some(HealthCmd::Ack { check }),
                ..
            } => {
                self.conn().await?.ack_health(&check).await??;
                println!("acknowledged {check}");
            }
            Cmd::Health { verbose, cmd: None } => {
                let h = self.conn().await?.health(Some(verbose)).await??;
                match self.output {
                    Some(Output::Json) | Some(Output::Yaml) => {
                        print_value(&serde_json::to_value(&h).unwrap_or_default(), self.output)
                    }
                    _ => {
                        println!("{} ({})", h.level, h.role);
                        for c in h.checks.iter().flatten() {
                            println!("  {:<10} {:<9} {}", c.name, c.level, c.message);
                        }
                    }
                }
                if h.level == "failed" {
                    return Err(Fail {
                        code: 1,
                        message: String::new(),
                    });
                }
            }
            Cmd::History { limit } => {
                let h = self.conn().await?.history(limit).await??;
                match self.output {
                    Some(Output::Json) | Some(Output::Yaml) => print_value(
                        &serde_json::to_value(&h.generations).unwrap_or_default(),
                        self.output,
                    ),
                    _ => {
                        println!(
                            "{:>5}  {:<12}  {:<20}  {:<9}  AUTHOR",
                            "ID", "HASH", "APPLIED (UTC)", "STATE"
                        );
                        for g in &h.generations {
                            println!("{}", generation_line(g));
                            for s in g.summary.iter().take(5) {
                                println!("       {s}");
                            }
                            if g.summary.len() > 5 {
                                println!("       … {} more", g.summary.len() - 5);
                            }
                        }
                    }
                }
            }
            Cmd::Confirm { id } => {
                let id = match id {
                    Some(i) => i,
                    None => self.current().await?.1.id,
                };
                self.conn().await?.confirm(id).await??;
                self.say(format!("Confirmed generation {id}."));
            }
            Cmd::Rollback { id, allow_diverge } => {
                let g = self
                    .conn()
                    .await?
                    .rollback(id, allow_diverge.then_some(true))
                    .await??;
                self.say(format!("Now running generation {}.", g.generation.id));
            }
            Cmd::Sync { from_node } => {
                let g = self.conn().await?.sync(&from_node).await??;
                self.say(format!("Now running generation {}.", g.generation.id));
            }
            Cmd::Export { generation } => {
                let r = self.conn().await?.export(generation).await??;
                let doc = sparewall_config::from_value(r.config)?;
                let f = if self.output == Some(Output::Json) {
                    Format::Json
                } else {
                    Format::Yaml
                };
                print!("{}", sparewall_config::export(&doc, f));
            }
            Cmd::Backup => {
                let r = self.conn().await?.backup().await??;
                if !self.quiet {
                    println!("{} {}", r.digest, r.path);
                    if let Some(s) = &r.snapshot {
                        eprintln!("Sent to the backup repository as snapshot {s}.");
                    }
                    if r.secrets.is_empty() {
                        eprintln!(
                            "The bundle has no cluster secrets: set a backup password with \
                             `sparewall secret set {}`.",
                            sparewall_core::backup::PASSWORD_SECRET
                        );
                    }
                }
            }
            Cmd::Events => {
                let mut conn = self.conn().await?;
                let stream = conn.subscribe().await?;
                pin_mut!(stream);
                while let Some(item) = stream.next().await {
                    let ev = item??;
                    println!("{}", ev.event);
                }
            }
            Cmd::Secret(SecretCmd::Set { name, node }) => {
                let value = read_secret(&name)?;
                let r = self.conn().await?.set(&name, &value, Some(!node)).await??;
                self.say(format!(
                    "Stored {} (version {}, {}).",
                    r.secret.name, r.secret.version, r.secret.class
                ));
            }
            Cmd::Passwd { lock } => {
                let value = if lock {
                    "!".to_string()
                } else {
                    hash_password(&read_new_password()?)?
                };
                self.conn()
                    .await?
                    .set("admin-password", &value, Some(true))
                    .await??;
                self.say(if lock {
                    "Locked the admin password on this node; the peer follows."
                } else {
                    "Set the admin password on this node; the peer follows."
                });
            }
            Cmd::Secret(SecretCmd::List) => {
                let r = self.conn().await?.list().await??;
                match self.output {
                    Some(Output::Json) | Some(Output::Yaml) => print_value(
                        &serde_json::to_value(&r.secrets).unwrap_or_default(),
                        self.output,
                    ),
                    _ => {
                        println!("{:<32} {:<8} {:>7}  UPDATED", "NAME", "CLASS", "VERSION");
                        for x in &r.secrets {
                            println!(
                                "{:<32} {:<8} {:>7}  {}",
                                x.name, x.class, x.version, x.updated
                            );
                        }
                    }
                }
            }
            Cmd::Secret(SecretCmd::Delete { name }) => {
                self.conn().await?.delete(&name).await??;
                self.say(format!("Deleted {name}."));
            }
            Cmd::Token(TokenCmd::Create {
                name,
                role,
                expires,
            }) => {
                let days = match expires.as_deref() {
                    None => None,
                    Some(e) => Some(
                        e.trim_end_matches('d')
                            .parse::<i64>()
                            .map_err(|_| Fail::usage("--expires takes days, e.g. 90d"))?,
                    ),
                };
                let r = self
                    .conn()
                    .await?
                    .create_token(&name, &role, days)
                    .await??;
                println!("{}", r.token);
                self.say(format!(
                    "Token {} ({}) created. It is shown only once.",
                    r.info.name, r.info.role
                ));
            }
            Cmd::Token(TokenCmd::List) => {
                let r = self.conn().await?.list_tokens().await??;
                match self.output {
                    Some(Output::Json) | Some(Output::Yaml) => print_value(
                        &serde_json::to_value(&r.tokens).unwrap_or_default(),
                        self.output,
                    ),
                    _ => {
                        println!(
                            "{:<24} {:<9} {:<21} LAST USED",
                            "NAME", "ROLE", "EXPIRES (UNIX)"
                        );
                        for t in &r.tokens {
                            println!(
                                "{:<24} {:<9} {:<21} {}",
                                t.name,
                                t.role,
                                t.expires.map_or("never".into(), |e| e.to_string()),
                                t.last_used.as_deref().unwrap_or("-")
                            );
                        }
                    }
                }
            }
            Cmd::Token(TokenCmd::Revoke { name }) => {
                self.conn().await?.revoke_token(&name).await??;
                self.say(format!("Revoked {name}."));
            }
            Cmd::Vpn(VpnCmd::ClientConfig {
                peer,
                instance,
                port,
                qr,
            }) => {
                let r = self
                    .conn()
                    .await?
                    .vpn_client_config(instance.as_deref(), &peer, port.map(i64::from))
                    .await??;
                print!("{}", r.config);
                if qr {
                    let child = std::process::Command::new("qrencode")
                        .args(["-t", "ansiutf8"])
                        .stdin(std::process::Stdio::piped())
                        .spawn();
                    match child {
                        Ok(mut c) => {
                            if let Some(mut i) = c.stdin.take() {
                                let _ = i.write_all(r.config.as_bytes());
                            }
                            let _ = c.wait();
                        }
                        Err(_) => self.say("qrencode is not installed; no QR code."),
                    }
                }
            }
            Cmd::Schema(SchemaCmd::Show) => {
                print!("{}", sparewall_config::schema::json_schema_text())
            }
            Cmd::Schema(_) => {
                return Err(Fail::other(format!(
                    "only schema version {} exists; nothing to migrate",
                    sparewall_config::SCHEMA_VERSION
                )));
            }
            Cmd::Failover { to } => {
                let r = self.conn().await?.failover(to.as_deref()).await??;
                self.say(&r.message);
            }
            Cmd::Upgrade {
                channel,
                image,
                check,
            } => {
                let r = self
                    .conn()
                    .await?
                    .check(channel.as_deref(), image.as_deref())
                    .await??;
                println!("booted:    {}", r.booted.as_deref().unwrap_or("unknown"));
                println!("target:    {}", r.target);
                println!("available: {}", if r.available { "yes" } else { "no" });
                if check {
                    return Ok(());
                }
                let mut events = self.conn().await?;
                let stream = events.subscribe().await?;
                let plan = self
                    .conn()
                    .await?
                    .start(channel.as_deref(), image.as_deref())
                    .await??;
                for (i, step) in plan.plan.iter().enumerate() {
                    println!("{}. {step}", i + 1);
                }
                pin_mut!(stream);
                while let Some(item) = stream.next().await {
                    let Ok(Ok(ev)) = item else { break };
                    if ev.event["type"] == "upgrade" {
                        println!(
                            "[{}] {}",
                            ev.event["step"].as_str().unwrap_or(""),
                            ev.event["detail"].as_str().unwrap_or("")
                        );
                        match ev.event["step"].as_str() {
                            Some("failed") => return Err(Fail::other("upgrade stopped")),
                            Some("reboot" | "done") => break,
                            _ => {}
                        }
                    }
                }
            }
            Cmd::Context(_)
            | Cmd::Init { .. }
            | Cmd::Restore { .. }
            | Cmd::Completion { .. }
            | Cmd::Bridge => {
                unreachable!("handled before connecting")
            }
        }
        Ok(())
    }

    async fn edit(&self, p: Option<String>, change: ChangeOpts) -> Result<(), Fail> {
        let (doc, _) = self.current().await?;
        let segs = path::parse_path(p.as_deref().unwrap_or(""))?;
        let sub = path::get(&doc, &segs)
            .cloned()
            .ok_or_else(|| Fail::usage(format!("{} is not set", p.clone().unwrap_or_default())))?;
        let mut tmp = tempfile::Builder::new()
            .prefix("sparewall-")
            .suffix(".yaml")
            .tempfile()
            .map_err(|e| Fail::other(e.to_string()))?;
        let original = sparewall_config::format_value(&sub, Format::Yaml);
        tmp.write_all(original.as_bytes())
            .map_err(|e| Fail::other(e.to_string()))?;
        let editor = std::env::var("VISUAL")
            .or_else(|_| std::env::var("EDITOR"))
            .unwrap_or_else(|_| "vi".into());
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{editor} \"$1\""))
            .arg("sh")
            .arg(tmp.path())
            .status()
            .map_err(|e| Fail::other(format!("{editor}: {e}")))?;
        if !status.success() {
            return Err(Fail::other("editor exited with an error; nothing applied"));
        }
        let edited = std::fs::read_to_string(tmp.path()).map_err(|e| Fail::other(e.to_string()))?;
        if edited == original {
            self.say("No changes.");
            return Ok(());
        }
        let v = sparewall_config::parse_value(&edited, Format::Yaml)?;
        if segs.is_empty() {
            self.change(&change, "apply", v).await
        } else {
            let pointer: String = segs
                .iter()
                .map(|s| format!("/{}", s.replace('~', "~0").replace('/', "~1")))
                .collect();
            self.change(
                &change,
                "patch",
                json!([{"op": "replace", "path": pointer, "value": v}]),
            )
            .await
        }
    }
}

fn local(cmd: &Cmd) -> Result<bool, Fail> {
    match cmd {
        Cmd::Context(c) => {
            let mut ctxs = Contexts::load()?;
            match c {
                ContextCmd::Add {
                    name,
                    host,
                    remote_command,
                } => {
                    ctxs.contexts.insert(
                        name.clone(),
                        Context {
                            host: Some(host.clone()),
                            remote_command: remote_command.clone(),
                            ssh_options: vec![],
                        },
                    );
                    if ctxs.current.is_none() {
                        ctxs.current = Some(name.clone());
                    }
                    ctxs.save()?;
                }
                ContextCmd::Use { name } => {
                    if !ctxs.contexts.contains_key(name) {
                        return Err(Fail::usage(format!("no context named {name}")));
                    }
                    ctxs.current = Some(name.clone());
                    ctxs.save()?;
                }
                ContextCmd::Remove { name } => {
                    ctxs.contexts.remove(name);
                    if ctxs.current.as_deref() == Some(name) {
                        ctxs.current = None;
                    }
                    ctxs.save()?;
                }
                ContextCmd::List => {
                    for (n, c) in &ctxs.contexts {
                        let mark = if ctxs.current.as_deref() == Some(n) {
                            "*"
                        } else {
                            " "
                        };
                        println!("{mark} {n}\t{}", c.host.as_deref().unwrap_or("local"));
                    }
                }
            }
            Ok(true)
        }
        Cmd::Init {
            node,
            mgmt_nic,
            mgmt_vlan,
            mgmt_address,
            mgmt_gateway,
            ssh_keys,
            from,
            out,
            config,
            config_out,
        } => {
            if let Some(f) = config {
                let text = std::fs::read_to_string(f)
                    .map_err(|e| Fail::other(format!("{}: {e}", f.display())))?;
                let doc = sparewall_config::parse_value(&text, Format::detect(f.to_str(), &text))?;
                write_init(config_out, &doc)?;
                eprintln!(
                    "Wrote {}. In bootstrap mode, sparewalld applies it within seconds and \
                     confirms it once healthy.",
                    config_out.display()
                );
                if from.is_none() && node.is_none() {
                    return Ok(true);
                }
            }
            let id = match from {
                Some(f) => {
                    let text = std::fs::read_to_string(f)
                        .map_err(|e| Fail::other(format!("{}: {e}", f.display())))?;
                    sparewall_config::parse_value(&text, Format::detect(f.to_str(), &text))?
                }
                None => json!({
                "node": node,
                "ssh_keys": ssh_keys,
                "management": {
                    "nic": mgmt_nic,
                    "vlan": mgmt_vlan,
                    "address": mgmt_address,
                    "gateway": mgmt_gateway,
                }
                }),
            };
            let mut id = id;
            if let Some(m) = id["management"].as_object_mut() {
                m.retain(|_, v| !v.is_null());
            }
            let parsed: sparewall_config::identity::Identity =
                serde_json::from_value(id.clone()).map_err(|e| Fail::invalid(e.to_string()))?;
            parsed.check().map_err(Fail::invalid)?;
            write_init(out, &id)?;
            eprintln!(
                "Wrote {}. A waiting sparewalld records it within seconds.",
                out.display()
            );
            Ok(true)
        }
        Cmd::Restore {
            file,
            repository,
            node,
            password_file,
            no_secrets,
            fake_system,
            state,
            leases,
        } => {
            let active = std::process::Command::new("systemctl")
                .args(["is-active", "--quiet", "sparewalld.service"])
                .status()
                .is_ok_and(|s| s.success());
            if active && !fake_system {
                return Err(Fail::usage(
                    "stop sparewalld first: systemctl stop sparewalld.service sparewalld.socket",
                ));
            }
            let password = match password_file {
                _ if *no_secrets => None,
                Some(p) => {
                    let s = std::fs::read_to_string(p)
                        .map_err(|e| Fail::other(format!("{}: {e}", p.display())))?;
                    Some(s.strip_suffix('\n').unwrap_or(&s).to_string())
                }
                None => Some(read_secret("the backup password")?),
            };
            let fetched;
            let file = match (file, repository) {
                (Some(f), _) => f.as_path(),
                (None, Some(repo)) => {
                    let node = match node {
                        Some(n) => n.clone(),
                        None => local_node(state)?,
                    };
                    fetched = fetch_bundle(repo, &node, password.as_deref())?;
                    fetched.path()
                }
                (None, None) => unreachable!("clap requires one"),
            };
            let (m, secrets) = sparewall_core::backup::restore(
                file,
                state,
                Some(leases),
                password.as_deref().map(str::as_bytes),
            )
            .map_err(|e| Fail::other(e.to_string()))?;
            if !m.secrets.is_empty() && password.is_none() {
                eprintln!("Skipped the cluster secrets ({}).", m.secrets.join(", "));
            }
            for s in &secrets {
                let blob = if *fake_system {
                    use sparewall_core::System;
                    sparewall_core::system::Fake::default().encrypt(&s.info.name, &s.value)
                } else {
                    sparewall_core::linux::creds_encrypt(&s.info.name, &s.value)
                }
                .map_err(|e| Fail::other(e.to_string()))?;
                sparewall_core::secrets::store_encrypted(state, &s.info, &blob)
                    .map_err(|e| Fail::other(e.to_string()))?;
            }
            eprintln!(
                "Restored node {} at generation {} ({} generations{}{}). Start sparewalld to apply it.",
                m.node,
                m.active,
                m.generations.len(),
                if m.leases { ", leases" } else { "" },
                if secrets.is_empty() {
                    String::new()
                } else {
                    format!(", {} secrets", secrets.len())
                }
            );
            Ok(true)
        }
        Cmd::Completion { shell } => {
            clap_complete::generate(
                *shell,
                &mut Cli::command(),
                "sparewall",
                &mut std::io::stdout(),
            );
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Write what `sparewall init` records, as JSON.
fn write_init(out: &Path, v: &Value) -> Result<(), Fail> {
    if let Some(d) = out.parent() {
        std::fs::create_dir_all(d).map_err(|e| Fail::other(format!("{}: {e}", d.display())))?;
    }
    std::fs::write(out, sparewall_config::format_value(v, Format::Json))
        .map_err(|e| Fail::other(format!("{}: {e}", out.display())))
}

/// The subcommands that work on a node itself (its state directory, its
/// systemd credentials, its socket), which a build for a workstation OS
/// cannot do. Elsewhere they say so before trying.
fn node_only(cmd: &Cmd, linux: bool) -> Option<&'static str> {
    if linux {
        return None;
    }
    match cmd {
        Cmd::Init { .. } => Some("init"),
        Cmd::Restore { .. } => Some("restore"),
        Cmd::Bridge => Some("bridge"),
        _ => None,
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = (|| -> Result<(), Fail> {
        if let Some(name) = node_only(&cli.cmd, cfg!(target_os = "linux")) {
            return Err(Fail::usage(format!(
                "`sparewall {name}` runs on a Sparewall node, not here: run it there (over ssh)"
            )));
        }
        if local(&cli.cmd)? {
            return Ok(());
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Fail::other(e.to_string()))?;
        let default_socket = PathBuf::from(sparewall_api::SOCKET);
        if matches!(cli.cmd, Cmd::Bridge) {
            return rt.block_on(conn::bridge(cli.socket.as_ref().unwrap_or(&default_socket)));
        }
        // --host, then --context, then an explicit socket, then the current
        // context, then the local socket.
        let from_context = |name: &str, ctxs: &Contexts| match ctxs.contexts.get(name) {
            Some(c) if c.host.is_some() => Ok(Target::Ssh(c.clone())),
            Some(_) => Ok(Target::Local(default_socket.clone())),
            None => Err(Fail::usage(format!("no context named {name}"))),
        };
        let target = if let Some(h) = &cli.host {
            Target::Ssh(Context {
                host: Some(h.clone()),
                ..Default::default()
            })
        } else if let Some(name) = &cli.context {
            from_context(name, &Contexts::load()?)?
        } else if let Some(s) = &cli.socket {
            Target::Local(s.clone())
        } else {
            let ctxs = Contexts::load()?;
            match &ctxs.current {
                Some(name) => from_context(name, &ctxs)?,
                None => Target::Local(default_socket.clone()),
            }
        };
        let app = App {
            target,
            output: cli.output,
            quiet: cli.quiet,
        };
        rt.block_on(app.run(cli.cmd))
    })();
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(f) => {
            if !f.message.is_empty() {
                eprintln!("sparewall: {}", f.message);
            }
            std::process::ExitCode::from(f.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, hash_password, node_only};
    use clap::Parser;

    #[test]
    fn node_only_commands_are_refused_off_linux() {
        let cmd = |args: &[&str]| {
            Cli::try_parse_from([&["sparewall"], args].concat())
                .unwrap()
                .cmd
        };
        let init = cmd(&["init", "--node", "fw1", "--mgmt-nic", "52:54:00:12:34:56"]);
        assert_eq!(node_only(&init, false), Some("init"));
        assert_eq!(node_only(&init, true), None);
        assert_eq!(node_only(&cmd(&["bridge"]), false), Some("bridge"));
        assert_eq!(node_only(&cmd(&["status"]), false), None);
    }

    #[test]
    fn password_hash_is_what_crypt_makes() {
        // `$6$rounds=5000$<16-character salt>$<digest>`: crypt(3) cuts
        // salts at 16, so a longer one would never match at login.
        let h = hash_password("correct horse").unwrap();
        let f: Vec<&str> = h.split('$').collect();
        assert_eq!(f[..3], ["", "6", "rounds=5000"], "{h}");
        assert_eq!(f[3].len(), 16, "{h}");
        assert!(sparewall_config::identity::password_hash_ok(&h), "{h}");
        use sha_crypt::password_hash::PasswordVerifier;
        assert!(
            sha_crypt::ShaCrypt::default()
                .verify_password(b"correct horse", h.as_str())
                .is_ok()
        );
        assert_ne!(h, hash_password("correct horse").unwrap(), "salted");
    }
}
