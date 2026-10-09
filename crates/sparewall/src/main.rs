//! sparewall: the command-line client for the Sparewall coordinator.

mod conn;

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use futures_util::{StreamExt, pin_mut};
use serde_json::{Value, json};
use sparewall_api::{ApplyReply, FirewallError, FirewallProxy, Generation};
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
    version,
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
    },
    /// List generations.
    History {
        #[arg(short = 'n', long)]
        limit: Option<i64>,
    },
    /// Keep a change that is waiting for confirmation.
    Confirm { id: Option<i64> },
    /// Return to a generation (default: the previous one).
    Rollback { id: Option<i64> },
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
    /// Manage named contexts (deployments reached over SSH).
    #[command(subcommand)]
    Context(ContextCmd),
    /// Record this node's install-time identity (run on the node as root).
    Init {
        /// Node name, e.g. fw1.
        #[arg(long)]
        node: String,
        /// Management NIC: permanent MAC address or udev path.
        #[arg(long)]
        mgmt_nic: String,
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
        /// Where to write the identity.
        #[arg(long, default_value = "/etc/sparewall/identity.json")]
        out: PathBuf,
    },
    /// Restore a backup bundle into the state directory (on the node, as
    /// root, with sparewalld stopped).
    Restore {
        #[arg(short, long)]
        file: PathBuf,
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
    /// OS image upgrades (milestone 5).
    Upgrade {
        #[arg(long)]
        channel: Option<String>,
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
        let (_, current) = self.current().await?;
        let window = if c.dry_run {
            None
        } else {
            Some(i64::from(self.default_confirm(c)))
        };
        let mut conn = self.conn().await?;
        let dry = Some(c.dry_run);
        let r: ApplyReply = match kind {
            "apply" => conn.apply(&body, current.id, window, dry).await??,
            "merge" => conn.merge(&body, current.id, window, dry).await??,
            "patch" => conn.patch(&body, current.id, window, dry).await??,
            _ => unreachable!(),
        };
        drop(conn);
        self.report(&r, c).await
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
        let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
        if c.no_prompt || !interactive || self.quiet {
            self.say(format!(
                "Applied generation {id}; it reverts in {}s unless you run `sparewall confirm {id}`.",
                r.confirm_seconds
            ));
            return Ok(());
        }
        eprint!(
            "Applied generation {id}. Keep it? It reverts in {}s otherwise. [y/N] ",
            r.confirm_seconds
        );
        let _ = std::io::stderr().flush();
        let answer = tokio::time::timeout(
            Duration::from_secs(r.confirm_seconds.max(1) as u64),
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
                let g = self.conn().await?.rollback(None).await??;
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
            Cmd::Health { verbose } => {
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
            Cmd::Rollback { id } => {
                let g = self.conn().await?.rollback(id).await??;
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
                println!("{} {}", r.digest, r.path);
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
            Cmd::Schema(SchemaCmd::Show) => {
                print!("{}", sparewall_config::schema::json_schema_text())
            }
            Cmd::Schema(_) => {
                return Err(Fail::other(format!(
                    "only schema version {} exists; nothing to migrate",
                    sparewall_config::SCHEMA_VERSION
                )));
            }
            Cmd::Upgrade { .. } => {
                return Err(Fail::other(
                    "rolling OS upgrades arrive in milestone 5; use `bootc upgrade` on each node for now",
                ));
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
            out,
        } => {
            let id = json!({
                "node": node,
                "ssh_keys": ssh_keys,
                "management": {
                    "nic": mgmt_nic,
                    "vlan": mgmt_vlan,
                    "address": mgmt_address,
                    "gateway": mgmt_gateway,
                }
            });
            let mut id = id;
            if let Some(m) = id["management"].as_object_mut() {
                m.retain(|_, v| !v.is_null());
            }
            let parsed: sparewall_config::identity::Identity =
                serde_json::from_value(id.clone()).map_err(|e| Fail::invalid(e.to_string()))?;
            parsed.check().map_err(Fail::invalid)?;
            if let Some(d) = out.parent() {
                std::fs::create_dir_all(d)
                    .map_err(|e| Fail::other(format!("{}: {e}", d.display())))?;
            }
            std::fs::write(out, sparewall_config::format_value(&id, Format::Json))
                .map_err(|e| Fail::other(format!("{}: {e}", out.display())))?;
            eprintln!(
                "Wrote {}. sparewalld records it on its next start (systemctl restart sparewalld).",
                out.display()
            );
            Ok(true)
        }
        Cmd::Restore {
            file,
            state,
            leases,
        } => {
            let active = std::process::Command::new("systemctl")
                .args(["is-active", "--quiet", "sparewalld.service"])
                .status()
                .is_ok_and(|s| s.success());
            if active {
                return Err(Fail::usage(
                    "stop sparewalld first: systemctl stop sparewalld.service sparewalld.socket",
                ));
            }
            let m = sparewall_core::backup::restore(file, state, Some(leases))
                .map_err(|e| Fail::other(e.to_string()))?;
            eprintln!(
                "Restored node {} at generation {} ({} generations{}). Start sparewalld to apply it.",
                m.node,
                m.active,
                m.generations.len(),
                if m.leases { ", leases" } else { "" }
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

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = (|| -> Result<(), Fail> {
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
