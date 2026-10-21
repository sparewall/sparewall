//! Reaching a coordinator: the local socket, or SSH to a node running
//! `sparewall bridge` there (design: "Remote use runs over SSH").

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use zlink::Connection;
use zlink::tokio::unix::Stream;

use crate::Fail;

/// A named deployment in the user's config directory.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Context {
    /// SSH destination, e.g. `admin@fw1.example.org`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Command run on the node; default `sudo -n sparewall bridge`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_command: Option<String>,
    /// Extra ssh options.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_options: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Contexts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(default)]
    pub contexts: BTreeMap<String, Context>,
}

pub fn contexts_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("sparewall/contexts.yaml")
}

impl Contexts {
    pub fn load() -> Result<Contexts, Fail> {
        let p = contexts_path();
        match std::fs::read_to_string(&p) {
            Ok(text) => {
                let v = sparewall_config::parse_value(&text, sparewall_config::Format::Yaml)
                    .map_err(|e| Fail::usage(format!("{}: {e}", p.display())))?;
                serde_json::from_value(v).map_err(|e| Fail::usage(format!("{}: {e}", p.display())))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Contexts::default()),
            Err(e) => Err(Fail::usage(format!("{}: {e}", p.display()))),
        }
    }

    pub fn save(&self) -> Result<(), Fail> {
        let p = contexts_path();
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(|e| Fail::other(format!("{}: {e}", d.display())))?;
        }
        std::fs::write(
            &p,
            sparewall_config::format_value(self, sparewall_config::Format::Yaml),
        )
        .map_err(|e| Fail::other(format!("{}: {e}", p.display())))
    }
}

/// Where to connect.
#[derive(Debug, Clone)]
pub enum Target {
    Local(PathBuf),
    Ssh(Context),
}

impl Target {
    pub fn is_remote(&self) -> bool {
        matches!(self, Target::Ssh(_))
    }
}

pub async fn connect(target: &Target) -> Result<Connection<Stream>, Fail> {
    match target {
        Target::Local(path) => zlink::tokio::unix::connect(path).await.map_err(|e| {
            let hint = if path.exists() {
                " (the socket is root-only: try sudo, or set SPAREWALL_TOKEN)"
            } else {
                " (is sparewalld running?)"
            };
            Fail::unreachable(format!("cannot connect to {}: {e}{hint}", path.display()))
        }),
        Target::Ssh(ctx) => ssh(ctx).await,
    }
}

/// Run the bridge over SSH and speak Varlink through its stdio.
async fn ssh(ctx: &Context) -> Result<Connection<Stream>, Fail> {
    let host = ctx
        .host
        .as_deref()
        .ok_or_else(|| Fail::usage("context has no host"))?;
    let remote = ctx
        .remote_command
        .clone()
        .unwrap_or_else(|| "sudo -n sparewall bridge".into());
    let mut child = Command::new("ssh")
        .args(&ctx.ssh_options)
        .arg("-T")
        .arg("-oBatchMode=yes")
        // A session cut by the change it carried (a renamed management
        // port) fails in seconds instead of leaving the CLI waiting. The
        // context's options come first, so they win.
        .arg("-oServerAliveInterval=5")
        .arg("-oServerAliveCountMax=3")
        .arg("-oConnectTimeout=10")
        .arg(host)
        .arg(remote)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| Fail::unreachable(format!("cannot run ssh: {e}")))?;
    let (ours, theirs) =
        std::os::unix::net::UnixStream::pair().map_err(|e| Fail::other(e.to_string()))?;
    ours.set_nonblocking(true)
        .map_err(|e| Fail::other(e.to_string()))?;
    theirs
        .set_nonblocking(true)
        .map_err(|e| Fail::other(e.to_string()))?;
    let theirs =
        tokio::net::UnixStream::from_std(theirs).map_err(|e| Fail::other(e.to_string()))?;
    let mut stdin = child.stdin.take().expect("piped");
    let mut stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let hint = host_key_hint(&ctx.ssh_options, host);
    // Drained alongside stdout: ssh blocks on a full stderr pipe.
    let errors = tokio::spawn(async move { relay_stderr(stderr, &hint).await });
    tokio::spawn(async move {
        let (mut rd, mut wr) = theirs.into_split();
        let up = async {
            let _ = tokio::io::copy(&mut rd, &mut stdin).await;
            let _ = stdin.shutdown().await;
        };
        let down = async {
            let _ = tokio::io::copy(&mut stdout, &mut wr).await;
            // Hold the stream open until ssh's messages are out, so a
            // hint comes before the caller's own error about the EOF.
            let _ = errors.await;
            drop(wr);
        };
        tokio::join!(up, down);
        let _ = child.wait().await;
    });
    let ours = tokio::net::UnixStream::from_std(ours).map_err(|e| Fail::other(e.to_string()))?;
    let stream: Stream = ours
        .try_into()
        .map_err(|e: zlink::Error| Fail::other(e.to_string()))?;
    Ok(Connection::new(stream))
}

/// Pass ssh's stderr through, and explain BatchMode's refusal of an
/// unknown host key, which every new node meets on first contact.
async fn relay_stderr(stderr: tokio::process::ChildStderr, hint: &str) {
    use std::io::Write;
    use tokio::io::AsyncBufReadExt;
    let mut rd = tokio::io::BufReader::new(stderr);
    let mut line = Vec::new();
    loop {
        line.clear();
        match rd.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let mut err = std::io::stderr().lock();
                let _ = err.write_all(&line);
                if line.starts_with(b"Host key verification failed") {
                    let _ = writeln!(err, "{hint}");
                }
            }
        }
    }
}

fn host_key_hint(options: &[String], host: &str) -> String {
    let ssh = std::iter::once("ssh")
        .chain(options.iter().map(String::as_str))
        .chain([host])
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "hint: ssh does not know {host}'s host key (or it changed). Run \
         `{ssh}` once to check the fingerprint and accept it, then retry."
    )
}

/// `sparewall bridge`: connect stdin/stdout to the local socket, for a
/// client on the other end of an SSH session.
pub async fn bridge(socket: &Path) -> Result<(), Fail> {
    let s = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(|e| Fail::unreachable(format!("{}: {e}", socket.display())))?;
    let (mut rd, mut wr) = s.into_split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let up = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if wr.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = wr.shutdown().await;
    };
    let down = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).await.is_err() || stdout.flush().await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    tokio::join!(up, down);
    Ok(())
}
