//! `sparewall-httpd`: the HTTP API and the web UI's files (design: "Web
//! UI and HTTP API").
//!
//! An unprivileged service with no authority of its own: each call goes
//! to the coordinator's restricted socket bound to the caller's token or
//! session, and the coordinator checks it against that role.

mod gateway;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::gateway::Gateway;

#[derive(Parser)]
#[command(
    name = "sparewall-httpd",
    version,
    about = "Sparewall's HTTP API and web UI"
)]
struct Args {
    /// Where to listen: `unix:<path>`, or `tcp:<address>` on loopback only,
    /// since it is plain HTTP (TLS is the proxy's in front of it).
    #[arg(
        long,
        env = "SPAREWALL_HTTPD_LISTEN",
        default_value = "unix:/run/sparewall-httpd/http.sock"
    )]
    listen: String,
    /// The coordinator's restricted socket.
    #[arg(long, env = "SPAREWALL_API_SOCKET", default_value = sparewall_api::API_SOCKET)]
    api_socket: PathBuf,
    /// The web UI's files.
    #[arg(long, env = "SPAREWALL_UI", default_value = "/usr/share/sparewall/ui")]
    ui: PathBuf,
}

fn serve_conn<I>(io: I, gw: Arc<Gateway>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let svc = service_fn(move |req| {
            let gw = gw.clone();
            async move { Ok::<_, std::convert::Infallible>(gw.handle(req).await) }
        });
        if let Err(e) = http1::Builder::new()
            .serve_connection(TokioIo::new(io), svc)
            .await
        {
            tracing::debug!(error = %e, "connection ended");
        }
    });
}

async fn run(args: Args) -> Result<(), String> {
    let gw = Arc::new(Gateway {
        api_socket: args.api_socket,
        ui: args.ui,
    });
    if let Some(path) = args.listen.strip_prefix("unix:") {
        let _ = std::fs::remove_file(path);
        let l = tokio::net::UnixListener::bind(path).map_err(|e| format!("{path}: {e}"))?;
        tracing::info!(path, "listening");
        loop {
            let (s, _) = l.accept().await.map_err(|e| e.to_string())?;
            serve_conn(s, gw.clone());
        }
    } else if let Some(addr) = args.listen.strip_prefix("tcp:") {
        // Plain HTTP carries tokens and session cookies in the clear: keep
        // it off the network.
        let sa: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| format!("{addr}: {e} (tcp: takes an IP address and port)"))?;
        if !sa.ip().is_loopback() {
            return Err(format!(
                "{addr}: tcp: listens on loopback only, as it is plain HTTP"
            ));
        }
        let l = tokio::net::TcpListener::bind(sa)
            .await
            .map_err(|e| format!("{addr}: {e}"))?;
        tracing::info!(addr, "listening");
        loop {
            let (s, _) = l.accept().await.map_err(|e| e.to_string())?;
            serve_conn(s, gw.clone());
        }
    } else {
        Err(format!(
            "--listen takes unix:<path> or tcp:<address>, not {}",
            args.listen
        ))
    }
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SPAREWALL_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sparewall-httpd: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(args)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
