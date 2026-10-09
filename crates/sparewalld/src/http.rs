//! HTTPS health endpoints (design: "Health endpoints").
//!
//! `/livez` answers without checks; `/readyz` (and its alias `/healthz`)
//! returns the health level: 200 for ok and degraded, 503 for failed.
//! Unauthenticated requests get only the level; `?verbose` and
//! `/readyz/<check>` detail is limited to loopback callers until API
//! tokens exist (milestone 4).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;

use crate::service::{Core, role_of, with_core};

/// SHA-256 fingerprint of the certificate being served, for `status`.
pub static FINGERPRINT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The node's self-signed certificate (node secret, never leaves the node).
pub struct SelfSigned {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl SelfSigned {
    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(&self.cert_der))
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or_default().to_uppercase())
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Load the self-signed certificate, generating it on first start.
pub fn self_signed(dir: &Path, node: &str) -> Result<SelfSigned, String> {
    let (cp, kp) = (dir.join("self.crt.der"), dir.join("self.key.der"));
    if let (Ok(cert_der), Ok(key_der)) = (std::fs::read(&cp), std::fs::read(&kp)) {
        return Ok(SelfSigned { cert_der, key_der });
    }
    let mut params = rcgen::CertificateParams::new(vec![node.to_string(), "localhost".into()])
        .map_err(|e| e.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("{node} (Sparewall self-signed)"),
    );
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2124, 1, 1);
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    let out = SelfSigned {
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
    };
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    sparewall_core::store::write_atomic(&kp, &out.key_der).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    sparewall_core::store::write_atomic(&cp, &out.cert_der).map_err(|e| e.to_string())?;
    tracing::info!(fingerprint = %out.fingerprint(), "generated self-signed certificate");
    Ok(out)
}

pub fn acceptor(cert: &SelfSigned) -> Result<TlsAcceptor, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert_der.clone().into()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_der.clone().into()),
        )
        .map_err(|e| e.to_string())?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn reply(status: u16, body: Value) -> Response<Full<Bytes>> {
    let mut text = body.to_string();
    text.push('\n');
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(text)))
        .expect("valid response")
}

async fn handle(
    req: Request<Incoming>,
    peer: SocketAddr,
    core: Core,
    events: broadcast::Sender<Value>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().trim_end_matches('/').to_string();
    let verbose_wanted = req.uri().query().is_some_and(|q| {
        q.split('&')
            .any(|p| p == "verbose" || p.starts_with("verbose="))
    });
    let trusted = peer.ip().is_loopback();
    if req.method() != hyper::Method::GET && req.method() != hyper::Method::HEAD {
        return Ok(reply(405, json!({"error": "method not allowed"})));
    }
    if path == "/livez" {
        return Ok(reply(200, json!({"level": "ok"})));
    }
    let check = path
        .strip_prefix("/readyz/")
        .or_else(|| path.strip_prefix("/healthz/"))
        .map(str::to_string);
    if path != "/readyz" && path != "/healthz" && check.is_none() {
        return Ok(reply(404, json!({"error": "not found"})));
    }
    let r = with_core(&core, &events, |c| Ok((c.health()?, role_of(c)?))).await;
    let (health, role) = match r {
        Ok(v) => v,
        Err(e) => {
            return Ok(reply(
                503,
                json!({"level": "failed", "error": e.to_string()}),
            ));
        }
    };
    if let Some(name) = check {
        if !trusted {
            return Ok(reply(401, json!({"error": "authentication required"})));
        }
        return Ok(match health.check(&name) {
            Some(c) => reply(
                c.level.http_status(),
                serde_json::to_value(c).unwrap_or_default(),
            ),
            None => reply(404, json!({"error": format!("no check named {name}")})),
        });
    }
    let status = health.level.http_status();
    if verbose_wanted && trusted {
        return Ok(reply(
            status,
            json!({"level": health.level.as_str(), "role": role, "checks": health.checks}),
        ));
    }
    if verbose_wanted {
        return Ok(reply(
            401,
            json!({"error": "authentication required", "level": health.level.as_str()}),
        ));
    }
    Ok(reply(status, json!({"level": health.level.as_str()})))
}

/// Serve the health endpoints until the listener fails.
pub async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    core: Core,
    events: broadcast::Sender<Value>,
) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "https accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let core = core.clone();
        let events = events.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                acceptor.accept(tcp),
            )
            .await
            {
                Ok(Ok(t)) => t,
                _ => return,
            };
            let svc = hyper::service::service_fn(move |req| {
                handle(req, peer, core.clone(), events.clone())
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}
