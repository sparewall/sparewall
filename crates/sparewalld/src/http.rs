//! HTTPS health endpoints (design: "Health endpoints").
//!
//! `/livez` answers without checks; `/readyz` (and its alias `/healthz`)
//! returns the health level: 200 for ok and degraded, 503 for failed.
//! Unauthenticated requests get only the level; `?verbose`,
//! `/readyz/<check>` and `/metrics` need an API token
//! (`Authorization: Bearer`), unless `metrics.mode` is `external`.
//!
//! Every other path goes to `sparewall-httpd` over its socket, when the
//! document turns it on (`management.web`): the web UI and the HTTP API
//! share this port and its certificate.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
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

fn server_config(
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(config))
}

/// The certificate the HTTPS listener serves, swappable without
/// restarting it.
pub struct Tls {
    self_signed: Arc<rustls::ServerConfig>,
    current: std::sync::Mutex<(Arc<rustls::ServerConfig>, Option<String>)>,
}

impl Tls {
    pub fn new(cert: &SelfSigned) -> Result<Tls, String> {
        let ss = server_config(
            vec![cert.cert_der.clone().into()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_der.clone().into()),
        )?;
        Ok(Tls {
            current: std::sync::Mutex::new((ss.clone(), None)),
            self_signed: ss,
        })
    }

    fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(
            self.current
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .0
                .clone(),
        )
    }

    pub fn use_self_signed(&self) {
        *self.current.lock().unwrap_or_else(|p| p.into_inner()) = (self.self_signed.clone(), None);
    }

    /// Serve a PEM chain and key (no-op when already serving them).
    pub fn use_pem(&self, chain_pem: &str, key_pem: &str) -> Result<(), String> {
        let id = hex::encode(Sha256::digest(chain_pem.as_bytes()));
        let mut cur = self.current.lock().unwrap_or_else(|p| p.into_inner());
        if cur.1.as_deref() == Some(id.as_str()) {
            return Ok(());
        }
        use rustls::pki_types::pem::PemObject;
        let chain: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(chain_pem.as_bytes())
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|e| e.to_string())?;
        *cur = (server_config(chain, key)?, Some(id));
        tracing::info!("serving the ACME certificate");
        Ok(())
    }
}

/// A reply's body: the coordinator's own, or `sparewall-httpd`'s streamed
/// through.
type Body = BoxBody<Bytes, hyper::Error>;

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}

fn reply(status: u16, body: Value) -> Response<Body> {
    let mut text = body.to_string();
    text.push('\n');
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(full(text))
        .expect("valid response")
}

/// Paths the coordinator answers itself; the rest are `sparewall-httpd`'s.
fn health_path(path: &str) -> bool {
    matches!(path, "/livez" | "/readyz" | "/healthz" | "/metrics")
        || path.starts_with("/readyz/")
        || path.starts_with("/healthz/")
}

/// Headers that describe one connection, not the request (RFC 9110
/// section 7.6.1), which a proxy drops in both directions.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn drop_hop_by_hop(h: &mut hyper::HeaderMap) {
    let named: Vec<hyper::header::HeaderName> = h
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| n.trim().parse().ok())
        .collect();
    for n in named {
        h.remove(n);
    }
    for n in HOP_BY_HOP {
        h.remove(*n);
    }
}

/// Pass a request to `sparewall-httpd` and stream its reply back. Its
/// socket exists only while the document turns it on, so without one the
/// path is simply not found.
async fn proxy<B>(mut req: Request<B>, socket: &Path) -> Response<Body>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let stream = match tokio::net::UnixStream::connect(socket).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return reply(404, json!({"error": "not found"}));
        }
        Err(e) => {
            tracing::warn!(error = %e, "sparewall-httpd did not answer");
            return reply(502, json!({"error": "the web UI did not answer"}));
        }
    };
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
    {
        Ok(x) => x,
        Err(e) => {
            tracing::warn!(error = %e, "sparewall-httpd did not answer");
            return reply(502, json!({"error": "the web UI did not answer"}));
        }
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    drop_hop_by_hop(req.headers_mut());
    match sender.send_request(req).await {
        Ok(r) => {
            let (mut parts, body) = r.into_parts();
            drop_hop_by_hop(&mut parts.headers);
            Response::from_parts(parts, body.boxed())
        }
        Err(e) => {
            tracing::warn!(error = %e, "sparewall-httpd did not answer");
            reply(502, json!({"error": "the web UI did not answer"}))
        }
    }
}

async fn handle(
    req: Request<Incoming>,
    _peer: SocketAddr,
    core: Core,
    events: broadcast::Sender<Value>,
    web: Arc<PathBuf>,
) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path().trim_end_matches('/').to_string();
    if !health_path(&path) {
        return Ok(proxy(req, &web).await);
    }
    let verbose_wanted = req.uri().query().is_some_and(|q| {
        q.split('&')
            .any(|p| p == "verbose" || p.starts_with("verbose="))
    });
    // A monitor-role (or higher) API token unlocks detail and metrics.
    let bearer = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.trim().to_string());
    let token_ok = match bearer {
        Some(t) => with_core(&core, &events, move |c| c.token_check(&t))
            .await
            .ok()
            .flatten()
            .is_some(),
        None => false,
    };
    let trusted = token_ok;
    if req.method() != hyper::Method::GET && req.method() != hyper::Method::HEAD {
        return Ok(reply(405, json!({"error": "method not allowed"})));
    }
    if path == "/livez" {
        return Ok(reply(200, json!({"level": "ok"})));
    }
    if path == "/metrics" {
        // With a token, or to anyone on the management network when the
        // document asks for an unauthenticated external scrape.
        let r = with_core(&core, &events, move |c| {
            let mode = c
                .active()
                .and_then(|id| {
                    if id == 0 {
                        Ok(None)
                    } else {
                        c.store().document(id).map(|d| d.metrics)
                    }
                })?
                .map(|m| m.mode);
            let allowed = match mode {
                Some(sparewall_config::model::MetricsMode::Off) => false,
                Some(sparewall_config::model::MetricsMode::External) => true,
                _ => trusted,
            };
            if allowed {
                c.metrics().map(Some)
            } else {
                Ok(None)
            }
        })
        .await;
        let r = match r {
            // Host metrics from node_exporter, which listens only on
            // localhost so this endpoint's access rules cover it too.
            Ok(Some(mut text)) => {
                if let Some(host) = node_exporter().await {
                    text.push_str(&host);
                }
                Ok(Some(text))
            }
            other => other,
        };
        return Ok(match r {
            Ok(Some(text)) => Response::builder()
                .status(200)
                .header("content-type", "text/plain; version=0.0.4")
                .header("cache-control", "no-store")
                .body(full(text))
                .expect("valid response"),
            Ok(None) => reply(
                403,
                json!({"error": "metrics are not exposed here (see metrics.mode)"}),
            ),
            Err(e) => reply(500, json!({"error": e.to_string()})),
        });
    }
    let check = path
        .strip_prefix("/readyz/")
        .or_else(|| path.strip_prefix("/healthz/"))
        .map(str::to_string);
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

/// Serve the health endpoints, and pass the rest to `sparewall-httpd`'s
/// socket at `web`, until the listener fails.
pub async fn serve(
    listener: TcpListener,
    tls: Arc<Tls>,
    core: Core,
    events: broadcast::Sender<Value>,
    web: PathBuf,
) {
    let web = Arc::new(web);
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "https accept failed");
                continue;
            }
        };
        let acceptor = tls.acceptor();
        let core = core.clone();
        let events = events.clone();
        let web = web.clone();
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
                handle(req, peer, core.clone(), events.clone(), web.clone())
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}

/// Where node_exporter serves host metrics.
const NODE_EXPORTER: &str = "127.0.0.1:9100";

/// node_exporter's metrics, or `None` when it is not running.
async fn node_exporter() -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fetch = async {
        let mut s = tokio::net::TcpStream::connect(NODE_EXPORTER).await.ok()?;
        s.write_all(b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .await
            .ok()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.ok()?;
        let text = String::from_utf8(buf).ok()?;
        let (head, body) = text.split_once("\r\n\r\n")?;
        head.lines()
            .next()?
            .split(' ')
            .nth(1)
            .filter(|c| *c == "200")?;
        Some(body.to_string())
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), fetch)
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_paths_stay_here() {
        for p in ["/livez", "/readyz", "/readyz/nft", "/healthz", "/metrics"] {
            assert!(health_path(p), "{p}");
        }
        for p in [
            "",
            "/call/org.sparewall.Firewall.Status",
            "/openapi.json",
            "/livezz",
        ] {
            assert!(!health_path(p), "{p}");
        }
    }

    #[test]
    fn hop_by_hop_headers_are_dropped() {
        let mut h = hyper::HeaderMap::new();
        h.insert("connection", "close, x-private".parse().unwrap());
        h.insert("x-private", "1".parse().unwrap());
        h.insert("keep-alive", "timeout=5".parse().unwrap());
        h.insert("cookie", "sparewall_session=t".parse().unwrap());
        drop_hop_by_hop(&mut h);
        assert_eq!(h.len(), 1, "{h:?}");
        assert!(h.contains_key("cookie"));
    }

    #[tokio::test]
    async fn requests_reach_the_web_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("http.sock");
        let r = proxy(Request::new(Full::new(Bytes::new())), &socket).await;
        assert_eq!(r.status(), 404, "no socket: the web UI is off");

        // A stand-in for sparewall-httpd that echoes what it was sent.
        let l = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                let line = format!(
                    "{} {} {:?} {:?}",
                    req.method(),
                    req.uri(),
                    req.headers().get("cookie"),
                    req.headers().get("x-private"),
                );
                let body = req.into_body().collect().await?.to_bytes();
                let r = Response::builder()
                    .header("connection", "keep-alive")
                    .body(Full::new(Bytes::from(format!("{line} {body:?}"))))
                    .unwrap();
                Ok::<_, hyper::Error>(r)
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(s), svc)
                .await;
        });
        let req = Request::post("/call/org.sparewall.Firewall.Status?x=1")
            .header("host", "fw1")
            .header("cookie", "sparewall_session=t")
            .header("connection", "x-private")
            .header("x-private", "1")
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap();
        let r = proxy(req, &socket).await;
        assert_eq!(r.status(), 200);
        assert!(r.headers().get("connection").is_none());
        let body = r.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            body,
            "POST /call/org.sparewall.Firewall.Status?x=1 \
             Some(\"sparewall_session=t\") None b\"{}\""
        );
    }
}
