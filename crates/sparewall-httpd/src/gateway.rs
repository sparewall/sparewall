//! HTTP to Varlink (docs/api/README.md).
//!
//! `POST /call/<interface>.<Method>` becomes a call on the coordinator's
//! restricted socket, on a connection bound to the caller's API token or
//! session; the coordinator checks the call against that role. Browsers
//! log in through `org.sparewall.Auth.Login`, which sets the session
//! cookie, and every request carrying the cookie must also carry
//! [`CSRF_HEADER`]. Everything else is the UI's static files.

use std::convert::Infallible;
use std::path::{Component, Path, PathBuf};

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sparewall_api::openapi::{
    CSRF_HEADER, METHOD_NOT_ALLOWED, NOT_FOUND, SESSION_COOKIE, TOO_LARGE, UNAVAILABLE, http_status,
};
use zlink::Call;

pub type Body = UnsyncBoxBody<Bytes, Infallible>;

/// The largest request body taken (a configuration document).
const MAX_BODY: usize = 4 << 20;

/// The HTTP API's description, generated from the interfaces.
const OPENAPI: &str = include_str!("../../../docs/api/openapi.json");

const LOGIN: &str = "org.sparewall.Auth.Login";
const LOGOUT: &str = "org.sparewall.Auth.Logout";

/// What the gateway serves.
pub struct Gateway {
    /// The coordinator's restricted socket.
    pub api_socket: PathBuf,
    /// The UI's static files; it may be missing.
    pub ui: PathBuf,
}

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).boxed_unsync()
}

fn json_response(status: u16, v: &Value) -> Response<Body> {
    let mut r = Response::new(full(serde_json::to_vec(v).unwrap_or_default()));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

/// An error in the coordinator's form, for one the gateway finds itself.
/// The gateway's own error reply, shaped as the description's `Error`.
fn refusal(status: u16, error: &str, parameters: Value, message: &str) -> Response<Body> {
    json_response(
        status,
        &json!({"error": error, "parameters": parameters, "message": message}),
    )
}

fn unauthenticated(reason: &str) -> Response<Body> {
    json_response(
        401,
        &json!({
            "error": "org.sparewall.Firewall.PermissionDenied",
            "parameters": {"role": "none", "reason": reason},
            "message": format!("permission denied for role none: {reason}"),
        }),
    )
}

/// The headers every response carries.
fn harden(r: &mut Response<Body>) {
    let h = r.headers_mut();
    for (k, v) in [
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("cross-origin-opener-policy", "same-origin"),
        (
            "content-security-policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
             frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    ] {
        h.insert(k, HeaderValue::from_static(v));
    }
}

/// How the caller identifies itself.
#[derive(Debug, PartialEq, Eq)]
enum Credentials {
    None,
    /// An API token (`Authorization: Bearer`).
    Bearer(String),
    /// A browser session (the cookie), with the CSRF header present.
    Session(String),
}

fn cookie(req: &Request<Incoming>, name: &str) -> Option<String> {
    req.headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| {
            let (k, v) = c.trim().split_once('=')?;
            (k == name && !v.is_empty()).then(|| v.to_string())
        })
}

fn has_csrf_header(req: &Request<Incoming>) -> bool {
    req.headers().contains_key(CSRF_HEADER)
}

/// The caller's credentials. A session cookie counts only with the CSRF
/// header, which a cross-site form cannot send. A refusal is the reason,
/// for [`unauthenticated`].
fn credentials(req: &Request<Incoming>) -> Result<Credentials, String> {
    if let Some(v) = req.headers().get(header::AUTHORIZATION) {
        return match v.to_str().ok().and_then(|v| v.strip_prefix("Bearer ")) {
            Some(t) if !t.trim().is_empty() => Ok(Credentials::Bearer(t.trim().to_string())),
            _ => Err("the Authorization header takes a bearer token".into()),
        };
    }
    match cookie(req, SESSION_COOKIE) {
        Some(s) if has_csrf_header(req) => Ok(Credentials::Session(s)),
        Some(_) => Err(format!(
            "a request with the session cookie must carry the {CSRF_HEADER} header"
        )),
        None => Ok(Credentials::None),
    }
}

/// A call with a method chosen at run time.
#[derive(Debug, Serialize)]
struct DynMethod<'a> {
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a Value>,
}

/// Methods that take no parameters, from the description. zlink's
/// services take such a call only without `parameters`, and any other
/// only with it (even empty), and drop the connection otherwise. Not
/// needed once zlink takes both (z-galaxy/zlink#275 and #324).
fn takes_parameters(method: &str) -> bool {
    static NONE: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
        DESCRIPTION["paths"]
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(_, op)| {
                op.pointer("/post/requestBody/content/application~1json/schema/properties")
                    .and_then(Value::as_object)
                    .is_some_and(serde_json::Map::is_empty)
            })
            .filter_map(|(p, _)| p.strip_prefix("/call/").map(str::to_string))
            .collect()
    });
    !NONE.iter().any(|m| m == method)
}

/// Methods that stream replies, from the description. Only these take
/// `?more=true`: any other would answer down the stream path, where a
/// login's token would reach the page instead of the cookie.
fn streams(method: &str) -> bool {
    static MORE: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
        DESCRIPTION["paths"]
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(_, op)| {
                op.pointer("/post/parameters")
                    .and_then(Value::as_array)
                    .is_some_and(|ps| ps.iter().any(|p| p["name"] == "more"))
            })
            .filter_map(|(p, _)| p.strip_prefix("/call/").map(str::to_string))
            .collect()
    });
    method != LOGIN && MORE.iter().any(|m| m == method)
}

static DESCRIPTION: std::sync::LazyLock<Value> =
    std::sync::LazyLock::new(|| serde_json::from_str(OPENAPI).unwrap_or_default());

/// A Varlink error reply.
#[derive(Debug, Deserialize)]
struct DynError {
    error: String,
    #[serde(default)]
    parameters: Value,
}

/// The coordinator's error, with its status and a message in words.
fn error_response(e: DynError) -> Response<Body> {
    let message = serde_json::from_value::<sparewall_api::FirewallError>(json!({
        "error": e.error,
        "parameters": e.parameters,
    }))
    .map_or_else(|_| e.error.clone(), |f| f.to_string());
    json_response(
        http_status(&e.error, &e.parameters),
        &json!({"error": e.error, "parameters": e.parameters, "message": message}),
    )
}

fn connection_error(e: zlink::Error) -> Response<Body> {
    if let zlink::Error::VarlinkService(owned) = &e
        && let Ok(v) = serde_json::to_value(owned.inner())
        && let Some(name) = v.get("error").and_then(Value::as_str)
    {
        return error_response(DynError {
            error: name.to_string(),
            parameters: v.get("parameters").cloned().unwrap_or(Value::Null),
        });
    }
    tracing::warn!(error = %e, "the coordinator did not answer");
    refusal(
        502,
        UNAVAILABLE,
        json!({}),
        &format!("the coordinator did not answer: {e}"),
    )
}

/// Whether `m` looks like `<interface>.<Method>`.
fn method_ok(m: &str) -> bool {
    let Some((iface, name)) = m.rsplit_once('.') else {
        return false;
    };
    iface.contains('.')
        && iface
            .split('.')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && name.chars().all(|c| c.is_ascii_alphanumeric())
}

fn flag(query: Option<&str>, name: &str) -> Result<bool, String> {
    let Some(q) = query else { return Ok(false) };
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, "true"));
        if k == name {
            return match v {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(format!("?{name}= takes true or false")),
            };
        }
    }
    Ok(false)
}

fn session_cookie(token: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static(""))
}

impl Gateway {
    pub async fn handle(&self, req: Request<Incoming>) -> Response<Body> {
        let path = req.uri().path().to_string();
        let mut r = match (req.method(), path.as_str()) {
            (&Method::POST, p) if p.starts_with("/call/") => {
                let m = p["/call/".len()..].to_string();
                self.call(req, &m).await
            }
            (_, p) if p.starts_with("/call/") => {
                refusal(405, METHOD_NOT_ALLOWED, json!({}), "calls are POST")
            }
            (&Method::GET, "/openapi.json") => {
                let mut r = Response::new(full(OPENAPI));
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                r
            }
            (&Method::GET | &Method::HEAD, p) => self.file(p).await,
            _ => refusal(405, METHOD_NOT_ALLOWED, json!({}), "not allowed"),
        };
        harden(&mut r);
        r
    }

    async fn call(&self, req: Request<Incoming>, method: &str) -> Response<Body> {
        if !method_ok(method) {
            return refusal(
                404,
                "org.varlink.service.MethodNotFound",
                json!({"method": method}),
                &format!("no method {method}"),
            );
        }
        let more = match flag(req.uri().query(), "more") {
            Ok(m) => m,
            Err(e) => {
                return refusal(
                    400,
                    "org.varlink.service.InvalidParameter",
                    json!({"parameter": "more"}),
                    &e,
                );
            }
        };
        if more && !streams(method) {
            return refusal(
                400,
                "org.varlink.service.InvalidParameter",
                json!({"parameter": "more"}),
                &format!("{method} does not stream, so it takes no ?more=true"),
            );
        }
        let creds = match credentials(&req) {
            Ok(c) => c,
            Err(reason) => return unauthenticated(&reason),
        };
        // A login sets the session cookie, so it needs the CSRF header
        // too: a cross-site form must not log the browser in.
        if method == LOGIN && !has_csrf_header(&req) {
            return unauthenticated(&format!("a login must carry the {CSRF_HEADER} header"));
        }
        let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) if e.is::<http_body_util::LengthLimitError>() => {
                return refusal(
                    413,
                    TOO_LARGE,
                    json!({}),
                    &format!("the request is over {MAX_BODY} bytes"),
                );
            }
            Err(e) => {
                return refusal(
                    400,
                    "org.varlink.service.InvalidParameter",
                    json!({"parameter": "parameters"}),
                    &format!("cannot read the request: {e}"),
                );
            }
        };
        let params: Value = if body.iter().all(u8::is_ascii_whitespace) {
            json!({})
        } else {
            match serde_json::from_slice(&body) {
                Ok(v @ Value::Object(_)) => v,
                Ok(_) => {
                    return refusal(
                        400,
                        "org.varlink.service.InvalidParameter",
                        json!({"parameter": "parameters"}),
                        "the parameters are a JSON object",
                    );
                }
                Err(e) => {
                    return refusal(
                        400,
                        "org.varlink.service.InvalidParameter",
                        json!({"parameter": "parameters"}),
                        &format!("invalid JSON: {e}"),
                    );
                }
            }
        };

        let mut conn = match zlink::tokio::unix::connect(&self.api_socket).await {
            Ok(c) => c,
            Err(e) => return connection_error(e),
        };
        let token = match &creds {
            Credentials::Bearer(t) | Credentials::Session(t) => Some(t.clone()),
            Credentials::None => None,
        };
        if let Some(t) = &token
            && method != LOGIN
        {
            let bind = json!({"token": t});
            let call = Call::new(DynMethod {
                method: "org.sparewall.Auth.Bind",
                parameters: Some(&bind),
            });
            match conn.call_method::<_, Value, DynError>(&call, vec![]).await {
                Ok((Ok(_), _)) => {}
                Ok((Err(e), _)) => {
                    let mut r = error_response(e);
                    if matches!(creds, Credentials::Session(_)) {
                        // An ended session: forget it.
                        r.headers_mut()
                            .insert(header::SET_COOKIE, session_cookie("", 0));
                    }
                    return r;
                }
                Err(e) => return connection_error(e),
            }
        }

        let call = Call::new(DynMethod {
            method,
            parameters: (takes_parameters(method) || params != json!({})).then_some(&params),
        })
        .set_more(more);
        if more {
            return match conn.send_call(&call, vec![]).await {
                Ok(()) => stream(conn),
                Err(e) => connection_error(e),
            };
        }
        let reply = match conn.call_method::<_, Value, DynError>(&call, vec![]).await {
            Ok((Ok(r), _)) => r.into_parameters().unwrap_or_else(|| json!({})),
            Ok((Err(e), _)) => return error_response(e),
            Err(e) => return connection_error(e),
        };
        match method {
            LOGIN => {
                // The session lives in the cookie, out of the page's reach.
                let token = reply["token"].as_str().unwrap_or_default().to_string();
                let expires = reply["expires"].as_i64().unwrap_or_default();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs() as i64);
                let mut shown = reply.clone();
                if let Some(o) = shown.as_object_mut() {
                    o.remove("token");
                }
                let mut r = json_response(200, &shown);
                r.headers_mut().insert(
                    header::SET_COOKIE,
                    session_cookie(&token, (expires - now).max(0)),
                );
                r
            }
            LOGOUT => {
                let mut r = json_response(200, &reply);
                r.headers_mut()
                    .insert(header::SET_COOKIE, session_cookie("", 0));
                r
            }
            _ => json_response(200, &reply),
        }
    }

    async fn file(&self, path: &str) -> Response<Body> {
        let rel = Path::new(path.trim_start_matches('/'));
        if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
            return refusal(404, NOT_FOUND, json!({}), "not found");
        }
        let mut p = self.ui.join(rel);
        if path.ends_with('/') || path == "/" {
            p = p.join("index.html");
        }
        let (p, bytes) = match tokio::fs::read(&p).await {
            Ok(b) => (p, b),
            // The UI routes in the page: a path without an extension
            // is one of its views.
            Err(_) if rel.extension().is_none() => {
                let index = self.ui.join("index.html");
                match tokio::fs::read(&index).await {
                    Ok(b) => (index, b),
                    Err(_) => {
                        return refusal(
                            404,
                            NOT_FOUND,
                            json!({}),
                            "the web UI is not installed; the API is at /call/",
                        );
                    }
                }
            }
            Err(_) => return refusal(404, NOT_FOUND, json!({}), "not found"),
        };
        let mut r = Response::new(full(bytes));
        let h = r.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(content_type(&p)),
        );
        // The page is small and names its assets by content hash.
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(if p.ends_with("index.html") {
                "no-cache"
            } else {
                "max-age=3600"
            }),
        );
        r
    }
}

fn content_type(p: &Path) -> &'static str {
    match p.extension().and_then(|e| e.to_str()).unwrap_or_default() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Replies to a call with `more`, as an RFC 7464 JSON text sequence,
/// until the coordinator ends them or the client goes away.
fn stream(conn: zlink::Connection<zlink::tokio::unix::Stream>) -> Response<Body> {
    let records = futures_util::stream::unfold(Some(conn), |conn| async move {
        let mut conn = conn?;
        let (record, more) = match conn.receive_reply::<Value, DynError>().await {
            Ok((Ok(r), _)) => {
                let more = r.continues().unwrap_or(false);
                (r.into_parameters().unwrap_or_else(|| json!({})), more)
            }
            Ok((Err(e), _)) => (json!({"error": e.error, "parameters": e.parameters}), false),
            Err(e) => (
                json!({"error": UNAVAILABLE, "parameters": {}, "message": e.to_string()}),
                false,
            ),
        };
        let bytes = Bytes::from(format!("\x1e{record}\n"));
        Some((
            Ok::<_, Infallible>(Frame::data(bytes)),
            more.then_some(conn),
        ))
    });
    let mut r = Response::new(BodyExt::boxed_unsync(StreamBody::new(records.boxed())));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json-seq"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_names() {
        assert!(method_ok("org.sparewall.Firewall.Apply"));
        assert!(!method_ok("Apply"));
        assert!(!method_ok("org.sparewall.Firewall.apply"));
        assert!(!method_ok("org..Firewall.Apply"));
        assert!(!method_ok("org.sparewall.Firewall.Ap/ply"));
    }

    #[test]
    fn methods_without_parameters() {
        assert!(!takes_parameters("org.sparewall.Auth.ListUsers"));
        assert!(!takes_parameters("org.sparewall.Firewall.Status"));
        assert!(takes_parameters("org.sparewall.Firewall.History"));
        assert!(takes_parameters("org.example.Unknown.Method"));
    }

    #[test]
    fn flags() {
        assert_eq!(flag(Some("more=true"), "more"), Ok(true));
        assert_eq!(flag(Some("a=1&more"), "more"), Ok(true));
        assert_eq!(flag(None, "more"), Ok(false));
        assert!(flag(Some("more=yes"), "more").is_err());
        assert!(streams("org.sparewall.Firewall.Subscribe"));
        assert!(!streams(LOGIN));
        assert!(!streams("org.sparewall.Firewall.GetConfig"));
    }
}
