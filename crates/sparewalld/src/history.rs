//! History from the local Prometheus (`metrics.mode: local`, #145), for
//! `org.sparewall.Metrics`. Prometheus listens on loopback only; this is
//! the one way in from the management network, as the caller's role
//! allows, and only to its query endpoints.

use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use sparewall_api::{FirewallError, QueryReply};

/// The most of Prometheus's answer passed on.
const MAX_REPLY: usize = 16 << 20;
/// Longer than Prometheus's own query timeout (the Quadlet's
/// `--query.timeout`), so that its error, which says why, comes first.
const TIMEOUT: Duration = Duration::from_secs(40);

fn unavailable(message: impl Into<String>) -> FirewallError {
    FirewallError::ServiceUnavailable {
        service: "prometheus".into(),
        message: message.into(),
    }
}

/// `application/x-www-form-urlencoded`.
fn form(params: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        for (j, s) in [k, v].into_iter().enumerate() {
            if j > 0 {
                out.push('=');
            }
            for b in s.bytes() {
                match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                        out.push(b as char)
                    }
                    b' ' => out.push('+'),
                    _ => out.push_str(&format!("%{b:02X}")),
                }
            }
        }
    }
    out
}

/// Prometheus's answer as the reply, or the error it gives.
fn answer(body: &[u8]) -> Result<QueryReply, FirewallError> {
    let v: Value = serde_json::from_slice(body)
        .map_err(|e| unavailable(format!("an answer that is not JSON: {e}")))?;
    let notes = || {
        ["warnings", "infos"]
            .iter()
            .flat_map(|k| v[*k].as_array().into_iter().flatten())
            .filter_map(|w| w.as_str().map(str::to_string))
            .collect()
    };
    if v["status"] == "success" {
        return Ok(QueryReply {
            result_type: v["data"]["resultType"].as_str().unwrap_or_default().into(),
            result: v["data"]["result"].clone(),
            warnings: notes(),
        });
    }
    let error = v["error"].as_str().unwrap_or("no reason given").to_string();
    // The query's own fault (it does not parse, or asks for too much),
    // or Prometheus's (a timeout, shutting down).
    match v["errorType"].as_str() {
        Some("bad_data" | "execution") => Err(FirewallError::ValidationFailed {
            errors: vec![error],
        }),
        _ => Err(unavailable(error)),
    }
}

/// POST `params` to Prometheus's `path` (`/api/v1/query`).
pub async fn query(path: &str, params: &[(&str, &str)]) -> Result<QueryReply, FirewallError> {
    let body = form(params);
    let run = async {
        let tcp = tokio::net::TcpStream::connect(sparewall_render::metrics::LISTEN)
            .await
            .map_err(|e| unavailable(format!("not answering: {e}")))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| unavailable(e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::post(path)
            .header("host", sparewall_render::metrics::LISTEN)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| unavailable(e.to_string()))?;
        let r = sender
            .send_request(req)
            .await
            .map_err(|e| unavailable(e.to_string()))?;
        let bytes = Limited::new(r.into_body(), MAX_REPLY)
            .collect()
            .await
            .map_err(|e| {
                if e.is::<http_body_util::LengthLimitError>() {
                    FirewallError::ValidationFailed {
                        errors: vec![format!(
                            "the result is over {} MiB: select fewer series, or a longer step",
                            MAX_REPLY >> 20
                        )],
                    }
                } else {
                    unavailable(e.to_string())
                }
            })?
            .to_bytes();
        answer(&bytes)
    };
    tokio::time::timeout(TIMEOUT, run)
        .await
        .unwrap_or_else(|_| Err(unavailable("no answer in time")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_are_encoded() {
        assert_eq!(
            form(&[("query", "rate(x{a=\"b c\"}[5m])"), ("time", "1.5")]),
            "query=rate%28x%7Ba%3D%22b+c%22%7D%5B5m%5D%29&time=1.5"
        );
    }

    #[test]
    fn answers_and_errors() {
        let r = answer(
            br#"{"status":"success","data":{"resultType":"vector","result":[{"metric":{"job":"sparewall"},"value":[1,"1"]}]},"infos":["note"]}"#,
        )
        .unwrap();
        assert_eq!(r.result_type, "vector");
        assert_eq!(r.result[0]["metric"]["job"], "sparewall");
        assert_eq!(r.warnings, ["note"]);
        let e = answer(br#"{"status":"error","errorType":"bad_data","error":"parse error"}"#)
            .unwrap_err();
        assert!(matches!(e, FirewallError::ValidationFailed { .. }), "{e}");
        let e = answer(br#"{"status":"error","errorType":"timeout","error":"query timed out"}"#)
            .unwrap_err();
        assert!(
            matches!(&e, FirewallError::ServiceUnavailable { service, .. } if service == "prometheus"),
            "{e}"
        );
    }
}
