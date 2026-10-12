//! DHCP takeover by the VRRP master (design: "DHCP HA").
//!
//! Kea's hot-standby standby declares its partner down only after it has
//! seen `max-unacked-clients` distinct clients go unanswered, which on a
//! small network may never happen. VRRP already decides which node is
//! alive, over every client VLAN: when this node is the master and the
//! peer is unreachable over the sync tunnel as well, the coordinator has
//! Kea serve the primary's scope (`ha-scopes`). A cut sync VLAN alone
//! leaves the roles alone, so it never triggers this. When the peer
//! returns, Kea's own state negotiation resets the scopes.

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sparewall_config::model::DhcpHa;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;

use crate::peer::Pair;
use crate::service::{Core, with_core_raw};

pub const CONTROL_SOCKET: &str = "/run/kea/kea4-ctrl-socket";
/// How long the peer must be gone before taking over, so a node that is
/// merely restarting its coordinator is not mistaken for a dead one.
const GRACE: Duration = Duration::from_secs(15);

/// Send one command to Kea's control socket.
async fn kea(command: Value) -> Result<Value, String> {
    let mut s = tokio::net::UnixStream::connect(CONTROL_SOCKET)
        .await
        .map_err(|e| format!("{CONTROL_SOCKET}: {e}"))?;
    s.write_all(command.to_string().as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    // Kea answers and closes the connection.
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf))
        .await
        .map_err(|_| "kea did not answer".to_string())?
        .map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&buf).map_err(|e| format!("kea: {e}"))?;
    match v["result"].as_i64() {
        Some(0) => Ok(v),
        _ => Err(format!("kea: {}", v["text"].as_str().unwrap_or("error"))),
    }
}

/// Whether the local Kea already serves `primary`'s scope.
fn serving(status: &Value, primary: &str) -> bool {
    let local = &status["arguments"]["high-availability"][0]["ha-servers"]["local"];
    local["state"] == "partner-down"
        || local["scopes"]
            .as_array()
            .is_some_and(|s| s.iter().any(|x| x == primary))
}

pub async fn takeover_loop(core: Core, events: broadcast::Sender<Value>, pair: Pair) {
    let mut down_since: Option<Instant> = None;
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let (master, unreachable) = {
            let p = pair.lock().unwrap_or_else(|p| p.into_inner());
            (
                p.role.as_deref() == Some("MASTER"),
                p.paired && !p.reachable,
            )
        };
        if !(master && unreachable) {
            down_since = None;
            continue;
        }
        let since = *down_since.get_or_insert_with(Instant::now);
        if since.elapsed() < GRACE {
            continue;
        }
        let Ok(primary) = with_core_raw(&core, &events, |c| {
            Ok(c.active_document()?.and_then(|d| {
                let dhcp = d.dhcp.as_ref()?;
                (d.is_pair() && dhcp.ha.unwrap_or(DhcpHa::HotStandby) == DhcpHa::HotStandby)
                    .then(|| d.cluster.nodes.first().cloned())
                    .flatten()
            }))
        })
        .await
        else {
            continue;
        };
        let Some(primary) = primary else { continue };
        let status = match kea(json!({"command": "status-get"})).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "kea status");
                continue;
            }
        };
        if serving(&status, &primary) {
            continue;
        }
        match kea(json!({"command": "ha-scopes", "arguments": {"scopes": [primary]}})).await {
            Ok(_) => {
                tracing::warn!(
                    scope = %primary,
                    "the peer is down and this node is the VRRP master: serving all DHCP clients"
                );
                let _ = events.send(json!({"type": "dhcp-takeover", "scope": primary}));
            }
            Err(e) => tracing::warn!(error = %e, "cannot take over DHCP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serving_scope() {
        let st = |state: &str, scopes: Value| {
            json!({"result": 0, "arguments": {"high-availability": [
                {"ha-servers": {"local": {"state": state, "scopes": scopes}}}
            ]}})
        };
        assert!(!serving(&st("communication-interrupted", json!([])), "fw1"));
        assert!(serving(&st("hot-standby", json!(["fw1"])), "fw1"));
        assert!(serving(&st("partner-down", json!([])), "fw1"));
        assert!(!serving(&json!({"result": 0}), "fw1"));
    }
}
