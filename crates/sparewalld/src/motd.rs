//! The login banner (#83): a `pam_motd` drop-in summarizing this node's
//! health, so a degraded node says so to whoever logs in. Written when
//! the summary changes, not on each login, so a login never waits on the
//! coordinator; it carries the time it was written, and is removed when
//! the coordinator stops.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use sparewall_api::StatusReply;
use tokio::sync::broadcast;

use crate::peer::Pair;
use crate::service::{Core, status, with_core};

/// Where pam_motd picks it up.
pub const PATH: &str = "/run/motd.d/50-sparewall";

/// The banner for a status: one line when all is well, else one line per
/// check that is not `ok`, with its message (which says how to act).
pub fn render(s: &StatusReply) -> String {
    let level = s.health["level"].as_str().unwrap_or("unknown");
    let generation = match s.sync.get("pending").filter(|p| !p.is_null()) {
        Some(p) => format!("generation {} (pending confirmation)", p["id"]),
        None => format!("generation {}", s.sync["active"]),
    };
    let mut out = format!(
        "Sparewall {}: {}, {generation}, health {level}\n",
        s.node, s.role
    );
    for c in s.health["checks"].as_array().into_iter().flatten() {
        let l = c["level"].as_str().unwrap_or("?");
        if l != "ok" {
            out.push_str(&format!(
                "  {:<11} {l:<9} {}\n",
                c["name"].as_str().unwrap_or("?"),
                c["message"].as_str().unwrap_or("")
            ));
        }
    }
    if level != "ok" {
        out.push_str("  (sparewall health -v for details)\n");
    }
    out
}

/// Keep the banner at `path` current.
pub async fn motd_loop(core: Core, events: broadcast::Sender<Value>, pair: Pair, path: PathBuf) {
    let mut last = String::new();
    loop {
        let p = pair.lock().unwrap_or_else(|p| p.into_inner()).clone();
        match with_core(&core, &events, move |c| status(c, &p)).await {
            Ok(s) => {
                let text = render(&s);
                if text != last {
                    let stamped = format!(
                        "{}  (as of {})\n",
                        text.trim_end(),
                        jiff::Timestamp::now().strftime("%Y-%m-%d %H:%M:%S UTC")
                    );
                    // In place, not renamed into place: a file made
                    // elsewhere would keep a label login sessions cannot
                    // read. It is a single small write.
                    match std::fs::write(&path, stamped) {
                        Ok(()) => last = text,
                        Err(e) => {
                            tracing::warn!(path = %path.display(), error = %e, "cannot write the login banner")
                        }
                    }
                }
            }
            Err(e) => tracing::debug!(error = %e, "login banner status"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Remove the banner, so a stopped coordinator leaves no stale one.
pub fn remove(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn status(health: Value, pending: Value) -> StatusReply {
        StatusReply {
            node: "fw1".into(),
            role: "MASTER".into(),
            sync: json!({"active": 4, "pending": pending}),
            links: json!({}),
            vrrp: json!({}),
            conntrack: json!({}),
            services: json!({}),
            tls: json!({}),
            health,
        }
    }

    #[test]
    fn one_line_when_ok_and_the_problems_otherwise() {
        let ok = status(
            json!({"level": "ok", "checks": [{"name": "nft", "level": "ok", "message": "53 chains"}]}),
            Value::Null,
        );
        assert_eq!(
            render(&ok),
            "Sparewall fw1: MASTER, generation 4, health ok\n"
        );
        let bad = status(
            json!({"level": "degraded", "checks": [
                {"name": "nft", "level": "ok", "message": "53 chains"},
                {"name": "selinux", "level": "degraded", "message": "2 denials; acknowledge with: sparewall health ack selinux"},
            ]}),
            json!({"id": 5, "reverts_in": 87}),
        );
        let text = render(&bad);
        assert!(text.starts_with(
            "Sparewall fw1: MASTER, generation 5 (pending confirmation), health degraded\n"
        ));
        assert!(text.contains(
            "  selinux     degraded  2 denials; acknowledge with: sparewall health ack selinux\n"
        ));
        assert!(!text.contains("nft"));
        // The countdown is left out, so the file is not rewritten each second.
        assert!(!text.contains("87"));
    }
}
