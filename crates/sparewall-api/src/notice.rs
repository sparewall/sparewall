//! One-line notices drawn from a status reply, shared by `sparewall status`
//! and the login banner (#189). They inform: none of them changes health
//! or an exit code.

use serde_json::Value;

use crate::StatusReply;

/// What the background update check (#188) found, if it offers anything:
/// `0.4.1 available (running 0.4.0); sparewall upgrade`.
pub fn update(s: &StatusReply) -> Option<String> {
    let u = s.update.as_ref()?;
    let running = u["running"].as_str().unwrap_or("?");
    let what = match u["available"].as_str()? {
        "newer" => format!(
            "{} available (running {running})",
            u["version"].as_str().unwrap_or("a newer version")
        ),
        "rebuild" => format!("a rebuild of {running} available"),
        "different" => format!(
            "a different image available on {}, whose version cannot be read (running {running})",
            u["target"].as_str().unwrap_or("the channel")
        ),
        _ => return None,
    };
    Some(format!("{what}; sparewall upgrade"))
}

/// A pair whose nodes run different images: usually an upgrade that
/// stopped halfway (docs/operations.md, Upgrades).
pub fn mixed_images(s: &StatusReply) -> Option<String> {
    if s.sync["peer_reachable"].as_bool() != Some(true) {
        return None;
    }
    let digest = |v: &Value| {
        v.as_str()
            .map(|i| i.rsplit_once('@').map_or(i, |(_, d)| d).to_string())
    };
    let (ours, peer) = (digest(&s.sync["image"])?, digest(&s.sync["peer_image"])?);
    (ours != peer).then(|| {
        format!(
            "the nodes run different images (this node {}, {} {}): if an upgrade stopped halfway, sparewall upgrade finishes it",
            short(&ours),
            s.sync["peer"].as_str().unwrap_or("its peer"),
            short(&peer)
        )
    })
}

fn short(digest: &str) -> &str {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    hex.get(..12).unwrap_or(hex)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn status(sync: Value, update: Option<Value>) -> StatusReply {
        StatusReply {
            node: "fw1".into(),
            role: "MASTER".into(),
            sync,
            links: json!({}),
            vrrp: json!({}),
            conntrack: json!({}),
            services: json!({}),
            tls: json!({}),
            health: json!({}),
            update,
        }
    }

    #[test]
    fn update_lines() {
        let line = |u: Value| update(&status(json!({}), Some(u)));
        assert_eq!(
            line(
                json!({"enabled": true, "running": "0.4.0", "available": "newer", "version": "0.4.1"})
            ),
            Some("0.4.1 available (running 0.4.0); sparewall upgrade".into())
        );
        assert_eq!(
            line(
                json!({"enabled": true, "running": "0.4.0", "available": "rebuild", "version": "0.4.0"})
            ),
            Some("a rebuild of 0.4.0 available; sparewall upgrade".into())
        );
        assert_eq!(
            line(
                json!({"enabled": true, "running": "0.4.0", "available": "different",
                        "target": "mirror.example:5000/sparewall:stable"})
            ),
            Some(
                "a different image available on mirror.example:5000/sparewall:stable, \
                 whose version cannot be read (running 0.4.0); sparewall upgrade"
                    .into()
            )
        );
        // Nothing to offer, not checked yet, the check off, an older node.
        assert_eq!(
            line(json!({"enabled": true, "running": "0.4.0", "available": "none"})),
            None
        );
        assert_eq!(line(json!({"enabled": true, "running": "0.4.0"})), None);
        assert_eq!(line(json!({"enabled": false, "running": "0.4.0"})), None);
        assert_eq!(update(&status(json!({}), None)), None);
    }

    #[test]
    fn mixed_image_line() {
        let a = "ghcr.io/sparewall/sparewall:stable@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "ghcr.io/sparewall/sparewall@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let line = |image: &str, peer: &str, reachable: bool| {
            mixed_images(&status(
                json!({"image": image, "peer": "fw2", "peer_image": peer, "peer_reachable": reachable}),
                None,
            ))
        };
        assert_eq!(
            line(a, b, true),
            Some(
                "the nodes run different images (this node aaaaaaaaaaaa, fw2 bbbbbbbbbbbb): \
                 if an upgrade stopped halfway, sparewall upgrade finishes it"
                    .into()
            )
        );
        // The same digest under another reference is the same image.
        let a2 = "10.0.2.2:5000/sparewall:candidate@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(line(a, a2, true), None);
        // An unreachable peer's image is stale; a standalone node has none.
        assert_eq!(line(a, b, false), None);
        assert_eq!(mixed_images(&status(json!({"image": a}), None)), None);
    }
}
