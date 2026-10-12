//! Rolling, health-gated OS upgrades (design: "Upgrade policy").
//!
//! Run on the pair's master: the standby stages the new image (bootc, with
//! the containers signature policy enforced) and reboots; once it is back,
//! healthy and in sync, the master hands over the gateway addresses and
//! upgrades itself. A standalone node stages and reboots, accepting one
//! reboot of downtime. A failed gate stops the upgrade; `bootc rollback`
//! returns a node.

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sparewall_api::{PEER_PROTOCOL, PeerProxy, PeerUpgradeProxy};
use tokio::sync::broadcast;

use crate::peer::{Link, Pair, connect, tunnel_addrs};
use crate::service::{Core, with_core_raw};

pub const IMAGE_REPO: &str = "ghcr.io/sparewall/sparewall";
pub const DEFAULT_CHANNEL: &str = "testing";

/// Run a host command outside this service's sandbox.
pub fn host_run(cmd: &str, args: &[&str]) -> Result<String, String> {
    sparewall_core::linux::host_run(cmd, args).map_err(|e| e.to_string())
}

fn bootc_status() -> Option<Value> {
    serde_json::from_str(&host_run("bootc", &["status", "--format=json"]).ok()?).ok()
}

/// The image reference the node tracks, e.g. `ghcr.io/sparewall/sparewall:testing`.
pub fn tracked_ref() -> Option<String> {
    bootc_status()?["spec"]["image"]["image"]
        .as_str()
        .map(str::to_string)
}

/// Split a reference into repository and tag (`None` for a digest or no tag).
fn split_ref(r: &str) -> (&str, Option<&str>) {
    let r = r.split_once('@').map_or(r, |(repo, _)| repo);
    match r.rsplit_once(':') {
        // A colon after the last '/' starts the tag; before it, a port.
        Some((repo, tag)) if !tag.contains('/') => (repo, Some(tag)),
        _ => (r, None),
    }
}

/// The image to move to: an explicit `image`, else the requested channel,
/// else the document's `updates.channel`, else the tag already tracked. A
/// channel is a tag of the repository the node tracks (so a node installed
/// from a mirror stays on it).
pub fn target_ref(
    image: Option<&str>,
    channel: Option<&str>,
    doc_channel: Option<&str>,
    tracked: Option<&str>,
) -> String {
    if let Some(i) = image {
        return i.to_string();
    }
    let (repo, tracked_tag) = tracked.map_or((IMAGE_REPO, None), split_ref);
    let tag = channel
        .or(doc_channel)
        .or(tracked_tag)
        .unwrap_or(DEFAULT_CHANNEL);
    format!("{repo}:{tag}")
}

/// Stage `image` for the next boot. Returns the staged image, or `None`
/// when the node already runs the newest one.
pub fn stage(image: &str) -> Result<Option<String>, String> {
    host_run("bootc", &["switch", "--enforce-container-sigpolicy", image])?;
    let st = bootc_status().ok_or("cannot read bootc status")?;
    let staged = &st["status"]["staged"]["image"];
    Ok(staged["imageDigest"]
        .as_str()
        .map(|d| format!("{}@{d}", staged["image"]["image"].as_str().unwrap_or(image))))
}

/// Reboot in a few seconds, after the reply has gone out.
pub fn reboot_soon() -> Result<(), String> {
    host_run(
        "systemd-run",
        &["--on-active=5s", "--", "systemctl", "reboot"],
    )
    .map(|_| ())
}

fn event(events: &broadcast::Sender<Value>, step: &str, detail: impl Into<String>) {
    let detail = detail.into();
    tracing::info!(step, %detail, "upgrade");
    let _ = events.send(json!({"type": "upgrade", "step": step, "detail": detail}));
}

/// Plan an upgrade and check its preconditions; the work happens in
/// [`run`].
pub async fn plan(
    core: &Core,
    events: &broadcast::Sender<Value>,
    pair: &Pair,
    channel: Option<String>,
    image: Option<String>,
) -> Result<(String, Option<Link>, Vec<String>), String> {
    let (doc, node) = with_core_raw(core, events, |c| {
        Ok((c.active_document()?, c.node().to_string()))
    })
    .await
    .map_err(|e| e.to_string())?;
    let doc_channel = doc
        .as_ref()
        .and_then(|d| d.updates.as_ref())
        .and_then(|u| u.channel.clone());
    let tracked = tokio::task::spawn_blocking(tracked_ref)
        .await
        .map_err(|e| e.to_string())?;
    let target = target_ref(
        image.as_deref(),
        channel.as_deref(),
        doc_channel.as_deref(),
        tracked.as_deref(),
    );
    let Some((own, peer_addr, peer)) = doc.as_ref().and_then(|d| tunnel_addrs(d, &node)) else {
        return Ok((
            target.clone(),
            None,
            vec![
                format!("stage {target} on {node}"),
                "reboot (one reboot of downtime)".into(),
            ],
        ));
    };
    let p = pair.lock().unwrap_or_else(|p| p.into_inner()).clone();
    if p.state.as_ref().map(|s| s.name()) != Some("in-sync") {
        return Err(format!(
            "the pair is not in sync ({:?}); upgrade only an in-sync pair",
            p.state.map(|s| s.name())
        ));
    }
    if p.role.as_deref() != Some("MASTER") {
        return Err(format!(
            "run the upgrade on the master; this node is {}",
            p.role.unwrap_or("unknown".into())
        ));
    }
    Ok((
        target.clone(),
        Some(Link {
            own,
            peer: peer_addr,
        }),
        vec![
            format!("stage {target} on {peer} (standby) and reboot it"),
            format!("wait for {peer} to return healthy and in sync"),
            format!("hand the gateway addresses to {peer}"),
            format!("stage {target} on {node} and reboot it"),
        ],
    ))
}

/// Carry out a planned upgrade.
pub async fn run(core: Core, events: broadcast::Sender<Value>, target: String, peer: Option<Link>) {
    let r = async {
        if let Some(addr) = peer {
            upgrade_peer(&core, &events, addr, &target).await?;
            event(
                &events,
                "failover",
                "stopping keepalived to hand over the gateway addresses",
            );
            host_run("systemctl", &["stop", "keepalived.service"])?;
            let node = with_core_raw(&core, &events, |c| Ok(c.node().to_string()))
                .await
                .map_err(|e| e.to_string())?;
            wait_peer_master(addr, &node).await?;
        }
        event(&events, "stage", format!("staging {target} on this node"));
        let staged = tokio::task::spawn_blocking({
            let t = target.clone();
            move || stage(&t)
        })
        .await
        .map_err(|e| e.to_string())??;
        match staged {
            None if peer.is_none() => {
                event(&events, "done", "already running the newest image");
                Ok(())
            }
            _ => {
                event(&events, "reboot", "rebooting into the new image");
                reboot_soon()
            }
        }
    }
    .await;
    if let Err(e) = r {
        event(&events, "failed", format!("upgrade stopped: {e}"));
        // Take the addresses back if we gave them up.
        let _ = host_run("systemctl", &["start", "keepalived.service"]);
    }
}

async fn upgrade_peer(
    core: &Core,
    events: &broadcast::Sender<Value>,
    addr: Link,
    target: &str,
) -> Result<(), String> {
    let node = with_core_raw(core, events, |c| Ok(c.node().to_string()))
        .await
        .map_err(|e| e.to_string())?;
    let before = connect(addr)
        .await?
        .hello(&node, PEER_PROTOCOL)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    if before.image.is_none() {
        return Err(format!("{} does not report its image yet", before.node));
    }
    event(
        events,
        "stage-peer",
        format!("staging {target} on {}", before.node),
    );
    connect(addr)
        .await?
        .upgrade(target)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    // Gate: the peer comes back on a different image, healthy, in sync.
    let ours = with_core_raw(core, events, |c| Ok(c.view()?.desired))
        .await
        .map_err(|e| e.to_string())?;
    let t0 = Instant::now();
    tokio::time::sleep(Duration::from_secs(30)).await;
    loop {
        if t0.elapsed() > Duration::from_secs(20 * 60) {
            return Err(format!(
                "{} did not come back healthy within 20 minutes; run bootc rollback there",
                before.node
            ));
        }
        if let Ok(mut c) = connect(addr).await
            && let Ok(Ok(h)) = c.hello(&node, PEER_PROTOCOL).await
        {
            let healthy = h.health.as_deref() != Some("failed");
            if h.image.is_some()
                && h.image != before.image
                && healthy
                && h.desired == ours
                && h.applied.as_deref() == Some(ours.as_str())
            {
                event(
                    events,
                    "peer-ready",
                    format!("{} is back on {}", h.node, h.image.unwrap_or_default()),
                );
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn wait_peer_master(addr: Link, node: &str) -> Result<(), String> {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(60) {
        if let Ok(mut c) = connect(addr).await
            && let Ok(Ok(h)) = c.hello(node, PEER_PROTOCOL).await
            && h.role.as_deref() == Some("MASTER")
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err("the peer did not become master".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_from_channel() {
        let tracked = "ghcr.io/sparewall/sparewall:testing";
        let ghcr = Some(tracked);
        assert_eq!(
            target_ref(None, Some("stable"), Some("testing"), ghcr),
            "ghcr.io/sparewall/sparewall:stable"
        );
        assert_eq!(
            target_ref(None, None, Some("testing"), None),
            "ghcr.io/sparewall/sparewall:testing"
        );
        assert_eq!(target_ref(None, None, None, ghcr), tracked);
        // A mirror with a port keeps its repository.
        assert_eq!(
            target_ref(
                None,
                Some("stable"),
                None,
                Some("mirror:5000/fw/sparewall:testing")
            ),
            "mirror:5000/fw/sparewall:stable"
        );
        assert_eq!(
            target_ref(None, None, None, Some("mirror:5000/sparewall@sha256:ab")),
            "mirror:5000/sparewall:testing"
        );
        assert_eq!(
            target_ref(Some("r/x:1"), Some("stable"), None, ghcr),
            "r/x:1"
        );
    }
}
