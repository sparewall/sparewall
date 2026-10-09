//! Rolling, health-gated OS upgrades (design: "Upgrade policy").
//!
//! Run on the pair's master: the standby stages the new image (bootc, with
//! the containers signature policy enforced) and reboots; once it is back,
//! healthy and in sync, the master hands over the gateway addresses and
//! upgrades itself. A standalone node stages and reboots, accepting one
//! reboot of downtime. A failed gate stops the upgrade; `bootc rollback`
//! returns a node.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sparewall_api::{PEER_PROTOCOL, PeerProxy, PeerUpgradeProxy};
use tokio::sync::broadcast;

use crate::peer::{Pair, connect, tunnel_addrs};
use crate::service::{Core, with_core_raw};

pub const IMAGE_REPO: &str = "ghcr.io/sparewall/sparewall";
pub const DEFAULT_CHANNEL: &str = "testing";

/// Run a host command outside this service's sandbox.
pub fn host_run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let under_systemd = std::env::var_os("INVOCATION_ID").is_some();
    let mut c = if under_systemd {
        let mut c = std::process::Command::new("systemd-run");
        c.args([
            "--wait",
            "--pipe",
            "--quiet",
            "--collect",
            "--service-type=exec",
            "--",
            cmd,
        ]);
        c
    } else {
        std::process::Command::new(cmd)
    };
    let out = c
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
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

/// The image to move to: the requested channel, else the document's
/// `updates.channel`, else the tag already tracked.
pub fn target_ref(channel: Option<&str>, doc_channel: Option<&str>) -> String {
    let tracked = tracked_ref();
    let tag = channel
        .or(doc_channel)
        .map(str::to_string)
        .or_else(|| {
            tracked
                .as_deref()
                .and_then(|t| t.rsplit_once(':'))
                .map(|(_, t)| t.to_string())
        })
        .unwrap_or_else(|| DEFAULT_CHANNEL.into());
    format!("{IMAGE_REPO}:{tag}")
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
) -> Result<(String, Option<IpAddr>, Vec<String>), String> {
    let (doc, node) = with_core_raw(core, events, |c| {
        Ok((c.active_document()?, c.node().to_string()))
    })
    .await
    .map_err(|e| e.to_string())?;
    let doc_channel = doc
        .as_ref()
        .and_then(|d| d.updates.as_ref())
        .and_then(|u| u.channel.clone());
    let target = target_ref(channel.as_deref(), doc_channel.as_deref());
    let Some((_, peer_addr, peer)) = doc.as_ref().and_then(|d| tunnel_addrs(d, &node)) else {
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
        Some(peer_addr),
        vec![
            format!("stage {target} on {peer} (standby) and reboot it"),
            format!("wait for {peer} to return healthy and in sync"),
            format!("hand the gateway addresses to {peer}"),
            format!("stage {target} on {node} and reboot it"),
        ],
    ))
}

/// Carry out a planned upgrade.
pub async fn run(
    core: Core,
    events: broadcast::Sender<Value>,
    target: String,
    peer: Option<IpAddr>,
) {
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
    addr: IpAddr,
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
            if h.image != before.image
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

async fn wait_peer_master(addr: IpAddr, node: &str) -> Result<(), String> {
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
        assert_eq!(
            target_ref(Some("stable"), Some("testing")),
            "ghcr.io/sparewall/sparewall:stable"
        );
        assert_eq!(
            target_ref(None, Some("testing")),
            "ghcr.io/sparewall/sparewall:testing"
        );
    }
}
