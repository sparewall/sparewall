//! Rolling, health-gated OS upgrades (design: "Upgrade policy").
//!
//! Run by the pair's master: the standby stages the new image (bootc, with
//! the containers signature policy enforced) and reboots; once it is back,
//! healthy and in sync, the master hands over the gateway addresses and
//! upgrades itself. Started on the backup, the request goes to the master,
//! whose progress the backup relays as its own events. A standalone node
//! stages and reboots, accepting one reboot of downtime. A failed gate
//! stops the upgrade; `bootc rollback` returns a node.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures_util::{StreamExt, pin_mut};
use serde_json::{Value, json};
use sparewall_api::{HelloReply, PEER_PROTOCOL, PeerProxy, PeerUpgradeProxy};
use sparewall_core::host::{HostUpgrade, UpgradeHost, bootc_status};
use tokio::sync::{broadcast, oneshot};

use crate::peer::{Link, Pair, connect, tunnel_addrs};
use crate::service::{Core, with_core_raw};

/// Set once this node has staged an upgrade and is about to reboot.
pub static REBOOTING: AtomicBool = AtomicBool::new(false);

pub const IMAGE_REPO: &str = "ghcr.io/sparewall/sparewall";
pub const DEFAULT_CHANNEL: &str = "testing";

/// Run a host command outside this service's sandbox.
pub fn host_run(cmd: &str, args: &[&str]) -> Result<String, String> {
    sparewall_core::linux::host_run(cmd, args).map_err(|e| e.to_string())
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

/// Wait for keepalived's stop. The job is queued without waiting on it
/// and its state polled: waiting holds a D-Bus call open across the
/// transition, and losing it ("D-Bus connection terminated while waiting
/// for jobs") stopped upgrades whose keepalived had in fact stopped (#29).
/// Even if queueing the stop reported an error, the unit may have
/// stopped; only a unit still running at the deadline fails.
async fn stop_keepalived(host: &Arc<dyn UpgradeHost>, t: &Timing) -> Result<(), String> {
    let queued = blocking(host, |h| h.stop_keepalived()).await;
    let deadline = Instant::now() + t.stop_timeout;
    loop {
        let last = match blocking(host, |h| h.keepalived_state()).await {
            Ok(s) if matches!(s.trim(), "inactive" | "failed") => return Ok(()),
            Ok(s) => s.trim().to_string(),
            Err(e) => e,
        };
        if Instant::now() >= deadline {
            let why = match queued {
                Err(e) => format!("stopping it failed ({e}) and it is still {last}"),
                Ok(()) => format!("it is still {last} after {}s", t.stop_timeout.as_secs()),
            };
            return Err(format!("keepalived did not stop: {why}"));
        }
        tokio::time::sleep(t.stop_poll).await;
    }
}

async fn blocking<T: Send + 'static>(
    host: &Arc<dyn UpgradeHost>,
    f: impl FnOnce(&dyn UpgradeHost) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let h = host.clone();
    tokio::task::spawn_blocking(move || f(&*h))
        .await
        .map_err(|e| e.to_string())?
}

/// The peer, as the upgrade sees it through the sync tunnel.
#[allow(async_fn_in_trait)]
pub trait UpgradePeer {
    async fn hello(&self) -> Result<HelloReply, String>;
    /// Ask the peer to stage `image` and reboot.
    async fn upgrade(&self, image: &str) -> Result<(), String>;
}

/// The peer over the sync tunnel.
pub struct LinkPeer {
    pub link: Link,
    /// This node's name, which `Hello` carries.
    pub node: String,
}

impl UpgradePeer for LinkPeer {
    async fn hello(&self) -> Result<HelloReply, String> {
        connect(self.link)
            .await?
            .hello(&self.node, PEER_PROTOCOL)
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())
    }

    async fn upgrade(&self, image: &str) -> Result<(), String> {
        connect(self.link)
            .await?
            .upgrade(image)
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())
            .map(|_| ())
    }
}

/// How long each gate waits.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Before asking the rebooting peer at all.
    pub peer_settle: Duration,
    /// For the peer to come back healthy and in sync on the new image.
    pub peer_timeout: Duration,
    pub peer_poll: Duration,
    pub stop_timeout: Duration,
    pub stop_poll: Duration,
    /// For the peer to take over the gateway addresses.
    pub master_timeout: Duration,
    pub master_poll: Duration,
    /// Tries at downloading this node's image, and the wait between them.
    pub download_tries: u32,
    pub download_retry: Duration,
}

pub const TIMING: Timing = Timing {
    peer_settle: Duration::from_secs(30),
    peer_timeout: Duration::from_secs(20 * 60),
    peer_poll: Duration::from_secs(10),
    stop_timeout: Duration::from_secs(30),
    stop_poll: Duration::from_millis(500),
    master_timeout: Duration::from_secs(60),
    master_poll: Duration::from_secs(2),
    download_tries: 3,
    download_retry: Duration::from_secs(15),
};

fn event(events: &broadcast::Sender<Value>, step: &str, detail: impl Into<String>) {
    let detail = detail.into();
    tracing::info!(step, %detail, "upgrade");
    let _ = events.send(json!({"type": "upgrade", "step": step, "detail": detail}));
}

/// A planned upgrade.
pub enum Planned {
    /// Run it here: upgrade `peer` first, if there is one.
    Run {
        target: String,
        peer: Option<Link>,
        steps: Vec<String>,
    },
    /// This node is the backup: the master runs it.
    Forward { link: Link, master: String },
}

/// Plan an upgrade and check its preconditions; the work happens in
/// [`run`], or on the master.
pub async fn plan(
    core: &Core,
    events: &broadcast::Sender<Value>,
    pair: &Pair,
    channel: Option<String>,
    image: Option<String>,
) -> Result<Planned, String> {
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
        return Ok(Planned::Run {
            target: target.clone(),
            peer: None,
            steps: vec![
                format!("stage {target} on {node}"),
                "reboot (one reboot of downtime)".into(),
            ],
        });
    };
    let link = Link {
        own,
        peer: peer_addr,
    };
    let p = pair.lock().unwrap_or_else(|p| p.into_inner()).clone();
    if p.state.as_ref().map(|s| s.name()) != Some("in-sync") {
        return Err(format!(
            "the pair is not in sync ({:?}); upgrade only an in-sync pair",
            p.state.map(|s| s.name())
        ));
    }
    match p.role.as_deref() {
        Some("MASTER") => {}
        Some("BACKUP") => return Ok(Planned::Forward { link, master: peer }),
        role => {
            return Err(format!(
                "run the upgrade on the master; this node is {}",
                role.unwrap_or("unknown")
            ));
        }
    }
    Ok(Planned::Run {
        target: target.clone(),
        peer: Some(link),
        steps: vec![
            format!("download {target} on {node}, without applying it"),
            format!("stage {target} on {peer} (standby) and reboot it"),
            format!("wait for {peer} to return healthy and in sync"),
            format!("hand the gateway addresses to {peer}, unless {node} already runs {target}"),
            format!("apply the downloaded image on {node} and reboot it"),
        ],
    })
}

/// Plan an upgrade and start it. On the backup, `forward` sends it to the
/// master (a master that is asked never forwards it back). Returns the
/// plan, in words.
pub async fn start(
    core: &Core,
    events: &broadcast::Sender<Value>,
    pair: &Pair,
    channel: Option<String>,
    image: Option<String>,
    forward: bool,
) -> Result<Vec<String>, String> {
    match plan(core, events, pair, channel.clone(), image.clone()).await? {
        Planned::Run {
            target,
            peer,
            steps,
        } => {
            tokio::spawn(run(core.clone(), events.clone(), target, peer));
            Ok(steps)
        }
        Planned::Forward { link, master } if forward => {
            forward_to(link, master, channel, image, events.clone()).await
        }
        Planned::Forward { master, .. } => Err(format!(
            "{master} asked this node to run the upgrade, but this node is the backup"
        )),
    }
}

/// Whether an upgrade event is its last.
pub fn ends(event: &Value) -> bool {
    matches!(event["step"].as_str(), Some("failed" | "done" | "reboot"))
}

type Started = oneshot::Sender<Result<Vec<String>, String>>;

/// Have the master run the upgrade, and relay its events here, named,
/// until it ends or the connection does (when this node reboots).
async fn forward_to(
    link: Link,
    master: String,
    channel: Option<String>,
    image: Option<String>,
    events: broadcast::Sender<Value>,
) -> Result<Vec<String>, String> {
    let (tx, rx) = oneshot::channel();
    let name = master.clone();
    // The proxy's stream is not Send: the relay runs on a thread of its
    // own.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        rt.block_on(async move {
            let mut tx = Some(tx);
            let why = relay(link, &name, channel, image, &events, &mut tx).await;
            match tx.take() {
                // The master never answered with a plan.
                Some(t) => {
                    let _ = t.send(Err(why));
                }
                // This node going down for its own upgrade ends the relay too.
                None if why.is_empty() || REBOOTING.load(Ordering::SeqCst) => {}
                None => event(
                    &events,
                    "failed",
                    format!("lost {name}, which runs the upgrade: {why}"),
                ),
            }
        })
    });
    rx.await
        .map_err(|_| format!("{master} did not answer"))?
        .map_err(|e| format!("{master} did not start the upgrade: {e}"))
}

/// The relay itself. Sends the plan on `tx` (taking it), then the events;
/// returns why it stopped, or "" at the upgrade's end.
async fn relay(
    link: Link,
    name: &str,
    channel: Option<String>,
    image: Option<String>,
    events: &broadcast::Sender<Value>,
    tx: &mut Option<Started>,
) -> String {
    let mut conn = match connect(link).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let stream = match conn
        .start_upgrade(channel.as_deref(), image.as_deref())
        .await
    {
        Ok(s) => s,
        Err(e) => return e.to_string(),
    };
    pin_mut!(stream);
    while let Some(item) = stream.next().await {
        let ev = match item {
            Ok(Ok(r)) => r.event,
            Ok(Err(e)) => return e.to_string(),
            Err(e) => return e.to_string(),
        };
        if ev["type"] != "upgrade" {
            continue;
        }
        let detail = ev["detail"].as_str().unwrap_or("");
        if let Some(t) = tx.take() {
            if ev["step"] != "plan" {
                *tx = Some(t);
                return if detail.is_empty() { "refused" } else { detail }.to_string();
            }
            let steps = ev["plan"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect();
            let _ = t.send(Ok(steps));
            continue;
        }
        event(
            events,
            ev["step"].as_str().unwrap_or(""),
            format!("{name}: {detail}"),
        );
        if ends(&ev) {
            return String::new();
        }
    }
    "the connection closed".into()
}

/// Carry out a planned upgrade.
pub async fn run(core: Core, events: broadcast::Sender<Value>, target: String, peer: Option<Link>) {
    let ids = with_core_raw(&core, &events, |c| {
        Ok((c.node().to_string(), c.view()?.desired))
    })
    .await;
    let (node, ours) = match ids {
        Ok(v) => v,
        Err(e) => {
            event(&events, "failed", format!("upgrade stopped: {e}"));
            return;
        }
    };
    let peer = peer.map(|link| LinkPeer { link, node });
    let host: Arc<dyn UpgradeHost> = Arc::new(HostUpgrade);
    let _ = run_with(&host, peer.as_ref(), &ours, &target, &events, &TIMING).await;
}

/// The upgrade, against any host and peer. `ours` is this node's desired
/// configuration hash, which the peer must be running when it returns.
/// Every gate that fails stops the upgrade; if this node had stopped
/// keepalived, it starts it again to take the addresses back.
pub async fn run_with<P: UpgradePeer>(
    host: &Arc<dyn UpgradeHost>,
    peer: Option<&P>,
    ours: &str,
    target: &str,
    events: &broadcast::Sender<Value>,
    t: &Timing,
) -> Result<(), String> {
    let mut handed_over = false;
    let r = async {
        let Some(p) = peer else {
            event(events, "stage", format!("staging {target} on this node"));
            let image = target.to_string();
            if blocking(host, move |h| h.stage(&image)).await?.is_none() {
                event(events, "done", "already running the newest image");
                return Ok(());
            }
            event(events, "reboot", "rebooting into the new image");
            return blocking(host, |h| h.reboot_soon()).await;
        };
        // While this node still has its own WAN: once it hands over, its
        // traffic leaves through the peer, which may not reach out yet
        // (#175, #176). Nothing after the handover needs the network.
        event(
            events,
            "download",
            format!("downloading {target} on this node, without applying it"),
        );
        let ours_new = download(host, target, t).await?;
        if ours_new.is_none() {
            // Nothing new here: if the peer runs the same image, so is
            // there. References may differ (a channel, a build tag); the
            // digest says.
            let digest = |i: &str| i.rsplit_once('@').map_or(i, |(_, d)| d).to_string();
            let booted = blocking(host, |h| Ok(h.booted())).await?;
            let peer_image = p.hello().await?.image;
            if let (Some(b), Some(pi)) = (&booted, &peer_image)
                && digest(b) == digest(pi)
            {
                event(events, "done", "both nodes already run the newest image");
                return Ok(());
            }
        }
        upgrade_peer(p, ours, target, events, t).await?;
        let Some(downloaded) = ours_new else {
            // Already on the target (a run that stopped after the
            // handover, say): only the peer needed it.
            event(
                events,
                "done",
                "this node already runs the newest image and keeps the gateway addresses",
            );
            return Ok(());
        };
        event(
            events,
            "failover",
            "stopping keepalived to hand over the gateway addresses",
        );
        handed_over = true;
        stop_keepalived(host, t).await?;
        wait_peer_master(p, t).await?;
        event(
            events,
            "stage",
            format!("applying {downloaded}, downloaded earlier, on this node"),
        );
        blocking(host, |h| h.apply_downloaded()).await?;
        event(events, "reboot", "rebooting into the new image");
        blocking(host, |h| h.reboot_soon()).await
    }
    .await;
    if let Err(e) = &r {
        event(events, "failed", format!("upgrade stopped: {e}"));
        if handed_over && let Err(e2) = blocking(host, |h| h.start_keepalived()).await {
            tracing::error!(error = %e2, "cannot start keepalived again");
        }
    }
    r
}

/// Download this node's image, a few times before giving up: nothing has
/// moved yet, so a failure only stops the run.
async fn download(
    host: &Arc<dyn UpgradeHost>,
    target: &str,
    t: &Timing,
) -> Result<Option<String>, String> {
    let mut tries = 0;
    loop {
        tries += 1;
        let image = target.to_string();
        match blocking(host, move |h| h.download(&image)).await {
            Ok(r) => return Ok(r),
            Err(e) if tries >= t.download_tries => {
                return Err(format!("cannot download {target} on this node: {e}"));
            }
            Err(e) => {
                tracing::warn!(tries, error = %e, "downloading the image failed; retrying");
                tokio::time::sleep(t.download_retry).await;
            }
        }
    }
}

async fn upgrade_peer<P: UpgradePeer>(
    peer: &P,
    ours: &str,
    target: &str,
    events: &broadcast::Sender<Value>,
    t: &Timing,
) -> Result<(), String> {
    let before = peer.hello().await?;
    if before.image.is_none() {
        return Err(format!("{} does not report its image yet", before.node));
    }
    event(
        events,
        "stage-peer",
        format!("staging {target} on {}", before.node),
    );
    peer.upgrade(target)
        .await
        .map_err(|e| format!("{} rejected the upgrade: {e}", before.node))?;
    // Gate: the peer comes back on a different image, healthy, in sync.
    let t0 = Instant::now();
    tokio::time::sleep(t.peer_settle).await;
    loop {
        if t0.elapsed() > t.peer_timeout {
            return Err(format!(
                "{} did not come back healthy within {} minutes; run bootc rollback there",
                before.node,
                t.peer_timeout.as_secs() / 60
            ));
        }
        if let Ok(h) = peer.hello().await {
            let healthy = h.health.as_deref() != Some("failed");
            if h.image.is_some()
                && h.image != before.image
                && healthy
                && h.desired == ours
                && h.applied.as_deref() == Some(ours)
            {
                event(
                    events,
                    "peer-ready",
                    format!("{} is back on {}", h.node, h.image.unwrap_or_default()),
                );
                return Ok(());
            }
        }
        tokio::time::sleep(t.peer_poll).await;
    }
}

async fn wait_peer_master<P: UpgradePeer>(peer: &P, t: &Timing) -> Result<(), String> {
    let t0 = Instant::now();
    while t0.elapsed() < t.master_timeout {
        if let Ok(h) = peer.hello().await
            && h.role.as_deref() == Some("MASTER")
        {
            return Ok(());
        }
        tokio::time::sleep(t.master_poll).await;
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

    #[test]
    fn the_last_event_ends_a_relay() {
        for step in ["failed", "done", "reboot"] {
            assert!(ends(&json!({"type": "upgrade", "step": step})), "{step}");
        }
        for step in ["plan", "stage-peer", "peer-ready", "failover", "stage"] {
            assert!(!ends(&json!({"type": "upgrade", "step": step})), "{step}");
        }
    }

    use std::sync::Mutex;

    /// A host whose steps fail as told; logs what ran.
    #[derive(Default)]
    struct FakeHost {
        stage: Option<Result<Option<String>, String>>,
        download: Option<Result<Option<String>, String>>,
        /// Downloads that fail before one goes through.
        download_fails: Mutex<usize>,
        apply_fails: bool,
        booted: Option<&'static str>,
        reboot_fails: bool,
        stop_fails: bool,
        /// `keepalived_state` answers, the last repeating.
        states: Vec<&'static str>,
        reads: Mutex<usize>,
        log: Mutex<Vec<String>>,
    }

    impl FakeHost {
        fn note(&self, s: &str) {
            self.log.lock().unwrap().push(s.into());
        }
    }

    impl UpgradeHost for FakeHost {
        fn stage(&self, image: &str) -> Result<Option<String>, String> {
            self.note(&format!("stage {image}"));
            self.stage
                .clone()
                .unwrap_or_else(|| Ok(Some(format!("{image}@sha256:new"))))
        }
        fn download(&self, image: &str) -> Result<Option<String>, String> {
            self.note(&format!("download {image}"));
            let mut fails = self.download_fails.lock().unwrap();
            if *fails > 0 {
                *fails -= 1;
                return Err("connect: no route to host".into());
            }
            self.download
                .clone()
                .unwrap_or_else(|| Ok(Some(format!("{image}@sha256:new"))))
        }
        fn booted(&self) -> Option<String> {
            self.booted.map(String::from)
        }
        fn apply_downloaded(&self) -> Result<(), String> {
            self.note("apply downloaded");
            if self.apply_fails {
                return Err("no staged deployment".into());
            }
            Ok(())
        }
        fn reboot_soon(&self) -> Result<(), String> {
            self.note("reboot");
            if self.reboot_fails {
                return Err("systemd-run failed".into());
            }
            Ok(())
        }
        fn stop_keepalived(&self) -> Result<(), String> {
            self.note("stop keepalived");
            if self.stop_fails {
                return Err("D-Bus connection terminated while waiting for jobs".into());
            }
            Ok(())
        }
        fn keepalived_state(&self) -> Result<String, String> {
            let mut n = self.reads.lock().unwrap();
            let states = if self.states.is_empty() {
                &["inactive"][..]
            } else {
                &self.states[..]
            };
            let s = states[(*n).min(states.len() - 1)];
            *n += 1;
            if s == "error" {
                return Err("show failed".into());
            }
            Ok(s.into())
        }
        fn start_keepalived(&self) -> Result<(), String> {
            self.note("start keepalived");
            Ok(())
        }
    }

    fn hello(image: &str, health: &str, desired: &str, role: &str) -> HelloReply {
        HelloReply {
            node: "fw1".into(),
            protocol: PEER_PROTOCOL,
            active: 5,
            desired: desired.into(),
            applied: Some(desired.into()),
            applying: false,
            lineage: vec![],
            pending: false,
            image: (!image.is_empty()).then(|| image.into()),
            health: Some(health.into()),
            role: Some(role.into()),
            link_decision: None,
            reach: vec![],
            schema: None,
        }
    }

    /// A peer answering `hellos` in order (the last repeating).
    struct FakePeer {
        hellos: Vec<HelloReply>,
        upgrade: Result<(), String>,
        calls: Mutex<usize>,
        log: Mutex<Vec<String>>,
    }

    impl UpgradePeer for FakePeer {
        async fn hello(&self) -> Result<HelloReply, String> {
            let mut n = self.calls.lock().unwrap();
            let h = self.hellos[(*n).min(self.hellos.len() - 1)].clone();
            *n += 1;
            Ok(h)
        }
        async fn upgrade(&self, image: &str) -> Result<(), String> {
            self.log.lock().unwrap().push(format!("upgrade {image}"));
            self.upgrade.clone()
        }
    }

    fn peer(hellos: Vec<HelloReply>, upgrade: Result<(), String>) -> FakePeer {
        FakePeer {
            hellos,
            upgrade,
            calls: Mutex::new(0),
            log: Mutex::new(vec![]),
        }
    }

    const FAST: Timing = Timing {
        peer_settle: Duration::from_millis(1),
        peer_timeout: Duration::from_millis(50),
        peer_poll: Duration::from_millis(1),
        stop_timeout: Duration::from_millis(20),
        stop_poll: Duration::from_millis(1),
        master_timeout: Duration::from_millis(20),
        master_poll: Duration::from_millis(1),
        download_tries: 3,
        download_retry: Duration::from_millis(1),
    };

    async fn upgrade(host: FakeHost, p: Option<&FakePeer>) -> (Result<(), String>, Vec<String>) {
        let host = Arc::new(host);
        let h: Arc<dyn UpgradeHost> = host.clone();
        let (tx, _) = broadcast::channel(64);
        let r = run_with(&h, p, "cfg", "reg/sw:next", &tx, &FAST).await;
        let log = host.log.lock().unwrap().clone();
        (r, log)
    }

    /// The peer: still rebooting on the old image, then back on the new
    /// one, healthy and in sync, then master once this node lets go.
    fn good_peer() -> FakePeer {
        peer(
            vec![
                hello("old", "ok", "cfg", "BACKUP"),
                hello("old", "ok", "cfg", "BACKUP"),
                hello("new", "ok", "cfg", "BACKUP"),
                hello("new", "ok", "cfg", "MASTER"),
            ],
            Ok(()),
        )
    }

    /// #12: a standalone node stages and reboots, or stops with the
    /// staging error; nothing touches keepalived.
    #[tokio::test]
    async fn standalone_upgrade_gates() {
        let none: Option<&FakePeer> = None;
        let (r, log) = upgrade(FakeHost::default(), none).await;
        assert_eq!(r, Ok(()));
        assert_eq!(log, ["stage reg/sw:next", "reboot"]);

        let (r, log) = upgrade(
            FakeHost {
                stage: Some(Ok(None)),
                ..Default::default()
            },
            none,
        )
        .await;
        assert_eq!(r, Ok(()));
        assert_eq!(log, ["stage reg/sw:next"]);

        let (r, log) = upgrade(
            FakeHost {
                stage: Some(Err("rejected by policy".into())),
                ..Default::default()
            },
            none,
        )
        .await;
        assert_eq!(r, Err("rejected by policy".into()));
        assert_eq!(log, ["stage reg/sw:next"]);

        let (r, _) = upgrade(
            FakeHost {
                reboot_fails: true,
                ..Default::default()
            },
            none,
        )
        .await;
        assert_eq!(r, Err("systemd-run failed".into()));
    }

    /// #12, #175: in a pair, the master downloads its own image first, hands
    /// over only once the peer is back healthy and in sync on the new
    /// image, applies the download only once the peer is master, and takes
    /// the addresses back if a later gate fails.
    #[tokio::test]
    async fn pair_upgrade_gates() {
        // All gates pass. A lost wait on the stop does not matter (#29).
        let p = good_peer();
        let (r, log) = upgrade(
            FakeHost {
                stop_fails: true,
                states: vec!["active", "deactivating", "error", "inactive"],
                ..Default::default()
            },
            Some(&p),
        )
        .await;
        assert_eq!(r, Ok(()));
        assert_eq!(
            log,
            [
                "download reg/sw:next",
                "stop keepalived",
                "apply downloaded",
                "reboot"
            ]
        );
        assert_eq!(*p.log.lock().unwrap(), ["upgrade reg/sw:next"]);

        // Gates before the handover: nothing happens here.
        for (case, p) in [
            (
                "no image",
                peer(vec![hello("", "ok", "cfg", "BACKUP")], Ok(())),
            ),
            (
                "peer rejects",
                peer(
                    vec![hello("old", "ok", "cfg", "BACKUP")],
                    Err("rejected by policy".into()),
                ),
            ),
            (
                "never back",
                peer(vec![hello("old", "ok", "cfg", "BACKUP")], Ok(())),
            ),
            (
                "failed health",
                peer(
                    vec![
                        hello("old", "ok", "cfg", "BACKUP"),
                        hello("new", "failed", "cfg", "BACKUP"),
                    ],
                    Ok(()),
                ),
            ),
            (
                "other config",
                peer(
                    vec![hello("old", "ok", "cfg", "BACKUP"), {
                        let mut h = hello("new", "ok", "other", "BACKUP");
                        h.applied = Some("cfg".into());
                        h
                    }],
                    Ok(()),
                ),
            ),
            (
                "still applying",
                peer(
                    vec![hello("old", "ok", "cfg", "BACKUP"), {
                        let mut h = hello("new", "ok", "cfg", "BACKUP");
                        h.applied = None;
                        h
                    }],
                    Ok(()),
                ),
            ),
        ] {
            let (r, log) = upgrade(FakeHost::default(), Some(&p)).await;
            let e = r.expect_err(case);
            assert_eq!(log, ["download reg/sw:next"], "{case}");
            match case {
                "no image" => assert!(e.contains("does not report its image"), "{e}"),
                "peer rejects" => assert!(
                    e.contains("fw1 rejected the upgrade: rejected by policy"),
                    "{e}"
                ),
                _ => assert!(e.contains("did not come back healthy"), "{case}: {e}"),
            }
        }

        // keepalived will not stop: take the addresses back, no staging.
        let (r, log) = upgrade(
            FakeHost {
                stop_fails: true,
                states: vec!["active"],
                ..Default::default()
            },
            Some(&good_peer()),
        )
        .await;
        let e = r.unwrap_err();
        assert!(
            e.contains("keepalived did not stop") && e.contains("D-Bus"),
            "{e}"
        );
        assert_eq!(
            log,
            [
                "download reg/sw:next",
                "stop keepalived",
                "start keepalived"
            ]
        );

        // The peer never becomes master.
        let p = peer(
            vec![
                hello("old", "ok", "cfg", "BACKUP"),
                hello("new", "ok", "cfg", "BACKUP"),
            ],
            Ok(()),
        );
        let (r, log) = upgrade(FakeHost::default(), Some(&p)).await;
        assert_eq!(r, Err("the peer did not become master".into()));
        assert_eq!(
            log,
            [
                "download reg/sw:next",
                "stop keepalived",
                "start keepalived"
            ]
        );

        // Applying the download fails after the handover: take the
        // addresses back.
        let (r, log) = upgrade(
            FakeHost {
                apply_fails: true,
                ..Default::default()
            },
            Some(&good_peer()),
        )
        .await;
        assert_eq!(r, Err("no staged deployment".into()));
        assert_eq!(
            log,
            [
                "download reg/sw:next",
                "stop keepalived",
                "apply downloaded",
                "start keepalived"
            ]
        );
    }

    /// #175: the master downloads its own image before anything moves. A
    /// download that keeps failing stops the run there, with the peer
    /// untouched; one that fails at first is retried.
    #[tokio::test]
    async fn the_master_downloads_before_anything_moves() {
        let p = good_peer();
        let (r, log) = upgrade(
            FakeHost {
                download_fails: Mutex::new(3),
                ..Default::default()
            },
            Some(&p),
        )
        .await;
        let e = r.unwrap_err();
        assert!(
            e.contains("cannot download reg/sw:next on this node: connect: no route to host"),
            "{e}"
        );
        assert_eq!(log, ["download reg/sw:next"; 3]);
        assert!(p.log.lock().unwrap().is_empty());

        let p = good_peer();
        let (r, log) = upgrade(
            FakeHost {
                download_fails: Mutex::new(2),
                ..Default::default()
            },
            Some(&p),
        )
        .await;
        assert_eq!(r, Ok(()));
        assert_eq!(
            log,
            [
                "download reg/sw:next",
                "download reg/sw:next",
                "download reg/sw:next",
                "stop keepalived",
                "apply downloaded",
                "reboot"
            ]
        );
    }

    /// #175: a master already on the target (a run that stopped after
    /// its handover, say) upgrades the peer and keeps the addresses: no
    /// handover, no reboot.
    #[tokio::test]
    async fn a_master_on_the_target_only_upgrades_the_peer() {
        let p = good_peer();
        let (r, log) = upgrade(
            FakeHost {
                download: Some(Ok(None)),
                ..Default::default()
            },
            Some(&p),
        )
        .await;
        assert_eq!(r, Ok(()));
        assert_eq!(log, ["download reg/sw:next"]);
        assert_eq!(*p.log.lock().unwrap(), ["upgrade reg/sw:next"]);

        // Both already run it, under different references: nothing to do.
        let p = peer(
            vec![hello("reg/sw:stable@sha256:new", "ok", "cfg", "BACKUP")],
            Ok(()),
        );
        let (r, log) = upgrade(
            FakeHost {
                download: Some(Ok(None)),
                booted: Some("reg/sw:next@sha256:new"),
                ..Default::default()
            },
            Some(&p),
        )
        .await;
        assert_eq!(r, Ok(()));
        assert_eq!(log, ["download reg/sw:next"]);
        assert!(p.log.lock().unwrap().is_empty());
    }
}
