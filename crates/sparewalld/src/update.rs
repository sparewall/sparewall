//! The background update check (#188): every few hours, the node asks the
//! registry what its channel offers, as `sparewall upgrade --check` does,
//! keeps the answer for status and `/metrics`, and logs when it changes.
//!
//! It never touches health: in a pair, health feeds keepalived's check
//! script, and the gateway must not move because an image was published.
//! A failed check (an offline site, a registry outage) is recorded and
//! retried, not raised.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::broadcast;
use tokio::time::Instant;

use crate::service::{Core, booted_image_digest, with_core_raw};
use crate::upgrade::{Compared, Remote, compare_versions};

/// The journal's `MESSAGE_ID` of a change in what is available, for
/// filtering and forwarding (`journalctl MESSAGE_ID=…`).
pub const MESSAGE_AVAILABLE: &str = "c8f95979678447529aa9b5914a38a3a0";
/// The journal's `MESSAGE_ID` of a check that failed after one that did
/// not (or the first one).
pub const MESSAGE_FAILED: &str = "52e0a9567b834f27aee3019c5703cf13";
/// The tracing target whose events go to the journal with their field
/// names as given, so `message_id` becomes `MESSAGE_ID` (main.rs).
pub const JOURNAL_TARGET: &str = "sparewall::journal";

/// The last answer, kept across a restart of the daemon (not a reboot).
const STATE_FILE: &str = "/run/sparewall/update.json";

/// The first check after start, and how often after that.
const FIRST: (Duration, Duration) = (Duration::from_secs(120), Duration::from_secs(420));
const INTERVAL: Duration = Duration::from_secs(6 * 3600);
/// After a failed check.
const RETRY: Duration = Duration::from_secs(3600);
/// After the channel or the check setting changes.
const SOON: Duration = Duration::from_secs(30);
/// How often the document is read for those changes.
const POLL: Duration = Duration::from_secs(60);

/// What the channel offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Nothing newer: the same image, or an older version.
    None,
    /// A newer version.
    Newer,
    /// The same version, rebuilt (#187).
    Rebuild,
    /// A different image whose version cannot be read (a mirror that
    /// drops labels).
    Different,
}

/// The check's state, as status and `/metrics` report it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The image reference checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The last successful check's answer; none before one succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<Kind>,
    /// The target's version and digest, as of the last successful check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// When the last check ran, and when the last one succeeded (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub succeeded: Option<String>,
    /// Why the last check failed; none once one succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What status and `/metrics` read: `None` while the check is off.
static CURRENT: Mutex<Option<State>> = Mutex::new(None);

fn set_current(s: Option<State>) {
    *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) = s;
}

fn current() -> Option<State> {
    CURRENT.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The `update` object of the status reply.
pub fn status() -> Value {
    match current() {
        Some(s) => {
            let mut v = serde_json::to_value(&s).unwrap_or_default();
            v["enabled"] = json!(true);
            v["running"] = json!(sparewall_core::VERSION);
            v
        }
        None => json!({"enabled": false, "running": sparewall_core::VERSION}),
    }
}

/// The check's lines of `/metrics`: nothing while it is off.
pub fn metrics() -> String {
    let Some(s) = current() else {
        return String::new();
    };
    metrics_of(&s)
}

fn metrics_of(s: &State) -> String {
    let mut o = String::new();
    if let Some(k) = s.available {
        let kind = match k {
            Kind::None => "none",
            Kind::Newer => "newer",
            Kind::Rebuild => "rebuild",
            Kind::Different => "different",
        };
        o.push_str(
            "# HELP sparewall_update_available 1 when the channel offers an update, by kind (newer, rebuild, different).\n\
             # TYPE sparewall_update_available gauge\n",
        );
        o.push_str(&format!(
            "sparewall_update_available{{kind=\"{kind}\"}} {}\n",
            u8::from(k != Kind::None)
        ));
    }
    if let Some(t) = s
        .succeeded
        .as_deref()
        .and_then(|t| t.parse::<jiff::Timestamp>().ok())
    {
        o.push_str(
            "# HELP sparewall_update_last_check_success_timestamp_seconds When the update check last succeeded.\n\
             # TYPE sparewall_update_last_check_success_timestamp_seconds gauge\n",
        );
        o.push_str(&format!(
            "sparewall_update_last_check_success_timestamp_seconds {}\n",
            t.as_second()
        ));
    }
    o
}

/// What a target offers this node, from its version, then its digest.
pub fn classify(running: &str, booted_digest: Option<&str>, r: &Remote) -> Result<Kind, String> {
    let digests = || match (r.digest.as_deref(), booted_digest) {
        (Some(t), Some(b)) => Ok(t != b),
        (None, _) => Err("the registry gave no digest for the target".to_string()),
        (_, None) => Err("the booted image's digest is not known yet".to_string()),
    };
    Ok(match compare_versions(running, r.version.as_deref()) {
        Compared::Newer => Kind::Newer,
        Compared::Older => Kind::None,
        Compared::Same if digests()? => Kind::Rebuild,
        Compared::Unknown if digests()? => Kind::Different,
        Compared::Same | Compared::Unknown => Kind::None,
    })
}

/// A change worth a journal entry and an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// What is available changed: the message says what.
    Available(String),
    /// A check failed after one that did not.
    Failed(String),
    /// A check succeeded after a failed one, and nothing else changed.
    Recovered,
}

/// The state after a check of `target` at `now`, and what changed.
pub fn record(
    prev: &State,
    running: &str,
    target: &str,
    result: Result<(Kind, Remote), String>,
    now: &str,
) -> (State, Option<Change>) {
    let mut next = prev.clone();
    next.checked = Some(now.to_string());
    match result {
        Err(e) => {
            let change = prev.error.is_none().then(|| Change::Failed(e.clone()));
            next.error = Some(e);
            (next, change)
        }
        Ok((kind, remote)) => {
            next.target = Some(target.to_string());
            next.available = Some(kind);
            next.version = remote.version;
            next.digest = remote.digest;
            next.succeeded = Some(now.to_string());
            next.error = None;
            let offered = |s: &State| {
                (s.available.is_some_and(|k| k != Kind::None)).then(|| {
                    (
                        s.target.clone(),
                        s.available,
                        s.version.clone(),
                        s.digest.clone(),
                    )
                })
            };
            let change = match (offered(prev), offered(&next)) {
                (a, b) if a == b => None,
                (_, Some(_)) => Some(Change::Available(message(&next, running))),
                (Some(_), None) => Some(Change::Available(format!(
                    "the update is no longer available (running {running})"
                ))),
                (None, None) => None,
            };
            let change = change.or_else(|| prev.error.is_some().then_some(Change::Recovered));
            (next, change)
        }
    }
}

fn message(s: &State, running: &str) -> String {
    let target = s.target.as_deref().unwrap_or_default();
    let version = s.version.as_deref().unwrap_or("?");
    match s.available {
        Some(Kind::Newer) => format!("{version} is available on {target} (running {running})"),
        Some(Kind::Rebuild) => format!("a rebuild of {running} is available on {target}"),
        Some(Kind::Different) => format!(
            "a different image is available on {target}, whose version cannot be read (running {running})"
        ),
        _ => String::new(),
    }
}

/// A duration with up to a fifth either way at random, so nodes installed
/// together do not ask the registry together.
fn jitter(d: Duration) -> Duration {
    let r = getrandom::u32().unwrap_or(0);
    let spread = d.as_secs() / 5;
    let off = if spread == 0 {
        0
    } else {
        u64::from(r) % (2 * spread + 1)
    };
    Duration::from_secs(d.as_secs() - spread + off)
}

fn between((lo, hi): (Duration, Duration)) -> Duration {
    let r = u64::from(getrandom::u32().unwrap_or(0));
    lo + Duration::from_secs(r % (hi - lo).as_secs().max(1))
}

fn load(path: &Path) -> State {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save(path: &Path, s: &State) {
    if let Ok(b) = serde_json::to_vec(s)
        && let Err(e) = sparewall_core::store::write_atomic(path, &b)
    {
        tracing::debug!(error = %e, "cannot keep the update check's state");
    }
}

/// Run the check against the registry: blocking.
fn check(target: &str) -> Result<(Kind, Remote), String> {
    let remote = crate::upgrade::inspect(target)?;
    let booted = booted_image_digest();
    let booted = booted
        .as_deref()
        .and_then(|b| b.rsplit_once('@'))
        .map(|(_, d)| d);
    let kind = classify(sparewall_core::VERSION, booted, &remote)?;
    Ok((kind, remote))
}

/// Log a change to the journal (with its `MESSAGE_ID`) and send it as an
/// event.
fn announce(events: &broadcast::Sender<Value>, s: &State, change: &Change, retry: Duration) {
    match change {
        Change::Available(m) => {
            tracing::info!(target: JOURNAL_TARGET, message_id = MESSAGE_AVAILABLE, "{m}");
            let _ = events.send(json!({"type": "update", "message": m, "update": s}));
        }
        Change::Failed(e) => {
            let m = format!(
                "the update check failed, and is retried in {} minutes: {e}",
                retry.as_secs() / 60
            );
            tracing::warn!(target: JOURNAL_TARGET, message_id = MESSAGE_FAILED, "{m}");
            let _ = events.send(json!({"type": "update", "message": m, "update": s}));
        }
        Change::Recovered => {
            tracing::info!("the update check succeeded again");
            let _ = events.send(json!({"type": "update", "update": s}));
        }
    }
}

/// Check every few hours while `updates.check` is on, and at once (nearly)
/// when the channel changes.
pub async fn check_loop(core: Core, events: broadcast::Sender<Value>) {
    let path = Path::new(STATE_FILE);
    let mut state = load(path);
    let mut next = Instant::now() + between(FIRST);
    let mut last: Option<(bool, Option<String>)> = None;
    loop {
        let want = with_core_raw(&core, &events, |c| {
            let u = c.active_document()?.and_then(|d| d.updates);
            Ok((
                u.as_ref().is_none_or(|u| u.check),
                u.and_then(|u| u.channel),
            ))
        })
        .await;
        let Ok((on, channel)) = want else {
            tokio::time::sleep(POLL).await;
            continue;
        };
        if !on {
            // Also forget a state left from before a restart.
            if current().is_some() || state != State::default() {
                tracing::info!("the update check is off (updates.check)");
                set_current(None);
                let _ = std::fs::remove_file(path);
                state = State::default();
                let _ = events.send(json!({"type": "update", "update": status()}));
            }
        } else {
            if current().is_none() {
                set_current(Some(state.clone()));
            }
            if last.as_ref().is_some_and(|l| *l != (on, channel.clone())) {
                next = next.min(Instant::now() + SOON);
            }
            if Instant::now() >= next {
                let ch = channel.clone();
                let ran = tokio::task::spawn_blocking(move || {
                    let tracked = crate::upgrade::tracked_ref();
                    let target =
                        crate::upgrade::target_ref(None, None, ch.as_deref(), tracked.as_deref());
                    let r = check(&target);
                    (target, r)
                })
                .await;
                let (target, result) = match ran {
                    Ok(v) => v,
                    Err(e) => (String::new(), Err(e.to_string())),
                };
                let failed = result.is_err();
                let now = jiff::Timestamp::now().to_string();
                let (s, change) = record(&state, sparewall_core::VERSION, &target, result, &now);
                let wait = jitter(if failed { RETRY } else { INTERVAL });
                if let Some(c) = &change {
                    announce(&events, &s, c, wait);
                }
                state = s;
                save(path, &state);
                set_current(Some(state.clone()));
                next = Instant::now() + wait;
            }
        }
        last = Some((on, channel));
        let now = Instant::now();
        tokio::time::sleep(
            POLL.min(next.saturating_duration_since(now))
                .max(Duration::from_secs(1)),
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(version: Option<&str>, digest: Option<&str>) -> Remote {
        Remote {
            version: version.map(str::to_string),
            digest: digest.map(str::to_string),
        }
    }

    #[test]
    fn classifies_by_version_then_digest() {
        let r = |v, d| classify("0.3.2", Some("sha256:a"), &remote(v, d));
        assert_eq!(r(Some("0.3.3"), Some("sha256:b")), Ok(Kind::Newer));
        assert_eq!(r(Some("0.3.1"), Some("sha256:b")), Ok(Kind::None));
        assert_eq!(r(Some("0.3.2"), Some("sha256:a")), Ok(Kind::None));
        assert_eq!(r(Some("0.3.2"), Some("sha256:b")), Ok(Kind::Rebuild));
        assert_eq!(r(None, Some("sha256:b")), Ok(Kind::Different));
        assert_eq!(r(None, Some("sha256:a")), Ok(Kind::None));
        assert!(r(Some("0.3.2"), None).is_err());
        // A newer version needs no digest.
        assert_eq!(r(Some("0.4.0"), None), Ok(Kind::Newer));
        // Before the booted image is known, only versions decide.
        assert!(classify("0.3.2", None, &remote(Some("0.3.2"), Some("sha256:b"))).is_err());
        assert_eq!(
            classify("0.3.2", None, &remote(Some("0.3.3"), Some("sha256:b"))),
            Ok(Kind::Newer)
        );
    }

    const T: &str = "ghcr.io/sparewall/sparewall:stable";

    fn ok(kind: Kind, v: &str, d: &str) -> Result<(Kind, Remote), String> {
        Ok((kind, remote(Some(v), Some(d))))
    }

    #[test]
    fn logs_only_changes() {
        let s0 = State::default();
        // Nothing to offer at first: nothing to say.
        let (s1, c) = record(&s0, "0.3.2", T, ok(Kind::None, "0.3.2", "sha256:a"), "t1");
        assert_eq!(c, None);
        assert_eq!(s1.available, Some(Kind::None));
        assert_eq!(s1.succeeded.as_deref(), Some("t1"));
        // A newer version appears: said once.
        let (s2, c) = record(&s1, "0.3.2", T, ok(Kind::Newer, "0.3.3", "sha256:b"), "t2");
        assert_eq!(
            c,
            Some(Change::Available(format!(
                "0.3.3 is available on {T} (running 0.3.2)"
            )))
        );
        let (s3, c) = record(&s2, "0.3.2", T, ok(Kind::Newer, "0.3.3", "sha256:b"), "t3");
        assert_eq!(c, None);
        // A rebuild of it replaces it: said again.
        let (s4, c) = record(&s3, "0.3.2", T, ok(Kind::Newer, "0.3.3", "sha256:c"), "t4");
        assert!(matches!(c, Some(Change::Available(_))));
        // Withdrawn.
        let (_, c) = record(&s4, "0.3.2", T, ok(Kind::None, "0.3.2", "sha256:a"), "t5");
        assert_eq!(
            c,
            Some(Change::Available(
                "the update is no longer available (running 0.3.2)".into()
            ))
        );
        // A rebuild of the running version.
        let (_, c) = record(
            &s1,
            "0.3.2",
            T,
            ok(Kind::Rebuild, "0.3.2", "sha256:z"),
            "t6",
        );
        assert_eq!(
            c,
            Some(Change::Available(format!(
                "a rebuild of 0.3.2 is available on {T}"
            )))
        );
    }

    #[test]
    fn a_failure_is_said_once_and_keeps_the_last_answer() {
        let (s1, _) = record(
            &State::default(),
            "0.3.2",
            T,
            ok(Kind::Newer, "0.3.3", "sha256:b"),
            "t1",
        );
        let (s2, c) = record(&s1, "0.3.2", T, Err("no route to host".into()), "t2");
        assert_eq!(c, Some(Change::Failed("no route to host".into())));
        assert_eq!(s2.available, Some(Kind::Newer));
        assert_eq!(s2.version.as_deref(), Some("0.3.3"));
        assert_eq!(s2.checked.as_deref(), Some("t2"));
        assert_eq!(s2.succeeded.as_deref(), Some("t1"));
        assert_eq!(s2.error.as_deref(), Some("no route to host"));
        let (s3, c) = record(&s2, "0.3.2", T, Err("timed out".into()), "t3");
        assert_eq!(c, None);
        // Success again, with the same answer: recovered, nothing new.
        let (s4, c) = record(&s3, "0.3.2", T, ok(Kind::Newer, "0.3.3", "sha256:b"), "t4");
        assert_eq!(c, Some(Change::Recovered));
        assert_eq!(s4.error, None);
        // Success again with a new answer: the answer is what is said.
        let (s5, _) = record(&s4, "0.3.2", T, Err("timed out".into()), "t5");
        let (_, c) = record(&s5, "0.3.2", T, ok(Kind::Newer, "0.4.0", "sha256:d"), "t6");
        assert!(matches!(c, Some(Change::Available(m)) if m.starts_with("0.4.0 is available")));
        // The first check failing is said too.
        let (_, c) = record(&State::default(), "0.3.2", T, Err("x".into()), "t1");
        assert_eq!(c, Some(Change::Failed("x".into())));
    }

    #[test]
    fn metrics_follow_the_last_answer() {
        assert_eq!(metrics_of(&State::default()), "");
        let (s, _) = record(
            &State::default(),
            "0.3.2",
            T,
            ok(Kind::Rebuild, "0.3.2", "sha256:b"),
            "2026-11-01T00:00:00Z",
        );
        let m = metrics_of(&s);
        assert!(
            m.contains("sparewall_update_available{kind=\"rebuild\"} 1\n"),
            "{m}"
        );
        assert!(
            m.contains("sparewall_update_last_check_success_timestamp_seconds 1793491200\n"),
            "{m}"
        );
        let (s, _) = record(
            &s,
            "0.3.2",
            T,
            ok(Kind::None, "0.3.2", "sha256:a"),
            "2026-11-01T06:00:00Z",
        );
        assert!(metrics_of(&s).contains("sparewall_update_available{kind=\"none\"} 0\n"));
    }

    #[test]
    fn jitter_stays_within_a_fifth() {
        for _ in 0..100 {
            let j = jitter(INTERVAL);
            assert!(j >= INTERVAL * 4 / 5 && j <= INTERVAL * 6 / 5, "{j:?}");
            let f = between(FIRST);
            assert!(f >= FIRST.0 && f < FIRST.1, "{f:?}");
        }
    }
}
