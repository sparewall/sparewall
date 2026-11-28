//! IP blocklists (#379): fetch each list, keep the last good copy of each
//! under the state directory, and load its addresses into the list's nft
//! sets ([`sparewall_config::blocklists::set_names`]), which the ruleset
//! drops traffic from (or to) and a reload keeps.
//!
//! Every node fetches for itself, master or backup, so a failover changes
//! nothing. A list that can't be fetched keeps its last copy, and a
//! reboot loads the kept copy before fetching. Applying a configuration
//! never waits for a list.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sparewall_config::Document;
use sparewall_config::blocklists::{self, Parsed};
use sparewall_core::{Check, Level};
use tokio::sync::broadcast;

use crate::service::{Core, with_core_raw};

/// How often the loop looks: lists are fetched every `refresh`, and the
/// sets are checked against what was loaded.
const ROUND: Duration = Duration::from_secs(60);
/// After a failed fetch, how long until the next try.
const RETRY: Duration = Duration::from_secs(900);
const CACHE_DIR: &str = "blocklists";
const CHECK: &str = "blocklists";

/// Where a list's last good copy is kept: its entries, one per line.
fn cached(dir: &Path, url: &str) -> PathBuf {
    let h = Sha256::digest(url.as_bytes());
    dir.join(format!("{}.list", hex::encode(&h[..16])))
}

fn age(p: &Path) -> Option<Duration> {
    let m = std::fs::metadata(p).ok()?.modified().ok()?;
    SystemTime::now().duration_since(m).ok()
}

/// A list's kept copy: its entries, IPv4 then IPv6, one per line.
fn kept(p: &Parsed) -> String {
    let mut s = String::new();
    for a in &p.v4 {
        s.push_str(&a.to_string());
        s.push('\n');
    }
    for a in &p.v6 {
        s.push_str(&a.to_string());
        s.push('\n');
    }
    s
}

/// The `nft -f` script that makes a set hold exactly `els`: flushed and
/// refilled in one transaction, so it is never half loaded.
pub fn load_script(set: &str, els: &[String]) -> String {
    let table = sparewall_render::nft::TABLE;
    let mut s = format!("flush set inet {table} {set}\n");
    for chunk in els.chunks(4096) {
        s.push_str(&format!(
            "add element inet {table} {set} {{ {} }}\n",
            chunk.join(", ")
        ));
    }
    s
}

/// Entries per transaction when a set has to be loaded in parts.
const PART: usize = 8192;

/// Adding `els` to a set, as one transaction.
fn add_script(set: &str, els: &[String]) -> String {
    let table = sparewall_render::nft::TABLE;
    format!("add element inet {table} {set} {{ {} }}\n", els.join(", "))
}

async fn nft_load(script: &str) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(script.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().await.map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// A list's `Authorization` header, from its credentials' secret.
async fn auth(
    core: &Core,
    events: &broadcast::Sender<Value>,
    b: &sparewall_config::model::Blocklist,
) -> Result<Option<String>, String> {
    let Some(r) = &b.credentials else {
        return Ok(None);
    };
    let name = r
        .strip_prefix("secret:")
        .ok_or("credentials are not a secret:<name> reference")?
        .to_string();
    let raw = with_core_raw(core, events, {
        let name = name.clone();
        move |c| c.secret_get(&name)
    })
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| format!("secret {name} is not set"))?;
    let creds = crate::backup::credentials_env(
        &format!("the {r} credentials"),
        &String::from_utf8_lossy(&raw),
    )?;
    let get = |k: &str| {
        creds
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| format!("the {r} credentials have no {k}"))
    };
    let pair = format!("{}:{}", get("USERNAME")?, get("PASSWORD")?);
    Ok(Some(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(pair)
    )))
}

/// What the loop knows of a list between rounds.
#[derive(Default)]
struct State {
    /// The last failed fetch, and why.
    failed: Option<(Instant, String)>,
    /// What the last parse dropped or skipped, for health.
    dropped: usize,
    /// Rounds in a row a set of the list couldn't be loaded, and why. One
    /// is an apply on its way (the set isn't there yet); more is health's.
    load_failures: (u32, String),
}

/// Health: degraded for a list never fetched once a fetch failed, one
/// not fetched in three refreshes, or one cut at its entry cap.
fn assess(
    lists: &BTreeMap<String, (String, u64)>,
    dir: &Path,
    state: &BTreeMap<String, State>,
    counts: &BTreeMap<String, usize>,
) -> Vec<Check> {
    if lists.is_empty() {
        return vec![];
    }
    let mut bad = Vec::new();
    let mut fine = Vec::new();
    for (name, (url, refresh)) in lists {
        let s = state.get(name);
        let why = s
            .and_then(|s| s.failed.as_ref())
            .map(|(_, e)| format!(" ({e})"))
            .unwrap_or_default();
        let n = counts.get(name).copied().unwrap_or(0);
        match age(&cached(dir, url)) {
            None if s.is_some_and(|s| s.failed.is_some()) => {
                bad.push(format!("{name}: never fetched{why}"));
            }
            None => fine.push(format!("{name}: not fetched yet")),
            Some(a) if a.as_secs() > 3 * refresh => bad.push(format!(
                "{name}: last fetched {} h ago, {n} entries{why}",
                a.as_secs() / 3600
            )),
            Some(a) => fine.push(format!(
                "{name}: {n} entries, fetched {} min ago",
                a.as_secs() / 60
            )),
        }
        if let Some(s) = s
            && s.load_failures.0 > 1
        {
            bad.push(format!("{name}: not loaded ({})", s.load_failures.1));
        }
        if let Some(s) = s
            && s.dropped > 0
        {
            bad.push(format!(
                "{name}: {} entries past the limit of {} were left out",
                s.dropped,
                blocklists::MAX_ENTRIES
            ));
        }
    }
    if bad.is_empty() {
        vec![Check::new(CHECK, Level::Ok, fine.join("; "))]
    } else {
        vec![Check::new(CHECK, Level::Degraded, bad.join("; "))]
    }
}

pub async fn blocklist_loop(core: Core, events: broadcast::Sender<Value>, state_dir: PathBuf) {
    let dir = state_dir.join(CACHE_DIR);
    let _ = std::fs::create_dir_all(&dir);
    let mut rx = events.subscribe();
    let mut state: BTreeMap<String, State> = BTreeMap::new();
    // What each set was last loaded with (a digest), so an unchanged list
    // isn't reloaded every round. Empty at start: a reboot reloads all.
    let mut loaded: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    loop {
        let doc: Option<Document> = with_core_raw(&core, &events, |c| c.active_document())
            .await
            .ok()
            .flatten();
        let wanted = doc
            .as_ref()
            .map(|d| d.blocklists.clone())
            .unwrap_or_default();
        // Without a WAN, no sets are rendered: nothing to load, and health
        // says so.
        let has_wan = doc.as_ref().is_some_and(|d| {
            d.networks_with_role(sparewall_config::model::NetworkRole::Wan)
                .next()
                .is_some()
        });
        state.retain(|n, _| wanted.contains_key(n));
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for (name, b) in &wanted {
            let st = state.entry(name.clone()).or_default();
            let path = cached(&dir, &b.url);
            let due = age(&path).is_none_or(|a| a.as_secs() >= b.refresh_secs());
            let waiting = st.failed.as_ref().is_some_and(|(t, _)| t.elapsed() < RETRY);
            if due && !waiting {
                let got = match auth(&core, &events, b).await {
                    Ok(a) => crate::filters::fetch_with(&b.url, a.as_deref()).await,
                    Err(e) => Err(e),
                };
                match got {
                    Ok(text) => {
                        let p = blocklists::parse(&text);
                        st.dropped = p.dropped;
                        match sparewall_core::store::write_atomic(&path, kept(&p).as_bytes()) {
                            Ok(()) => {
                                tracing::info!(
                                    list = name,
                                    v4 = p.v4.len(),
                                    v6 = p.v6.len(),
                                    skipped = p.skipped,
                                    dropped = p.dropped,
                                    "fetched a blocklist"
                                );
                                st.failed = None;
                            }
                            Err(e) => {
                                tracing::warn!(list = name, error = %e, "cannot keep a blocklist")
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(list = name, error = e, "cannot fetch a blocklist");
                        st.failed = Some((Instant::now(), e));
                    }
                }
            }
            // Load the kept copy into the list's sets when it differs from
            // what they were loaded with.
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let p = blocklists::parse(&text);
            counts.insert(name.clone(), p.v4.len() + p.v6.len());
            let mut load_error: Option<String> = None;
            if !has_wan {
                load_error = Some("no WAN network: not enforced".into());
            }
            let (s4, s6) = blocklists::set_names(name);
            let v4: Vec<String> = p.v4.iter().map(ToString::to_string).collect();
            let v6: Vec<String> = p.v6.iter().map(ToString::to_string).collect();
            for (set, els) in [(s4, v4), (s6, v6)].into_iter().filter(|_| has_wan) {
                let digest = Sha256::digest(els.join(",").as_bytes()).to_vec();
                if loaded.get(&set) == Some(&digest) {
                    continue;
                }
                let mut r = nft_load(&load_script(&set, &els)).await;
                // Too big for one netlink message (a socket buffer cap
                // lower than the sysctl asks): in parts, which leaves the
                // set partly filled for the moment it takes.
                if matches!(&r, Err(e) if e.contains("Message too long")) {
                    tracing::warn!(set, entries = els.len(), "loading a blocklist set in parts");
                    r = nft_load(&load_script(&set, &[])).await;
                    for chunk in els.chunks(PART) {
                        if r.is_err() {
                            break;
                        }
                        r = nft_load(&add_script(&set, chunk)).await;
                    }
                }
                match r {
                    Ok(()) => {
                        loaded.insert(set, digest);
                    }
                    // Not there yet (an apply is on its way): next round.
                    Err(e) => {
                        tracing::debug!(set, error = e, "cannot load a blocklist set yet");
                        load_error = Some(e);
                    }
                }
            }
            let st = state.entry(name.clone()).or_default();
            st.load_failures = match load_error {
                Some(e) => (st.load_failures.0 + 1, e),
                None => (0, String::new()),
            };
        }
        // Sets of lists no longer wanted go with the next apply; their
        // kept copies go now.
        let keep: BTreeSet<PathBuf> = wanted.values().map(|b| cached(&dir, &b.url)).collect();
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            if !keep.contains(&e.path()) {
                let _ = std::fs::remove_file(e.path());
            }
        }
        let lists: BTreeMap<String, (String, u64)> = wanted
            .iter()
            .map(|(n, b)| (n.clone(), (b.url.clone(), b.refresh_secs())))
            .collect();
        let checks = assess(&lists, &dir, &state, &counts);
        let _ = with_core_raw(&core, &events, move |c| {
            c.set_named_checks(CHECK, checks);
            Ok(())
        })
        .await;
        // Wake on an apply or a rollback (a reload keeps the sets, but a
        // new list's are new and empty), or after a round.
        let woke = tokio::time::timeout(ROUND, async {
            loop {
                match rx.recv().await {
                    Ok(v)
                        if ["applied", "rolled-back"]
                            .contains(&v["type"].as_str().unwrap_or_default()) =>
                    {
                        break;
                    }
                    Err(broadcast::error::RecvError::Closed) => std::future::pending::<()>().await,
                    _ => {}
                }
            }
        })
        .await;
        if woke.is_ok() {
            // Reload every set after an apply: one rendered anew starts
            // empty, and a reload's prelude keeps only those it preserves.
            loaded.clear();
            let _ = events.send(json!({"type": "blocklists"}));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_set_is_flushed_and_refilled_in_one_script() {
        let els: Vec<String> = (0..5000)
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
            .collect();
        let s = load_script("bl_x_4", &els);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines[0], "flush set inet sparewall bl_x_4");
        assert_eq!(lines.len(), 3, "flush, then 4096 and 904");
        assert!(lines[1].starts_with("add element inet sparewall bl_x_4 { 10.0.0.0/24, "));
        assert_eq!(
            load_script("bl_x_6", &[]),
            "flush set inet sparewall bl_x_6\n"
        );
    }

    #[test]
    fn health_by_list() {
        let dir = std::env::temp_dir().join(format!("sw-bl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lists: BTreeMap<String, (String, u64)> = [
            ("a".to_string(), ("https://a.example/l".to_string(), 3600)),
            ("b".to_string(), ("https://b.example/l".to_string(), 3600)),
        ]
        .into();
        std::fs::write(cached(&dir, "https://a.example/l"), "192.0.2.1/32\n").unwrap();
        let counts: BTreeMap<String, usize> = [("a".to_string(), 1)].into();
        let mut state: BTreeMap<String, State> = BTreeMap::new();
        let ok = assess(&lists, &dir, &state, &counts);
        assert_eq!(ok[0].level, Level::Ok, "{}", ok[0].message);
        assert!(
            ok[0].message.contains("a: 1 entries") && ok[0].message.contains("b: not fetched yet")
        );
        state.insert(
            "b".into(),
            State {
                failed: Some((Instant::now(), "403 Forbidden".into())),
                ..State::default()
            },
        );
        let bad = assess(&lists, &dir, &state, &counts);
        assert_eq!(bad[0].level, Level::Degraded);
        assert!(
            bad[0].message.contains("b: never fetched (403 Forbidden)"),
            "{}",
            bad[0].message
        );
        // A set that keeps failing to load is health's: once is an apply
        // on its way.
        state.insert(
            "a".into(),
            State {
                load_failures: (1, "No such file or directory".into()),
                ..State::default()
            },
        );
        state.remove("b");
        assert_eq!(assess(&lists, &dir, &state, &counts)[0].level, Level::Ok);
        state.get_mut("a").unwrap().load_failures.0 = 2;
        let unloaded = assess(&lists, &dir, &state, &counts);
        assert_eq!(unloaded[0].level, Level::Degraded);
        assert!(
            unloaded[0]
                .message
                .contains("a: not loaded (No such file or directory)")
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
