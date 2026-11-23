//! DNS filters (#74): fetch each filter's lists, keep the last good copy
//! of each under the state directory, and give the resolver each view's
//! blocked names, in the dotfile its configuration includes
//! ([`sparewall_config::filters::view_file`]). Unbound is reloaded when a
//! view's names change.
//!
//! Every node fetches for itself, master or backup: both answer queries.
//! A list that can't be fetched keeps its last copy; with none, its names
//! are simply not blocked, and DNS never waits for a list.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sparewall_config::Document;
use sparewall_config::filters::{self, MAX_LIST_BYTES, View};
use sparewall_core::{Check, Level};
use tokio::sync::broadcast;

use crate::service::{Core, with_core_raw};

const ROUND: Duration = Duration::from_secs(300);
/// After a failed fetch, how long until the next try.
const RETRY: Duration = Duration::from_secs(900);
const FETCH_TIMEOUT: Duration = Duration::from_secs(120);
const DNS_DIR: &str = "/run/sparewall/dns";
const CACHE_DIR: &str = "dns-filters";

/// Where a list's last good copy is kept: its names, one per line.
fn cached(dir: &Path, url: &str) -> PathBuf {
    let h = Sha256::digest(url.as_bytes());
    dir.join(format!("{}.list", hex::encode(&h[..16])))
}

fn age(p: &Path) -> Option<Duration> {
    let m = std::fs::metadata(p).ok()?.modified().ok()?;
    Some(SystemTime::now().duration_since(m).unwrap_or_default())
}

/// Each list the document's filters name, with the shortest `refresh` of
/// the filters that name it.
fn lists(doc: &Document) -> BTreeMap<String, u64> {
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
    for f in doc
        .dns
        .iter()
        .filter(|d| d.enabled)
        .flat_map(|d| d.filters.values())
    {
        for u in &f.lists {
            let r = f.refresh_secs();
            out.entry(u.clone())
                .and_modify(|x| *x = (*x).min(r))
                .or_insert(r);
        }
    }
    out
}

/// A view's file: its blocked names as Unbound zones, and how many were
/// left out past [`filters::MAX_NAMES`].
fn view_body(doc: &Document, v: &View, cache: &Path) -> (String, usize) {
    let Some(d) = &doc.dns else {
        return (String::new(), 0);
    };
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut allow: Vec<String> = Vec::new();
    for f in v.filters.iter().filter_map(|f| d.filters.get(f)) {
        names.extend(f.block.iter().map(|n| filters::normalize(n)));
        allow.extend(f.allow.iter().cloned());
        for u in &f.lists {
            if let Ok(text) = std::fs::read_to_string(cached(cache, u)) {
                names.extend(text.lines().filter(|l| !l.is_empty()).map(str::to_string));
            }
        }
    }
    let (kept, dropped) = filters::compact(names.iter().map(String::as_str), &allow);
    let mut body = String::with_capacity(kept.len() * 48);
    for n in kept {
        body.push_str("    local-zone: \"");
        body.push_str(&n);
        body.push_str(".\" always_nxdomain\n");
    }
    (body, dropped)
}

/// Write each view's file, and remove those of views no longer wanted.
/// Whether anything changed.
fn sync_views(doc: Option<&Document>, cache: &Path, dir: &Path) -> (bool, Vec<String>) {
    let views = doc.map(filters::views).unwrap_or_default();
    let mut changed = false;
    let mut full = Vec::new();
    let mut keep = BTreeSet::new();
    for v in &views {
        let Some(doc) = doc else { break };
        let file = filters::view_file(&v.name);
        let (body, dropped) = view_body(doc, v, cache);
        if dropped > 0 {
            full.push(format!(
                "{}: {dropped} names left out past {}",
                v.name,
                filters::MAX_NAMES
            ));
        }
        let p = dir.join(&file);
        keep.insert(file);
        if std::fs::read(&p).ok().as_deref() != Some(body.as_bytes()) {
            match sparewall_core::store::write_atomic(&p, body.as_bytes()) {
                Ok(()) => changed = true,
                Err(e) => {
                    tracing::warn!(error = %e, view = v.name, "cannot write a DNS filter's names");
                    full.push(format!("{}: cannot write its names: {e}", v.name));
                }
            }
        }
    }
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with(".filter-") && name.ends_with(".conf") && !keep.contains(&name) {
            let _ = std::fs::remove_file(e.path());
            changed = true;
        }
    }
    (changed, full)
}

/// Where a redirect from `at` to `loc` goes: an absolute URL, one
/// without a scheme (`//host/path`), or a path on the same host. Never
/// from HTTPS to plain HTTP: the list would lose the protection the
/// document asked for.
fn redirect(at: &str, loc: &str) -> Result<String, String> {
    let scheme = if at.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    let next = if loc.starts_with("https://") || loc.starts_with("http://") {
        loc.to_string()
    } else if let Some(rest) = loc.strip_prefix("//") {
        format!("{scheme}://{rest}")
    } else if let Some(path) = loc.strip_prefix('/') {
        let base = at.splitn(4, '/').take(3).collect::<Vec<_>>().join("/");
        format!("{base}/{path}")
    } else {
        return Err(format!("to {loc:?}, which isn't a URL or a path"));
    };
    if scheme == "https" && !next.starts_with("https://") {
        return Err(format!("to {next:?}, which isn't HTTPS"));
    }
    Ok(next)
}

/// The body at `url`, following up to five redirects; at most
/// [`MAX_LIST_BYTES`].
async fn fetch(url: &str) -> Result<String, String> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|e| format!("no trusted certificates: {e}"))?
        .https_or_http()
        .enable_http1()
        .build();
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
    let mut at = url.to_string();
    for _ in 0..5 {
        let req = hyper::Request::get(&at)
            .header(hyper::header::USER_AGENT, "sparewall")
            .body(Empty::new())
            .map_err(|e| e.to_string())?;
        let resp = tokio::time::timeout(FETCH_TIMEOUT, client.request(req))
            .await
            .map_err(|_| "timed out".to_string())?
            .map_err(|e| e.to_string())?;
        let status = resp.status();
        if status.is_redirection() {
            let loc = resp
                .headers()
                .get(hyper::header::LOCATION)
                .and_then(|l| l.to_str().ok())
                .ok_or_else(|| format!("{status} with no location"))?;
            at = redirect(&at, loc).map_err(|e| format!("{status}: {e}"))?;
            continue;
        }
        if !status.is_success() {
            return Err(status.to_string());
        }
        let body = tokio::time::timeout(
            FETCH_TIMEOUT,
            Limited::new(resp.into_body(), MAX_LIST_BYTES).collect(),
        )
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| format!("{e} (at most {} MiB)", MAX_LIST_BYTES >> 20))?
        .to_bytes();
        return Ok(String::from_utf8_lossy(&body).into_owned());
    }
    Err("too many redirects".into())
}

async fn reload_resolver() {
    let unit = sparewall_render::unbound::UNIT;
    let active = tokio::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .await
        .is_ok_and(|s| s.success());
    if !active {
        return;
    }
    let ok = tokio::process::Command::new("systemctl")
        .args(["reload", unit])
        .status()
        .await
        .is_ok_and(|s| s.success());
    if !ok {
        tracing::warn!("cannot reload the resolver after its DNS filters changed");
    }
}

/// Health: lists with no copy, or one older than three refreshes, and
/// views past the most names.
fn assess(
    wanted: &BTreeMap<String, u64>,
    cache: &Path,
    failed: &BTreeMap<String, (Instant, String)>,
    full: Vec<String>,
) -> Vec<Check> {
    let mut stale = full;
    for (u, refresh) in wanted {
        let why = failed
            .get(u)
            .map(|(_, e)| format!(" ({e})"))
            .unwrap_or_default();
        match age(&cached(cache, u)) {
            None if failed.contains_key(u) => stale.push(format!("{u}: never fetched{why}")),
            Some(a) if a.as_secs() > 3 * refresh => stale.push(format!(
                "{u}: last fetched {} h ago{why}",
                a.as_secs() / 3600
            )),
            _ => {}
        }
    }
    if stale.is_empty() {
        vec![]
    } else {
        vec![Check::new("dns-filters", Level::Degraded, stale.join("; "))]
    }
}

pub async fn filter_loop(core: Core, events: broadcast::Sender<Value>, state: PathBuf) {
    let cache = state.join(CACHE_DIR);
    let dir = Path::new(DNS_DIR);
    let mut rx = events.subscribe();
    let mut failed: BTreeMap<String, (Instant, String)> = BTreeMap::new();
    loop {
        let doc = with_core_raw(&core, &events, |c| c.active_document())
            .await
            .ok()
            .flatten();
        let wanted = doc.as_ref().map(lists).unwrap_or_default();
        failed.retain(|u, _| wanted.contains_key(u));
        for (u, refresh) in &wanted {
            let p = cached(&cache, u);
            let due = age(&p).is_none_or(|a| a.as_secs() >= *refresh);
            let waiting = failed.get(u).is_some_and(|(t, _)| t.elapsed() < RETRY);
            if !due || waiting {
                continue;
            }
            match fetch(u).await {
                Ok(text) => {
                    let names = filters::parse_list(&text);
                    let mut body = names.join("\n");
                    body.push('\n');
                    match sparewall_core::store::write_atomic(&p, body.as_bytes()) {
                        Ok(()) => {
                            tracing::info!(
                                list = u,
                                names = names.len(),
                                "fetched a DNS filter list"
                            );
                            failed.remove(u);
                        }
                        Err(e) => {
                            tracing::warn!(list = u, error = %e, "cannot keep a DNS filter list");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(list = u, error = e, "cannot fetch a DNS filter list");
                    failed.insert(u.clone(), (Instant::now(), e));
                }
            }
        }
        // Lists no filter names any more.
        let keep: BTreeSet<PathBuf> = wanted.keys().map(|u| cached(&cache, u)).collect();
        for e in std::fs::read_dir(&cache).into_iter().flatten().flatten() {
            if !keep.contains(&e.path()) {
                let _ = std::fs::remove_file(e.path());
            }
        }
        let (changed, full) = sync_views(doc.as_ref(), &cache, dir);
        if changed {
            reload_resolver().await;
            let _ = events.send(json!({"type": "dns-filters"}));
        }
        let checks = assess(&wanted, &cache, &failed, full);
        let _ = with_core_raw(&core, &events, move |c| {
            c.set_named_checks("dns-filters", checks);
            Ok(())
        })
        .await;
        // Wake on an apply or a rollback, or after a round.
        let _ = tokio::time::timeout(ROUND, async {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(filters: Value) -> Document {
        let text = include_str!("../../../examples/standalone.yaml");
        let mut v = sparewall_config::to_value(
            &sparewall_config::parse(text, sparewall_config::Format::Yaml).unwrap(),
        );
        sparewall_config::merge_patch(&mut v, &json!({"dns": {"filters": filters}}));
        sparewall_config::from_value(v).unwrap()
    }

    #[test]
    fn views_get_their_lists_blocks_and_allows() {
        let tmp = std::env::temp_dir().join(format!("sw-filters-{}", std::process::id()));
        let (cache, dir) = (tmp.join("cache"), tmp.join("dns"));
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let d = doc(json!({
            "ads": {"networks": ["users", "guests"], "lists": ["https://l.example/a"],
                "allow": ["ok.example.com"]},
            "kids": {"networks": ["users"], "block": ["Games.example."]},
        }));
        std::fs::write(
            cached(&cache, "https://l.example/a"),
            "ads.example.com\nx.ads.example.com\nok.example.com\nsub.ok.example.com\n",
        )
        .unwrap();
        std::fs::write(dir.join(".filter-gone.conf"), "x").unwrap();
        std::fs::write(dir.join("unbound.conf"), "x").unwrap();
        let (changed, full) = sync_views(Some(&d), &cache, &dir);
        assert!(changed && full.is_empty());
        let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap();
        assert_eq!(
            read(".filter-ads.conf"),
            "    local-zone: \"ads.example.com.\" always_nxdomain\n"
        );
        assert_eq!(
            read(".filter-ads+kids.conf"),
            "    local-zone: \"ads.example.com.\" always_nxdomain\n    local-zone: \"games.example.\" always_nxdomain\n"
        );
        assert!(!dir.join(".filter-gone.conf").exists());
        assert!(dir.join("unbound.conf").exists());
        // Nothing new: nothing to reload.
        assert!(!sync_views(Some(&d), &cache, &dir).0);
        // No filters: every view's file goes.
        assert!(sync_views(None, &cache, &dir).0);
        assert!(!dir.join(".filter-ads.conf").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn stale_and_missing_lists_degrade_health() {
        let tmp = std::env::temp_dir().join(format!("sw-filters-h-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let mut wanted = BTreeMap::new();
        wanted.insert("https://l.example/a".to_string(), 3600);
        wanted.insert("https://l.example/b".to_string(), 3600);
        std::fs::write(cached(&tmp, "https://l.example/b"), "x.example\n").unwrap();
        // Not tried yet: nothing to say.
        assert!(assess(&wanted, &tmp, &BTreeMap::new(), vec![]).is_empty());
        let mut failed = BTreeMap::new();
        failed.insert(
            "https://l.example/a".to_string(),
            (Instant::now(), "404 Not Found".to_string()),
        );
        let c = assess(&wanted, &tmp, &failed, vec![]);
        assert_eq!(c.len(), 1);
        assert_eq!(
            c[0].message,
            "https://l.example/a: never fetched (404 Not Found)"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn redirects_never_drop_tls() {
        let a = "https://lists.example/ads.txt";
        assert_eq!(
            redirect(a, "https://cdn.example/x").unwrap(),
            "https://cdn.example/x"
        );
        assert_eq!(
            redirect(a, "/v2/ads.txt").unwrap(),
            "https://lists.example/v2/ads.txt"
        );
        assert_eq!(
            redirect(a, "//cdn.example/x").unwrap(),
            "https://cdn.example/x"
        );
        assert!(
            redirect(a, "http://cdn.example/x")
                .unwrap_err()
                .contains("isn't HTTPS")
        );
        assert!(redirect(a, "ads2.txt").is_err());
        let h = "http://lists.example/ads.txt";
        assert_eq!(
            redirect(h, "https://cdn.example/x").unwrap(),
            "https://cdn.example/x"
        );
        assert_eq!(redirect(h, "/y").unwrap(), "http://lists.example/y");
    }

    #[test]
    fn the_shortest_refresh_wins() {
        let d = doc(json!({
            "a": {"networks": ["users"], "lists": ["https://l.example/x"], "refresh": "6h"},
            "b": {"networks": ["guests"], "lists": ["https://l.example/x"]},
        }));
        assert_eq!(lists(&d)["https://l.example/x"], 6 * 3600);
    }
}
