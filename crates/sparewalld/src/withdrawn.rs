//! Announcing a delegated network's withdrawn /64 as deprecated (#232),
//! until networkd does it itself: see [`sparewall_core::withdrawn`].
//!
//! Each round reads the prefix in use (this node's own delegated one, or
//! on a pair's backup the master's last), keeps the /64s each delegated
//! network used in the state directory, and keeps a drop-in beside the
//! `.network` file whose link sends the network's advertisements listing
//! the withdrawn ones. A changed drop-in takes a `networkctl reload`,
//! which also sends a few advertisements at once. A pair's backup keeps
//! its drop-ins too, on a link that is down, so a failover inside the
//! two hours goes on announcing them.
//!
//! The same round keeps the sets of `ipv6` objects that name hosts by
//! suffix on a delegated network (#245) at each suffix in each /64 a
//! rule should still reach: those of the prefixes in use (this node's
//! own, and the peer's last while valid, so a host's rules keep working
//! through a failover), and those announced as deprecated, so existing
//! connections to a renumbered host are not cut by the policy. An apply,
//! a rollback or a VRRP transition starts a round at once.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sparewall_config::Document;
use sparewall_core::ipv6;
use sparewall_core::withdrawn::{DROPIN, Withdrawn, dropin, in_use};
use sparewall_render::networkd::ra_network_file;
use tokio::sync::broadcast;

use crate::peer::Pair;
use crate::service::{Core, with_core_raw};

const ROUND: Duration = Duration::from_secs(10);
const STATE_FILE: &str = "ipv6-withdrawn.json";
const NETWORK_DIR: &str = "/run/systemd/network";

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The peer's last prefixes while valid, each with the seconds left of
/// its valid lifetime.
fn peer_valid(
    peer: Option<&(Instant, Vec<sparewall_api::DelegatedPrefix>)>,
    now: Instant,
) -> Vec<(String, Option<u64>)> {
    let Some((heard, prefixes)) = peer else {
        return vec![];
    };
    let elapsed = now.saturating_duration_since(*heard).as_secs();
    prefixes
        .iter()
        .filter_map(|p| match p.valid_seconds {
            None => Some((p.prefix.clone(), None)),
            Some(s) => {
                let left = u64::try_from(s).unwrap_or(0).checked_sub(elapsed)?;
                (left > 0).then(|| (p.prefix.clone(), Some(left)))
            }
        })
        .collect()
}

fn own_prefixes(own: &[ipv6::Lifetimed]) -> Vec<(String, Option<u64>)> {
    own.iter()
        .map(|p| (p.address.clone(), p.valid_seconds))
        .collect()
}

/// The prefixes in use, each with the seconds left of its valid lifetime:
/// this node's own, or failing those the peer's last while valid.
fn prefixes_in_use(
    own: &[ipv6::Lifetimed],
    peer: Option<&(Instant, Vec<sparewall_api::DelegatedPrefix>)>,
    now: Instant,
) -> Vec<(String, Option<u64>)> {
    if !own.is_empty() {
        return own_prefixes(own);
    }
    peer_valid(peer, now)
}

/// The /64s, by delegated network, that rules naming hosts by suffix
/// reach (#245): of this node's own prefixes and the peer's last while
/// valid, and those announced as deprecated.
fn reached(
    doc: &Document,
    own: &[ipv6::Lifetimed],
    peer: Option<&(Instant, Vec<sparewall_api::DelegatedPrefix>)>,
    w: &Withdrawn,
    now: (Instant, u64),
) -> BTreeMap<String, BTreeSet<String>> {
    let mut prefixes: Vec<(String, Option<u64>)> = own_prefixes(own)
        .into_iter()
        .filter(|(_, left)| *left != Some(0))
        .collect();
    prefixes.extend(peer_valid(peer, now.0));
    let mut out: BTreeMap<String, BTreeSet<String>> = in_use(doc, &prefixes, now.1)
        .into_iter()
        .map(|(net, nets)| (net, nets.into_keys().collect()))
        .collect();
    for (net, a) in &w.announced {
        if let Some(o) = out.get_mut(net) {
            o.extend(a.keys().cloned());
        }
    }
    out
}

/// The drop-ins wanted, by path.
fn wanted(doc: Option<&Document>, w: &Withdrawn, dir: &Path) -> BTreeMap<PathBuf, String> {
    let Some(doc) = doc else {
        return BTreeMap::new();
    };
    w.announced
        .iter()
        .filter_map(|(net, a)| {
            let f = ra_network_file(doc, net)?;
            Some((dir.join(format!("{f}.d")).join(DROPIN), dropin(a)))
        })
        .collect()
}

/// The drop-ins there now, by path.
fn present(dir: &Path) -> BTreeMap<PathBuf, String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return BTreeMap::new();
    };
    rd.flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".network.d"))
        .filter_map(|e| {
            let p = e.path().join(DROPIN);
            let text = std::fs::read_to_string(&p).ok()?;
            Some((p, text))
        })
        .collect()
}

/// Make the drop-ins as wanted; whether any changed.
fn sync_dropins(want: &BTreeMap<PathBuf, String>, have: &BTreeMap<PathBuf, String>) -> bool {
    let mut changed = false;
    for (p, text) in want {
        if have.get(p) == Some(text) {
            continue;
        }
        let ok = p
            .parent()
            .is_some_and(|d| std::fs::create_dir_all(d).is_ok())
            && sparewall_core::store::write_atomic(p, text.as_bytes()).is_ok();
        if ok {
            changed = true;
        } else {
            tracing::warn!(path = %p.display(), "cannot write the withdrawn prefixes' drop-in");
        }
    }
    for p in have.keys().filter(|p| !want.contains_key(*p)) {
        if std::fs::remove_file(p).is_ok() {
            changed = true;
        }
        if let Some(d) = p.parent() {
            // Only if empty: an admin's own drop-ins stay.
            let _ = std::fs::remove_dir(d);
        }
    }
    changed
}

pub async fn withdrawn_loop(
    core: Core,
    events: broadcast::Sender<Value>,
    pair: Pair,
    state: PathBuf,
) {
    let state_file = state.join(STATE_FILE);
    let dir = Path::new(NETWORK_DIR);
    let mut rx = events.subscribe();
    let mut w: Withdrawn = std::fs::read(&state_file)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    loop {
        let (doc, own) = with_core_raw(&core, &events, |c| {
            let doc = c.active_document()?;
            let delegates = |d: &&Document| {
                d.networks.values().any(|n| {
                    n.ipv6
                        .as_ref()
                        .is_some_and(|v| v.mode == sparewall_config::model::Ipv6Mode::Delegated)
                })
            };
            let own = match doc.as_ref().filter(delegates) {
                Some(d) => ipv6::delegated(d, &c.system().ipv6_links()),
                None => vec![],
            };
            Ok((doc, own))
        })
        .await
        .unwrap_or_default();
        let peer = pair
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .peer_delegated
            .clone();
        let now = unix_now();
        let current = match &doc {
            Some(d) => in_use(
                d,
                &prefixes_in_use(&own, peer.as_ref(), Instant::now()),
                now,
            ),
            None => BTreeMap::new(),
        };
        let before = w.announced.clone();
        if w.update(&current, now) {
            if let Ok(b) = serde_json::to_vec(&w)
                && let Err(e) = sparewall_core::store::write_atomic(&state_file, &b)
            {
                tracing::warn!(error = %e, "cannot save the delegated prefixes in use");
            }
            for (net, a) in &w.announced {
                for p in a.keys() {
                    if !before.get(net).is_some_and(|b| b.contains_key(p)) {
                        tracing::info!(
                            network = net,
                            prefix = p,
                            "announcing a withdrawn delegated prefix as deprecated"
                        );
                    }
                }
            }
        }
        if sync_dropins(&wanted(doc.as_ref(), &w, dir), &present(dir)) {
            let ok = tokio::process::Command::new("networkctl")
                .arg("reload")
                .status()
                .await
                .is_ok_and(|s| s.success());
            if !ok {
                tracing::warn!("networkctl reload failed after changing the withdrawn prefixes");
            }
            let _ =
                events.send(json!({"type": "ipv6-withdrawn", "announced": w.announced, "ok": ok}));
        }
        if let Some(d) = &doc {
            let r = reached(d, &own, peer.as_ref(), &w, (Instant::now(), now));
            for (set, els) in sparewall_render::nft::suffix_sets(d, &r) {
                crate::lease::fill_set(&set, &els).await;
            }
        }
        // Wake on an apply, a rollback or a transition, or after a round.
        let _ = tokio::time::timeout(ROUND, async {
            loop {
                match rx.recv().await {
                    Ok(v)
                        if ["applied", "rolled-back", "vrrp"]
                            .contains(&v["type"].as_str().unwrap_or_default()) =>
                    {
                        return;
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => return,
                    Err(broadcast::error::RecvError::Closed) => std::future::pending().await,
                }
            }
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sparewall_api::DelegatedPrefix;
    use sparewall_core::ipv6::Lifetimed;

    #[test]
    fn the_prefix_in_use_is_this_node_s_or_the_peer_s_last() {
        let own = vec![Lifetimed {
            address: "2001:db8:200::/56".into(),
            preferred_seconds: Some(90),
            valid_seconds: Some(180),
        }];
        let t0 = Instant::now();
        let peer = (
            t0,
            vec![
                DelegatedPrefix {
                    prefix: "2001:db8:100::/56".into(),
                    preferred_seconds: Some(90),
                    valid_seconds: Some(180),
                },
                DelegatedPrefix {
                    prefix: "2001:db8:300::/56".into(),
                    preferred_seconds: None,
                    valid_seconds: None,
                },
            ],
        );
        assert_eq!(
            prefixes_in_use(&own, Some(&peer), t0),
            [("2001:db8:200::/56".to_string(), Some(180))]
        );
        let later = t0 + Duration::from_secs(100);
        assert_eq!(
            prefixes_in_use(&[], Some(&peer), later),
            [
                ("2001:db8:100::/56".to_string(), Some(80)),
                ("2001:db8:300::/56".to_string(), None)
            ]
        );
        let lapsed = t0 + Duration::from_secs(200);
        assert_eq!(
            prefixes_in_use(&[], Some(&peer), lapsed),
            [("2001:db8:300::/56".to_string(), None)]
        );
        assert!(prefixes_in_use(&[], None, t0).is_empty());
    }

    /// The two-NIC example, its LAN on subnet 1 of a delegated prefix.
    fn delegated_lan() -> Document {
        let text = std::fs::read_to_string(format!(
            "{}/../../examples/two-nic.yaml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let d = sparewall_config::parse(&text, sparewall_config::Format::Yaml).unwrap();
        let mut v = sparewall_config::to_value(&d);
        sparewall_config::merge_patch(
            &mut v,
            &json!({"networks": {
                "wan": {"ipv6": {"mode": "dhcpv6"}},
                "lan": {"ipv6": {"mode": "delegated", "subnet_id": 1}}}}),
        );
        sparewall_config::from_value(v).unwrap()
    }

    /// The /64s a rule by suffix reaches (#245): this node's prefix, the
    /// peer's last while valid (a takeover), and the deprecated ones.
    #[test]
    fn rules_by_suffix_reach_every_64_still_in_use() {
        let doc = delegated_lan();
        let t0 = Instant::now();
        let now = (t0, 1_000_000);
        let lan = |r: BTreeMap<String, BTreeSet<String>>| -> Vec<String> {
            r.get("lan").into_iter().flatten().cloned().collect()
        };
        let own = |p: &str, valid: Option<u64>| Lifetimed {
            address: p.into(),
            preferred_seconds: valid,
            valid_seconds: valid,
        };
        let w = Withdrawn::default();
        assert!(lan(reached(&doc, &[], None, &w, now)).is_empty());
        assert_eq!(
            lan(reached(
                &doc,
                &[own("2001:db8:100::/56", Some(180))],
                None,
                &w,
                now
            )),
            ["2001:db8:100:1::/64"]
        );
        // One whose lease has run out is not.
        assert!(
            lan(reached(
                &doc,
                &[own("2001:db8:100::/56", Some(0))],
                None,
                &w,
                now
            ))
            .is_empty()
        );
        // A takeover: the old master's prefix while valid, beside this
        // node's own once it has one.
        let peer = (
            t0,
            vec![DelegatedPrefix {
                prefix: "2001:db8:100::/56".into(),
                preferred_seconds: Some(90),
                valid_seconds: Some(180),
            }],
        );
        assert_eq!(
            lan(reached(&doc, &[], Some(&peer), &w, now)),
            ["2001:db8:100:1::/64"]
        );
        assert_eq!(
            lan(reached(
                &doc,
                &[own("2001:db8:200::/56", Some(180))],
                Some(&peer),
                &w,
                now
            )),
            ["2001:db8:100:1::/64", "2001:db8:200:1::/64"]
        );
        let lapsed = (t0 + Duration::from_secs(200), now.1 + 200);
        assert_eq!(
            lan(reached(
                &doc,
                &[own("2001:db8:200::/56", Some(180))],
                Some(&peer),
                &w,
                lapsed
            )),
            ["2001:db8:200:1::/64"]
        );
        // Renumbered: the withdrawn /64, while announced as deprecated.
        let mut w = Withdrawn::default();
        let first = in_use(&doc, &[("2001:db8:100::/56".into(), Some(3600))], now.1);
        w.update(&first, now.1);
        let second = in_use(
            &doc,
            &[("2001:db8:200::/56".into(), Some(3600))],
            now.1 + 10,
        );
        w.update(&second, now.1 + 10);
        assert_eq!(
            lan(reached(
                &doc,
                &[own("2001:db8:200::/56", Some(3600))],
                None,
                &w,
                (t0, now.1 + 10)
            )),
            ["2001:db8:100:1::/64", "2001:db8:200:1::/64"]
        );
    }

    #[test]
    fn drop_ins_are_written_and_removed() {
        let tmp = std::env::temp_dir().join(format!("sw-withdrawn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("20-sparewall-lan0.network.d")).unwrap();
        // An admin's own drop-in, beside ours: left alone.
        std::fs::write(tmp.join("20-sparewall-lan0.network.d/10-mine.conf"), "x").unwrap();
        let p = tmp.join("30-sparewall-users.network.d").join(DROPIN);
        let want = BTreeMap::from([(p.clone(), "a".to_string())]);
        assert!(sync_dropins(&want, &present(&tmp)));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "a");
        assert!(!sync_dropins(&want, &present(&tmp)));
        assert!(sync_dropins(&BTreeMap::new(), &present(&tmp)));
        assert!(!p.exists() && !p.parent().unwrap().exists());
        assert!(
            tmp.join("20-sparewall-lan0.network.d/10-mine.conf")
                .exists()
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
