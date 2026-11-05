//! Links a pair keeps up on the master only, which networkd leaves down
//! (`ActivationPolicy=manual`):
//!
//! - the one WAN lease (#54): both nodes have the lease link (a macvlan
//!   with the VRRP virtual MAC, running the DHCP client), so the ISP sees
//!   one MAC and one client ID, and the lease moves with the gateway;
//! - the VPN clients (#149): both nodes hold the same key, so the
//!   service sees one client, which moves with the gateway;
//! - the inside networks' IPv6 gateways (#215), which send the router
//!   advertisements from `fe80::1` and the IPv6 virtual MAC.
//!
//! The links are reconciled on every keepalived transition and every few
//! seconds, so a link created by an apply, or a restart of this daemon,
//! catches up.
//!
//! IPv6 in a pair (#215) runs here too:
//!
//! - **The delegated prefix:** each round reads the prefixes DHCPv6
//!   delegated to this node, for the peer's hello. The backup keeps the
//!   master's last ones.
//! - **At a failover:** until the new master's own DHCPv6 reply arrives,
//!   it routes the delegated networks' /64s of the old master's prefix to
//!   their gateway links, expiring with the prefix, so hosts' addresses
//!   keep working. The RAs carry no prefix meanwhile, which leaves hosts'
//!   addresses as they were. With the expected same prefix, networkd's own
//!   routes take over, and these go.
//! - **Health:** the master checks its IPv6; the backup has none by design.
//! - **ipv6 objects** on a delegated network: networkd fills them from the
//!   node's address there, which a pair's nodes do not take, so this loop
//!   keeps them at the /64s of the prefixes in use: the node's own, and
//!   the peer's last while valid (routed at a takeover).

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sparewall_api::DelegatedPrefix;
use sparewall_config::Document;
use sparewall_config::model::{DynamicKind, Ipv6Mode, ObjectKind};
use sparewall_config::topology::LEASE_IFACE;
use sparewall_core::ipv6::{self, Lifetimed};
use tokio::sync::broadcast;

use crate::peer::Pair;
use crate::service::{Core, with_core_raw};

const ROUND: Duration = Duration::from_secs(5);

/// Whether the link exists, and whether it is administratively up.
async fn link_up(iface: &str) -> Option<bool> {
    let out = tokio::process::Command::new("ip")
        .args(["-j", "link", "show", "dev", iface])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    let flags = v.get(0)?.get("flags")?.as_array()?;
    Some(flags.iter().any(|f| f == "UP"))
}

/// The links up on a pair's master only: the WAN lease's, the VPN
/// clients', and the IPv6 gateways'. None on a standalone node, which
/// keeps them up.
pub fn master_links(doc: &Document) -> Vec<String> {
    if !doc.is_pair() {
        return vec![];
    }
    let mut v: Vec<String> = Vec::new();
    if doc.networks.keys().any(|n| doc.leased_wan(n).is_some()) {
        v.push(LEASE_IFACE.to_string());
    }
    v.extend(doc.vpn_clients.keys().cloned());
    v.extend(
        doc.networks
            .keys()
            .filter_map(|n| doc.ipv6_gateway_iface(n)),
    );
    v
}

/// The metric of a route a new master adds for a delegated network until
/// its own DHCPv6 reply arrives: below networkd's (1024), which wins once
/// it is there.
pub const TAKEOVER_METRIC: u32 = 2048;
/// The longest a taken-over route lasts, for a prefix valid forever.
const TAKEOVER_MAX_S: u64 = 86_400;

/// A route to a delegated network's /64 on its gateway link.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Takeover {
    pub iface: String,
    pub dst: String,
    /// Seconds left of the prefix's valid lifetime.
    pub expires: u64,
}

/// The prefixes delegated to this node, as the peer hears them.
pub fn to_peer(own: &[Lifetimed]) -> Vec<DelegatedPrefix> {
    let secs = |s: Option<u64>| s.map(|s| i64::try_from(s).unwrap_or(i64::MAX));
    own.iter()
        .map(|p| DelegatedPrefix {
            prefix: p.address.clone(),
            preferred_seconds: secs(p.preferred_seconds),
            valid_seconds: secs(p.valid_seconds),
        })
        .collect()
}

/// What a master routes for its delegated networks from the peer's last
/// prefixes, heard at `heard` (#215): those it does not hold itself (once
/// it does, networkd routes it), while they are valid. A prefix the new
/// lease does not repeat stays routed for hosts' addresses in it, which
/// they keep, since nothing announces it withdrawn.
pub fn takeovers(
    doc: &Document,
    own: &[Lifetimed],
    peer: Option<&(Instant, Vec<DelegatedPrefix>)>,
    now: Instant,
) -> Vec<Takeover> {
    let Some((heard, prefixes)) = peer else {
        return vec![];
    };
    let mut out = Vec::new();
    for p in prefixes
        .iter()
        .filter(|p| !own.iter().any(|o| o.address == p.prefix))
    {
        let Some(left) = left(p, *heard, now) else {
            continue;
        };
        for (name, net) in &doc.networks {
            let (Some(iface), Some(v6)) = (doc.ipv6_gateway_iface(name), &net.ipv6) else {
                continue;
            };
            if v6.mode != Ipv6Mode::Delegated {
                continue;
            }
            if let Some(dst) = v6.subnet_id.and_then(|id| ipv6::subnet64(&p.prefix, id)) {
                out.push(Takeover {
                    iface,
                    dst,
                    expires: left,
                });
            }
        }
    }
    out.sort();
    out.dedup_by(|a, b| a.iface == b.iface && a.dst == b.dst);
    out
}

/// The seconds left of a heard prefix's valid lifetime, capped; `None`
/// once lapsed.
fn left(p: &DelegatedPrefix, heard: Instant, now: Instant) -> Option<u64> {
    let elapsed = now.saturating_duration_since(heard).as_secs();
    p.valid_seconds
        .map_or(TAKEOVER_MAX_S, |s| u64::try_from(s).unwrap_or(0))
        .min(TAKEOVER_MAX_S)
        .checked_sub(elapsed)
        .filter(|l| *l > 0)
}

/// A pair's ipv6 objects on delegated networks (#215), by set name, with
/// the elements they should hold: the network's /64 of each prefix the
/// node holds, and of each the peer last reported while it is valid.
pub fn object_elements(
    doc: &Document,
    own: &[Lifetimed],
    peer: Option<&(Instant, Vec<DelegatedPrefix>)>,
    now: Instant,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut prefixes: Vec<&str> = own
        .iter()
        .filter(|p| p.valid_seconds != Some(0))
        .map(|p| p.address.as_str())
        .collect();
    if let Some((heard, ps)) = peer {
        prefixes.extend(
            ps.iter()
                .filter(|p| left(p, *heard, now).is_some())
                .map(|p| p.prefix.as_str()),
        );
    }
    let mut out = BTreeMap::new();
    for (name, o) in &doc.objects {
        let Some(d) = &o.dynamic else { continue };
        if o.kind != ObjectKind::Ipv6 || d.source != DynamicKind::Prefix {
            continue;
        }
        let Some(v6) = doc.networks.get(&d.network).and_then(|n| n.ipv6.as_ref()) else {
            continue;
        };
        if doc.ipv6_gateway_iface(&d.network).is_none() || v6.mode != Ipv6Mode::Delegated {
            continue;
        }
        let Some(id) = v6.subnet_id else { continue };
        out.insert(
            name.clone(),
            prefixes
                .iter()
                .filter_map(|p| ipv6::subnet64(p, id))
                .collect(),
        );
    }
    out
}

/// A set's elements from `nft -j list set`: addresses, prefixes
/// (`2001:db8::/64`) and ranges (`a-b`).
pub fn set_elements(listing: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for item in listing["nftables"].as_array().into_iter().flatten() {
        for e in item["set"]["elem"].as_array().into_iter().flatten() {
            let e = e.get("elem").map_or(e, |x| &x["val"]);
            if let Some(a) = e.as_str() {
                out.insert(a.to_string());
            } else if let (Some(a), Some(l)) =
                (e["prefix"]["addr"].as_str(), e["prefix"]["len"].as_u64())
            {
                out.insert(format!("{a}/{l}"));
            } else if let Some([a, b]) = e["range"].as_array().map(Vec::as_slice)
                && let (Some(a), Some(b)) = (a.as_str(), b.as_str())
            {
                out.insert(format!("{a}-{b}"));
            }
        }
    }
    out
}

async fn nft(args: &[&str]) -> Option<Vec<u8>> {
    let out = tokio::process::Command::new("nft")
        .args(args)
        .output()
        .await
        .ok()?;
    out.status.success().then_some(out.stdout)
}

/// Bring a coordinator-filled set to `want`.
async fn fill_set(name: &str, want: &BTreeSet<String>) {
    let table = sparewall_render::nft::TABLE;
    // Not there (an apply is on its way): next round.
    let Some(listing) = nft(&["-j", "list", "set", "inet", table, name]).await else {
        return;
    };
    let have = serde_json::from_slice(&listing)
        .map(|v| set_elements(&v))
        .unwrap_or_default();
    let add: Vec<&str> = want.difference(&have).map(String::as_str).collect();
    let del: Vec<&str> = have.difference(want).map(String::as_str).collect();
    for (verb, els) in [("add", add), ("delete", del)] {
        if els.is_empty() {
            continue;
        }
        let list = format!("{{ {} }}", els.join(", "));
        if nft(&[verb, "element", "inet", table, name, &list])
            .await
            .is_some()
        {
            tracing::info!(set = name, verb, elements = %list, "an ipv6 object follows the delegated prefix");
        } else {
            tracing::warn!(set = name, verb, elements = %list, "cannot update an ipv6 object");
        }
    }
}

/// A pair's `ipv6` check by role: the master's own; the backup's says
/// IPv6 runs on the master; any other role (FAULT, or not known yet)
/// holds no IPv6 for hosts, and says so.
pub fn ipv6_check(
    doc: &Document,
    links: &std::collections::BTreeMap<String, ipv6::LinkIpv6>,
    role: Option<&str>,
) -> Option<sparewall_core::Check> {
    match role {
        Some("MASTER") => ipv6::health(doc, links),
        Some("BACKUP") => ipv6::standby(doc),
        other => doc.routes_ipv6().then(|| {
            sparewall_core::Check::new(
                "ipv6",
                sparewall_core::Level::Degraded,
                format!(
                    "neither master nor backup ({}): IPv6 runs on the master",
                    other.unwrap_or("role not known yet")
                ),
            )
        }),
    }
}

async fn ip(args: &[&str]) -> bool {
    tokio::process::Command::new("ip")
        .args(args)
        .status()
        .await
        .is_ok_and(|s| s.success())
}

/// What to do with the lease link, if anything: `Some(true)` to bring it
/// up, `Some(false)` to take it down.
pub fn wanted(master: bool, up: Option<bool>) -> Option<bool> {
    match up {
        Some(up) if up != master => Some(master),
        _ => None,
    }
}

pub async fn lease_loop(core: Core, events: broadcast::Sender<Value>, pair: Pair) {
    let mut rx = events.subscribe();
    // The routes this node added at a takeover, to remove once networkd's
    // are there.
    let mut taken: BTreeSet<(String, String)> = BTreeSet::new();
    loop {
        let master = {
            let p = pair.lock().unwrap_or_else(|p| p.into_inner());
            p.role.as_deref() == Some("MASTER")
        };
        let role = pair.lock().unwrap_or_else(|p| p.into_inner()).role.clone();
        let (links, doc, own) = with_core_raw(&core, &events, move |c| {
            let doc = c.active_document()?;
            let v6 = doc.as_ref().filter(|d| d.is_pair() && d.routes_ipv6());
            let (own, check) = match v6 {
                Some(d) => {
                    let l = c.system().ipv6_links();
                    (ipv6::delegated(d, &l), ipv6_check(d, &l, role.as_deref()))
                }
                None => (vec![], None),
            };
            c.set_named_checks("ipv6", check.into_iter().collect());
            Ok((doc.as_ref().map(master_links).unwrap_or_default(), doc, own))
        })
        .await
        .unwrap_or_default();
        let peer = {
            let mut p = pair.lock().unwrap_or_else(|p| p.into_inner());
            p.delegated = to_peer(&own);
            p.peer_delegated.clone()
        };
        for link in &links {
            if let Some(up) = wanted(master, link_up(link).await) {
                let verb = if up { "up" } else { "down" };
                let ok = tokio::process::Command::new("networkctl")
                    .args([verb, link])
                    .status()
                    .await
                    .is_ok_and(|s| s.success());
                if ok {
                    tracing::info!(link, verb, "a link that follows the master");
                } else {
                    tracing::warn!(link, verb, "cannot change a link that follows the master");
                }
                let _ = events.send(json!({"type": "lease", "link": link, "up": up, "ok": ok}));
            }
        }
        if let Some(d) = &doc {
            for (set, els) in object_elements(d, &own, peer.as_ref(), Instant::now()) {
                fill_set(&set, &els).await;
            }
        }
        let want = match (&doc, master) {
            (Some(d), true) => takeovers(d, &own, peer.as_ref(), Instant::now()),
            _ => vec![],
        };
        for t in &want {
            let (expires, metric) = (t.expires.to_string(), TAKEOVER_METRIC.to_string());
            let args = [
                "-6", "route", "replace", &t.dst, "dev", &t.iface, "metric", &metric, "expires",
                &expires, "proto", "static",
            ];
            if ip(&args).await {
                if taken.insert((t.iface.clone(), t.dst.clone())) {
                    tracing::info!(
                        dst = t.dst,
                        iface = t.iface,
                        expires = t.expires,
                        "routing the old master's delegated prefix until this node's own arrives"
                    );
                }
            } else {
                tracing::warn!(
                    dst = t.dst,
                    iface = t.iface,
                    "cannot route the old master's delegated prefix"
                );
            }
        }
        let gone: Vec<(String, String)> = taken
            .iter()
            .filter(|(i, d)| !want.iter().any(|t| &t.iface == i && &t.dst == d))
            .cloned()
            .collect();
        for (iface, dst) in gone {
            let metric = TAKEOVER_METRIC.to_string();
            // Gone already with the link, or by expiring, as often as not.
            let _ = ip(&["-6", "route", "del", &dst, "dev", &iface, "metric", &metric]).await;
            taken.remove(&(iface, dst));
        }
        // Wake on a transition, or after a round.
        let _ = tokio::time::timeout(ROUND, async {
            loop {
                match rx.recv().await {
                    Ok(v) if v["type"] == "vrrp" => return,
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

    #[test]
    fn the_link_follows_the_role() {
        assert_eq!(wanted(true, Some(false)), Some(true));
        assert_eq!(wanted(false, Some(true)), Some(false));
        assert_eq!(wanted(true, Some(true)), None);
        assert_eq!(wanted(false, Some(false)), None);
        // Not created yet (an apply is on its way): nothing to do.
        assert_eq!(wanted(true, None), None);
    }

    fn pair_v6() -> Document {
        let text = std::fs::read_to_string(format!(
            "{}/../../examples/pair.yaml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let d = sparewall_config::parse(&text, sparewall_config::Format::Yaml).unwrap();
        let mut v = sparewall_config::to_value(&d);
        sparewall_config::merge_patch(
            &mut v,
            &json!({"networks": {
                "wan": {"dhcp_client": true, "vip": null, "extra_vips": [], "gateway": null,
                    "ipv6": {"mode": "dhcpv6"}},
                "users": {"ipv6": {"mode": "delegated", "subnet_id": 1}}}}),
        );
        sparewall_config::from_value(v).unwrap()
    }

    #[test]
    fn ipv6_health_by_role() {
        use sparewall_core::Level;
        let d = pair_v6();
        let none = std::collections::BTreeMap::new();
        // The master without its lease: degraded, as a standalone node's.
        assert_eq!(
            ipv6_check(&d, &none, Some("MASTER")).unwrap().level,
            Level::Degraded
        );
        assert_eq!(
            ipv6_check(&d, &none, Some("BACKUP")).unwrap().level,
            Level::Ok
        );
        for role in [Some("FAULT"), None] {
            let c = ipv6_check(&d, &none, role).unwrap();
            assert_eq!(c.level, Level::Degraded, "{role:?}");
        }
    }

    #[test]
    fn a_pair_s_ipv6_objects_follow_the_prefixes_in_use() {
        let mut v = sparewall_config::to_value(&pair_v6());
        sparewall_config::merge_patch(
            &mut v,
            &json!({"objects": {
                "users6": {"type": "ipv6", "dynamic": {"network": "users", "source": "prefix"}}}}),
        );
        let d: Document = sparewall_config::from_value(v).unwrap();
        let t0 = Instant::now();
        let own = [Lifetimed {
            address: "2001:db8:200::/56".into(),
            preferred_seconds: Some(1800),
            valid_seconds: Some(3600),
        }];
        let heard = (
            t0,
            vec![DelegatedPrefix {
                prefix: "2001:db8:100::/56".into(),
                preferred_seconds: Some(0),
                valid_seconds: Some(600),
            }],
        );
        let set = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        let e = object_elements(&d, &own, Some(&heard), t0);
        assert_eq!(
            e["users6"],
            set(&["2001:db8:100:1::/64", "2001:db8:200:1::/64"])
        );
        // The peer's lapses; the node's own stays.
        let e = object_elements(&d, &own, Some(&heard), t0 + Duration::from_secs(600));
        assert_eq!(e["users6"], set(&["2001:db8:200:1::/64"]));
        // Nothing known: empty, so a stale element goes.
        assert_eq!(object_elements(&d, &[], None, t0)["users6"], set(&[]));
        // Only a pair's delegated networks' prefix objects.
        assert!(object_elements(&pair_v6(), &own, None, t0).is_empty());
    }

    #[test]
    fn reads_a_set_s_elements() {
        let l = json!({"nftables": [{"metainfo": {}}, {"set": {"name": "users6", "elem": [
            {"prefix": {"addr": "2001:db8:100:1::", "len": 64}},
            "2001:db8::1",
            {"range": ["2001:db8::10", "2001:db8::20"]},
            {"elem": {"val": {"prefix": {"addr": "2001:db8:200:1::", "len": 64}}, "timeout": 5}}]}}]});
        let want: BTreeSet<String> = [
            "2001:db8:100:1::/64",
            "2001:db8::1",
            "2001:db8::10-2001:db8::20",
            "2001:db8:200:1::/64",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(set_elements(&l), want);
        assert!(set_elements(&json!({})).is_empty());
    }

    #[test]
    fn the_ipv6_gateways_follow_the_master() {
        assert_eq!(master_links(&pair_v6()), vec!["swwan", "swgw20"]);
    }

    #[test]
    fn a_new_master_routes_the_old_one_s_prefix_until_it_has_its_own() {
        let d = pair_v6();
        let t0 = Instant::now();
        let heard = (
            t0,
            vec![DelegatedPrefix {
                prefix: "2001:db8:100::/56".into(),
                preferred_seconds: Some(1800),
                valid_seconds: Some(3600),
            }],
        );
        let want = vec![Takeover {
            iface: "swgw20".into(),
            dst: "2001:db8:100:1::/64".into(),
            expires: 3600,
        }];
        assert_eq!(takeovers(&d, &[], Some(&heard), t0), want);
        // Counted from when it was heard.
        let later = takeovers(&d, &[], Some(&heard), t0 + Duration::from_secs(600));
        assert_eq!(later[0].expires, 3000);
        // Lapsed: nothing.
        assert!(takeovers(&d, &[], Some(&heard), t0 + Duration::from_secs(3600)).is_empty());
        // Its own arrived: networkd routes it.
        let own = [Lifetimed {
            address: "2001:db8:100::/56".into(),
            preferred_seconds: None,
            valid_seconds: None,
        }];
        assert!(takeovers(&d, &own, Some(&heard), t0).is_empty());
        // A different one: the old stays routed while it is valid, for
        // hosts' addresses in it.
        let other = [Lifetimed {
            address: "2001:db8:200::/56".into(),
            preferred_seconds: None,
            valid_seconds: None,
        }];
        assert_eq!(takeovers(&d, &other, Some(&heard), t0), want);
        assert!(takeovers(&d, &other, Some(&heard), t0 + Duration::from_secs(3600)).is_empty());
        // Never heard one.
        assert!(takeovers(&d, &[], None, t0).is_empty());
        // Forever is capped.
        let forever = (
            t0,
            vec![DelegatedPrefix {
                prefix: "2001:db8:100::/56".into(),
                preferred_seconds: None,
                valid_seconds: None,
            }],
        );
        assert_eq!(
            takeovers(&d, &[], Some(&forever), t0)[0].expires,
            TAKEOVER_MAX_S
        );
        assert_eq!(to_peer(&own)[0].valid_seconds, None);
    }
}
