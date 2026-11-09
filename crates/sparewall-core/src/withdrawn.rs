//! Deprecating a delegated network's withdrawn /64 (#232).
//!
//! When the ISP delegates another prefix, networkd moves a delegated
//! network to the new /64 but never announces the old one as deprecated
//! (systemd#29651), so hosts keep preferring their old address, which the
//! ISP may no longer route, until its preferred lifetime runs out. Until
//! networkd does it itself, the coordinator adds the old /64 to the
//! network's router advertisements with a preferred lifetime of 0,
//! through a drop-in beside the `.network` file whose link sends them.
//!
//! Which /64 a network uses follows from the prefix in use and the
//! network's `subnet_id`: a single node's or a pair master's own
//! delegated prefix, or on a pair's backup the master's last. The /64s
//! last in use are kept across a restart or reboot, so a node that comes
//! back with another prefix deprecates the old one too.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sparewall_config::Document;
use sparewall_config::model::Ipv6Mode;

use crate::ipv6::subnet64;

/// The longest a withdrawn /64 is announced, and the valid lifetime that
/// cuts a host's longer one: RFC 4862 §5.5.3(e) lets an unauthenticated
/// advertisement cut it no lower than 2 hours.
pub const ANNOUNCE_MAX_S: u64 = 7200;

/// The drop-in's file name, in `<the .network file>.d/`.
pub const DROPIN: &str = "60-sparewall-withdrawn.conf";

/// What the coordinator keeps: the /64s each delegated network used last,
/// and the withdrawn ones it announces.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withdrawn {
    /// By network: each /64 in use, with when it stops being valid (Unix
    /// seconds; `u64::MAX` for never).
    #[serde(default)]
    pub in_use: BTreeMap<String, BTreeMap<String, u64>>,
    /// By network: each withdrawn /64 announced as deprecated.
    #[serde(default)]
    pub announced: BTreeMap<String, BTreeMap<String, Announced>>,
}

/// A withdrawn /64 in the advertisements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announced {
    /// When to stop announcing it (Unix seconds).
    pub until: u64,
    /// The valid lifetime announced: [`ANNOUNCE_MAX_S`] while the prefix
    /// had longer left, which cuts hosts' to that; else 0, which hosts
    /// ignore, leaving their own countdown alone (a lifetime above it
    /// would restart that with each advertisement).
    pub valid_seconds: u64,
}

/// Each delegated network's /64s of the `prefixes` in use (each with the
/// seconds left of its valid lifetime, `None` for forever), with when
/// each stops being valid. Every delegated network is listed, with none
/// while no prefix is in use.
pub fn in_use(
    doc: &Document,
    prefixes: &[(String, Option<u64>)],
    now: u64,
) -> BTreeMap<String, BTreeMap<String, u64>> {
    doc.networks
        .iter()
        .filter_map(|(name, net)| {
            let v6 = net.ipv6.as_ref()?;
            let id = v6.subnet_id.filter(|_| v6.mode == Ipv6Mode::Delegated)?;
            let nets = prefixes
                .iter()
                .filter_map(|(p, left)| {
                    let until = left.map_or(u64::MAX, |l| now.saturating_add(l));
                    Some((subnet64(p, id)?, until))
                })
                .collect();
            Some((name.clone(), nets))
        })
        .collect()
}

impl Withdrawn {
    /// Take the /64s now in use (from [`in_use`]), at `now`: a /64 used
    /// before and not now, still valid, is announced as deprecated; one
    /// back in use, lapsed, or on a network no longer delegated is not.
    /// A network with no prefix in use (no lease yet, or none heard from
    /// the master) withdraws nothing. Whether anything changed, to save.
    pub fn update(&mut self, current: &BTreeMap<String, BTreeMap<String, u64>>, now: u64) -> bool {
        let before = self.clone();
        for (net, using) in current.iter().filter(|(_, u)| !u.is_empty()) {
            let prev = self
                .in_use
                .insert(net.clone(), using.clone())
                .unwrap_or_default();
            for (p, valid_until) in prev {
                if using.contains_key(&p) || valid_until <= now {
                    continue;
                }
                let left = valid_until - now;
                self.announced
                    .entry(net.clone())
                    .or_default()
                    .entry(p)
                    .or_insert(Announced {
                        until: now + left.min(ANNOUNCE_MAX_S),
                        valid_seconds: if left > ANNOUNCE_MAX_S {
                            ANNOUNCE_MAX_S
                        } else {
                            0
                        },
                    });
            }
        }
        self.in_use.retain(|net, _| current.contains_key(net));
        let in_use = &self.in_use;
        for (net, a) in &mut self.announced {
            a.retain(|p, x| x.until > now && !in_use.get(net).is_some_and(|u| u.contains_key(p)));
        }
        self.announced
            .retain(|net, a| !a.is_empty() && current.contains_key(net));
        *self != before
    }
}

/// A network's drop-in announcing its withdrawn /64s.
pub fn dropin(announced: &BTreeMap<String, Announced>) -> String {
    let mut s = String::from(
        "# Generated by sparewalld (#232): delegated prefixes the ISP withdrew,\n\
         # announced as deprecated until networkd does it itself (systemd#29651).\n",
    );
    for (p, a) in announced {
        s.push_str(&format!(
            "\n[IPv6Prefix]\nPrefix={p}\nPreferredLifetimeSec=0\nValidLifetimeSec={}\n",
            a.valid_seconds
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> Document {
        let text = std::fs::read_to_string(format!(
            "{}/../../examples/two-nic.yaml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let d = sparewall_config::parse(&text, sparewall_config::Format::Yaml).unwrap();
        let mut v = sparewall_config::to_value(&d);
        sparewall_config::merge_patch(
            &mut v,
            &serde_json::json!({"networks": {
                "wan": {"ipv6": {"mode": "dhcpv6"}},
                "lan": {"ipv6": {"mode": "delegated", "subnet_id": 1}},
            }}),
        );
        sparewall_config::from_value(v).unwrap()
    }

    fn using(p: &[(&str, u64)]) -> BTreeMap<String, BTreeMap<String, u64>> {
        BTreeMap::from([(
            "lan".to_string(),
            p.iter().map(|(p, u)| (p.to_string(), *u)).collect(),
        )])
    }

    #[test]
    fn a_delegated_network_s_64s() {
        let d = doc();
        let got = in_use(
            &d,
            &[
                ("2001:db8:100::/56".into(), Some(3600)),
                ("2001:db8:200::/56".into(), None),
            ],
            1000,
        );
        assert_eq!(
            got,
            BTreeMap::from([(
                "lan".to_string(),
                BTreeMap::from([
                    ("2001:db8:100:1::/64".to_string(), 4600),
                    ("2001:db8:200:1::/64".to_string(), u64::MAX),
                ])
            )])
        );
        assert_eq!(in_use(&d, &[], 0), using(&[]));
    }

    #[test]
    fn a_withdrawn_64_is_announced_until_it_lapses() {
        let mut w = Withdrawn::default();
        assert!(w.update(&using(&[("2001:db8:100:1::/64", 1000 + 600)]), 1000));
        assert!(w.announced.is_empty());
        // No prefix for a while (the server down): nothing is withdrawn.
        assert!(!w.update(&using(&[]), 1010));
        // Another: the old one, 590 s left, is announced for those with a
        // valid lifetime of 0, which leaves hosts' countdown alone.
        assert!(w.update(&using(&[("2001:db8:200:1::/64", 1020 + 600)]), 1020));
        assert_eq!(
            w.announced["lan"]["2001:db8:100:1::/64"],
            Announced {
                until: 1600,
                valid_seconds: 0
            }
        );
        // The new one renewed: the old one is still announced.
        w.update(&using(&[("2001:db8:200:1::/64", 1030 + 600)]), 1030);
        assert!(w.announced["lan"].contains_key("2001:db8:100:1::/64"));
        // Lapsed.
        w.update(&using(&[("2001:db8:200:1::/64", 1600 + 600)]), 1600);
        assert!(w.announced.is_empty(), "{w:?}");
    }

    #[test]
    fn a_long_lived_one_is_cut_to_two_hours() {
        let mut w = Withdrawn::default();
        w.update(&using(&[("2001:db8:100:1::/64", u64::MAX)]), 0);
        w.update(&using(&[("2001:db8:200:1::/64", u64::MAX)]), 10);
        assert_eq!(
            w.announced["lan"]["2001:db8:100:1::/64"],
            Announced {
                until: 10 + ANNOUNCE_MAX_S,
                valid_seconds: ANNOUNCE_MAX_S
            }
        );
    }

    #[test]
    fn one_back_in_use_or_on_a_network_gone_is_not_announced() {
        let mut w = Withdrawn::default();
        w.update(&using(&[("2001:db8:100:1::/64", u64::MAX)]), 0);
        w.update(&using(&[("2001:db8:200:1::/64", u64::MAX)]), 10);
        assert!(!w.announced.is_empty());
        assert!(w.update(&using(&[("2001:db8:100:1::/64", u64::MAX)]), 20));
        // 200:1 is now the withdrawn one.
        assert_eq!(
            w.announced["lan"].keys().collect::<Vec<_>>(),
            ["2001:db8:200:1::/64"]
        );
        assert!(w.update(&BTreeMap::new(), 30));
        assert_eq!(w, Withdrawn::default());
    }

    #[test]
    fn the_drop_in() {
        let a = BTreeMap::from([
            (
                "2001:db8:100:1::/64".to_string(),
                Announced {
                    until: 1,
                    valid_seconds: 0,
                },
            ),
            (
                "2001:db8:300:1::/64".to_string(),
                Announced {
                    until: 1,
                    valid_seconds: 7200,
                },
            ),
        ]);
        let s = dropin(&a);
        assert!(s.starts_with("# Generated by sparewalld (#232)"), "{s}");
        assert!(
            s.contains(
                "\n[IPv6Prefix]\nPrefix=2001:db8:100:1::/64\nPreferredLifetimeSec=0\nValidLifetimeSec=0\n\
                 \n[IPv6Prefix]\nPrefix=2001:db8:300:1::/64\nPreferredLifetimeSec=0\nValidLifetimeSec=7200\n"
            ),
            "{s}"
        );
    }

    #[test]
    fn it_survives_a_restart() {
        let mut w = Withdrawn::default();
        w.update(&using(&[("2001:db8:100:1::/64", u64::MAX)]), 0);
        let saved = serde_json::to_string(&w).unwrap();
        let mut back: Withdrawn = serde_json::from_str(&saved).unwrap();
        assert_eq!(back, w);
        back.update(&using(&[("2001:db8:200:1::/64", u64::MAX)]), 5);
        assert!(back.announced["lan"].contains_key("2001:db8:100:1::/64"));
        assert_eq!(
            serde_json::from_str::<Withdrawn>("{}").unwrap(),
            Withdrawn::default()
        );
    }
}
