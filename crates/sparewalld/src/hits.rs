//! Logged traffic: hits of rules, policy defaults and forwards with
//! `log: true` (#262, part of #181), read-only.
//!
//! Each hit is a sparewalld journal entry (`TARGET=sparewall::rules`,
//! from [`crate::rules`]) with the rule as `F_RULE`, a one-line summary
//! as `F_PACKET` and ulogd's record as `F_RECORD`. A rule is matched by
//! journalctl, exactly; a zone pair, an address and a port are matched
//! here, from the record, over at most [`SCAN`] entries a call, and a
//! page goes on from the last entry looked at, so none is skipped.

use std::net::IpAddr;

use futures_util::StreamExt;
use serde_json::Value;
use sparewall_api::{FirewallError, HitsReply, LogEntry, RuleHit};

use crate::journal::{self, Entries, Pos, invalid};

/// Entries looked at in one call when filtering here.
pub const SCAN: usize = 5000;

/// What a caller asks for.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Query {
    pub rule: Option<String>,
    pub pair: Option<String>,
    pub address: Option<ipnet::IpNet>,
    pub port: Option<u16>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: usize,
    pub pos: Pos,
}

fn label_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && !s.chars().any(|c| c.is_control() || c == ' ')
}

impl Query {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule: Option<String>,
        pair: Option<String>,
        address: Option<String>,
        port: Option<i64>,
        since: Option<String>,
        until: Option<String>,
        limit: Option<i64>,
        before: Option<String>,
    ) -> Result<Query, FirewallError> {
        if let Some(r) = &rule
            && !label_ok(r)
        {
            return Err(invalid(
                "rule: a rule as hits name it, such as users->self:ssh, guests->users:default or forward:web",
            ));
        }
        if let Some(p) = &pair
            && (!label_ok(p) || !p.contains("->") || p.contains(':'))
        {
            return Err(invalid("pair: a zone pair, such as wan->lan"));
        }
        let address = address
            .map(|a| {
                a.parse::<ipnet::IpNet>()
                    .or_else(|_| a.parse::<IpAddr>().map(ipnet::IpNet::from))
                    .map_err(|_| invalid(format!("address: {a:?} is not an address or prefix")))
            })
            .transpose()?;
        let port = port
            .map(|p| u16::try_from(p).map_err(|_| invalid("port: 0 to 65535")))
            .transpose()?;
        for (name, t) in [("since", &since), ("until", &until)] {
            if let Some(t) = t
                && (t.is_empty() || t.len() > 64 || t.chars().any(char::is_control))
            {
                return Err(invalid(format!("{name}: not a time")));
            }
        }
        let limit = match limit {
            None => journal::DEFAULT_LIMIT,
            Some(n) if (1..=journal::MAX_LIMIT as i64).contains(&n) => n as usize,
            Some(_) => return Err(invalid(format!("limit: 1 to {}", journal::MAX_LIMIT))),
        };
        let pos = match before {
            None => Pos::Start,
            Some(b) => {
                let p: Pos = serde_json::from_str(&b)
                    .map_err(|_| invalid("before: not a page from a reply's older"))?;
                if let Pos::After(c) = &p
                    && (c.is_empty() || c.len() > 512 || c.chars().any(char::is_control))
                {
                    return Err(invalid("before: not a page from a reply's older"));
                }
                p
            }
        };
        Ok(Query {
            rule,
            pair,
            address,
            port,
            since,
            until,
            limit,
            pos,
        })
    }

    /// Whether some filter is applied here rather than by journalctl.
    fn filters_here(&self) -> bool {
        self.pair.is_some() || self.address.is_some() || self.port.is_some()
    }

    /// journalctl's arguments: the hits, the rule matched exactly.
    pub fn args(&self, follow: bool) -> Vec<String> {
        let n = if self.filters_here() {
            SCAN
        } else {
            self.limit
        };
        let mut a = journal::base_args(follow, n);
        a.push("--unit=sparewalld.service".into());
        // Matches, not options: each is FIELD=value.
        a.push("TARGET=sparewall::rules".into());
        if let Some(r) = &self.rule {
            a.push(format!("F_RULE={r}"));
        }
        if !follow {
            if let Some(s) = &self.since {
                a.push(format!("--since={s}"));
            }
            if let Some(u) = &self.until {
                a.push(format!("--until={u}"));
            }
            if let Pos::After(c) = &self.pos {
                a.push(format!("--after-cursor={c}"));
            }
        }
        a
    }

    /// Whether a hit passes the filters applied here.
    pub fn matches(&self, h: &RuleHit) -> bool {
        if let Some(p) = &self.pair
            && !h.rule.starts_with(&format!("{p}:"))
        {
            return false;
        }
        if let Some(net) = &self.address {
            let inside = |a: &Option<String>| {
                a.as_deref()
                    .and_then(|a| a.parse::<IpAddr>().ok())
                    .is_some_and(|a| net.contains(&a))
            };
            if !inside(&h.src) && !inside(&h.dst) {
                return false;
            }
        }
        if let Some(port) = self.port {
            let p = Some(i64::from(port));
            if h.sport != p && h.dport != p {
                return false;
            }
        }
        true
    }
}

/// A hit from its journal entry; `None` for an entry that is not one.
pub fn hit(e: &LogEntry) -> Option<RuleHit> {
    let rule = e.fields.get("F_RULE")?.clone();
    let packet = e.fields.get("F_PACKET").cloned().unwrap_or_default();
    let rec: Value = e
        .fields
        .get("F_RECORD")
        .and_then(|r| serde_json::from_str(r).ok())
        .unwrap_or(Value::Null);
    let s = |k: &str| {
        rec[k]
            .as_str()
            .map(str::to_string)
            .filter(|s| !s.is_empty())
    };
    let n = |k: &str| rec[k].as_i64();
    let proto = match rec["ip.protocol"].as_u64() {
        Some(6) => Some("tcp".to_string()),
        Some(17) => Some("udp".to_string()),
        Some(1) => Some("icmp".to_string()),
        Some(58) => Some("icmpv6".to_string()),
        Some(p) => Some(p.to_string()),
        None => None,
    };
    Some(RuleHit {
        time: e.time.clone(),
        usec: e.usec,
        rule,
        packet,
        proto,
        src: s("src_ip"),
        dst: s("dest_ip"),
        sport: n("src_port"),
        dport: n("dest_port"),
        in_iface: s("oob.in"),
        out_iface: s("oob.out"),
    })
}

/// The newest hits that pass, from the entries journalctl read (with
/// their cursors), and where the next page goes on from.
pub fn page(q: &Query, read: &[(LogEntry, String)]) -> HitsReply {
    let mut hits = Vec::new();
    let mut last: Option<&str> = None;
    let mut full = false;
    for (e, cursor) in read {
        last = Some(cursor);
        if let Some(h) = hit(e).filter(|h| q.matches(h)) {
            hits.push(h);
            if hits.len() == q.limit {
                full = true;
                break;
            }
        }
    }
    let read_all = read.len() < if q.filters_here() { SCAN } else { q.limit };
    let pos = match last {
        // Nothing read: nothing older.
        None => Pos::Done,
        // Read out and every entry looked at.
        Some(_) if read_all && !full => Pos::Done,
        Some(c) => Pos::After(c.to_string()),
    };
    HitsReply {
        hits,
        older: (pos != Pos::Done).then(|| serde_json::to_string(&pos).unwrap_or_default()),
    }
}

pub async fn hits(q: &Query) -> Result<HitsReply, FirewallError> {
    if q.pos == Pos::Done {
        return Ok(HitsReply {
            hits: vec![],
            older: None,
        });
    }
    let read = journal::read(q.args(false), false).await?;
    Ok(page(q, &read))
}

type Hits =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<RuleHit, FirewallError>> + Send>>;

/// New hits that pass, as they are logged, until the caller goes.
pub fn follow(q: &Query) -> Result<Hits, FirewallError> {
    let slot = journal::slot()?;
    let entries: Entries = journal::follow_one(q.args(true), false);
    let q = q.clone();
    Ok(Box::pin(entries.filter_map(move |e| {
        let _ = &slot;
        let out = match e {
            Ok(e) => hit(&e).filter(|h| q.matches(h)).map(Ok),
            Err(e) => Some(Err(e)),
        };
        std::future::ready(out)
    })))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn entry(usec: i64, rule: &str, rec: Value) -> (LogEntry, String) {
        (
            LogEntry {
                time: String::new(),
                usec,
                unit: "sparewalld.service".into(),
                priority: 6,
                identifier: None,
                message: "rule hit".into(),
                fields: BTreeMap::from([
                    ("F_RULE".to_string(), rule.to_string()),
                    ("F_PACKET".to_string(), "tcp …".to_string()),
                    ("F_RECORD".to_string(), rec.to_string()),
                ]),
            },
            format!("c{usec}"),
        )
    }

    fn q(
        rule: Option<&str>,
        pair: Option<&str>,
        address: Option<&str>,
        port: Option<i64>,
    ) -> Query {
        Query::new(
            rule.map(Into::into),
            pair.map(Into::into),
            address.map(Into::into),
            port,
            None,
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn filters_are_checked() {
        let bad = |r: Option<&str>, p: Option<&str>, a: Option<&str>, port: Option<i64>| {
            Query::new(
                r.map(Into::into),
                p.map(Into::into),
                a.map(Into::into),
                port,
                None,
                None,
                None,
                None,
            )
            .is_err()
        };
        assert!(bad(Some("a b"), None, None, None));
        assert!(bad(Some(""), None, None, None));
        assert!(bad(None, Some("wan"), None, None));
        assert!(bad(None, Some("wan->lan:x"), None, None));
        assert!(bad(None, None, Some("lan"), None));
        assert!(bad(None, None, None, Some(70000)));
        assert!(!bad(
            Some("users->self:ssh"),
            Some("wan->lan"),
            Some("2001:db8::/32"),
            Some(443)
        ));
        assert!(!bad(None, None, Some("192.0.2.7"), None));
        assert!(Query::new(None, None, None, None, None, None, None, Some("5".into())).is_err());
    }

    #[test]
    fn a_rule_is_journalctl_s_to_match_the_rest_is_ours() {
        let a = q(Some("users->self:ssh"), None, None, None).args(false);
        assert!(a.contains(&"TARGET=sparewall::rules".to_string()));
        assert!(a.contains(&"F_RULE=users->self:ssh".to_string()));
        assert!(a.contains(&format!("--lines={}", journal::DEFAULT_LIMIT)));
        let a = q(None, Some("wan->lan"), None, None).args(false);
        assert!(a.contains(&format!("--lines={SCAN}")));
        assert!(!a.iter().any(|x| x.starts_with("F_RULE=")));
    }

    #[test]
    fn hits_from_the_record() {
        let rec = serde_json::json!({"ip.protocol": 6, "src_ip": "192.0.2.7", "dest_ip": "10.0.0.2",
            "src_port": 51234, "dest_port": 443, "oob.in": "wan0", "oob.out": "lan0"});
        let (e, _) = entry(1, "wan->lan:https", rec);
        let h = hit(&e).unwrap();
        assert_eq!(h.rule, "wan->lan:https");
        assert_eq!(h.proto.as_deref(), Some("tcp"));
        assert_eq!(h.src.as_deref(), Some("192.0.2.7"));
        assert_eq!(h.dport, Some(443));
        assert_eq!(h.in_iface.as_deref(), Some("wan0"));
        assert_eq!(h.out_iface.as_deref(), Some("lan0"));
        let mut other = e.clone();
        other.fields.remove("F_RULE");
        assert!(hit(&other).is_none());
        // Pair, address (or prefix, either end) and port (either end).
        assert!(q(None, Some("wan->lan"), None, None).matches(&h));
        assert!(!q(None, Some("wan->self"), None, None).matches(&h));
        assert!(q(None, None, Some("10.0.0.0/24"), None).matches(&h));
        assert!(q(None, None, Some("192.0.2.7"), None).matches(&h));
        assert!(!q(None, None, Some("198.51.100.0/24"), None).matches(&h));
        assert!(q(None, None, None, Some(51234)).matches(&h));
        assert!(!q(None, None, None, Some(22)).matches(&h));
    }

    #[test]
    fn a_page_goes_on_from_the_last_entry_looked_at() {
        let rec = |port: i64| {
            serde_json::json!({"ip.protocol": 6, "src_ip": "192.0.2.7",
            "dest_ip": "10.0.0.2", "src_port": 1000, "dest_port": port})
        };
        let read: Vec<_> = (0..6)
            .map(|i| entry(10 - i, "wan->lan:x", rec(if i % 2 == 0 { 443 } else { 22 })))
            .collect();
        // By journalctl alone: a full page goes on after its last.
        let mut all = q(None, None, None, None);
        all.limit = 6;
        let r = page(&all, &read);
        assert_eq!(r.hits.len(), 6);
        assert_eq!(r.older.as_deref(), Some(r#"{"after":"c5"}"#));
        // Filtered here: two of three 443s fill a page of two, after the
        // second (the fourth entry looked at).
        let mut https = q(None, None, None, Some(443));
        https.limit = 2;
        let r = page(&https, &read);
        assert_eq!(r.hits.iter().map(|h| h.usec).collect::<Vec<_>>(), [10, 8]);
        assert_eq!(r.older.as_deref(), Some(r#"{"after":"c8"}"#));
        // Fewer than a scan read, all looked at: nothing older.
        https.limit = 10;
        let r = page(&https, &read);
        assert_eq!(r.hits.len(), 3);
        assert_eq!(r.older, None);
        assert_eq!(page(&https, &[]).older, None);
    }
}
