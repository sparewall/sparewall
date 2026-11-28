//! Network Time Security (#357): health says whether chrony's sources
//! authenticated. With `ntp.nts`, chrony takes time only from a source
//! that has, so with none, the clock drifts unsynchronised. chrony's own
//! report (`chronyc -c authdata`, through `sparewall-run@`) says, for each
//! source, how many NTS cookies it holds: none means its key exchange
//! hasn't succeeded.

use std::time::Duration;

use serde_json::Value;
use sparewall_core::hostop::HostOp;
use sparewall_core::{Check, Level};
use tokio::sync::broadcast;

use crate::service::{Core, with_core_raw};

const ROUND: Duration = Duration::from_secs(300);
/// After an apply, how long chrony has for its first key exchange before
/// the first look.
const SETTLE: Duration = Duration::from_secs(30);
const CHECK: &str = "ntp-nts";

/// One source's line of `chronyc -c authdata`: address, mode, key ID,
/// type, key length, last (s), attempts, NAKs, cookies, cookie length.
#[derive(Debug, PartialEq)]
pub struct Source {
    pub address: String,
    pub nts: bool,
    pub naks: u64,
    pub cookies: u64,
}

pub fn parse(out: &str) -> Vec<Source> {
    out.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            (f.len() >= 10).then(|| Source {
                address: f[0].to_string(),
                nts: f[1] == "NTS",
                naks: f[7].parse().unwrap_or(0),
                cookies: f[8].parse().unwrap_or(0),
            })
        })
        .collect()
}

/// Health from chrony's sources: degraded while no NTS source holds
/// cookies (has authenticated).
pub fn assess(sources: &[Source]) -> Vec<Check> {
    let nts: Vec<&Source> = sources.iter().filter(|s| s.nts).collect();
    if nts.is_empty() {
        return vec![Check::new(
            CHECK,
            Level::Degraded,
            "no NTS source yet: chrony hasn't resolved or reached any of ntp.servers",
        )];
    }
    let describe = |s: &Source| {
        if s.cookies > 0 {
            format!("{} authenticated", s.address)
        } else if s.naks > 0 {
            format!("{} refused our cookies ({} NAKs)", s.address, s.naks)
        } else {
            format!(
                "{} not authenticated (key exchange failed or pending)",
                s.address
            )
        }
    };
    let ok = nts.iter().filter(|s| s.cookies > 0).count();
    let all: Vec<String> = nts.iter().map(|s| describe(s)).collect();
    if ok == 0 {
        vec![Check::new(
            CHECK,
            Level::Degraded,
            format!(
                "no NTS source has authenticated, so the clock isn't synchronised: {}",
                all.join("; ")
            ),
        )]
    } else {
        vec![Check::new(CHECK, Level::Ok, all.join("; "))]
    }
}

fn wanted(doc: &sparewall_config::Document) -> bool {
    doc.ntp.as_ref().is_some_and(|n| n.nts)
}

pub async fn ntp_nts_loop(core: Core, events: broadcast::Sender<Value>) {
    let mut rx = events.subscribe();
    loop {
        let doc = with_core_raw(&core, &events, |c| c.active_document())
            .await
            .ok()
            .flatten();
        let checks = if doc.as_ref().is_some_and(wanted) {
            match tokio::task::spawn_blocking(|| crate::upgrade::host_run(&HostOp::ChronyAuthData))
                .await
            {
                Ok(Ok(out)) => assess(&parse(&out)),
                Ok(Err(e)) => vec![Check::new(
                    CHECK,
                    Level::Degraded,
                    format!("cannot ask chrony: {e}"),
                )],
                Err(e) => vec![Check::new(
                    CHECK,
                    Level::Degraded,
                    format!("cannot ask chrony: {e}"),
                )],
            }
        } else {
            vec![]
        };
        let _ = with_core_raw(&core, &events, move |c| {
            c.set_named_checks(CHECK, checks);
            Ok(())
        })
        .await;
        // Wake on an apply or a rollback (and give chrony a moment for its
        // key exchange), or after a round.
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
            tokio::time::sleep(SETTLE).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUT: &str = "192.0.2.40,NTS,1,15,256,33,0,0,8,100\n\
                       198.51.100.7,NTS,0,0,0,-,3,0,0,0\n\
                       203.0.113.9,-,0,0,0,-,0,0,0,0\n";

    #[test]
    fn parses_chronyc_authdata() {
        let s = parse(OUT);
        assert_eq!(s.len(), 3);
        assert_eq!(
            s[0],
            Source {
                address: "192.0.2.40".into(),
                nts: true,
                naks: 0,
                cookies: 8
            }
        );
        assert!(!s[2].nts);
        assert!(parse("garbage\n").is_empty());
    }

    #[test]
    fn degraded_only_while_no_source_authenticated() {
        let c = assess(&parse(OUT));
        assert_eq!(c[0].level, Level::Ok);
        assert!(c[0].message.contains("192.0.2.40 authenticated"));
        assert!(c[0].message.contains("198.51.100.7 not authenticated"));
        let none = assess(&parse("198.51.100.7,NTS,0,0,0,-,3,2,0,0\n"));
        assert_eq!(none[0].level, Level::Degraded);
        assert!(none[0].message.contains("refused our cookies (2 NAKs)"));
        assert_eq!(assess(&[])[0].level, Level::Degraded);
    }
}
