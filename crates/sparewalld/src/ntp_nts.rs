//! Network Time Security (#357): health says whether chrony is getting
//! authenticated time. With `ntp.nts`, chrony takes time only from
//! responses that authenticate, so with none, the clock drifts
//! unsynchronised. chrony's own report (`chronyc -n ntpdata`, through
//! `sparewall-run@`) says, for each source, whether its last response was
//! authenticated, and how many valid responses it has sent: a source is
//! counted only with both, not merely once its key exchange succeeded.

use std::time::Duration;

use serde_json::Value;
use sparewall_core::hostop::HostOp;
use sparewall_core::{Check, Level};
use tokio::sync::broadcast;

use crate::service::{Core, with_core_raw};

const ROUND: Duration = Duration::from_secs(300);
/// After an apply, how long chrony has for its first key exchange and
/// responses before the first look.
const SETTLE: Duration = Duration::from_secs(30);
const CHECK: &str = "ntp-nts";

/// One source of `chronyc -n ntpdata`.
#[derive(Debug, PartialEq)]
pub struct Source {
    pub address: String,
    /// Whether its last response was authenticated.
    pub authenticated: bool,
    /// Valid responses received.
    pub valid_rx: u64,
}

/// The sources of `chronyc -n ntpdata`: blocks of `Field : value` lines,
/// one per source, by their labels (column positions differ between
/// chrony versions; the labels don't).
pub fn parse(out: &str) -> Vec<Source> {
    let mut sources = Vec::new();
    let mut cur: Option<Source> = None;
    for line in out.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "Remote address" => {
                sources.extend(cur.take());
                cur = Some(Source {
                    address: v.split_whitespace().next().unwrap_or_default().to_string(),
                    authenticated: false,
                    valid_rx: 0,
                });
            }
            "Authenticated" => {
                if let Some(c) = cur.as_mut() {
                    c.authenticated = v == "Yes";
                }
            }
            "Total valid RX" => {
                if let Some(c) = cur.as_mut() {
                    c.valid_rx = v.parse().unwrap_or(0);
                }
            }
            _ => {}
        }
    }
    sources.extend(cur);
    sources
}

/// Health from chrony's sources: degraded while none has sent a valid,
/// authenticated response.
pub fn assess(sources: &[Source]) -> Vec<Check> {
    if sources.is_empty() {
        return vec![Check::new(
            CHECK,
            Level::Degraded,
            "no NTS source yet: chrony hasn't completed a key exchange with any of ntp.servers",
        )];
    }
    let good = |s: &Source| s.authenticated && s.valid_rx > 0;
    let all: Vec<String> = sources
        .iter()
        .map(|s| {
            if good(s) {
                format!(
                    "{} authenticated ({} valid responses)",
                    s.address, s.valid_rx
                )
            } else if s.valid_rx == 0 {
                format!("{} no valid response yet", s.address)
            } else {
                format!("{} last response not authenticated", s.address)
            }
        })
        .collect();
    if sources.iter().any(good) {
        vec![Check::new(CHECK, Level::Ok, all.join("; "))]
    } else {
        vec![Check::new(
            CHECK,
            Level::Degraded,
            format!(
                "no source has sent authenticated time, so the clock isn't synchronised: {}",
                all.join("; ")
            ),
        )]
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
            match tokio::task::spawn_blocking(|| crate::upgrade::host_run(&HostOp::ChronyNtpData))
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

    /// As chrony 4.9 prints it, two sources, cut down.
    const OUT: &str = "Remote address  : 192.0.2.40 (C0000228)\n\
                       Remote port     : 123\n\
                       Mode            : Server\n\
                       NTP tests       : 111 111 1111\n\
                       Authenticated   : Yes\n\
                       Total RX        : 9\n\
                       Total valid RX  : 9\n\
                       Total good RX   : 8\n\
                       \n\
                       Remote address  : 198.51.100.7 (C6336407)\n\
                       Remote port     : 123\n\
                       Authenticated   : No\n\
                       Total valid RX  : 0\n";

    #[test]
    fn parses_chronyc_ntpdata_by_label() {
        assert_eq!(
            parse(OUT),
            [
                Source {
                    address: "192.0.2.40".into(),
                    authenticated: true,
                    valid_rx: 9
                },
                Source {
                    address: "198.51.100.7".into(),
                    authenticated: false,
                    valid_rx: 0
                },
            ]
        );
        assert!(parse("").is_empty());
    }

    #[test]
    fn degraded_until_a_source_sends_authenticated_time() {
        let c = assess(&parse(OUT));
        assert_eq!(c[0].level, Level::Ok);
        assert!(
            c[0].message
                .contains("192.0.2.40 authenticated (9 valid responses)")
        );
        assert!(c[0].message.contains("198.51.100.7 no valid response yet"));
        // Valid responses that didn't authenticate (or a key exchange and
        // nothing since) aren't authenticated time.
        let plain = assess(&parse(
            "Remote address : 192.0.2.40 (x)\nAuthenticated : No\nTotal valid RX : 5\n",
        ));
        assert_eq!(plain[0].level, Level::Degraded);
        assert!(plain[0].message.contains("last response not authenticated"));
        let pending = assess(&parse(
            "Remote address : 192.0.2.40 (x)\nAuthenticated : Yes\nTotal valid RX : 0\n",
        ));
        assert_eq!(pending[0].level, Level::Degraded);
        assert_eq!(assess(&[])[0].level, Level::Degraded);
    }
}
