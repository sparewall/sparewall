//! The journal of Sparewall's own units, read-only (#261, part of #181).
//!
//! `journalctl` reads it: the units are named from a fixed list, every
//! other argument is passed as `--option=value`, so nothing a caller
//! sends can become an option, and no shell is involved. Each read has a
//! time limit and an entry limit. `selinux` stands for the kernel's
//! denials of the coordinator's domain (`sparewalld_t`), which health
//! already counts: audit entries, read apart and merged by time.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::Stream;
use serde_json::Value;
use sparewall_api::{FirewallError, LogEntry, LogsReply};
use tokio::io::{AsyncBufReadExt, BufReader};

/// The units one may read: Sparewall's own, and its providers'. A name
/// with `@*` stands for every instance.
pub const UNITS: &[&str] = &[
    "sparewalld.service",
    "sparewall-early.service",
    "sparewall-httpd.service",
    "sparewall-run@*.service",
    "sparewall-seed@*.service",
    "sparewall-kea.service",
    "sparewall-unbound.service",
    "sparewall-ulogd.service",
    "sparewall-prometheus.service",
    "keepalived.service",
    "conntrackd.service",
    "chronyd.service",
    "rsyslog.service",
    "systemd-journal-upload.service",
    "prometheus-node-exporter.service",
];

/// The kernel's denials of the coordinator's domain.
pub const SELINUX: &str = "selinux";

pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 1000;
/// A message longer than this is cut, as is a field.
const MAX_TEXT: usize = 8192;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Followers at once: each is a journalctl process or two.
const MAX_FOLLOWERS: usize = 8;

const PRIORITIES: &[&str] = &[
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

/// The journal's own fields, and those the entry carries apart.
const HIDDEN: &[&str] = &[
    "MESSAGE",
    "PRIORITY",
    "SYSLOG_IDENTIFIER",
    "SYSLOG_FACILITY",
    "SYSLOG_PID",
    "SYSLOG_TIMESTAMP",
    "SYSLOG_RAW",
    "CODE_FILE",
    "CODE_LINE",
    "CODE_FUNC",
    "TID",
    "INVOCATION_ID",
];

/// An audit entry that is a denial of the coordinator's domain.
const AVC_PATTERN: &str = r"avc:\s+denied.*scontext=[^ ]*:sparewalld_t:";

/// A unit by its name, or a short one: `kea` for
/// `sparewall-kea.service`, `sparewalld`, `sparewall-run@*`.
pub fn unit_named(u: &str) -> Option<String> {
    if u == SELINUX {
        return Some(u.to_string());
    }
    [
        u.to_string(),
        format!("{u}.service"),
        format!("sparewall-{u}.service"),
    ]
    .into_iter()
    .find(|c| UNITS.contains(&c.as_str()))
}

fn invalid(msg: impl Into<String>) -> FirewallError {
    FirewallError::ValidationFailed {
        errors: vec![msg.into()],
    }
}

/// What a caller asks for.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Query {
    pub units: Vec<String>,
    pub priority: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub grep: Option<String>,
    pub limit: usize,
    /// Only entries before this (microseconds since the epoch).
    pub before: Option<i64>,
}

impl Query {
    /// Checked: known units (none means all), a syslog priority by name
    /// or number, times journalctl can read and no option among them,
    /// and a limit within bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        units: Option<Vec<String>>,
        priority: Option<String>,
        since: Option<String>,
        until: Option<String>,
        grep: Option<String>,
        limit: Option<i64>,
        before: Option<i64>,
    ) -> Result<Query, FirewallError> {
        let units = units
            .unwrap_or_default()
            .iter()
            .map(|u| {
                unit_named(u).ok_or_else(|| {
                    invalid(format!(
                        "units: {u:?} is not one of {}, {SELINUX}",
                        UNITS.join(", ")
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(p) = &priority
            && !PRIORITIES.contains(&p.as_str())
            && !matches!(p.parse::<u8>(), Ok(0..=7))
        {
            return Err(invalid(format!(
                "priority: {p:?} is not 0 to 7 or one of {}",
                PRIORITIES.join(", ")
            )));
        }
        for (name, t) in [("since", &since), ("until", &until)] {
            if let Some(t) = t
                && (t.is_empty() || t.len() > 64 || t.chars().any(char::is_control))
            {
                return Err(invalid(format!("{name}: not a time")));
            }
        }
        if let Some(g) = &grep
            && (g.len() > 256 || g.chars().any(char::is_control))
        {
            return Err(invalid("grep: at most 256 characters, on one line"));
        }
        let limit = match limit {
            None => DEFAULT_LIMIT,
            Some(n) if (1..=MAX_LIMIT as i64).contains(&n) => n as usize,
            Some(_) => return Err(invalid(format!("limit: 1 to {MAX_LIMIT}"))),
        };
        Ok(Query {
            units,
            priority,
            since,
            until,
            grep: grep.filter(|g| !g.is_empty()),
            limit,
            before,
        })
    }

    /// Whether it reads the units' entries, the denials, or both.
    fn wants(&self) -> (bool, bool) {
        if self.units.is_empty() {
            return (true, true);
        }
        let selinux = self.units.iter().any(|u| u == SELINUX);
        (self.units.iter().any(|u| u != SELINUX), selinux)
    }

    fn units(&self) -> Vec<&str> {
        if self.units.iter().all(|u| u == SELINUX) {
            UNITS.to_vec()
        } else {
            self.units
                .iter()
                .filter(|u| *u != SELINUX)
                .map(String::as_str)
                .collect()
        }
    }

    /// Filters both reads share: priority, times, the text.
    fn common(&self, out: &mut Vec<String>, follow: bool) {
        if let Some(p) = &self.priority {
            out.push(format!("--priority={p}"));
        }
        if !follow {
            if let Some(s) = &self.since {
                out.push(format!("--since={s}"));
            }
            // The earlier of `until` and `before`: journalctl takes one.
            match (self.before, &self.until) {
                (Some(b), _) => {
                    let b = b - 1;
                    out.push(format!(
                        "--until=@{}.{:06}",
                        b.div_euclid(1_000_000),
                        b.rem_euclid(1_000_000)
                    ));
                }
                (None, Some(u)) => out.push(format!("--until={u}")),
                (None, None) => {}
            }
        }
    }

    /// journalctl's arguments for the units' entries, newest first.
    pub fn unit_args(&self, follow: bool) -> Vec<String> {
        let mut a = base_args(follow, self.limit);
        for u in self.units() {
            a.push(format!("--unit={u}"));
        }
        self.common(&mut a, follow);
        if let Some(g) = &self.grep {
            a.push("--case-sensitive=false".into());
            a.push(format!("--grep={}", regex_escape(g)));
        }
        a
    }

    /// journalctl's arguments for the denials; the text, if any, is
    /// matched here afterwards, as journalctl takes one pattern.
    pub fn selinux_args(&self, follow: bool) -> Vec<String> {
        let mut a = base_args(follow, self.limit);
        a.push("_TRANSPORT=audit".into());
        self.common(&mut a, follow);
        a.push(format!("--grep={AVC_PATTERN}"));
        a
    }
}

fn base_args(follow: bool, limit: usize) -> Vec<String> {
    let mut a = vec![
        "--output=json".to_string(),
        "--quiet".into(),
        "--no-pager".into(),
    ];
    if follow {
        a.push("--follow".into());
        a.push("--lines=0".into());
    } else {
        a.push("--reverse".into());
        a.push(format!("--lines={limit}"));
    }
    a
}

/// `text` as a PCRE2 pattern that matches it literally.
pub fn regex_escape(text: &str) -> String {
    let mut s = String::with_capacity(text.len());
    for c in text.chars() {
        if "\\^$.|?*+()[]{}".contains(c) {
            s.push('\\');
        }
        s.push(c);
    }
    s
}

/// A field's value as text: a string, bytes (binary or not UTF-8), or
/// several values.
fn text(v: &Value) -> String {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Array(a) if a.iter().all(Value::is_u64) => {
            let b: Vec<u8> = a
                .iter()
                .filter_map(|x| x.as_u64())
                .map(|x| x as u8)
                .collect();
            String::from_utf8_lossy(&b).into_owned()
        }
        Value::Array(a) => a.iter().map(text).collect::<Vec<_>>().join("\n"),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    if s.len() > MAX_TEXT {
        let mut end = MAX_TEXT;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    } else {
        s
    }
}

/// An entry from journalctl's JSON; `None` for a line that is not one.
pub fn parse(line: &str, selinux: bool) -> Option<LogEntry> {
    let v: Value = serde_json::from_str(line).ok()?;
    let o = v.as_object()?;
    let usec: i64 = o.get("__REALTIME_TIMESTAMP")?.as_str()?.parse().ok()?;
    let time = jiff::Timestamp::from_microsecond(usec)
        .ok()?
        .strftime("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string();
    let unit = if selinux {
        SELINUX.to_string()
    } else {
        o.get("_SYSTEMD_UNIT")
            .or_else(|| o.get("UNIT"))
            .map(text)
            .unwrap_or_default()
    };
    let fields: BTreeMap<String, String> = o
        .iter()
        .filter(|(k, _)| !k.starts_with('_') && !HIDDEN.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), text(v)))
        .collect();
    Some(LogEntry {
        time,
        usec,
        unit,
        priority: o
            .get("PRIORITY")
            .map(text)
            .and_then(|p| p.parse().ok())
            .unwrap_or(6),
        identifier: o.get("SYSLOG_IDENTIFIER").map(text),
        message: o.get("MESSAGE").map(text).unwrap_or_default(),
        fields,
    })
}

/// Whether a denial matches the caller's text, which journalctl could
/// not apply to it.
fn matches(e: &LogEntry, grep: Option<&str>) -> bool {
    grep.is_none_or(|g| e.message.to_lowercase().contains(&g.to_lowercase()))
}

/// The units' entries and the denials, newest first, cut to `limit`.
pub fn merge(q: &Query, units: Vec<LogEntry>, denials: Vec<LogEntry>) -> LogsReply {
    let mut all: Vec<LogEntry> = units
        .into_iter()
        .chain(
            denials
                .into_iter()
                .filter(|e| matches(e, q.grep.as_deref())),
        )
        .collect();
    all.sort_by_key(|e| std::cmp::Reverse(e.usec));
    // A full page may have more behind it.
    let full = all.len() >= q.limit;
    all.truncate(q.limit);
    LogsReply {
        older: full.then(|| all.last().map(|e| e.usec)).flatten(),
        entries: all,
        units: UNITS
            .iter()
            .map(|u| u.to_string())
            .chain([SELINUX.to_string()])
            .collect(),
    }
}

async fn read(args: Vec<String>, selinux: bool) -> Result<Vec<LogEntry>, FirewallError> {
    let unavailable = |m: String| FirewallError::ServiceUnavailable {
        service: "journal".into(),
        message: m,
    };
    let child = tokio::process::Command::new("journalctl")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| unavailable(format!("journalctl: {e}")))?;
    let out = tokio::time::timeout(READ_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| unavailable("reading the journal took too long".into()))?
        .map_err(|e| unavailable(format!("journalctl: {e}")))?;
    // 1 with no output: nothing matched the pattern.
    if !out.status.success() && !(out.status.code() == Some(1) && out.stdout.is_empty()) {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(unavailable(format!("journalctl: {}", err.trim())));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| parse(l, selinux))
        .collect())
}

/// Entries for `q`, newest first.
pub async fn logs(q: &Query) -> Result<LogsReply, FirewallError> {
    let (units, selinux) = q.wants();
    let u = if units {
        read(q.unit_args(false), false).await?
    } else {
        vec![]
    };
    let d = if selinux {
        read(q.selinux_args(false), true).await?
    } else {
        vec![]
    };
    Ok(merge(q, u, d))
}

static FOLLOWERS: AtomicUsize = AtomicUsize::new(0);

/// A follower's place, given back when its stream ends.
struct Slot;

impl Drop for Slot {
    fn drop(&mut self) {
        FOLLOWERS.fetch_sub(1, Ordering::SeqCst);
    }
}

type Entries = Pin<Box<dyn Stream<Item = Result<LogEntry, FirewallError>> + Send>>;

fn follow_one(args: Vec<String>, selinux: bool, grep: Option<String>) -> Entries {
    let child = tokio::process::Command::new("journalctl")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return Box::pin(tokio_stream::once(Err(FirewallError::ServiceUnavailable {
                service: "journal".into(),
                message: format!("journalctl: {e}"),
            })));
        }
    };
    let Some(stdout) = child.stdout.take() else {
        return Box::pin(tokio_stream::empty());
    };
    let lines = BufReader::new(stdout).lines();
    Box::pin(futures_util::stream::unfold(
        (lines, child),
        move |(mut lines, child)| {
            let grep = grep.clone();
            async move {
                loop {
                    match lines.next_line().await {
                        Ok(Some(l)) => {
                            if let Some(e) = parse(&l, selinux)
                                && (!selinux || matches(&e, grep.as_deref()))
                            {
                                return Some((Ok(e), (lines, child)));
                            }
                        }
                        // The process ended (or was ended): so does the stream.
                        _ => return None,
                    }
                }
            }
        },
    ))
}

/// New entries for `q` as they are logged, until the caller goes.
pub fn follow(q: &Query) -> Result<Entries, FirewallError> {
    if FOLLOWERS.fetch_add(1, Ordering::SeqCst) >= MAX_FOLLOWERS {
        FOLLOWERS.fetch_sub(1, Ordering::SeqCst);
        return Err(FirewallError::ServiceUnavailable {
            service: "journal".into(),
            message: format!("{MAX_FOLLOWERS} clients follow the logs already"),
        });
    }
    let slot = Slot;
    let (units, selinux) = q.wants();
    let mut streams: Vec<Entries> = Vec::new();
    if units {
        streams.push(follow_one(q.unit_args(true), false, None));
    }
    if selinux {
        streams.push(follow_one(q.selinux_args(true), true, q.grep.clone()));
    }
    let merged = futures_util::stream::select_all(streams);
    // The slot goes with the stream.
    Ok(Box::pin(futures_util::StreamExt::map(merged, move |e| {
        let _ = &slot;
        e
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(units: &[&str]) -> Query {
        Query::new(
            Some(units.iter().map(|u| u.to_string()).collect()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn only_known_units_and_sane_filters() {
        assert!(q(&["sparewalld.service", "selinux"]).units.len() == 2);
        let bad = |u: Option<Vec<String>>, p: Option<&str>, g: Option<&str>, l: Option<i64>| {
            Query::new(u, p.map(Into::into), None, None, g.map(Into::into), l, None).is_err()
        };
        assert!(bad(Some(vec!["sshd.service".into()]), None, None, None));
        assert!(bad(Some(vec!["sshd".into()]), None, None, None));
        assert_eq!(
            q(&["kea", "sparewalld", "keepalived"]).units,
            [
                "sparewall-kea.service",
                "sparewalld.service",
                "keepalived.service"
            ]
        );
        assert!(bad(Some(vec!["--all".into()]), None, None, None));
        assert!(bad(None, Some("loud"), None, None));
        assert!(bad(None, Some("8"), None, None));
        assert!(bad(None, None, Some("a\nb"), None));
        assert!(bad(None, None, None, Some(0)));
        assert!(bad(None, None, None, Some(1001)));
        assert!(!bad(None, Some("warning"), Some("x"), Some(5)));
        assert!(!bad(None, Some("3"), None, None));
        let t = Query::new(None, None, Some("\u{7}".into()), None, None, None, None);
        assert!(t.is_err());
    }

    #[test]
    fn arguments_are_options_with_values_and_text_is_literal() {
        let q = Query::new(
            Some(vec![
                "sparewalld.service".into(),
                "sparewall-run@*.service".into(),
            ]),
            Some("warning".into()),
            Some("-1h".into()),
            None,
            Some("a.b (c)".into()),
            Some(50),
            Some(1_700_000_000_000_000),
        )
        .unwrap();
        assert_eq!(
            q.unit_args(false),
            [
                "--output=json",
                "--quiet",
                "--no-pager",
                "--reverse",
                "--lines=50",
                "--unit=sparewalld.service",
                "--unit=sparewall-run@*.service",
                "--priority=warning",
                "--since=-1h",
                "--until=@1699999999.999999",
                "--case-sensitive=false",
                "--grep=a\\.b \\(c\\)",
            ]
        );
        let f = q.unit_args(true);
        assert!(f.contains(&"--follow".to_string()) && f.contains(&"--lines=0".to_string()));
        assert!(
            !f.iter()
                .any(|a| a.starts_with("--since") || a.starts_with("--until"))
        );
        let s = q.selinux_args(false);
        assert!(s.contains(&"_TRANSPORT=audit".to_string()));
        assert!(s.iter().any(|a| a.starts_with("--grep=avc:")));
        // Only denials: every unit's entries are left out.
        assert_eq!(super::tests::q(&["selinux"]).wants(), (false, true));
        assert_eq!(super::tests::q(&[]).wants(), (true, true));
    }

    #[test]
    fn entries_from_journalctl() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1700000000123456","__CURSOR":"s=1","_SYSTEMD_UNIT":"sparewalld.service","PRIORITY":"4","SYSLOG_IDENTIFIER":"sparewalld","MESSAGE":"upgrade","F_STEP":"staged","F_DETAIL":[104,105],"_PID":"7","CODE_LINE":"1"}"#;
        let e = parse(line, false).unwrap();
        assert_eq!(e.time, "2023-11-14T22:13:20.123456Z");
        assert_eq!(e.usec, 1_700_000_000_123_456);
        assert_eq!(e.unit, "sparewalld.service");
        assert_eq!(e.priority, 4);
        assert_eq!(e.identifier.as_deref(), Some("sparewalld"));
        assert_eq!(e.message, "upgrade");
        assert_eq!(
            e.fields,
            BTreeMap::from([
                ("F_DETAIL".to_string(), "hi".to_string()),
                ("F_STEP".to_string(), "staged".to_string())
            ])
        );
        assert!(parse("not json", false).is_none());
        let long = format!(
            r#"{{"__REALTIME_TIMESTAMP":"1","MESSAGE":"{}"}}"#,
            "x".repeat(MAX_TEXT + 10)
        );
        assert!(parse(&long, false).unwrap().message.ends_with('…'));
        assert_eq!(parse(&long, true).unwrap().unit, SELINUX);
    }

    #[test]
    fn denials_merge_by_time_and_a_full_page_says_where_to_go_on() {
        let e = |usec: i64, unit: &str, msg: &str| LogEntry {
            time: String::new(),
            usec,
            unit: unit.into(),
            priority: 6,
            identifier: None,
            message: msg.into(),
            fields: BTreeMap::new(),
        };
        let mut q = q(&[]);
        q.limit = 3;
        let r = merge(
            &q,
            vec![e(5, "a", "x"), e(3, "a", "y")],
            vec![e(4, SELINUX, "avc: denied"), e(1, SELINUX, "avc: denied")],
        );
        assert_eq!(
            r.entries.iter().map(|e| e.usec).collect::<Vec<_>>(),
            [5, 4, 3]
        );
        assert_eq!(r.older, Some(3));
        assert!(r.units.contains(&SELINUX.to_string()));
        q.limit = 10;
        q.grep = Some("Y".into());
        // journalctl matched the units' text; the denials are matched here.
        let r = merge(&q, vec![e(3, "a", "y")], vec![e(4, SELINUX, "avc: denied")]);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.older, None);
    }
}
