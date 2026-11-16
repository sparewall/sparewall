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
use serde::{Deserialize, Serialize};
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

pub(crate) fn invalid(msg: impl Into<String>) -> FirewallError {
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
    /// Where each source goes on from, from a reply's `older`.
    pub page: Page,
}

/// Where a source of entries stands in paging back.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pos {
    /// From the newest.
    #[default]
    Start,
    /// From the entry before this journal cursor.
    After(String),
    /// Nothing older.
    Done,
}

/// The two sources' positions: a reply's `older`, and the next call's
/// `before`, as an opaque token. A journal cursor, not a time, so a page
/// never skips entries logged in the same microsecond as its last.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    #[serde(default)]
    pub units: Pos,
    #[serde(default)]
    pub selinux: Pos,
}

impl Page {
    fn parse(token: &str) -> Result<Page, FirewallError> {
        let p: Page = serde_json::from_str(token)
            .map_err(|_| invalid("before: not a page from a reply's older"))?;
        for pos in [&p.units, &p.selinux] {
            if let Pos::After(c) = pos
                && (c.is_empty() || c.len() > 512 || c.chars().any(char::is_control))
            {
                return Err(invalid("before: not a page from a reply's older"));
            }
        }
        Ok(p)
    }

    fn token(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
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
        before: Option<String>,
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
            page: before
                .as_deref()
                .map(Page::parse)
                .transpose()?
                .unwrap_or_default(),
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

    /// Filters both reads share: priority, the times, and where the
    /// source goes on from.
    fn common(&self, out: &mut Vec<String>, follow: bool, pos: &Pos) {
        if let Some(p) = &self.priority {
            out.push(format!("--priority={p}"));
        }
        if !follow {
            if let Some(s) = &self.since {
                out.push(format!("--since={s}"));
            }
            if let Some(u) = &self.until {
                out.push(format!("--until={u}"));
            }
            // Newest first, so "after" is older.
            if let Pos::After(c) = pos {
                out.push(format!("--after-cursor={c}"));
            }
        }
    }

    /// journalctl's arguments for the units' entries, newest first.
    pub fn unit_args(&self, follow: bool) -> Vec<String> {
        let mut a = base_args(follow, self.limit);
        for u in self.units() {
            a.push(format!("--unit={u}"));
        }
        self.common(&mut a, follow, &self.page.units);
        if let Some(g) = &self.grep {
            a.push("--case-sensitive=false".into());
            a.push(format!("--grep={}", regex_escape(g)));
        }
        a
    }

    /// journalctl's arguments for the denials. The caller's text joins
    /// the denial's pattern as a lookahead, so journalctl matches both
    /// before it counts the entries.
    pub fn selinux_args(&self, follow: bool) -> Vec<String> {
        let mut a = base_args(follow, self.limit);
        a.push("_TRANSPORT=audit".into());
        self.common(&mut a, follow, &self.page.selinux);
        a.push("--case-sensitive=true".into());
        a.push(match &self.grep {
            Some(g) => format!("--grep=^(?=.*(?i:{})).*{AVC_PATTERN}", regex_escape(g)),
            None => format!("--grep={AVC_PATTERN}"),
        });
        a
    }
}

pub(crate) fn base_args(follow: bool, limit: usize) -> Vec<String> {
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
    parse_at(line, selinux).map(|(e, _)| e)
}

/// An entry and its journal cursor.
pub(crate) fn parse_at(line: &str, selinux: bool) -> Option<(LogEntry, String)> {
    let v: Value = serde_json::from_str(line).ok()?;
    let o = v.as_object()?;
    let cursor = o.get("__CURSOR")?.as_str()?.to_string();
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
    let e = LogEntry {
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
    };
    Some((e, cursor))
}

/// One source's read: its entries with their cursors, newest first, or
/// `None` when it was not read (not asked for, or done).
pub type Read = Option<Vec<(LogEntry, String)>>;

/// Where a source goes on from, after `taken` of its `read` entries made
/// the page.
fn next(pos: &Pos, read: &Read, taken: usize, limit: usize) -> Pos {
    let Some(r) = read else { return Pos::Done };
    if taken == r.len() && r.len() < limit {
        // All of it shown, and journalctl had no more.
        return Pos::Done;
    }
    match taken {
        0 => pos.clone(),
        n => Pos::After(r[n - 1].1.clone()),
    }
}

/// The units' entries and the denials, newest first, cut to `limit`;
/// `older` says where each source goes on from.
pub fn merge(q: &Query, units: Read, denials: Read) -> LogsReply {
    let mut all: Vec<(bool, &(LogEntry, String))> = units
        .iter()
        .flatten()
        .map(|e| (false, e))
        .chain(denials.iter().flatten().map(|e| (true, e)))
        .collect();
    // Stable, so each source keeps its own order within a microsecond.
    all.sort_by_key(|(_, (e, _))| std::cmp::Reverse(e.usec));
    all.truncate(q.limit);
    let taken = |selinux: bool| all.iter().filter(|(s, _)| *s == selinux).count();
    let page = Page {
        units: next(&q.page.units, &units, taken(false), q.limit),
        selinux: next(&q.page.selinux, &denials, taken(true), q.limit),
    };
    let done = page.units == Pos::Done && page.selinux == Pos::Done;
    LogsReply {
        older: (!done).then(|| page.token()),
        entries: all.into_iter().map(|(_, (e, _))| e.clone()).collect(),
        units: UNITS
            .iter()
            .map(|u| u.to_string())
            .chain([SELINUX.to_string()])
            .collect(),
    }
}

pub(crate) async fn read(
    args: Vec<String>,
    selinux: bool,
) -> Result<Vec<(LogEntry, String)>, FirewallError> {
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
        .filter_map(|l| parse_at(l, selinux))
        .collect())
}

/// Entries for `q`, newest first.
pub async fn logs(q: &Query) -> Result<LogsReply, FirewallError> {
    let (units, selinux) = q.wants();
    let u = if units && q.page.units != Pos::Done {
        Some(read(q.unit_args(false), false).await?)
    } else {
        None
    };
    let d = if selinux && q.page.selinux != Pos::Done {
        Some(read(q.selinux_args(false), true).await?)
    } else {
        None
    };
    Ok(merge(q, u, d))
}

static FOLLOWERS: AtomicUsize = AtomicUsize::new(0);

/// A follower's place, given back when its stream ends.
pub(crate) struct Slot;

impl Drop for Slot {
    fn drop(&mut self) {
        FOLLOWERS.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) type Entries = Pin<Box<dyn Stream<Item = Result<LogEntry, FirewallError>> + Send>>;

pub(crate) fn follow_one(args: Vec<String>, selinux: bool) -> Entries {
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
            async move {
                loop {
                    match lines.next_line().await {
                        Ok(Some(l)) => {
                            if let Some(e) = parse(&l, selinux) {
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
/// A follower's place, if there is one free: logs and rule hits share
/// them.
pub(crate) fn slot() -> Result<Slot, FirewallError> {
    if FOLLOWERS.fetch_add(1, Ordering::SeqCst) >= MAX_FOLLOWERS {
        FOLLOWERS.fetch_sub(1, Ordering::SeqCst);
        return Err(FirewallError::ServiceUnavailable {
            service: "journal".into(),
            message: format!("{MAX_FOLLOWERS} clients follow the journal already"),
        });
    }
    Ok(Slot)
}

pub fn follow(q: &Query) -> Result<Entries, FirewallError> {
    let slot = slot()?;
    let (units, selinux) = q.wants();
    let mut streams: Vec<Entries> = Vec::new();
    if units {
        streams.push(follow_one(q.unit_args(true), false));
    }
    if selinux {
        streams.push(follow_one(q.selinux_args(true), true));
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
            Some(r#"{"units": {"after": "s=1;i=2"}, "selinux": "done"}"#.into()),
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
                "--after-cursor=s=1;i=2",
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
        // The caller's text is matched by journalctl too, in any case,
        // before it counts the denials.
        assert!(
            s.contains(&format!("--grep=^(?=.*(?i:a\\.b \\(c\\))).*{AVC_PATTERN}")),
            "{s:?}"
        );
        assert!(!s.iter().any(|a| a.starts_with("--after-cursor")));
        let mut plain = super::tests::q(&["selinux"]);
        plain.page.selinux = Pos::After("s=9".into());
        let s = plain.selinux_args(false);
        assert!(
            s.contains(&format!("--grep={AVC_PATTERN}"))
                && s.contains(&"--after-cursor=s=9".to_string())
        );
        // `until` stays as given beside a page.
        let mut until = super::tests::q(&[]);
        until.until = Some("-1d".into());
        until.page.units = Pos::After("s=3".into());
        let u = until.unit_args(false);
        assert!(
            u.contains(&"--until=-1d".to_string()) && u.contains(&"--after-cursor=s=3".to_string())
        );
        // A page token is checked.
        let bad = |b: &str| Query::new(None, None, None, None, None, None, Some(b.into())).is_err();
        assert!(bad("12345"));
        assert!(bad(r#"{"units": {"after": "a
b"}}"#));
        assert!(bad(r#"{"units": "start", "other": 1}"#));
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
            r#"{{"__REALTIME_TIMESTAMP":"1","__CURSOR":"s=2","MESSAGE":"{}"}}"#,
            "x".repeat(MAX_TEXT + 10)
        );
        assert!(parse(&long, false).unwrap().message.ends_with('…'));
        assert_eq!(parse(&long, true).unwrap().unit, SELINUX);
    }

    #[test]
    fn denials_merge_by_time_and_a_full_page_says_where_to_go_on() {
        let e = |usec: i64, unit: &str, c: &str| {
            (
                LogEntry {
                    time: String::new(),
                    usec,
                    unit: unit.into(),
                    priority: 6,
                    identifier: None,
                    message: String::new(),
                    fields: BTreeMap::new(),
                },
                c.to_string(),
            )
        };
        let mut q = q(&[]);
        q.limit = 3;
        // Three of each read; the page takes the newest three of both.
        let units = Some(vec![e(5, "a", "u5"), e(3, "a", "u3"), e(3, "a", "u3b")]);
        let denials = Some(vec![
            e(4, SELINUX, "s4"),
            e(1, SELINUX, "s1"),
            e(0, SELINUX, "s0"),
        ]);
        let r = merge(&q, units, denials);
        assert_eq!(
            r.entries.iter().map(|e| e.usec).collect::<Vec<_>>(),
            [5, 4, 3]
        );
        // Each source goes on after the last of its own on the page: the
        // units after u3, so u3b, logged in the same microsecond, comes next.
        let next = Page::parse(r.older.as_deref().unwrap()).unwrap();
        assert_eq!(next.units, Pos::After("u3".into()));
        assert_eq!(next.selinux, Pos::After("s4".into()));
        assert!(r.units.contains(&SELINUX.to_string()));
        // A source that showed nothing goes on from where it was.
        q.page = Page {
            units: Pos::After("u0".into()),
            selinux: Pos::Start,
        };
        let r = merge(
            &q,
            Some(vec![e(9, "a", "u9"), e(8, "a", "u8"), e(7, "a", "u7")]),
            Some(vec![e(1, SELINUX, "s1")]),
        );
        let next = Page::parse(r.older.as_deref().unwrap()).unwrap();
        assert_eq!(next.units, Pos::After("u7".into()));
        assert_eq!(next.selinux, Pos::Start);
        // Both read out, all shown: nothing older.
        q.limit = 10;
        let r = merge(
            &q,
            Some(vec![e(3, "a", "u3")]),
            Some(vec![e(4, SELINUX, "s4")]),
        );
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.older, None);
        // A source not read (not asked for, or done) stays done.
        let r = merge(&q, Some(vec![e(3, "a", "u3")]), None);
        assert_eq!(r.older, None);
    }
}
