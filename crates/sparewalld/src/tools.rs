//! Network tools run from the node: ping, traceroute and DNS lookups
//! (#264, part of #181), for an operator and up.
//!
//! Every argument is checked (an address or a host name, a network the
//! document has, a record type from a list) and passed as an argument,
//! never through a shell. A run has a fixed count or hop limit, a time
//! limit and an output limit, and at most [`MAX_RUNS`] run at once: more
//! are refused, not queued.

use std::net::IpAddr;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::Stream;
use sparewall_api::FirewallError;
use sparewall_config::Document;
use tokio::io::{AsyncBufReadExt, BufReader};

pub const MAX_RUNS: usize = 3;
const MAX_LINES: usize = 200;
const MAX_LINE: usize = 512;
const PING_MAX: i64 = 10;
const PING_DEFAULT: i64 = 4;
const HOPS: u32 = 20;
/// Record types a lookup may ask for: no zone transfers, no ANY.
pub const RECORDS: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "CAA",
];

fn invalid(msg: impl Into<String>) -> FirewallError {
    FirewallError::ValidationFailed {
        errors: vec![msg.into()],
    }
}

/// A host name as DNS has them: labels of letters, digits and `-`, not
/// starting with one, dot-separated, 253 characters at most.
pub fn host_name_ok(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// A target: an address, or a host name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Addr(IpAddr),
    Name(String),
}

impl Target {
    pub fn parse(s: &str, what: &str) -> Result<Target, FirewallError> {
        if let Ok(a) = s.parse::<IpAddr>() {
            return Ok(Target::Addr(a));
        }
        if host_name_ok(s) {
            return Ok(Target::Name(s.to_string()));
        }
        Err(invalid(format!(
            "{what}: {s:?} is not an address or a host name"
        )))
    }

    fn v6(&self) -> bool {
        matches!(self, Target::Addr(IpAddr::V6(_)))
    }

    fn text(&self) -> String {
        match self {
            Target::Addr(a) => a.to_string(),
            Target::Name(n) => n.clone(),
        }
    }
}

/// Where a run leaves from, for `network`: the node's own IPv4 address
/// there (in a pair, not the shared one), or for an IPv6 target the
/// network's interface. `None` without a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Addr(std::net::Ipv4Addr),
    Iface(String),
}

pub fn source(
    doc: Option<&Document>,
    node: &str,
    network: Option<&str>,
    target: &Target,
) -> Result<Option<Source>, FirewallError> {
    let Some(name) = network else {
        return Ok(None);
    };
    let Some((doc, net)) = doc.and_then(|d| d.networks.get(name).map(|n| (d, n))) else {
        return Err(invalid(format!("network: no network named {name:?}")));
    };
    if target.v6() {
        return doc
            .network_iface(name)
            .map(|i| Some(Source::Iface(i.to_string())))
            .ok_or_else(|| invalid(format!("network: {name} has no interface on this node")));
    }
    net.addresses
        .get(node)
        .map(|a| Some(Source::Addr(a.0.addr())))
        .ok_or_else(|| {
            invalid(format!(
                "network: this node has no address of its own on {name}; leave it out to go by the routes"
            ))
        })
}

/// ping's arguments.
pub fn ping_args(
    target: &Target,
    source: Option<&Source>,
    count: Option<i64>,
) -> Result<Vec<String>, FirewallError> {
    let n = count.unwrap_or(PING_DEFAULT);
    if !(1..=PING_MAX).contains(&n) {
        return Err(invalid(format!("count: 1 to {PING_MAX}")));
    }
    let mut a = vec![
        "-n".to_string(),
        format!("-c{n}"),
        "-W2".into(),
        // At most this long in all.
        format!("-w{}", n * 2 + 3),
    ];
    match source {
        Some(Source::Addr(s)) => {
            a.push("-4".into());
            a.push(format!("-I{s}"));
        }
        Some(Source::Iface(i)) => a.push(format!("-I{i}")),
        None => {}
    }
    a.push("--".into());
    a.push(target.text());
    Ok(a)
}

/// traceroute's arguments: numeric, one probe a hop, at most [`HOPS`].
pub fn traceroute_args(target: &Target, source: Option<&Source>) -> Vec<String> {
    let mut a = vec![
        "-n".to_string(),
        format!("-m{HOPS}"),
        "-q1".into(),
        "-w2".into(),
    ];
    if target.v6() {
        a.push("-6".into());
    }
    match source {
        Some(Source::Addr(s)) => {
            a.push("-4".into());
            a.push(format!("-s{s}"));
        }
        Some(Source::Iface(i)) => a.push(format!("-i{i}")),
        None => {}
    }
    a.push("--".into());
    a.push(target.text());
    a
}

/// dig's arguments: one try, two seconds, through `server` or the node's
/// own resolver; an address is looked up in reverse.
pub fn lookup_args(
    name: &Target,
    record: Option<&str>,
    server: Option<&str>,
) -> Result<Vec<String>, FirewallError> {
    let mut a = vec![
        "+time=2".to_string(),
        "+tries=1".into(),
        "+nocomments".into(),
    ];
    if let Some(s) = server {
        let s: IpAddr = s
            .parse()
            .map_err(|_| invalid(format!("server: {s:?} is not an address")))?;
        a.push(format!("@{s}"));
    }
    match name {
        Target::Addr(addr) => {
            if record.is_some_and(|r| !r.eq_ignore_ascii_case("PTR")) {
                return Err(invalid("record: an address is looked up as PTR"));
            }
            a.push("-x".into());
            a.push(addr.to_string());
        }
        Target::Name(n) => {
            let r = record.unwrap_or("A").to_ascii_uppercase();
            if !RECORDS.contains(&r.as_str()) {
                return Err(invalid(format!("record: one of {}", RECORDS.join(", "))));
            }
            // dig takes a name and a type, in any order; -q makes the
            // name a name even should it look like a type.
            a.push("-q".into());
            a.push(n.clone());
            a.push("-t".into());
            a.push(r);
        }
    }
    Ok(a)
}

static RUNS: AtomicUsize = AtomicUsize::new(0);

struct Slot;

impl Drop for Slot {
    fn drop(&mut self) {
        RUNS.fetch_sub(1, Ordering::SeqCst);
    }
}

fn slot() -> Result<Slot, FirewallError> {
    if RUNS.fetch_add(1, Ordering::SeqCst) >= MAX_RUNS {
        RUNS.fetch_sub(1, Ordering::SeqCst);
        return Err(FirewallError::ServiceUnavailable {
            service: "tools".into(),
            message: format!("{MAX_RUNS} tools run already: try again shortly"),
        });
    }
    Ok(Slot)
}

/// What a run gives: a line of output, or its end with the exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    Line(String),
    Exit(i64),
}

pub type Run = Pin<Box<dyn Stream<Item = Result<Out, FirewallError>> + Send>>;

fn cut(mut l: String) -> String {
    if l.len() > MAX_LINE {
        let mut end = MAX_LINE;
        while !l.is_char_boundary(end) {
            end -= 1;
        }
        l.truncate(end);
        l.push('…');
    }
    l
}

/// Run `program` with `args`, its output line by line (stdout, then
/// stderr), then its exit status; stopped after `limit`.
pub fn run(
    program: &'static str,
    args: Vec<String>,
    limit: Duration,
) -> Result<Run, FirewallError> {
    let slot = slot()?;
    let mut child = tokio::process::Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| FirewallError::ServiceUnavailable {
            service: "tools".into(),
            message: format!("{program}: {e}"),
        })?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let deadline = tokio::time::Instant::now() + limit;
    struct State {
        child: tokio::process::Child,
        out: Option<tokio::io::Lines<BufReader<tokio::process::ChildStdout>>>,
        err: Option<tokio::io::Lines<BufReader<tokio::process::ChildStderr>>>,
        lines: usize,
        done: bool,
        _slot: Slot,
    }
    let st = State {
        child,
        out: stdout.map(|o| BufReader::new(o).lines()),
        err: stderr.map(|e| BufReader::new(e).lines()),
        lines: 0,
        done: false,
        _slot: slot,
    };
    Ok(Box::pin(futures_util::stream::unfold(
        st,
        move |mut st| async move {
            if st.done {
                return None;
            }
            let next = tokio::time::timeout_at(deadline, async {
                loop {
                    if let Some(o) = st.out.as_mut() {
                        match o.next_line().await {
                            Ok(Some(l)) => return Some(l),
                            _ => st.out = None,
                        }
                    } else {
                        let e = st.err.as_mut()?;
                        match e.next_line().await {
                            Ok(Some(l)) => return Some(l),
                            _ => st.err = None,
                        }
                    }
                }
            })
            .await;
            match next {
                Ok(Some(l)) if st.lines < MAX_LINES => {
                    st.lines += 1;
                    Some((Ok(Out::Line(cut(l))), st))
                }
                Ok(Some(_)) => {
                    // Over the limit: stop it.
                    let _ = st.child.start_kill();
                    st.done = true;
                    Some((
                        Ok(Out::Line(format!("(output cut at {MAX_LINES} lines)"))),
                        st,
                    ))
                }
                Ok(None) => {
                    st.done = true;
                    let code = tokio::time::timeout_at(deadline, st.child.wait())
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .and_then(|s| s.code())
                        .map_or(-1, i64::from);
                    Some((Ok(Out::Exit(code)), st))
                }
                Err(_) => {
                    let _ = st.child.start_kill();
                    st.done = true;
                    Some((
                        Ok(Out::Line(format!("(stopped after {} s)", limit.as_secs()))),
                        st,
                    ))
                }
            }
        },
    )))
}

pub const PING_LIMIT: Duration = Duration::from_secs(30);
pub const TRACEROUTE_LIMIT: Duration = Duration::from_secs(60);
pub const LOOKUP_LIMIT: Duration = Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_addresses_or_host_names() {
        assert_eq!(
            Target::parse("192.0.2.1", "host").unwrap(),
            Target::Addr("192.0.2.1".parse().unwrap())
        );
        assert!(Target::parse("2001:db8::1", "host").unwrap().v6());
        assert_eq!(
            Target::parse("nas.home.arpa.", "host").unwrap(),
            Target::Name("nas.home.arpa.".into())
        );
        for bad in ["-c100", "a b", "x;reboot", "", "-", "a..b", &"a".repeat(64)] {
            assert!(Target::parse(bad, "host").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ping_is_bounded_and_takes_a_source() {
        let t = Target::parse("192.0.2.1", "host").unwrap();
        let s = Source::Addr("192.168.1.1".parse().unwrap());
        assert_eq!(
            ping_args(&t, Some(&s), Some(2)).unwrap(),
            [
                "-n",
                "-c2",
                "-W2",
                "-w7",
                "-4",
                "-I192.168.1.1",
                "--",
                "192.0.2.1"
            ]
        );
        assert_eq!(
            ping_args(&t, Some(&Source::Iface("lan0".into())), None).unwrap()[4],
            "-Ilan0"
        );
        assert!(ping_args(&t, None, Some(0)).is_err());
        assert!(ping_args(&t, None, Some(11)).is_err());
        let v6 = Target::parse("2001:db8::1", "host").unwrap();
        assert!(traceroute_args(&v6, None).contains(&"-6".to_string()));
        assert_eq!(
            traceroute_args(&t, Some(&s)),
            [
                "-n",
                "-m20",
                "-q1",
                "-w2",
                "-4",
                "-s192.168.1.1",
                "--",
                "192.0.2.1"
            ]
        );
    }

    #[test]
    fn lookups_take_a_known_record_type() {
        let n = Target::parse("nas.home.arpa", "name").unwrap();
        assert_eq!(
            lookup_args(&n, Some("aaaa"), Some("192.168.1.1")).unwrap(),
            [
                "+time=2",
                "+tries=1",
                "+nocomments",
                "@192.168.1.1",
                "-q",
                "nas.home.arpa",
                "-t",
                "AAAA"
            ]
        );
        assert!(lookup_args(&n, Some("AXFR"), None).is_err());
        assert!(lookup_args(&n, Some("ANY"), None).is_err());
        assert!(lookup_args(&n, None, Some("ns1.example")).is_err());
        let a = Target::parse("192.0.2.1", "name").unwrap();
        assert_eq!(
            lookup_args(&a, None, None).unwrap()[3..],
            ["-x", "192.0.2.1"]
        );
        assert!(lookup_args(&a, Some("A"), None).is_err());
    }

    #[test]
    fn a_source_is_the_node_s_own_address_on_the_network() {
        let text = std::fs::read_to_string(format!(
            "{}/../../examples/two-nic.yaml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let doc = sparewall_config::parse(&text, sparewall_config::Format::Yaml).unwrap();
        let v4 = Target::parse("192.0.2.1", "host").unwrap();
        let v6 = Target::parse("2001:db8::1", "host").unwrap();
        assert_eq!(
            source(Some(&doc), "fw1", Some("lan"), &v4).unwrap(),
            Some(Source::Addr("192.168.1.1".parse().unwrap()))
        );
        assert_eq!(
            source(Some(&doc), "fw1", Some("lan"), &v6).unwrap(),
            Some(Source::Iface("lan0".into()))
        );
        assert_eq!(source(Some(&doc), "fw1", None, &v4).unwrap(), None);
        assert!(source(Some(&doc), "fw1", Some("nope"), &v4).is_err());
        // The WAN's address is DHCP's: none of the node's own in the document.
        assert!(source(Some(&doc), "fw1", Some("wan"), &v4).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_run_gives_its_lines_then_its_exit() {
        use futures_util::StreamExt;
        let r = run(
            "sh",
            vec!["-c".into(), "echo a; echo b >&2; exit 3".into()],
            Duration::from_secs(5),
        )
        .unwrap();
        let out: Vec<_> = r.map(Result::unwrap).collect().await;
        assert_eq!(
            out,
            [Out::Line("a".into()), Out::Line("b".into()), Out::Exit(3)]
        );
        let r = run("sleep", vec!["5".into()], Duration::from_millis(200)).unwrap();
        let out: Vec<_> = r.map(Result::unwrap).collect().await;
        assert_eq!(out, [Out::Line("(stopped after 0 s)".into())]);
    }
}
