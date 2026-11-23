//! DNS filters (#74): the names a blocklist holds, read from the formats
//! lists are published in, and the set a view blocks.
//!
//! A blocked name takes its subdomains with it (Unbound's
//! `always_nxdomain` zone), and an allowed one keeps them: so a list is
//! kept as the shortest names that cover it, less every allowed name and
//! what lies under one.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::Document;

/// The most names one view blocks. Past it the rest are left out, and
/// health says so: Unbound keeps every one in memory.
pub const MAX_NAMES: usize = 1_000_000;

/// The most a list may take to download.
pub const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;

/// Whether `s` is a domain name a zone may be made of: dot-separated
/// labels of letters, digits, `-` and `_`, none empty or longer than 63,
/// at most 253 in all, and at least two labels (a bare `com` would block
/// a whole top-level domain).
pub fn is_name(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// A name as it is compared: lower case, without a final dot.
pub fn normalize(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The names in a list, in any of the common formats: a hosts file
/// (`0.0.0.0 ads.example`), one name per line, adblock-style lines
/// (`||ads.example^`), or names with a `*.` in front. Comments (`#`,
/// `!`) and anything that isn't a name are skipped; `localhost` and its
/// kin too, which hosts files list for themselves.
pub fn parse_list(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            continue;
        }
        let mut words = line.split_whitespace();
        let first = words.next().unwrap_or("");
        // A hosts line names an address first; each name after it is
        // blocked.
        let names: Vec<&str> = if first.parse::<std::net::IpAddr>().is_ok() {
            words.collect()
        } else {
            vec![first]
        };
        for n in names {
            let n = n.strip_prefix("||").unwrap_or(n);
            let n = n.strip_suffix('^').unwrap_or(n);
            let n = n.strip_prefix("*.").unwrap_or(n);
            let n = normalize(n);
            if is_name(&n) && !is_local(&n) && n.parse::<std::net::IpAddr>().is_err() {
                out.push(n);
            }
        }
    }
    out
}

fn is_local(n: &str) -> bool {
    matches!(
        n,
        "localhost.localdomain" | "local.localdomain" | "ip6-localhost" | "broadcasthost"
    ) || n.ends_with(".localhost")
}

/// Whether `name` is `zone` or lies under it.
pub fn within(name: &str, zone: &str) -> bool {
    name == zone
        || (name.len() > zone.len()
            && name.ends_with(zone)
            && name.as_bytes()[name.len() - zone.len() - 1] == b'.')
}

/// The names a view blocks: every name given, less those an allowed name
/// covers, and less those a blocked parent already covers; sorted. Past
/// [`MAX_NAMES`] the rest are left out, and the second value is how many.
pub fn compact<'a>(
    names: impl IntoIterator<Item = &'a str>,
    allow: &[String],
) -> (Vec<String>, usize) {
    let allow: BTreeSet<String> = allow.iter().map(|a| normalize(a)).collect();
    let allowed = |n: &str| {
        let mut z = n;
        loop {
            if allow.contains(z) {
                return true;
            }
            match z.split_once('.') {
                Some((_, rest)) => z = rest,
                None => return false,
            }
        }
    };
    let all: BTreeSet<&str> = names.into_iter().filter(|n| !allowed(n)).collect();
    // A name whose parent is blocked too adds nothing.
    let covered = |n: &str| {
        let mut z = n;
        while let Some((_, rest)) = z.split_once('.') {
            if all.contains(rest) {
                return true;
            }
            z = rest;
        }
        false
    };
    let mut out: Vec<String> = all
        .iter()
        .filter(|n| !covered(n))
        .map(|n| n.to_string())
        .collect();
    let dropped = out.len().saturating_sub(MAX_NAMES);
    out.truncate(MAX_NAMES);
    (out, dropped)
}

/// Networks in the same filters share an Unbound view, named after
/// them (`ads`, or `ads+kids` for a network in both).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub name: String,
    pub filters: Vec<String>,
    pub networks: Vec<String>,
}

/// The views a document's filters make, by name.
pub fn views(doc: &Document) -> Vec<View> {
    let Some(d) = &doc.dns else { return vec![] };
    let mut of: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (f, x) in &d.filters {
        for n in &x.networks {
            of.entry(n).or_default().push(f.clone());
        }
    }
    let mut by: BTreeMap<Vec<String>, Vec<String>> = BTreeMap::new();
    for (n, mut fs) in of {
        fs.sort();
        fs.dedup();
        by.entry(fs).or_default().push(n.to_string());
    }
    by.into_iter()
        .map(|(filters, networks)| View {
            name: filters.join("+"),
            filters,
            networks,
        })
        .collect()
}

/// The file a view's names are in, in the resolver's configuration
/// directory: a dotfile, which an apply leaves alone.
pub fn view_file(view: &str) -> String {
    format!(".filter-{view}.conf")
}

/// Seconds in a duration such as `24h`, `1d`, `90m` or `1d12h`.
pub fn duration_secs(s: &str) -> Option<u64> {
    let mut total: u64 = 0;
    let mut n: Option<u64> = None;
    for c in s.trim().chars() {
        if let Some(d) = c.to_digit(10) {
            n = Some(n.unwrap_or(0).checked_mul(10)?.checked_add(u64::from(d))?);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            'w' => 7 * 86400,
            _ => return None,
        };
        total = total.checked_add(n.take()?.checked_mul(unit)?)?;
    }
    if n.is_some() || total == 0 {
        return None;
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_in_every_format() {
        let text = "\
# A hosts file
127.0.0.1 localhost
0.0.0.0 ads.example.com tracker.example.net # two at once
::1 ip6-localhost
0.0.0.0 0.0.0.0
Pixel.Example.ORG.
! adblock comment
||adblock.example^
*.wild.example
[Adblock Plus 2.0]
not_a_name
-bad-.example
com
x.localhost
";
        assert_eq!(
            parse_list(text),
            [
                "ads.example.com",
                "tracker.example.net",
                "pixel.example.org",
                "adblock.example",
                "wild.example",
            ]
        );
    }

    #[test]
    fn names() {
        assert!(is_name("a.example"));
        assert!(is_name("_dmarc.example.com."));
        assert!(!is_name("example"));
        assert!(!is_name("a..example"));
        assert!(!is_name("a b.example"));
        assert!(!is_name(&format!("{}.example", "a".repeat(64))));
        assert!(within("a.b.example", "b.example"));
        assert!(within("b.example", "b.example"));
        assert!(!within("ab.example", "b.example"));
    }

    #[test]
    fn compacting_keeps_the_shortest_and_drops_the_allowed() {
        let names = [
            "ads.example.com",
            "x.ads.example.com",
            "cdn.example.net",
            "img.cdn.example.net",
            "tracker.example.org",
            "ok.example.org",
        ];
        let (out, dropped) = compact(names, &["cdn.example.net".into(), "OK.example.org".into()]);
        assert_eq!(out, ["ads.example.com", "tracker.example.org"]);
        assert_eq!(dropped, 0);
    }

    #[test]
    fn durations() {
        assert_eq!(duration_secs("24h"), Some(86400));
        assert_eq!(duration_secs("1d12h"), Some(129600));
        assert_eq!(duration_secs("90m"), Some(5400));
        for bad in ["", "24", "h", "0h", "1x", "-1h"] {
            assert_eq!(duration_secs(bad), None, "{bad}");
        }
    }
}
