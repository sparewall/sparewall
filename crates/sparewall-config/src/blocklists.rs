//! IP blocklists (#379): what a list's text holds, and the names of the
//! nft sets its addresses go in. Shared by the renderer, which declares
//! the sets, and the coordinator, which fills them from the lists it
//! fetches.

use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// The most a list's body may hold, as for DNS filters.
pub const MAX_LIST_BYTES: usize = crate::filters::MAX_LIST_BYTES;
/// The most entries kept from one list; the rest are left out, and
/// health says so. Measured on a 2-vCPU node: an interval set takes about
/// 0.34 KiB of kernel memory per entry and loads 500,000 in 1.5 s in one
/// transaction, so this cap is about 85 MiB a list, several times
/// CrowdSec's lists, on both nodes of a pair.
pub const MAX_ENTRIES: usize = 250_000;
/// The shortest `refresh`, so a list's publisher isn't hammered.
pub const MIN_REFRESH_SECS: u64 = 15 * 60;

/// The nft sets a list's addresses go in, IPv4 and IPv6.
pub fn set_names(list: &str) -> (String, String) {
    let base = list.replace('-', "_");
    (format!("bl_{base}_4"), format!("bl_{base}_6"))
}

/// A blocklist name: it becomes part of the sets' names, with `-` as `_`
/// (so `_` itself isn't taken, or two names could share a set).
pub fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// An address or prefix, as a prefix (a bare address is a /32 or /128).
pub fn entry(s: &str) -> Option<IpNet> {
    if let Ok(n) = s.parse::<IpNet>() {
        return Some(n.trunc());
    }
    s.parse::<IpAddr>().ok().map(IpNet::from)
}

/// What a list holds.
#[derive(Debug, Default, PartialEq)]
pub struct Parsed {
    pub v4: Vec<Ipv4Net>,
    pub v6: Vec<Ipv6Net>,
    /// Lines that are neither blank, a comment nor an address or prefix.
    pub skipped: usize,
    /// Entries past [`MAX_ENTRIES`], left out.
    pub dropped: usize,
}

/// A list's text: one address or prefix per line, its first word (so
/// Spamhaus' `1.2.3.0/24 ; SBL123` reads), with `#` and `;` comments and
/// blank lines ignored. Sorted and without duplicates.
pub fn parse(text: &str) -> Parsed {
    let mut p = Parsed::default();
    let mut n = 0usize;
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or_default().trim();
        let Some(word) = line.split_whitespace().next() else {
            continue;
        };
        match entry(word) {
            Some(_) if n >= MAX_ENTRIES => p.dropped += 1,
            Some(IpNet::V4(a)) => {
                n += 1;
                p.v4.push(a);
            }
            Some(IpNet::V6(a)) => {
                n += 1;
                p.v6.push(a);
            }
            None => p.skipped += 1,
        }
    }
    p.v4.sort();
    p.v4.dedup();
    p.v6.sort();
    p.v6.dedup();
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_plain_lists_and_spamhaus() {
        let p = parse(
            "# CrowdSec\n192.0.2.7\n198.51.100.0/24\n\n2001:db8::1\n2001:db8:1::/48\n\
             203.0.113.0/24 ; SBL123\n; comment\nnot-an-address\n192.0.2.7\n10.1.2.3/8\n",
        );
        assert_eq!(
            p.v4,
            [
                "10.0.0.0/8".parse().unwrap(),
                "192.0.2.7/32".parse().unwrap(),
                "198.51.100.0/24".parse().unwrap(),
                "203.0.113.0/24".parse().unwrap(),
            ]
        );
        assert_eq!(
            p.v6,
            [
                "2001:db8::1/128".parse().unwrap(),
                "2001:db8:1::/48".parse().unwrap()
            ]
        );
        assert_eq!(p.skipped, 1);
        assert_eq!(p.dropped, 0);
    }

    #[test]
    fn names_and_sets() {
        assert!(name_ok("crowdsec") && name_ok("spamhaus-drop") && name_ok("a1"));
        assert!(
            !name_ok("")
                && !name_ok("Bad")
                && !name_ok("1st")
                && !name_ok("a.b")
                && !name_ok("a_1")
        );
        assert_eq!(
            set_names("spamhaus-drop"),
            ("bl_spamhaus_drop_4".into(), "bl_spamhaus_drop_6".into())
        );
    }
}
