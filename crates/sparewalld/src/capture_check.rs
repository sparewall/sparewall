//! What a packet capture's request may hold (#265): checked by the
//! coordinator before it asks, and again by `sparewall-capture`, which
//! runs tcpdump with it. The two share this file.

/// The longest filter taken.
pub const MAX_FILTER: usize = 512;

/// An interface name as the kernel takes one: 1 to 15 bytes, none of
/// them `/`, whitespace or a NUL, and none that tcpdump would read as an
/// option.
pub fn iface_ok(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && !s.starts_with('-')
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'@'))
}

/// Why a capture filter is refused, if it is: a pcap-filter expression
/// in its own syntax's characters only, which tcpdump then compiles. It
/// reaches tcpdump as one argument after `--`, never through a shell.
pub fn filter_problem(f: &str) -> Option<String> {
    if f.len() > MAX_FILTER {
        return Some(format!("filter: at most {MAX_FILTER} characters"));
    }
    f.chars()
        .find(|c| !(c.is_ascii_alphanumeric() || " .:/[]()&|!<>=-_*+%^~,".contains(*c)))
        .map(|c| format!("filter: {c:?} is not part of a capture filter's syntax"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_checked() {
        for i in ["eth0", "users", "enp1s0.10", "wg-site", "lan_2", "a@b"] {
            assert!(iface_ok(i), "{i}");
        }
        for i in ["", "-i", "a/b", "a b", "..", "0123456789abcdef", "eth0;x"] {
            assert!(!iface_ok(i), "{i}");
        }
        for f in [
            "icmp",
            "tcp port 443 and host 192.0.2.1",
            "ip6 and not (udp port 53)",
            "ether host 52:54:00:12:34:56",
            "tcp[tcpflags] & (tcp-syn|tcp-fin) != 0",
            "net 2001:db8::/32 || vlan 10",
        ] {
            assert_eq!(filter_problem(f), None, "{f}");
        }
        for f in ["icmp; reboot", "$(id)", "`id`", "host 'a'", "a\nb", "\"x\""] {
            assert!(filter_problem(f).is_some(), "{f}");
        }
        assert!(filter_problem(&"a".repeat(MAX_FILTER + 1)).is_some());
    }
}
