//! Document paths and JSON Pointers (#305).
//!
//! The validator names a place in the document as a path: names joined by
//! `.`, and `[n]` for a list index, e.g. `networks.lan.dhcp.ranges[0]`. A
//! name that would not read back as itself (one holding a `.`, `[`, `]`,
//! a quote or a `\`, starting or ending with a space, or empty) is quoted
//! with `'`, a `'` or `\` inside escaped with `\`, as [`name`] does. A
//! path therefore reads one way only, and [`segments`] reads back exactly
//! the names [`name`] wrote: `policy.'users->wan'.rules.'allow.web'.action`.
//! Policy keys are always quoted ([`quoted`]), for the `->`.

use std::borrow::Cow;

/// A document name as one path segment: quoted when it would otherwise
/// not read back as itself.
pub fn name(k: &str) -> Cow<'_, str> {
    let plain = !k.is_empty() && !k.contains(['.', '[', ']', '\'', '"', '\\']) && k.trim() == k;
    if plain {
        Cow::Borrowed(k)
    } else {
        Cow::Owned(quoted(k))
    }
}

/// A document name quoted, whatever it holds.
pub fn quoted(k: &str) -> String {
    let mut out = String::with_capacity(k.len() + 2);
    out.push('\'');
    for c in k.chars() {
        if c == '\'' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// The segments of a path: names, and list indexes as their digits.
/// `None` for one that isn't a path (an unterminated quote, a bad index,
/// an empty name outside quotes).
pub fn segments(path: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut rest = path;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('[') {
            let end = r.find(']')?;
            let index: usize = r[..end].parse().ok()?;
            out.push(index.to_string());
            rest = &r[end + 1..];
        } else if let Some(r) = rest.strip_prefix('\'') {
            let mut name = String::new();
            let mut chars = r.char_indices();
            let end = loop {
                match chars.next()? {
                    (_, '\\') => name.push(chars.next()?.1),
                    (i, '\'') => break i,
                    (_, c) => name.push(c),
                }
            };
            out.push(name);
            rest = &r[end + 1..];
        } else {
            let end = rest.find(['.', '[']).unwrap_or(rest.len());
            if end == 0 {
                return None;
            }
            out.push(rest[..end].to_string());
            rest = &rest[end..];
        }
        match rest.strip_prefix('.') {
            Some(r) if !r.is_empty() => rest = r,
            Some(_) => return None,
            None if rest.is_empty() || rest.starts_with('[') => {}
            None => return None,
        }
    }
    Some(out)
}

/// The RFC 6901 JSON Pointer for a path, or `None` for one that names the
/// whole document or isn't a path.
pub fn pointer(path: &str) -> Option<String> {
    if path.starts_with('(') {
        return None;
    }
    let segments = segments(path).filter(|s| !s.is_empty())?;
    Some(
        segments
            .iter()
            .map(|s| format!("/{}", s.replace('~', "~0").replace('/', "~1")))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::{name, pointer, quoted, segments};

    #[test]
    fn names_and_indexes() {
        assert_eq!(
            pointer("networks.lan.dhcp.ranges[1]").as_deref(),
            Some("/networks/lan/dhcp/ranges/1")
        );
        assert_eq!(
            pointer("cluster.nodes[1]").as_deref(),
            Some("/cluster/nodes/1")
        );
        assert_eq!(pointer("a[0][2].b").as_deref(), Some("/a/0/2/b"));
    }

    #[test]
    fn quoted_names_keep_their_dots() {
        assert_eq!(
            pointer("policy.'users->wan'.rules.'allow.web'.action").as_deref(),
            Some("/policy/users->wan/rules/allow.web/action")
        );
    }

    /// Codex's review of #337: with keys `home->wan` and `home->wan.nat`,
    /// and `nas` and `nas.home`, each path reads one way only.
    #[test]
    fn keys_that_extend_one_another_stay_apart() {
        let p = |k: &str| format!("policy.{}.nat.snat", quoted(k));
        assert_eq!(
            pointer(&p("home->wan")).as_deref(),
            Some("/policy/home->wan/nat/snat")
        );
        assert_eq!(
            pointer(&p("home->wan.nat")).as_deref(),
            Some("/policy/home->wan.nat/nat/snat")
        );
        let h = |k: &str| format!("dhcp.lan.reservations.{}.mac", name(k));
        assert_eq!(
            pointer(&h("nas.home")).as_deref(),
            Some("/dhcp/lan/reservations/nas.home/mac")
        );
        assert_eq!(
            pointer(&h("nas")).as_deref(),
            Some("/dhcp/lan/reservations/nas/mac")
        );
    }

    /// Codex's second review: every name reads back as itself, quotes,
    /// backslashes, spaces and the empty name included.
    #[test]
    fn every_name_round_trips() {
        let names = [
            "users",
            "users->wan",
            "a.b",
            "x[0]",
            "]",
            "it's",
            "say \"hi\"",
            "both ' and \"",
            "back\\slash",
            "\\'",
            "'",
            "\"",
            "",
            " lead",
            "trail ",
            "a..b",
            "[",
            "~/",
        ];
        for k in names {
            for path in [
                format!("raw.{}.nft", name(k)),
                format!("raw.{}.nft", quoted(k)),
                format!("raw.{}[3]", name(k)),
            ] {
                let s = segments(&path).unwrap_or_else(|| panic!("{path:?} does not read"));
                assert_eq!(s[1], k, "{path:?}");
                assert_eq!(s.len(), 3, "{path:?}");
            }
        }
        assert_eq!(
            pointer(&format!("raw.{}.nft", name(""))).as_deref(),
            Some("/raw//nft")
        );
    }

    #[test]
    fn name_quotes_only_when_it_must() {
        assert_eq!(name("users"), "users");
        assert_eq!(name("users->wan"), "users->wan");
        assert_eq!(name("a.b"), "'a.b'");
        assert_eq!(name("x[0]"), "'x[0]'");
        assert_eq!(name("it's"), "'it\\'s'");
        assert_eq!(name(""), "''");
        assert_eq!(quoted("users->wan"), "'users->wan'");
    }

    #[test]
    fn escapes_and_non_paths() {
        assert_eq!(
            pointer("policy.'a/b~c'").as_deref(),
            Some("/policy/a~1b~0c")
        );
        assert_eq!(pointer(""), None);
        assert_eq!(pointer("(document)"), None);
        assert_eq!(pointer("x[oops]"), None);
        assert_eq!(pointer("x.'open"), None);
        assert_eq!(pointer("x.'esc\\"), None);
        assert_eq!(pointer("x..y"), None);
        assert_eq!(pointer("x."), None);
        assert_eq!(pointer("'a'b"), None);
    }
}
