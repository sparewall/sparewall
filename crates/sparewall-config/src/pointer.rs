//! Document paths and JSON Pointers (#305).
//!
//! The validator names a place in the document as a path: names joined by
//! `.`, and `[n]` for a list index, e.g. `networks.lan.dhcp.ranges[0]`. A
//! name that holds a `.`, `[`, `]` or a quote is quoted with `'` (or `"`,
//! when it holds a `'`), as [`name`] does, so a path always reads one way:
//! `policy.'users->wan'.rules.'allow.web'.action`. Policy keys are quoted
//! always, for the `->`.

use std::borrow::Cow;

/// A document name as one path segment: quoted when it would otherwise
/// read as more than one, or as an index.
pub fn name(k: &str) -> Cow<'_, str> {
    if !k.is_empty() && !k.contains(['.', '[', ']', '\'', '"']) {
        Cow::Borrowed(k)
    } else if k.contains('\'') {
        Cow::Owned(format!("\"{k}\""))
    } else {
        Cow::Owned(format!("'{k}'"))
    }
}

/// The segments of a path: names, and list indexes as their digits.
/// `None` for one that isn't a path (an unterminated quote, a bad index).
pub fn segments(path: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut rest = path.trim();
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('[') {
            let end = r.find(']')?;
            let index: usize = r[..end].parse().ok()?;
            out.push(index.to_string());
            rest = &r[end + 1..];
        } else if let Some(q) = rest.chars().next().filter(|c| *c == '\'' || *c == '"') {
            let r = &rest[1..];
            let end = r.find(q)?;
            out.push(r[..end].to_string());
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
    use super::{name, pointer};

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
        assert_eq!(pointer("raw.\"it's.x\"").as_deref(), Some("/raw/it's.x"));
    }

    /// Codex's review of #337: with keys `home->wan` and `home->wan.nat`,
    /// and `nas` and `nas.home`, each path reads one way only.
    #[test]
    fn keys_that_extend_one_another_stay_apart() {
        let p = |k: &str| format!("policy.{}.nat.snat", name(k));
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

    #[test]
    fn name_quotes_only_when_it_must() {
        assert_eq!(name("users"), "users");
        assert_eq!(name("users->wan"), "users->wan");
        assert_eq!(name("a.b"), "'a.b'");
        assert_eq!(name("x[0]"), "'x[0]'");
        assert_eq!(name("it's"), "\"it's\"");
        assert_eq!(name(""), "''");
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
        assert_eq!(pointer("x..y"), None);
        assert_eq!(pointer("x."), None);
    }
}
