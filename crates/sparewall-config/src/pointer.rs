//! From a validator path to a JSON Pointer (#305).
//!
//! The validator names a place in the document as a path: names joined by
//! `.`, and `[n]` for a list index, e.g. `networks.lan.dhcp.ranges[0]`,
//! the form `serde_path_to_error` uses too; a name may be quoted, as
//! `policy.'users->wan'` is. Names may hold a `.` themselves
//! (a DNS name, say), so the path is read against the document: at each
//! step the longest name the document has there wins. Past what the
//! document has (a required field left out), each `.` separates a name.

use serde_json::Value;

/// The RFC 6901 JSON Pointer for `path` in `doc`, or `None` for a path
/// that names the whole document or isn't one.
pub fn pointer(doc: &Value, path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty() || path == "." || path.starts_with('(') {
        return None;
    }
    let mut segments: Vec<String> = Vec::new();
    let mut here = Some(doc);
    let mut rest = path;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('[') {
            let end = r.find(']')?;
            let index: usize = r[..end].parse().ok()?;
            segments.push(index.to_string());
            here = here.and_then(|v| v.get(index));
            rest = &r[end + 1..];
        } else if let Some(q) = rest.chars().next().filter(|c| *c == '\'' || *c == '"') {
            let r = &rest[1..];
            let end = r.find(q)?;
            let name = &r[..end];
            here = here.and_then(|v| v.get(name));
            segments.push(name.to_string());
            rest = &r[end + 1..];
        } else {
            let known = here
                .and_then(Value::as_object)
                .and_then(|o| {
                    o.keys()
                        .filter(|k| {
                            rest.strip_prefix(k.as_str()).is_some_and(|after| {
                                after.is_empty() || after.starts_with(['.', '['])
                            })
                        })
                        .max_by_key(|k| k.len())
                })
                .cloned();
            let name = known.unwrap_or_else(|| {
                let end = rest.find(['.', '[']).unwrap_or(rest.len());
                rest[..end].to_string()
            });
            if name.is_empty() {
                return None;
            }
            here = here.and_then(|v| v.get(&name));
            rest = &rest[name.len()..];
            segments.push(name);
        }
        rest = rest.strip_prefix('.').unwrap_or(rest);
    }
    Some(
        segments
            .iter()
            .map(|s| format!("/{}", s.replace('~', "~0").replace('/', "~1")))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::pointer;
    use serde_json::json;

    #[test]
    fn names_and_indexes() {
        let doc = json!({"networks": {"lan": {"dhcp": {"ranges": ["a", "b"]}}}});
        assert_eq!(
            pointer(&doc, "networks.lan.dhcp.ranges[1]").as_deref(),
            Some("/networks/lan/dhcp/ranges/1")
        );
        assert_eq!(
            pointer(&doc, "networks.lan").as_deref(),
            Some("/networks/lan")
        );
    }

    #[test]
    fn a_name_with_dots_is_read_against_the_document() {
        let doc = json!({"dns": {"hosts": {"nas.home.arpa": {"a": "192.0.2.5"}}}});
        assert_eq!(
            pointer(&doc, "dns.hosts.nas.home.arpa.a").as_deref(),
            Some("/dns/hosts/nas.home.arpa/a")
        );
    }

    #[test]
    fn past_the_document_each_dot_separates() {
        let doc = json!({"networks": {"wan": {}}});
        assert_eq!(
            pointer(&doc, "networks.wan.gateway").as_deref(),
            Some("/networks/wan/gateway")
        );
        assert_eq!(
            pointer(&json!({}), "cluster.nodes[1]").as_deref(),
            Some("/cluster/nodes/1")
        );
    }

    #[test]
    fn a_quoted_name() {
        let doc = json!({"policy": {"users->wan": {"rules": {"web": {}}}}});
        assert_eq!(
            pointer(&doc, "policy.'users->wan'.rules.web.action").as_deref(),
            Some("/policy/users->wan/rules/web/action")
        );
        assert_eq!(
            pointer(&doc, "policy.users->wan.nat.snat").as_deref(),
            Some("/policy/users->wan/nat/snat")
        );
    }

    #[test]
    fn escapes_and_non_paths() {
        let doc = json!({"policy": {"a/b~c": {}}});
        assert_eq!(
            pointer(&doc, "policy.a/b~c").as_deref(),
            Some("/policy/a~1b~0c")
        );
        assert_eq!(pointer(&doc, "(document)"), None);
        assert_eq!(pointer(&doc, ""), None);
        assert_eq!(pointer(&doc, "x[oops]"), None);
    }
}
