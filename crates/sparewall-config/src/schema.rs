//! The JSON Schema of the document, and lookups into it by path for typing
//! `set` values and for `sparewall explain`.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde_json::Value;

use crate::model::Document;

/// The JSON Schema (draft 2020-12) for the current document version.
pub fn json_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let mut v = serde_json::to_value(schemars::schema_for!(Document)).expect("schema");
        if let Value::Object(m) = &mut v {
            m.insert(
                "$id".into(),
                Value::String(format!(
                    "https://sparewall.org/schema/v{}.json",
                    crate::SCHEMA_VERSION
                )),
            );
        }
        v
    })
}

fn resolve<'a>(root: &'a Value, node: &'a Value) -> &'a Value {
    let mut n = node;
    for _ in 0..16 {
        match n.get("$ref").and_then(Value::as_str) {
            Some(r) => {
                let name = r.rsplit('/').next().unwrap_or(r);
                match root.get("$defs").and_then(|d| d.get(name)) {
                    Some(t) => n = t,
                    None => break,
                }
            }
            None => break,
        }
    }
    n
}

/// The alternatives a node allows (`anyOf`/`oneOf`), resolved, or the node
/// itself.
fn alternatives<'a>(root: &'a Value, node: &'a Value) -> Vec<&'a Value> {
    let node = resolve(root, node);
    for key in ["anyOf", "oneOf"] {
        if let Some(Value::Array(alts)) = node.get(key) {
            return alts.iter().flat_map(|a| alternatives(root, a)).collect();
        }
    }
    vec![node]
}

fn child<'a>(root: &'a Value, node: &'a Value, seg: &str) -> Option<&'a Value> {
    for alt in alternatives(root, node) {
        if let Some(p) = alt.get("properties").and_then(|p| p.get(seg)) {
            return Some(p);
        }
        if let Some(ap) = alt.get("additionalProperties")
            && ap.is_object()
        {
            return Some(ap);
        }
        if let Some(items) = alt.get("items")
            && seg.parse::<usize>().is_ok()
        {
            return Some(items);
        }
    }
    None
}

/// The schema node at a path, if the schema describes it.
pub fn node_at<S: AsRef<str>>(path: &[S]) -> Option<&'static Value> {
    let root = json_schema();
    let mut n = root;
    for seg in path {
        n = child(root, n, seg.as_ref())?;
    }
    Some(n)
}

/// The JSON types allowed at a path ("string", "integer", "object", ...).
/// Empty when anything goes (or the path is unknown).
pub fn types_at<S: AsRef<str>>(path: &[S]) -> BTreeSet<String> {
    let root = json_schema();
    let Some(n) = node_at(path) else {
        return BTreeSet::new();
    };
    let mut out = BTreeSet::new();
    for alt in alternatives(root, n) {
        match alt.get("type") {
            Some(Value::String(t)) => {
                out.insert(t.clone());
            }
            Some(Value::Array(ts)) => {
                out.extend(ts.iter().filter_map(|t| t.as_str()).map(String::from))
            }
            _ => {
                if alt.get("enum").is_some() || alt.get("const").is_some_and(Value::is_string) {
                    out.insert("string".into());
                } else if alt.as_object().is_some_and(|m| m.is_empty()) || alt == &Value::Bool(true)
                {
                    return BTreeSet::new();
                }
            }
        }
    }
    out.remove("null");
    out
}

fn describe_type(root: &Value, node: &Value) -> String {
    let mut parts = Vec::new();
    for alt in alternatives(root, node) {
        let s = if let Some(Value::Array(e)) = alt.get("enum") {
            e.iter()
                .map(|v| v.as_str().map_or(v.to_string(), str::to_string))
                .collect::<Vec<_>>()
                .join(" | ")
        } else if let Some(c) = alt.get("const") {
            c.as_str().map_or(c.to_string(), str::to_string)
        } else {
            match alt.get("type") {
                Some(Value::String(t)) if t == "null" => continue,
                Some(Value::String(t))
                    if t == "object"
                        && alt
                            .get("additionalProperties")
                            .is_some_and(Value::is_object) =>
                {
                    "map of name -> object".to_string()
                }
                Some(Value::String(t)) if t == "array" => {
                    let item = alt
                        .get("items")
                        .map(|i| describe_type(root, i))
                        .unwrap_or_else(|| "any".into());
                    format!("list of {item}")
                }
                Some(Value::String(t)) => t.clone(),
                Some(Value::Array(ts)) => ts
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|t| *t != "null")
                    .collect::<Vec<_>>()
                    .join(" | "),
                _ => "any".to_string(),
            }
        };
        if !parts.contains(&s) {
            parts.push(s);
        }
    }
    parts.join(" | ")
}

fn description(root: &Value, node: &Value) -> Option<String> {
    node.get("description")
        .or_else(|| resolve(root, node).get("description"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Human-readable description of a field, like `kubectl explain`.
pub fn explain<S: AsRef<str>>(path: &[S]) -> Option<String> {
    let root = json_schema();
    let node = node_at(path)?;
    let mut out = String::new();
    let name = if path.is_empty() {
        "(document)".to_string()
    } else {
        crate::path::format_path(path)
    };
    out.push_str(&format!(
        "FIELD: {name}\nTYPE:  {}\n",
        describe_type(root, node)
    ));
    if let Some(d) = description(root, node) {
        out.push_str(&format!("\n{d}\n"));
    }
    let mut fields: Vec<(String, String, bool, Option<String>)> = Vec::new();
    for alt in alternatives(root, node) {
        let target = alt
            .get("additionalProperties")
            .filter(|ap| ap.is_object())
            .map(|ap| resolve(root, ap))
            .unwrap_or(alt);
        let required: BTreeSet<&str> = target
            .get("required")
            .and_then(Value::as_array)
            .map(|r| r.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if let Some(Value::Object(props)) = target.get("properties") {
            for (k, v) in props {
                if fields.iter().any(|f| &f.0 == k) {
                    continue;
                }
                fields.push((
                    k.clone(),
                    describe_type(root, v),
                    required.contains(k.as_str()),
                    description(root, v),
                ));
            }
        }
    }
    if !fields.is_empty() {
        out.push_str("\nFIELDS:\n");
        for (k, t, req, d) in fields {
            let req = if req { " (required)" } else { "" };
            out.push_str(&format!("  {k}  <{t}>{req}\n"));
            if let Some(d) = d {
                for line in d.lines() {
                    out.push_str(&format!("      {line}\n"));
                }
            }
        }
    }
    Some(out)
}

/// The schema as a pretty JSON string, for shipping in the image.
pub fn json_schema_text() -> String {
    let mut s = serde_json::to_string_pretty(json_schema()).expect("schema");
    s.push('\n');
    s
}
