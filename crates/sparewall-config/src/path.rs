//! Dot-separated document paths (`policy.'wan->self'.rules`) and the merge
//! patches that `set` and `unset` compile to.

use serde_json::{Map, Value};

use crate::{Error, schema};

/// Split a path into segments. Segments containing dots or `->` are quoted
/// with `'` or `"`.
pub fn parse_path(path: &str) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    let mut chars = path.chars().peekable();
    let mut cur = String::new();
    let mut quoted = false;
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' if cur.is_empty() && !quoted => {
                let q = c;
                loop {
                    match chars.next() {
                        Some(x) if x == q => break,
                        Some(x) => cur.push(x),
                        None => return Err(Error::Path(format!("unterminated quote in {path:?}"))),
                    }
                }
                quoted = true;
            }
            '.' => {
                if cur.is_empty() && !quoted {
                    return Err(Error::Path(format!("empty segment in {path:?}")));
                }
                out.push(std::mem::take(&mut cur));
                quoted = false;
            }
            _ if quoted => {
                return Err(Error::Path(format!(
                    "unexpected {c:?} after quoted segment in {path:?}"
                )));
            }
            _ => cur.push(c),
        }
    }
    if cur.is_empty() && !quoted {
        if out.is_empty() {
            return Ok(out);
        }
        return Err(Error::Path(format!("empty segment in {path:?}")));
    }
    out.push(cur);
    Ok(out)
}

/// Join segments back into a path, quoting where needed.
pub fn format_path<S: AsRef<str>>(segments: &[S]) -> String {
    segments
        .iter()
        .map(|s| {
            let s = s.as_ref();
            if s.is_empty() || s.contains(['.', '\'', '"', ' ', '>']) {
                if s.contains('\'') {
                    format!("\"{s}\"")
                } else {
                    format!("'{s}'")
                }
            } else {
                s.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Look up a subtree. Numeric segments index arrays.
pub fn get<'a, S: AsRef<str>>(root: &'a Value, path: &[S]) -> Option<&'a Value> {
    let mut v = root;
    for seg in path {
        let seg = seg.as_ref();
        v = match v {
            Value::Object(m) => m.get(seg)?,
            Value::Array(a) => a.get(seg.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(v)
}

/// The merge patch that sets `path` to `value`.
pub fn set_patch<S: AsRef<str>>(path: &[S], value: Value) -> Result<Value, Error> {
    if path.is_empty() {
        return Err(Error::Path(
            "cannot set the whole document; use apply".into(),
        ));
    }
    let mut v = value;
    for seg in path.iter().rev() {
        let mut m = Map::new();
        m.insert(seg.as_ref().to_string(), v);
        v = Value::Object(m);
    }
    Ok(v)
}

/// The merge patch that removes `path`.
pub fn unset_patch<S: AsRef<str>>(path: &[S]) -> Result<Value, Error> {
    if path.is_empty() {
        return Err(Error::Path("cannot unset the whole document".into()));
    }
    set_patch(path, Value::Null)
}

/// Combine several merge patches into one (later ones win).
pub fn combine(patches: impl IntoIterator<Item = Value>) -> Value {
    let mut out = Value::Object(Map::new());
    for p in patches {
        combine_into(&mut out, p);
    }
    out
}

fn combine_into(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Object(t), Value::Object(p)) => {
            for (k, v) in p {
                match t.get_mut(&k) {
                    Some(existing @ Value::Object(_)) if v.is_object() => combine_into(existing, v),
                    _ => {
                        t.insert(k, v);
                    }
                }
            }
        }
        (t, p) => *t = p,
    }
}

/// Parse a command-line `path=value` pair, typing the value from the schema:
/// `vlan=20` is a number, string fields stay strings, and lists or maps may
/// be given in YAML flow syntax (`members=[a, b]`).
pub fn parse_assignment(arg: &str) -> Result<(Vec<String>, Value), Error> {
    let (p, raw) = arg
        .split_once('=')
        .ok_or_else(|| Error::Path(format!("expected path=value, got {arg:?}")))?;
    let segs = parse_path(p.trim())?;
    let value = typed_value(&segs, raw)?;
    Ok((segs, value))
}

/// Convert a raw command-line string into the JSON type the schema expects.
pub fn typed_value<S: AsRef<str>>(path: &[S], raw: &str) -> Result<Value, Error> {
    let types = schema::types_at(path);
    let yaml = || -> Result<Value, Error> {
        if raw.trim().is_empty() {
            return Ok(Value::String(String::new()));
        }
        crate::parse_value(raw, crate::Format::Yaml)
    };
    // Only a string is acceptable: never let YAML turn "0042" into 42.
    if types.len() == 1 && types.contains("string") {
        return Ok(Value::String(raw.to_string()));
    }
    let parsed = match yaml() {
        Ok(v) => v,
        // Not valid YAML on its own (`@web`): take it as a plain string.
        Err(_) if types.is_empty() || types.contains("string") => {
            return Ok(Value::String(raw.to_string()));
        }
        Err(e) => return Err(e),
    };
    let kind = match &parsed {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    };
    if types.is_empty() || types.contains(kind) || (kind == "integer" && types.contains("number")) {
        return Ok(parsed);
    }
    if types.contains("string") {
        return Ok(Value::String(raw.to_string()));
    }
    Err(Error::Path(format!(
        "{}: expected {}, got {raw:?}",
        format_path(path),
        types.into_iter().collect::<Vec<_>>().join(" or ")
    )))
}
