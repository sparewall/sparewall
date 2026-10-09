//! The Sparewall configuration document: its model, JSON Schema, semantic
//! validation, canonical form and hash, and the merge, patch and path
//! operations the CLI and coordinator share.

pub mod identity;
pub mod model;
pub mod path;
pub mod schema;
pub mod topology;
pub mod validate;

use serde_json::Value;
use sha2::{Digest, Sha256};

pub use model::{Document, SCHEMA_VERSION};
pub use validate::{Issue, Severity, validate};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot parse {format}: {message}")]
    Parse { format: Format, message: String },
    #[error("{path}: {message}")]
    Type { path: String, message: String },
    #[error("{0}")]
    Patch(String),
    #[error("{0}")]
    Path(String),
}

/// Input or output format of a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Yaml,
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Format::Json => "JSON",
            Format::Yaml => "YAML",
        })
    }
}

impl Format {
    /// Guess the format from a file name, falling back to the content.
    pub fn detect(name: Option<&str>, text: &str) -> Format {
        match name.and_then(|n| n.rsplit_once('.')).map(|(_, ext)| ext) {
            Some("json") => Format::Json,
            Some("yaml" | "yml") => Format::Yaml,
            _ if text.trim_start().starts_with(['{', '[']) => Format::Json,
            _ => Format::Yaml,
        }
    }
}

/// Parse JSON or YAML 1.2 text into an untyped value.
pub fn parse_value(text: &str, format: Format) -> Result<Value, Error> {
    match format {
        Format::Json => serde_json::from_str(text).map_err(|e| Error::Parse {
            format,
            message: e.to_string(),
        }),
        Format::Yaml => {
            // YAML 1.2 core schema: only true/false are booleans, no legacy
            // octal, and a repeated key is an error rather than a silent win.
            let options = serde_saphyr::options! {
                strict_booleans: true,
                legacy_octal_numbers: false,
                duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
            };
            let v: Value =
                serde_saphyr::from_str_with_options(text, options).map_err(|e| Error::Parse {
                    format,
                    message: e.to_string(),
                })?;
            Ok(v)
        }
    }
}

/// Render a value as JSON (pretty) or YAML.
pub fn format_value<T: serde::Serialize>(value: &T, format: Format) -> String {
    match format {
        Format::Json => {
            let mut s = serde_json::to_string_pretty(value).expect("serializable");
            s.push('\n');
            s
        }
        Format::Yaml => serde_saphyr::to_string(value).expect("serializable"),
    }
}

/// Convert an untyped value into a typed document, reporting the path of the
/// first type error.
pub fn from_value(value: Value) -> Result<Document, Error> {
    serde_path_to_error::deserialize(value).map_err(|e| Error::Type {
        path: display_path(&e.path().to_string()),
        message: e.inner().to_string(),
    })
}

fn display_path(p: &str) -> String {
    if p == "." || p.is_empty() {
        "(document)".into()
    } else {
        p.to_string()
    }
}

/// Parse a document from text.
pub fn parse(text: &str, format: Format) -> Result<Document, Error> {
    from_value(parse_value(text, format)?)
}

/// The document as an untyped value in canonical form (defaults omitted).
pub fn to_value(doc: &Document) -> Value {
    serde_json::to_value(doc).expect("documents always serialize")
}

/// Canonical text form: fixed key order and formatting, so exported files
/// diff cleanly.
pub fn export(doc: &Document, format: Format) -> String {
    format_value(doc, format)
}

/// SHA-256 of the canonical compact JSON form, hex encoded. Equal content
/// always hashes equal, whatever the key order or format it arrived in.
pub fn hash(doc: &Document) -> String {
    let bytes = serde_json::to_vec(doc).expect("documents always serialize");
    hex::encode(Sha256::digest(&bytes))
}

/// Apply a JSON Merge Patch (RFC 7386) in place.
pub fn merge_patch(target: &mut Value, patch: &Value) {
    json_patch::merge(target, patch);
}

/// Apply RFC 6902 operations in place.
pub fn json_patch(target: &mut Value, ops: &Value) -> Result<(), Error> {
    let patch: json_patch::Patch =
        serde_json::from_value(ops.clone()).map_err(|e| Error::Patch(e.to_string()))?;
    json_patch::patch(target, &patch).map_err(|e| Error::Patch(e.to_string()))
}

/// A short, line-oriented summary of what changed between two documents,
/// one `+`, `-` or `~` line per changed leaf path.
pub fn diff_summary(old: &Value, new: &Value) -> Vec<String> {
    let mut out = Vec::new();
    diff_rec(&mut Vec::new(), old, new, &mut out);
    out
}

fn diff_rec(prefix: &mut Vec<String>, old: &Value, new: &Value, out: &mut Vec<String>) {
    match (old, new) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                prefix.push(k.clone());
                match (a.get(k), b.get(k)) {
                    (Some(x), Some(y)) => diff_rec(prefix, x, y, out),
                    (Some(_), None) => out.push(format!("- {}", path::format_path(prefix))),
                    (None, Some(y)) => {
                        out.push(format!("+ {} = {}", path::format_path(prefix), compact(y)))
                    }
                    (None, None) => unreachable!(),
                }
                prefix.pop();
            }
        }
        (a, b) if a == b => {}
        (_, b) => out.push(format!("~ {} = {}", path::format_path(prefix), compact(b))),
    }
}

fn compact(v: &Value) -> String {
    let s = v.to_string();
    if s.len() > 120 {
        format!("{}…", &s[..s.floor_char_boundary(117)])
    } else {
        s
    }
}

#[cfg(test)]
mod tests;
