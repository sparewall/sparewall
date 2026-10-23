//! The HTTP API's OpenAPI description, generated from the Varlink
//! interface descriptions (design: "Web UI and HTTP API").
//!
//! `sparewall-httpd` follows systemd's varlink-http-bridge: every method
//! is `POST /call/<interface>.<Method>` with its parameters as a JSON
//! object, and a method that streams replies (`[Requires 'more' flag]` or
//! `[Supports 'more' flag]` in its comments) answers `?more=true` with an
//! RFC 7464 JSON text sequence. Errors keep their Varlink name and
//! parameters, with the HTTP status from [`http_status`]. An error that
//! several interfaces list with the same parameters is one error, named
//! by the first interface listing it (the coordinator's errors are all
//! `org.sparewall.Firewall`'s).

use serde_json::{Map, Value, json};
use zlink::idl::{Comment, CustomType, Field, Interface, Method, Type};

/// The browser session cookie.
pub const SESSION_COOKIE: &str = "sparewall_session";
/// The header every cookie-authenticated request carries, which a
/// cross-site form cannot send.
pub const CSRF_HEADER: &str = "X-Sparewall-Request";

/// The gateway's own error, when the coordinator does not answer (502).
pub const UNAVAILABLE: &str = "org.sparewall.Httpd.Unavailable";

const REQUIRES_MORE: &str = "[Requires 'more' flag]";
const SUPPORTS_MORE: &str = "[Supports 'more' flag]";

/// The HTTP status for a Varlink error reply: its name, and its
/// parameters (a refusal with role `none` was not authenticated).
pub fn http_status(error: &str, parameters: &Value) -> u16 {
    match error.rsplit('.').next().unwrap_or_default() {
        "ValidationFailed" => 422,
        "Conflict" | "NotPending" | "ConfirmTimeout" => 409,
        "PermissionDenied" if parameters["role"] == "none" => 401,
        "PermissionDenied" => 403,
        "NotFound" | "MethodNotFound" | "InterfaceNotFound" => 404,
        "PeerUnreachable" => 503,
        _ if error == UNAVAILABLE => 502,
        "NotSupported" | "InvalidParameter" | "ExpectedMore" => 400,
        _ => 500,
    }
}

/// What the generator needs to know beyond the interfaces.
pub struct Options<'a> {
    /// `info.version`.
    pub version: &'a str,
    /// The role a method (`<interface>.<Method>`) needs: `None` leaves it
    /// out of the description, `Some("none")` needs no credentials.
    pub role: &'a dyn Fn(&str) -> Option<&'static str>,
    /// The configuration document's JSON Schema, as `Document`.
    pub document: Option<&'a Value>,
    /// Fields typed by a schema of their own: (method, field, schema), as
    /// a method's `config` by `Document`.
    pub fields: &'a [(&'a str, &'a str, &'a str)],
}

/// Build the description from Varlink IDL texts.
pub fn document(idls: &[&str], opts: &Options) -> Result<Value, String> {
    let mut paths = Map::new();
    let mut schemas = Map::new();
    let mut errors: Vec<(String, Value)> = vec![];
    let mut tags = vec![];
    for text in idls {
        let iface = Interface::try_from(*text).map_err(|e| format!("{e}"))?;
        let name = iface.name();
        // The service interface is not called over HTTP, but its errors
        // (MethodNotFound, InvalidParameter, ...) can answer any call.
        let service = name == "org.varlink.service";
        let mut used = service;
        for m in iface.methods().filter(|_| !service) {
            let full = format!("{name}.{}", m.name());
            let Some(role) = (opts.role)(&full) else {
                continue;
            };
            used = true;
            let mut op = operation(name, m, role);
            for (_, field, schema) in opts.fields.iter().filter(|(m, ..)| *m == full) {
                let r = json!({"$ref": format!("#/components/schemas/{schema}")});
                for ptr in [
                    "/requestBody/content/application~1json/schema/properties",
                    "/responses/200/content/application~1json/schema/properties",
                ] {
                    if let Some(f) = op.pointer_mut(ptr).and_then(|p| p.get_mut(*field)) {
                        *f = r.clone();
                    }
                }
            }
            paths.insert(format!("/call/{full}"), json!({"post": op}));
        }
        if !used {
            continue;
        }
        if !service {
            let mut tag = json!({"name": name});
            describe(&mut tag, comments(iface.comments()));
            tags.push(tag);
        }
        for t in iface.custom_types() {
            schemas.insert(format!("{name}.{}", t.name()), custom_type(name, t));
        }
        for e in iface.errors() {
            let mut s = object(name, e.fields());
            describe(&mut s, comments(e.comments()));
            // One error type serves several interfaces under the name of
            // the one it belongs to, while each interface's description
            // lists it as its own: keep the first.
            let same = |(n, p): &(String, Value)| n.rsplit('.').next() == Some(e.name()) && *p == s;
            if !errors.iter().any(same) {
                errors.push((format!("{name}.{}", e.name()), s));
            }
        }
    }
    if let Some(d) = opts.document {
        hoist(d, &mut schemas);
    }
    errors.push((
        UNAVAILABLE.into(),
        json!({
            "type": "object",
            "description": "The coordinator did not answer the gateway.",
        }),
    ));
    errors.sort_by(|a, b| a.0.cmp(&b.0));
    let names: Vec<&String> = errors.iter().map(|(n, _)| n).collect();
    let variants: Vec<Value> = errors
        .iter()
        .map(|(n, params)| {
            json!({
                "type": "object",
                "title": n,
                "required": ["error", "parameters"],
                "properties": {
                    "error": {"const": n},
                    "parameters": params,
                    "message": {"type": "string"},
                },
            })
        })
        .collect();
    schemas.insert(
        "Error".into(),
        json!({
            "description": "A Varlink error: its name and parameters, and a message in words. \
                            The HTTP status follows the error (422 ValidationFailed, 409 \
                            Conflict, NotPending and ConfirmTimeout, 401 PermissionDenied \
                            without credentials and 403 with them, 404 NotFound, \
                            MethodNotFound and InterfaceNotFound, 503 PeerUnreachable, 502 \
                            Unavailable, 400 NotSupported, InvalidParameter and malformed \
                            calls, 500 the rest).",
            "type": "object",
            "required": ["error"],
            "properties": {
                "error": {"type": "string", "enum": names},
                "parameters": {"type": "object"},
                "message": {"type": "string"},
            },
            "oneOf": variants,
        }),
    );
    Ok(json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Sparewall",
            "version": opts.version,
            "description": "The Sparewall coordinator's Varlink interfaces over HTTPS, as \
                            sparewall-httpd serves them. Each call is checked against the \
                            role of the caller's API token or session (x-sparewall-role).",
            "license": {"name": "GPL-3.0-only", "identifier": "GPL-3.0-only"},
        },
        "tags": tags,
        "paths": paths,
        "components": {
            "schemas": schemas,
            "securitySchemes": {
                "token": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "An API token (`sparewall token create`).",
                },
                "session": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": SESSION_COOKIE,
                    "description": format!(
                        "A browser session from org.sparewall.Auth.Login. Requests \
                         with it must also carry the {CSRF_HEADER} header."
                    ),
                },
            },
            "responses": {
                "Error": {
                    "description": "The call failed.",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                },
            },
        },
        "security": [{"token": []}, {"session": []}],
    }))
}

/// Add a JSON Schema as `Document`, its definitions as `Document.<name>`.
fn hoist(doc: &Value, schemas: &mut Map<String, Value>) {
    fn rewrite(v: &mut Value) {
        match v {
            Value::Object(m) => {
                if let Some(Value::String(r)) = m.get_mut("$ref")
                    && let Some(name) = r.strip_prefix("#/$defs/")
                {
                    *r = format!("#/components/schemas/Document.{name}");
                }
                m.values_mut().for_each(rewrite);
            }
            Value::Array(a) => a.iter_mut().for_each(rewrite),
            _ => {}
        }
    }
    let mut root = doc.clone();
    let Value::Object(m) = &mut root else {
        return;
    };
    m.remove("$schema");
    m.remove("$id");
    if let Some(Value::Object(defs)) = m.remove("$defs") {
        for (name, mut d) in defs {
            rewrite(&mut d);
            schemas.insert(format!("Document.{name}"), d);
        }
    }
    rewrite(&mut root);
    schemas.insert("Document".into(), root);
}

fn operation(iface: &str, m: &Method, role: &str) -> Value {
    let short = iface.rsplit('.').next().unwrap_or(iface);
    let (desc, more) = method_comments(m);
    let reply = object(iface, m.outputs());
    let mut content = Map::new();
    content.insert("application/json".into(), json!({"schema": reply}));
    let mut op = json!({
        "operationId": format!("{short}.{}", m.name()),
        "tags": [iface],
        "x-sparewall-role": role,
        "requestBody": {
            "required": false,
            "content": {"application/json": {"schema": object(iface, m.inputs())}},
        },
        "responses": {
            "200": {"description": "The reply.", "content": content},
            "default": {"$ref": "#/components/responses/Error"},
        },
    });
    if let Some(d) = desc {
        let para = d.split("\n\n").next().unwrap_or_default();
        let first = para.split_inclusive(". ").next().unwrap_or_default();
        op["summary"] = json!(first.trim());
        op["description"] = json!(d);
    }
    if more != More::No {
        op["parameters"] = json!([{
            "name": "more",
            "in": "query",
            "required": more == More::Required,
            "schema": {"type": "boolean"},
            "description": "Stream replies as an RFC 7464 JSON text sequence \
                            (application/json-seq) until the connection closes.",
        }]);
        op["responses"]["200"]["content"]["application/json-seq"] = json!({"schema": reply});
    }
    if role == "none" {
        op["security"] = json!([]);
    }
    op
}

#[derive(PartialEq)]
enum More {
    No,
    Supported,
    Required,
}

fn method_comments(m: &Method) -> (Option<String>, More) {
    let mut more = More::No;
    let lines: Vec<&str> = m
        .comments()
        .map(Comment::text)
        .filter(|c| match c.trim() {
            REQUIRES_MORE => {
                more = More::Required;
                false
            }
            SUPPORTS_MORE => {
                more = More::Supported;
                false
            }
            _ => true,
        })
        .collect();
    (join(&lines), more)
}

fn comments<'a>(c: impl Iterator<Item = &'a Comment<'a>>) -> Option<String> {
    join(&c.map(Comment::text).collect::<Vec<_>>())
}

/// Comment lines as prose: lines joined, blank lines kept as breaks.
fn join(lines: &[&str]) -> Option<String> {
    let text = lines
        .iter()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join("\n")
        .replace("\n\n", "\u{0}")
        .replace('\n', " ")
        .replace('\u{0}', "\n\n");
    (!text.trim().is_empty()).then(|| text.trim().to_string())
}

fn describe(schema: &mut Value, desc: Option<String>) {
    if let Some(d) = desc {
        schema["description"] = json!(d);
    }
}

fn object<'a>(iface: &str, fields: impl Iterator<Item = &'a Field<'a>>) -> Value {
    let mut props = Map::new();
    let mut required = vec![];
    for f in fields {
        let mut s = schema(iface, f.ty());
        describe(&mut s, comments(f.comments()));
        if !matches!(f.ty(), Type::Optional(_)) {
            required.push(f.name());
        }
        props.insert(f.name().to_string(), s);
    }
    let mut o = json!({"type": "object", "properties": props, "additionalProperties": false});
    if !required.is_empty() {
        o["required"] = json!(required);
    }
    o
}

fn schema(iface: &str, ty: &Type) -> Value {
    match ty {
        Type::Bool => json!({"type": "boolean"}),
        Type::Int => json!({"type": "integer", "format": "int64"}),
        Type::Float => json!({"type": "number"}),
        Type::String => json!({"type": "string"}),
        Type::ForeignObject => json!({"type": "object"}),
        Type::Any => json!({}),
        Type::Optional(t) => {
            let inner = schema(iface, t.inner());
            match inner.get("type").and_then(Value::as_str) {
                Some(t) if inner.get("$ref").is_none() => {
                    let mut v = inner.clone();
                    v["type"] = json!([t, "null"]);
                    v
                }
                _ => json!({"anyOf": [inner, {"type": "null"}]}),
            }
        }
        Type::Array(t) => json!({"type": "array", "items": schema(iface, t.inner())}),
        Type::Map(t) => json!({"type": "object", "additionalProperties": schema(iface, t.inner())}),
        Type::Custom(n) => json!({"$ref": format!("#/components/schemas/{iface}.{n}")}),
        Type::Enum(vs) => {
            json!({"type": "string", "enum": vs.iter().map(|v| v.name()).collect::<Vec<_>>()})
        }
        Type::Object(fs) => object(iface, fs.iter()),
    }
}

fn custom_type(iface: &str, t: &CustomType) -> Value {
    match t {
        CustomType::Object(o) => {
            let mut s = object(iface, o.fields());
            describe(&mut s, comments(o.comments()));
            s
        }
        CustomType::Enum(e) => {
            let mut s = json!({"type": "string", "enum": e.variants().map(|v| v.name()).collect::<Vec<_>>()});
            describe(&mut s, comments(e.comments()));
            s
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDL: &str = "\
# A test interface.
interface org.example.Test

# A thing.
type Thing (name: string, # Its size.
size: ?int, tags: [string]bool)

# Get things.
#
# All of them.
method Get(prefix: ?string) -> (things: []Thing)

# [Requires 'more' flag]
method Watch() -> (event: object)

method Secret() -> ()

error Gone (id: int)
";

    const OTHER: &str = "\
interface org.example.Other

method Ping() -> ()

error Gone (id: int)

error Lost ()
";

    const SERVICE: &str = "\
interface org.varlink.service

method GetInfo() -> (vendor: string)

error MethodNotFound (method: string)
";

    fn doc() -> Value {
        let role = |m: &str| match m {
            "org.example.Test.Get" => Some("viewer"),
            "org.example.Test.Watch" => Some("none"),
            _ => None,
        };
        let role = |m: &str| role(m).or((m == "org.example.Other.Ping").then_some("viewer"));
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://example.org/doc.json",
            "type": "object",
            "properties": {"thing": {"$ref": "#/$defs/Part"}},
            "$defs": {
                "Part": {"type": "object", "properties": {"sub": {"$ref": "#/$defs/Sub"}}},
                "Sub": {"type": "string"},
            },
        });
        document(
            &[SERVICE, IDL, OTHER],
            &Options {
                version: "0",
                role: &role,
                document: Some(&schema),
                fields: &[("org.example.Test.Watch", "event", "Document")],
            },
        )
        .unwrap()
    }

    #[test]
    fn methods_become_calls() {
        let d = doc();
        let get = &d["paths"]["/call/org.example.Test.Get"]["post"];
        assert_eq!(get["operationId"], "Test.Get");
        assert_eq!(get["x-sparewall-role"], "viewer");
        assert_eq!(get["summary"], "Get things.");
        assert_eq!(get["description"], "Get things.\n\nAll of them.");
        let body = &get["requestBody"]["content"]["application/json"]["schema"];
        assert_eq!(
            body["properties"]["prefix"]["type"],
            json!(["string", "null"])
        );
        assert!(body.get("required").is_none());
        let reply = &get["responses"]["200"]["content"]["application/json"]["schema"];
        assert_eq!(
            reply["properties"]["things"]["items"]["$ref"],
            "#/components/schemas/org.example.Test.Thing"
        );
        assert!(
            d["paths"].get("/call/org.example.Test.Secret").is_none(),
            "a method without a role is left out"
        );
    }

    #[test]
    fn types_errors_and_streams() {
        let d = doc();
        let thing = &d["components"]["schemas"]["org.example.Test.Thing"];
        assert_eq!(thing["description"], "A thing.");
        assert_eq!(thing["required"], json!(["name", "tags"]));
        assert_eq!(thing["properties"]["size"]["description"], "Its size.");
        assert_eq!(
            thing["properties"]["tags"]["additionalProperties"]["type"],
            "boolean"
        );
        let err = &d["components"]["schemas"]["Error"];
        assert_eq!(
            err["properties"]["error"]["enum"],
            json!([
                "org.example.Other.Lost",
                "org.example.Test.Gone",
                UNAVAILABLE,
                "org.varlink.service.MethodNotFound"
            ])
        );
        assert!(
            d["paths"]
                .get("/call/org.varlink.service.GetInfo")
                .is_none()
                && d["tags"].as_array().unwrap().len() == 2,
            "the service interface is not called over HTTP"
        );
        let watch = &d["paths"]["/call/org.example.Test.Watch"]["post"];
        assert_eq!(watch["security"], json!([]));
        assert_eq!(watch["parameters"][0]["name"], "more");
        assert_eq!(watch["parameters"][0]["required"], true);
        assert!(watch["responses"]["200"]["content"]["application/json-seq"].is_object());
        assert!(
            watch.get("description").is_none(),
            "the marker is not prose"
        );
    }

    #[test]
    fn the_document_schema_is_a_component() {
        let d = doc();
        let s = &d["components"]["schemas"];
        assert_eq!(
            s["Document"]["properties"]["thing"]["$ref"],
            "#/components/schemas/Document.Part"
        );
        assert_eq!(
            s["Document.Part"]["properties"]["sub"]["$ref"],
            "#/components/schemas/Document.Sub"
        );
        assert!(s["Document"].get("$defs").is_none() && s["Document"].get("$id").is_none());
        let watch = &d["paths"]["/call/org.example.Test.Watch"]["post"];
        assert_eq!(
            watch["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["event"]
                ["$ref"],
            "#/components/schemas/Document"
        );
    }

    #[test]
    fn statuses() {
        let none = json!({"role": "none"});
        let viewer = json!({"role": "viewer"});
        let e = |n: &str| format!("org.sparewall.Firewall.{n}");
        assert_eq!(http_status(&e("PermissionDenied"), &none), 401);
        assert_eq!(http_status(&e("PermissionDenied"), &viewer), 403);
        assert_eq!(http_status(&e("ValidationFailed"), &Value::Null), 422);
        assert_eq!(http_status(&e("Conflict"), &Value::Null), 409);
        assert_eq!(http_status(&e("ApplyFailed"), &Value::Null), 500);
        assert_eq!(
            http_status("org.varlink.service.MethodNotFound", &Value::Null),
            404
        );
        assert_eq!(http_status(UNAVAILABLE, &Value::Null), 502);
    }
}
