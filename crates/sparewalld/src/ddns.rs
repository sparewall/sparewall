//! Dynamic DNS (#316): keep each `dns.dynamic` entry's names at the
//! site's public address, speaking each provider's protocol here.
//!
//! - **Who:** a standalone node, or a pair's master. The backup sends
//!   nothing. A node that takes over (or restarts as the master) sends
//!   once, since it can't know what the peer sent meanwhile.
//! - **When:** each round reads the WAN's address (or asks `discover`);
//!   an entry is sent when its address differs from what the provider
//!   last accepted. A keepalived transition, a lease change or an apply
//!   starts a round at once. Hourly, Cloudflare's records are read back,
//!   and the other providers' names are looked up, so a record changed
//!   elsewhere is put right; an unchanged address is sent again weekly.
//! - **Rate:** at most one update a minute per entry; after a failure, 5
//!   minutes, doubling to an hour. An answer that says retrying can't help
//!   (bad credentials, an unknown name, `abuse`) stops the entry until its
//!   settings or its secret change, across restarts too, as the DynDNS2
//!   protocol asks of clients.
//! - **Health:** `ddns` degrades for a failed or stopped entry, a WAN
//!   address that isn't public (behind NAT: set `discover`), or a record
//!   that doesn't match.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sparewall_config::Document;
use sparewall_config::model::{DynamicDns, NetworkRole};
use sparewall_core::{Check, Level};
use tokio::sync::broadcast;

use crate::peer::Pair;
use crate::service::{Core, with_core_raw};

const ROUND: Duration = Duration::from_secs(60);
const DISCOVER_EVERY: Duration = Duration::from_secs(300);
const VERIFY_EVERY: Duration = Duration::from_secs(3600);
/// An unchanged address is sent again this often (DynDNS2 services drop
/// names nobody updates; more often counts as abuse at some).
const RESEND_SECS: i64 = 7 * 86_400;
const MIN_GAP: Duration = Duration::from_secs(60);
const RETRY_FIRST: Duration = Duration::from_secs(300);
const RETRY_MAX: Duration = Duration::from_secs(3600);
const TIMEOUT: Duration = Duration::from_secs(30);
const STATE_FILE: &str = "ddns.json";
const CLOUDFLARE: &str = "https://api.cloudflare.com/client/v4";
const DUCKDNS: &str = "https://www.duckdns.org";

/// The addresses an entry's names get.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addrs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v4: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6: Option<Ipv6Addr>,
}

/// What a provider last accepted for an entry, kept across restarts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Sent {
    /// The entry's settings, as sent: a change sends again.
    key: String,
    addrs: Addrs,
    at: i64,
}

/// An entry stopped by an answer retrying can't fix, kept across
/// restarts so a known-bad request isn't sent again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Stopped {
    /// The entry's settings and a digest of its credentials when it
    /// stopped ([`stop_key`]): a change to either starts it again.
    key: String,
    message: String,
}

/// The state file.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Kept {
    #[serde(default)]
    sent: BTreeMap<String, Sent>,
    #[serde(default)]
    stopped: BTreeMap<String, Stopped>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Fail {
    /// Worth trying again later.
    Retry(String),
    /// Retrying can't help until the settings change.
    Stop(String),
}

impl Fail {
    fn message(&self) -> &str {
        match self {
            Fail::Retry(m) | Fail::Stop(m) => m,
        }
    }
}

/// One HTTP exchange; the status and the body. Redirects are not
/// followed: an update service has no business sending credentials on.
pub trait Http {
    fn call(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, String)],
        body: Option<String>,
    ) -> impl Future<Output = Result<(u16, String), String>> + Send;
}

pub struct Hyper;

impl Http for Hyper {
    async fn call(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, String)],
        body: Option<String>,
    ) -> Result<(u16, String), String> {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| format!("no trusted certificates: {e}"))?
            .https_or_http()
            .enable_http1()
            .build();
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
        let mut req = hyper::Request::builder().method(method).uri(url).header(
            hyper::header::USER_AGENT,
            format!("sparewall/{}", sparewall_core::VERSION),
        );
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        let req = req
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|e| e.to_string())?;
        let resp = tokio::time::timeout(TIMEOUT, client.request(req))
            .await
            .map_err(|_| "timed out".to_string())?
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body = tokio::time::timeout(TIMEOUT, Limited::new(resp.into_body(), 1 << 20).collect())
            .await
            .map_err(|_| "timed out".to_string())?
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok((status, String::from_utf8_lossy(&body).into_owned()))
    }
}

/// Percent-encode a query value.
fn q(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

fn cred<'a>(creds: &'a [(String, String)], keys: &[&str]) -> Result<&'a str, Fail> {
    creds
        .iter()
        .find(|(k, _)| keys.contains(&k.as_str()))
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| Fail::Stop(format!("the credentials have no {}", keys[0])))
}

fn redirected(status: u16) -> Option<Fail> {
    (300..400).contains(&status).then(|| {
        Fail::Stop(format!(
            "the service answered {status}, a redirect, which updates never follow: check the URL"
        ))
    })
}

/// DynDNS2: one GET for every name, one answer line per name.
pub async fn dyndns2<H: Http>(
    http: &H,
    server: &str,
    creds: &[(String, String)],
    names: &[String],
    a: Addrs,
) -> Result<(), Fail> {
    let user = cred(creds, &["DYNDNS2_USERNAME"])?;
    let pass = cred(creds, &["DYNDNS2_PASSWORD"])?;
    let mut ips: Vec<String> = a.v4.iter().map(ToString::to_string).collect();
    ips.extend(a.v6.iter().map(ToString::to_string));
    let sep = if server.contains('?') { '&' } else { '?' };
    let url = format!(
        "{server}{sep}hostname={}&myip={}",
        q(&names.join(",")),
        q(&ips.join(","))
    );
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    let (status, body) = http
        .call(
            "GET",
            &url,
            &[("authorization", format!("Basic {auth}"))],
            None,
        )
        .await
        .map_err(Fail::Retry)?;
    if let Some(f) = redirected(status) {
        return Err(f);
    }
    if status == 401 || status == 403 {
        return Err(Fail::Stop(format!(
            "{status}: the service refused the credentials"
        )));
    }
    if !(200..300).contains(&status) {
        return Err(Fail::Retry(format!("the service answered {status}")));
    }
    let lines: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return Err(Fail::Retry("an empty answer".into()));
    }
    for (i, l) in lines.iter().enumerate() {
        let code = l.split_whitespace().next().unwrap_or_default();
        let name = names.get(i).map_or("", String::as_str);
        match code {
            "good" | "nochg" => {}
            "badauth" | "!donator" | "notfqdn" | "nohost" | "numhost" | "abuse" | "badagent"
            | "!yours" | "badsys" | "nochglimit" => {
                return Err(Fail::Stop(format!("{name}: {l}")));
            }
            _ => return Err(Fail::Retry(format!("{name}: {l}"))),
        }
    }
    Ok(())
}

/// DuckDNS: one GET for every name; `OK` or `KO`.
pub async fn duckdns<H: Http>(
    http: &H,
    server: &str,
    creds: &[(String, String)],
    names: &[String],
    a: Addrs,
) -> Result<(), Fail> {
    let token = cred(creds, &["DUCKDNS_TOKEN"])?;
    let domains: Vec<String> = names
        .iter()
        .map(|n| {
            let n = sparewall_config::filters::normalize(n);
            n.strip_suffix(".duckdns.org").unwrap_or(&n).to_string()
        })
        .collect();
    let mut url = format!(
        "{}/update?domains={}&token={}",
        server.trim_end_matches('/'),
        q(&domains.join(",")),
        q(token)
    );
    if let Some(v4) = a.v4 {
        url.push_str(&format!("&ip={v4}"));
    }
    if let Some(v6) = a.v6 {
        url.push_str(&format!("&ipv6={}", q(&v6.to_string())));
    }
    let (status, body) = http
        .call("GET", &url, &[], None)
        .await
        .map_err(Fail::Retry)?;
    if let Some(f) = redirected(status) {
        return Err(f);
    }
    if !(200..300).contains(&status) {
        return Err(Fail::Retry(format!("DuckDNS answered {status}")));
    }
    match body.trim() {
        "OK" => Ok(()),
        "KO" => Err(Fail::Stop(
            "DuckDNS refused the update: check the token and the names".into(),
        )),
        other => Err(Fail::Retry(format!("DuckDNS answered {other:?}"))),
    }
}

async fn cf_call<H: Http>(
    http: &H,
    token: &str,
    method: &str,
    url: &str,
    body: Option<Value>,
) -> Result<Value, Fail> {
    let mut headers = vec![("authorization", format!("Bearer {token}"))];
    if body.is_some() {
        headers.push(("content-type", "application/json".into()));
    }
    let (status, text) = http
        .call(method, url, &headers, body.map(|b| b.to_string()))
        .await
        .map_err(Fail::Retry)?;
    if let Some(f) = redirected(status) {
        return Err(f);
    }
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let why = v["errors"][0]["message"]
        .as_str()
        .map(|m| format!(": {m}"))
        .unwrap_or_default();
    match status {
        200..300 if v["success"] == true => Ok(v),
        401 | 403 => Err(Fail::Stop(format!(
            "Cloudflare refused the token ({status}{why}): it needs Zone:DNS:Edit on the zone"
        ))),
        429 | 500.. => Err(Fail::Retry(format!("Cloudflare answered {status}{why}"))),
        _ => Err(Fail::Stop(format!("Cloudflare answered {status}{why}"))),
    }
}

/// The zone a name is in: `zone` if set, else the longest of the name's
/// suffixes Cloudflare has.
async fn cf_zone<H: Http>(
    http: &H,
    base: &str,
    token: &str,
    zone: Option<&str>,
    name: &str,
) -> Result<String, Fail> {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    let tries: Vec<String> = match zone {
        Some(z) => vec![z.trim_end_matches('.').to_string()],
        None => (0..labels.len().saturating_sub(1))
            .map(|i| labels[i..].join("."))
            .collect(),
    };
    for z in &tries {
        let v = cf_call(
            http,
            token,
            "GET",
            &format!("{base}/zones?name={}", q(z)),
            None,
        )
        .await?;
        if let Some(id) = v["result"][0]["id"].as_str() {
            return Ok(id.to_string());
        }
    }
    Err(Fail::Stop(format!(
        "no Cloudflare zone holds {name} that the token can see"
    )))
}

/// Cloudflare: read each name's records, and change only those that
/// differ (creating one where there is none). Reading first makes this
/// the hourly check as well.
pub async fn cloudflare<H: Http>(
    http: &H,
    base: &str,
    zone: Option<&str>,
    creds: &[(String, String)],
    names: &[String],
    a: Addrs,
) -> Result<bool, Fail> {
    let token = cred(creds, &["CF_DNS_API_TOKEN", "CLOUDFLARE_DNS_API_TOKEN"])?;
    let base = base.trim_end_matches('/');
    let mut zones: BTreeMap<String, String> = BTreeMap::new();
    let mut changed = false;
    for name in names {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let key = zone.map_or_else(|| name.clone(), str::to_string);
        let id = match zones.get(&key) {
            Some(id) => id.clone(),
            None => {
                let id = cf_zone(http, base, token, zone, &name).await?;
                zones.insert(key, id.clone());
                id
            }
        };
        let wanted = [
            ("A", a.v4.map(|x| x.to_string())),
            ("AAAA", a.v6.map(|x| x.to_string())),
        ];
        for (kind, addr) in wanted {
            let Some(addr) = addr else { continue };
            let list = cf_call(
                http,
                token,
                "GET",
                &format!(
                    "{base}/zones/{id}/dns_records?type={kind}&name={}",
                    q(&name)
                ),
                None,
            )
            .await?;
            let records = list["result"].as_array().cloned().unwrap_or_default();
            if records.is_empty() {
                cf_call(
                    http,
                    token,
                    "POST",
                    &format!("{base}/zones/{id}/dns_records"),
                    Some(json!({"type": kind, "name": name, "content": addr, "ttl": 60, "proxied": false})),
                )
                .await?;
                changed = true;
            }
            for r in records {
                if r["content"].as_str() == Some(addr.as_str()) {
                    continue;
                }
                let rid = r["id"].as_str().unwrap_or_default();
                cf_call(
                    http,
                    token,
                    "PATCH",
                    &format!("{base}/zones/{id}/dns_records/{rid}"),
                    Some(json!({"content": addr})),
                )
                .await?;
                changed = true;
            }
        }
    }
    Ok(changed)
}

/// The WAN network an entry publishes.
fn wan_of<'a>(doc: &'a Document, x: &'a DynamicDns) -> Option<&'a str> {
    match &x.network {
        Some(n) => Some(n.as_str()),
        None => {
            let mut w = doc
                .networks
                .iter()
                .filter(|(_, n)| n.role == NetworkRole::Wan)
                .map(|(k, _)| k.as_str());
            let first = w.next();
            w.next().is_none().then_some(first).flatten()
        }
    }
}

/// The WAN's public IPv4 address: its gateway address, a static node
/// address, or what DHCP gave the interface.
pub fn wan_v4(
    doc: &Document,
    node: &str,
    network: &str,
    on_iface: &[Ipv4Addr],
) -> Option<Ipv4Addr> {
    let net = doc.networks.get(network)?;
    if let Some(vip) = net.vip {
        return Some(vip.0.addr());
    }
    if !net.dhcp_client
        && let Some(a) = net.addresses.get(node)
    {
        return Some(a.0.addr());
    }
    on_iface.first().copied()
}

/// Whether an address is one the internet can reach.
pub fn public_v4(a: Ipv4Addr) -> bool {
    let shared = ipnet::Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10).expect("net");
    !(a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_unspecified()
        || shared.contains(&a))
}

/// An interface's global IPv4 addresses.
async fn iface_v4(iface: &str) -> Vec<Ipv4Addr> {
    let Ok(out) = tokio::process::Command::new("ip")
        .args(["-j", "-4", "addr", "show", "dev", iface, "scope", "global"])
        .output()
        .await
    else {
        return vec![];
    };
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    v.get(0)
        .and_then(|l| l["addr_info"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|a| a["local"].as_str()?.parse().ok())
        .collect()
}

/// The first global IPv6 address still preferred, of the first interface
/// that has one.
fn wan_v6(
    links: &BTreeMap<String, sparewall_core::ipv6::LinkIpv6>,
    ifaces: &[&str],
) -> Option<Ipv6Addr> {
    ifaces.iter().find_map(|i| {
        links.get(*i)?.addresses.iter().find_map(|a| {
            if a.preferred_seconds == Some(0) {
                return None;
            }
            a.address.split('/').next()?.parse().ok()
        })
    })
}

/// The IPv4 address a lookup service says this site has.
async fn discover<H: Http>(http: &H, url: &str) -> Result<Ipv4Addr, String> {
    let (status, body) = http.call("GET", url, &[], None).await?;
    if !(200..300).contains(&status) {
        return Err(format!("{url} answered {status}"));
    }
    body.trim().parse().map_err(|_| {
        format!(
            "{url} answered {:?}, not an IPv4 address",
            body.trim().chars().take(40).collect::<String>()
        )
    })
}

/// What the world's DNS has for a name, by the node's resolver.
async fn looked_up(name: &str) -> Option<Vec<IpAddr>> {
    let r = tokio::time::timeout(TIMEOUT, tokio::net::lookup_host((name, 0)))
        .await
        .ok()?
        .ok()?;
    Some(r.map(|s| s.ip()).collect())
}

/// Whether the names resolve to something other than `a` (`None` when
/// that can't be told).
async fn mismatch(names: &[String], a: Addrs) -> Option<String> {
    for n in names {
        let Some(ips) = looked_up(n).await else {
            continue;
        };
        if let Some(m) = differs(n, &ips, a) {
            return Some(m);
        }
    }
    None
}

/// Whether what a name resolves to differs from what it should have, in
/// each family it should have an address in: a missing A or AAAA record
/// counts, once the name resolves at all. No answer says nothing: the
/// name may not have reached the resolvers yet.
fn differs(name: &str, ips: &[IpAddr], a: Addrs) -> Option<String> {
    if ips.is_empty() {
        return None;
    }
    let want = [a.v4.map(IpAddr::V4), a.v6.map(IpAddr::V6)];
    for w in want.into_iter().flatten() {
        let same: Vec<&IpAddr> = ips.iter().filter(|i| i.is_ipv4() == w.is_ipv4()).collect();
        if same.is_empty() {
            let kind = if w.is_ipv4() { "A" } else { "AAAA" };
            return Some(format!("{name} has no {kind} record, not {w}"));
        }
        if !same.contains(&&w) {
            return Some(format!("{name} resolves to {}, not {w}", same[0]));
        }
    }
    None
}

struct Entry {
    key: String,
    next_try: Instant,
    backoff: Duration,
    stopped: Option<String>,
    error: Option<String>,
    verified: Option<Instant>,
    mismatch: Option<String>,
}

impl Entry {
    fn new(key: String) -> Self {
        Entry {
            key,
            next_try: Instant::now(),
            backoff: RETRY_FIRST,
            stopped: None,
            error: None,
            verified: None,
            mismatch: None,
        }
    }
}

static CURRENT: Mutex<Option<Value>> = Mutex::new(None);

/// The `dynamic_dns` object of the status reply: each entry's names,
/// address and last update. `None` without entries.
pub fn status() -> Option<Value> {
    CURRENT.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn load(path: &Path) -> Kept {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn key_of(x: &DynamicDns) -> String {
    serde_json::to_string(x).unwrap_or_default()
}

/// What a stop is keyed by: the entry's settings, and a digest of the
/// secret its credentials reference (never the secret itself).
async fn stop_key(
    core: &Core,
    events: &broadcast::Sender<Value>,
    x: &DynamicDns,
    key: &str,
) -> String {
    let name = x
        .credentials
        .strip_prefix("secret:")
        .unwrap_or_default()
        .to_string();
    let secret = with_core_raw(core, events, move |c| c.secret_get(&name))
        .await
        .ok()
        .flatten();
    stop_key_of(key, secret.as_deref())
}

fn stop_key_of(key: &str, secret: Option<&[u8]>) -> String {
    use sha2::Digest;
    let d = match secret {
        Some(s) => hex::encode(&sha2::Sha256::digest(s)[..16]),
        None => "unset".into(),
    };
    format!("{key}#{d}")
}

async fn update(
    core: &Core,
    events: &broadcast::Sender<Value>,
    x: &DynamicDns,
    a: Addrs,
) -> Result<bool, Fail> {
    let name = x
        .credentials
        .strip_prefix("secret:")
        .ok_or_else(|| Fail::Stop("credentials are not a secret:<name> reference".into()))?
        .to_string();
    let raw = with_core_raw(core, events, {
        let name = name.clone();
        move |c| c.secret_get(&name)
    })
    .await
    .map_err(|e| Fail::Retry(e.to_string()))?
    .ok_or_else(|| Fail::Stop(format!("secret {name} is not set")))?;
    let creds = crate::backup::credentials_env(
        &format!("the {} credentials", x.credentials),
        &String::from_utf8_lossy(&raw),
    )
    .map_err(Fail::Stop)?;
    let server = x.options.get("server").map(String::as_str);
    match x.provider.as_str() {
        "dyndns2" => {
            let server = server.ok_or_else(|| Fail::Stop("dyndns2 needs options.server".into()))?;
            dyndns2(&Hyper, server, &creds, &x.names, a)
                .await
                .map(|()| true)
        }
        "duckdns" => duckdns(&Hyper, server.unwrap_or(DUCKDNS), &creds, &x.names, a)
            .await
            .map(|()| true),
        "cloudflare" => {
            cloudflare(
                &Hyper,
                server.unwrap_or(CLOUDFLARE),
                x.options.get("zone").map(String::as_str),
                &creds,
                &x.names,
                a,
            )
            .await
        }
        p => Err(Fail::Stop(format!("unknown provider {p:?}"))),
    }
}

pub async fn ddns_loop(core: Core, events: broadcast::Sender<Value>, pair: Pair, state: PathBuf) {
    let path = state.join(STATE_FILE);
    let Kept {
        mut sent,
        mut stopped,
    } = load(&path);
    let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
    let mut discovered: BTreeMap<String, (Instant, Result<Ipv4Addr, String>)> = BTreeMap::new();
    let mut rx = events.subscribe();
    let mut was_active = false;
    loop {
        let got = with_core_raw(&core, &events, |c| {
            let doc = c.active_document()?;
            let links = if doc
                .as_ref()
                .is_some_and(|d| d.routes_ipv6() || d.networks.values().any(|n| n.ipv6.is_some()))
            {
                c.system().ipv6_links()
            } else {
                BTreeMap::new()
            };
            Ok((doc, c.node().to_string(), links))
        })
        .await;
        let (doc, node, links) = got.unwrap_or_default();
        let wanted: BTreeMap<String, DynamicDns> = doc
            .as_ref()
            .and_then(|d| d.dns.as_ref())
            .map(|d| d.dynamic.clone())
            .unwrap_or_default();
        entries.retain(|k, _| wanted.contains_key(k));
        let before = sent.len();
        sent.retain(|k, _| wanted.contains_key(k));
        let before_stopped = stopped.len();
        stopped.retain(|k, _| wanted.contains_key(k));
        let mut dirty = sent.len() != before || stopped.len() != before_stopped;
        let active = doc.as_ref().is_some_and(|d| !d.is_pair())
            || pair
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .role
                .as_deref()
                == Some("MASTER");
        // Taking over in a pair: the provider may have had the peer's
        // updates since this node last sent, so what it sent then counts
        // for nothing.
        if active && !was_active && doc.as_ref().is_some_and(Document::is_pair) && !sent.is_empty()
        {
            sent.clear();
            dirty = true;
        }
        was_active = active;
        let mut problems: Vec<String> = Vec::new();
        let mut shown = serde_json::Map::new();
        for (e, x) in &wanted {
            let key = key_of(x);
            let entry = entries
                .entry(e.clone())
                .or_insert_with(|| Entry::new(key.clone()));
            if entry.key != key {
                *entry = Entry::new(key.clone());
            }
            // A stop holds while the settings and the credentials are
            // what they were; a new secret starts the entry again.
            if let Some(st) = stopped.get(e) {
                if st.key == stop_key(&core, &events, x, &key).await {
                    entry.stopped = Some(st.message.clone());
                } else {
                    stopped.remove(e);
                    dirty = true;
                    *entry = Entry::new(key.clone());
                }
            }
            let mut want = Addrs::default();
            let mut notes: Vec<String> = Vec::new();
            if active && let Some(d) = &doc {
                let net = wan_of(d, x);
                let iface = net.and_then(|n| d.public_iface(n));
                want.v4 = match &x.discover {
                    Some(u) => {
                        let fresh = discovered
                            .get(u)
                            .is_some_and(|(t, _)| t.elapsed() < DISCOVER_EVERY);
                        if !fresh {
                            discovered
                                .insert(u.clone(), (Instant::now(), discover(&Hyper, u).await));
                        }
                        match &discovered[u].1 {
                            Ok(a) => Some(*a),
                            Err(err) => {
                                notes.push(format!("cannot discover the address: {err}"));
                                None
                            }
                        }
                    }
                    None => {
                        let on = match iface {
                            Some(i) => iface_v4(i).await,
                            None => vec![],
                        };
                        let a = net.and_then(|n| wan_v4(d, &node, n, &on));
                        if let Some(a) = a
                            && !public_v4(a)
                        {
                            notes.push(format!(
                                "{a} is not a public address (behind NAT?): set discover"
                            ));
                        }
                        a
                    }
                };
                if x.ipv6 {
                    let ifs: Vec<&str> = iface
                        .into_iter()
                        .chain(net.and_then(|n| d.network_iface(n)))
                        .collect();
                    want.v6 = wan_v6(&links, &ifs);
                    if want.v6.is_none() {
                        notes.push("the WAN has no global IPv6 address yet".into());
                    }
                }
                if want.v4.is_none() && x.discover.is_none() {
                    notes.push("the WAN has no IPv4 address yet".into());
                }
            }
            let last = sent.get(e).filter(|s| s.key == key);
            let now = jiff::Timestamp::now().as_second();
            let have_addr = want.v4.is_some() || want.v6.is_some();
            let verify_due = entry.verified.is_none_or(|t| t.elapsed() >= VERIFY_EVERY);
            if active
                && have_addr
                && entry.stopped.is_none()
                && x.provider != "cloudflare"
                && verify_due
            {
                if let Some(l) = last
                    && l.addrs == want
                    && now - l.at > 600
                {
                    entry.mismatch = mismatch(&x.names, want).await;
                }
                entry.verified = Some(Instant::now());
            }
            let due = last.is_none_or(|l| l.addrs != want || now - l.at >= RESEND_SECS)
                || entry.mismatch.is_some()
                || (x.provider == "cloudflare" && verify_due);
            if active
                && have_addr
                && due
                && entry.stopped.is_none()
                && Instant::now() >= entry.next_try
            {
                match update(&core, &events, x, want).await {
                    Ok(changed) => {
                        let moved = last.is_none_or(|l| l.addrs != want);
                        if moved || changed {
                            tracing::info!(
                                entry = e,
                                names = x.names.join(","),
                                address = ?want.v4,
                                ipv6 = ?want.v6,
                                "updated dynamic DNS"
                            );
                            let _ = events.send(json!({
                                "type": "ddns", "name": e, "names": x.names,
                                "address": want.v4, "ipv6": want.v6,
                            }));
                        }
                        sent.insert(
                            e.clone(),
                            Sent {
                                key: key.clone(),
                                addrs: want,
                                at: now,
                            },
                        );
                        dirty = true;
                        if stopped.remove(e).is_some() {
                            dirty = true;
                        }
                        entry.error = None;
                        entry.mismatch = None;
                        entry.backoff = RETRY_FIRST;
                        entry.next_try = Instant::now() + MIN_GAP;
                        if x.provider == "cloudflare" {
                            entry.verified = Some(Instant::now());
                        }
                    }
                    Err(f) => {
                        tracing::warn!(entry = e, error = f.message(), "dynamic DNS update failed");
                        entry.error = Some(f.message().to_string());
                        if let Fail::Stop(m) = f {
                            stopped.insert(
                                e.clone(),
                                Stopped {
                                    key: stop_key(&core, &events, x, &key).await,
                                    message: m.clone(),
                                },
                            );
                            dirty = true;
                            entry.stopped = Some(m);
                        }
                        entry.next_try = Instant::now() + entry.backoff;
                        entry.backoff = (entry.backoff * 2).min(RETRY_MAX);
                    }
                }
            }
            if active {
                if let Some(m) = &entry.stopped {
                    problems.push(format!(
                        "{e}: stopped until its settings or credentials change: {m}"
                    ));
                } else if let Some(m) = &entry.error {
                    problems.push(format!("{e}: {m}"));
                } else if let Some(m) = &entry.mismatch {
                    problems.push(format!("{e}: {m}"));
                }
                problems.extend(notes.iter().map(|n| format!("{e}: {n}")));
            }
            let last = sent.get(e).filter(|s| s.key == key);
            shown.insert(
                e.clone(),
                json!({
                    "names": x.names,
                    "provider": x.provider,
                    "address": want.v4,
                    "ipv6": want.v6,
                    "sent": last.map(|l| &l.addrs),
                    "updated": last.map(|l| l.at),
                    "error": entry.stopped.as_ref().or(entry.error.as_ref()),
                    "active": active,
                }),
            );
        }
        if dirty
            && let Err(err) = sparewall_core::store::write_atomic(
                &path,
                &serde_json::to_vec(&Kept {
                    sent: sent.clone(),
                    stopped: stopped.clone(),
                })
                .unwrap_or_default(),
            )
        {
            tracing::warn!(error = %err, "cannot keep what dynamic DNS last sent");
        }
        *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) =
            (!wanted.is_empty()).then_some(Value::Object(shown));
        let checks = if wanted.is_empty() || !active {
            vec![]
        } else if problems.is_empty() {
            vec![Check::new("ddns", Level::Ok, "names current")]
        } else {
            vec![Check::new("ddns", Level::Degraded, problems.join("; "))]
        };
        let _ = with_core_raw(&core, &events, move |c| {
            c.set_named_checks("ddns", checks);
            Ok(())
        })
        .await;
        // Wake on a transition, a lease, an apply or a rollback, or after
        // a round.
        let _ = tokio::time::timeout(ROUND, async {
            loop {
                match rx.recv().await {
                    Ok(v)
                        if ["vrrp", "lease", "applied", "rolled-back"]
                            .contains(&v["type"].as_str().unwrap_or_default()) =>
                    {
                        break;
                    }
                    Err(broadcast::error::RecvError::Closed) => std::future::pending::<()>().await,
                    _ => {}
                }
            }
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Answers from a script, keeping each request.
    struct Fake {
        answers: StdMutex<Vec<(u16, String)>>,
        seen: StdMutex<Vec<String>>,
    }

    impl Fake {
        fn new(answers: &[(u16, &str)]) -> Self {
            Fake {
                answers: StdMutex::new(
                    answers
                        .iter()
                        .rev()
                        .map(|(s, b)| (*s, b.to_string()))
                        .collect(),
                ),
                seen: StdMutex::new(vec![]),
            }
        }
        fn seen(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Http for Fake {
        async fn call(
            &self,
            method: &str,
            url: &str,
            headers: &[(&str, String)],
            body: Option<String>,
        ) -> Result<(u16, String), String> {
            let auth = headers
                .iter()
                .find(|(k, _)| *k == "authorization")
                .map(|(_, v)| format!(" [{v}]"))
                .unwrap_or_default();
            let body = body.map(|b| format!(" {b}")).unwrap_or_default();
            self.seen
                .lock()
                .unwrap()
                .push(format!("{method} {url}{auth}{body}"));
            self.answers
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| "no answer".to_string())
        }
    }

    fn creds(kv: &[(&str, &str)]) -> Vec<(String, String)> {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn v4(s: &str) -> Addrs {
        Addrs {
            v4: Some(s.parse().unwrap()),
            v6: None,
        }
    }

    #[tokio::test]
    async fn dyndns2_sends_every_name_and_reads_each_answer() {
        let c = creds(&[("DYNDNS2_USERNAME", "me"), ("DYNDNS2_PASSWORD", "pw")]);
        let names = vec!["a.example.org".to_string(), "b.example.org".to_string()];
        let both = Addrs {
            v4: Some("203.0.113.7".parse().unwrap()),
            v6: Some("2001:db8::1".parse().unwrap()),
        };
        let f = Fake::new(&[(200, "good 203.0.113.7\nnochg 203.0.113.7\n")]);
        dyndns2(&f, "https://dyn.example/nic/update", &c, &names, both)
            .await
            .unwrap();
        assert_eq!(
            f.seen(),
            [
                "GET https://dyn.example/nic/update?hostname=a.example.org%2Cb.example.org&myip=203.0.113.7%2C2001%3Adb8%3A%3A1 [Basic bWU6cHc=]"
            ]
        );
        let f = Fake::new(&[(200, "good 203.0.113.7\nnohost\n")]);
        assert_eq!(
            dyndns2(&f, "https://dyn.example/u", &c, &names, v4("203.0.113.7")).await,
            Err(Fail::Stop("b.example.org: nohost".into()))
        );
        let f = Fake::new(&[(200, "911\n")]);
        assert!(matches!(
            dyndns2(&f, "https://dyn.example/u", &c, &names, v4("203.0.113.7")).await,
            Err(Fail::Retry(_))
        ));
        let f = Fake::new(&[(401, "")]);
        assert!(matches!(
            dyndns2(&f, "https://dyn.example/u", &c, &names, v4("203.0.113.7")).await,
            Err(Fail::Stop(_))
        ));
        let f = Fake::new(&[(302, "")]);
        assert!(matches!(
            dyndns2(&f, "https://dyn.example/u", &c, &names, v4("203.0.113.7")).await,
            Err(Fail::Stop(_))
        ));
        let f = Fake::new(&[]);
        assert_eq!(
            dyndns2(
                &f,
                "https://dyn.example/u",
                &creds(&[]),
                &names,
                v4("203.0.113.7")
            )
            .await,
            Err(Fail::Stop(
                "the credentials have no DYNDNS2_USERNAME".into()
            ))
        );
    }

    #[tokio::test]
    async fn duckdns_takes_the_subdomains() {
        let c = creds(&[("DUCKDNS_TOKEN", "t-1")]);
        let names = vec!["Home.DuckDNS.org.".to_string()];
        let f = Fake::new(&[(200, "OK")]);
        duckdns(&f, DUCKDNS, &c, &names, v4("203.0.113.7"))
            .await
            .unwrap();
        assert_eq!(
            f.seen(),
            ["GET https://www.duckdns.org/update?domains=home&token=t-1&ip=203.0.113.7"]
        );
        let f = Fake::new(&[(200, "KO")]);
        assert!(matches!(
            duckdns(&f, DUCKDNS, &c, &names, v4("203.0.113.7")).await,
            Err(Fail::Stop(_))
        ));
    }

    #[tokio::test]
    async fn cloudflare_changes_only_what_differs() {
        let c = creds(&[("CF_DNS_API_TOKEN", "tok")]);
        let names = vec!["vpn.home.example.org".to_string()];
        let ok = |r: Value| json!({"success": true, "result": r}).to_string();
        let f = Fake::new(&[
            (200, &ok(json!([]))),
            (200, &ok(json!([{"id": "z1"}]))),
            (200, &ok(json!([{"id": "r1", "content": "198.51.100.1"}]))),
            (200, &ok(json!({}))),
        ]);
        let changed = cloudflare(&f, CLOUDFLARE, None, &c, &names, v4("203.0.113.7"))
            .await
            .unwrap();
        assert!(changed);
        let b = CLOUDFLARE;
        assert_eq!(
            f.seen(),
            [
                format!("GET {b}/zones?name=vpn.home.example.org [Bearer tok]"),
                format!("GET {b}/zones?name=home.example.org [Bearer tok]"),
                format!(
                    "GET {b}/zones/z1/dns_records?type=A&name=vpn.home.example.org [Bearer tok]"
                ),
                format!(
                    "PATCH {b}/zones/z1/dns_records/r1 [Bearer tok] {{\"content\":\"203.0.113.7\"}}"
                ),
            ]
        );
        // Current already: read only. None yet: created.
        let f = Fake::new(&[
            (200, &ok(json!([{"id": "z1"}]))),
            (200, &ok(json!([{"id": "r1", "content": "203.0.113.7"}]))),
            (200, &ok(json!([]))),
            (200, &ok(json!({}))),
        ]);
        let both = Addrs {
            v4: Some("203.0.113.7".parse().unwrap()),
            v6: Some("2001:db8::1".parse().unwrap()),
        };
        assert!(
            cloudflare(&f, b, Some("example.org"), &c, &names, both)
                .await
                .unwrap()
        );
        let seen = f.seen();
        assert_eq!(seen.len(), 4);
        assert!(
            seen[3].starts_with(&format!("POST {b}/zones/z1/dns_records"))
                && seen[3].contains("\"type\":\"AAAA\""),
            "{seen:#?}"
        );
        let f = Fake::new(&[(
            403,
            r#"{"success":false,"errors":[{"message":"Authentication error"}]}"#,
        )]);
        let e = cloudflare(&f, b, Some("example.org"), &c, &names, v4("203.0.113.7"))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, Fail::Stop(m) if m.contains("Authentication error")),
            "{e:?}"
        );
        // lego's other name for the token serves too.
        let f = Fake::new(&[(429, "{}")]);
        let c2 = creds(&[("CLOUDFLARE_DNS_API_TOKEN", "tok")]);
        assert!(matches!(
            cloudflare(&f, b, Some("example.org"), &c2, &names, v4("203.0.113.7")).await,
            Err(Fail::Retry(_))
        ));
    }

    #[test]
    fn the_wan_address() {
        let text = include_str!("../../../examples/standalone.yaml");
        let mut d = sparewall_config::parse(text, sparewall_config::Format::Yaml).unwrap();
        let on: Vec<Ipv4Addr> = vec!["203.0.113.9".parse().unwrap()];
        assert_eq!(wan_v4(&d, "fw1", "wan", &on), Some(on[0]));
        assert_eq!(wan_v4(&d, "fw1", "wan", &[]), None);
        let w = d.networks.get_mut("wan").unwrap();
        w.dhcp_client = false;
        w.addresses.insert(
            "fw1".into(),
            sparewall_config::model::Cidr("198.51.100.5/24".parse().unwrap()),
        );
        assert_eq!(
            wan_v4(&d, "fw1", "wan", &on),
            Some("198.51.100.5".parse().unwrap())
        );
        assert!(public_v4("203.0.113.9".parse().unwrap()));
        for p in ["10.1.2.3", "192.168.1.1", "100.64.0.1", "169.254.1.1"] {
            assert!(!public_v4(p.parse().unwrap()), "{p}");
        }
    }

    #[test]
    fn records_are_checked_in_each_family() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let both = Addrs {
            v4: Some("203.0.113.7".parse().unwrap()),
            v6: Some("2001:db8::1".parse().unwrap()),
        };
        let only6 = Addrs {
            v4: None,
            v6: both.v6,
        };
        assert_eq!(
            differs("n", &[ip("203.0.113.7"), ip("2001:db8::1")], both),
            None
        );
        assert_eq!(
            differs("n", &[ip("203.0.113.7"), ip("2001:db8::9")], both).as_deref(),
            Some("n resolves to 2001:db8::9, not 2001:db8::1")
        );
        assert_eq!(
            differs("n", &[ip("198.51.100.1"), ip("2001:db8::1")], both).as_deref(),
            Some("n resolves to 198.51.100.1, not 203.0.113.7")
        );
        assert_eq!(
            differs("n", &[ip("2001:db8::9")], only6).as_deref(),
            Some("n resolves to 2001:db8::9, not 2001:db8::1")
        );
        // An A record an IPv6-only entry doesn't keep; no answer at all.
        assert_eq!(
            differs("n", &[ip("198.51.100.1"), ip("2001:db8::1")], only6),
            None
        );
        assert_eq!(differs("n", &[], both), None);
        // A family missing while the other resolves.
        assert_eq!(
            differs("n", &[ip("2001:db8::1")], both).as_deref(),
            Some("n has no A record, not 203.0.113.7")
        );
        assert_eq!(
            differs("n", &[ip("203.0.113.7")], both).as_deref(),
            Some("n has no AAAA record, not 2001:db8::1")
        );
    }

    #[test]
    fn a_stopped_entry_stays_stopped_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(STATE_FILE);
        let mut k = Kept::default();
        k.stopped.insert(
            "home".into(),
            Stopped {
                key: "k".into(),
                message: "badauth".into(),
            },
        );
        std::fs::write(&p, serde_json::to_vec(&k).unwrap()).unwrap();
        let back = load(&p);
        assert_eq!(back.stopped["home"].message, "badauth");
        assert!(back.sent.is_empty());
        // Keyed by the settings and the secret's digest: a new secret, or
        // one set where there was none, is a new key.
        let a = stop_key_of("k", Some(b"DYNDNS2_PASSWORD=old"));
        assert_eq!(a, stop_key_of("k", Some(b"DYNDNS2_PASSWORD=old")));
        assert_ne!(a, stop_key_of("k", Some(b"DYNDNS2_PASSWORD=new")));
        assert_ne!(a, stop_key_of("k2", Some(b"DYNDNS2_PASSWORD=old")));
        assert_ne!(stop_key_of("k", None), a);
        assert!(!a.contains("old"));
    }

    #[test]
    fn query_values_are_encoded() {
        assert_eq!(q("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
    }
}
