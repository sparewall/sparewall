//! ACME certificates (design: "TLS and ACME").
//!
//! DNS-01 is the primary challenge; RFC 2136 dynamic updates with TSIG are
//! built in (through `nsupdate`, behind [`DnsZone`]). Any other DNS
//! provider is a lego provider: lego runs the whole order in its container
//! ([`Lego`]), with the provider's settings and credentials in its
//! environment, and keeps its own account per node. The ACME account and issued certificates
//! are cluster secrets, so in a pair only the active node orders a
//! certificate and the peer receives it through the sync tunnel. Renewal
//! happens at two-thirds of the lifetime. Without a usable certificate the
//! node keeps serving its self-signed one and health reports it.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, ExternalAccountKey,
    Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sparewall_config::model::{Acme, Certificate};
use sparewall_core::host::{DnsZone, Lego, LegoContainer, Rfc2136};
use sparewall_core::secrets::SecretClass;
use sparewall_core::{Check, Level};
use tokio::sync::broadcast;

use crate::http::Tls;
use crate::peer::Pair;
use crate::service::{Core, with_core_raw};

/// The certificate served on the management network, if configured.
pub const MGMT_CERT: &str = "mgmt";

/// An issued certificate, kept as the cluster secret `tls-<name>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issued {
    pub names: Vec<String>,
    pub chain_pem: String,
    pub key_pem: String,
    pub not_before: i64,
    pub not_after: i64,
}

impl Issued {
    /// Renew at two-thirds of the lifetime.
    pub fn due(&self, now: i64) -> bool {
        now >= self.not_before + (self.not_after - self.not_before) * 2 / 3
    }
}

fn secret_name(cert: &str) -> String {
    format!("tls-{cert}")
}

fn account_secret(directory: &str) -> String {
    format!(
        "acme-account-{}",
        &hex::encode(Sha256::digest(directory.as_bytes()))[..16]
    )
}

/// Validity of the first certificate in a PEM chain.
pub fn validity(chain_pem: &str) -> Result<(i64, i64), String> {
    use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject};
    let der = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .next()
        .ok_or("no certificate in the chain")?
        .map_err(|e| e.to_string())?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).map_err(|e| e.to_string())?;
    Ok((
        cert.validity().not_before.timestamp(),
        cert.validity().not_after.timestamp(),
    ))
}

/// How long to wait for a challenge record to reach the server.
#[derive(Clone, Copy)]
struct Propagation {
    attempts: u32,
    every: Duration,
}

const PROPAGATION: Propagation = Propagation {
    attempts: 24,
    every: Duration::from_secs(5),
};

/// The dns-01 challenge records of one order. Every record is removed at
/// the end, whatever happened: one whose update failed may have been
/// applied, and an order that fails partway leaves the earlier ones.
struct Challenges {
    dns: Arc<dyn DnsZone>,
    published: Vec<String>,
    wait: Propagation,
}

impl Challenges {
    fn new(dns: Arc<dyn DnsZone>, wait: Propagation) -> Self {
        Challenges {
            dns,
            published: Vec::new(),
            wait,
        }
    }

    /// Publish `value` at `record` and wait until the server answers it.
    async fn publish(&mut self, record: &str, value: &str) -> Result<(), String> {
        self.published.push(record.to_string());
        let (dns, r, v) = (self.dns.clone(), record.to_string(), value.to_string());
        blocking(move || dns.set_txt(&r, &v)).await?;
        for _ in 0..self.wait.attempts {
            let (dns, r) = (self.dns.clone(), record.to_string());
            if blocking(move || dns.txt(&r))
                .await
                .is_ok_and(|vals| vals.iter().any(|x| x == value))
            {
                return Ok(());
            }
            tokio::time::sleep(self.wait.every).await;
        }
        Err(format!("{record} did not appear on {}", self.dns.server()))
    }

    /// Remove every record published; a failure is logged, not fatal.
    async fn remove_all(self) {
        for r in self.published {
            let (dns, rr) = (self.dns.clone(), r.clone());
            if let Err(e) = blocking(move || dns.delete_txt(&rr)).await {
                tracing::warn!(record = %r, error = %e, "cannot remove the challenge record");
            }
        }
    }
}

/// Run `f` with an order's challenges; afterwards every record it
/// published is removed, however `f` ended.
async fn with_challenges<T>(
    dns: Arc<dyn DnsZone>,
    wait: Propagation,
    f: impl AsyncFnOnce(&mut Challenges) -> Result<T, String>,
) -> Result<T, String> {
    let mut challenges = Challenges::new(dns, wait);
    let result = f(&mut challenges).await;
    challenges.remove_all().await;
    result
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
}

async fn secret(
    core: &Core,
    events: &broadcast::Sender<Value>,
    name: String,
) -> Result<Option<Vec<u8>>, String> {
    with_core_raw(core, events, move |c| c.secret_get(&name))
        .await
        .map_err(|e| e.to_string())
}

fn secret_ref(r: &str) -> Result<String, String> {
    r.strip_prefix("secret:")
        .map(str::to_string)
        .ok_or_else(|| format!("{r:?} is not a secret:<name> reference"))
}

async fn provider(
    core: &Core,
    events: &broadcast::Sender<Value>,
    acme: &Acme,
) -> Result<Arc<dyn DnsZone>, String> {
    let dns = acme.dns.as_ref().ok_or("acme.dns is required for dns-01")?;
    let cred = dns
        .credentials
        .as_deref()
        .ok_or("acme.dns.credentials is required")?;
    let tsig = secret(core, events, secret_ref(cred)?)
        .await?
        .ok_or_else(|| format!("secret {cred} is not set"))?;
    Ok(Arc::new(Rfc2136 {
        server: dns
            .options
            .get("server")
            .cloned()
            .ok_or("acme.dns.options.server is required")?,
        zone: dns.options.get("zone").cloned(),
        tsig: String::from_utf8_lossy(&tsig).trim().to_string(),
    }))
}

async fn account(
    core: &Core,
    events: &broadcast::Sender<Value>,
    acme: &Acme,
) -> Result<Account, String> {
    let name = account_secret(&acme.directory);
    let ca_file = match &acme.ca {
        Some(pem) => {
            let p = std::env::temp_dir().join(format!(
                "sparewall-acme-ca-{}.pem",
                &hex::encode(Sha256::digest(pem.as_bytes()))[..12]
            ));
            std::fs::write(&p, pem).map_err(|e| e.to_string())?;
            Some(p)
        }
        None => None,
    };
    let builder = || match &ca_file {
        Some(p) => Account::builder_with_root(p).map_err(|e| e.to_string()),
        None => Account::builder().map_err(|e| e.to_string()),
    };
    if let Some(creds) = secret(core, events, name.clone()).await? {
        let creds: AccountCredentials =
            serde_json::from_slice(&creds).map_err(|e| e.to_string())?;
        return builder()?
            .from_credentials(creds)
            .await
            .map_err(|e| e.to_string());
    }
    let contact = acme.email.as_ref().map(|e| format!("mailto:{e}"));
    let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
    let eab = match &acme.eab {
        Some(e) => {
            let key = secret(core, events, secret_ref(&e.hmac)?)
                .await?
                .ok_or_else(|| format!("secret {} is not set", e.hmac))?;
            Some(ExternalAccountKey::new(e.kid.clone(), &key))
        }
        None => None,
    };
    let (account, creds) = builder()?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            acme.directory.clone(),
            eab.as_ref(),
        )
        .await
        .map_err(|e| e.to_string())?;
    let json = serde_json::to_vec(&creds).map_err(|e| e.to_string())?;
    with_core_raw(core, events, move |c| {
        c.secret_set(&name, &json, SecretClass::Cluster)
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(account)
}

/// Order a certificate.
pub async fn issue(
    core: &Core,
    events: &broadcast::Sender<Value>,
    name: &str,
    cert: &Certificate,
) -> Result<Issued, String> {
    let acme = cert.acme.as_ref().ok_or("no acme settings")?;
    if acme.challenge.as_deref().unwrap_or("dns-01") != "dns-01" {
        return Err("only the dns-01 challenge is built in so far".into());
    }
    if acme.dns.as_ref().is_some_and(|d| d.provider != "rfc2136") {
        let lego = Arc::new(LegoContainer::shipped()?);
        return issue_with_lego(core, events, name, cert, lego).await;
    }
    let dns = provider(core, events, acme).await?;
    let account = account(core, events, acme).await?;
    let ids: Vec<Identifier> = cert
        .names
        .iter()
        .map(|n| Identifier::Dns(n.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(&ids))
        .await
        .map_err(|e| e.to_string())?;
    with_challenges(dns, PROPAGATION, async |challenges| {
        {
            let mut authzs = order.authorizations();
            while let Some(a) = authzs.next().await {
                let mut authz = a.map_err(|e| e.to_string())?;
                if authz.status == AuthorizationStatus::Valid {
                    continue;
                }
                let mut ch = authz
                    .challenge(ChallengeType::Dns01)
                    .ok_or("the CA offered no dns-01 challenge")?;
                let name = match ch.identifier().identifier {
                    Identifier::Dns(d) => d.trim_start_matches("*.").to_string(),
                    other => return Err(format!("unsupported identifier {other:?}")),
                };
                let value = ch.key_authorization().dns_value();
                challenges
                    .publish(&format!("_acme-challenge.{name}"), &value)
                    .await?;
                ch.set_ready().await.map_err(|e| e.to_string())?;
            }
        }
        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| e.to_string())?;
        if status != OrderStatus::Ready {
            return Err(format!("order is {status:?}"));
        }
        let key_pem = order.finalize().await.map_err(|e| e.to_string())?;
        let chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| e.to_string())?;
        let (not_before, not_after) = validity(&chain_pem)?;
        Ok(Issued {
            names: cert.names.clone(),
            chain_pem,
            key_pem,
            not_before,
            not_after,
        })
    })
    .await
}

/// Order certificate `name` through lego. Its data directory (account and
/// certificates) is `lego` in the state directory; the environment file,
/// with the credentials, lives only while lego runs.
async fn issue_with_lego(
    core: &Core,
    events: &broadcast::Sender<Value>,
    name: &str,
    cert: &Certificate,
    lego: Arc<dyn Lego>,
) -> Result<Issued, String> {
    let acme = cert.acme.as_ref().ok_or("no acme settings")?;
    let dns = acme.dns.as_ref().ok_or("acme.dns is required for dns-01")?;
    let mut env: Vec<(String, String)> = dns
        .options
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if let Some(cred) = &dns.credentials {
        let text = secret(core, events, secret_ref(cred)?)
            .await?
            .ok_or_else(|| format!("secret {cred} is not set"))?;
        env.extend(crate::backup::credentials_env(
            &format!("the {cred} credentials"),
            &String::from_utf8_lossy(&text),
        )?);
    }
    if let Some(e) = &acme.eab {
        let hmac = secret(core, events, secret_ref(&e.hmac)?)
            .await?
            .ok_or_else(|| format!("secret {} is not set", e.hmac))?;
        env.push(("LEGO_EAB".into(), "true".into()));
        env.push(("LEGO_EAB_KID".into(), e.kid.clone()));
        env.push((
            "LEGO_EAB_HMAC".into(),
            String::from_utf8_lossy(&hmac).trim().to_string(),
        ));
    }
    let root = with_core_raw(core, events, |c| Ok(c.store().root().to_path_buf()))
        .await
        .map_err(|e| e.to_string())?;
    let data = root.join("lego");
    std::fs::create_dir_all(data.join("certificates")).map_err(|e| e.to_string())?;
    if let Some(pem) = &acme.ca {
        std::fs::write(data.join("ca.pem"), pem).map_err(|e| e.to_string())?;
        env.push(("LEGO_CA_CERTIFICATES".into(), "/data/ca.pem".into()));
    }
    let mut lines = String::new();
    for (k, v) in &env {
        if v.contains('\n') {
            return Err(format!("{k}: a value cannot span lines"));
        }
        lines.push_str(&format!("{k}={v}\n"));
    }
    // Credentials stay off the disk where the runtime directory exists.
    let run = Path::new("/run/sparewall");
    let env_dir = if run.is_dir() {
        run.join("lego")
    } else {
        data.clone()
    };
    std::fs::create_dir_all(&env_dir).map_err(|e| e.to_string())?;
    let env_file = env_dir.join(format!(".env-{}-{name}", std::process::id()));
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&env_file)
            .map_err(|e| e.to_string())?;
        f.write_all(lines.as_bytes()).map_err(|e| e.to_string())?;
    }
    let args = lego_args(name, cert, acme, &dns.provider);
    let (d, f) = (data.clone(), env_file.clone());
    let ran = blocking(move || lego.run(&d, &f, &args)).await;
    let _ = std::fs::remove_file(&env_file);
    ran.map_err(|e| format!("lego: {e}"))?;
    let read = |ext: &str| {
        let p = data.join("certificates").join(format!("{name}.{ext}"));
        std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))
    };
    let chain_pem = read("crt")?;
    let key_pem = read("key")?;
    let (not_before, not_after) = validity(&chain_pem)?;
    Ok(Issued {
        names: cert.names.clone(),
        chain_pem,
        key_pem,
        not_before,
        not_after,
    })
}

/// lego's command line for one order. Called only when the certificate is
/// due, so the renewal is forced; the names are forced too, for a
/// certificate whose names changed.
fn lego_args(name: &str, cert: &Certificate, acme: &Acme, provider: &str) -> Vec<String> {
    let mut a: Vec<String> = [
        "--log.format",
        "text",
        "run",
        "--path",
        "/data",
        "--accept-tos",
        "--no-random-sleep",
        "--renew-force",
        "--force-cert-domains",
        "--server",
        &acme.directory,
        "--dns",
        provider,
        "--cert.name",
        name,
    ]
    .map(String::from)
    .to_vec();
    if let Some(e) = &acme.email {
        a.extend(["--email".into(), e.clone()]);
    }
    for n in &cert.names {
        a.extend(["--domains".into(), n.clone()]);
    }
    a
}

async fn stored(core: &Core, events: &broadcast::Sender<Value>, name: &str) -> Option<Issued> {
    let raw = secret(core, events, secret_name(name)).await.ok()??;
    serde_json::from_slice(&raw).ok()
}

/// Keep certificates issued and the management listener serving the
/// right one. Runs every fifteen minutes.
pub async fn acme_loop(core: Core, events: broadcast::Sender<Value>, pair: Pair, tls: Arc<Tls>) {
    tokio::time::sleep(Duration::from_secs(20)).await;
    loop {
        let checks = once(&core, &events, &pair, &tls).await;
        let _ = with_core_raw(&core, &events, move |c| {
            c.set_named_checks("tls", checks);
            Ok(())
        })
        .await;
        tokio::time::sleep(Duration::from_secs(15 * 60)).await;
    }
}

async fn once(
    core: &Core,
    events: &broadcast::Sender<Value>,
    pair: &Pair,
    tls: &Tls,
) -> Vec<Check> {
    let doc = match with_core_raw(core, events, |c| c.active_document()).await {
        Ok(Some(d)) => d,
        _ => return vec![],
    };
    let Some(t) = &doc.tls else {
        tls.use_self_signed();
        return vec![];
    };
    let active = !doc.is_pair()
        || pair
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .role
            .as_deref()
            == Some("MASTER");
    let now = jiff::Timestamp::now().as_second();
    let mut problems = Vec::new();
    for (name, cert) in &t.certificates {
        if cert.acme.is_none() {
            continue;
        }
        let have = stored(core, events, name).await;
        let names_changed = have.as_ref().is_some_and(|h| h.names != cert.names);
        let needs = have.as_ref().is_none_or(|h| h.due(now)) || names_changed;
        if needs && active {
            match issue(core, events, name, cert).await {
                Ok(i) => {
                    let json = serde_json::to_vec(&i).expect("json");
                    let n = secret_name(name);
                    let _ = with_core_raw(core, events, move |c| {
                        c.secret_set(&n, &json, SecretClass::Cluster)
                    })
                    .await;
                    tracing::info!(certificate = %name, not_after = i.not_after, "issued certificate");
                    let _ = events.send(serde_json::json!({"type": "certificate", "name": name, "not_after": i.not_after}));
                }
                Err(e) => {
                    tracing::warn!(certificate = %name, error = %e, "certificate order failed");
                    problems.push(format!("{name}: {e}"));
                }
            }
        }
        if let Some(i) = stored(core, events, name).await {
            if i.not_after <= now {
                problems.push(format!("{name} expired"));
            } else if i.not_after - now < 7 * 86_400 {
                problems.push(format!("{name} expires within a week"));
            }
        } else if !active {
            problems.push(format!("{name}: waiting for the peer to issue it"));
        }
    }
    // Serve the management certificate when there is a valid one.
    let mgmt = t
        .certificates
        .keys()
        .find(|k| *k == MGMT_CERT)
        .or(t.certificates.keys().next());
    match mgmt {
        Some(m) => match stored(core, events, m).await.filter(|i| i.not_after > now) {
            Some(i) => {
                if let Err(e) = tls.use_pem(&i.chain_pem, &i.key_pem) {
                    problems.push(format!("{m}: cannot load: {e}"));
                }
            }
            None => tls.use_self_signed(),
        },
        None => tls.use_self_signed(),
    }
    if problems.is_empty() {
        vec![Check::new("tls", Level::Ok, "certificates valid")]
    } else {
        vec![Check::new("tls", Level::Degraded, problems.join("; "))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_at_two_thirds() {
        let i = Issued {
            names: vec![],
            chain_pem: String::new(),
            key_pem: String::new(),
            not_before: 0,
            not_after: 90,
        };
        assert!(!i.due(59));
        assert!(i.due(60));
    }

    /// A coordinator with no configuration, for issuing certificates.
    fn acme_core(dir: &std::path::Path) -> (Core, broadcast::Sender<Value>) {
        let id = sparewall_config::identity::Identity {
            node: "fw1".into(),
            ssh_keys: vec![],
            management: sparewall_config::identity::BootstrapPort {
                nic: "52:54:00:aa:00:01".into(),
                vlan: None,
                address: None,
                gateway: None,
                dns: vec![],
            },
        };
        let sys: Box<dyn sparewall_core::System> =
            Box::new(sparewall_core::system::Fake::default());
        let c =
            sparewall_core::Coordinator::new(sparewall_core::Store::open(dir).unwrap(), sys, id);
        let (events, _) = broadcast::channel(16);
        (Arc::new(std::sync::Mutex::new(c)), events)
    }

    fn set_secret(core: &Core, name: &str, value: &str) {
        core.lock()
            .unwrap()
            .secret_set(name, value.as_bytes(), SecretClass::Cluster)
            .unwrap();
    }

    fn pebble_cert(provider: &str, credentials: &str, options: Value) -> Certificate {
        let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"));
        serde_json::from_value(serde_json::json!({
            "names": ["fw.example.test", "vpn.example.test"],
            "acme": {
                "directory": env("ACME_DIRECTORY"),
                "ca": std::fs::read_to_string(env("ACME_CA")).unwrap(),
                "dns": {"provider": provider, "credentials": credentials, "options": options}
            }
        }))
        .unwrap()
    }

    fn servable(dir: &std::path::Path, issued: &Issued) {
        assert!(issued.chain_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.not_after > issued.not_before);
        let ss = crate::http::self_signed(&dir.join("tls"), "fw1").unwrap();
        crate::http::Tls::new(&ss)
            .unwrap()
            .use_pem(&issued.chain_pem, &issued.key_pem)
            .unwrap();
    }

    /// Issue a real certificate from Pebble, with challenges published to
    /// a BIND server by RFC 2136 (tests/acme/run.sh sets this up).
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "needs Pebble and BIND; run by tests/acme/run.sh"]
    async fn against_pebble() {
        let dir = tempfile::tempdir().unwrap();
        let (core, events) = acme_core(dir.path());
        set_secret(&core, "dns-tsig", &std::env::var("ACME_TSIG").unwrap());
        let cert = pebble_cert(
            "rfc2136",
            "secret:dns-tsig",
            serde_json::json!({"server": std::env::var("ACME_DNS").unwrap(), "zone": "example.test"}),
        );
        let issued = issue(&core, &events, "mgmt", &cert).await.unwrap();
        servable(dir.path(), &issued);
        // A second order reuses the stored account.
        issue(&core, &events, "mgmt", &cert).await.unwrap();
    }

    /// The same through lego (its RFC 2136 provider, `dnsupdate`), in the
    /// image `SPAREWALL_LEGO_IMAGE` names.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "needs Pebble, BIND and the lego image; run by tests/acme/run.sh"]
    async fn against_pebble_with_lego() {
        let dir = tempfile::tempdir().unwrap();
        let (core, events) = acme_core(dir.path());
        let tsig = std::env::var("ACME_TSIG").unwrap();
        let mut parts = tsig.splitn(3, ':');
        let (alg, key, secret) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        set_secret(
            &core,
            "lego-dns",
            &format!(
                "DNSUPDATE_TSIG_KEY={key}\nDNSUPDATE_TSIG_SECRET={secret}\nDNSUPDATE_TSIG_ALGORITHM={alg}.\n"
            ),
        );
        let dns = std::env::var("ACME_DNS").unwrap();
        let cert = pebble_cert(
            "dnsupdate",
            "secret:lego-dns",
            serde_json::json!({
                "DNSUPDATE_NAMESERVER": dns,
                "DNSUPDATE_ZONES": "example.test",
                "LEGO_DNS_RESOLVERS": dns,
                // The zone's NS record names port 53; BIND listens on 5353.
                "LEGO_DNS_PROPAGATION_WAIT": "2s",
            }),
        );
        let issued = issue(&core, &events, "mgmt", &cert).await.unwrap();
        servable(dir.path(), &issued);
        // A renewal reuses lego's account.
        let again = issue(&core, &events, "mgmt", &cert).await.unwrap();
        assert_ne!(again.chain_pem, issued.chain_pem);
        assert!(
            std::fs::read_dir(dir.path().join("lego"))
                .unwrap()
                .all(|e| !e.unwrap().file_name().to_string_lossy().starts_with(".env")),
            "the environment file is gone"
        );
    }

    /// lego's command line and environment, with a fake lego.
    #[tokio::test(flavor = "current_thread")]
    async fn lego_gets_settings_and_credentials() {
        struct FakeLego(std::sync::Mutex<Vec<(Vec<String>, String)>>);
        impl Lego for FakeLego {
            fn run(
                &self,
                data: &std::path::Path,
                env_file: &std::path::Path,
                args: &[String],
            ) -> Result<(), String> {
                let env = std::fs::read_to_string(env_file).unwrap();
                self.0.lock().unwrap().push((args.to_vec(), env));
                let key = rcgen::KeyPair::generate().unwrap();
                let p = rcgen::CertificateParams::new(vec!["fw.example.org".into()]).unwrap();
                let certs = data.join("certificates");
                std::fs::write(certs.join("mgmt.crt"), p.self_signed(&key).unwrap().pem()).unwrap();
                std::fs::write(certs.join("mgmt.key"), key.serialize_pem()).unwrap();
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let (core, events) = acme_core(dir.path());
        set_secret(
            &core,
            "gcloud",
            "# a service account\nGCE_SERVICE_ACCOUNT={\"k\":1}\n",
        );
        set_secret(&core, "eab", "c2VjcmV0");
        let cert: Certificate = serde_json::from_value(serde_json::json!({
            "names": ["fw.example.org", "*.lan.example.org"],
            "acme": {
                "directory": "https://acme.example/dir",
                "email": "ops@example.org",
                "ca": "-----BEGIN CERTIFICATE-----\n",
                "eab": {"kid": "k1", "hmac": "secret:eab"},
                "dns": {
                    "provider": "gcloud",
                    "credentials": "secret:gcloud",
                    "options": {"GCE_PROJECT": "fw-dns"}
                }
            }
        }))
        .unwrap();
        let lego = Arc::new(FakeLego(Default::default()));
        let issued = issue_with_lego(&core, &events, "mgmt", &cert, lego.clone())
            .await
            .unwrap();
        assert_eq!(issued.names, cert.names);
        let (args, env) = lego.0.lock().unwrap()[0].clone();
        let arg = |flag: &str| {
            args.iter()
                .enumerate()
                .filter(|(_, a)| *a == flag)
                .map(|(i, _)| args[i + 1].as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(arg("--dns"), ["gcloud"]);
        assert_eq!(arg("--server"), ["https://acme.example/dir"]);
        assert_eq!(arg("--cert.name"), ["mgmt"]);
        assert_eq!(arg("--email"), ["ops@example.org"]);
        assert_eq!(arg("--domains"), ["fw.example.org", "*.lan.example.org"]);
        assert!(args.contains(&"--renew-force".to_string()));
        let mut env: Vec<&str> = env.lines().collect();
        env.sort();
        assert_eq!(
            env,
            [
                "GCE_PROJECT=fw-dns",
                "GCE_SERVICE_ACCOUNT={\"k\":1}",
                "LEGO_CA_CERTIFICATES=/data/ca.pem",
                "LEGO_EAB=true",
                "LEGO_EAB_HMAC=c2VjcmV0",
                "LEGO_EAB_KID=k1",
            ]
        );
        // The credentials do not outlive the run.
        let left: Vec<String> = std::fs::read_dir(dir.path().join("lego"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(left.iter().all(|f| !f.starts_with(".env")), "{left:?}");
        // A credential that is not KEY=value lines is refused before lego runs.
        set_secret(&core, "gcloud", "just a token");
        let e = issue_with_lego(&core, &events, "mgmt", &cert, lego.clone())
            .await
            .unwrap_err();
        assert!(e.contains("KEY=value"), "{e}");
    }

    #[test]
    fn reads_validity() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["fw.example.org".into()]).unwrap();
        p.not_before = rcgen::date_time_ymd(2026, 1, 1);
        p.not_after = rcgen::date_time_ymd(2026, 4, 1);
        let pem = p.self_signed(&key).unwrap().pem();
        let (a, b) = validity(&pem).unwrap();
        assert_eq!(b - a, 90 * 86_400);
    }

    /// A zone that records every operation. `set_fails`/`delete_fails`
    /// name records whose update errors; a record appears to `txt` only
    /// after `visible_after` reads (never if absent).
    #[derive(Default)]
    struct FakeDns {
        set_fails: Vec<&'static str>,
        delete_fails: Vec<&'static str>,
        visible_after: std::collections::HashMap<&'static str, usize>,
        values: std::sync::Mutex<std::collections::HashMap<String, String>>,
        reads: std::sync::Mutex<std::collections::HashMap<String, usize>>,
        log: std::sync::Mutex<Vec<String>>,
    }

    impl DnsZone for FakeDns {
        fn set_txt(&self, record: &str, value: &str) -> Result<(), String> {
            self.log.lock().unwrap().push(format!("set {record}"));
            // A failed update may still have been applied.
            self.values
                .lock()
                .unwrap()
                .insert(record.into(), value.into());
            if self.set_fails.contains(&record) {
                return Err("nsupdate: SERVFAIL".into());
            }
            Ok(())
        }
        fn delete_txt(&self, record: &str) -> Result<(), String> {
            self.log.lock().unwrap().push(format!("delete {record}"));
            if self.delete_fails.contains(&record) {
                return Err("nsupdate: REFUSED".into());
            }
            self.values.lock().unwrap().remove(record);
            Ok(())
        }
        fn txt(&self, record: &str) -> Result<Vec<String>, String> {
            let mut reads = self.reads.lock().unwrap();
            let n = reads.entry(record.into()).or_default();
            *n += 1;
            match self.visible_after.get(record) {
                Some(after) if *n > *after => Ok(self
                    .values
                    .lock()
                    .unwrap()
                    .get(record)
                    .cloned()
                    .into_iter()
                    .collect()),
                _ => Ok(vec![]),
            }
        }
        fn server(&self) -> &str {
            "ns.example:53"
        }
    }

    const FAST: Propagation = Propagation {
        attempts: 5,
        every: Duration::from_millis(1),
    };

    fn log(d: &FakeDns) -> Vec<String> {
        d.log.lock().unwrap().clone()
    }

    /// #12: every challenge record published is removed afterwards, also
    /// when a later one fails to appear or its update fails, and one
    /// failed removal does not stop the others.
    #[tokio::test]
    async fn challenge_records_are_always_removed() {
        let (a, b) = ("_acme-challenge.a.example", "_acme-challenge.b.example");

        // a appears after two reads; b never does.
        let dns = Arc::new(FakeDns {
            visible_after: [(a, 2)].into(),
            ..Default::default()
        });
        let e = with_challenges(dns.clone(), FAST, async |ch| {
            ch.publish(a, "va").await?;
            ch.publish(b, "vb").await?;
            Ok(())
        })
        .await
        .unwrap_err();
        assert_eq!(e, format!("{b} did not appear on ns.example:53"));
        assert_eq!(dns.reads.lock().unwrap()[b], 5);
        assert_eq!(
            log(&dns)[2..],
            [format!("delete {a}"), format!("delete {b}")]
        );
        assert!(dns.values.lock().unwrap().is_empty());

        // An update that reports failure is removed too.
        let dns = Arc::new(FakeDns {
            set_fails: vec![a],
            ..Default::default()
        });
        let r = with_challenges(dns.clone(), FAST, async |ch| ch.publish(a, "va").await).await;
        assert_eq!(r, Err("nsupdate: SERVFAIL".into()));
        assert_eq!(log(&dns), [format!("set {a}"), format!("delete {a}")]);
        assert!(dns.values.lock().unwrap().is_empty());

        // A removal that fails does not stop the next.
        let dns = Arc::new(FakeDns {
            delete_fails: vec![a],
            visible_after: [(a, 0), (b, 0)].into(),
            ..Default::default()
        });
        // A later step of the order fails (the CA rejects it).
        let r: Result<(), String> = with_challenges(dns.clone(), FAST, async |ch| {
            ch.publish(a, "va").await?;
            ch.publish(b, "vb").await?;
            Err("order is Invalid".into())
        })
        .await;
        assert_eq!(r, Err("order is Invalid".into()));
        assert_eq!(
            log(&dns)[2..],
            [format!("delete {a}"), format!("delete {b}")]
        );
        assert_eq!(dns.values.lock().unwrap().keys().collect::<Vec<_>>(), [a]);
    }
}
