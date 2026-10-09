//! ACME certificates (design: "TLS and ACME").
//!
//! DNS-01 is the primary challenge; RFC 2136 dynamic updates with TSIG are
//! built in (through `nsupdate`). The ACME account and issued certificates
//! are cluster secrets, so in a pair only the active node orders a
//! certificate and the peer receives it through the sync tunnel. Renewal
//! happens at two-thirds of the lifetime. Without a usable certificate the
//! node keeps serving its self-signed one and health reports it.

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

/// What the DNS-01 provider needs.
struct Rfc2136 {
    server: String,
    zone: Option<String>,
    /// `algorithm:name:secret`, as `nsupdate -y` takes it.
    tsig: String,
}

async fn nsupdate(p: &Rfc2136, record: &str, value: Option<&str>) -> Result<(), String> {
    let mut script = format!("server {}\n", p.server.replace(':', " "));
    if let Some(z) = &p.zone {
        script.push_str(&format!("zone {z}\n"));
    }
    script.push_str(&format!("update delete {record}. TXT\n"));
    if let Some(v) = value {
        script.push_str(&format!("update add {record}. 60 TXT \"{v}\"\n"));
    }
    script.push_str("send\n");
    let mut child = tokio::process::Command::new("nsupdate")
        .args(["-y", &p.tsig])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("nsupdate: {e}"))?;
    use tokio::io::AsyncWriteExt;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(script.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().await.map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "nsupdate: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Wait until the authoritative server answers with the TXT value.
async fn propagated(p: &Rfc2136, record: &str, value: &str) -> bool {
    let (host, port) = p.server.split_once(':').unwrap_or((&p.server, "53"));
    for _ in 0..24 {
        let out = tokio::process::Command::new("dig")
            .args(["+short", "-p", port, &format!("@{host}"), "TXT", record])
            .output()
            .await;
        if out.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains(value)) {
            return true;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    false
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
) -> Result<Rfc2136, String> {
    let dns = acme.dns.as_ref().ok_or("acme.dns is required for dns-01")?;
    if dns.provider != "rfc2136" {
        return Err(format!(
            "DNS provider {:?} needs lego, which is not built in yet; use rfc2136",
            dns.provider
        ));
    }
    let cred = dns
        .credentials
        .as_deref()
        .ok_or("acme.dns.credentials is required")?;
    let tsig = secret(core, events, secret_ref(cred)?)
        .await?
        .ok_or_else(|| format!("secret {cred} is not set"))?;
    Ok(Rfc2136 {
        server: dns
            .options
            .get("server")
            .cloned()
            .ok_or("acme.dns.options.server is required")?,
        zone: dns.options.get("zone").cloned(),
        tsig: String::from_utf8_lossy(&tsig).trim().to_string(),
    })
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
    cert: &Certificate,
) -> Result<Issued, String> {
    let acme = cert.acme.as_ref().ok_or("no acme settings")?;
    if acme.challenge.as_deref().unwrap_or("dns-01") != "dns-01" {
        return Err("only the dns-01 challenge is built in so far".into());
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
    let mut records = Vec::new();
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
            let record = format!("_acme-challenge.{name}");
            let value = ch.key_authorization().dns_value();
            nsupdate(&dns, &record, Some(&value)).await?;
            records.push(record.clone());
            if !propagated(&dns, &record, &value).await {
                return Err(format!("{record} did not appear on {}", dns.server));
            }
            ch.set_ready().await.map_err(|e| e.to_string())?;
        }
    }
    let result = async {
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
    }
    .await;
    for r in records {
        if let Err(e) = nsupdate(&dns, &r, None).await {
            tracing::warn!(record = %r, error = %e, "cannot remove the challenge record");
        }
    }
    result
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
            match issue(core, events, cert).await {
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

    /// Issue a real certificate from Pebble, with challenges published to
    /// a BIND server by RFC 2136 (tests/acme/run.sh sets this up).
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "needs Pebble and BIND; run by tests/acme/run.sh"]
    async fn against_pebble() {
        let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"));
        let dir = tempfile::tempdir().unwrap();
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
        let mut c = sparewall_core::Coordinator::new(
            sparewall_core::Store::open(dir.path()).unwrap(),
            sys,
            id,
        );
        c.secret_set(
            "dns-tsig",
            env("ACME_TSIG").as_bytes(),
            SecretClass::Cluster,
        )
        .unwrap();
        let core: Core = Arc::new(std::sync::Mutex::new(c));
        let (events, _) = broadcast::channel(16);
        let cert: Certificate = serde_json::from_value(serde_json::json!({
            "names": ["fw.example.test", "vpn.example.test"],
            "acme": {
                "directory": env("ACME_DIRECTORY"),
                "ca": std::fs::read_to_string(env("ACME_CA")).unwrap(),
                "dns": {
                    "provider": "rfc2136",
                    "credentials": "secret:dns-tsig",
                    "options": {"server": env("ACME_DNS"), "zone": "example.test"}
                }
            }
        }))
        .unwrap();
        let issued = issue(&core, &events, &cert).await.unwrap();
        assert!(issued.chain_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.not_after > issued.not_before);
        // The listener can serve it.
        let ss = crate::http::self_signed(&dir.path().join("tls"), "fw1").unwrap();
        crate::http::Tls::new(&ss)
            .unwrap()
            .use_pem(&issued.chain_pem, &issued.key_pem)
            .unwrap();
        // A second order reuses the stored account.
        issue(&core, &events, &cert).await.unwrap();
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
}
