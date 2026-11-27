//! Forwarders over TLS (#356): health says whether they answer. Unbound
//! forwards to them with no fallback to plain DNS, so with none of them
//! answering, names don't resolve. Each node asks each forwarder's
//! addresses itself, as the resolver does: over TLS, the certificate
//! verified against the forwarder's name by the system trust store and
//! `dns.tls_ca`, a query for the root's name servers.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use sparewall_config::Document;
use sparewall_core::{Check, Level};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio_rustls::rustls::{self, RootCertStore};

use crate::service::{Core, with_core_raw};

const ROUND: Duration = Duration::from_secs(300);
const TIMEOUT: Duration = Duration::from_secs(10);
const CHECK: &str = "dns-tls";

/// One forwarder address to ask.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub forwarder: String,
    pub address: Ipv4Addr,
    pub port: u16,
    pub name: String,
}

/// The addresses the document forwards to over TLS, and its CA.
pub fn targets(doc: &Document) -> (Vec<Target>, Option<String>) {
    let Some(d) = doc.dns.as_ref().filter(|d| d.enabled) else {
        return (vec![], None);
    };
    let t = d
        .tls_forwarders
        .iter()
        .flat_map(|(n, f)| {
            f.addresses.iter().map(move |a| Target {
                forwarder: n.clone(),
                address: *a,
                port: f.port(),
                name: f.name.clone(),
            })
        })
        .collect();
    (t, d.tls_ca.clone())
}

/// A TLS client that trusts the system store and `ca`.
pub fn connector(ca: Option<&str>) -> Result<TlsConnector, String> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    if let Some(pem) = ca {
        for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let c = c.map_err(|e| format!("dns.tls_ca: {e}"))?;
            roots.add(c).map_err(|e| format!("dns.tls_ca: {e}"))?;
        }
    }
    if roots.is_empty() {
        return Err("no trusted certificates".into());
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// A query for the root's name servers, with its ID, as DNS over TCP
/// sends it: a two-byte length first.
fn query(id: u16) -> Vec<u8> {
    let mut m = Vec::with_capacity(19);
    m.extend_from_slice(&17u16.to_be_bytes());
    m.extend_from_slice(&id.to_be_bytes());
    // Recursion desired; one question.
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    // The root, NS, IN.
    m.extend_from_slice(&[0, 0, 2, 0, 1]);
    m
}

/// Whether a reply answers query `id`: its ID, the response bit, and
/// NOERROR, or what went wrong.
fn check_reply(id: u16, reply: &[u8]) -> Result<(), String> {
    if reply.len() < 12 {
        return Err("a reply too short to be DNS".into());
    }
    if u16::from_be_bytes([reply[0], reply[1]]) != id || reply[2] & 0x80 == 0 {
        return Err("a reply that doesn't answer the query".into());
    }
    match reply[3] & 0x0f {
        0 => Ok(()),
        2 => Err("SERVFAIL".into()),
        5 => Err("REFUSED".into()),
        r => Err(format!("rcode {r}")),
    }
}

/// Ask one forwarder address, over TLS.
pub async fn probe(t: &Target, tls: &TlsConnector) -> Result<(), String> {
    let name = ServerName::try_from(t.name.clone()).map_err(|e| format!("{}: {e}", t.name))?;
    let ask = async {
        let tcp = tokio::net::TcpStream::connect((t.address, t.port))
            .await
            .map_err(|e| e.to_string())?;
        let mut s = tls
            .connect(name, tcp)
            .await
            .map_err(|e| format!("TLS: {e}"))?;
        let mut id = [0u8; 2];
        getrandom::fill(&mut id).map_err(|e| e.to_string())?;
        let id = u16::from_be_bytes(id);
        s.write_all(&query(id)).await.map_err(|e| e.to_string())?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.map_err(|e| e.to_string())?;
        let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut reply).await.map_err(|e| e.to_string())?;
        check_reply(id, &reply)
    };
    tokio::time::timeout(TIMEOUT, ask)
        .await
        .map_err(|_| "no answer in 10 s".to_string())?
}

/// Health from each address's result: degraded while none answers.
pub fn assess(results: &[(Target, Result<(), String>)]) -> Vec<Check> {
    if results.is_empty() {
        return vec![];
    }
    let failed: Vec<String> = results
        .iter()
        .filter_map(|(t, r)| {
            r.as_ref().err().map(|e| {
                format!(
                    "{} ({}:{} as {}): {e}",
                    t.forwarder, t.address, t.port, t.name
                )
            })
        })
        .collect();
    let answering = results.len() - failed.len();
    let (level, message) = if answering == 0 {
        (
            Level::Degraded,
            format!(
                "no forwarder answers over TLS, so names don't resolve: {}",
                failed.join("; ")
            ),
        )
    } else if failed.is_empty() {
        (
            Level::Ok,
            format!(
                "{answering} of {} forwarder addresses answer over TLS",
                results.len()
            ),
        )
    } else {
        (
            Level::Ok,
            format!(
                "{answering} of {} forwarder addresses answer over TLS; {}",
                results.len(),
                failed.join("; ")
            ),
        )
    };
    vec![Check::new(CHECK, level, message)]
}

pub async fn dns_tls_loop(core: Core, events: broadcast::Sender<Value>) {
    let mut rx = events.subscribe();
    loop {
        let doc = with_core_raw(&core, &events, |c| c.active_document())
            .await
            .ok()
            .flatten();
        let (wanted, ca) = doc.as_ref().map(targets).unwrap_or_default();
        let checks = if wanted.is_empty() {
            vec![]
        } else {
            match connector(ca.as_deref()) {
                Ok(tls) => {
                    let results = futures_util::future::join_all(
                        wanted
                            .iter()
                            .map(|t| async { (t.clone(), probe(t, &tls).await) }),
                    )
                    .await;
                    for (t, r) in &results {
                        if let Err(e) = r {
                            tracing::warn!(
                                forwarder = t.forwarder,
                                address = %t.address,
                                error = e,
                                "a DNS forwarder does not answer over TLS"
                            );
                        }
                    }
                    assess(&results)
                }
                Err(e) => vec![Check::new(CHECK, Level::Degraded, e)],
            }
        };
        let _ = with_core_raw(&core, &events, move |c| {
            c.set_named_checks(CHECK, checks);
            Ok(())
        })
        .await;
        // Wake on an apply or a rollback, or after a round.
        let _ = tokio::time::timeout(ROUND, async {
            loop {
                match rx.recv().await {
                    Ok(v)
                        if ["applied", "rolled-back"]
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

    fn target(a: &str) -> Target {
        Target {
            forwarder: "quad9".into(),
            address: a.parse().unwrap(),
            port: 853,
            name: "dns.quad9.net".into(),
        }
    }

    #[test]
    fn the_query_asks_for_the_roots_name_servers() {
        let q = query(0x1234);
        assert_eq!(u16::from_be_bytes([q[0], q[1]]) as usize, q.len() - 2);
        assert_eq!(&q[2..4], &[0x12, 0x34]);
        assert_eq!(&q[q.len() - 5..], &[0, 0, 2, 0, 1]);
    }

    #[test]
    fn replies_are_checked() {
        let ok = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 13, 0, 0, 0, 0];
        assert_eq!(check_reply(0x1234, &ok), Ok(()));
        assert!(check_reply(0x9999, &ok).is_err(), "another ID");
        let mut q = ok;
        q[2] = 0x01;
        assert!(check_reply(0x1234, &q).is_err(), "not a response");
        let mut f = ok;
        f[3] = 0x82;
        assert_eq!(check_reply(0x1234, &f), Err("SERVFAIL".into()));
        assert!(check_reply(0x1234, &ok[..5]).is_err());
    }

    #[test]
    fn degraded_only_while_none_answers() {
        assert!(assess(&[]).is_empty());
        let a = target("9.9.9.9");
        let b = target("149.112.112.112");
        let all = assess(&[(a.clone(), Ok(())), (b.clone(), Ok(()))]);
        assert_eq!(all[0].level, Level::Ok);
        let some = assess(&[(a.clone(), Ok(())), (b.clone(), Err("TLS: bad".into()))]);
        assert_eq!(some[0].level, Level::Ok);
        assert!(
            some[0]
                .message
                .contains("149.112.112.112:853 as dns.quad9.net): TLS: bad")
        );
        let none = assess(&[(a, Err("refused".into())), (b, Err("TLS: bad".into()))]);
        assert_eq!(none[0].level, Level::Degraded);
        assert!(none[0].message.starts_with("no forwarder answers over TLS"));
    }

    /// A DNS-over-TLS server on loopback, with a certificate for
    /// `dot.test` from a CA of its own, answering every query with
    /// NOERROR. Returns its port and the CA's PEM.
    async fn dot_server() -> (u16, String) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["dot.test".into()])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    // The question back, as a response with no answers.
                    q[2] |= 0x80;
                    q[3] = 0x80;
                    let mut r = (q.len() as u16).to_be_bytes().to_vec();
                    r.extend_from_slice(&q);
                    let _ = s.write_all(&r).await;
                });
            }
        });
        (port, ca.pem())
    }

    #[tokio::test]
    async fn a_forwarder_answers_only_as_the_name_its_certificate_is_for() {
        let (port, ca) = dot_server().await;
        let t = |name: &str| Target {
            forwarder: "test".into(),
            address: Ipv4Addr::LOCALHOST,
            port,
            name: name.into(),
        };
        let trusted = connector(Some(&ca)).unwrap();
        assert_eq!(probe(&t("dot.test"), &trusted).await, Ok(()));
        let e = probe(&t("other.test"), &trusted).await.unwrap_err();
        assert!(e.starts_with("TLS:"), "{e}");
        // Without the CA, the system store doesn't know it.
        let system = connector(None).unwrap();
        let e = probe(&t("dot.test"), &system).await.unwrap_err();
        assert!(e.starts_with("TLS:"), "{e}");
    }

    #[test]
    fn a_ca_that_is_no_certificate_is_an_error() {
        assert!(
            connector(Some(
                "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"
            ))
            .is_err()
        );
    }
}
