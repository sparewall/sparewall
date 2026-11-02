//! Rule logging and log forwarding (design: "Logging").
//!
//! Rules log with `log group N`; ulogd2 reads that NFLOG group and streams
//! each packet as JSON to the coordinator, which writes it to the journal
//! with structured fields. `logging.remote` forwards the journal off the
//! box with systemd-journal-upload, or with rsyslog to a syslog collector.

use std::fmt::Write;

use sparewall_config::model::Document;
use sparewall_config::providers::{self, Role};

use crate::{Rendered, Service, Subsystem};

pub const ULOGD_UNIT: &str = "sparewall-ulogd.service";
pub const ULOGD_CONF: &str = "ulogd.conf";
pub const UPLOAD_UNIT: &str = "systemd-journal-upload.service";
pub const UPLOAD_CONF: &str = "journal-upload.conf";
/// The stock rsyslog unit; a drop-in points it at [`SYSLOG_CONF`] and keeps
/// it stopped without one.
pub const SYSLOG_UNIT: &str = "rsyslog.service";
pub const SYSLOG_CONF: &str = "rsyslog.conf";
/// The collector's CA, when `logging.remote.ca` names one.
pub const SYSLOG_CA: &str = "syslog-ca.pem";
/// rsyslog's client certificate and key (`logging.remote.certificate`),
/// in [`crate::SECRETS_DIR`], where the coordinator installs them.
pub const SYSLOG_CLIENT_CERT: &str = "syslog-client.pem";
pub const SYSLOG_CLIENT_KEY: &str = "syslog-client.key";
const RUN_DIR: &str = "/run/sparewall/logging";
/// The trust store used when the document names no CA.
const SYSTEM_CA: &str = "/etc/pki/tls/certs/ca-bundle.crt";
/// The cap on what the disk-assisted queue holds while the collector is
/// unreachable (under /var/lib/rsyslog). When it is full, rsyslog stops
/// reading the journal, and carries on from there once the collector is
/// back: what the journal still holds is not lost.
const QUEUE_DISK: &str = "256m";
/// Where ulogd streams JSON packet records.
pub const RULES_SOCKET: &str = "/run/sparewall/rules.sock";
const PLUGINS: &str = "/usr/lib64/ulogd";

fn logs_anything(doc: &Document) -> bool {
    doc.policy
        .values()
        .any(|p| p.log || p.rules.values().any(|r| r.log))
        || doc.forwards.values().any(|f| f.log)
}

pub(crate) fn render(doc: &Document, out: &mut Rendered) {
    let group = doc.logging.as_ref().and_then(|l| l.group).unwrap_or(0);
    if logs_anything(doc) {
        let mut s = String::from(crate::HEADER);
        s.push_str("[global]\nlogfile=\"stdout\"\nloglevel=3\n");
        for p in [
            "ulogd_inppkt_NFLOG",
            "ulogd_raw2packet_BASE",
            "ulogd_filter_IFINDEX",
            "ulogd_filter_IP2STR",
            "ulogd_output_JSON",
        ] {
            writeln!(s, "plugin=\"{PLUGINS}/{p}.so\"").unwrap();
        }
        s.push_str("stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,json1:JSON\n\n");
        writeln!(s, "[log1]\ngroup={group}\n").unwrap();
        writeln!(s, "[json1]\nmode=\"unix\"\nfile=\"{RULES_SOCKET}\"\nsync=1").unwrap();
        out.add(Subsystem::Logging, ULOGD_CONF, s);
        out.meta.services.insert(
            "rule-logging".into(),
            Service {
                provider: "ulogd".into(),
                unit: ULOGD_UNIT.into(),
                subsystem: Subsystem::Logging,
                reload: false,
                management: false,
                check: None,
            },
        );
    }
    if let Some(remote) = doc.logging.as_ref().and_then(|l| l.remote.as_ref())
        && providers::chosen(doc, Role::LogForwarding) == Some("syslog")
    {
        syslog(remote, out);
    }
    if let Some(remote) = doc.logging.as_ref().and_then(|l| l.remote.as_ref())
        && providers::chosen(doc, Role::LogForwarding) == Some("journal-upload")
    {
        let url = if remote.destination.contains("://") {
            remote.destination.clone()
        } else {
            let scheme = if remote.tls { "https" } else { "http" };
            format!("{scheme}://{}", remote.destination)
        };
        let s = format!("{}[Upload]\nURL={url}\n", crate::HEADER);
        out.add(Subsystem::Logging, UPLOAD_CONF, s);
        out.meta.services.insert(
            "log-forwarding".into(),
            Service {
                provider: "journal-upload".into(),
                unit: UPLOAD_UNIT.into(),
                subsystem: Subsystem::Logging,
                reload: false,
                management: false,
                check: None,
            },
        );
    }
}

/// Quote a value for RainerScript (validation keeps quotes and
/// backslashes out of hosts; this keeps the file well-formed regardless).
fn q(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

/// rsyslog reading the journal and forwarding it, RFC 5424, to the
/// collector (`logging.remote.provider: syslog`, #147).
fn syslog(remote: &sparewall_config::model::RemoteLog, out: &mut Rendered) {
    let Some((host, port)) = sparewall_config::validate::syslog_target(&remote.destination) else {
        return;
    };
    let protocol = remote.protocol.as_deref().unwrap_or("udp");
    let port = port.unwrap_or(match (protocol, remote.tls) {
        ("relp", _) => 2514,
        (_, true) => 6514,
        _ => 514,
    });
    let ca = if remote.ca.is_some() {
        format!("{RUN_DIR}/{SYSLOG_CA}")
    } else {
        SYSTEM_CA.to_string()
    };
    let client = remote.certificate.is_some().then(|| {
        (
            format!("{}/{SYSLOG_CLIENT_CERT}", crate::SECRETS_DIR),
            format!("{}/{SYSLOG_CLIENT_KEY}", crate::SECRETS_DIR),
        )
    });
    let mut s = String::from(crate::HEADER);
    s.push_str(
        "# Only forwarding: nothing is written locally; the journal keeps\n\
         # everything.\n\
         global(workDirectory=\"/var/lib/rsyslog\")\n\
         # From the journal's tail at the first start (not its whole\n\
         # history), then from where it left off. No rate limit: rule hits\n\
         # can be many, and the queue below bounds what is kept.\n\
         module(load=\"imjournal\" StateFile=\"sparewall-imjournal.state\"\n       \
         IgnorePreviousMessages=\"on\" Ratelimit.Interval=\"0\")\n",
    );
    if protocol == "relp" {
        s.push_str("module(load=\"omrelp\")\n");
    }
    // Rule hits carry the rule and the packet as journal fields (F_RULE,
    // F_PACKET), not in the message; a syslog collector sees only the
    // message, so they are appended to it.
    s.push_str(
        "\ntemplate(name=\"sparewall\" type=\"string\"\n         \
         string=\"<%PRI%>1 %TIMESTAMP:::date-rfc3339% %HOSTNAME% %APP-NAME% %PROCID% %MSGID% - %$.msg%\\n\")\n\n\
         if $!F_RULE != \"\" then {\n    \
         set $.msg = $msg & \" rule=\" & $!F_RULE & \" \" & $!F_PACKET;\n\
         } else {\n    \
         set $.msg = $msg;\n\
         }\n\n",
    );
    let mut a: Vec<(&str, String)> = Vec::new();
    match protocol {
        "relp" => {
            a.push(("type", q("omrelp")));
            a.push(("target", q(host)));
            a.push(("port", q(&port.to_string())));
            if remote.tls {
                a.push(("tls", q("on")));
                a.push(("tls.caCert", q(&ca)));
                a.push(("tls.authMode", q("name")));
                a.push(("tls.permittedPeer", format!("[{}]", q(host))));
                if let Some((cert, key)) = &client {
                    a.push(("tls.myCert", q(cert)));
                    a.push(("tls.myPrivKey", q(key)));
                }
            }
        }
        _ => {
            a.push(("type", q("omfwd")));
            a.push(("target", q(host)));
            a.push(("port", q(&port.to_string())));
            a.push(("protocol", q(protocol)));
            if remote.tls {
                // RFC 5425: TLS, the peer's name checked, octet counting.
                a.push(("StreamDriver", q("gtls")));
                a.push(("StreamDriverMode", q("1")));
                a.push(("StreamDriverAuthMode", q("x509/name")));
                a.push(("StreamDriverPermittedPeers", q(host)));
                a.push(("StreamDriver.CAFile", q(&ca)));
                if let Some((cert, key)) = &client {
                    a.push(("StreamDriver.CertFile", q(cert)));
                    a.push(("StreamDriver.KeyFile", q(key)));
                }
                a.push(("TCP_Framing", q("octet-counted")));
            }
        }
    }
    a.push(("template", q("sparewall")));
    // While the collector is unreachable, messages wait in memory, then on
    // disk up to the cap, and are sent when it is back; they also survive
    // a restart.
    a.push(("queue.type", q("LinkedList")));
    a.push(("queue.size", q("100000")));
    a.push(("queue.filename", q("sparewall-forward")));
    a.push(("queue.maxDiskSpace", q(QUEUE_DISK)));
    a.push(("queue.saveOnShutdown", q("on")));
    a.push(("action.resumeRetryCount", q("-1")));
    a.push(("action.resumeInterval", q("10")));
    s.push_str("action(");
    for (i, (k, v)) in a.iter().enumerate() {
        if i > 0 {
            s.push_str("\n       ");
        }
        write!(s, "{k}={v}").unwrap();
    }
    s.push_str(")\n");
    out.add(Subsystem::Logging, SYSLOG_CONF, s);
    if let Some(pem) = &remote.ca {
        let mut pem = pem.clone();
        if !pem.ends_with('\n') {
            pem.push('\n');
        }
        out.add(Subsystem::Logging, SYSLOG_CA, pem);
    }
    out.meta.services.insert(
        "log-forwarding".into(),
        Service {
            provider: "syslog".into(),
            unit: SYSLOG_UNIT.into(),
            subsystem: Subsystem::Logging,
            reload: false,
            management: false,
            check: None,
        },
    );
}
