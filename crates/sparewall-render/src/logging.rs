//! Rule logging and log forwarding (design: "Logging").
//!
//! Rules log with `log group N`; ulogd2 reads that NFLOG group and streams
//! each packet as JSON to the coordinator, which writes it to the journal
//! with structured fields. `logging.remote` forwards the journal off the
//! box with systemd-journal-upload.

use std::fmt::Write;

use sparewall_config::model::Document;
use sparewall_config::providers::{self, Role};

use crate::{Rendered, Service, Subsystem};

pub const ULOGD_UNIT: &str = "sparewall-ulogd.service";
pub const ULOGD_CONF: &str = "ulogd.conf";
pub const UPLOAD_UNIT: &str = "systemd-journal-upload.service";
pub const UPLOAD_CONF: &str = "journal-upload.conf";
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
                check: None,
            },
        );
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
                check: None,
            },
        );
    }
}
