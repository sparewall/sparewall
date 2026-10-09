//! chrony on the host, as NTP client and LAN time server (design:
//! "Defaults in detail": systemd-timesyncd cannot serve time).

use std::fmt::Write;

use sparewall_config::model::Document;

use crate::{CheckSpec, Rendered, Service, Subsystem};

pub const UNIT: &str = "chronyd.service";
pub const CONF: &str = "chrony.conf";
pub const DEFAULT_POOL: &str = "2.fedora.pool.ntp.org";

fn base(servers: &[String]) -> String {
    let mut s = String::from(crate::HEADER);
    if servers.is_empty() {
        writeln!(s, "pool {DEFAULT_POOL} iburst").unwrap();
    }
    for srv in servers {
        let kind = if srv.contains("pool") {
            "pool"
        } else {
            "server"
        };
        writeln!(s, "{kind} {srv} iburst").unwrap();
    }
    s.push_str(
        "driftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync\n\
         ntsdumpdir /var/lib/chrony\nleapseclist /usr/share/zoneinfo/leap-seconds.list\n\
         logdir /var/log/chrony\n",
    );
    s
}

fn service(out: &mut Rendered) {
    out.meta.services.insert(
        "ntp".into(),
        Service {
            provider: "chrony".into(),
            unit: UNIT.into(),
            subsystem: Subsystem::Ntp,
            reload: false,
            check: Some(CheckSpec {
                container: None,
                mount: "/run/sparewall/ntp".into(),
                command: vec![
                    "chronyd".into(),
                    "-p".into(),
                    "-f".into(),
                    format!("/run/sparewall/ntp/{CONF}"),
                ],
                overrides: Default::default(),
            }),
        },
    );
}

pub(crate) fn render(doc: &Document, node: &str, out: &mut Rendered) {
    let ntp = doc.ntp.as_ref();
    let mut s = base(ntp.map(|n| n.servers.as_slice()).unwrap_or_default());
    for n in ntp.map(|n| n.serve.as_slice()).unwrap_or_default() {
        if let Some(sub) = doc.subnet(n, node) {
            writeln!(s, "allow {sub}").unwrap();
        }
    }
    out.add(Subsystem::Ntp, CONF, s);
    service(out);
}

pub(crate) fn render_bootstrap(out: &mut Rendered) {
    out.add(Subsystem::Ntp, CONF, base(&[]));
    service(out);
}
