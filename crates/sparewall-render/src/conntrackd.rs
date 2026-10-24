//! conntrackd in FTFW mode over the sync tunnel (design: "conntrackd").

use std::fmt::Write;

use sparewall_config::model::Document;
use sparewall_config::topology::SYNC_TUNNEL_IFACE;

use crate::networkd::sync_tunnel_addr;
use crate::{Rendered, Service, Subsystem};

pub const UNIT: &str = "conntrackd.service";
pub const CONF: &str = "conntrackd.conf";
pub const PORT: u16 = 3780;
/// The control socket the failover sequence talks to.
pub const SOCKET: &str = "/run/conntrackd.ctl";

pub(crate) fn render(doc: &Document, node: &str, out: &mut Rendered) {
    if !doc.is_pair() {
        return;
    }
    let peer = doc.peer_of(node).expect("pair");
    // No tunnel until both sync keys are in the document.
    if !doc.cluster.sync_keys.contains_key(peer) {
        return;
    }
    let (Some(own), Some(other)) = (sync_tunnel_addr(doc, node), sync_tunnel_addr(doc, peer))
    else {
        return;
    };
    let mut ignore: Vec<String> = vec![
        "127.0.0.1".into(),
        own.addr().to_string(),
        other.addr().to_string(),
    ];
    for net in doc.networks.values() {
        for a in net.addresses.values() {
            ignore.push(a.0.addr().to_string());
        }
    }
    ignore.sort();
    ignore.dedup();
    let mut s = String::from(crate::HEADER);
    s.push_str("Sync {\n    Mode FTFW {\n        DisableExternalCache Off\n        CommitTimeout 1800\n        PurgeTimeout 5\n    }\n");
    writeln!(
        s,
        "    UDP {{\n        IPv4_address {}\n        IPv4_Destination_Address {}\n        Port {PORT}\n        \
         Interface {SYNC_TUNNEL_IFACE}\n        SndSocketBuffer 1249280\n        RcvSocketBuffer 1249280\n        \
         Checksum on\n    }}\n}}\n",
        own.addr(),
        other.addr()
    )
    .unwrap();
    let ct = doc.cluster.conntrack.as_ref();
    let limit = ct.and_then(|c| c.max).unwrap_or(262_144);
    writeln!(
        s,
        "General {{\n    Systemd on\n    HashSize {}\n    HashLimit {}\n    LogFile off\n    Syslog on\n    \
         LockFile /run/conntrackd.lock\n    UNIX {{\n        Path {SOCKET}\n    }}\n    \
         NetlinkBufferSize 2097152\n    NetlinkBufferSizeMaxGrowth 8388608\n    \
         NetlinkOverrunResync On\n    NetlinkEventsReliable On\n    \
         Filter From Userspace {{\n        Protocol Accept {{\n            TCP\n            UDP\n            ICMP\n        }}\n        \
         Address Ignore {{",
        (limit / 8).max(8192),
        u64::from(limit) * 2
    )
    .unwrap();
    for a in ignore {
        writeln!(s, "            IPv4_address {a}").unwrap();
    }
    s.push_str("        }\n    }\n}\n");
    out.add(Subsystem::Conntrackd, CONF, s);
    out.meta.services.insert(
        "conntrack-sync".into(),
        Service {
            provider: "conntrackd".into(),
            unit: UNIT.into(),
            subsystem: Subsystem::Conntrackd,
            reload: false,
            management: false,
            check: None,
        },
    );
}
