//! Watch the kernel's audit stream for SELinux denials that concern the
//! coordinator, record them, and keep the `selinux` health check current
//! (sparewall_core::selinux). The audit multicast group delivers every
//! record, whether or not auditd runs, to a reader with CAP_AUDIT_READ.

use std::sync::Mutex;
use std::time::Duration;

use rustix::net::netlink::{self, SocketAddrNetlink};
use rustix::net::{AddressFamily, RecvFlags, SocketFlags, SocketType};
use serde_json::Value;
use sparewall_api::FirewallError;
use sparewall_core::selinux::{CHECK, Denials};
use tokio::sync::{broadcast, mpsc};

use crate::service::{Core, with_core, with_core_raw};

/// AUDIT_NLGRP_READLOG: read-only copies of every audit record.
const READLOG: u32 = 1;
const AUDIT_AVC: u16 = 1400;
const AUDIT_USER_AVC: u16 = 1107;
/// The netlink message header.
const NLMSG_HDRLEN: usize = 16;

/// Why the stream cannot be read, if it cannot.
static WATCH_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn enforcing() -> Option<bool> {
    std::fs::read_to_string("/sys/fs/selinux/enforce")
        .ok()
        .map(|s| s.trim() == "1")
}

fn check(d: &Denials) -> sparewall_core::Check {
    let e = WATCH_ERROR
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    d.check(enforcing(), e.as_deref())
}

/// The audit records in one netlink datagram, as text.
fn records(buf: &[u8]) -> Vec<(u16, String)> {
    let mut out = Vec::new();
    let mut rest = buf;
    while rest.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes(rest[0..4].try_into().expect("4 bytes")) as usize;
        let ty = u16::from_ne_bytes(rest[4..6].try_into().expect("2 bytes"));
        if len < NLMSG_HDRLEN || len > rest.len() {
            break;
        }
        let text = String::from_utf8_lossy(&rest[NLMSG_HDRLEN..len]);
        out.push((ty, text.trim_end_matches('\0').to_string()));
        // Messages are 4-byte aligned.
        rest = &rest[((len + 3) & !3).min(rest.len())..];
    }
    out
}

/// Read the stream in a thread of its own, passing on what concerns the
/// coordinator. Returns only if the socket cannot be opened.
fn read_stream(tx: mpsc::Sender<(String, bool)>) -> rustix::io::Result<()> {
    let fd = rustix::net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(netlink::AUDIT),
    )?;
    rustix::net::bind(&fd, &SocketAddrNetlink::new(0, READLOG))?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match rustix::net::recv(&fd, &mut buf[..], RecvFlags::empty()) {
            Ok((n, _)) => n,
            // A burst overflowed the socket buffer: records were lost, but
            // the stream goes on.
            Err(rustix::io::Errno::NOBUFS) => {
                tracing::warn!("audit records were dropped");
                continue;
            }
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e),
        };
        for (ty, text) in records(&buf[..n]) {
            if (ty == AUDIT_AVC || ty == AUDIT_USER_AVC)
                && let Some(d) = sparewall_core::selinux::relevant(&text)
                && tx.blocking_send(d).is_err()
            {
                return Ok(());
            }
        }
    }
}

pub async fn watch(core: Core, events: broadcast::Sender<Value>) {
    let (tx, mut rx) = mpsc::channel(256);
    std::thread::spawn(move || {
        if let Err(e) = read_stream(tx) {
            tracing::warn!(error = %e, "cannot watch for SELinux denials");
            *WATCH_ERROR.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.to_string());
        }
    });
    // Recheck now and then: the system's mode can change, and so can the
    // stream's state.
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        let mut new = Vec::new();
        tokio::select! {
            d = rx.recv() => match d {
                Some(d) => new.push(d),
                None => {
                    // The reader stopped; keep the check current.
                    tick.tick().await;
                }
            },
            _ = tick.tick() => {}
        }
        while let Ok(d) = rx.try_recv() {
            new.push(d);
        }
        for (record, _) in &new {
            tracing::warn!(record, "SELinux denial for the coordinator");
        }
        let _ = with_core_raw(&core, &events, move |c| {
            let root = c.store().root().to_path_buf();
            let mut d = Denials::read(&root);
            if !new.is_empty() {
                let now = jiff::Timestamp::now().to_string();
                for (record, permissive) in new {
                    d.record(record, permissive, now.clone());
                }
                if let Err(e) = d.write(&root) {
                    tracing::warn!(error = %e, "cannot record SELinux denials");
                }
            }
            c.set_named_checks(CHECK, vec![check(&d)]);
            Ok(())
        })
        .await;
    }
}

/// Acknowledge a check that stays degraded until someone has seen it.
pub async fn acknowledge(
    core: &Core,
    events: &broadcast::Sender<Value>,
    name: String,
    by: String,
) -> Result<(), FirewallError> {
    if name != CHECK {
        return Err(FirewallError::NotSupported {
            message: format!("health check {name} has nothing to acknowledge"),
        });
    }
    with_core(core, events, move |c| {
        let root = c.store().root().to_path_buf();
        let mut d = Denials::read(&root);
        d.acknowledge(by, jiff::Timestamp::now().to_string());
        d.write(&root)
            .map_err(|e| sparewall_core::Error::io(&root, e))?;
        c.set_named_checks(CHECK, vec![check(&d)]);
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(ty: u16, text: &str) -> Vec<u8> {
        let len = NLMSG_HDRLEN + text.len();
        let mut b = Vec::new();
        b.extend_from_slice(&(len as u32).to_ne_bytes());
        b.extend_from_slice(&ty.to_ne_bytes());
        b.extend_from_slice(&[0; 10]);
        b.extend_from_slice(text.as_bytes());
        b.resize((len + 3) & !3, 0);
        b
    }

    #[test]
    fn splits_a_datagram_into_records() {
        let mut b = msg(AUDIT_AVC, "audit(1.2:3): avc:  denied  { x }");
        b.extend(msg(1300, "audit(1.2:3): arch=c000003e syscall=41\0"));
        let r = records(&b);
        assert_eq!(r.len(), 2);
        assert_eq!(
            r[0],
            (AUDIT_AVC, "audit(1.2:3): avc:  denied  { x }".into())
        );
        assert_eq!(
            r[1],
            (1300, "audit(1.2:3): arch=c000003e syscall=41".into())
        );
        // A truncated one is dropped.
        assert!(records(&b[..10]).is_empty());
    }
}
