//! Firewall rule hits from ulogd2 (JSON over a Unix socket) into the
//! journal as structured entries (design: "Logging").

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;

/// One rule hit: the rule (from the nft log prefix) and the packet.
pub fn describe(v: &Value) -> Option<(String, String)> {
    let prefix = v["oob.prefix"].as_str()?.trim().to_string();
    let s = |k: &str| {
        v[k].as_str()
            .map(str::to_string)
            .or_else(|| v[k].as_u64().map(|n| n.to_string()))
    };
    let proto = match v["ip.protocol"].as_u64() {
        Some(6) => "tcp".to_string(),
        Some(17) => "udp".to_string(),
        Some(1) => "icmp".to_string(),
        Some(n) => n.to_string(),
        None => "?".into(),
    };
    let src = s("src_ip").unwrap_or_default();
    let dst = s("dest_ip").unwrap_or_default();
    let ports = match (s("src_port"), s("dest_port")) {
        (Some(a), Some(b)) => format!(" {src}:{a} -> {dst}:{b}"),
        _ => format!(" {src} -> {dst}"),
    };
    let ifs = format!(
        " in={} out={}",
        s("oob.in").unwrap_or_default(),
        s("oob.out").unwrap_or_default()
    );
    Some((prefix, format!("{proto}{ports}{ifs}")))
}

/// Bind the socket ulogd2 sends rule hits to. This happens before the
/// start-up activation, which restarts ulogd2: it connects once, at
/// start, and exits if nothing is listening, so the services check would
/// fail until systemd started it again.
pub fn bind(path: &Path) -> Option<std::os::unix::net::UnixListener> {
    let _ = std::fs::remove_file(path);
    let l = std::os::unix::net::UnixListener::bind(path)
        .and_then(|l| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            l.set_nonblocking(true)?;
            Ok(l)
        })
        .inspect_err(|e| {
            tracing::error!(path = %path.display(), error = %e, "cannot listen for rule logs");
        })
        .ok()?;
    Some(l)
}

/// Write the rule hits arriving on `l` to the journal.
pub async fn listener(l: Option<std::os::unix::net::UnixListener>) {
    let Some(l) = l.and_then(|l| UnixListener::from_std(l).ok()) else {
        return std::future::pending().await;
    };
    loop {
        let Ok((stream, _)) = l.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let mut lines = BufReader::new(stream).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                if let Some((rule, packet)) = describe(&v) {
                    tracing::info!(target: "sparewall::rules", rule = %rule, packet = %packet, record = %line, "rule hit");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_a_hit() {
        let v: Value = serde_json::from_str(
            r#"{"timestamp":"2026-10-09T00:00:00","oob.prefix":"guests->users:default ","oob.in":"guests","oob.out":"users","ip.protocol":6,"src_ip":"198.51.100.100","dest_ip":"192.0.2.20","src_port":40000,"dest_port":22}"#,
        )
        .unwrap();
        let (rule, pkt) = describe(&v).unwrap();
        assert_eq!(rule, "guests->users:default");
        assert_eq!(
            pkt,
            "tcp 198.51.100.100:40000 -> 192.0.2.20:22 in=guests out=users"
        );
    }
}
