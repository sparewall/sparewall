//! Short packet captures, as a pcap (#265).
//!
//! tcpdump runs in `sparewall-capture@.service`, never in the
//! coordinator: a dynamic user with only `CAP_NET_RAW`, in its own SELinux
//! domain, started for each connection to `sparewall-capture.socket`
//! (`/run/sparewall/capture.sock`, root's only). The coordinator connects,
//! sends the interface and filter, and passes the pcap on as it comes,
//! in replies of complete packets: a capture stopped at its size limit
//! leaves out the packet past it, so what the caller gets is always one
//! well-formed pcap file. Nothing is kept on the node. One capture runs
//! at a time; the time and size limits are the coordinator's, and the
//! unit's `RuntimeMaxSec` stops tcpdump should the coordinator not.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine as _;
use sparewall_api::{CaptureReply, FirewallError};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

pub use crate::capture_check::{filter_problem, iface_ok};

pub const SOCKET: &str = "/run/sparewall/capture.sock";
pub const DEFAULT_SECONDS: i64 = 30;
pub const MAX_SECONDS: i64 = 300;
pub const DEFAULT_SIZE: i64 = 8 << 20;
pub const MIN_SIZE: i64 = 64 << 10;
pub const MAX_SIZE: i64 = 32 << 20;
/// The most of the pcap one reply carries.
const CHUNK: usize = 64 << 10;
/// How long tcpdump may take to start (the helper's first line).
const START: Duration = Duration::from_secs(15);
/// A pcap's file header, and each packet's record header.
const FILE_HEADER: usize = 24;
const RECORD_HEADER: usize = 16;

fn invalid(e: impl Into<String>) -> FirewallError {
    FirewallError::ValidationFailed {
        errors: vec![e.into()],
    }
}

/// A capture's limits, checked: (seconds, bytes).
pub fn limits(seconds: Option<i64>, max_size: Option<i64>) -> Result<(i64, i64), FirewallError> {
    let s = seconds.unwrap_or(DEFAULT_SECONDS);
    if !(1..=MAX_SECONDS).contains(&s) {
        return Err(invalid(format!("seconds: 1 to {MAX_SECONDS}")));
    }
    let b = max_size.unwrap_or(DEFAULT_SIZE);
    if !(MIN_SIZE..=MAX_SIZE).contains(&b) {
        return Err(invalid(format!(
            "max_size: {} KiB to {} MiB",
            MIN_SIZE >> 10,
            MAX_SIZE >> 20
        )));
    }
    Ok((s, b))
}

static RUNNING: AtomicBool = AtomicBool::new(false);

/// The one capture a node runs, held while it does.
pub struct Slot;

impl Drop for Slot {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::SeqCst);
    }
}

pub fn slot(node: &str) -> Result<Slot, FirewallError> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err(FirewallError::ServiceUnavailable {
            service: "capture".into(),
            message: format!("a capture runs on {node} already: one at a time"),
        });
    }
    Ok(Slot)
}

/// The packet records in a pcap's bytes after its file header, as far
/// as they are complete.
struct Records {
    big_endian: bool,
}

impl Records {
    /// The byte order of a pcap file header (microsecond or nanosecond
    /// timestamps), or `None` for anything else.
    fn of(header: &[u8]) -> Option<Records> {
        let m: [u8; 4] = header.get(..4)?.try_into().ok()?;
        match u32::from_le_bytes(m) {
            0xa1b2_c3d4 | 0xa1b2_3c4d => Some(Records { big_endian: false }),
            0xd4c3_b2a1 | 0x4d3c_b2a1 => Some(Records { big_endian: true }),
            _ => None,
        }
    }

    /// The length of the first record in `b`, if all of it is there.
    fn next(&self, b: &[u8]) -> Option<usize> {
        let l: [u8; 4] = b.get(8..12)?.try_into().ok()?;
        let l = if self.big_endian {
            u32::from_be_bytes(l)
        } else {
            u32::from_le_bytes(l)
        } as usize;
        let n = RECORD_HEADER + l;
        (b.len() >= n).then_some(n)
    }
}

/// What a capture is asked for, checked.
pub struct Request {
    pub iface: String,
    pub filter: Option<String>,
    pub seconds: i64,
    pub max_size: i64,
}

pub type Captured =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<CaptureReply, FirewallError>> + Send>>;

/// Run a capture: its replies as they come, each of complete packets,
/// the last with why it ended. `audit` names it in the journal's record
/// of its end. Holds `slot` until it ends or the caller goes.
pub fn run(req: Request, slot: Slot, audit: String) -> Captured {
    run_at(std::path::PathBuf::from(SOCKET), req, slot, audit)
}

fn run_at(
    socket: std::path::PathBuf,
    req: Request,
    slot: impl Send + 'static,
    audit: String,
) -> Captured {
    let (tx, rx) = mpsc::channel::<Result<CaptureReply, FirewallError>>(4);
    tokio::spawn(async move {
        let _slot = slot;
        let r = capture(&socket, &req, &tx).await;
        match r {
            Ok((bytes, packets, end)) => {
                tracing::info!(capture = audit, bytes, packets, end, "capture ended");
                let _ = tx
                    .send(Ok(CaptureReply {
                        data: String::new(),
                        bytes,
                        packets,
                        end: Some(end.into()),
                    }))
                    .await;
            }
            Err(e) => {
                tracing::info!(capture = audit, error = ?e, "capture failed");
                let _ = tx.send(Err(e)).await;
            }
        }
    });
    Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
}

fn unavailable(message: impl Into<String>) -> FirewallError {
    FirewallError::ServiceUnavailable {
        service: "capture".into(),
        message: message.into(),
    }
}

/// The capture itself: (bytes, packets, why it ended). Ends early,
/// as `Ok`, when the caller goes.
async fn capture(
    socket: &std::path::Path,
    req: &Request,
    tx: &mpsc::Sender<Result<CaptureReply, FirewallError>>,
) -> Result<(i64, i64, &'static str), FirewallError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(req.seconds as u64);
    let max = req.max_size as usize;
    if !iface_ok(&req.iface) {
        return Err(invalid(format!("no interface {:?}", req.iface)));
    }
    let conn = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(|e| unavailable(format!("{}: {e}", socket.display())))?;
    let (r, mut w) = conn.into_split();
    let mut r = BufReader::new(r);
    let line = serde_json::json!({ "iface": req.iface, "filter": req.filter });
    w.write_all(format!("{line}\n").as_bytes())
        .await
        .map_err(|e| unavailable(format!("the capture helper: {e}")))?;
    let mut first = String::new();
    match tokio::time::timeout(START, (&mut r).take(4096).read_line(&mut first)).await {
        Err(_) => return Err(unavailable("tcpdump did not start")),
        Ok(Err(e)) => return Err(unavailable(format!("the capture helper: {e}"))),
        Ok(Ok(_)) => {}
    }
    let first: serde_json::Value = serde_json::from_str(&first)
        .map_err(|_| unavailable("the capture helper gave no answer"))?;
    if let Some(e) = first.get("error").and_then(|e| e.as_str()) {
        // The interface was checked here: what tcpdump refuses is the
        // filter, in its own words.
        return Err(invalid(format!("filter: {e}")));
    }
    if first.get("ok").and_then(|o| o.as_bool()) != Some(true) {
        return Err(unavailable("the capture helper gave no answer"));
    }

    let mut buf: Vec<u8> = Vec::with_capacity(2 * CHUNK);
    let mut records: Option<Records> = None;
    let (mut bytes, mut packets) = (0usize, 0i64);
    let mut read = vec![0u8; CHUNK];
    loop {
        let n = tokio::select! {
            n = r.read(&mut read) => n.map_err(|e| unavailable(format!("the capture: {e}")))?,
            () = tokio::time::sleep_until(deadline) => return Ok((bytes as i64, packets, "time")),
            () = tx.closed() => return Ok((bytes as i64, packets, "gone")),
        };
        buf.extend_from_slice(&read[..n]);
        // Pass on what of buf is complete and fits, a chunk at a time:
        // the file header, then whole records, up to the size limit.
        loop {
            let mut take = 0;
            let mut got = 0;
            if records.is_none() {
                if buf.len() < FILE_HEADER {
                    break;
                }
                records =
                    Some(Records::of(&buf).ok_or_else(|| unavailable("tcpdump wrote no pcap"))?);
                take = FILE_HEADER;
            }
            let rec = records.as_ref().expect("set");
            let mut full = false;
            while take < CHUNK {
                let Some(l) = rec.next(&buf[take..]) else {
                    break;
                };
                if bytes + take + l > max {
                    full = true;
                    break;
                }
                take += l;
                got += 1;
            }
            if take > 0 {
                bytes += take;
                packets += got;
                let data = base64::engine::general_purpose::STANDARD.encode(&buf[..take]);
                buf.drain(..take);
                let reply = CaptureReply {
                    data,
                    bytes: bytes as i64,
                    packets,
                    end: None,
                };
                if tx.send(Ok(reply)).await.is_err() {
                    return Ok((bytes as i64, packets, "gone"));
                }
            }
            // Dropping the connection stops tcpdump.
            if full {
                return Ok((bytes as i64, packets, "size"));
            }
            if take == 0 {
                break;
            }
        }
        if n == 0 {
            return Ok((bytes as i64, packets, "stopped"));
        }
    }
}

/// A capture as one reply, for a call without `more`: its pcap whole.
pub fn gather(s: Captured) -> Captured {
    Box::pin(futures_util::stream::once(async move {
        use futures_util::StreamExt;
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut s = s;
        let mut all = Vec::new();
        let mut last = CaptureReply::default();
        while let Some(r) = s.next().await {
            let r = r?;
            all.extend(
                b64.decode(&r.data)
                    .map_err(|e| unavailable(format!("the capture's data: {e}")))?,
            );
            last = r;
        }
        last.data = b64.encode(&all);
        Ok(last)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    #[test]
    fn limits_are_bounded() {
        assert_eq!(limits(None, None).unwrap(), (DEFAULT_SECONDS, DEFAULT_SIZE));
        assert!(limits(Some(0), None).is_err());
        assert!(limits(Some(MAX_SECONDS + 1), None).is_err());
        assert!(limits(None, Some(MIN_SIZE - 1)).is_err());
        assert!(limits(None, Some(MAX_SIZE + 1)).is_err());
        assert_eq!(limits(Some(5), Some(MIN_SIZE)).unwrap(), (5, MIN_SIZE));
    }

    #[test]
    fn one_capture_at_a_time() {
        let a = slot("fw1").unwrap();
        assert!(
            matches!(slot("fw1"), Err(FirewallError::ServiceUnavailable { message, .. })
            if message.contains("one at a time"))
        );
        drop(a);
        drop(slot("fw1").unwrap());
    }

    fn header() -> Vec<u8> {
        let mut h = 0xa1b2_c3d4u32.to_le_bytes().to_vec();
        h.extend([2, 0, 4, 0]);
        h.extend([0; 8]);
        h.extend(65535u32.to_le_bytes());
        h.extend(1u32.to_le_bytes());
        h
    }

    fn record(len: usize) -> Vec<u8> {
        let mut r = vec![0u8; 8];
        r.extend((len as u32).to_le_bytes());
        r.extend((len as u32).to_le_bytes());
        r.extend(vec![0xab; len]);
        r
    }

    /// A fake helper: answers `first`, then writes `body` in small
    /// pieces, and holds the connection open until the capture ends.
    async fn helper(first: &'static str, body: Vec<u8>) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capture.sock");
        let l = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (c, _) = l.accept().await.unwrap();
            let (r, mut w) = c.into_split();
            let mut r = BufReader::new(r);
            let mut req = String::new();
            r.read_line(&mut req).await.unwrap();
            assert!(req.contains("\"iface\":\"eth0\""), "{req}");
            w.write_all(first.as_bytes()).await.unwrap();
            for piece in body.chunks(7) {
                if w.write_all(piece).await.is_err() {
                    return;
                }
            }
            // Until the coordinator closes.
            let mut b = [0u8; 1];
            let _ = r.read(&mut b).await;
        });
        (dir, path)
    }

    fn req(seconds: i64, max_size: i64) -> Request {
        Request {
            iface: "eth0".into(),
            filter: Some("icmp".into()),
            seconds,
            max_size,
        }
    }

    async fn all(s: Captured) -> (Vec<u8>, Result<CaptureReply, FirewallError>) {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut data = Vec::new();
        let mut s = s;
        let mut last = Err(unavailable("nothing"));
        while let Some(r) = s.next().await {
            if let Ok(r) = &r {
                data.extend(b64.decode(&r.data).unwrap());
            }
            last = r;
        }
        (data, last)
    }

    /// A capture is whole packets, cut before the one past the size
    /// limit, and the slot is free once it ends.
    #[tokio::test]
    async fn a_capture_stops_at_its_size_before_a_packet() {
        let mut body = header();
        for _ in 0..100 {
            body.extend(record(1000));
        }
        let (_d, path) = helper("{\"ok\":true}\n", body.clone()).await;
        let max = FILE_HEADER + 10 * (RECORD_HEADER + 1000) + 500;
        let s = run_at(path, req(30, max as i64), (), "t".into());
        let (data, last) = all(s).await;
        let last = last.unwrap();
        assert_eq!(last.end.as_deref(), Some("size"));
        assert_eq!(last.packets, 10);
        assert_eq!(data, body[..FILE_HEADER + 10 * (RECORD_HEADER + 1000)]);
        assert_eq!(last.bytes as usize, data.len());
    }

    #[tokio::test]
    async fn a_capture_stops_at_its_time() {
        let mut body = header();
        body.extend(record(60));
        let (_d, path) = helper("{\"ok\":true}\n", body.clone()).await;
        let s = run_at(path, req(1, MIN_SIZE), (), "t".into());
        let (data, last) = all(gather(s)).await;
        let last = last.unwrap();
        assert_eq!(last.end.as_deref(), Some("time"));
        assert_eq!((last.packets, data), (1, body));
    }

    #[tokio::test]
    async fn tcpdump_refusing_the_filter_says_why() {
        let (_d, path) = helper(
            "{\"error\":\"syntax error in filter expression\"}\n",
            vec![],
        )
        .await;
        let s = run_at(path, req(5, MIN_SIZE), (), "t".into());
        let (_, last) = all(s).await;
        assert!(
            matches!(last, Err(FirewallError::ValidationFailed { errors })
            if errors[0] == "filter: syntax error in filter expression")
        );
    }
}
