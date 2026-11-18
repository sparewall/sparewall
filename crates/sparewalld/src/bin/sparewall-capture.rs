//! The body of `sparewall-capture@.service` (#265): one packet capture
//! for the coordinator, on the connection systemd accepted for it from
//! `sparewall-capture.socket`, which only root reaches.
//!
//! It runs as a dynamic user holding only `CAP_NET_RAW`, in its own
//! SELinux domain, `sparewall_capture_t`. The coordinator sends one line,
//! `{"iface": …, "filter": …}`; this checks it again, starts tcpdump
//! writing a pcap to its stdout, and answers one line: `{"ok": true}`
//! once tcpdump has written the pcap's header, then the pcap as it
//! comes, or `{"error": …}` with what tcpdump said, if it stopped before.
//! Nothing is written to disk. The capture ends when the coordinator
//! closes the connection (its time and size limits are its own), when
//! tcpdump stops, or at the unit's `RuntimeMaxSec`.

use std::io::{BufRead, Read, Write};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};

#[path = "../capture_check.rs"]
mod capture_check;

const TCPDUMP: &str = "/usr/sbin/tcpdump";
/// A pcap's file header.
const HEADER: usize = 24;
/// The most of tcpdump's own messages kept for an error.
const MAX_MESSAGE: usize = 2048;

#[derive(serde::Deserialize)]
struct Request {
    iface: String,
    #[serde(default)]
    filter: Option<String>,
}

fn answer(out: &mut impl Write, v: serde_json::Value) -> std::io::Result<()> {
    writeln!(out, "{v}")?;
    out.flush()
}

/// Refuse the capture, saying why; `filter` when the filter is why, the
/// caller's to fix.
fn refuse_as(message: impl Into<String>, filter: bool) -> ExitCode {
    let message = message.into();
    eprintln!("sparewall-capture: {message}");
    let _ = answer(
        &mut std::io::stdout().lock(),
        serde_json::json!({ "error": message, "filter": filter }),
    );
    ExitCode::FAILURE
}

fn refuse(message: impl Into<String>) -> ExitCode {
    refuse_as(message, false)
}

fn kill(child: &Mutex<Child>) {
    let _ = child.lock().unwrap_or_else(|p| p.into_inner()).kill();
}

fn main() -> ExitCode {
    let mut line = String::new();
    if let Err(e) = std::io::stdin().lock().take(4096).read_line(&mut line) {
        return refuse(format!("reading the request: {e}"));
    }
    let req: Request = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => return refuse(format!("the request: {e}")),
    };
    if !capture_check::iface_ok(&req.iface)
        || !std::path::Path::new("/sys/class/net")
            .join(&req.iface)
            .exists()
    {
        return refuse(format!("no interface {:?}", req.iface));
    }
    let filter = req.filter.unwrap_or_default();
    if let Some(p) = capture_check::filter_problem(&filter) {
        return refuse_as(p, true);
    }

    // -U and --immediate-mode: each packet as it comes, the header first.
    // -n: no lookups. As a dynamic user, it changes to no other.
    let mut cmd = Command::new(TCPDUMP);
    cmd.args(["-i", &req.iface, "-n", "-U", "--immediate-mode", "-w", "-"]);
    if !filter.trim().is_empty() {
        cmd.args(["--", &filter]);
    }
    let mut child = match cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return refuse(format!("{TCPDUMP}: {e}")),
    };
    let mut pcap = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let child = Arc::new(Mutex::new(child));

    // tcpdump's messages go to the journal, and the first of them back
    // to the coordinator should it stop before the header.
    let said = Arc::new(Mutex::new(String::new()));
    let messages = {
        let said = said.clone();
        std::thread::spawn(move || {
            for l in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                eprintln!("{l}");
                let mut s = said.lock().unwrap_or_else(|p| p.into_inner());
                if s.len() < MAX_MESSAGE {
                    if !s.is_empty() {
                        s.push('\n');
                    }
                    s.push_str(l.strip_prefix("tcpdump: ").unwrap_or(&l));
                }
            }
        })
    };
    // The coordinator closing the connection ends the capture, even while
    // nothing matches the filter.
    {
        let child = child.clone();
        std::thread::spawn(move || {
            let mut b = [0u8; 64];
            while matches!(std::io::stdin().read(&mut b), Ok(n) if n > 0) {}
            kill(&child);
        });
    }

    let mut out = std::io::stdout().lock();
    let mut header = [0u8; HEADER];
    let started = pcap.read_exact(&mut header);
    if started.is_err() {
        let status = child.lock().unwrap_or_else(|p| p.into_inner()).wait();
        let _ = messages.join();
        let said = said.lock().unwrap_or_else(|p| p.into_inner()).clone();
        // tcpdump names the filter when the filter is what it refused.
        let filter = said.contains("filter expression");
        let how = match status {
            Ok(s) => match (s.code(), std::os::unix::process::ExitStatusExt::signal(&s)) {
                (Some(c), _) => format!("tcpdump exited with status {c}"),
                (None, Some(n)) => format!("tcpdump was killed by signal {n}"),
                _ => format!("tcpdump stopped ({s})"),
            },
            Err(e) => format!("tcpdump: {e}"),
        };
        let said = if said.is_empty() {
            how
        } else if filter {
            format!("filter: {said}")
        } else {
            format!("{how}: {said}")
        };
        return refuse_as(said, filter);
    }
    let mut copy = || -> std::io::Result<()> {
        answer(&mut out, serde_json::json!({ "ok": true }))?;
        out.write_all(&header)?;
        out.flush()?;
        let mut b = vec![0u8; 64 * 1024];
        loop {
            let n = pcap.read(&mut b)?;
            if n == 0 {
                return Ok(());
            }
            out.write_all(&b[..n])?;
            out.flush()?;
        }
    };
    // A failed write is the coordinator gone: the capture is over.
    let _ = copy();
    kill(&child);
    let _ = child.lock().unwrap_or_else(|p| p.into_inner()).wait();
    let _ = messages.join();
    ExitCode::SUCCESS
}
