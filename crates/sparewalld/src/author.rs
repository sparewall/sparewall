//! Who made a change: the caller's login user (from the audit login UID,
//! which survives `sudo`) and the user it ran as.

use zlink::connection::Connection;
use zlink::connection::socket::{FetchPeerCredentials, Socket};

/// User name for a UID from /etc/passwd, or the number.
pub fn user_name(uid: u32) -> String {
    std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|p| {
            p.lines().find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() > 2 && f[2] == uid.to_string()).then(|| f[0].to_string())
            })
        })
        .or_else(|| {
            // bootc images ship users in /usr/lib/passwd (nss-altfiles).
            std::fs::read_to_string("/usr/lib/passwd")
                .ok()
                .and_then(|p| {
                    p.lines().find_map(|l| {
                        let f: Vec<&str> = l.split(':').collect();
                        (f.len() > 2 && f[2] == uid.to_string()).then(|| f[0].to_string())
                    })
                })
        })
        .unwrap_or_else(|| format!("uid {uid}"))
}

/// Describe a caller from its UID and PID.
pub fn describe(uid: u32, pid: i32) -> String {
    let login = std::fs::read_to_string(format!("/proc/{pid}/loginuid"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|l| *l != u32::MAX);
    let as_user = user_name(uid);
    match login {
        Some(l) if l != uid => format!("{} (as {as_user})", user_name(l)),
        _ => as_user,
    }
}

pub async fn of<S: Socket>(conn: &mut Connection<S>) -> String
where
    S::ReadHalf: FetchPeerCredentials,
{
    match conn.peer_credentials().await {
        Ok(c) => describe(
            c.unix_user_id().as_raw(),
            c.process_id().as_raw_nonzero().get(),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "cannot read peer credentials");
            "unknown".into()
        }
    }
}
