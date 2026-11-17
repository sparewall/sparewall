//! The peer's diagnostics, through this node (#268). In a pair, each
//! `org.sparewall.Diagnostics` method takes `node`: naming the peer runs
//! the call there, over the sync tunnel, where the peer's listener serves
//! the same read-only interface beside `org.sparewall.Peer`. The call is
//! checked against the caller's role here, as any other; the peer trusts
//! the tunnel, as it does for the rest of its API, and runs a call that
//! came through it only locally.
//!
//! A reply comes back as it is. A stream (a follow, or a tool with
//! `more`) is relayed by a task that owns the tunnel connection: it ends
//! when the peer's stream does, when the caller goes, or with
//! `PeerUnreachable` when the tunnel does.

use std::pin::Pin;

use futures_util::{Stream, StreamExt};
use sparewall_api::{FirewallError, ToolReply};
use tokio::sync::mpsc;
use zlink::Reply;

use crate::peer::Link;

/// The node a diagnostics call runs on.
pub enum Where {
    Here,
    Peer { link: Link, peer: String },
}

pub type Conn = zlink::Connection<zlink::tokio::unix::Stream>;

/// What a relayed stream yields, as the local methods' streams do.
pub type Item<T> = Result<Reply<T>, FirewallError>;
pub type Relayed<T> = Pin<Box<dyn Stream<Item = Item<T>> + Send>>;

/// A connection to the peer's listener.
pub async fn connect(link: Link, peer: &str) -> Result<Conn, FirewallError> {
    crate::peer::connect(link).await.map_err(|e| {
        tracing::debug!(peer, error = %e, "cannot reach the peer for diagnostics");
        FirewallError::PeerUnreachable { peer: peer.into() }
    })
}

/// The peer's reply to a call, or why there is none.
pub fn reply<T>(
    peer: &str,
    r: zlink::Result<Result<T, FirewallError>>,
) -> Result<T, FirewallError> {
    r.map_err(|e| failed(peer, e))?
}

/// A call to the peer that failed below its own errors: the tunnel went,
/// or the peer, older than 0.7.0, doesn't serve diagnostics.
fn failed(peer: &str, e: zlink::Error) -> FirewallError {
    FirewallError::ApplyFailed {
        message: format!("{peer}: {e}"),
    }
}

/// A method call as zlink sends it: the method's name and parameters.
#[derive(Debug, serde::Serialize)]
struct Method {
    method: &'static str,
    parameters: serde_json::Map<String, serde_json::Value>,
}

/// Parameters for a call, leaving out those not given.
pub fn params<const N: usize>(
    p: [(&str, Option<serde_json::Value>); N],
) -> serde_json::Map<String, serde_json::Value> {
    p.into_iter()
        .filter_map(|(k, v)| v.map(|v| (k.to_string(), v)))
        .collect()
}

/// Call `method` on the peer with `more`, and relay its replies as they
/// come, each with the peer's `continues`, until its last, the caller
/// going, or the tunnel failing. zlink's proxies would do the call, but
/// their streams can't move to the task that relays them.
pub fn relay<T>(
    link: Link,
    peer: String,
    method: &'static str,
    parameters: serde_json::Map<String, serde_json::Value>,
) -> Relayed<T>
where
    T: serde::de::DeserializeOwned + std::fmt::Debug + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<Item<T>>(16);
    tokio::spawn(async move {
        let mut c = match connect(link, &peer).await {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        };
        let call = zlink::Call::new(Method { method, parameters }).set_more(true);
        if let Err(e) = c.send_call(&call, vec![]).await {
            let _ = tx.send(Err(failed(&peer, e))).await;
            return;
        }
        loop {
            let r = tokio::select! {
                r = c.receive_reply::<T, FirewallError>() => r,
                () = tx.closed() => return,
            };
            let out = match r {
                Ok((Ok(reply), _)) => {
                    let more = reply.continues() == Some(true);
                    let p = reply.into_parameters();
                    if tx
                        .send(Ok(Reply::new(p).set_continues(Some(more))))
                        .await
                        .is_err()
                        || !more
                    {
                        return;
                    }
                    continue;
                }
                Ok((Err(e), _)) => e,
                Err(e) => failed(&peer, e),
            };
            let _ = tx.send(Err(out)).await;
            return;
        }
    });
    Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
}

/// A tool's run on the peer as one reply, for a call without `more`, as
/// a local run answers one.
pub fn gather(s: Relayed<ToolReply>) -> Relayed<ToolReply> {
    Box::pin(futures_util::stream::once(async move {
        let mut s = s;
        let mut all = ToolReply {
            lines: vec![],
            exit: None,
        };
        while let Some(r) = s.next().await {
            if let Some(r) = r?.into_parameters() {
                all.lines.extend(r.lines);
                all.exit = r.exit.or(all.exit);
            }
        }
        Ok(Reply::new(Some(all)))
    }))
}
