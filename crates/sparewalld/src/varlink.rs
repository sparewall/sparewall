//! Serving Varlink connections side by side.
//!
//! zlink's `Server` handles one method call at a time across all its
//! connections, so a call that waits on the network (a peer push, `sync
//! --from`, an upgrade plan) would hold up every other client. Here each
//! connection gets a server of its own, with its own clone of the
//! service; calls on one connection still run in order.

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use tokio::net::UnixListener;
use zlink::tokio::unix::Stream;

/// Accept connections on `listener` and serve each with a clone of
/// `service`. Returns only if accepting fails.
pub async fn serve<S>(listener: UnixListener, service: S) -> std::io::Result<()>
where
    S: zlink::Service<Stream> + Clone,
{
    // Server::run is not Send, so the connections are driven here
    // rather than spawned.
    let mut conns = FuturesUnordered::new();
    loop {
        tokio::select! {
            r = listener.accept() => {
                let (stream, _) = r?;
                match Stream::try_from(stream) {
                    Ok(s) => conns.push(
                        zlink::Server::new(zlink::ReadyListener::new(s), service.clone()).run(),
                    ),
                    Err(e) => tracing::debug!(error = %e, "dropping a Varlink connection"),
                }
            }
            Some(r) = conns.next(), if !conns.is_empty() => {
                if let Err(e) = r {
                    tracing::debug!(error = %e, "Varlink connection ended");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde::{Deserialize, Serialize};
    use zlink::introspect::{self, CustomType};

    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, CustomType)]
    struct Done {
        ok: bool,
    }

    #[derive(Debug, Clone, PartialEq, zlink::ReplyError, introspect::ReplyError)]
    #[zlink(interface = "org.sparewall.Test")]
    enum TestError {
        Never,
    }

    #[derive(Clone)]
    struct Slow;

    #[zlink::service(
        interface = "org.sparewall.Test",
        vendor = "Sparewall",
        product = "test",
        version = "0",
        url = "https://sparewall.org",
        types = [Done]
    )]
    impl Slow {
        async fn wait(&self) -> Done {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Done { ok: true }
        }
        async fn ping(&self) -> Done {
            Done { ok: true }
        }
    }

    #[zlink::proxy("org.sparewall.Test")]
    trait TestProxy {
        async fn wait(&mut self) -> zlink::Result<Result<Done, TestError>>;
        async fn ping(&mut self) -> zlink::Result<Result<Done, TestError>>;
    }

    /// A call that waits must not delay another client's call (#36).
    #[tokio::test(flavor = "current_thread")]
    async fn a_waiting_call_does_not_block_another_connection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = serve(listener, Slow);
        let clients = async {
            let mut a = zlink::tokio::unix::connect(&path).await.unwrap();
            let mut b = zlink::tokio::unix::connect(&path).await.unwrap();
            let waiting = a.wait();
            let quick = async {
                // Let the waiting call reach the server first.
                tokio::time::sleep(Duration::from_millis(100)).await;
                tokio::time::timeout(Duration::from_secs(5), b.ping()).await
            };
            tokio::select! {
                _ = waiting => panic!("the waiting call returned early"),
                r = quick => r.expect("ping waited behind the other connection's call"),
            }
        };
        tokio::select! {
            r = server => panic!("server ended: {r:?}"),
            r = clients => assert!(r.unwrap().unwrap().ok),
        }
    }
}
