//! The restricted socket: role checks for unprivileged clients (#11;
//! design: "Roles", "Web UI and HTTP API").
//!
//! A client binds its connection to a token (`org.sparewall.Auth.Bind`)
//! before anything else. [`Guard`] wraps the service on every connection
//! of the socket and checks each call against the role [`needed`] for its
//! method before the service sees it, so a method missing from the table
//! is refused rather than open. The token is looked up again on each
//! call, so revoking it or its expiry ends the connection's access at
//! once.

use std::cell::{OnceCell, RefCell};
use std::fmt;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::de::value::MapAccessDeserializer;
use serde::de::{DeserializeSeed, IntoDeserializer, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sparewall_api::FirewallError;
use sparewall_core::tokens::{self, Role};
use zlink::connection::Socket;
use zlink::service::{HandleResult, MethodReply};
use zlink::{Call, Connection, Service};

/// Who a restricted connection acts as, once bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The token's name.
    pub name: String,
    pub role: Role,
    /// The token's SHA-256, to look it up again on each call.
    pub hash: String,
    /// A session's user; `None` for an API token.
    pub user: Option<String>,
}

impl Principal {
    pub fn of(t: &tokens::TokenInfo) -> Principal {
        Principal {
            name: t.name.clone(),
            role: t.role,
            hash: t.hash.clone(),
            user: t.user.clone(),
        }
    }

    /// As a generation's author and in the journal.
    pub fn describe(&self) -> String {
        match &self.user {
            Some(u) => u.clone(),
            None => format!("token {}", self.name),
        }
    }
}

/// A restricted connection's principal, shared by its [`Guard`] and the
/// service it wraps (which binds it). One per connection.
pub type Session = Arc<Mutex<Option<Principal>>>;

/// What a method needs on the restricted socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Open before binding: binding itself.
    Nothing,
    /// A bound token whose role allows this one.
    Role(Role),
}

/// The role each method needs on the restricted socket; `None` for a
/// method it does not serve. Every method of the coordinator's
/// interfaces is listed (a test holds this to the interface
/// descriptions).
pub fn needed(method: &str) -> Option<Need> {
    use Role::*;
    let role = match method {
        "org.sparewall.Auth.Bind" | "org.sparewall.Auth.Login" => return Some(Need::Nothing),
        "org.sparewall.Auth.Logout" => Monitor,
        "org.varlink.service.GetInfo" | "org.varlink.service.GetInterfaceDescription" => Monitor,
        "org.sparewall.Firewall.Health" => Monitor,
        "org.sparewall.Firewall.Validate"
        | "org.sparewall.Firewall.GetConfig"
        | "org.sparewall.Firewall.Export"
        | "org.sparewall.Firewall.History"
        | "org.sparewall.Firewall.Status"
        | "org.sparewall.Firewall.Subscribe"
        | "org.sparewall.Upgrade.Check" => Viewer,
        "org.sparewall.Firewall.Apply"
        | "org.sparewall.Firewall.Merge"
        | "org.sparewall.Firewall.Patch"
        | "org.sparewall.Firewall.Confirm"
        | "org.sparewall.Firewall.Rollback"
        | "org.sparewall.Firewall.Sync"
        | "org.sparewall.Cluster.Failover" => Operator,
        // The bundle carries the cluster secrets, and a client
        // configuration a peer's keys. A check that stays degraded until
        // seen (an SELinux denial) is an admin's to acknowledge.
        "org.sparewall.Firewall.Backup"
        | "org.sparewall.Firewall.AckHealth"
        | "org.sparewall.Firewall.VpnClientConfig"
        | "org.sparewall.Upgrade.Start"
        | "org.sparewall.Secrets.Set"
        | "org.sparewall.Secrets.List"
        | "org.sparewall.Secrets.Delete"
        | "org.sparewall.Auth.CreateToken"
        | "org.sparewall.Auth.ListTokens"
        | "org.sparewall.Auth.RevokeToken"
        | "org.sparewall.Auth.SetUser"
        | "org.sparewall.Auth.ListUsers"
        | "org.sparewall.Auth.RemoveUser" => Admin,
        _ => return None,
    };
    Some(Need::Role(role))
}

fn denied(role: &str, reason: impl Into<String>) -> FirewallError {
    FirewallError::PermissionDenied {
        role: role.into(),
        reason: Some(reason.into()),
    }
}

/// Wraps a service on one restricted connection.
#[derive(Clone)]
pub struct Guard<S> {
    inner: S,
    session: Session,
    /// The coordinator's state directory, where the tokens are.
    store: PathBuf,
}

impl<S> Guard<S> {
    pub fn new(inner: S, session: Session, store: PathBuf) -> Self {
        Guard {
            inner,
            session,
            store,
        }
    }

    /// Whether the connection may call `method`, logging calls that need
    /// an operator or more with their principal.
    fn check(&self, method: &str) -> Result<(), FirewallError> {
        let Some(need) = needed(method) else {
            return Err(denied(
                "none",
                format!("{method} is not available on this socket"),
            ));
        };
        let Need::Role(need) = need else {
            return Ok(());
        };
        let mut session = self.session.lock().unwrap_or_else(|p| p.into_inner());
        let Some(p) = session.as_ref() else {
            return Err(denied(
                "none",
                "bind the connection to a token first (org.sparewall.Auth.Bind)",
            ));
        };
        let current =
            tokens::current(&self.store, &p.hash).map_err(|e| FirewallError::ApplyFailed {
                message: e.to_string(),
            })?;
        let Some(t) = current else {
            tracing::info!(
                principal = p.describe(),
                method,
                "refused a call: the token is gone"
            );
            *session = None;
            return Err(denied("none", "the token was revoked or has expired"));
        };
        if !t.role.allows(need) {
            tracing::info!(
                token = p.name,
                role = t.role.as_str(),
                method,
                "refused a call"
            );
            return Err(denied(
                t.role.as_str(),
                format!("{method} needs the {} role", need.as_str()),
            ));
        }
        if need >= Role::Operator {
            tracing::info!(principal = p.describe(), method, "call");
        }
        Ok(())
    }
}

impl<S, Sock> Service<Sock> for Guard<S>
where
    S: Service<Sock>,
    Sock: Socket,
{
    type MethodCall<'de> = Guarded<S::MethodCall<'de>>;
    type ReplyParams<'ser>
        = S::ReplyParams<'ser>
    where
        Self: 'ser;
    type ReplyStreamParams = S::ReplyStreamParams;
    type ReplyStreamError = S::ReplyStreamError;
    type ReplyStream = S::ReplyStream;
    type ReplyError<'ser>
        = GuardError<S::ReplyError<'ser>>
    where
        Self: 'ser;

    async fn handle<'ser>(
        &'ser mut self,
        call: &'ser Call<Self::MethodCall<'_>>,
        conn: &mut Connection<Sock>,
        fds: Vec<std::os::fd::OwnedFd>,
    ) -> HandleResult<Self::ReplyParams<'ser>, Self::ReplyStream, Self::ReplyError<'ser>> {
        let g = call.method();
        let inner = g.call(call);
        if let Err(e) = self.check(&g.name) {
            return (MethodReply::Error(GuardError::Denied(e)), vec![]);
        }
        let (reply, fds) = self.inner.handle(inner, conn, fds).await;
        let reply = match reply {
            MethodReply::Single(p) => MethodReply::Single(p),
            MethodReply::Multi(s) => MethodReply::Multi(s),
            MethodReply::Error(e) => MethodReply::Error(GuardError::Inner(e)),
        };
        (reply, fds)
    }
}

/// The wrapped service's errors, or the guard's refusal.
#[derive(Debug)]
pub enum GuardError<E> {
    Inner(E),
    Denied(FirewallError),
}

impl<E: Serialize> Serialize for GuardError<E> {
    fn serialize<Ser: Serializer>(&self, s: Ser) -> Result<Ser::Ok, Ser::Error> {
        match self {
            GuardError::Inner(e) => e.serialize(s),
            GuardError::Denied(e) => e.serialize(s),
        }
    }
}

/// A call as the wrapped service reads it, with its method name, which
/// the guard needs before the service sees the call.
#[derive(Debug)]
pub struct Guarded<M> {
    name: String,
    method: RefCell<Option<M>>,
    call: OnceCell<Call<M>>,
}

impl<M> Guarded<M> {
    /// The call for the wrapped service, with `outer`'s flags.
    fn call(&self, outer: &Call<Guarded<M>>) -> &Call<M> {
        self.call.get_or_init(|| {
            let m = self.method.borrow_mut().take().expect("taken once");
            Call::new(m)
                .set_oneway(outer.oneway())
                .set_more(outer.more())
                .set_upgrade(outer.upgrade())
        })
    }
}

impl<'de, M: Deserialize<'de>> Deserialize<'de> for Guarded<M> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<M>(PhantomData<M>);
        impl<'de, M: Deserialize<'de>> Visitor<'de> for V<M> {
            type Value = Guarded<M>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a method call")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Guarded<M>, A::Error> {
                let name = RefCell::new(None);
                let m = M::deserialize(MapAccessDeserializer::new(Tee {
                    inner: map,
                    name: &name,
                    method_next: false,
                }))?;
                Ok(Guarded {
                    name: name.into_inner().unwrap_or_default(),
                    method: RefCell::new(Some(m)),
                    call: OnceCell::new(),
                })
            }
        }
        d.deserialize_map(V(PhantomData))
    }
}

/// Passes a call's fields through, keeping a copy of `method`.
struct Tee<'a, A> {
    inner: A,
    name: &'a RefCell<Option<String>>,
    method_next: bool,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for Tee<'_, A> {
    type Error = A::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, A::Error> {
        let Some(key) = self.inner.next_key::<String>()? else {
            return Ok(None);
        };
        self.method_next = key == "method";
        seed.deserialize(IntoDeserializer::<A::Error>::into_deserializer(key))
            .map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, A::Error> {
        if !std::mem::take(&mut self.method_next) {
            return self.inner.next_value_seed(seed);
        }
        let name: String = self.inner.next_value()?;
        *self.name.borrow_mut() = Some(name.clone());
        seed.deserialize(IntoDeserializer::<A::Error>::into_deserializer(name))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use serde_json::{Value, json};
    use sparewall_api::{AuthProxy, FirewallError, FirewallProxy, SecretsProxy};
    use sparewall_config::identity::{BootstrapPort, Identity};
    use sparewall_core::system::Fake;
    use sparewall_core::{Coordinator, Store, System};
    use tokio::net::UnixListener;

    use super::*;
    use crate::service::{Core, Firewall};
    use crate::varlink;

    #[derive(Debug, Serialize, Deserialize)]
    struct Info {
        interfaces: Vec<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Description {
        description: String,
    }

    /// `org.varlink.service`, with the guard's refusal as its error.
    #[zlink::proxy("org.varlink.service")]
    trait Introspect {
        async fn get_info(&mut self) -> zlink::Result<Result<Info, FirewallError>>;
        async fn get_interface_description(
            &mut self,
            interface: &str,
        ) -> zlink::Result<Result<Description, FirewallError>>;
    }

    fn firewall(dir: &Path) -> (Core, Firewall) {
        let id = Identity {
            node: "fw1".into(),
            ssh_keys: vec![],
            password_hash: None,
            management: BootstrapPort {
                nic: "52:54:00:aa:00:01".into(),
                vlan: None,
                address: None,
                gateway: None,
                dns: vec![],
            },
        };
        let mut c = Coordinator::new(
            Store::open(dir).unwrap(),
            Box::new(Fake::default()) as Box<dyn System>,
            id,
        );
        c.boot(false).unwrap();
        let core: Core = Arc::new(std::sync::Mutex::new(c));
        let (tx, _) = tokio::sync::broadcast::channel(16);
        let f = Firewall::new(
            core.clone(),
            tx,
            Default::default(),
            Default::default(),
            Default::default(),
        );
        (core, f)
    }

    /// Serve `f` on a root socket and a restricted one in `dir`, bound
    /// before this returns.
    fn serve(dir: &Path, f: Firewall) -> impl Future<Output = ()> {
        let state = dir.to_path_buf();
        let root = UnixListener::bind(dir.join("root.sock")).unwrap();
        let api = UnixListener::bind(dir.join("api.sock")).unwrap();
        async move {
            let root = {
                let f = f.clone();
                varlink::serve(root, move || f.clone())
            };
            let api = varlink::serve(api, move || {
                let s = Session::default();
                Guard::new(f.restricted(s.clone()), s, state.clone())
            });
            let r = tokio::try_join!(root, api);
            panic!("a server ended: {r:?}");
        }
    }

    async fn connect(dir: &Path, name: &str) -> zlink::Connection<zlink::tokio::unix::Stream> {
        zlink::tokio::unix::connect(dir.join(name)).await.unwrap()
    }

    fn doc() -> Value {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/standalone.yaml"
        ))
        .unwrap();
        sparewall_config::parse_value(&text, sparewall_config::Format::Yaml).unwrap()
    }

    fn role_of(e: FirewallError) -> String {
        match e {
            FirewallError::PermissionDenied { role, .. } => role,
            e => panic!("not a refusal: {e}"),
        }
    }

    /// `$6$` crypt(3) of "not a password".
    const NOT_A_PASSWORD: &str = "$6$saltsaltsaltsalt$xBi0h9JAwekg0C/DjMgN2QuqkLmpxS6oSlGvlfbpVmNU6BoD2CIlyMob7DONgVGP/f3HoIdRtnZQ3hEVYIRer.";

    /// A user logs in on the restricted socket, acts with its role and
    /// as itself, and logs out; the session token then binds nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn users_log_in_and_out() {
        let dir = tempfile::tempdir().unwrap();
        let (_core, f) = firewall(dir.path());
        let server = serve(dir.path(), f);
        let test = async {
            let mut root = connect(dir.path(), "root.sock").await;
            root.set_user("alice", "operator", NOT_A_PASSWORD)
                .await
                .unwrap()
                .unwrap();
            let users = root.list_users().await.unwrap().unwrap().users;
            assert_eq!(users.len(), 2, "{users:?}");
            // Users are not secrets to set by hand.
            let e = root
                .set("user.bob", "{}", Some(true))
                .await
                .unwrap()
                .unwrap_err();
            assert!(matches!(e, FirewallError::NotSupported { .. }), "{e}");

            let mut c = connect(dir.path(), "api.sock").await;
            let e = c.login("alice", "wrong").await.unwrap().unwrap_err();
            assert!(e.to_string().contains("wrong user name or password"), "{e}");
            let r = c.login("alice", "not a password").await.unwrap().unwrap();
            assert_eq!((r.user.as_str(), r.role.as_str()), ("alice", "operator"));
            let a = c.apply(&doc(), 0, None, None, None).await.unwrap().unwrap();
            assert_eq!(a.generation.author, "alice");
            let e = c.list_users().await.unwrap().unwrap_err();
            assert_eq!(role_of(e), "operator");
            // Sessions are not API tokens.
            let tokens = root.list_tokens().await.unwrap().unwrap().tokens;
            assert!(tokens.is_empty(), "{tokens:?}");

            // Another connection binds the session's token.
            let mut other = connect(dir.path(), "api.sock").await;
            other.bind(&r.token).await.unwrap().unwrap();
            other.history(None).await.unwrap().unwrap();
            c.logout().await.unwrap().unwrap();
            let e = c.history(None).await.unwrap().unwrap_err();
            assert_eq!(role_of(e), "none");
            let e = other.history(None).await.unwrap().unwrap_err();
            assert!(e.to_string().contains("revoked"), "{e}");
            let e = other.bind(&r.token).await.unwrap().unwrap_err();
            assert_eq!(role_of(e), "none");

            // A new admin password (sparewall passwd) ends admin's sessions.
            root.set("admin-password", NOT_A_PASSWORD, Some(true))
                .await
                .unwrap()
                .unwrap();
            let mut a = connect(dir.path(), "api.sock").await;
            a.login("admin", "not a password").await.unwrap().unwrap();
            a.history(None).await.unwrap().unwrap();
            root.set("admin-password", NOT_A_PASSWORD, Some(true))
                .await
                .unwrap()
                .unwrap();
            let e = a.history(None).await.unwrap().unwrap_err();
            assert!(e.to_string().contains("revoked"), "{e}");
        };
        tokio::select! {
            () = server => unreachable!(),
            () = test => {}
        }
    }

    #[test]
    fn failed_logins_are_limited_per_user() {
        let l = crate::service::Logins::default();
        for _ in 0..5 {
            assert!(l.attempt("alice"));
        }
        assert!(!l.attempt("alice"));
        assert!(l.attempt("bob"));
        l.succeeded("alice");
        assert!(l.attempt("alice"));
    }

    /// A table full of names failing within the window refuses new ones
    /// rather than forgetting the old.
    #[test]
    fn failing_names_are_bounded() {
        let l = crate::service::Logins::default();
        for i in 0..10_000 {
            assert!(l.attempt(&format!("u{i}")));
        }
        assert!(!l.attempt("mallory"));
        assert!(l.attempt("u0"));
        l.succeeded("u0");
        assert!(l.attempt("mallory"));
    }

    /// Every method the coordinator serves has an entry in the table, so
    /// none is open by omission (or refused by it).
    #[tokio::test(flavor = "current_thread")]
    async fn every_method_has_a_role() {
        let dir = tempfile::tempdir().unwrap();
        let (_core, f) = firewall(dir.path());
        let server = serve(dir.path(), f);
        let test = async {
            let mut c = connect(dir.path(), "root.sock").await;
            let interfaces = c.get_info().await.unwrap().unwrap().interfaces;
            let mut methods = vec![];
            for i in &interfaces {
                let d = c.get_interface_description(i).await.unwrap().unwrap();
                for line in d.description.lines() {
                    if let Some(m) = line.trim().strip_prefix("method ") {
                        let m = m.split('(').next().unwrap().trim();
                        methods.push(format!("{i}.{m}"));
                    }
                }
            }
            assert!(methods.len() > 25, "{methods:?}");
            let missing: Vec<_> = methods.iter().filter(|m| needed(m).is_none()).collect();
            assert!(missing.is_empty(), "no role for {missing:?}");
        };
        tokio::select! {
            () = server => unreachable!(),
            () = test => {}
        }
    }

    /// Calls through the restricted socket act with the bound token's
    /// role, and stop when it is revoked.
    #[tokio::test(flavor = "current_thread")]
    async fn calls_are_checked_against_the_role() {
        let dir = tempfile::tempdir().unwrap();
        let (core, f) = firewall(dir.path());
        let (viewer, operator) = {
            let mut c = core.lock().unwrap();
            (
                c.token_create("ro", Role::Viewer, None).unwrap().0,
                c.token_create("ci", Role::Operator, None).unwrap().0,
            )
        };
        let server = serve(dir.path(), f);
        let test = async {
            // Unbound: only Bind is open.
            let mut c = connect(dir.path(), "api.sock").await;
            let e = c.history(None).await.unwrap().unwrap_err();
            assert_eq!(role_of(e), "none");
            let e = c.get_info().await.unwrap().unwrap_err();
            assert_eq!(role_of(e), "none", "introspection needs a token");
            let e = c.bind("swt_nope").await.unwrap().unwrap_err();
            assert_eq!(role_of(e), "none");

            // A viewer reads, and may not change anything.
            let r = c.bind(&viewer).await.unwrap().unwrap();
            assert_eq!((r.name.as_str(), r.role.as_str()), ("ro", "viewer"));
            c.history(None).await.unwrap().unwrap();
            c.validate(&doc()).await.unwrap().unwrap();
            {
                use futures_util::StreamExt;
                let mut sub = connect(dir.path(), "api.sock").await;
                sub.bind(&viewer).await.unwrap().unwrap();
                let events = sub.subscribe().await.unwrap();
                futures_util::pin_mut!(events);
                let first = events.next().await.unwrap().unwrap().unwrap();
                assert_eq!(first.event["type"], "subscribed");
            }
            let e = c
                .apply(&doc(), 0, None, None, None)
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(role_of(e), "viewer");
            assert_eq!(core.lock().unwrap().active().unwrap(), 0);

            // An operator changes the configuration, as its author, but
            // may not turn anti-lockout off or manage tokens.
            let mut c = connect(dir.path(), "api.sock").await;
            c.bind(&operator).await.unwrap().unwrap();
            let r = c.apply(&doc(), 0, None, None, None).await.unwrap().unwrap();
            assert_eq!(r.generation.author, "token ci");
            let mut off = doc();
            off["management"]["anti_lockout"] = json!(false);
            let e = c
                .apply(&off, 1, None, None, None)
                .await
                .unwrap()
                .unwrap_err();
            assert!(e.to_string().contains("anti_lockout"), "{e}");
            let e = c.list_tokens().await.unwrap().unwrap_err();
            assert_eq!(role_of(e), "operator");
            let e = c.ack_health("selinux").await.unwrap().unwrap_err();
            assert_eq!(role_of(e), "operator");
            let e = c
                .create_token("mine", "admin", None)
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(role_of(e), "operator");

            // Revoked from the root socket: the bound connection stops.
            let mut root = connect(dir.path(), "root.sock").await;
            root.revoke_token("ci").await.unwrap().unwrap();
            let e = c.history(None).await.unwrap().unwrap_err();
            assert!(e.to_string().contains("revoked"), "{e}");

            // The root socket needs no token, and takes none.
            root.list_tokens().await.unwrap().unwrap();
            let e = root.bind(&viewer).await.unwrap().unwrap_err();
            assert!(matches!(e, FirewallError::NotSupported { .. }), "{e}");
        };
        tokio::select! {
            () = server => unreachable!(),
            () = test => {}
        }
    }
}
