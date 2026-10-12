//! Adversarial test of sync-tunnel isolation (issue #3) against a real
//! kernel, in unprivileged user and network namespaces.
//!
//! The firewall namespace gets a LAN interface `users` with a client
//! behind it and a stand-in `swsync` with the peer behind it (the rules
//! and the socket key on the interface, so a veth stands in for
//! WireGuard). The ruleset is a pair's, with a permissive `users->self:
//! accept`. A LAN client routing to the tunnel address must not reach the
//! peer port, through either layer on its own (the nft rule, and the
//! listener's `SO_BINDTODEVICE`), while the peer can, and that must hold
//! across a configuration change and a rollback.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Child, Command, Stdio};

use serde_json::json;
use sparewall_api::PEER_PORT;
use sparewall_core::System;
use sparewall_core::linux::Linux;

use crate::peer::{Link, PeerListener, bind_peer, from_peer_addr};

const INSIDE: &str = "SPAREWALL_TEST_IN_NETNS";
const OWN: Ipv4Addr = Ipv4Addr::new(169, 254, 77, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(169, 254, 77, 2);
const LAN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
/// A listener on the tunnel address without the device binding, so the
/// nft layer is tested on its own.
const PLAIN_PORT: u16 = 8650;
const LAN_PORT: u16 = 9000;

fn reexec(name: &str) -> bool {
    if std::env::var_os(INSIDE).is_some() {
        return false;
    }
    let ok = Command::new("unshare")
        .args(["-rn", "true"])
        .status()
        .is_ok_and(|s| s.success())
        && Command::new("nft").arg("--version").output().is_ok()
        && Command::new("nsenter").arg("--version").output().is_ok();
    if !ok {
        eprintln!("skipping {name}: no unprivileged namespaces, nft or nsenter");
        return true;
    }
    let out = Command::new("unshare")
        .arg("-rn")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(INSIDE, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "inner test failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    true
}

fn sh(cmd: &str) {
    let st = Command::new("sh").args(["-ec", cmd]).status().unwrap();
    assert!(st.success(), "{cmd}");
}

/// A process holding a fresh network namespace.
struct Ns(Child);

impl Ns {
    fn new() -> Ns {
        Ns(Command::new("unshare")
            .args(["-n", "sleep", "600"])
            .spawn()
            .unwrap())
    }
    fn pid(&self) -> u32 {
        self.0.id()
    }
    fn run(&self, cmd: &str) {
        sh(&format!("nsenter -t {} -n sh -ec '{cmd}'", self.pid()));
    }
}

impl Drop for Ns {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ruleset(patch: serde_json::Value) -> (String, Vec<String>) {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/pair.yaml"
    ))
    .unwrap();
    let mut v = sparewall_config::parse_value(&text, sparewall_config::Format::Yaml).unwrap();
    sparewall_config::merge_patch(&mut v, &patch);
    let doc = sparewall_config::from_value(v).unwrap();
    let r = sparewall_render::render(&doc, "fw1").unwrap();
    (
        r.files["nftables/sparewall.nft"].clone(),
        r.meta.preserved_sets,
    )
}

#[test]
fn lan_cannot_reach_the_peer_api() {
    if reexec("isolation_tests::lan_cannot_reach_the_peer_api") {
        return;
    }
    let client = Ns::new();
    let peer = Ns::new();
    std::thread::sleep(std::time::Duration::from_millis(200));
    sh(&format!(
        "ip link set lo up
         ip link add users type veth peer name eth0 netns {c}
         ip link add swsync type veth peer name eth0 netns {p}
         ip addr add {LAN}/24 dev users && ip link set users up
         ip addr add {OWN}/30 dev swsync && ip link set swsync up",
        c = client.pid(),
        p = peer.pid()
    ));
    client.run(&format!(
        "ip link set lo up; ip addr add 192.0.2.10/24 dev eth0; ip link set eth0 up
         ip route add 169.254.77.0/30 via {LAN}"
    ));
    peer.run(&format!(
        "ip link set lo up; ip addr add {PEER}/30 dev eth0; ip link set eth0 up"
    ));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let link = Link {
            own: IpAddr::V4(OWN),
            peer: IpAddr::V4(PEER),
        };
        let bound = bind_peer(link.own, Some("swsync")).unwrap();
        let plain = tokio::net::TcpListener::bind(SocketAddr::new(link.own, PLAIN_PORT))
            .await
            .unwrap();
        let lan = tokio::net::TcpListener::bind(SocketAddr::new(LAN.into(), LAN_PORT))
            .await
            .unwrap();
        // Accept (and drop) everything; the probes only need the handshake.
        for l in [bound, plain, lan] {
            tokio::spawn(async move {
                while let Ok((_, from)) = l.accept().await {
                    let _ = from_peer_addr(&link, from);
                }
            });
        }
        let probe = |ns: &Ns, addr: Ipv4Addr, port: u16| {
            let pid = ns.pid();
            async move {
                tokio::task::spawn_blocking(move || Ns::connects_pid(pid, addr, port))
                    .await
                    .unwrap()
            }
        };

        let mut sys = Linux::default();
        let permissive = json!({"zones": {"users": {"networks": ["users"]}},
                                "policy": {"users->self": {"action": "accept"}}});
        let (body, preserved) = ruleset(permissive.clone());
        sys.nft_load(&body, &preserved).unwrap();
        assert!(
            probe(&client, LAN, LAN_PORT).await,
            "the permissive policy should let the client in"
        );
        assert!(
            !probe(&client, OWN, PLAIN_PORT).await,
            "nft let the LAN reach the tunnel address"
        );
        assert!(
            !probe(&client, OWN, PEER_PORT).await,
            "the LAN reached the peer API"
        );
        assert!(
            probe(&peer, OWN, PEER_PORT).await,
            "the peer cannot reach the peer API"
        );

        // A later generation that opens more (a raw input rule accepting
        // everything from the LAN) cannot open the tunnel either.
        let mut wider = permissive.clone();
        sparewall_config::merge_patch(
            &mut wider,
            &json!({"raw": {"open-lan": {"at": {"hook": "input"}, "order": 1,
                                         "nft": "iifname \"users\" accept"}}}),
        );
        let (body2, preserved2) = ruleset(wider);
        sys.nft_load(&body2, &preserved2).unwrap();
        assert!(
            !probe(&client, OWN, PLAIN_PORT).await,
            "a raw accept opened the tunnel address"
        );
        assert!(
            !probe(&client, OWN, PEER_PORT).await,
            "a raw accept opened the peer API"
        );
        assert!(probe(&peer, OWN, PEER_PORT).await);

        // Rolled back to the first generation.
        sys.nft_load(&body, &preserved).unwrap();
        assert!(
            !probe(&client, OWN, PLAIN_PORT).await,
            "the rollback opened the tunnel address"
        );
        assert!(!probe(&client, OWN, PEER_PORT).await);
        assert!(probe(&peer, OWN, PEER_PORT).await);

        // With no ruleset at all, the device binding still refuses the
        // LAN, though a plain socket on the same address would accept it.
        sh("nft flush ruleset");
        assert!(
            probe(&client, OWN, PLAIN_PORT).await,
            "the attack path should be real without nft"
        );
        assert!(
            !probe(&client, OWN, PEER_PORT).await,
            "the device-bound listener accepted the LAN"
        );
        assert!(probe(&peer, OWN, PEER_PORT).await);
    });
}

impl Ns {
    fn connects_pid(pid: u32, addr: Ipv4Addr, port: u16) -> bool {
        Command::new("nsenter")
            .args(["-t", &pid.to_string(), "-n"])
            .args(["timeout", "3", "bash", "-c"])
            .arg(format!("exec 3<>/dev/tcp/{addr}/{port}"))
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

/// (Re)create the stand-in tunnel interface, as networkd does when the
/// WireGuard netdev changes: same name, same addresses, a new index.
fn make_swsync(peer: &Ns) {
    sh(&format!(
        "ip link del swsync 2>/dev/null || true
         ip link add swsync type veth peer name eth0 netns {p}
         ip addr add {OWN}/30 dev swsync && ip link set swsync up",
        p = peer.pid()
    ));
    peer.run(&format!(
        "ip link set lo up; ip addr add {PEER}/30 dev eth0; ip link set eth0 up"
    ));
}

fn ifindex(name: &str) -> String {
    let out = Command::new("ip")
        .args(["-o", "link", "show", name])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split(':')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// The listener follows `swsync` through startup (bound once it appears)
/// and through recreation with the same name and addresses (re-pairing
/// with a new key, then reverting it): the peer gets back in by itself,
/// and the LAN stays out.
#[test]
fn listener_follows_a_recreated_tunnel() {
    if reexec("isolation_tests::listener_follows_a_recreated_tunnel") {
        return;
    }
    let client = Ns::new();
    let peer = Ns::new();
    std::thread::sleep(std::time::Duration::from_millis(200));
    sh(&format!(
        "ip link set lo up
         ip link add users type veth peer name eth0 netns {c}
         ip addr add {LAN}/24 dev users && ip link set users up",
        c = client.pid()
    ));
    client.run(&format!(
        "ip link set lo up; ip addr add 192.0.2.10/24 dev eth0; ip link set eth0 up
         ip route add 169.254.77.0/30 via {LAN}"
    ));
    let mut sys = Linux::default();
    let (body, preserved) = ruleset(json!({"zones": {"users": {"networks": ["users"]}},
                                           "policy": {"users->self": {"action": "accept"}}}));
    sys.nft_load(&body, &preserved).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let link = Link {
            own: IpAddr::V4(OWN),
            peer: IpAddr::V4(PEER),
        };
        // The daemon's loop, without the coordinator: refresh, accept.
        tokio::spawn(async move {
            let mut pl = PeerListener::new(Some("swsync".into()));
            loop {
                pl.refresh(Some(link));
                let _ = pl.accept(std::time::Duration::from_millis(300)).await;
            }
        });
        let probe = |ns: &Ns, addr: Ipv4Addr| {
            let pid = ns.pid();
            async move {
                tokio::task::spawn_blocking(move || Ns::connects_pid(pid, addr, PEER_PORT))
                    .await
                    .unwrap()
            }
        };
        // The listener has nothing to bind to until the tunnel exists.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut indexes = Vec::new();
        for round in ["startup", "re-pairing", "revert"] {
            make_swsync(&peer);
            indexes.push(ifindex("swsync"));
            let mut ok = false;
            for _ in 0..10 {
                if probe(&peer, OWN).await {
                    ok = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            assert!(
                ok,
                "{round}: the peer cannot reach the peer API on swsync {indexes:?}"
            );
            assert!(
                !probe(&client, OWN).await,
                "{round}: the LAN reached the peer API"
            );
        }
        indexes.dedup();
        assert_eq!(indexes.len(), 3, "swsync was not recreated: {indexes:?}");
    });
}

#[test]
fn only_the_peer_address_is_accepted() {
    let link = Link {
        own: IpAddr::V4(OWN),
        peer: IpAddr::V4(PEER),
    };
    assert!(from_peer_addr(&link, SocketAddr::new(PEER.into(), 40000)));
    assert!(!from_peer_addr(&link, SocketAddr::new(OWN.into(), 40000)));
    assert!(!from_peer_addr(
        &link,
        SocketAddr::new("192.0.2.10".parse().unwrap(), 40000)
    ));
}
