//! sparewall-httpd against a real sparewalld (with its fake system
//! adapter), over HTTP.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sparewall_api::AuthProxy;

/// `$6$` crypt(3) of "not a password".
const NOT_A_PASSWORD: &str = "$6$saltsaltsaltsalt$xBi0h9JAwekg0C/DjMgN2QuqkLmpxS6oSlGvlfbpVmNU6BoD2CIlyMob7DONgVGP/f3HoIdRtnZQ3hEVYIRer.";

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Node {
    dir: tempfile::TempDir,
    port: u16,
    _procs: Vec<Kill>,
}

fn wait_for(p: &Path) {
    let t0 = Instant::now();
    while !p.exists() {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "{} did not appear",
            p.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start() -> Option<Node> {
    let me = PathBuf::from(env!("CARGO_BIN_EXE_sparewall-httpd"));
    let daemon = me.parent()?.join("sparewalld");
    if !daemon.exists() {
        eprintln!("skipping: build sparewalld first (cargo test --workspace)");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("id.yaml"),
        "node: fw1\nmanagement: { nic: \"52:54:00:aa:00:01\" }\n",
    )
    .unwrap();
    let d = Command::new(daemon)
        .args(["--state", dir.path().join("state").to_str().unwrap()])
        .args(["--socket", dir.path().join("fw.sock").to_str().unwrap()])
        .args([
            "--api-socket",
            dir.path().join("api.sock").to_str().unwrap(),
        ])
        .args(["--identity", dir.path().join("id.yaml").to_str().unwrap()])
        .args(["--motd", dir.path().join("motd").to_str().unwrap()])
        .args(["--https", "off", "--fake-system"])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let d = Kill(d);
    wait_for(&dir.path().join("api.sock"));
    let port = free_port();
    std::fs::create_dir(dir.path().join("ui")).unwrap();
    let h = Command::new(&me)
        .args(["--listen", &format!("tcp:127.0.0.1:{port}")])
        .args([
            "--api-socket",
            dir.path().join("api.sock").to_str().unwrap(),
        ])
        .args(["--ui", dir.path().join("ui").to_str().unwrap()])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let h = Kill(h);
    let t0 = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "httpd did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Some(Node {
        dir,
        port,
        _procs: vec![d, h],
    })
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

fn request(n: &Node, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Reply {
    let mut s = TcpStream::connect(("127.0.0.1", n.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: fw1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        req += &format!("{k}: {v}\r\n");
    }
    req += "\r\n";
    req += body;
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = vec![];
    let _ = s.read_to_end(&mut raw);
    parse(&raw)
}

fn parse(raw: &[u8]) -> Reply {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a response");
    let head = String::from_utf8_lossy(&raw[..end]).to_string();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut body = raw[end + 4..].to_vec();
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v == "chunked");
    if chunked {
        let mut out = vec![];
        let mut rest = &body[..];
        while let Some(i) = rest.windows(2).position(|w| w == b"\r\n") {
            let n = usize::from_str_radix(std::str::from_utf8(&rest[..i]).unwrap().trim(), 16)
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&rest[i + 2..i + 2 + n]);
            rest = &rest[i + 4 + n..];
        }
        body = out;
    }
    Reply {
        status,
        headers,
        body,
    }
}

fn call(n: &Node, method: &str, headers: &[(&str, &str)], params: Value) -> Reply {
    request(
        n,
        "POST",
        &format!("/call/{method}"),
        headers,
        &params.to_string(),
    )
}

fn root_call<F, T>(n: &Node, f: F) -> T
where
    F: AsyncFnOnce(&mut zlink::Connection<zlink::tokio::unix::Stream>) -> T,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut c = zlink::tokio::unix::connect(n.dir.path().join("fw.sock"))
            .await
            .unwrap();
        f(&mut c).await
    })
}

fn token(n: &Node, name: &str, role: &str) -> String {
    root_call(n, async |c| {
        c.create_token(name, role, None)
            .await
            .unwrap()
            .unwrap()
            .token
    })
}

#[test]
fn tokens_and_statuses() {
    let Some(n) = start() else { return };
    let viewer = format!("Bearer {}", token(&n, "ro", "viewer"));

    let r = call(&n, "org.sparewall.Firewall.History", &[], json!({}));
    assert_eq!(r.status, 401, "{}", r.json());
    assert_eq!(r.json()["parameters"]["role"], "none");
    assert_eq!(r.header("x-frame-options"), Some("DENY"));

    let r = call(
        &n,
        "org.sparewall.Firewall.History",
        &[("Authorization", &viewer)],
        json!({}),
    );
    assert_eq!(r.status, 200, "{}", r.json());
    assert!(r.json()["generations"].is_array());

    let r = call(
        &n,
        "org.sparewall.Firewall.Apply",
        &[("Authorization", &viewer)],
        json!({"config": {}, "base": 0}),
    );
    assert_eq!(r.status, 403, "{}", r.json());
    assert!(
        r.json()["message"]
            .as_str()
            .unwrap()
            .contains("needs the operator role")
    );

    let r = call(
        &n,
        "org.sparewall.Firewall.Validate",
        &[("Authorization", &viewer)],
        json!({"config": {"schema": 1, "networks": 7}}),
    );
    assert_eq!(r.status, 422, "{}", r.json());
    assert!(r.json()["parameters"]["errors"].is_array());

    let r = call(
        &n,
        "org.sparewall.Firewall.History",
        &[("Authorization", "Bearer swt_nope")],
        json!({}),
    );
    assert_eq!(r.status, 401);
    let r = request(&n, "GET", "/call/org.sparewall.Firewall.History", &[], "");
    assert_eq!(r.status, 405);
    let r = request(
        &n,
        "POST",
        "/call/org.sparewall.Firewall.History",
        &[("Authorization", &viewer)],
        "[1]",
    );
    assert_eq!(r.status, 400);
    // The gateway's own refusals carry parameters, as the description's
    // Error has them.
    assert_eq!(r.json()["parameters"]["parameter"], "parameters");
    let r = call(&n, "not-a-method", &[("Authorization", &viewer)], json!({}));
    assert_eq!(r.status, 404, "{}", r.json());
    assert_eq!(r.json()["parameters"]["method"], "not-a-method");

    // Subscribe streams JSON text sequence records.
    let mut s = TcpStream::connect(("127.0.0.1", n.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "POST /call/org.sparewall.Firewall.Subscribe?more=true HTTP/1.1\r\nHost: fw1\r\n\
         Authorization: {viewer}\r\nContent-Length: 0\r\n\r\n"
    )
    .unwrap();
    let mut got = vec![];
    let mut buf = [0u8; 4096];
    while !String::from_utf8_lossy(&got).contains("subscribed") {
        let k = s.read(&mut buf).unwrap();
        assert!(k > 0, "the stream ended: {}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..k]);
    }
    let text = String::from_utf8_lossy(&got);
    assert!(text.contains("application/json-seq"), "{text}");
    assert!(
        text.contains("\u{1e}{\"event\":{\"type\":\"subscribed\"}}"),
        "{text}"
    );
}

#[test]
fn browser_sessions() {
    let Some(n) = start() else { return };
    root_call(&n, async |c| {
        c.set_user("alice", "operator", NOT_A_PASSWORD)
            .await
            .unwrap()
            .unwrap()
    });
    let csrf = ("X-Sparewall-Request", "1");
    let login = json!({"user": "alice", "password": "not a password"});

    let r = call(&n, "org.sparewall.Auth.Login", &[], login.clone());
    assert_eq!(r.status, 401, "a login needs the CSRF header");
    let r = call(
        &n,
        "org.sparewall.Auth.Login",
        &[csrf],
        json!({"user": "alice", "password": "no"}),
    );
    assert_eq!(r.status, 401);
    let r = call(&n, "org.sparewall.Auth.Login", &[csrf], login);
    assert_eq!(r.status, 200, "{}", r.json());
    assert!(
        r.json().get("token").is_none(),
        "the token stays in the cookie"
    );
    assert_eq!(r.json()["role"], "operator");
    let set = r.header("set-cookie").unwrap().to_string();
    assert!(
        set.contains("HttpOnly") && set.contains("Secure") && set.contains("SameSite=Strict"),
        "{set}"
    );
    let cookie = set.split(';').next().unwrap().to_string();

    let r = call(
        &n,
        "org.sparewall.Firewall.History",
        &[("Cookie", &cookie)],
        json!({}),
    );
    assert_eq!(r.status, 401, "the cookie alone is refused");
    let r = call(
        &n,
        "org.sparewall.Firewall.History",
        &[("Cookie", &cookie), csrf],
        json!({}),
    );
    assert_eq!(r.status, 200, "{}", r.json());
    let r = call(
        &n,
        "org.sparewall.Auth.ListUsers",
        &[("Cookie", &cookie), csrf],
        json!({}),
    );
    assert_eq!(r.status, 403);

    let r = call(
        &n,
        "org.sparewall.Auth.Logout",
        &[("Cookie", &cookie), csrf],
        json!({}),
    );
    assert_eq!(r.status, 200, "{}", r.json());
    assert!(r.header("set-cookie").unwrap().contains("Max-Age=0"));
    let r = call(
        &n,
        "org.sparewall.Firewall.History",
        &[("Cookie", &cookie), csrf],
        json!({}),
    );
    assert_eq!(r.status, 401);
    assert!(
        r.header("set-cookie").unwrap().contains("Max-Age=0"),
        "an ended session is forgotten"
    );
}

#[test]
fn files_and_the_description() {
    let Some(n) = start() else { return };
    let r = request(&n, "GET", "/openapi.json", &[], "");
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["openapi"], "3.1.0");
    let r = request(&n, "GET", "/", &[], "");
    assert_eq!(r.status, 404);
    assert!(
        r.json()["message"]
            .as_str()
            .unwrap()
            .contains("not installed")
    );

    let ui = n.dir.path().join("ui");
    std::fs::write(ui.join("index.html"), "<html>ui</html>").unwrap();
    std::fs::write(ui.join("main.js"), "1").unwrap();
    std::fs::write(n.dir.path().join("secret"), "no").unwrap();
    let r = request(&n, "GET", "/", &[], "");
    assert_eq!(
        (r.status, r.body.as_slice()),
        (200, &b"<html>ui</html>"[..])
    );
    assert!(
        r.header("content-security-policy")
            .unwrap()
            .contains("default-src 'self'")
    );
    let r = request(&n, "GET", "/status/pair", &[], "");
    assert_eq!(
        (r.status, r.body.as_slice()),
        (200, &b"<html>ui</html>"[..]),
        "the page's routes"
    );
    let r = request(&n, "GET", "/main.js", &[], "");
    assert_eq!(
        r.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );
    let r = request(&n, "GET", "/missing.js", &[], "");
    assert_eq!(r.status, 404);
    let r = request(&n, "GET", "/../secret", &[], "");
    assert_eq!(r.status, 404);
    let r = request(&n, "GET", "/%2e%2e/secret", &[], "");
    assert_ne!(r.body.as_slice(), b"no");
}
