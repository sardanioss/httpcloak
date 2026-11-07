//! The local proxy, driven by a session pointed at it.

mod common;

use std::time::Duration;

use common::*;
use httpcloak::{LocalProxy, Session};

fn through(proxy: &LocalProxy) -> Session {
    Session::builder().proxy(proxy.url()).timeout(Duration::from_secs(10)).build().unwrap()
}

/// Sends a request for the HTTPS test server to the proxy the way an ordinary
/// proxy client does, in absolute form over plain HTTP, asking the proxy to
/// make the TLS connection. (httpcloak's own client always tunnels through an
/// HTTP proxy with CONNECT, which the proxy passes through untouched.)
fn via_proxy(proxy: &LocalProxy, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    use std::io::{Read, Write};
    let target = https(path).replacen("https://", "http://", 1);
    let host = target.trim_start_matches("http://").split('/').next().unwrap().to_string();
    let mut request =
        format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nX-HTTPCloak-Scheme: https\r\n");
    for (k, v) in headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("\r\n");
    let mut conn = std::net::TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    conn.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    let _ = conn.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response).into_owned();
    let status = response.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = response.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (status, body)
}

#[test]
fn forwards_plain_http_as_it_came() {
    let proxy = LocalProxy::start().unwrap();
    assert!(proxy.port() > 0);
    assert!(proxy.is_running());
    assert_eq!(proxy.url(), format!("http://127.0.0.1:{}", proxy.port()));

    // httpcloak tunnels through it with CONNECT, which it passes through.
    let r = through(&proxy).post(http("/echo")).body("via proxy").send().unwrap();
    assert_eq!(echoed_body(&echo(&r)), b"via proxy");

    let stats = proxy.stats().unwrap();
    assert!(stats.running);
    assert_eq!(stats.port, proxy.port());
    assert!(stats.total_requests >= 1);
}

#[test]
fn fingerprints_https_with_registered_sessions() {
    let proxy = LocalProxy::start().unwrap();
    let firefox = Session::builder()
        .preset(httpcloak::presets::FIREFOX_LATEST)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    proxy.register_session("ff", &firefox).unwrap();
    assert!(proxy.has_session("ff"));
    assert_eq!(proxy.session_ids(), ["ff"]);
    assert_eq!(proxy.stats().unwrap().registered_sessions, 1);

    // The proxy keeps the session alive on its own.
    drop(firefox);
    let (status, body) = via_proxy(&proxy, "/echo", &[("X-HTTPCloak-Session", "ff")]);
    assert_eq!(status, 200, "{body}");
    let e: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(e["version"], "HTTP/2.0", "the proxy's own connection is HTTP/2");
    assert!(echoed_header(&e, "user-agent").unwrap().contains("Firefox/"), "{e}");
    assert!(echoed_header(&e, "x-httpcloak-session").is_none());
    assert!(echoed_header(&e, "x-httpcloak-scheme").is_none());
    // A header the client sends replaces the preset's.
    let (_, body) = via_proxy(&proxy, "/echo", &[("X-HTTPCloak-Session", "ff"), ("User-Agent", "curl/8")]);
    let e: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(echoed_header(&e, "user-agent").as_deref(), Some("curl/8"));

    let (status, body) = via_proxy(&proxy, "/echo", &[("X-HTTPCloak-Session", "nope")]);
    assert_eq!(status, 400, "{body}");

    let other = Session::new().unwrap();
    let e = proxy.register_session("ff", &other).unwrap_err();
    assert!(e.message().contains("already exists"), "{e}");
    assert!(proxy.register_session("", &other).unwrap_err().is_invalid_input());
    assert!(proxy.register_session("a\0b", &other).unwrap_err().is_invalid_input());

    assert!(proxy.unregister_session("ff"));
    assert!(!proxy.unregister_session("ff"));
    assert!(!proxy.has_session("ff"));
    assert!(!proxy.has_session("a\0b"));
    assert!(proxy.session_ids().is_empty());
}

#[test]
fn a_taken_port_is_reported_as_such() {
    let first = LocalProxy::start().unwrap();
    let e = LocalProxy::builder().port(first.port()).start().unwrap_err();
    assert!(e.message().contains(&format!("127.0.0.1:{}", first.port())), "{e}");
}

#[test]
fn options_are_checked() {
    assert!(LocalProxy::builder().preset("no-such").start().unwrap_err().is_invalid_input());
    assert!(LocalProxy::builder().timeout(Duration::ZERO).start().unwrap_err().is_invalid_input());
    assert!(LocalProxy::builder().max_connections(0).start().unwrap_err().is_invalid_input());
    let proxy = LocalProxy::builder()
        .preset(httpcloak::presets::SAFARI_LATEST)
        .timeout(Duration::from_secs(5))
        .max_connections(10)
        .tls_only(true)
        .start()
        .unwrap();
    let stats = proxy.stats().unwrap();
    assert_eq!(stats.max_connections, 10);
    assert_eq!(stats.preset, httpcloak::presets::SAFARI_LATEST);
}

#[test]
fn dropping_the_proxy_stops_it() {
    let proxy = LocalProxy::start().unwrap();
    let url = proxy.url();
    drop(proxy);
    let s = Session::builder().proxy(url).timeout(Duration::from_secs(5)).build().unwrap();
    assert!(s.get(http("/echo")).send().is_err());
}
