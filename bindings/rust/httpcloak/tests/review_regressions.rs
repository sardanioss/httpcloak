//! Regression tests for the findings of the first external review. Each one
//! failed before its fix; the comments say what used to happen.

mod common;

use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use futures_util::StreamExt;
use httpcloak::{ErrorKind, Session};

/// A server that sends headers announcing a body it never sends, and reports
/// when the client hangs up.
fn idle_server() -> (RawServer, mpsc::Receiver<()>) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let server = RawServer::start(move |s, _| {
        write(s, b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n");
        let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
        let mut buf = [0u8; 1];
        // Returns 0 (or an error) once the client closes the connection.
        let _ = std::io::Read::read(s, &mut buf);
        let _ = tx.lock().unwrap().send(());
    });
    (server, rx)
}

#[cfg(target_os = "linux")]
fn body_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("comm")).ok())
        .filter(|name| name.trim() == "httpcloak-body")
        .count()
}

/// Dropping a BodyStream whose read was blocked on an idle connection used to
/// keep the reader thread, the socket and the session until the peer sent
/// something, which an idle event stream may never do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_an_idle_body_stream_releases_everything() {
    let (server, hung_up) = idle_server();
    let stream = session().get(server.url("/")).send_stream_async().await.unwrap();
    let mut body = stream.into_body_stream();
    // Let the read start and block.
    assert!(tokio::time::timeout(Duration::from_millis(300), body.next()).await.is_err());
    drop(body);
    assert!(hung_up.recv_timeout(Duration::from_secs(5)).is_ok(), "the connection was kept open");
    #[cfg(target_os = "linux")]
    assert!(eventually(Duration::from_secs(5), || body_threads() == 0), "the reader thread is still there");
}

/// A streamed request's timeout used to be exact only until the headers;
/// the body then had until the timeout rounded up to whole seconds.
#[test]
fn a_subsecond_stream_timeout_bounds_the_body_exactly() {
    let (server, _hung_up) = idle_server();
    let stream = session().get(server.url("/")).timeout(Duration::from_millis(300)).send_stream().unwrap();
    let start = Instant::now();
    let e = stream.bytes().unwrap_err();
    assert!(e.is_timeout(), "{e:?}");
    assert!(start.elapsed() < Duration::from_millis(900), "the body read ended after {:?}", start.elapsed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subsecond_stream_timeout_bounds_an_async_body_exactly() {
    let (server, _hung_up) = idle_server();
    let stream = session().get(server.url("/")).timeout(Duration::from_millis(300)).send_stream_async().await.unwrap();
    let start = Instant::now();
    let mut body = stream.into_body_stream();
    let item = tokio::time::timeout(Duration::from_secs(5), body.next()).await.expect("the deadline never fired");
    let e = item.unwrap().unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}");
    assert!(start.elapsed() < Duration::from_millis(900), "{:?}", start.elapsed());
}

/// A deadline already passed fails the next read without blocking.
#[test]
fn a_read_after_the_deadline_fails_at_once() {
    let mut stream = session().get(https("/stream/50/50")).timeout(Duration::from_millis(400)).send_stream().unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let start = Instant::now();
    let mut buf = [0u8; 1 << 20];
    let mut result = Ok(1);
    while matches!(result, Ok(n) if n > 0) {
        result = std::io::Read::read(&mut stream, &mut buf);
    }
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_millis(300));
}

/// A stream's own timeout used to be overridden by the session's while the
/// connection and headers were set up, so a longer one was cut short.
#[test]
fn a_stream_timeout_longer_than_the_session_reaches_slow_headers() {
    let server = RawServer::start(|s, _| {
        std::thread::sleep(Duration::from_millis(1500));
        write(s, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    });
    let s = Session::builder().timeout(Duration::from_secs(1)).build().unwrap();
    let stream = s.get(server.url("/")).timeout(Duration::from_secs(4)).send_stream().unwrap();
    assert_eq!(stream.text().unwrap(), "ok");
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let stream = rt.block_on(s.get(server.url("/")).timeout(Duration::from_secs(4)).send_stream_async()).unwrap();
    assert_eq!(stream.text().unwrap(), "ok");
    // Without its own timeout, the session's still bounds the headers.
    let e = s.get(server.url("/")).send_stream().unwrap_err();
    assert!(e.is_timeout() || e.kind() == ErrorKind::Other, "{e:?}");
}

/// Host names that spell the words the classifier looks for used to decide
/// the kind of a plain refused connection.
#[test]
fn single_label_hosts_do_not_decide_the_kind() {
    let port = refused_url().trim_end_matches('/').rsplit(':').next().unwrap().to_string();
    for host in ["timeout", "tls", "proxy", "certificate", "eof", "innocent"] {
        let s = Session::builder().connect_to(host, "127.0.0.1").build().unwrap();
        let e = s.get(format!("http://{host}:{port}/")).send().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Connect, "{host}: {e}");
    }
}

/// A cookie expiring after year 9999 used to panic inside the date formatter.
#[test]
fn a_far_future_cookie_is_refused_not_a_panic() {
    let far = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(253_402_300_800);
    let cookie = httpcloak::Cookie::new("a", "b").with_domain("localhost").with_expires(far);
    assert!(session().set_cookie(&cookie).unwrap_err().is_invalid_input());
    let _ = format!("{cookie:?}");
}

/// Converting a response with more headers than an http::HeaderMap holds used
/// to panic instead of failing.
#[test]
fn too_many_response_headers_convert_to_an_error() {
    let server = RawServer::start(|s, _| {
        let mut head = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n".to_vec();
        for _ in 0..40_000 {
            head.extend_from_slice(b"X-A: a\r\n");
        }
        head.extend_from_slice(b"\r\n");
        write(s, &head);
    });
    match session().get(server.url("/")).send() {
        Ok(r) => assert_eq!(r.headers().to_header_map().unwrap_err().kind(), ErrorKind::Decode),
        // The library may refuse a header block this large itself; either way
        // nothing panics.
        Err(e) => assert!(!e.message().is_empty()),
    }
}
