//! Buffered requests, blocking, against the local servers.

mod common;

use std::time::{Duration, Instant};

use common::*;
use httpcloak::multipart::{Form, Part};
use httpcloak::{ErrorKind, FetchMode, Method, StatusCode, Version};

#[test]
fn plain_http_is_http1() {
    let r = session().get(http("/echo")).send().unwrap();
    assert_eq!(r.version(), Version::HTTP_11);
    let e = echo(&r);
    assert_eq!(e["method"], "GET");
    // The preset's headers went out.
    assert!(echoed_header(&e, "user-agent").unwrap().contains("Chrome/"));
    assert!(echoed_header(&e, "sec-ch-ua").is_some());
}

#[test]
fn tls_negotiates_http2() {
    let r = session().get(https("/echo")).send().unwrap();
    assert_eq!(r.version(), Version::HTTP_2);
    assert_eq!(echo(&r)["version"], "HTTP/2.0");
    assert!(!r.header_order().is_empty(), "HTTP/2 reports the header order");
}

#[test]
fn forcing_http1_over_tls() {
    let s = httpcloak::Session::builder()
        .danger_accept_invalid_certs(true)
        .http_version(httpcloak::HttpVersion::Http1)
        .build()
        .unwrap();
    assert_eq!(s.get(https("/echo")).send().unwrap().version(), Version::HTTP_11);
}

#[test]
fn a_self_signed_certificate_fails_verification() {
    let e = httpcloak::Session::new().unwrap().get(https("/echo")).send().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Tls, "{e}");
    assert_eq!(e.url(), Some(https("/echo").as_str()));
}

#[test]
fn every_method() {
    let s = session();
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        let r = s.request(Method::from_bytes(method.as_bytes()).unwrap(), https("/echo")).send().unwrap();
        assert_eq!(echo(&r)["method"], method);
    }
    let r = s.head(https("/bytes/100")).send().unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.body().is_empty());
    let r = s.request(Method::from_bytes(b"PROPFIND").unwrap(), https("/echo")).send().unwrap();
    assert_eq!(echo(&r)["method"], "PROPFIND");
}

#[test]
fn binary_request_bodies_arrive_byte_for_byte() {
    let s = session();
    let body: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    for url in [http("/echo"), https("/echo")] {
        let r = s.post(&url).body(body.clone()).send().unwrap();
        assert_eq!(echoed_body(&echo(&r)), body, "{url}");
    }
}

#[test]
fn binary_response_bodies_arrive_byte_for_byte() {
    // Not UTF-8, so the library sends it base64.
    let r = session().get(https("/bytes/300000")).send().unwrap();
    assert_eq!(r.body(), pattern(300_000).as_slice());
}

#[test]
fn text_bodies_arrive_exactly() {
    // Valid UTF-8 travels as a JSON string, escapes and a NUL included.
    let r = session().get(https("/text")).send().unwrap();
    assert_eq!(r.text(), "héllo wörld ✓ \u{0} nul and \"quotes\" <tags> & \u{1F600}");
    let r = session().get(https("/latin1")).send().unwrap();
    assert_eq!(r.text(), "café");
}

#[test]
fn json_form_and_multipart_bodies() {
    let s = session();
    let r = s.post(https("/echo")).json(&serde_json::json!({"a": [1, 2], "b": "ü"})).send().unwrap();
    let e = echo(&r);
    assert_eq!(echoed_header(&e, "content-type").as_deref(), Some("application/json"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&echoed_body(&e)).unwrap(),
        serde_json::json!({"a": [1, 2], "b": "ü"})
    );

    let e = echo(&s.post(https("/echo")).form(&[("k", "v w"), ("é", "&=")]).send().unwrap());
    assert_eq!(echoed_header(&e, "content-type").as_deref(), Some("application/x-www-form-urlencoded"));
    assert_eq!(echoed_body(&e), b"k=v+w&%C3%A9=%26%3D");

    let form = Form::new().text("field", "value").part("file", Part::bytes(vec![0, 1, 2, 255]).file_name("x.bin"));
    let e = echo(&s.post(https("/echo")).multipart(form).send().unwrap());
    let ct = echoed_header(&e, "content-type").unwrap();
    let boundary = ct.strip_prefix("multipart/form-data; boundary=").unwrap();
    let body = echoed_body(&e);
    assert!(body.starts_with(format!("--{boundary}\r\n").as_bytes()));
    assert!(body.windows(4).any(|w| w == [0, 1, 2, 255]));
}

#[test]
fn headers_query_and_auth() {
    let r = session()
        .get(https("/echo?x=1"))
        .query(&[("q", "a b"), ("r", "ü&")])
        .header("X-Custom", "one")
        .header("x-custom", "two")
        .basic_auth("user", Some("pa:ss"))
        .send()
        .unwrap();
    let e = echo(&r);
    assert_eq!(e["query"], "x=1&q=a+b&r=%C3%BC%26");
    assert_eq!(echoed_header(&e, "x-custom").as_deref(), Some("two"));
    assert_eq!(echoed_header(&e, "authorization").as_deref(), Some("Basic dXNlcjpwYTpzcw=="));
}

#[test]
fn multi_valued_response_headers() {
    let r = session().get(https("/multi")).send().unwrap();
    assert_eq!(r.headers().get_all("X-Multi").collect::<Vec<_>>(), ["one", "two"]);
    assert_eq!(r.header("x-single"), Some("only"));
    // Over HTTP/2 the entries keep the order they were sent in.
    let names: Vec<_> = r.headers().iter().map(|(k, _)| k).collect();
    let first = names.iter().position(|n| *n == "x-multi").unwrap();
    assert_eq!(names[first + 1], "x-multi");
}

#[test]
fn exact_headers_go_on_the_wire_as_given() {
    let server =
        RawServer::start(|s, _| write(s, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"));
    let r = session()
        .get(server.url("/x"))
        .exact_headers([
            ("X-First", "1"),
            ("user-agent", "custom/1.0"),
            ("X-Dup", "a"),
            ("X-Dup", "b"),
            ("ACCEPT", "*/*"),
        ])
        .send()
        .unwrap();
    assert_eq!(r.text(), "ok");
    let lines = header_lines(&server.next_head());
    let without_host: Vec<_> = lines.iter().filter(|l| !l.starts_with("Host:")).cloned().collect();
    assert_eq!(without_host, ["X-First: 1", "user-agent: custom/1.0", "X-Dup: a", "X-Dup: b", "ACCEPT: */*"]);
}

#[test]
fn header_order_puts_named_headers_first() {
    let server =
        RawServer::start(|s, _| write(s, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
    session().get(server.url("/")).header("X-Late", "1").header_order(["x-late", "accept"]).send().unwrap();
    let lines = header_lines(&server.next_head());
    let names: Vec<String> =
        // Host and Connection are HTTP/1.1 framing, written first.
        lines.iter().map(|l| l.split(':').next().unwrap().to_ascii_lowercase()).filter(|n| n != "host" && n != "connection").collect();
    assert_eq!(&names[..2], ["x-late", "accept"], "{lines:?}");
}

#[test]
fn fetch_mode_and_per_request_toggles() {
    let e = echo(&session().get(https("/echo")).fetch_mode(FetchMode::Cors).send().unwrap());
    assert_eq!(echoed_header(&e, "sec-fetch-mode").as_deref(), Some("cors"));
    assert_eq!(echoed_header(&e, "sec-fetch-dest").as_deref(), Some("empty"));
    let e = echo(&session().get(https("/echo")).disable_client_hints().send().unwrap());
    assert!(echoed_header(&e, "sec-ch-ua").is_none());
}

#[test]
fn redirects() {
    let s = session();
    let r = s.get(https("/redirect/3")).send().unwrap();
    assert_eq!(r.text(), "landed");
    assert!(r.url().ends_with("/redirect/0"));
    let hops: Vec<_> =
        r.history().iter().map(|h| (h.status(), h.url().rsplit('/').next().unwrap().to_string())).collect();
    assert_eq!(
        hops,
        [(StatusCode::FOUND, "3".into()), (StatusCode::FOUND, "2".into()), (StatusCode::FOUND, "1".into())]
    );
    assert_eq!(r.history()[0].headers().get("location"), Some("/redirect/2"));

    let r = s.get(https("/redirect/3")).follow_redirects(false).send().unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    assert!(r.history().is_empty());

    let few = httpcloak::Session::builder().danger_accept_invalid_certs(true).max_redirects(2).build().unwrap();
    let e = few.get(https("/redirect/5")).send().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Redirect, "{e}");

    s.set_follow_redirects(false);
    assert!(!s.follow_redirects());
    assert_eq!(s.get(https("/redirect/1")).send().unwrap().status(), 302);
    assert_eq!(s.get(https("/redirect/1")).follow_redirects(true).send().unwrap().status(), 200);
}

#[test]
fn status_errors_are_opt_in() {
    let r = session().get(https("/status/503")).send().unwrap();
    assert_eq!(r.status(), 503);
    let e = r.error_for_status().unwrap_err();
    assert!(e.is_status());
    assert_eq!(e.status(), Some(StatusCode::SERVICE_UNAVAILABLE));
    assert_eq!(session().get(https("/empty")).send().unwrap().status(), 204);
}

#[test]
fn cookies_round_trip_through_the_jar() {
    let s = session();
    let r = s.get(https("/set-cookie")).send().unwrap();
    let set: Vec<_> = r.cookies().iter().map(|c| (c.name().to_string(), c.value().to_string())).collect();
    assert_eq!(set, [("a".into(), "1".into()), ("b".into(), "2".into())]);
    assert!(r.cookies()[0].http_only());
    assert_eq!(r.cookies()[1].same_site(), Some(&httpcloak::SameSite::Lax));

    let jar = s.cookies().unwrap();
    assert!(jar.iter().any(|c| c.name() == "a"));
    let e = echo(&s.get(https("/echo")).cookie("extra", "x").send().unwrap());
    let sent = echoed_cookies(&e);
    assert!(sent.contains("a=1") && sent.contains("b=2") && sent.contains("extra=x"), "{sent}");

    s.set_cookie(&httpcloak::Cookie::new("manual", "m").with_domain("localhost").with_path("/")).unwrap();
    assert!(echoed_cookies(&echo(&s.get(https("/echo")).send().unwrap())).contains("manual=m"));
    // A name browsers keep though it is no HTTP token (Azure AD B2C's session cookie).
    let b2c = "x-ms-cpim-sso:tenant.onmicrosoft.com_0";
    s.set_cookie(&httpcloak::Cookie::new(b2c, "s").with_domain("localhost").with_path("/")).unwrap();
    assert!(echoed_cookies(&echo(&s.get(https("/echo")).send().unwrap())).contains(&format!("{b2c}=s")));
    assert!(s.cookies().unwrap().iter().any(|c| c.name() == b2c));
    s.delete_cookie(b2c, None).unwrap();
    s.delete_cookie("manual", None).unwrap();
    assert!(!s.cookies().unwrap().iter().any(|c| c.name() == "manual"));
    s.clear_cookies();
    assert!(s.cookies().unwrap().is_empty());
    assert_eq!(echoed_cookies(&echo(&s.get(https("/echo")).send().unwrap())), "");
}

/// `cookies_for` is what a request to the URL carries, in its header's order,
/// and the jar expires and deletes cookies by `Max-Age` and `Expires`.
#[test]
fn cookies_for_a_url_are_what_its_request_carries() {
    let s = session();
    let set = |name: &str, path: &str| httpcloak::Cookie::new(name, "1").with_domain("localhost").with_path(path);
    let names = |url: &str| s.cookies_for(url).unwrap().iter().map(|c| c.name().to_string()).collect::<Vec<_>>();
    s.set_cookie(&set("root", "/")).unwrap();
    std::thread::sleep(Duration::from_millis(2));
    s.set_cookie(&set("deep", "/a")).unwrap();
    std::thread::sleep(Duration::from_millis(2));
    s.set_cookie(&set("secure", "/").with_secure(true)).unwrap();
    s.set_cookie(&httpcloak::Cookie::new("elsewhere", "1").with_domain("example.com").with_path("/")).unwrap();

    assert_eq!(names("https://localhost/a/b"), ["deep", "root", "secure"]);
    assert_eq!(names("http://localhost/a/b"), ["deep", "root"]);
    assert_eq!(names("https://localhost/b?q=1"), ["root", "secure"]);
    assert!(s.cookies_for("ftp://localhost/").unwrap_err().is_invalid_input());
    let sent = echoed_cookies(&echo(&s.get(https("/echo")).send().unwrap()));
    assert_eq!(sent, "root=1; secure=1", "the header lists what cookies_for does");

    s.set_cookie(&set("brief", "/").with_max_age(Duration::from_secs(1))).unwrap();
    assert!(names("https://localhost/").contains(&"brief".to_string()));
    std::thread::sleep(Duration::from_millis(1100));
    assert!(!names("https://localhost/").contains(&"brief".to_string()), "gone after its Max-Age");
    assert!(!s.cookies().unwrap().iter().any(|c| c.name() == "brief"));

    s.set_cookie(&set("root", "/").with_max_age(Duration::ZERO)).unwrap();
    s.set_cookie(&set("secure", "/").with_expires(std::time::UNIX_EPOCH + Duration::from_secs(10))).unwrap();
    assert_eq!(names("https://localhost/a/b"), ["deep"]);
}

#[test]
fn a_request_timeout_is_exact() {
    let start = Instant::now();
    let e = session().get(https("/sleep/3000")).timeout(Duration::from_millis(300)).send().unwrap_err();
    let took = start.elapsed();
    assert!(e.is_timeout(), "{e}");
    assert!(took >= Duration::from_millis(300) && took < Duration::from_millis(1200), "{took:?}");
}

#[test]
fn a_request_timeout_may_outlast_the_session_timeout() {
    let s = httpcloak::Session::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let e = s.get(https("/sleep/1600")).send().unwrap_err();
    assert!(e.is_timeout(), "{e}");
    let r = s.get(https("/sleep/1600")).timeout(Duration::from_secs(5)).send().unwrap();
    assert_eq!(r.text(), "slept 1600");
}

#[test]
fn connection_failures_are_classified() {
    let e = session().get(refused_url()).send().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Connect, "{e}");
    let e = session().get("http://does-not-exist.invalid/").send().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Dns, "{e}");
    // The library ignores the scheme and would fetch this over plain HTTP.
    for url in ["ftp://example.com/", "ftps://example.com/", "example.com", "//example.com/", "ws://x/"] {
        let e = session().get(url).send().unwrap_err();
        assert!(e.is_invalid_input(), "{url}: {e:?}");
    }
    assert_eq!(session().get(http("/echo").replace("http://", "HTTP://")).send().unwrap().status(), 200);
}

/// A request is not sent only when the library knows no part of it reached the
/// server, or it was refused before it went to the library; every failure once
/// it was written, or may have been, leaves the question open.
#[test]
fn failures_say_whether_the_request_was_sent() {
    let pay = |s: &Session, url: &str| s.post(url).body("charge=100").send().unwrap_err();

    let e = pay(&session(), &refused_url());
    assert!(e.is_not_sent() && e.is_connect(), "{e:?}");
    let refused_proxy = refused_url();
    let via =
        Session::builder().proxy(refused_proxy.trim_end_matches('/')).timeout(Duration::from_secs(5)).build().unwrap();
    let e = pay(&via, "https://pay.test/");
    assert!(e.is_not_sent() && e.is_proxy() && e.proxy_status().is_none(), "{e:?}");
    let e = session().post(http("/echo")).header("X", "a\nb").send().unwrap_err();
    assert!(e.is_not_sent() && e.is_invalid_input(), "{e:?}");

    let hangs_up = RawServer::start(|_, _| {});
    let e = pay(&session(), &hangs_up.url("/pay"));
    assert!(!e.is_not_sent(), "{e:?}");
    let silent = RawServer::start(|_, _| std::thread::sleep(Duration::from_secs(3)));
    let e = session().post(silent.url("/pay")).body("x").timeout(Duration::from_millis(300)).send().unwrap_err();
    assert!(!e.is_not_sent() && e.is_timeout(), "{e:?}");
    let away = refused_url();
    let redirects = RawServer::start(move |s, _| {
        write(
            s,
            format!("HTTP/1.1 303 See Other\r\nLocation: {away}done\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
    });
    let e = pay(&session(), &redirects.url("/pay"));
    assert!(!e.is_not_sent(), "the first hop was answered: {e:?}");
}

/// A proxy that refuses the tunnel says with what status, and nothing was sent.
#[test]
fn a_proxys_refusal_carries_its_status() {
    let proxy = RawServer::start(|s, _| {
        write(s, b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 0\r\n\r\n")
    });
    for version in [httpcloak::HttpVersion::Auto, httpcloak::HttpVersion::Http1] {
        let s = Session::builder()
            .proxy(format!("http://user:wrong@{}", proxy.addr))
            .http_version(version)
            .build()
            .unwrap();
        let e = s.post("https://pay.test/").body("x").send().unwrap_err();
        assert_eq!(e.proxy_status(), Some(StatusCode::PROXY_AUTHENTICATION_REQUIRED), "{e:?}");
        assert!(e.is_proxy() && e.is_not_sent(), "{e:?}");
    }
}

#[test]
fn elapsed_is_measured() {
    let r = session().get(https("/sleep/200")).send().unwrap();
    assert!(r.elapsed() >= Duration::from_millis(200) && r.elapsed() < Duration::from_secs(5), "{:?}", r.elapsed());
}

#[test]
fn concurrent_failures_each_get_their_own_reason() {
    // The library's last-error slot is per session, so blocking requests that
    // fail together used to report each other's reason, or none.
    let s = session();
    let refused = refused_url();
    let ok = https("/sleep/10");
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..64)
            .map(|i| {
                let (s, refused, ok) = (s.clone(), refused.clone(), ok.clone());
                scope.spawn(move || {
                    if i % 2 == 0 {
                        Err(s.get(refused).send().unwrap_err())
                    } else {
                        Ok(s.get(ok).send().unwrap())
                    }
                })
            })
            .collect();
        for h in handles {
            match h.join().unwrap() {
                Err(e) => assert!(e.message().contains("refused"), "{e}"),
                Ok(r) => assert_eq!(r.status(), 200),
            }
        }
    });
}
