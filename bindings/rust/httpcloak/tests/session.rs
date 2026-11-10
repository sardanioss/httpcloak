//! Session lifecycle, configuration, presets and the misbehaving server.

mod common;

use std::time::Duration;

use common::*;
use httpcloak::{presets, Cookie, ErrorKind, HttpVersion, PresetPool, Session};

#[test]
fn every_preset_constant_builds_a_working_session() {
    let available = httpcloak::available_presets().unwrap();
    for name in presets::ALL {
        assert!(available.contains_key(*name), "{name} is not a built-in preset");
        Session::builder().preset(*name).build().unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    assert!(available[presets::CHROME_LATEST].supports_http3());
    // Each constant in a browser family really is different on the wire.
    let ua = |preset: &str| {
        let s = Session::builder().preset(preset).build().unwrap();
        echoed_header(&echo(&s.get(http("/echo")).send().unwrap()), "user-agent").unwrap()
    };
    assert!(ua(presets::FIREFOX_LATEST).contains("Firefox/"));
    assert!(ua(presets::SAFARI_LATEST).contains("Safari/") && !ua(presets::SAFARI_LATEST).contains("Chrome/"));
    assert!(ua(presets::CHROME_LATEST_WINDOWS).contains("Windows NT"));
}

#[test]
fn an_unknown_preset_fails_at_build_not_at_the_first_request() {
    let e = Session::builder().preset("chrome-9999").build().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    assert!(e.message().contains("chrome-9999"), "{e}");
    // An empty name means the default, as in every binding.
    Session::builder().preset("").build().unwrap();
}

#[test]
fn describe_and_custom_presets() {
    let described: serde_json::Value =
        serde_json::from_str(&httpcloak::describe_preset(presets::CHROME_155).unwrap()).unwrap();
    assert!(described["preset"]["name"].as_str().unwrap().starts_with("chrome-155"));
    assert!(httpcloak::describe_preset("nope").unwrap_err().is_invalid_input());

    // A custom preset derived from a built-in one.
    let json = r#"{"version":1,"preset":{"name":"rust-test-preset","based_on":"chrome-155","headers":{"user_agent":"RustTestAgent/1.0"}}}"#;
    let name = match httpcloak::load_preset(json) {
        Ok(name) => name,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(name, "rust-test-preset");
    let e = httpcloak::load_preset(json).unwrap_err();
    assert!(e.message().contains("already registered"), "{e}");
    let s = Session::builder().preset(&name).build().unwrap();
    let r = s.get(http("/echo")).send().unwrap();
    assert_eq!(echoed_header(&echo(&r), "user-agent").as_deref(), Some("RustTestAgent/1.0"));
    httpcloak::unregister_preset(&name).unwrap();
    assert!(Session::builder().preset(&name).build().is_err());

    assert!(httpcloak::load_preset("{not json").unwrap_err().is_invalid_input());
    assert!(httpcloak::load_preset_file("/no/such/preset.json").is_err());
}

#[test]
fn preset_pools() {
    let json = r#"{"version":1,"pool":{"name":"rust-pool","strategy":"round-robin","presets":[
        {"name":"rust-pool-a","based_on":"chrome-155-windows"},
        {"name":"rust-pool-b","based_on":"chrome-155-linux"},
        {"name":"rust-pool-c","based_on":"firefox-148"}]}}"#;
    let pool = PresetPool::from_json(json).unwrap();
    assert_eq!(pool.name().unwrap(), "rust-pool");
    assert_eq!(pool.len(), 3);
    assert_eq!(pool.presets().len(), 3);
    assert!(pool.get(3).is_none());
    assert!(pool.get(usize::MAX).is_none());
    let picks: Vec<_> = (0..6).map(|_| pool.next_preset().unwrap()).collect();
    assert_eq!(picks[..3], picks[3..]);
    let random = pool.random().unwrap();
    assert!(pool.presets().contains(&random));
    Session::builder().preset(pool.pick().unwrap()).build().unwrap();
    assert!(format!("{pool:?}").contains("rust-pool"));

    assert!(PresetPool::from_json("[]").unwrap_err().is_invalid_input());
    assert!(PresetPool::from_json(r#"{"version":1,"pool":{"name":"x","presets":[]}}"#).is_err());
    // Dropping the pool unregisters its presets.
    drop(pool);
    assert!(Session::builder().preset("rust-pool-a").build().unwrap_err().is_invalid_input());
    assert!(PresetPool::from_file("/no/such/pool.json").is_err());
}

#[test]
fn fork_shares_cookies_but_not_connections() {
    let s = session();
    s.get(https("/set-cookie")).send().unwrap();
    s.set_conditional_cache(true);
    s.set_client_hints(false);
    let fork = s.fork().unwrap();
    assert!(fork.conditional_cache());
    assert!(!fork.client_hints());
    assert!(echoed_cookies(&echo(&fork.get(https("/echo")).send().unwrap())).contains("a=1"));
    fork.set_cookie(&Cookie::new("from_fork", "1").with_domain("localhost")).unwrap();
    assert!(s.cookies().unwrap().iter().any(|c| c.name() == "from_fork"));
    drop(s);
    assert_eq!(fork.get(https("/bytes/1")).send().unwrap().status(), 200);
}

#[test]
fn marshal_save_and_load() {
    let s = session();
    s.get(https("/set-cookie")).send().unwrap();
    let data = s.marshal().unwrap();
    let restored = Session::unmarshal(&data).unwrap();
    assert!(restored.cookies().unwrap().iter().any(|c| c.name() == "a"));
    // The restored session keeps the options: its certificate check is off.
    assert_eq!(restored.get(https("/bytes/3")).send().unwrap().status(), 200);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.json");
    s.save(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let loaded = Session::load(&path).unwrap();
    assert_eq!(loaded.cookies().unwrap().len(), s.cookies().unwrap().len());

    assert_eq!(Session::load(dir.path().join("missing")).unwrap_err().kind(), ErrorKind::Io);
    assert!(Session::unmarshal("not json").unwrap_err().is_invalid_input());
    assert!(Session::unmarshal(r#"{"version":9999}"#).unwrap_err().is_invalid_input());
    assert!(Session::unmarshal("").unwrap_err().is_invalid_input());
    assert!(s.save(dir.path().join("no/such/dir/file")).is_err());
}

#[test]
fn runtime_settings_round_trip() {
    let s = session();
    for value in [false, true] {
        s.set_conditional_cache(value);
        assert_eq!(s.conditional_cache(), value);
        s.set_client_hints(value);
        assert_eq!(s.client_hints(), value);
        s.set_high_entropy_client_hints(value);
        assert_eq!(s.high_entropy_client_hints(), value);
        s.set_follow_redirects(value);
        assert_eq!(s.follow_redirects(), value);
    }
    s.set_max_redirects(4).unwrap();
    assert_eq!(s.max_redirects(), 4);
    assert!(s.set_max_redirects(0).unwrap_err().is_invalid_input());
    assert!(s.set_max_redirects(u32::MAX).unwrap_err().is_invalid_input());
    assert_eq!(s.max_redirects(), 4);

    let preset_order = s.header_order();
    assert!(preset_order.iter().any(|h| h == "user-agent"), "{preset_order:?}");
    s.set_header_order(["accept", "user-agent"]).unwrap();
    assert_eq!(s.header_order(), ["accept", "user-agent"]);
    s.set_header_order(Vec::<String>::new()).unwrap();
    assert_eq!(s.header_order(), preset_order);
    assert!(s.set_header_order(["bad header"]).unwrap_err().is_invalid_input());

    assert_eq!(s.proxy(), None);
    s.set_proxy(Some("http://127.0.0.1:1")).unwrap();
    assert_eq!(s.proxy().as_deref(), Some("http://127.0.0.1:1"));
    s.set_proxy(None).unwrap();
    assert_eq!(s.proxy(), None);
    s.set_tcp_proxy(Some("socks5://127.0.0.1:2")).unwrap();
    assert_eq!(s.tcp_proxy().as_deref(), Some("socks5://127.0.0.1:2"));
    s.set_udp_proxy(Some("masque://127.0.0.1:3")).unwrap();
    assert_eq!(s.udp_proxy().as_deref(), Some("masque://127.0.0.1:3"));
    assert!(s.set_proxy(Some("http://a\0b")).unwrap_err().is_invalid_input());

    s.set_identifier(Some("tenant-1")).unwrap();
    s.set_identifier(None).unwrap();
    s.clear_cache();
    s.touch();
    assert!(s.idle_time() < Duration::from_secs(5));
    assert!(s.is_active());
}

#[test]
fn a_dead_proxy_is_a_proxy_error() {
    let s =
        Session::builder().proxy(refused_url().trim_end_matches('/')).timeout(Duration::from_secs(5)).build().unwrap();
    let e = s.get("http://example.com/").send().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Proxy, "{e}");
}

#[test]
fn stats_count_requests() {
    let s = session();
    for _ in 0..3 {
        s.get(https("/bytes/1")).send().unwrap();
    }
    let stats = s.stats().unwrap();
    assert_eq!(stats.request_count, 3);
    assert!(stats.active);
    assert!(stats.age > Duration::ZERO);
    assert!(stats.transport.is_object());
    assert!(stats.created_at <= stats.last_used);
}

#[test]
fn refresh_and_protocol_switches() {
    let s = session();
    s.get(https("/bytes/1")).send().unwrap();
    s.refresh();
    let e = echo(&s.get(https("/echo")).send().unwrap());
    assert_eq!(echoed_header(&e, "cache-control").as_deref(), Some("max-age=0"));
    s.refresh_with_protocol(HttpVersion::Http1).unwrap();
    assert_eq!(s.get(https("/echo")).send().unwrap().version(), httpcloak::Version::HTTP_11);
    s.refresh_with_protocol(HttpVersion::Auto).unwrap();
}

#[test]
fn warmup_loads_a_page() {
    session().warmup(&https("/text"), Some(Duration::from_secs(5))).unwrap();
    assert!(session().warmup(&refused_url(), Some(Duration::from_secs(5))).is_err());
    assert!(session().warmup("http://x\0", None).unwrap_err().is_invalid_input());
    assert!(session().warmup(&https("/"), Some(Duration::ZERO)).unwrap_err().is_invalid_input());
}

#[test]
fn ech_dns_servers() {
    let defaults = httpcloak::ech_dns_servers();
    assert!(!defaults.is_empty());
    httpcloak::set_ech_dns_servers(["1.1.1.1:53", "[2606:4700:4700::1111]:53"]).unwrap();
    assert_eq!(httpcloak::ech_dns_servers(), ["1.1.1.1:53", "[2606:4700:4700::1111]:53"]);
    for bad in ["1.1.1.1", "::1:53", ":53", "host:0", "host:99999", ""] {
        assert!(httpcloak::set_ech_dns_servers([bad]).unwrap_err().is_invalid_input(), "{bad}");
    }
    httpcloak::set_ech_dns_servers(Vec::<&str>::new()).unwrap();
    assert_eq!(httpcloak::ech_dns_servers(), defaults);
}

#[test]
fn version_and_memory() {
    assert_eq!(httpcloak::version(), env!("CARGO_PKG_VERSION"));
    httpcloak::trim_memory();
}

// --- Servers that misbehave -------------------------------------------------

#[test]
fn a_server_that_closes_without_answering() {
    let server = RawServer::start(|s, _| {
        let _ = s.shutdown(std::net::Shutdown::Both);
    });
    let e = session().get(server.url("/")).send().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Connect, "{e}");
}

#[test]
fn a_server_that_never_answers_times_out() {
    let server = RawServer::start(|_, _| std::thread::sleep(Duration::from_secs(30)));
    let e = session().get(server.url("/")).timeout(Duration::from_millis(500)).send().unwrap_err();
    assert!(e.is_timeout(), "{e}");
}

#[test]
fn a_server_that_answers_garbage() {
    for garbage in [
        &b"NOT HTTP AT ALL\r\n\r\n"[..],
        b"HTTP/1.1 abc OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nBad Header\r\n\r\n",
        b"\x00\xff\x00\xff",
    ] {
        let server = RawServer::start(move |s, _| {
            write(s, garbage);
            let _ = s.shutdown(std::net::Shutdown::Both);
        });
        let result = session().get(server.url("/")).send();
        assert!(result.is_err(), "{:?} was accepted: {result:?}", String::from_utf8_lossy(garbage));
    }
}

#[test]
fn a_chunked_body_that_breaks_off() {
    let server = RawServer::start(|s, _| {
        write(s, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n");
        let _ = s.shutdown(std::net::Shutdown::Both);
    });
    assert!(session().get(server.url("/")).send().is_err());
    let server2 = RawServer::start(|s, _| {
        write(s, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n");
        let _ = s.shutdown(std::net::Shutdown::Both);
    });
    let mut stream = session().get(server2.url("/")).send_stream().unwrap();
    let mut body = Vec::new();
    assert!(std::io::Read::read_to_end(&mut stream, &mut body).is_err());
    assert_eq!(body, b"hello");
}

#[test]
fn huge_headers_and_many_of_them() {
    let s = session();
    // As large as the test server takes (hyper's limit is 16 KiB in all).
    let big = "v".repeat(8 * 1024);
    let e = echo(&s.get(https("/echo")).header("X-Big", &big).send().unwrap());
    assert_eq!(echoed_header(&e, "x-big").unwrap().len(), big.len());
    let many: Vec<(String, String)> = (0..100).map(|i| (format!("X-H{i}"), i.to_string())).collect();
    let e = echo(&s.get(https("/echo")).headers(many).send().unwrap());
    assert_eq!(echoed_header(&e, "x-h99").as_deref(), Some("99"));
}

#[test]
fn unicode_everywhere_it_is_allowed() {
    let e =
        echo(&session().get(https("/echo/ünï/✓")).query(&[("ключ", "值")]).header("X-U", "ünïcödé ✓").send().unwrap());
    assert_eq!(echoed_header(&e, "x-u").as_deref(), Some("ünïcödé ✓"));
    assert_eq!(e["query"], "%D0%BA%D0%BB%D1%8E%D1%87=%E5%80%BC");
}
