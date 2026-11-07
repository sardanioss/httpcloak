//! Property tests through the real library and over the wire: whatever a
//! caller can put in a request arrives as given, whatever a server sends
//! comes back as sent, and nothing the library cannot carry is accepted.

mod common;

use common::*;
use proptest::prelude::*;

/// `cases` by default; PROPTEST_CASES for a longer run.
fn config(cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(cases);
    ProptestConfig { cases, failure_persistence: None, ..ProptestConfig::default() }
}

/// What a header value may hold: anything but control characters, which
/// the binding refuses. HTTP trims the surrounding spaces and tabs.
fn header_value() -> impl Strategy<Value = String> {
    "[^\\x00-\\x08\\x0a-\\x1f\\x7f]{0,40}"
}

proptest! {
    #![proptest_config(config(150))]

    #[test]
    fn request_bodies_arrive_intact(body in prop::collection::vec(any::<u8>(), 0..4096), tls in any::<bool>()) {
        let url = if tls { https("/echo") } else { http("/echo") };
        let r = session().post(url).body(body.clone()).send().unwrap();
        prop_assert_eq!(echoed_body(&echo(&r)), body);
    }

    #[test]
    fn response_bodies_arrive_intact(body in prop_oneof![
        prop::collection::vec(any::<u8>(), 0..4096),
        ".{0,512}".prop_map(String::into_bytes),
    ], tls in any::<bool>()) {
        // Valid UTF-8 travels through the library as a JSON string, anything
        // else as base64; both must give back exactly the bytes sent.
        let url = if tls { https("/reflect") } else { http("/reflect") };
        let r = session().post(url).body(body.clone()).send().unwrap();
        prop_assert_eq!(r.body(), body.as_slice());
    }

    #[test]
    fn streamed_bodies_arrive_intact(body in prop::collection::vec(any::<u8>(), 0..8192)) {
        let s = session().post(https("/reflect")).body(body.clone()).send_stream().unwrap();
        prop_assert_eq!(s.bytes().unwrap(), body);
    }

    #[test]
    fn uploads_arrive_intact(chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..2048), 0..8)) {
        use std::io::Write;
        let mut up = session().upload(https("/upload")).start().unwrap();
        let mut all = Vec::new();
        for c in &chunks {
            up.write_all(c).unwrap();
            all.extend_from_slice(c);
        }
        let report: serde_json::Value = up.finish().unwrap().json().unwrap();
        prop_assert_eq!(report["len"].as_u64().unwrap() as usize, all.len());
        prop_assert_eq!(report["fnv"].as_str().unwrap(), fnv(&all).to_string());
    }

    #[test]
    fn header_values_arrive_as_given(value in header_value(), tls in any::<bool>()) {
        let url = if tls { https("/echo") } else { http("/echo") };
        let r = session().get(url).header("X-Fuzz", value.clone()).send().unwrap();
        let got = echoed_header(&echo(&r), "x-fuzz").unwrap_or_default();
        prop_assert_eq!(got.as_str(), value.trim_matches(|c| c == ' ' || c == '\t'));
    }

    #[test]
    fn query_parameters_arrive_as_given(pairs in prop::collection::vec((".{0,12}", ".{0,12}"), 1..5)) {
        let r = session().get(https("/echo")).query(&pairs).send().unwrap();
        let query = echo(&r)["query"].as_str().unwrap().to_string();
        let got: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes()).into_owned().collect();
        prop_assert_eq!(got, pairs);
    }

    #[test]
    fn per_request_cookies_arrive_as_given(name in "[A-Za-z0-9_!#$%&'*+.^`|~-]{1,12}", value in "[!-:<-~]{0,20}") {
        let r = session().get(https("/echo")).cookie(name.clone(), value.clone()).send().unwrap();
        let sent = echoed_cookies(&echo(&r));
        prop_assert!(sent.split("; ").any(|c| c == format!("{name}={value}")), "{}", sent);
    }

    #[test]
    fn arbitrary_strings_are_refused_or_sent_never_mangled(name in ".{0,12}", value in ".{0,24}") {
        match session().get(http("/echo")).header(name.clone(), value.clone()).send() {
            Ok(r) => {
                let got = echoed_header(&echo(&r), &name);
                // A value that is empty once trimmed asks for no such header.
                let sent = value.trim_matches(|c| c == ' ' || c == '\t');
                prop_assert_eq!(got.as_deref(), (!sent.is_empty()).then_some(sent));
            }
            Err(e) => prop_assert!(e.is_invalid_input(), "{:?}", e),
        }
    }
}

proptest! {
    #![proptest_config(config(60))]

    #[test]
    fn exact_headers_go_on_the_wire_byte_for_byte(
        pairs in prop::collection::vec(("[A-Za-z][A-Za-z0-9-]{0,10}", "[!-~][ -~]{0,20}[!-~]|[!-~]"), 1..8)
    ) {
        let server = RawServer::start(|s, _| write(s, b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"));
        // Host is framing the library writes itself.
        let pairs: Vec<_> = pairs.into_iter().filter(|(k, _)| !k.eq_ignore_ascii_case("host")
            && !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("transfer-encoding")
            && !k.eq_ignore_ascii_case("connection")).collect();
        prop_assume!(!pairs.is_empty());
        session().get(server.url("/")).exact_headers(pairs.clone()).send().unwrap();
        let lines: Vec<String> = header_lines(&server.next_head()).into_iter().filter(|l| !l.starts_with("Host: ")).collect();
        let want: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}: {v}")).collect();
        prop_assert_eq!(lines, want);
    }
}

#[test]
fn an_empty_value_leaves_the_header_off() {
    let r = session().get(http("/echo")).header("Accept-Language", "").header("X-Kept", "1").send().unwrap();
    let sent = echo(&r);
    assert_eq!(echoed_header(&sent, "accept-language"), None, "the preset's is left off too");
    assert_eq!(echoed_header(&sent, "x-kept").as_deref(), Some("1"));
}
