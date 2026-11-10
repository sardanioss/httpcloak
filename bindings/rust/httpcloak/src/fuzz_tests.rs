//! Property tests for what crosses the C boundary as text: the JSON the
//! library returns, the messages it fails with, and the JSON sent to it. None
//! of it may panic, whatever the library or a caller hands over.

use std::collections::BTreeMap;
use std::time::Duration;

use proptest::prelude::*;

use crate::error::classify;
use crate::headers::{valid_name, valid_value, Headers};
use crate::response::Response;
use crate::session::Session;

fn fake_session() -> Session {
    // No session has handle -1; freeing it is a no-op in the library.
    Session { inner: std::sync::Arc::new(crate::session::SessionInner { handle: -1 }) }
}

/// Arbitrary JSON, nested a few levels, shaped like the library's output
/// often enough to reach past the first field.
fn json_value() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::from),
        any::<i64>().prop_map(serde_json::Value::from),
        any::<f64>().prop_filter("finite", |f| f.is_finite()).prop_map(serde_json::Value::from),
        ".*".prop_map(serde_json::Value::from),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(serde_json::Value::from),
            prop::collection::btree_map(
                prop_oneof![
                    Just("status_code".to_string()),
                    Just("headers".to_string()),
                    Just("body".to_string()),
                    Just("body_encoding".to_string()),
                    Just("cookies".to_string()),
                    Just("history".to_string()),
                    Just("header_order".to_string()),
                    Just("trailer".to_string()),
                    Just("protocol".to_string()),
                    Just("expires".to_string()),
                    ".{0,8}".prop_map(String::from),
                ],
                inner,
                0..8
            )
            .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn response_json_never_panics(value in json_value()) {
        let _ = Response::from_json(&value.to_string(), Duration::ZERO).map(|r| r.check_complete(&http::Method::GET));
    }

    #[test]
    fn response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = Response::from_json(&String::from_utf8_lossy(&bytes), Duration::ZERO);
    }

    #[test]
    fn well_formed_responses_decode_exactly(
        status in 100u16..600,
        body in prop::collection::vec(any::<u8>(), 0..256),
        headers in prop::collection::btree_map("[a-z-]{1,12}", prop::collection::vec("[ -~]{0,16}", 1..3), 0..6),
    ) {
        use base64::Engine as _;
        let json = serde_json::json!({
            "status_code": status,
            "headers": headers,
            "body": base64::engine::general_purpose::STANDARD.encode(&body),
            "body_encoding": "base64",
        });
        let r = Response::from_json(&json.to_string(), Duration::ZERO).unwrap();
        prop_assert_eq!(r.status().as_u16(), status);
        prop_assert_eq!(r.body(), body.as_slice());
        prop_assert_eq!(r.headers().len(), headers.values().map(Vec::len).sum::<usize>());
        for (name, values) in &headers {
            prop_assert_eq!(r.headers().get_all(name).collect::<Vec<_>>(), values.iter().map(String::as_str).collect::<Vec<_>>());
        }
    }

    #[test]
    fn header_ordering_loses_and_invents_nothing(
        map in prop::collection::btree_map("[a-c]{1,2}", prop::collection::vec("[a-z]{0,3}", 0..4), 0..6),
        order in prop::collection::vec("[a-d]{1,2}", 0..12),
    ) {
        let h = Headers::from_map(map.clone(), &order);
        let mut got: Vec<(String, String)> = h.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let mut want: Vec<(String, String)> =
            map.iter().flat_map(|(k, vs)| vs.iter().map(move |v| (k.clone(), v.clone()))).collect();
        got.sort();
        want.sort();
        prop_assert_eq!(got, want);
    }

    #[test]
    fn classification_never_panics(message in ".*") {
        let _ = classify(&message, &[]);
        let _ = classify(&message, std::slice::from_ref(&message));
    }

    #[test]
    fn a_host_name_never_decides_the_classification(host in prop_oneof![
        "[a-z0-9]([a-z0-9.-]{0,20}[a-z0-9])?",
        // The words the classifier looks for, as whole single-label names.
        prop::sample::select(vec!["timeout", "tls", "proxy", "socks", "socks5", "masque", "eof", "dial", "x509",
            "certificate", "handshake", "redirect", "ech", "dns", "timed", "deadline"]).prop_map(String::from),
    ]) {
        // Whatever words the host spells, a refused dial to it is a refused dial.
        let message = format!("dial {host}:443 [h1]: dial tcp 10.0.0.1:443: connect: connection refused");
        prop_assert_eq!(classify(&message, &[]), crate::ErrorKind::Connect);
        let unprefixed = format!("DNS resolution failed: lookup {host}: no such host");
        prop_assert_eq!(classify(&unprefixed, std::slice::from_ref(&host)), crate::ErrorKind::Dns);
    }

    #[test]
    fn requests_never_panic_and_never_send_invalid_headers(
        url in ".{0,40}",
        name in ".{0,16}",
        value in ".{0,32}",
        cookie in (".{0,8}", ".{0,8}"),
        query in prop::collection::vec((".{0,8}", ".{0,8}"), 0..4),
        body in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let s = fake_session();
        let b = s.post(format!("http://h/{url}"))
            .header(name.clone(), value.clone())
            .cookie(cookie.0.clone(), cookie.1.clone())
            .query(&query)
            .body(body);
        match b.prepare(false) {
            Ok(p) => {
                // Whatever got through is what a server can accept.
                prop_assert!(valid_name(&name) && valid_value(&value));
                let v: serde_json::Value = serde_json::from_slice(p.json.as_bytes()).unwrap();
                for (k, val) in v["headers"].as_object().unwrap() {
                    prop_assert!(valid_name(k));
                    prop_assert!(valid_value(val.as_str().unwrap()));
                }
                prop_assert!(!v["url"].as_str().unwrap().bytes().any(|b| b < 0x20 || b == 0x7f));
            }
            Err(e) => prop_assert!(e.is_invalid_input(), "{:?}", e),
        }
    }

    #[test]
    fn exact_headers_never_panic(pairs in prop::collection::vec((".{0,10}", ".{0,10}"), 0..6)) {
        let s = fake_session();
        let _ = s.get("http://h/").exact_headers(pairs).prepare(false);
    }

    #[test]
    fn session_options_never_panic(
        preset in ".{0,12}",
        timeout_ms in 0u64..10_000_000,
        redirects in any::<u32>(),
        retry in any::<u32>(),
        statuses in prop::collection::vec(any::<u16>(), 0..4),
        proxy in ".{0,20}",
    ) {
        // Building validates without calling the library unless it would
        // create a session; stop short of that for invalid presets.
        let b = Session::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .max_redirects(redirects)
            .retry(retry)
            .retry_on_status(statuses)
            .proxy(proxy);
        if preset.is_empty() || crate::session::check_preset(&preset).is_ok() {
            let _ = b.preset(preset).build();
        } else {
            prop_assert!(b.preset(preset).build().unwrap_err().is_invalid_input());
        }
    }

    #[test]
    fn cookie_wire_form_never_panics(value in json_value()) {
        if let Ok(w) = serde_json::from_value::<crate::cookie::WireCookie>(value) {
            let c = crate::cookie::Cookie::from_wire(w);
            let _ = c.validate();
            let _ = serde_json::to_string(&c.to_wire()).unwrap();
        }
    }

    #[test]
    fn header_maps_from_the_library_never_panic(map in prop::collection::btree_map(".{0,6}", prop::collection::vec(".{0,6}", 0..3), 0..5)) {
        let h = Headers::from_map(map, &[]);
        let _ = h.to_header_map();
        let _: BTreeMap<_, _> = h.iter().collect();
    }
}
