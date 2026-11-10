//! Against real servers on the internet. Ignored by default; run with
//! `cargo test --test live -- --ignored`.

use std::time::Duration;

use httpcloak::{presets, ErrorKind, HttpVersion, Session, Version};

fn trace(session: &Session, host: &str) -> std::collections::HashMap<String, String> {
    let r = session.get(format!("https://{host}/cdn-cgi/trace")).send().unwrap().error_for_status().unwrap();
    r.text().lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
#[ignore = "network"]
fn chrome_fingerprint_matches_chrome() {
    let s = Session::builder().preset(presets::CHROME_LATEST).build().unwrap();
    let seen: serde_json::Value = s.get("https://tls.peet.ws/api/all").send().unwrap().json().unwrap();
    let ja4 = seen["tls"]["ja4"].as_str().unwrap();
    assert!(ja4.starts_with("t13d") && ja4.contains("h2"), "{ja4}");
    assert_eq!(seen["http_version"], "h2");
    assert!(seen["user_agent"].as_str().unwrap().contains("Chrome/"));
}

#[test]
#[ignore = "network"]
fn http3_to_cloudflare() {
    let s = Session::builder().http_version(HttpVersion::Http3).build().unwrap();
    assert_eq!(trace(&s, "www.cloudflare.com")["http"], "http/3");
    let r = s.get("https://www.cloudflare.com/cdn-cgi/trace").send().unwrap();
    assert_eq!(r.version(), Version::HTTP_3);
}

#[test]
#[ignore = "network"]
fn ech_over_http3() {
    // cloudflare-ech.com is Cloudflare's ECH test host.
    let s = Session::builder().http_version(HttpVersion::Http3).build().unwrap();
    assert_eq!(trace(&s, "cloudflare-ech.com")["sni"], "encrypted");
}

#[test]
#[ignore = "network"]
fn ech_over_http2_when_opted_in() {
    // Over TCP the library only uses ECH with a config domain given.
    let s =
        Session::builder().http_version(HttpVersion::Http2).ech_config_domain("cloudflare-ech.com").build().unwrap();
    let t = trace(&s, "cloudflare-ech.com");
    assert_eq!((t["http"].as_str(), t["sni"].as_str()), ("http/2", "encrypted"));
}

#[test]
#[ignore = "network"]
fn async_http3_and_streams_to_cloudflare() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let s = Session::builder().http_version(HttpVersion::Http3).build().unwrap();
        let r = s.get("https://www.cloudflare.com/cdn-cgi/trace").send_async().await.unwrap();
        assert!(r.text().contains("http=http/3"));
        let stream = s.get("https://www.cloudflare.com/cdn-cgi/trace").send_stream_async().await.unwrap();
        assert_eq!(stream.version(), Version::HTTP_3);
        assert!(stream.text().unwrap().contains("http=http/3"));
    });
}

#[test]
#[ignore = "network"]
fn bad_certificates_fail() {
    for host in ["expired.badssl.com", "self-signed.badssl.com", "wrong.host.badssl.com", "untrusted-root.badssl.com"] {
        let attempt = || {
            Session::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap()
                .get(format!("https://{host}/"))
                .send()
                .unwrap_err()
        };
        // badssl.com is slow to accept at times; a timeout says nothing here.
        let mut e = attempt();
        if e.is_timeout() {
            e = attempt();
        }
        assert_eq!(e.kind(), ErrorKind::Tls, "{host}: {e}");
    }
}

#[test]
#[ignore = "network"]
fn a_real_host_that_does_not_resolve() {
    let e = Session::new().unwrap().get("https://this-host-does-not-exist.invalid/").send().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Dns, "{e}");
}
