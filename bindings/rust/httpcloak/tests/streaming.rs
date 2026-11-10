//! Streamed responses and streamed uploads.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::time::{Duration, Instant};

use common::*;
use httpcloak::{ErrorKind, Method};

#[test]
fn chunks_arrive_as_they_are_sent() {
    let stream = session().get(https("/stream/5/300")).send_stream().unwrap();
    assert_eq!(stream.status(), 200);
    let start = Instant::now();
    let mut lines = BufReader::new(stream).lines();
    assert_eq!(lines.next().unwrap().unwrap(), "chunk 0");
    // The first line came well before the last was sent (5 x 300ms).
    assert!(start.elapsed() < Duration::from_millis(1000), "{:?}", start.elapsed());
    let rest: Vec<_> = lines.map(Result::unwrap).collect();
    assert_eq!(rest, ["chunk 1", "chunk 2", "chunk 3", "chunk 4"]);
}

#[test]
fn stream_metadata_and_full_reads() {
    for url in [http("/bytes/200000"), https("/bytes/200000")] {
        let stream = session().get(&url).send_stream().unwrap();
        assert_eq!(stream.content_length(), Some(200_000));
        assert_eq!(stream.header("content-type"), Some("application/octet-stream"));
        assert_eq!(stream.bytes().unwrap(), pattern(200_000), "{url}");
    }
    let text = session().get(https("/latin1")).send_stream().unwrap().text().unwrap();
    assert_eq!(text, "café");
}

#[test]
fn trailers_after_the_body() {
    let mut stream = session().get(https("/trailers")).send_stream().unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).unwrap();
    assert_eq!(body, "body");
    let trailers = stream.trailers();
    assert_eq!(trailers.get("grpc-status"), Some("0"));
    assert_eq!(trailers.get("x-checksum"), Some("abc"));
    // A buffered response has them too.
    let r = session().get(https("/trailers")).send().unwrap();
    assert_eq!(r.trailers().get("grpc-status"), Some("0"));
}

#[test]
fn reads_after_the_end_keep_returning_zero() {
    let mut stream = session().get(https("/bytes/10")).send_stream().unwrap();
    let mut buf = [0u8; 64];
    let mut total = 0;
    loop {
        let n = stream.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        total += n;
    }
    assert_eq!(total, 10);
    assert_eq!(stream.read(&mut buf).unwrap(), 0);
    assert_eq!(stream.read(&mut []).unwrap(), 0);
}

#[test]
fn a_truncated_body_is_an_error_not_an_end() {
    let server = RawServer::start(|s, _| {
        write(s, b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nonly a little");
        let _ = s.shutdown(std::net::Shutdown::Both);
    });
    let e = session().get(server.url("/")).send_stream().unwrap().bytes().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
}

#[test]
fn a_truncated_buffered_body_is_an_error() {
    let server = RawServer::start(|s, _| {
        write(s, b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nonly a little");
        let _ = s.shutdown(std::net::Shutdown::Both);
    });
    let e = session().get(server.url("/")).send().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    assert!(e.message().contains("13 of the 1000 bytes"), "{e}");
}

#[test]
fn dropping_a_stream_unread_closes_it() {
    for _ in 0..20 {
        let stream = session().get(https("/stream/1000/10")).send_stream().unwrap();
        drop(stream);
    }
    // And the session still works afterwards.
    assert_eq!(session().get(https("/bytes/1")).send().unwrap().status(), 200);
}

#[test]
fn a_stream_outlives_its_session_handle() {
    let s = session();
    let stream = s.get(https("/stream/3/100")).send_stream().unwrap();
    drop(s);
    assert_eq!(stream.text().unwrap(), "chunk 0\nchunk 1\nchunk 2\n");
}

#[test]
fn streams_do_not_follow_redirects() {
    let stream = session().get(https("/redirect/2")).send_stream().unwrap();
    assert_eq!(stream.status(), 302);
    assert_eq!(stream.header("location"), Some("/redirect/1"));
}

#[test]
fn a_stream_timeout_bounds_the_whole_body() {
    let stream = session().get(https("/stream/50/100")).timeout(Duration::from_millis(1500)).send_stream().unwrap();
    let start = Instant::now();
    let e = stream.bytes().unwrap_err();
    assert!(e.is_timeout(), "{e:?}");
    // Exactly, not at the whole second the library rounds it up to.
    assert!(start.elapsed() < Duration::from_millis(1900), "{:?}", start.elapsed());
}

#[test]
fn a_stream_without_a_timeout_reads_past_the_old_two_minute_default_shape() {
    // Not two minutes of test, but: no timeout means the library is given an
    // unbounded one, so a body slower than the session timeout still arrives.
    let s = httpcloak::Session::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let text = s.get(https("/stream/4/500")).send_stream().unwrap().text().unwrap();
    assert_eq!(text.lines().count(), 4);
}

#[test]
fn an_upload_streams_a_large_body() {
    let mut upload =
        session().upload(https("/upload")).method(Method::PUT).content_type("application/x-test").start().unwrap();
    let mut sent = Vec::new();
    for i in 0..40u32 {
        let chunk: Vec<u8> = (0..250_000).map(|j| ((i as usize * 7 + j) % 256) as u8).collect();
        upload.write_all(&chunk).unwrap();
        sent.extend(chunk);
    }
    let r = upload.finish().unwrap();
    let report: serde_json::Value = r.json().unwrap();
    assert_eq!(report["method"], "PUT");
    assert_eq!(report["len"], 10_000_000);
    assert_eq!(report["fnv"], fnv(&sent).to_string());
    assert_eq!(report["content_type"], "application/x-test");
}

#[test]
fn an_upload_that_cannot_connect_fails_its_write_instead_of_hanging() {
    let mut upload = session().upload(refused_url()).start().unwrap();
    let start = Instant::now();
    let e = upload.write_all(&vec![0u8; 4 << 20]).unwrap_err();
    assert!(start.elapsed() < Duration::from_secs(10));
    assert!(e.to_string().contains("refused"), "{e}");
    // finish() reports the same failure, and further writes fail too.
    assert!(upload.write(b"more").is_err());
    let e = upload.finish().unwrap_err();
    assert!(e.is_connect(), "{e}");
}

#[test]
fn an_early_answer_ends_the_upload_with_that_answer() {
    let mut upload = session().upload(http("/reject")).start().unwrap();
    let mut result = Ok(());
    for _ in 0..200 {
        result = upload.write_all(&vec![1u8; 256 * 1024]);
        if result.is_err() {
            break;
        }
    }
    // Small bodies can fit in socket buffers before the answer lands, so the
    // write may succeed; either way finish() has the server's answer.
    // The server hanging up may surface as the response or as the broken
    // pipe, depending on which the library sees first; neither may hang.
    // Windows has no broken pipe for sockets: a write after the server hung
    // up fails as aborted (WSAECONNABORTED) or reset.
    if let Err(e) = result {
        assert!(
            matches!(
                e.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ),
            "{e:?}"
        );
    }
    match upload.finish() {
        Ok(r) => assert_eq!(r.status(), 413),
        Err(e) => assert!(e.is_connect(), "{e:?}"),
    }
}

#[test]
fn dropping_an_upload_cancels_it() {
    for _ in 0..10 {
        let mut upload = session().upload(https("/upload")).start().unwrap();
        upload.write_all(b"partial").unwrap();
        drop(upload);
    }
    let upload = session().upload(https("/upload")).start().unwrap();
    assert_eq!(upload.finish().unwrap().json::<serde_json::Value>().unwrap()["len"], 0);
}

#[test]
fn upload_arguments_are_checked() {
    assert!(session().upload("").start().unwrap_err().is_invalid_input());
    assert!(session().upload("ftp://x").start().unwrap_err().is_invalid_input());
    assert!(session().upload(https("/upload")).header("a b", "c").start().unwrap_err().is_invalid_input());
    assert!(session().upload(https("/upload")).content_type("a\nb").start().unwrap_err().is_invalid_input());
    assert!(session().upload(https("/upload")).timeout(Duration::ZERO).start().unwrap_err().is_invalid_input());
}
