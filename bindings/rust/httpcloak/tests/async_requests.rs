//! Requests as futures, on tokio and on a bare executor.

mod common;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::*;
use futures_util::StreamExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_future_resolves_with_the_response() {
    let r = session().post(https("/echo")).body("async body").send_async().await.unwrap();
    assert_eq!(echoed_body(&echo(&r)), b"async body");
    assert!(r.elapsed() > Duration::ZERO);
}

#[tokio::test(flavor = "current_thread")]
async fn works_on_a_single_threaded_runtime() {
    // The library completes futures from its own threads, so nothing here
    // needs a second runtime thread.
    let r = session().get(https("/sleep/50")).send_async().await.unwrap();
    assert_eq!(r.text(), "slept 50");
}

#[test]
fn works_without_any_runtime() {
    let r = futures_executor_block_on(session().get(http("/bytes/5")).send_async()).unwrap();
    assert_eq!(r.body(), pattern(5).as_slice());
}

/// A minimal executor: polls on this thread, parks between wakes.
fn futures_executor_block_on<F: std::future::Future>(f: F) -> F::Output {
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake};
    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Arc::new(Unpark(std::thread::current())).into();
    let mut cx = Context::from_waker(&waker);
    let mut f = std::pin::pin!(f);
    loop {
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::park(),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hundreds_of_concurrent_requests_on_one_session() {
    let s = session();
    let tasks: Vec<_> = (0..300)
        .map(|i| {
            let s = s.clone();
            tokio::spawn(async move {
                let url = if i % 3 == 0 { http(&format!("/bytes/{i}")) } else { https(&format!("/bytes/{i}")) };
                let r = s.get(url).send_async().await.unwrap();
                assert_eq!(r.body(), pattern(i).as_slice());
            })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_async_timeout_is_exact() {
    let start = Instant::now();
    let e = session().get(https("/sleep/5000")).timeout(Duration::from_millis(250)).send_async().await.unwrap_err();
    assert!(e.is_timeout(), "{e}");
    assert!(start.elapsed() < Duration::from_millis(1000), "{:?}", start.elapsed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_future_cancels_its_request() {
    let before = servers().disconnects.load(Ordering::SeqCst);
    let fut = session().get(http("/sleep/10000")).send_async();
    // Give the request time to reach the server, then give up on it.
    let _ = tokio::time::timeout(Duration::from_millis(300), fut).await;
    assert!(
        eventually(Duration::from_secs(5), || servers().disconnects.load(Ordering::SeqCst) > before),
        "the server never saw the request abandoned"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_future_dropped_before_its_first_poll_sends_nothing() {
    let server = RawServer::start(|_, _| {});
    drop(session().get(server.url("/")).send_async());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(server.next_head_within(Duration::from_millis(100)).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_errors_carry_their_kind() {
    let e = session().get(refused_url()).send_async().await.unwrap_err();
    assert!(e.is_connect(), "{e}");
    let e = session().get("http://x/\0").send_async().await.unwrap_err();
    assert!(e.is_invalid_input());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streams_open_asynchronously_and_read_as_a_stream() {
    let stream = session().get(https("/stream/20/10")).send_stream_async().await.unwrap();
    assert_eq!(stream.status(), 200);
    let mut body = stream.into_body_stream();
    let mut text = Vec::new();
    while let Some(chunk) = body.next().await {
        text.extend(chunk.unwrap());
    }
    let expected: String = (0..20).map(|i| format!("chunk {i}\n")).collect();
    assert_eq!(String::from_utf8(text).unwrap(), expected);
    assert!(body.trailers().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_stream_dropped_early_releases_the_stream() {
    let stream = session().get(https("/stream/1000/5")).send_stream_async().await.unwrap();
    let mut body = stream.into_body_stream();
    assert!(body.next().await.unwrap().is_ok());
    drop(body);
    // Nothing to observe but that this does not hang or crash; the reader
    // thread closes the stream once its read returns.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_header_timeout_is_exact() {
    let server = RawServer::start(|_, _| std::thread::sleep(Duration::from_secs(5)));
    let start = Instant::now();
    let e = session().get(server.url("/")).timeout(Duration::from_millis(300)).send_stream_async().await.unwrap_err();
    assert!(e.is_timeout(), "{e}");
    assert!(start.elapsed() < Duration::from_millis(1500), "{:?}", start.elapsed());
}
