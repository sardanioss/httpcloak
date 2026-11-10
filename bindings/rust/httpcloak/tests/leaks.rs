//! Nothing is left behind: no pending calls, no growing memory. A test binary
//! of its own, run one test at a time, so other tests' requests do not count.

mod common;

use std::sync::Mutex;
use std::time::Duration;

use common::*;

static ALONE: Mutex<()> = Mutex::new(());

fn settled() -> bool {
    eventually(Duration::from_secs(10), || httpcloak::__pending_calls() == 0)
}

#[test]
fn completed_failed_cancelled_and_timed_out_calls_all_unregister() {
    let _alone = ALONE.lock().unwrap_or_else(|e| e.into_inner());
    let s = session();
    for _ in 0..50 {
        s.get(https("/bytes/10")).send().unwrap();
        s.get(refused_url()).send().unwrap_err();
        s.get(https("/sleep/2000")).timeout(Duration::from_millis(20)).send().unwrap_err();
        s.get(https("/stream/3/0")).send_stream().unwrap();
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        for _ in 0..50 {
            let _ = tokio::time::timeout(Duration::from_millis(5), s.get(https("/sleep/2000")).send_async()).await;
            let _ =
                tokio::time::timeout(Duration::from_millis(5), s.get(https("/stream/3/0")).send_stream_async()).await;
            let _ = s.get(https("/sleep/2000")).timeout(Duration::from_millis(10)).send_async().await;
        }
    });
    assert!(settled(), "{} calls never reported back", httpcloak::__pending_calls());
}

#[cfg(target_os = "linux")]
fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status.lines().find_map(|l| l.strip_prefix("VmRSS:")).unwrap().trim().trim_end_matches(" kB").parse().unwrap()
}

/// Memory settles rather than growing with the number of sessions, requests
/// and streams. A generous bound: this catches a leak per call, not a byte.
#[cfg(target_os = "linux")]
#[test]
fn memory_does_not_grow_with_use() {
    let _alone = ALONE.lock().unwrap_or_else(|e| e.into_inner());
    let round = || {
        for _ in 0..40 {
            let s = session();
            s.get(https("/bytes/100000")).send().unwrap();
            s.post(https("/echo")).body(vec![7u8; 50_000]).send().unwrap();
            let _ = s.get(https("/stream/5/0")).send_stream().unwrap().bytes().unwrap();
            let mut up = s.upload(https("/upload")).start().unwrap();
            std::io::Write::write_all(&mut up, &[1u8; 10_000]).unwrap();
            up.finish().unwrap();
        }
        httpcloak::trim_memory();
    };
    // Warm up: pools, caches and the Go heap reach their working size.
    round();
    round();
    let before = rss_kib();
    for _ in 0..5 {
        round();
    }
    let after = rss_kib();
    assert!(after < before + 64 * 1024, "RSS grew from {before} KiB to {after} KiB over 200 sessions");
    assert!(settled());
}

/// Every request with a timeout used to leave its deadline in the timer until
/// the deadline passed, so fast requests with long timeouts grew memory with
/// the number completed, not the number in flight.
#[test]
fn deadlines_leave_the_timer_with_their_requests() {
    let _alone = ALONE.lock().unwrap_or_else(|e| e.into_inner());
    let year = Duration::from_secs(365 * 24 * 3600);
    let s = session();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        for _ in 0..2000 {
            s.get(https("/bytes/1")).timeout(year).send_async().await.unwrap();
        }
        for _ in 0..50 {
            let _ =
                tokio::time::timeout(Duration::from_millis(2), s.get(https("/sleep/500")).timeout(year).send_async())
                    .await;
        }
    });
    for _ in 0..50 {
        let stream = s.get(https("/stream/3/0")).timeout(year).send_stream().unwrap();
        let _ = stream.bytes();
        drop(s.get(https("/stream/3/0")).timeout(year).send_stream().unwrap());
    }
    assert!(
        eventually(Duration::from_secs(5), || httpcloak::__armed_deadlines() == 0),
        "{} deadlines are still armed",
        httpcloak::__armed_deadlines()
    );
    assert!(settled());
}
