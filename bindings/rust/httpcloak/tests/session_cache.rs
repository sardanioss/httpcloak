//! The process-wide TLS session cache. A test binary of its own, since
//! setting one affects every session created afterwards.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use httpcloak::{CacheError, SessionCache};

#[derive(Default, Clone)]
struct Memory {
    store: Arc<Mutex<HashMap<String, String>>>,
    gets: Arc<AtomicUsize>,
    hits: Arc<AtomicUsize>,
    puts: Arc<AtomicUsize>,
}

impl SessionCache for Memory {
    fn get(&self, key: &str) -> Option<String> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        let v = self.store.lock().unwrap().get(key).cloned();
        if v.is_some() {
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
        v
    }

    fn put(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError> {
        assert!(key.starts_with("httpcloak:sessions:"), "{key}");
        assert!(ttl > Duration::ZERO);
        self.puts.fetch_add(1, Ordering::SeqCst);
        self.store.lock().unwrap().insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), CacheError> {
        self.store.lock().unwrap().remove(key);
        Ok(())
    }
}

/// Panics in every method; the library must carry on regardless.
struct Panicking;

impl SessionCache for Panicking {
    fn get(&self, _: &str) -> Option<String> {
        panic!("get")
    }
    fn put(&self, _: &str, _: &str, _: Duration) -> Result<(), CacheError> {
        panic!("put")
    }
    fn delete(&self, _: &str) -> Result<(), CacheError> {
        panic!("delete")
    }
    fn on_error(&self, _: &str, _: &str, _: &str) {
        panic!("on_error")
    }
}

/// Every test here sets the one global cache, so they take turns.
static TURN: Mutex<()> = Mutex::new(());

#[test]
fn tickets_go_to_the_cache_and_come_back() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let cache = Memory::default();
    httpcloak::set_session_cache(cache.clone());

    // TLS 1.3 tickets arrive after the handshake; a second request on the
    // connection gives the session time to see one.
    let first = session();
    first.get(https("/bytes/1")).send().unwrap();
    first.get(https("/bytes/1")).send().unwrap();
    assert!(eventually(Duration::from_secs(5), || cache.puts.load(Ordering::SeqCst) > 0), "no ticket was stored");

    // A brand-new session finds it there.
    let second = session();
    second.get(https("/bytes/1")).send().unwrap();
    assert!(cache.gets.load(Ordering::SeqCst) > 0);
    assert!(cache.hits.load(Ordering::SeqCst) > 0, "the stored ticket was never read back");

    httpcloak::clear_session_cache();
    let gets = cache.gets.load(Ordering::SeqCst);
    session().get(https("/bytes/1")).send().unwrap();
    assert_eq!(cache.gets.load(Ordering::SeqCst), gets, "a cleared cache was still asked");
}

#[test]
fn a_panicking_cache_does_not_take_the_process_down() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    httpcloak::set_session_cache(Panicking);
    let s = session();
    for _ in 0..3 {
        assert_eq!(s.get(https("/bytes/1")).send().unwrap().status(), 200);
    }
    httpcloak::clear_session_cache();
}

#[test]
fn a_cache_under_concurrent_load() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let cache = Memory::default();
    httpcloak::set_session_cache(cache.clone());
    std::thread::scope(|scope| {
        for _ in 0..16 {
            scope.spawn(|| {
                for _ in 0..5 {
                    assert_eq!(session().get(https("/bytes/1")).send().unwrap().status(), 200);
                }
            });
        }
    });
    httpcloak::clear_session_cache();
    assert!(cache.gets.load(Ordering::SeqCst) > 0);
}

/// A cache whose destructor sets or clears the cache itself used to deadlock:
/// the old cache was dropped with the global lock held.
struct ClearsOnDrop;

impl SessionCache for ClearsOnDrop {
    fn get(&self, _: &str) -> Option<String> {
        None
    }
    fn put(&self, _: &str, _: &str, _: Duration) -> Result<(), CacheError> {
        Ok(())
    }
    fn delete(&self, _: &str) -> Result<(), CacheError> {
        Ok(())
    }
}

impl Drop for ClearsOnDrop {
    fn drop(&mut self) {
        httpcloak::clear_session_cache();
    }
}

#[test]
fn a_cache_destructor_may_use_the_cache_api() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let (done, finished) = std::sync::mpsc::channel();
    // On a thread of its own, so a deadlock fails the test rather than
    // wedging the suite.
    std::thread::spawn(move || {
        httpcloak::set_session_cache(ClearsOnDrop);
        httpcloak::set_session_cache(Memory::default()); // drops ClearsOnDrop
        httpcloak::set_session_cache(ClearsOnDrop);
        httpcloak::clear_session_cache(); // drops it again
        let _ = done.send(());
    });
    assert!(finished.recv_timeout(Duration::from_secs(5)).is_ok(), "replacing or clearing the cache deadlocked");
}
