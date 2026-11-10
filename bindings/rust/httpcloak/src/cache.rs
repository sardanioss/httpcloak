use std::cell::RefCell;
use std::error::Error as StdError;
use std::ffi::{c_char, c_int, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use httpcloak_sys as sys;

use crate::ffi::borrow_string;

/// The error a [`SessionCache`] method may fail with.
pub type CacheError = Box<dyn StdError + Send + Sync>;

/// External storage for TLS session tickets, so that resumption survives a
/// restart or is shared between processes. Install one with
/// [`set_session_cache`].
///
/// Keys look like `httpcloak:sessions:{preset}:{protocol}:{host}:{port}`, with
/// a session's [identifier](crate::Session::set_identifier) after `sessions:`
/// when it has one. Values are opaque JSON; store them as given. The library
/// already keeps entries for 24 hours and ignores older ones, so `ttl` is
/// a hint for the store.
///
/// The methods are called on the library's own threads, which wait for them,
/// so they may block, on a network round trip for instance. A panic in one is
/// caught and treated as a failure.
pub trait SessionCache: Send + Sync + 'static {
    /// The value stored under `key`, or `None` when there is none.
    fn get(&self, key: &str) -> Option<String>;

    /// Stores `value` under `key` for `ttl`.
    fn put(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError>;

    /// Removes `key`.
    fn delete(&self, key: &str) -> Result<(), CacheError>;

    /// The ECH config (base64) stored under `key`, for HTTP/3.
    fn get_ech(&self, key: &str) -> Option<String> {
        let _ = key;
        None
    }

    /// Stores an ECH config (base64) under `key` for `ttl`.
    fn put_ech(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError> {
        let _ = (key, value, ttl);
        Ok(())
    }

    /// Called when an operation on the cache fails: `operation` is `get`,
    /// `put` or `delete`.
    fn on_error(&self, operation: &str, key: &str, error: &str) {
        let _ = (operation, key, error);
    }
}

static CACHE: RwLock<Option<Arc<dyn SessionCache>>> = RwLock::new(None);

/// Uses `cache` for the TLS session tickets of every session and local proxy
/// created from now on, replacing any cache set before. Sessions created
/// earlier keep the cache they started with, which from then on is this one.
pub fn set_session_cache(cache: impl SessionCache) {
    let mut slot = CACHE.write().unwrap_or_else(|e| e.into_inner());
    let previous = slot.replace(Arc::new(cache));
    // SAFETY: the callbacks have the signatures the library expects, never
    // unwind, and live for the whole program.
    unsafe {
        sys::httpcloak_set_session_cache_callbacks(
            Some(cache_get),
            Some(cache_put),
            Some(cache_delete),
            Some(ech_get),
            Some(ech_put),
            Some(cache_error),
        )
    }
    // The cache it replaces is dropped with the lock released: its Drop is
    // the caller's code, and may set or clear a cache itself, or wait on a
    // request that needs this one.
    drop(slot);
    drop(previous);
}

/// Stops using the cache set with [`set_session_cache`]: new sessions keep
/// their tickets in memory only, and existing ones find nothing in it.
pub fn clear_session_cache() {
    let mut slot = CACHE.write().unwrap_or_else(|e| e.into_inner());
    // SAFETY: plain call.
    unsafe { sys::httpcloak_clear_session_cache_callbacks() };
    let previous = slot.take();
    // As in set_session_cache: the cache's Drop runs unlocked.
    drop(slot);
    drop(previous);
}

fn current() -> Option<Arc<dyn SessionCache>> {
    CACHE.read().unwrap_or_else(|e| e.into_inner()).clone()
}

thread_local! {
    /// The string a get callback returned on this thread. The library copies
    /// it before the thread runs anything else, so it only has to outlive the
    /// call, and the next call on the thread replaces it.
    static RETURNED: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn hand_back(value: Option<String>) -> *mut c_char {
    let Some(value) = value.and_then(|v| CString::new(v).ok()) else { return ptr::null_mut() };
    RETURNED.with(|slot| {
        let ptr = value.as_ptr().cast_mut();
        *slot.borrow_mut() = Some(value);
        ptr
    })
}

/// Runs a cache operation for a callback: no panic escapes, and a missing key
/// or cache gives `fallback`.
fn guarded<T>(fallback: T, f: impl FnOnce(&dyn SessionCache) -> Option<T>) -> T {
    catch_unwind(AssertUnwindSafe(|| current().and_then(|cache| f(cache.as_ref())))).ok().flatten().unwrap_or(fallback)
}

fn status(result: Result<(), CacheError>) -> c_int {
    c_int::from(result.is_err())
}

fn ttl(seconds: i64) -> Duration {
    Duration::from_secs(u64::try_from(seconds).unwrap_or(0))
}

unsafe extern "C" fn cache_get(key: *const c_char) -> *mut c_char {
    // SAFETY: the library passes a string valid for the call.
    let key = unsafe { borrow_string(key) };
    guarded(ptr::null_mut(), |cache| Some(hand_back(cache.get(&key?))))
}

unsafe extern "C" fn cache_put(key: *const c_char, value: *const c_char, ttl_seconds: i64) -> c_int {
    // SAFETY: the library passes strings valid for the call.
    let (key, value) = unsafe { (borrow_string(key), borrow_string(value)) };
    guarded(-1, |cache| Some(status(cache.put(&key?, &value?, ttl(ttl_seconds)))))
}

unsafe extern "C" fn cache_delete(key: *const c_char) -> c_int {
    // SAFETY: the library passes a string valid for the call.
    let key = unsafe { borrow_string(key) };
    guarded(-1, |cache| Some(status(cache.delete(&key?))))
}

unsafe extern "C" fn ech_get(key: *const c_char) -> *mut c_char {
    // SAFETY: the library passes a string valid for the call.
    let key = unsafe { borrow_string(key) };
    guarded(ptr::null_mut(), |cache| Some(hand_back(cache.get_ech(&key?))))
}

unsafe extern "C" fn ech_put(key: *const c_char, value: *const c_char, ttl_seconds: i64) -> c_int {
    // SAFETY: the library passes strings valid for the call.
    let (key, value) = unsafe { (borrow_string(key), borrow_string(value)) };
    guarded(-1, |cache| Some(status(cache.put_ech(&key?, &value?, ttl(ttl_seconds)))))
}

unsafe extern "C" fn cache_error(operation: *const c_char, key: *const c_char, error: *const c_char) {
    // SAFETY: the library passes strings valid for the call.
    let (operation, key, error) = unsafe { (borrow_string(operation), borrow_string(key), borrow_string(error)) };
    guarded((), |cache| {
        cache.on_error(&operation.unwrap_or_default(), &key.unwrap_or_default(), &error.unwrap_or_default());
        Some(())
    })
}
