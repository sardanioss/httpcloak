//! Raw declarations for the httpcloak C library, the Go c-archive built from
//! `bindings/clib`.
//!
//! Use the `httpcloak` crate rather than this one. Everything here is a direct
//! mirror of the generated `httpcloak.h`; the conventions it does not spell out:
//!
//! - Every `*mut c_char` a function returns was allocated by the library with
//!   `malloc` and must be released with [`httpcloak_free_string`]. The strings
//!   handed to a callback are not the callback's: copy them before returning.
//! - String arguments must be NUL-terminated and are only read during the call.
//!   The library declares them `char*`; they are `*const c_char` here because
//!   it never writes through them.
//! - Handles are `i64`. Functions that create one return `-1` (or `0` for some
//!   older exports) on failure.
//! - The `timeout` field of a request's JSON is in milliseconds for the
//!   `*_raw`, `httpcloak_get`/`httpcloak_post`, `httpcloak_stream_get`/
//!   `httpcloak_stream_post` and `httpcloak_upload_start` exports, and in
//!   seconds for `httpcloak_request`, the `*_async` exports and
//!   `httpcloak_stream_request`.
//! - Callbacks are invoked on threads the library creates for them, never on a
//!   Go thread, and the library waits for each to return. They must not unwind.

#![no_std]
#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_void};

/// Completion callback for the `*_async` exports. Exactly one of
/// `response_json` and `error` is non-null.
pub type async_callback =
    Option<unsafe extern "C" fn(callback_id: i64, response_json: *const c_char, error: *const c_char)>;

/// Returns the cached value for `key` as a NUL-terminated string, or null when
/// there is none. The library copies the string before the callback's thread
/// runs anything else, so it only has to outlive the call.
pub type session_cache_get_callback = Option<unsafe extern "C" fn(key: *const c_char) -> *mut c_char>;
/// Stores `value_json` under `key`. Returns 0 on success.
pub type session_cache_put_callback =
    Option<unsafe extern "C" fn(key: *const c_char, value_json: *const c_char, ttl_seconds: i64) -> c_int>;
/// Removes `key`. Returns 0 on success.
pub type session_cache_delete_callback = Option<unsafe extern "C" fn(key: *const c_char) -> c_int>;
/// Reports a failed cache operation.
pub type session_cache_error_callback =
    Option<unsafe extern "C" fn(operation: *const c_char, key: *const c_char, error: *const c_char)>;
/// As [`session_cache_get_callback`], for base64 ECH configs.
pub type ech_cache_get_callback = Option<unsafe extern "C" fn(key: *const c_char) -> *mut c_char>;
/// As [`session_cache_put_callback`], for base64 ECH configs.
pub type ech_cache_put_callback =
    Option<unsafe extern "C" fn(key: *const c_char, value_base64: *const c_char, ttl_seconds: i64) -> c_int>;

/// Asynchronous cache callbacks: the result is reported later through
/// [`httpcloak_async_cache_get_result`] or [`httpcloak_async_cache_op_result`].
pub type async_cache_get_callback = Option<unsafe extern "C" fn(request_id: i64, key: *const c_char)>;
pub type async_cache_put_callback =
    Option<unsafe extern "C" fn(request_id: i64, key: *const c_char, value_json: *const c_char, ttl_seconds: i64)>;
pub type async_cache_delete_callback = Option<unsafe extern "C" fn(request_id: i64, key: *const c_char)>;
pub type async_ech_get_callback = Option<unsafe extern "C" fn(request_id: i64, key: *const c_char)>;
pub type async_ech_put_callback =
    Option<unsafe extern "C" fn(request_id: i64, key: *const c_char, value_base64: *const c_char, ttl_seconds: i64)>;

/// Metadata of a response from the `httpcloak_get_fast` path.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FastResponseMeta {
    pub status_code: i32,
    pub body_len: i32,
    pub headers_len: i32,
    /// 1 = HTTP/1.1, 2 = HTTP/2, 3 = HTTP/3.
    pub protocol: i32,
    /// NUL-terminated; empty when the URL did not fit.
    pub final_url: [c_char; 2048],
}

extern "C" {
    // --- Buffered responses held by handle (the *_raw family) ---
    pub fn httpcloak_response_get_metadata(handle: i64) -> *mut c_char;
    /// Returns a `malloc`ed copy of the body; free it with `free`, not
    /// [`httpcloak_free_string`].
    pub fn httpcloak_response_get_body(handle: i64, out_len: *mut c_int) -> *mut c_void;
    /// Points into the library's own copy; valid until the response is freed.
    pub fn httpcloak_response_get_body_ptr(handle: i64, out_len: *mut c_int) -> *mut c_void;
    pub fn httpcloak_response_get_body_len(handle: i64) -> c_int;
    pub fn httpcloak_response_copy_body_to(handle: i64, dest: *mut c_void, dest_len: c_int) -> c_int;
    pub fn httpcloak_response_free(handle: i64);
    pub fn httpcloak_response_finalize(handle: i64, dest: *mut c_void, dest_len: c_int) -> *mut c_char;
    pub fn httpcloak_get_raw(handle: i64, url: *const c_char, options_json: *const c_char) -> i64;
    /// Why the last int64-returning call on this session failed. The slot is
    /// per session, not per call: concurrent calls overwrite each other's.
    pub fn httpcloak_last_error(handle: i64) -> *mut c_char;
    pub fn httpcloak_post_raw(
        handle: i64,
        url: *const c_char,
        body: *const c_char,
        body_len: c_int,
        options_json: *const c_char,
    ) -> i64;
    pub fn httpcloak_request_raw(handle: i64, request_json: *const c_char, body: *const c_char, body_len: c_int)
        -> i64;

    // --- Sessions ---
    pub fn httpcloak_session_new(config_json: *const c_char) -> i64;
    pub fn httpcloak_session_free(handle: i64);
    pub fn httpcloak_session_refresh(handle: i64);
    pub fn httpcloak_session_refresh_protocol(handle: i64, protocol: *const c_char) -> *mut c_char;
    pub fn httpcloak_session_warmup(handle: i64, url: *const c_char, timeout_ms: i64) -> *mut c_char;
    pub fn httpcloak_session_fork(handle: i64) -> i64;

    // --- Synchronous requests with the response as JSON ---
    pub fn httpcloak_get(handle: i64, url: *const c_char, options_json: *const c_char) -> *mut c_char;
    pub fn httpcloak_post(
        handle: i64,
        url: *const c_char,
        body: *const c_char,
        options_json: *const c_char,
    ) -> *mut c_char;
    pub fn httpcloak_request(handle: i64, request_json: *const c_char) -> *mut c_char;

    // --- Asynchronous requests ---
    pub fn httpcloak_register_callback(callback: async_callback) -> i64;
    pub fn httpcloak_unregister_callback(callback_id: i64);
    pub fn httpcloak_cancel_request(callback_id: i64);
    pub fn httpcloak_get_async(handle: i64, url: *const c_char, options_json: *const c_char, callback_id: i64);
    pub fn httpcloak_post_async(
        handle: i64,
        url: *const c_char,
        body: *const c_char,
        options_json: *const c_char,
        callback_id: i64,
    );
    pub fn httpcloak_request_async(handle: i64, request_json: *const c_char, callback_id: i64);

    // --- Cookies ---
    pub fn httpcloak_get_cookies(handle: i64) -> *mut c_char;
    pub fn httpcloak_set_cookie(handle: i64, cookie_json: *const c_char);
    pub fn httpcloak_delete_cookie(handle: i64, name: *const c_char, domain: *const c_char);
    pub fn httpcloak_clear_cookies(handle: i64);

    // --- Persistence ---
    pub fn httpcloak_session_save(handle: i64, path: *const c_char) -> *mut c_char;
    pub fn httpcloak_session_load(path: *const c_char) -> i64;
    pub fn httpcloak_session_marshal(handle: i64) -> *mut c_char;
    pub fn httpcloak_session_unmarshal(data: *const c_char) -> i64;

    // --- Runtime session settings ---
    pub fn httpcloak_session_set_proxy(handle: i64, proxy_url: *const c_char) -> *mut c_char;
    pub fn httpcloak_session_set_tcp_proxy(handle: i64, proxy_url: *const c_char) -> *mut c_char;
    pub fn httpcloak_session_set_udp_proxy(handle: i64, proxy_url: *const c_char) -> *mut c_char;
    pub fn httpcloak_session_get_proxy(handle: i64) -> *mut c_char;
    pub fn httpcloak_session_get_tcp_proxy(handle: i64) -> *mut c_char;
    pub fn httpcloak_session_get_udp_proxy(handle: i64) -> *mut c_char;
    pub fn httpcloak_session_set_header_order(handle: i64, order_json: *const c_char) -> *mut c_char;
    pub fn httpcloak_session_get_header_order(handle: i64) -> *mut c_char;
    pub fn httpcloak_session_set_identifier(handle: i64, session_id: *const c_char);
    pub fn httpcloak_session_clear_cache(handle: i64);
    pub fn httpcloak_session_stats(handle: i64) -> *mut c_char;
    pub fn httpcloak_session_idle_time(handle: i64) -> i64;
    pub fn httpcloak_session_is_active(handle: i64) -> c_int;
    pub fn httpcloak_session_touch(handle: i64);
    pub fn httpcloak_session_set_conditional_cache(handle: i64, enabled: c_int);
    pub fn httpcloak_session_get_conditional_cache(handle: i64) -> c_int;
    pub fn httpcloak_session_set_client_hints(handle: i64, enabled: c_int);
    pub fn httpcloak_session_get_client_hints(handle: i64) -> c_int;
    pub fn httpcloak_session_set_high_entropy_client_hints(handle: i64, enabled: c_int);
    pub fn httpcloak_session_get_high_entropy_client_hints(handle: i64) -> c_int;
    pub fn httpcloak_session_set_follow_redirects(handle: i64, enabled: c_int);
    pub fn httpcloak_session_get_follow_redirects(handle: i64) -> c_int;
    pub fn httpcloak_session_set_max_redirects(handle: i64, max: c_int);
    pub fn httpcloak_session_get_max_redirects(handle: i64) -> c_int;

    // --- Library-wide ---
    pub fn httpcloak_free_string(s: *mut c_char);
    pub fn httpcloak_trim_memory();
    pub fn httpcloak_version() -> *mut c_char;
    pub fn httpcloak_available_presets() -> *mut c_char;
    /// Returns null on success, or a plain (not JSON) error message.
    pub fn httpcloak_set_ech_dns_servers(servers_json: *const c_char) -> *mut c_char;
    pub fn httpcloak_get_ech_dns_servers() -> *mut c_char;

    // --- Session cache callbacks (process-wide) ---
    pub fn httpcloak_async_cache_get_result(request_id: i64, value: *const c_char);
    pub fn httpcloak_async_cache_op_result(request_id: i64, success: c_int);
    pub fn httpcloak_set_session_cache_callbacks(
        get_callback: session_cache_get_callback,
        put_callback: session_cache_put_callback,
        delete_callback: session_cache_delete_callback,
        ech_get_callback: ech_cache_get_callback,
        ech_put_callback: ech_cache_put_callback,
        error_callback: session_cache_error_callback,
    );
    pub fn httpcloak_set_async_session_cache_callbacks(
        get_callback: async_cache_get_callback,
        put_callback: async_cache_put_callback,
        delete_callback: async_cache_delete_callback,
        ech_get_callback: async_ech_get_callback,
        ech_put_callback: async_ech_put_callback,
        error_callback: session_cache_error_callback,
    );
    pub fn httpcloak_clear_session_cache_callbacks();

    // --- Local proxy ---
    pub fn httpcloak_local_proxy_start(config_json: *const c_char) -> i64;
    pub fn httpcloak_local_proxy_stop(handle: i64);
    pub fn httpcloak_local_proxy_get_port(handle: i64) -> c_int;
    pub fn httpcloak_local_proxy_is_running(handle: i64) -> c_int;
    pub fn httpcloak_local_proxy_get_stats(handle: i64) -> *mut c_char;
    /// Returns null on success, or a JSON error object.
    pub fn httpcloak_local_proxy_register_session(
        proxy_handle: i64,
        session_id: *const c_char,
        session_handle: i64,
    ) -> *mut c_char;
    pub fn httpcloak_local_proxy_unregister_session(proxy_handle: i64, session_id: *const c_char) -> c_int;
    pub fn httpcloak_local_proxy_list_sessions(proxy_handle: i64) -> *mut c_char;
    pub fn httpcloak_local_proxy_has_session(proxy_handle: i64, session_id: *const c_char) -> c_int;

    // --- Streaming responses ---
    pub fn httpcloak_stream_get(session_handle: i64, url: *const c_char, options_json: *const c_char) -> i64;
    pub fn httpcloak_stream_post(
        session_handle: i64,
        url: *const c_char,
        body: *const c_char,
        options_json: *const c_char,
    ) -> i64;
    pub fn httpcloak_stream_request(session_handle: i64, request_json: *const c_char) -> i64;
    pub fn httpcloak_stream_request_async(session_handle: i64, request_json: *const c_char, callback_id: i64);
    pub fn httpcloak_stream_get_metadata(stream_handle: i64) -> *mut c_char;
    /// Returns base64 of the next chunk, `""` at EOF, or null on error.
    pub fn httpcloak_stream_read(stream_handle: i64, buffer_size: c_int) -> *mut c_char;
    pub fn httpcloak_stream_trailer(stream_handle: i64) -> *mut c_char;
    /// Returns the number of bytes read, 0 at EOF, or -1 on error.
    pub fn httpcloak_stream_read_raw(stream_handle: i64, buffer: *mut c_void, buffer_size: c_int) -> c_int;
    /// Cancels the stream's context without closing it: a read blocked on it
    /// in another thread returns -1, and the stream stays open until
    /// [`httpcloak_stream_close`]. Safe to call concurrently with a read,
    /// which closing is not. Unknown and closed handles are a no-op.
    pub fn httpcloak_stream_cancel(stream_handle: i64);
    pub fn httpcloak_stream_close(stream_handle: i64);

    // --- Streaming uploads ---
    pub fn httpcloak_upload_start(session_handle: i64, url: *const c_char, options_json: *const c_char) -> i64;
    pub fn httpcloak_upload_write(upload_handle: i64, data_base64: *const c_char) -> c_int;
    pub fn httpcloak_upload_write_raw(upload_handle: i64, data: *const c_void, data_len: c_int) -> c_int;
    pub fn httpcloak_upload_finish(upload_handle: i64) -> *mut c_char;
    pub fn httpcloak_upload_cancel(upload_handle: i64);

    // --- Custom presets ---
    pub fn httpcloak_preset_load_file(path: *const c_char) -> *mut c_char;
    pub fn httpcloak_preset_load_json(json_data: *const c_char) -> *mut c_char;
    pub fn httpcloak_preset_unregister(name: *const c_char);
    pub fn httpcloak_describe_preset(name: *const c_char) -> *mut c_char;

    // --- Preset pools ---
    pub fn httpcloak_pool_load_file(path: *const c_char) -> *mut c_char;
    pub fn httpcloak_pool_load_json(json_data: *const c_char) -> *mut c_char;
    pub fn httpcloak_pool_pick(handle: i64) -> *mut c_char;
    pub fn httpcloak_pool_random(handle: i64) -> *mut c_char;
    pub fn httpcloak_pool_next(handle: i64) -> *mut c_char;
    pub fn httpcloak_pool_get(handle: i64, index: i64) -> *mut c_char;
    pub fn httpcloak_pool_size(handle: i64) -> i64;
    pub fn httpcloak_pool_name(handle: i64) -> *mut c_char;
    pub fn httpcloak_pool_free(handle: i64);

    // --- Start-up and the fast GET path ---
    pub fn httpcloak_init();
    pub fn httpcloak_warmup(config_json: *const c_char);
    pub fn httpcloak_warmup_full(config_json: *const c_char, warmup_url: *const c_char, warmup_url_len: c_int);
    pub fn httpcloak_get_fast_timed(handle: i64, url: *const c_char, url_len: c_int, timings: *mut i64) -> i64;
    pub fn httpcloak_get_fast(handle: i64, url: *const c_char, url_len: c_int) -> i64;
    pub fn httpcloak_fast_get_meta(handle: i64) -> *mut FastResponseMeta;
    pub fn httpcloak_fast_get_body_ptr(handle: i64) -> *mut c_void;
    pub fn httpcloak_fast_get_body_len(handle: i64) -> c_int;
    pub fn httpcloak_fast_free(handle: i64);
}
