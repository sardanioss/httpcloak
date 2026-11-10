//! An HTTP client whose every byte on the wire matches a real browser's: the
//! TLS handshake (JA3/JA4, GREASE, post-quantum key shares, ECH), the HTTP/2
//! SETTINGS and priorities, the QUIC transport parameters of HTTP/3, and the
//! headers, in the browser's order.
//!
//! This crate is a safe binding to [httpcloak](https://httpcloak.dev), a Go
//! library, linked in statically by [`httpcloak-sys`].
//!
//! # Making requests
//!
//! ```no_run
//! # fn main() -> httpcloak::Result<()> {
//! use httpcloak::{presets, Session};
//!
//! let session = Session::builder().preset(presets::CHROME_LATEST).build()?;
//!
//! let response = session
//!     .post("https://httpbin.org/post")
//!     .header("X-Requested-With", "httpcloak")
//!     .json(&serde_json::json!({"hello": "world"}))
//!     .send()?
//!     .error_for_status()?;
//! println!("{} {:?} {}", response.status(), response.version(), response.text());
//! # Ok(())
//! # }
//! ```
//!
//! A [`Session`] is a browser profile: it keeps cookies, TLS session tickets
//! and connections between requests. It is cheap to clone and safe to share
//! between threads.
//!
//! # Blocking and async
//!
//! Every request can be sent either way, on the same session:
//! [`send`](RequestBuilder::send) blocks the calling thread, and
//! [`send_async`](RequestBuilder::send_async) returns a future. The futures
//! need no particular runtime, since the library completes them from its own
//! threads, and dropping one cancels its request.
//!
//! ```no_run
//! # async fn run() -> httpcloak::Result<()> {
//! let session = httpcloak::Session::new()?;
//! let (a, b) = futures_util::join!(
//!     session.get("https://example.com/a").send_async(),
//!     session.get("https://example.com/b").send_async(),
//! );
//! # let _ = (a?, b?);
//! # Ok(())
//! # }
//! ```
//!
//! # Streaming
//!
//! [`send_stream`](RequestBuilder::send_stream) returns as soon as the response
//! headers arrive, with the body to [read](std::io::Read) as it comes, or to
//! consume as an async stream with
//! [`into_body_stream`](StreamResponse::into_body_stream). Large request
//! bodies can be written incrementally through [`Session::upload`].
//!
//! # Timeouts
//!
//! A session's [timeout](SessionBuilder::timeout), 30 seconds unless set,
//! bounds each request, redirects and retries included. A request's own
//! [timeout](RequestBuilder::timeout) replaces it, longer or shorter, and is
//! exact: the library counts in whole seconds, so this crate keeps its own
//! deadline and cancels the request when it passes.
//!
//! # Errors
//!
//! Every fallible call returns [`Result`], with an [`Error`] whose
//! [`kind`](Error::kind) says what went wrong. Arguments the library cannot
//! use, a string with a NUL in it or an invalid header, are rejected before
//! anything is sent; nothing in this crate panics on bad input.
//!
//! [`httpcloak-sys`]: https://docs.rs/httpcloak-sys

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations, rust_2018_idioms)]

mod cache;
mod call;
mod cookie;
mod error;
mod ffi;
mod headers;
mod local_proxy;
mod preset;
pub mod presets;
mod request;
mod response;
mod session;
mod stream;
mod upload;

#[cfg(test)]
mod fuzz_tests;

use httpcloak_sys as sys;

pub use cache::{clear_session_cache, set_session_cache, CacheError, SessionCache};
pub use cookie::{Cookie, SameSite};
pub use error::{Error, ErrorKind, Result};
pub use headers::Headers;
pub use local_proxy::{LocalProxy, LocalProxyBuilder, LocalProxyStats};
pub use preset::{
    available_presets, describe_preset, load_preset, load_preset_file, unregister_preset, PresetInfo, PresetPool,
};
pub use request::{multipart, FetchMode, RequestBuilder};
pub use response::{Redirect, Response};
pub use session::{ExtraFingerprint, HttpVersion, Session, SessionBuilder, SessionStats, TcpFingerprint};
pub use stream::{BodyStream, StreamResponse};
pub use upload::{Upload, UploadBuilder};

pub use http::{Method, StatusCode, Version};

/// The version of the linked httpcloak library.
pub fn version() -> String {
    // SAFETY: plain call; the result is ours to free.
    unsafe { ffi::take_string(sys::httpcloak_version()) }.unwrap_or_default()
}

/// Sets the DNS servers, as `host:port` (`[addr]:port` for IPv6), used to look
/// up ECH configs. An empty list restores the defaults: Google, Cloudflare and
/// Quad9. Applies to the whole process.
pub fn set_ech_dns_servers<I, S>(servers: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let servers: Vec<String> = servers.into_iter().map(|s| s.as_ref().to_string()).collect();
    // The library takes anything and fails, silently, at lookup time.
    for server in &servers {
        let valid = server.rsplit_once(':').is_some_and(|(host, port)| {
            let bracketed = host.starts_with('[') && host.ends_with(']') && host.len() > 2;
            !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0) && (bracketed || !host.contains(':'))
        });
        if !valid {
            return Err(Error::invalid_input(format!("{server:?} is not a host:port DNS server address")));
        }
    }
    let json = (!servers.is_empty())
        .then(|| ffi::cstring(&serde_json::to_string(&servers).expect("strings serialize"), "the DNS servers"))
        .transpose()?;
    let ptr = json.as_ref().map_or(std::ptr::null(), |j| j.as_ptr());
    // SAFETY: null or a valid NUL-terminated string; the result, a bare error
    // message when there is one, is ours to free.
    match unsafe { ffi::take_string(sys::httpcloak_set_ech_dns_servers(ptr)) } {
        Some(message) if !message.is_empty() => Err(Error::invalid_input(message)),
        _ => Ok(()),
    }
}

/// The DNS servers used to look up ECH configs.
pub fn ech_dns_servers() -> Vec<String> {
    // SAFETY: plain call; the result is ours to free.
    let json = unsafe { ffi::take_string(sys::httpcloak_get_ech_dns_servers()) };
    json.and_then(|j| serde_json::from_str::<Option<Vec<String>>>(&j).ok()).flatten().unwrap_or_default()
}

/// Returns memory freed by dropped sessions to the operating system, which
/// the Go runtime otherwise does lazily. It stops the world for a full
/// collection, so call it between batches of work, not after every session.
pub fn trim_memory() {
    // SAFETY: plain call.
    unsafe { sys::httpcloak_trim_memory() }
}

/// For the crate's own tests: how many calls the library has yet to report
/// on. Not part of the API.
#[doc(hidden)]
pub fn __pending_calls() -> usize {
    call::pending_calls()
}

/// For the crate's own tests: how many deadlines are armed. Not part of the
/// API.
#[doc(hidden)]
pub fn __armed_deadlines() -> usize {
    call::armed_deadlines()
}
