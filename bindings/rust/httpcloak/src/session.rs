use std::collections::BTreeMap;
use std::ffi::c_int;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use http::Method;
use httpcloak_sys as sys;
use serde::{Deserialize, Serialize};

use crate::cookie::{Cookie, WireCookie};
use crate::error::{Error, ErrorKind, Result};
use crate::ffi::{self, cpath, cstring};
use crate::request::RequestBuilder;
use crate::upload::UploadBuilder;

/// An HTTP client whose TLS, HTTP/2 and HTTP/3 fingerprints match a real
/// browser's.
///
/// A session keeps cookies, TLS session tickets and connections across
/// requests, as a browser tab does. It is cheap to clone: clones share the same
/// underlying session, which is closed, and its connections released, once the
/// last clone, request, stream and upload using it is gone. It is `Send` and
/// `Sync`, and requests on it may run concurrently from any number of threads
/// or tasks.
///
/// ```no_run
/// # fn main() -> httpcloak::Result<()> {
/// let session = httpcloak::Session::builder()
///     .preset(httpcloak::presets::CHROME_LATEST)
///     .build()?;
/// let response = session.get("https://example.com").send()?;
/// println!("{} over {:?}", response.status(), response.version());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Session {
    pub(crate) inner: Arc<SessionInner>,
}

pub(crate) struct SessionInner {
    pub(crate) handle: i64,
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        // SAFETY: the handle is ours, and this is its last user.
        unsafe { sys::httpcloak_session_free(self.handle) }
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session").field("handle", &self.inner.handle).finish()
    }
}

/// An HTTP version to force or switch to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HttpVersion {
    /// Negotiate as the browser would: HTTP/3 where advertised, else HTTP/2
    /// or HTTP/1.1 by ALPN.
    #[default]
    Auto,
    Http1,
    Http2,
    Http3,
}

impl HttpVersion {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            HttpVersion::Auto => "auto",
            HttpVersion::Http1 => "h1",
            HttpVersion::Http2 => "h2",
            HttpVersion::Http3 => "h3",
        }
    }
}

/// Extra TLS fingerprint options, layered over a preset or a custom
/// [JA3](SessionBuilder::ja3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtraFingerprint {
    /// ALPN protocols to offer, e.g. `["h2", "http/1.1"]`.
    pub alpn: Vec<String>,
    /// Signature algorithms, e.g. `"ecdsa_secp256r1_sha256"`.
    pub signature_algorithms: Vec<String>,
    /// Certificate compression algorithms: `"brotli"`, `"zlib"`, `"zstd"`.
    pub cert_compression: Vec<String>,
    /// Shuffle the extension order per connection, as Chrome does.
    pub permute_extensions: Option<bool>,
    /// Delegated credential algorithms (extension 34).
    pub delegated_credential_algorithms: Vec<String>,
    /// The `record_size_limit` extension value, as Firefox sends.
    pub record_size_limit: Option<u16>,
    /// How many key shares to send.
    pub key_share_curves: Option<u32>,
}

impl ExtraFingerprint {
    pub fn new() -> ExtraFingerprint {
        ExtraFingerprint::default()
    }

    fn is_empty(&self) -> bool {
        *self == ExtraFingerprint::default()
    }

    fn to_json(&self) -> serde_json::Map<String, serde_json::Value> {
        use serde_json::Value;
        let mut m = serde_json::Map::new();
        let mut list = |key: &str, v: &[String]| {
            if !v.is_empty() {
                m.insert(key.into(), Value::from(v.to_vec()));
            }
        };
        list("tls_alpn", &self.alpn);
        list("tls_signature_algorithms", &self.signature_algorithms);
        list("tls_cert_compression", &self.cert_compression);
        list("tls_delegated_credential_algorithms", &self.delegated_credential_algorithms);
        if let Some(p) = self.permute_extensions {
            m.insert("tls_permute_extensions".into(), Value::from(p));
        }
        if let Some(n) = self.record_size_limit {
            m.insert("tls_record_size_limit".into(), Value::from(n));
        }
        if let Some(n) = self.key_share_curves {
            m.insert("tls_key_share_curves".into(), Value::from(n));
        }
        m
    }
}

/// TCP/IP fingerprint overrides. Each field left `None` keeps the preset's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TcpFingerprint {
    /// IP time-to-live: 128 for Windows, 64 for Linux and macOS.
    pub ttl: Option<u8>,
    /// Maximum segment size: 1460 on Ethernet.
    pub mss: Option<u16>,
    /// Initial window size: 64240 for Windows, 65535 for Linux.
    pub window_size: Option<u16>,
    /// Window scale: 8 for Windows, 7 for Linux, 6 for macOS.
    pub window_scale: Option<u8>,
    /// The IP Don't Fragment bit.
    pub dont_fragment: Option<bool>,
}

impl TcpFingerprint {
    pub fn new() -> TcpFingerprint {
        TcpFingerprint::default()
    }
}

/// The library's session config JSON (`SessionConfig` in clib/httpcloak.go).
#[derive(Serialize, Default, Clone, Debug)]
struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    preset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_proxy: Option<String>,
    /// Seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_version: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_redirects: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_redirects: Option<u32>,
    /// Always sent: 0 turns retries off, which is also the library default.
    retry: u32,
    /// Milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_wait_min: Option<u64>,
    /// Milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_wait_max: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    retry_on_status: Vec<u16>,
    #[serde(skip_serializing_if = "is_false")]
    prefer_ipv4: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    connect_to: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ech_config_domain: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    tls_only: bool,
    /// Seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    quic_idle_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_log_file: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    disable_ech: bool,
    #[serde(skip_serializing_if = "is_false")]
    disable_http3: bool,
    #[serde(skip_serializing_if = "is_false")]
    enable_speculative_tls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    switch_protocol: Option<&'static str>,
    #[serde(skip_serializing_if = "is_false")]
    without_cookie_jar: bool,
    #[serde(skip_serializing_if = "is_false")]
    without_conditional_cache: bool,
    #[serde(skip_serializing_if = "is_false")]
    without_client_hints: bool,
    #[serde(skip_serializing_if = "is_false")]
    without_high_entropy_client_hints: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ja3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    akamai: Option<String>,
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    extra_fp: serde_json::Map<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_ttl: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_mss: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_window_size: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_window_scale: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_df: Option<bool>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Builds a [`Session`]. Options left unset keep the library's defaults: the
/// `chrome-latest` preset, a 30 second timeout, automatic protocol
/// negotiation, certificate verification, up to 10 redirects followed, and no
/// retries.
///
/// Invalid options are reported by [`build`](SessionBuilder::build), the first
/// one found.
#[derive(Clone, Debug, Default)]
#[must_use]
pub struct SessionBuilder {
    config: Config,
    error: Option<String>,
}

/// Rounds a duration up to whole seconds, the unit the library takes, so a
/// timeout is never made shorter than asked.
pub(crate) fn ceil_secs(d: Duration) -> u64 {
    d.as_secs().saturating_add(u64::from(d.subsec_nanos() > 0))
}

/// The longest timeout passed to the library. Go measures durations in signed
/// 64-bit nanoseconds, about 292 years; this keeps far from that.
pub(crate) const MAX_LIBRARY_SECS: u64 = 100 * 365 * 24 * 3600;

impl SessionBuilder {
    fn fail(&mut self, message: impl Into<String>) {
        self.error.get_or_insert(message.into());
    }

    fn seconds(&mut self, what: &str, d: Duration) -> Option<u64> {
        if d.is_zero() {
            self.fail(format!("{what} must be greater than zero"));
            return None;
        }
        Some(ceil_secs(d).min(MAX_LIBRARY_SECS))
    }

    /// The browser preset to emulate, e.g. [`presets::CHROME_LATEST`]. Any name
    /// from [`available_presets`](crate::available_presets) works, as does a
    /// custom preset registered with [`load_preset`](crate::load_preset).
    ///
    /// [`presets::CHROME_LATEST`]: crate::presets::CHROME_LATEST
    pub fn preset(mut self, preset: impl Into<String>) -> Self {
        self.config.preset = Some(preset.into());
        self
    }

    /// A proxy for all traffic: `http://`, `https://`, `socks5://` or
    /// `masque://`, with credentials as `scheme://user:pass@host:port`.
    /// HTTP/3 needs a SOCKS5 or MASQUE proxy; over an HTTP proxy, requests
    /// use HTTP/2 or HTTP/1.1.
    pub fn proxy(mut self, url: impl Into<String>) -> Self {
        self.config.proxy = Some(url.into());
        self
    }

    /// A proxy for HTTP/1.1 and HTTP/2 only, for a split setup with
    /// [`udp_proxy`](SessionBuilder::udp_proxy).
    pub fn tcp_proxy(mut self, url: impl Into<String>) -> Self {
        self.config.tcp_proxy = Some(url.into());
        self
    }

    /// A proxy for HTTP/3 only: SOCKS5 (UDP ASSOCIATE) or MASQUE.
    pub fn udp_proxy(mut self, url: impl Into<String>) -> Self {
        self.config.udp_proxy = Some(url.into());
        self
    }

    /// How long a request may take, redirects and retries included, unless it
    /// sets its own [timeout](crate::RequestBuilder::timeout). 30 seconds by
    /// default. The library counts in whole seconds, so this is rounded up.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = self.seconds("the session timeout", timeout);
        self
    }

    /// Forces one HTTP version, or [`HttpVersion::Auto`] to negotiate.
    pub fn http_version(mut self, version: HttpVersion) -> Self {
        self.config.http_version = Some(version.as_str());
        self
    }

    /// Never race HTTP/3, but still negotiate HTTP/2 or HTTP/1.1.
    pub fn disable_http3(mut self, disable: bool) -> Self {
        self.config.disable_http3 = disable;
        self
    }

    /// Accept any certificate, including expired, self-signed and mismatched
    /// ones. Dangerous: anyone on the path can read and alter the traffic.
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.config.verify = accept.then_some(false);
        self
    }

    /// Whether to follow redirects. On by default.
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.config.allow_redirects = (!follow).then_some(false);
        self
    }

    /// The most redirects to follow, 10 by default. Must be at least 1; turn
    /// following off with [`follow_redirects`](SessionBuilder::follow_redirects).
    pub fn max_redirects(mut self, max: u32) -> Self {
        match check_max_redirects(max) {
            Ok(max) => self.config.max_redirects = Some(max),
            Err(e) => self.fail(e),
        }
        self
    }

    /// Retry a failed request up to `attempts` times. Off by default, because a
    /// retried POST is sent twice.
    pub fn retry(mut self, attempts: u32) -> Self {
        self.config.retry = attempts;
        self
    }

    /// The wait between retries: it starts at `min` and backs off up to `max`.
    /// 500ms and 10s by default.
    pub fn retry_wait(mut self, min: Duration, max: Duration) -> Self {
        if min > max {
            self.fail("the minimum retry wait is longer than the maximum");
        }
        if min.is_zero() || max.is_zero() {
            self.fail("retry waits must be greater than zero");
        }
        let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1);
        self.config.retry_wait_min = Some(ms(min));
        self.config.retry_wait_max = Some(ms(max));
        self
    }

    /// Statuses that are retried as failures, e.g. `[429, 503]`.
    pub fn retry_on_status(mut self, statuses: impl IntoIterator<Item = u16>) -> Self {
        for status in statuses {
            if !(100..=599).contains(&status) {
                self.fail(format!("{status} is not an HTTP status"));
            }
            self.config.retry_on_status.push(status);
        }
        self
    }

    /// Prefer IPv4 addresses over IPv6.
    pub fn prefer_ipv4(mut self, prefer: bool) -> Self {
        self.config.prefer_ipv4 = prefer;
        self
    }

    /// Connect to `connect_host` for requests to `request_host`, keeping
    /// `request_host` in the SNI and `Host`: domain fronting.
    pub fn connect_to(mut self, request_host: impl Into<String>, connect_host: impl Into<String>) -> Self {
        self.config.connect_to.insert(request_host.into(), connect_host.into());
        self
    }

    /// The domain to fetch the ECH config from, e.g. `"cloudflare-ech.com"`.
    pub fn ech_config_domain(mut self, domain: impl Into<String>) -> Self {
        self.config.ech_config_domain = Some(domain.into());
        self
    }

    /// Skip the ECH DNS lookup, saving a round trip on the first connection.
    pub fn disable_ech(mut self, disable: bool) -> Self {
        self.config.disable_ech = disable;
        self
    }

    /// Use the preset's TLS and HTTP/2 fingerprint but none of its HTTP
    /// headers: every header is then the caller's.
    pub fn tls_only(mut self, tls_only: bool) -> Self {
        self.config.tls_only = tls_only;
        self
    }

    /// How long an idle QUIC connection is kept, 30 seconds by default.
    /// Rounded up to whole seconds.
    pub fn quic_idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.quic_idle_timeout = self.seconds("the QUIC idle timeout", timeout);
        self
    }

    /// The local address to send from, e.g. to rotate through an IPv6 range.
    pub fn local_address(mut self, address: IpAddr) -> Self {
        self.config.local_address = Some(address.to_string());
        self
    }

    /// Append the TLS keys of every connection to this file, in the NSS key
    /// log format Wireshark reads.
    pub fn key_log_file(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        match path.to_str() {
            Some(p) => self.config.key_log_file = Some(p.to_string()),
            None => self.fail(format!("the key log path {} is not valid UTF-8", path.display())),
        }
        self
    }

    /// Resume TLS speculatively through a proxy, saving a round trip.
    pub fn enable_speculative_tls(mut self, enable: bool) -> Self {
        self.config.enable_speculative_tls = enable;
        self
    }

    /// The protocol to switch to on [`Session::refresh`].
    pub fn switch_protocol(mut self, version: HttpVersion) -> Self {
        self.config.switch_protocol = Some(version.as_str());
        self
    }

    /// Keep no cookies: each request carries only the cookies it sets itself.
    pub fn without_cookie_jar(mut self, without: bool) -> Self {
        self.config.without_cookie_jar = without;
        self
    }

    /// Never send `If-None-Match` or `If-Modified-Since`.
    pub fn without_conditional_cache(mut self, without: bool) -> Self {
        self.config.without_conditional_cache = without;
        self
    }

    /// Send no `Sec-CH-UA` client hints at all.
    pub fn without_client_hints(mut self, without: bool) -> Self {
        self.config.without_client_hints = without;
        self
    }

    /// Send the three low-entropy client hints but none of the high-entropy
    /// ones, even when a server asks.
    pub fn without_high_entropy_client_hints(mut self, without: bool) -> Self {
        self.config.without_high_entropy_client_hints = without;
        self
    }

    /// A custom TLS fingerprint as a JA3 string, replacing the preset's.
    pub fn ja3(mut self, ja3: impl Into<String>) -> Self {
        self.config.ja3 = Some(ja3.into());
        self
    }

    /// A custom HTTP/2 fingerprint in Akamai's shorthand, replacing the
    /// preset's.
    pub fn akamai(mut self, akamai: impl Into<String>) -> Self {
        self.config.akamai = Some(akamai.into());
        self
    }

    /// TLS fingerprint options beyond what JA3 describes.
    pub fn extra_fingerprint(mut self, extra: ExtraFingerprint) -> Self {
        if !extra.is_empty() {
            self.config.extra_fp = extra.to_json();
        }
        self
    }

    /// TCP/IP fingerprint overrides. Sending with a different TTL or window
    /// may need elevated privileges.
    pub fn tcp_fingerprint(mut self, tcp: TcpFingerprint) -> Self {
        self.config.tcp_ttl = tcp.ttl;
        self.config.tcp_mss = tcp.mss;
        self.config.tcp_window_size = tcp.window_size;
        self.config.tcp_window_scale = tcp.window_scale;
        self.config.tcp_df = tcp.dont_fragment;
        self
    }

    /// Creates the session.
    pub fn build(self) -> Result<Session> {
        if let Some(message) = self.error {
            return Err(Error::invalid_input(message));
        }
        let config = self.config;
        if config.retry == 0 && (!config.retry_on_status.is_empty() || config.retry_wait_min.is_some()) {
            return Err(Error::invalid_input("retry_on_status and retry_wait have no effect without retry(n)"));
        }
        if config.allow_redirects == Some(false) && config.max_redirects.is_some() {
            return Err(Error::invalid_input("max_redirects has no effect with follow_redirects(false)"));
        }
        // The library accepts an unknown preset and fails every request on
        // the session with it instead. Fail here, where the mistake is.
        if let Some(preset) = config.preset.as_deref().filter(|p| !p.is_empty()) {
            check_preset(preset)?;
        }
        let json = serde_json::to_string(&config).expect("the session config always serializes");
        let json = cstring(&json, "the session config")?;
        // SAFETY: a valid NUL-terminated string, only read during the call.
        let handle = unsafe { sys::httpcloak_session_new(json.as_ptr()) };
        Session::from_handle(handle, "could not create the session")
    }
}

pub(crate) fn check_max_redirects(max: u32) -> std::result::Result<u32, String> {
    match max {
        0 => Err("max_redirects must be at least 1; use follow_redirects(false) to follow none".into()),
        m if m > i32::MAX as u32 => Err(format!("max_redirects {m} is too large")),
        m => Ok(m),
    }
}

/// Fails with [`ErrorKind::InvalidInput`] unless `preset` is registered.
pub(crate) fn check_preset(preset: &str) -> Result<()> {
    let name = cstring(preset, "the preset name")?;
    // SAFETY: a valid NUL-terminated string; the result is ours to free.
    let described = unsafe { ffi::take_string(sys::httpcloak_describe_preset(name.as_ptr())) };
    match described.as_deref().map(ffi::error_in) {
        Some(None) => Ok(()),
        _ => Err(Error::invalid_input(format!(
            "unknown preset {preset:?}; see httpcloak::available_presets() for the built-in ones"
        ))),
    }
}

/// A snapshot of a session's counters, from [`Session::stats`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SessionStats {
    /// The session's random ID.
    pub id: String,
    /// The preset name the session was created with.
    pub preset: String,
    pub created_at: SystemTime,
    /// When the session last started a request.
    pub last_used: SystemTime,
    /// Requests sent, each redirect hop counted.
    pub request_count: u64,
    pub active: bool,
    pub cookie_count: u64,
    /// Entries in the conditional-request cache.
    pub cache_entry_count: u64,
    pub age: Duration,
    pub idle_time: Duration,
    /// Per-protocol connection statistics, shaped as the Go library reports
    /// them (`http1`, `http2`, `http3`).
    pub transport: serde_json::Value,
}

#[derive(Deserialize)]
struct WireStats {
    #[serde(default)]
    id: String,
    #[serde(default)]
    preset: String,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    last_used: i64,
    #[serde(default)]
    request_count: u64,
    #[serde(default)]
    active: bool,
    #[serde(default)]
    cookie_count: u64,
    #[serde(default)]
    cache_entry_count: u64,
    #[serde(default)]
    age_ns: i64,
    #[serde(default)]
    idle_time_ns: i64,
    #[serde(default)]
    transport_stats: serde_json::Value,
}

fn unix_nanos(ns: i64) -> SystemTime {
    match u64::try_from(ns) {
        Ok(ns) => SystemTime::UNIX_EPOCH + Duration::from_nanos(ns),
        Err(_) => SystemTime::UNIX_EPOCH,
    }
}

fn nanos(ns: i64) -> Duration {
    Duration::from_nanos(u64::try_from(ns).unwrap_or(0))
}

fn flag(enabled: bool) -> c_int {
    c_int::from(enabled)
}

impl Session {
    /// A session with the default options, emulating `chrome-latest`.
    pub fn new() -> Result<Session> {
        Session::builder().build()
    }

    pub fn builder() -> SessionBuilder {
        SessionBuilder::default()
    }

    pub(crate) fn from_handle(handle: i64, what: &str) -> Result<Session> {
        if handle <= 0 {
            return Err(Error::new_other(what.to_string()));
        }
        Ok(Session { inner: Arc::new(SessionInner { handle }) })
    }

    pub(crate) fn handle(&self) -> i64 {
        self.inner.handle
    }

    // --- Requests -----------------------------------------------------------

    /// Starts a request with any method.
    pub fn request(&self, method: Method, url: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(self.clone(), method, url.into())
    }

    pub fn get(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    pub fn post(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    pub fn put(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    pub fn patch(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    pub fn delete(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    pub fn head(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    pub fn options(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::OPTIONS, url)
    }

    /// Starts an upload whose body is written incrementally, for bodies too
    /// large to hold in memory. See [`Upload`](crate::Upload).
    pub fn upload(&self, url: impl Into<String>) -> UploadBuilder {
        UploadBuilder::new(self.clone(), url.into())
    }

    // --- Lifecycle ----------------------------------------------------------

    /// A new session that shares this one's cookie jar and TLS session
    /// tickets but has its own connections, like another tab of the same
    /// browser. It keeps the parent's runtime settings, but not a header order
    /// set with [`set_header_order`](Session::set_header_order).
    pub fn fork(&self) -> Result<Session> {
        // SAFETY: plain call with our handle.
        let handle = unsafe { sys::httpcloak_session_fork(self.handle()) };
        Session::from_handle(handle, "could not fork the session")
    }

    /// Closes every connection but keeps cookies and TLS tickets, like a page
    /// refresh. Switches protocol if the session was built with
    /// [`switch_protocol`](SessionBuilder::switch_protocol). Requests after a
    /// refresh carry `Cache-Control: max-age=0`, as a reloading browser's do.
    pub fn refresh(&self) {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_session_refresh(self.handle()) }
    }

    /// [`refresh`](Session::refresh), switching to `version` from now on.
    pub fn refresh_with_protocol(&self, version: HttpVersion) -> Result<()> {
        let protocol = cstring(version.as_str(), "the protocol")?;
        // SAFETY: a valid NUL-terminated string; the result is ours to free.
        let result =
            unsafe { ffi::take_string(sys::httpcloak_session_refresh_protocol(self.handle(), protocol.as_ptr())) };
        match result.as_deref().and_then(ffi::error_in) {
            Some(message) => Err(Error::from_library(message)),
            None => Ok(()),
        }
    }

    /// Loads `url` the way a browser loads a page, the HTML and then its
    /// stylesheets, scripts and images, to warm TLS sessions, cookies and
    /// caches. Blocks for up to `timeout`, 60 seconds when `None`.
    pub fn warmup(&self, url: &str, timeout: Option<Duration>) -> Result<()> {
        let c_url = cstring(url, "the URL")?;
        let ms = match timeout {
            Some(t) if t.is_zero() => return Err(Error::invalid_input("the warmup timeout must be greater than zero")),
            Some(t) => i64::try_from(t.as_millis()).unwrap_or(i64::MAX).max(1),
            None => 0,
        };
        // SAFETY: a valid NUL-terminated string; the result is ours to free.
        let result = unsafe { ffi::take_string(sys::httpcloak_session_warmup(self.handle(), c_url.as_ptr(), ms)) };
        match result.as_deref().and_then(ffi::error_in) {
            Some(message) => {
                Err(Error::from_library(message).with_hosts(&crate::request::hosts_involved(self, url)).with_url(url))
            }
            None => Ok(()),
        }
    }

    /// Writes the session to `path`, readable only by its owner: cookies, TLS
    /// tickets, ECH configs and the options it was built with. A custom
    /// fingerprint, header order and runtime toggles are not saved.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = cpath(path.as_ref(), "the session path")?;
        // SAFETY: a valid NUL-terminated string; the result is ours to free.
        let result = unsafe { ffi::take_string(sys::httpcloak_session_save(self.handle(), path.as_ptr())) };
        ffi::checked(result, "saving the session").map(drop)
    }

    /// Restores a session written by [`save`](Session::save).
    pub fn load(path: impl AsRef<Path>) -> Result<Session> {
        let path = path.as_ref();
        let data = std::fs::read_to_string(path).map_err(|e| {
            Error::new(ErrorKind::Io, format!("could not read the session file {}: {e}", path.display())).with_source(e)
        })?;
        Session::unmarshal(&data)
    }

    /// The session's state as a string, for [`unmarshal`](Session::unmarshal).
    /// It holds cookies and TLS tickets; keep it as secret as they are.
    pub fn marshal(&self) -> Result<String> {
        // SAFETY: plain call; the result is ours to free.
        let result = unsafe { ffi::take_string(sys::httpcloak_session_marshal(self.handle())) };
        ffi::checked(result, "marshalling the session")
    }

    /// Restores a session from [`marshal`](Session::marshal) output.
    pub fn unmarshal(data: &str) -> Result<Session> {
        // The library says only that it failed; say why where we can.
        if let Err(e) = serde_json::from_str::<serde::de::IgnoredAny>(data) {
            return Err(Error::invalid_input(format!("not a saved session: {e}")));
        }
        let c_data = cstring(data, "the session data")?;
        // SAFETY: a valid NUL-terminated string, only read during the call.
        let handle = unsafe { sys::httpcloak_session_unmarshal(c_data.as_ptr()) };
        Session::from_handle(
            handle,
            "could not restore the session: the data is not a saved session, or was saved by a newer version",
        )
        .map_err(|e| Error::invalid_input(e.message()))
    }

    // --- Cookies ------------------------------------------------------------

    /// Every cookie in the jar that has not expired.
    pub fn cookies(&self) -> Result<Vec<Cookie>> {
        // SAFETY: plain call; the result is ours to free.
        let result = unsafe { ffi::take_string(sys::httpcloak_get_cookies(self.handle())) };
        let json = ffi::checked(result, "reading the cookies")?;
        let cookies: Option<Vec<WireCookie>> = ffi::parse_json(&json, "the cookies")?;
        Ok(cookies.unwrap_or_default().into_iter().map(Cookie::from_wire).collect())
    }

    /// Puts `cookie` in the jar, replacing one with the same name, domain and
    /// path. A cookie with no domain is sent to every host.
    pub fn set_cookie(&self, cookie: &Cookie) -> Result<()> {
        cookie.validate()?;
        let json = serde_json::to_string(&cookie.to_wire()).expect("a cookie always serializes");
        let json = cstring(&json, "the cookie")?;
        // SAFETY: a valid NUL-terminated string, only read during the call.
        unsafe { sys::httpcloak_set_cookie(self.handle(), json.as_ptr()) };
        Ok(())
    }

    /// Removes the cookies named `name`: from every domain when `domain` is
    /// `None`, else from exactly that domain, written as the cookie stores it
    /// (`.example.com` for one set with a `Domain` attribute).
    pub fn delete_cookie(&self, name: &str, domain: Option<&str>) -> Result<()> {
        let name = cstring(name, "the cookie name")?;
        let domain = cstring(domain.unwrap_or(""), "the cookie domain")?;
        // SAFETY: valid NUL-terminated strings, only read during the call.
        unsafe { sys::httpcloak_delete_cookie(self.handle(), name.as_ptr(), domain.as_ptr()) };
        Ok(())
    }

    pub fn clear_cookies(&self) {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_clear_cookies(self.handle()) }
    }

    // --- Proxies ------------------------------------------------------------

    /// Routes all traffic through `proxy`, or directly when `None`. Closes the
    /// open connections, interrupting requests in flight over HTTP/2 and
    /// HTTP/3, and starts new TLS session caches.
    pub fn set_proxy(&self, proxy: Option<&str>) -> Result<()> {
        self.set_proxy_with(proxy, sys::httpcloak_session_set_proxy)
    }

    /// Sets the proxy for HTTP/1.1 and HTTP/2 only.
    pub fn set_tcp_proxy(&self, proxy: Option<&str>) -> Result<()> {
        self.set_proxy_with(proxy, sys::httpcloak_session_set_tcp_proxy)
    }

    /// Sets the proxy for HTTP/3 only.
    pub fn set_udp_proxy(&self, proxy: Option<&str>) -> Result<()> {
        self.set_proxy_with(proxy, sys::httpcloak_session_set_udp_proxy)
    }

    fn set_proxy_with(
        &self,
        proxy: Option<&str>,
        set: unsafe extern "C" fn(i64, *const std::ffi::c_char) -> *mut std::ffi::c_char,
    ) -> Result<()> {
        let proxy = cstring(proxy.unwrap_or(""), "the proxy URL")?;
        // SAFETY: a valid NUL-terminated string; the result is ours to free.
        let result = unsafe { ffi::take_string(set(self.handle(), proxy.as_ptr())) };
        ffi::checked(result, "setting the proxy").map(drop)
    }

    /// The proxy for all traffic, if one is set.
    pub fn proxy(&self) -> Option<String> {
        self.get_proxy_with(sys::httpcloak_session_get_proxy)
    }

    pub fn tcp_proxy(&self) -> Option<String> {
        self.get_proxy_with(sys::httpcloak_session_get_tcp_proxy)
    }

    pub fn udp_proxy(&self) -> Option<String> {
        self.get_proxy_with(sys::httpcloak_session_get_udp_proxy)
    }

    fn get_proxy_with(&self, get: unsafe extern "C" fn(i64) -> *mut std::ffi::c_char) -> Option<String> {
        // SAFETY: plain call; the result is ours to free.
        let proxy = unsafe { ffi::take_string(get(self.handle())) }?;
        (!proxy.is_empty() && ffi::error_in(&proxy).is_none()).then_some(proxy)
    }

    // --- Header order and identity ------------------------------------------

    /// Sends the named headers first, in this order, on every request; the
    /// rest keep the preset's order. An empty list restores the preset's.
    /// A request's own [`header_order`](crate::RequestBuilder::header_order)
    /// takes precedence, and is the one to use for a single request: this
    /// changes the order for requests already being sent too.
    pub fn set_header_order<I, S>(&self, names: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let names: Vec<String> = names.into_iter().map(|s| s.as_ref().to_string()).collect();
        if let Some(bad) = names.iter().find(|n| !crate::headers::valid_name(n)) {
            return Err(Error::invalid_input(format!("{bad:?} is not a valid header name")));
        }
        let json = cstring(&serde_json::to_string(&names).expect("strings serialize"), "the header order")?;
        // SAFETY: a valid NUL-terminated string; the result is ours to free.
        let result = unsafe { ffi::take_string(sys::httpcloak_session_set_header_order(self.handle(), json.as_ptr())) };
        ffi::checked(result, "setting the header order").map(drop)
    }

    /// The header order in effect, lowercase: the one set with
    /// [`set_header_order`](Session::set_header_order), or else the preset's.
    pub fn header_order(&self) -> Vec<String> {
        // SAFETY: plain call; the result is ours to free.
        let result = unsafe { ffi::take_string(sys::httpcloak_session_get_header_order(self.handle())) };
        result.and_then(|json| serde_json::from_str(&json).ok()).unwrap_or_default()
    }

    /// Isolates this session's keys in a shared
    /// [session cache](crate::set_session_cache), for sessions that must not
    /// resume each other's TLS sessions. `None` clears it.
    pub fn set_identifier(&self, id: Option<&str>) -> Result<()> {
        let id = id.map(|id| cstring(id, "the session identifier")).transpose()?;
        let ptr = id.as_ref().map_or(std::ptr::null(), |id| id.as_ptr());
        // SAFETY: null or a valid NUL-terminated string, only read during the
        // call.
        unsafe { sys::httpcloak_session_set_identifier(self.handle(), ptr) };
        Ok(())
    }

    // --- Runtime toggles ----------------------------------------------------

    /// Drops the conditional-request cache. Cookies and TLS tickets are kept.
    pub fn clear_cache(&self) {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_session_clear_cache(self.handle()) }
    }

    /// Whether requests send `If-None-Match` / `If-Modified-Since` for cached
    /// URLs.
    pub fn conditional_cache(&self) -> bool {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_session_get_conditional_cache(self.handle()) != 0 }
    }

    pub fn set_conditional_cache(&self, enabled: bool) {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_session_set_conditional_cache(self.handle(), flag(enabled)) }
    }

    /// Whether `Sec-CH-UA` client hints are sent.
    pub fn client_hints(&self) -> bool {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_session_get_client_hints(self.handle()) != 0 }
    }

    pub fn set_client_hints(&self, enabled: bool) {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_session_set_client_hints(self.handle(), flag(enabled)) }
    }

    /// Whether high-entropy client hints are sent when a server asks for them.
    pub fn high_entropy_client_hints(&self) -> bool {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_session_get_high_entropy_client_hints(self.handle()) != 0 }
    }

    pub fn set_high_entropy_client_hints(&self, enabled: bool) {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_session_set_high_entropy_client_hints(self.handle(), flag(enabled)) }
    }

    pub fn follow_redirects(&self) -> bool {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_session_get_follow_redirects(self.handle()) != 0 }
    }

    pub fn set_follow_redirects(&self, follow: bool) {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_session_set_follow_redirects(self.handle(), flag(follow)) }
    }

    pub fn max_redirects(&self) -> u32 {
        // SAFETY: plain call with our handle.
        let max = unsafe { sys::httpcloak_session_get_max_redirects(self.handle()) };
        u32::try_from(max).unwrap_or(0)
    }

    /// Sets the most redirects to follow. Must be at least 1.
    pub fn set_max_redirects(&self, max: u32) -> Result<()> {
        let max = check_max_redirects(max).map_err(Error::invalid_input)?;
        // SAFETY: plain call with our handle; max fits a c_int.
        unsafe { sys::httpcloak_session_set_max_redirects(self.handle(), max as c_int) };
        Ok(())
    }

    // --- Observability ------------------------------------------------------

    pub fn stats(&self) -> Result<SessionStats> {
        // SAFETY: plain call; the result is ours to free.
        let json = unsafe { ffi::take_string(sys::httpcloak_session_stats(self.handle())) }
            .ok_or_else(|| Error::new_other("the library returned no statistics"))?;
        let s: WireStats = ffi::parse_json(&json, "the session statistics")?;
        Ok(SessionStats {
            id: s.id,
            preset: s.preset,
            created_at: unix_nanos(s.created_at),
            last_used: unix_nanos(s.last_used),
            request_count: s.request_count,
            active: s.active,
            cookie_count: s.cookie_count,
            cache_entry_count: s.cache_entry_count,
            age: nanos(s.age_ns),
            idle_time: nanos(s.idle_time_ns),
            transport: s.transport_stats,
        })
    }

    /// The time since the session last started a request.
    pub fn idle_time(&self) -> Duration {
        // SAFETY: plain call with our handle.
        nanos(unsafe { sys::httpcloak_session_idle_time(self.handle()) })
    }

    /// Resets the idle time without sending anything.
    pub fn touch(&self) {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_session_touch(self.handle()) }
    }

    /// Whether the session is usable, which it is for as long as a `Session`
    /// refers to it.
    pub fn is_active(&self) -> bool {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_session_is_active(self.handle()) != 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(b: SessionBuilder) -> serde_json::Value {
        assert!(b.error.is_none(), "{:?}", b.error);
        serde_json::to_value(&b.config).unwrap()
    }

    #[test]
    fn the_default_config_only_turns_retries_off() {
        assert_eq!(json(Session::builder()), serde_json::json!({"retry": 0}));
    }

    #[test]
    fn maps_every_option_to_the_library_names() {
        let b = Session::builder()
            .preset("chrome-155")
            .proxy("socks5://h:1")
            .tcp_proxy("http://t:2")
            .udp_proxy("masque://u:3")
            .timeout(Duration::from_millis(1500))
            .http_version(HttpVersion::Http2)
            .danger_accept_invalid_certs(true)
            .max_redirects(3)
            .retry(2)
            .retry_wait(Duration::from_millis(100), Duration::from_secs(2))
            .retry_on_status([429, 503])
            .prefer_ipv4(true)
            .connect_to("a.com", "b.com")
            .ech_config_domain("cloudflare-ech.com")
            .tls_only(true)
            .quic_idle_timeout(Duration::from_secs(10))
            .local_address("::1".parse().unwrap())
            .key_log_file("/tmp/keys")
            .disable_ech(true)
            .disable_http3(true)
            .enable_speculative_tls(true)
            .switch_protocol(HttpVersion::Http3)
            .without_cookie_jar(true)
            .without_conditional_cache(true)
            .without_client_hints(true)
            .without_high_entropy_client_hints(true)
            .ja3("771,4865,0,29,0")
            .akamai("1:65536|15663105|0|m,a,s,p")
            .extra_fingerprint(ExtraFingerprint {
                alpn: vec!["h2".into()],
                permute_extensions: Some(true),
                record_size_limit: Some(16385),
                key_share_curves: Some(2),
                ..Default::default()
            })
            .tcp_fingerprint(TcpFingerprint { ttl: Some(128), dont_fragment: Some(true), ..Default::default() });
        assert_eq!(
            json(b),
            serde_json::json!({
                "preset": "chrome-155", "proxy": "socks5://h:1", "tcp_proxy": "http://t:2",
                "udp_proxy": "masque://u:3", "timeout": 2, "http_version": "h2", "verify": false,
                "max_redirects": 3, "retry": 2, "retry_wait_min": 100, "retry_wait_max": 2000,
                "retry_on_status": [429, 503], "prefer_ipv4": true, "connect_to": {"a.com": "b.com"},
                "ech_config_domain": "cloudflare-ech.com", "tls_only": true, "quic_idle_timeout": 10,
                "local_address": "::1", "key_log_file": "/tmp/keys", "disable_ech": true,
                "disable_http3": true, "enable_speculative_tls": true, "switch_protocol": "h3",
                "without_cookie_jar": true, "without_conditional_cache": true,
                "without_client_hints": true, "without_high_entropy_client_hints": true,
                "ja3": "771,4865,0,29,0", "akamai": "1:65536|15663105|0|m,a,s,p",
                "extra_fp": {"tls_alpn": ["h2"], "tls_permute_extensions": true,
                             "tls_record_size_limit": 16385, "tls_key_share_curves": 2},
                "tcp_ttl": 128, "tcp_df": true
            })
        );
    }

    #[test]
    fn toggling_back_restores_the_defaults() {
        let b = Session::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_certs(false)
            .follow_redirects(false)
            .follow_redirects(true);
        assert_eq!(json(b), serde_json::json!({"retry": 0}));
    }

    #[test]
    fn rejects_what_the_library_would_reinterpret() {
        let err = |b: SessionBuilder| b.build().unwrap_err();
        assert!(err(Session::builder().timeout(Duration::ZERO)).is_invalid_input());
        assert!(err(Session::builder().max_redirects(0)).is_invalid_input());
        assert!(err(Session::builder().quic_idle_timeout(Duration::ZERO)).is_invalid_input());
        assert!(err(Session::builder().retry_on_status([429])).is_invalid_input());
        assert!(err(Session::builder().retry(1).retry_on_status([42])).is_invalid_input());
        assert!(err(Session::builder().retry(1).retry_wait(Duration::from_secs(2), Duration::from_secs(1)))
            .is_invalid_input());
        assert!(err(Session::builder().follow_redirects(false).max_redirects(2)).is_invalid_input());
        assert!(err(Session::builder().preset("a\0b")).is_invalid_input());
        // The first problem found is the one reported.
        let e = err(Session::builder().timeout(Duration::ZERO).max_redirects(0));
        assert!(e.message().contains("timeout"), "{e}");
    }

    #[test]
    fn timeouts_round_up_to_whole_seconds() {
        assert_eq!(ceil_secs(Duration::from_millis(1)), 1);
        assert_eq!(ceil_secs(Duration::from_secs(2)), 2);
        assert_eq!(ceil_secs(Duration::from_millis(2001)), 3);
        assert_eq!(ceil_secs(Duration::MAX), u64::MAX);
        let b = Session::builder().timeout(Duration::MAX);
        assert_eq!(b.config.timeout, Some(MAX_LIBRARY_SECS));
    }
}
