use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use httpcloak_sys as sys;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::ffi::{self, cstring};
use crate::session::{ceil_secs, check_preset, Session, MAX_LIBRARY_SECS};

/// An HTTP proxy on `127.0.0.1` that sends what it receives through httpcloak,
/// so that a client which can only be pointed at a proxy gets a browser's
/// fingerprint.
///
/// What is fingerprinted is a request for an HTTPS origin made to the proxy
/// in plain HTTP: either an absolute `https://` URL, or an `http://` URL with
/// the header `X-HTTPCloak-Scheme: https`. The proxy makes the TLS connection
/// itself, with the preset's fingerprint. A `CONNECT` tunnel carries the
/// client's own TLS, and a plain `http://` request is forwarded as it came.
///
/// A fingerprinted request picks one of the
/// [registered sessions](LocalProxy::register_session) with the header
/// `X-HTTPCloak-Session: <id>`; the proxy strips its `X-HTTPCloak-*` headers
/// before forwarding. The proxy stops when dropped.
pub struct LocalProxy {
    handle: i64,
    port: u16,
    /// The registered sessions, kept alive while the proxy may use them.
    sessions: Mutex<HashMap<String, Session>>,
}

/// Configures and starts a [`LocalProxy`].
#[derive(Clone, Debug, Default)]
#[must_use]
pub struct LocalProxyBuilder {
    config: Config,
    error: Option<String>,
}

#[derive(Serialize, Default, Clone, Debug)]
struct Config {
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    preset: Option<String>,
    /// Seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_connections: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_proxy: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    tls_only: bool,
}

impl LocalProxyBuilder {
    /// The port to listen on; 0, the default, picks a free one.
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// The preset for requests that name no session, `chrome-latest` by
    /// default.
    pub fn preset(mut self, preset: impl Into<String>) -> Self {
        self.config.preset = Some(preset.into());
        self
    }

    /// How long a request through the proxy may take, 30 seconds by default.
    /// Rounded up to whole seconds.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        if timeout.is_zero() {
            self.error.get_or_insert("the proxy timeout must be greater than zero".into());
        }
        self.config.timeout = Some(ceil_secs(timeout).min(MAX_LIBRARY_SECS));
        self
    }

    /// The most connections served at once, 1000 by default.
    pub fn max_connections(mut self, max: u32) -> Self {
        if max == 0 || max > i32::MAX as u32 {
            self.error.get_or_insert(format!("max_connections must be between 1 and {}", i32::MAX));
        }
        self.config.max_connections = Some(max);
        self
    }

    /// An upstream proxy for HTTP/1.1 and HTTP/2.
    pub fn tcp_proxy(mut self, url: impl Into<String>) -> Self {
        self.config.tcp_proxy = Some(url.into());
        self
    }

    /// An upstream proxy for HTTP/3: SOCKS5 or MASQUE.
    pub fn udp_proxy(mut self, url: impl Into<String>) -> Self {
        self.config.udp_proxy = Some(url.into());
        self
    }

    /// Use the preset's TLS fingerprint but leave the client's HTTP headers
    /// alone.
    pub fn tls_only(mut self, tls_only: bool) -> Self {
        self.config.tls_only = tls_only;
        self
    }

    /// Starts listening.
    pub fn start(self) -> Result<LocalProxy> {
        if let Some(message) = self.error {
            return Err(Error::invalid_input(message));
        }
        if let Some(preset) = self.config.preset.as_deref().filter(|p| !p.is_empty()) {
            check_preset(preset)?;
        }
        let json = serde_json::to_string(&self.config).expect("the proxy config always serializes");
        let json = cstring(&json, "the proxy config")?;
        // SAFETY: a valid NUL-terminated string, only read during the call.
        let handle = unsafe { sys::httpcloak_local_proxy_start(json.as_ptr()) };
        if handle <= 0 {
            // The library says only that it failed. Listening is the one step
            // that fails for a valid config; see whether that is why.
            let port = self.config.port;
            let reason = match std::net::TcpListener::bind(("127.0.0.1", port)) {
                Err(e) if port != 0 => format!("127.0.0.1:{port} is not available: {e}"),
                _ => "the library gave no reason".to_string(),
            };
            return Err(Error::new_other(format!("could not start the local proxy: {reason}")));
        }
        // SAFETY: plain call with the handle just returned.
        let port = unsafe { sys::httpcloak_local_proxy_get_port(handle) };
        Ok(LocalProxy { handle, port: u16::try_from(port).unwrap_or(0), sessions: Mutex::new(HashMap::new()) })
    }
}

/// A snapshot of a proxy's counters, from [`LocalProxy::stats`].
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct LocalProxyStats {
    #[serde(default)]
    pub running: bool,
    #[serde(default)]
    pub port: u16,
    /// Connections being served now.
    #[serde(default, rename = "active_conns")]
    pub active_connections: u64,
    #[serde(default)]
    pub total_requests: u64,
    #[serde(default)]
    pub preset: String,
    #[serde(default)]
    pub max_connections: u64,
    #[serde(default)]
    pub registered_sessions: u64,
}

impl LocalProxy {
    pub fn builder() -> LocalProxyBuilder {
        LocalProxyBuilder::default()
    }

    /// A proxy on a free port, with the default options.
    pub fn start() -> Result<LocalProxy> {
        LocalProxy::builder().start()
    }

    /// The port the proxy listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The proxy's URL, `http://127.0.0.1:<port>`, to configure a client with.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn is_running(&self) -> bool {
        // SAFETY: plain call with our handle.
        unsafe { sys::httpcloak_local_proxy_is_running(self.handle) != 0 }
    }

    pub fn stats(&self) -> Result<LocalProxyStats> {
        // SAFETY: plain call; the result is ours to free.
        let json = unsafe { ffi::take_string(sys::httpcloak_local_proxy_get_stats(self.handle)) };
        ffi::parse_json(&ffi::checked(json, "reading the proxy statistics")?, "the proxy statistics")
    }

    /// Makes `session` the one used for fingerprinted requests carrying the
    /// header `X-HTTPCloak-Session: <id>`. The proxy keeps the session alive until
    /// it is unregistered or the proxy is dropped. Also sets the session's
    /// [identifier](Session::set_identifier) to `id`.
    pub fn register_session(&self, id: &str, session: &Session) -> Result<()> {
        if id.is_empty() {
            return Err(Error::invalid_input("the session ID is empty"));
        }
        let c_id = cstring(id, "the session ID")?;
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: both handles are alive (we hold the proxy, and the caller
        // the session), and the ID is a valid NUL-terminated string.
        let result = unsafe {
            ffi::take_string(sys::httpcloak_local_proxy_register_session(self.handle, c_id.as_ptr(), session.handle()))
        };
        if let Some(message) = result.as_deref().map(|r| ffi::error_in(r).unwrap_or_else(|| r.to_string())) {
            return Err(Error::from_library(message));
        }
        sessions.insert(id.to_string(), session.clone());
        Ok(())
    }

    /// Stops routing `X-HTTPCloak-Session: <id>` to its session, and lets the
    /// proxy's hold on it go. Returns whether a session was registered as `id`.
    pub fn unregister_session(&self, id: &str) -> bool {
        let Ok(c_id) = cstring(id, "the session ID") else { return false };
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: plain call with our handle and a valid NUL-terminated string.
        let removed = unsafe { sys::httpcloak_local_proxy_unregister_session(self.handle, c_id.as_ptr()) } == 1;
        // Dropped after the library has let go of it.
        let session = sessions.remove(id);
        drop(sessions);
        drop(session);
        removed
    }

    /// The IDs of the registered sessions, in no particular order.
    pub fn session_ids(&self) -> Vec<String> {
        // SAFETY: plain call; the result is ours to free.
        let json = unsafe { ffi::take_string(sys::httpcloak_local_proxy_list_sessions(self.handle)) };
        json.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default()
    }

    pub fn has_session(&self, id: &str) -> bool {
        let Ok(c_id) = cstring(id, "the session ID") else { return false };
        // SAFETY: plain call with our handle and a valid NUL-terminated string.
        unsafe { sys::httpcloak_local_proxy_has_session(self.handle, c_id.as_ptr()) == 1 }
    }
}

impl Drop for LocalProxy {
    fn drop(&mut self) {
        // SAFETY: our handle, stopped once, here. In-flight requests are
        // cancelled; the call waits up to 10 seconds for them to end.
        unsafe { sys::httpcloak_local_proxy_stop(self.handle) }
        // Only now let the registered sessions go.
        self.sessions.get_mut().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

impl fmt::Debug for LocalProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalProxy").field("port", &self.port).finish_non_exhaustive()
    }
}
