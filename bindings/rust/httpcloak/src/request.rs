use std::collections::hash_map::RandomState;
use std::ffi::{c_char, CString};
use std::fmt;
use std::future::Future;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use http::Method;
use httpcloak_sys as sys;
use serde::{Serialize, Serializer};

use crate::call::{Call, Deadline, Leftover};
use crate::error::{Error, ErrorKind, Result};
use crate::headers::{normalize_value, valid_name, valid_value};
use crate::response::Response;
use crate::session::{ceil_secs, Session, MAX_LIBRARY_SECS};
use crate::stream::StreamResponse;

/// How the request is meant to be used, which `Sec-Fetch-Mode` (and a
/// matching `Sec-Fetch-Dest`) it carries. Left unset, the library works it out
/// from the request, as a browser does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FetchMode {
    /// A page load: `navigate`, with `Sec-Fetch-Dest: document`.
    Navigate,
    /// A `fetch()` or XHR call: `cors`, with `Sec-Fetch-Dest: empty`.
    Cors,
    /// A subresource like an image or script: `no-cors`.
    NoCors,
    /// A WebSocket handshake: `websocket`, with `Sec-Fetch-Dest: empty`.
    WebSocket,
}

impl FetchMode {
    fn as_str(self) -> &'static str {
        match self {
            FetchMode::Navigate => "navigate",
            FetchMode::Cors => "cors",
            FetchMode::NoCors => "no-cors",
            FetchMode::WebSocket => "websocket",
        }
    }
}

/// A request being put together, sent with [`send`](RequestBuilder::send) or
/// one of its variants.
///
/// Headers set here are added to the preset's, replacing a preset header of
/// the same name; the library puts them all in the browser's order. A problem
/// with any argument is reported when the request is sent.
#[derive(Clone)]
#[must_use = "a request does nothing until it is sent"]
pub struct RequestBuilder {
    session: Session,
    method: Method,
    url: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    exact_headers: Option<Vec<(String, String)>>,
    header_order: Vec<String>,
    cookies: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    /// The Content-Type a body helper implies, used unless one is set.
    implied_content_type: Option<String>,
    timeout: Option<Duration>,
    fetch_mode: Option<FetchMode>,
    follow_redirects: Option<bool>,
    disable_conditional_cache: bool,
    disable_client_hints: bool,
    disable_high_entropy_client_hints: bool,
    disable_redirect_referer: bool,
    error: Option<(ErrorKind, String)>,
}

impl fmt::Debug for RequestBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestBuilder")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body_len", &self.body.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

impl RequestBuilder {
    pub(crate) fn new(session: Session, method: Method, url: String) -> RequestBuilder {
        RequestBuilder {
            session,
            method,
            url,
            query: Vec::new(),
            headers: Vec::new(),
            exact_headers: None,
            header_order: Vec::new(),
            cookies: Vec::new(),
            body: None,
            implied_content_type: None,
            timeout: None,
            fetch_mode: None,
            follow_redirects: None,
            disable_conditional_cache: false,
            disable_client_hints: false,
            disable_high_entropy_client_hints: false,
            disable_redirect_referer: false,
            error: None,
        }
    }

    fn fail(&mut self, kind: ErrorKind, message: impl Into<String>) {
        self.error.get_or_insert((kind, message.into()));
    }

    /// Sets header `name`, replacing any value set before under any spelling
    /// of the name. Spaces and tabs around the value are dropped, as a
    /// browser drops them. A value that is empty after that sends no `name`
    /// at all, which is how to leave off a header the preset adds (Chrome
    /// sends no `Priority` with an async script, say). To send a name more
    /// than once, or headers exactly as given, use
    /// [`exact_headers`](RequestBuilder::exact_headers).
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let (name, value) = (name.into(), normalize_value(value.into()));
        if !valid_name(&name) {
            self.fail(ErrorKind::InvalidInput, format!("{name:?} is not a valid header name"));
        } else if !valid_value(&value) {
            self.fail(ErrorKind::InvalidInput, format!("the value of header {name:?} has a control character in it"));
        }
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&name));
        self.headers.push((name, value));
        self
    }

    /// Sets several headers, as [`header`](RequestBuilder::header) does.
    pub fn headers<I, K, V>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in headers {
            self = self.header(k, v);
        }
        self
    }

    /// Replaces the whole header pipeline: these headers go out exactly as
    /// given, in this order and casing, values untrimmed, a name may repeat,
    /// and nothing is
    /// added: no preset headers, no client hints, no `Content-Type` from a
    /// body helper. For reproducing a captured request.
    ///
    /// Only the protocol's framing is still written for you: `Host` on
    /// HTTP/1.1 and the pseudo-headers on HTTP/2 and HTTP/3. Cannot be
    /// combined with [`header`](RequestBuilder::header),
    /// [`cookie`](RequestBuilder::cookie) or the auth helpers.
    pub fn exact_headers<I, K, V>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut list = Vec::new();
        for (k, v) in headers {
            let (k, v) = (k.into(), v.into());
            if !valid_name(&k) {
                self.fail(ErrorKind::InvalidInput, format!("{k:?} is not a valid header name"));
            } else if !valid_value(&v) {
                self.fail(ErrorKind::InvalidInput, format!("the value of header {k:?} has a control character in it"));
            }
            list.push((k, v));
        }
        if list.is_empty() {
            // The library reads an empty list as "not set" and would send the
            // preset's headers.
            self.fail(ErrorKind::InvalidInput, "exact_headers needs at least one header");
        }
        self.exact_headers = Some(list);
        self
    }

    /// Sends the named headers first, in this order, for this request only;
    /// the rest keep the preset's order.
    pub fn header_order<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for name in names {
            let name = name.into();
            if !valid_name(&name) {
                self.fail(ErrorKind::InvalidInput, format!("{name:?} is not a valid header name"));
            }
            self.header_order.push(name);
        }
        self
    }

    /// Adds a cookie to this request only, on top of the session's jar.
    pub fn cookie(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let (name, value) = (name.into(), value.into());
        if let Err(e) = crate::cookie::validate_pair(&name, &value) {
            self.fail(ErrorKind::InvalidInput, e.message());
        }
        self.cookies.push((name, value));
        self
    }

    /// Sets `Authorization` to HTTP Basic credentials.
    pub fn basic_auth(self, username: impl fmt::Display, password: Option<impl fmt::Display>) -> Self {
        let credentials = match password {
            Some(p) => format!("{username}:{p}"),
            None => format!("{username}:"),
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
        self.header("Authorization", format!("Basic {encoded}"))
    }

    /// Sets `Authorization` to a bearer token.
    pub fn bearer_auth(self, token: impl fmt::Display) -> Self {
        self.header("Authorization", format!("Bearer {token}"))
    }

    /// Appends query parameters to the URL, form-encoded.
    pub fn query<K: AsRef<str>, V: AsRef<str>>(mut self, pairs: &[(K, V)]) -> Self {
        self.query.extend(pairs.iter().map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string())));
        self
    }

    /// Sets the body. Sets no `Content-Type`.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self.implied_content_type = None;
        self
    }

    /// Sets the body to `value` as JSON, with `Content-Type: application/json`
    /// unless one is set.
    pub fn json<T: Serialize + ?Sized>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => {
                self.body = Some(body);
                self.implied_content_type = Some("application/json".into());
            }
            Err(e) => self.fail(ErrorKind::InvalidInput, format!("the JSON body could not be serialized: {e}")),
        }
        self
    }

    /// Sets the body to a URL-encoded form, with `Content-Type:
    /// application/x-www-form-urlencoded` unless one is set.
    pub fn form<K: AsRef<str>, V: AsRef<str>>(mut self, fields: &[(K, V)]) -> Self {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().map(|(k, v)| (k.as_ref(), v.as_ref())))
            .finish();
        self.body = Some(body.into_bytes());
        self.implied_content_type = Some("application/x-www-form-urlencoded".into());
        self
    }

    /// Sets the body to a `multipart/form-data` form, with its `Content-Type`
    /// unless one is set.
    pub fn multipart(mut self, form: Form) -> Self {
        match form.encode() {
            Ok((content_type, body)) => {
                self.body = Some(body);
                self.implied_content_type = Some(content_type);
            }
            Err(e) => self.fail(ErrorKind::InvalidInput, e.message()),
        }
        self
    }

    /// Limits the time this request may take, redirects and retries included,
    /// in place of the session's timeout, whether shorter or longer.
    ///
    /// For a [streamed](RequestBuilder::send_stream) request it bounds the
    /// whole exchange, body included. A streamed request without one may read
    /// its body for as long as it likes; only the connection and the response
    /// headers are bounded, by the session's timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        if timeout.is_zero() {
            self.fail(ErrorKind::InvalidInput, "the request timeout must be greater than zero");
        }
        self.timeout = Some(timeout);
        self
    }

    /// Forces `Sec-Fetch-Mode`, instead of letting the library work it out.
    pub fn fetch_mode(mut self, mode: FetchMode) -> Self {
        self.fetch_mode = Some(mode);
        self
    }

    /// Whether to follow redirects for this request, overriding the session.
    /// Streamed requests never follow redirects.
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = Some(follow);
        self
    }

    /// Sends no `If-None-Match` / `If-Modified-Since` for this request, and
    /// keeps its response out of the session's cache.
    pub fn disable_conditional_cache(mut self) -> Self {
        self.disable_conditional_cache = true;
        self
    }

    /// Sends no `Sec-CH-UA` client hints with this request.
    pub fn disable_client_hints(mut self) -> Self {
        self.disable_client_hints = true;
        self
    }

    /// Sends the low-entropy client hints but no high-entropy ones.
    pub fn disable_high_entropy_client_hints(mut self) -> Self {
        self.disable_high_entropy_client_hints = true;
        self
    }

    /// Adds no `Referer` on redirect hops, and drops the request's own there.
    pub fn disable_redirect_referer(mut self) -> Self {
        self.disable_redirect_referer = true;
        self
    }

    /// Sends the request and blocks until the whole response has been read.
    pub fn send(self) -> Result<Response> {
        let method = self.method.clone();
        let request = self.prepare(false)?;
        let url = request.url.clone();
        let call = request.start(Leftover::Discard, sys::httpcloak_request_async)?;
        let completed = call.wait(request.deadline).map_err(|e| request.explain(e))?;
        Response::from_json(&completed.json, completed.elapsed).map_err(|e| e.with_url(url))?.check_complete(&method)
    }

    /// Sends the request; the future resolves once the whole response has been
    /// read. It works on any executor, and does nothing until first polled.
    /// Dropping it before it resolves cancels the request.
    // Not an async fn, so that the future being Send and 'static is part of
    // the signature rather than inferred from the body.
    #[allow(clippy::manual_async_fn)]
    pub fn send_async(self) -> impl Future<Output = Result<Response>> + Send + 'static {
        async move {
            let method = self.method.clone();
            let request = self.prepare(false)?;
            let url = request.url.clone();
            let call = request.start(Leftover::Discard, sys::httpcloak_request_async)?;
            let completed = call.into_future(request.deadline).await.map_err(|e| request.explain(e))?;
            Response::from_json(&completed.json, completed.elapsed)
                .map_err(|e| e.with_url(url))?
                .check_complete(&method)
        }
    }

    /// Sends the request and blocks until the response headers have arrived;
    /// the body is then read from the returned [`StreamResponse`]. Streamed
    /// requests do not follow redirects.
    pub fn send_stream(self) -> Result<StreamResponse> {
        let request = self.prepare(true)?;
        let url = request.url.clone();
        let call = request.start(Leftover::CloseStream, sys::httpcloak_stream_request_async)?;
        let completed = call.wait(request.deadline).map_err(|e| request.explain(e))?;
        StreamResponse::open(request.session, &completed.json, request.deadline).map_err(|e| e.with_url(url))
    }

    /// [`send_stream`](RequestBuilder::send_stream) as a future. Dropping it
    /// before it resolves cancels the request.
    #[allow(clippy::manual_async_fn)]
    pub fn send_stream_async(self) -> impl Future<Output = Result<StreamResponse>> + Send + 'static {
        async move {
            let request = self.prepare(true)?;
            let url = request.url.clone();
            let call = request.start(Leftover::CloseStream, sys::httpcloak_stream_request_async)?;
            let completed = call.into_future(request.deadline).await.map_err(|e| request.explain(e))?;
            StreamResponse::open(request.session, &completed.json, request.deadline).map_err(|e| e.with_url(url))
        }
    }

    /// Checks the request and encodes it as the library's request JSON.
    pub(crate) fn prepare(self, stream: bool) -> Result<Prepared> {
        if let Some((kind, message)) = self.error {
            return Err(Error::new(kind, message).with_url(self.url));
        }
        if self.url.is_empty() {
            return Err(Error::invalid_input("the URL is empty"));
        }
        if self.url.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(Error::invalid_input("the URL contains a control character").with_url(self.url));
        }
        check_scheme(&self.url)?;
        let url = with_query(&self.url, &self.query);

        let mut headers = self.headers;
        if self.exact_headers.is_some() && (!headers.is_empty() || !self.cookies.is_empty()) {
            return Err(Error::invalid_input(
                "exact_headers replaces every other header; put these headers, cookies or credentials in it",
            )
            .with_url(url));
        }
        if !self.cookies.is_empty() {
            let added = self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
            match headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case("cookie")) {
                Some((_, v)) if !v.is_empty() => *v = format!("{v}; {added}"),
                Some((_, v)) => *v = added,
                None => headers.push(("Cookie".into(), added)),
            }
        }
        if let Some(content_type) = self.implied_content_type {
            if self.exact_headers.is_none() && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                headers.push(("Content-Type".into(), content_type));
            }
        }

        // The library's own deadline is in whole seconds, rounded up, so the
        // exact one here always fires first. A stream without a timeout has
        // no overall limit rather than the library's 2 minute default; its
        // connection and headers are still bounded by the session's timeout.
        let library_timeout = self.timeout.map(|t| ceil_secs(t).clamp(1, MAX_LIBRARY_SECS));
        let unbounded_body = stream && self.timeout.is_none();
        let deadline = self.timeout.and_then(Deadline::after);

        let body = self.body.filter(|b| !b.is_empty()).map(|b| base64::engine::general_purpose::STANDARD.encode(b));
        let wire = WireRequest {
            method: self.method.as_str(),
            url: &url,
            headers: &headers,
            exact_headers: self
                .exact_headers
                .as_ref()
                .map(|h| h.iter().map(|(k, v)| [k.as_str(), v.as_str()]).collect()),
            header_order: &self.header_order,
            body_encoding: body.as_ref().map(|_| "base64"),
            body,
            timeout: library_timeout,
            unbounded_body,
            fetch_mode: self.fetch_mode.map(FetchMode::as_str),
            follow_redirects: self.follow_redirects,
            disable_conditional_cache: self.disable_conditional_cache,
            disable_client_hints: self.disable_client_hints,
            disable_high_entropy_client_hints: self.disable_high_entropy_client_hints,
            disable_redirect_referer: self.disable_redirect_referer,
        };
        let json = serde_json::to_string(&wire).expect("the request JSON always serializes");
        // JSON escapes every control character, so it never holds a NUL.
        let json =
            CString::new(json).map_err(|_| Error::new_other("the request JSON held a NUL byte").with_url(&url))?;
        Ok(Prepared { session: self.session, url, json, deadline })
    }
}

/// A checked request, ready for the library.
pub(crate) struct Prepared {
    session: Session,
    url: String,
    pub(crate) json: CString,
    deadline: Option<Deadline>,
}

impl Prepared {
    /// Attaches the URL to a failure, and reads its kind again knowing which
    /// host names the message may mention, so none is taken for the cause.
    fn explain(&self, e: Error) -> Error {
        e.with_hosts(&hosts_involved(&self.session, &self.url)).with_url(&self.url)
    }

    fn start(&self, leftover: Leftover, export: unsafe extern "C" fn(i64, *const c_char, i64)) -> Result<Call> {
        let handle = self.session.handle();
        Call::start(leftover, |id| {
            // SAFETY: the session is alive (we hold it), and the JSON is a
            // valid NUL-terminated string the export copies before it returns.
            unsafe { export(handle, self.json.as_ptr(), id) }
        })
    }
}

/// The library's request JSON (`RequestConfig` in clib/httpcloak.go).
#[derive(Serialize)]
struct WireRequest<'a> {
    method: &'a str,
    url: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty", serialize_with = "as_map")]
    headers: &'a [(String, String)],
    #[serde(skip_serializing_if = "Option::is_none")]
    exact_headers: Option<Vec<[&'a str; 2]>>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    header_order: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_encoding: Option<&'static str>,
    /// Seconds: the unit of the async and stream exports.
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,
    /// Streams only: no overall deadline when there is no timeout.
    #[serde(skip_serializing_if = "is_false")]
    unbounded_body: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    fetch_mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    follow_redirects: Option<bool>,
    #[serde(skip_serializing_if = "is_false")]
    disable_conditional_cache: bool,
    #[serde(skip_serializing_if = "is_false")]
    disable_client_hints: bool,
    #[serde(skip_serializing_if = "is_false")]
    disable_high_entropy_client_hints: bool,
    #[serde(skip_serializing_if = "is_false")]
    disable_redirect_referer: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn as_map<S: Serializer>(pairs: &&[(String, String)], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.collect_map(pairs.iter().map(|(k, v)| (k, v)))
}

/// Fails unless `url` is http or https, before anything is sent. The library
/// refuses other schemes too, but earlier builds sent them, ftps
/// included, as plain HTTP.
pub(crate) fn check_scheme(url: &str) -> Result<()> {
    let scheme = url.split_once("://").map(|(s, _)| s.to_ascii_lowercase());
    match scheme.as_deref() {
        Some("http" | "https") => Ok(()),
        Some(other) => {
            Err(Error::invalid_input(format!("unsupported URL scheme {other:?}; use http or https")).with_url(url))
        }
        None => {
            Err(Error::invalid_input("the URL has no scheme; it must start with http:// or https://").with_url(url))
        }
    }
}

/// The host names a request's failure can mention: its URL's, and its
/// session's proxies'.
pub(crate) fn hosts_involved(session: &Session, url: &str) -> Vec<String> {
    let proxies = [session.proxy(), session.tcp_proxy(), session.udp_proxy()];
    std::iter::once(url_host(url)).chain(proxies.iter().flatten().map(|p| url_host(p))).flatten().collect()
}

/// The host of a URL: no scheme, credentials, port, path or brackets.
pub(crate) fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match host_port.strip_prefix('[') {
        Some(v6) => v6.split(']').next()?,
        None => host_port.split(':').next()?,
    };
    (!host.is_empty()).then(|| host.to_string())
}

/// `url` with `query` appended, before any fragment.
fn with_query(url: &str, query: &[(String, String)]) -> String {
    if query.is_empty() {
        return url.to_string();
    }
    let encoded = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(query.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .finish();
    let (base, fragment) = match url.find('#') {
        Some(i) => url.split_at(i),
        None => (url, ""),
    };
    let separator = match base.find('?') {
        None => "?",
        Some(_) if base.ends_with('?') || base.ends_with('&') => "",
        Some(_) => "&",
    };
    format!("{base}{separator}{encoded}{fragment}")
}

/// A `multipart/form-data` body, encoded the way Chrome encodes a form.
///
/// ```
/// use httpcloak::multipart::{Form, Part};
///
/// let form = Form::new()
///     .text("title", "holiday")
///     .part("photo", Part::bytes(vec![0xff, 0xd8]).file_name("beach.jpg").mime("image/jpeg"));
/// ```
pub mod multipart {
    use super::*;

    /// The fields of a multipart form, sent in the order added.
    #[derive(Clone, Debug, Default)]
    pub struct Form {
        parts: Vec<(String, Part)>,
    }

    /// One field of a [`Form`]: text, or a file.
    #[derive(Clone, Debug)]
    pub struct Part {
        data: Vec<u8>,
        file_name: Option<String>,
        mime: Option<String>,
    }

    impl Form {
        pub fn new() -> Form {
            Form::default()
        }

        /// Adds a text field.
        pub fn text(self, name: impl Into<String>, value: impl Into<String>) -> Form {
            self.part(name, Part::text(value))
        }

        /// Adds a field.
        pub fn part(mut self, name: impl Into<String>, part: Part) -> Form {
            self.parts.push((name.into(), part));
            self
        }

        /// The `Content-Type` and the encoded body.
        pub(crate) fn encode(&self) -> Result<(String, Vec<u8>)> {
            let boundary = boundary();
            let mut out = Vec::new();
            for (name, part) in &self.parts {
                out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                let mut disposition = format!("Content-Disposition: form-data; name=\"{}\"", escape(name));
                if let Some(file_name) = &part.file_name {
                    disposition.push_str(&format!("; filename=\"{}\"", escape(file_name)));
                }
                out.extend_from_slice(disposition.as_bytes());
                out.extend_from_slice(b"\r\n");
                if part.file_name.is_some() || part.mime.is_some() {
                    let mime = part.mime.as_deref().unwrap_or("application/octet-stream");
                    if !valid_value(mime) {
                        return Err(Error::invalid_input(format!(
                            "the content type of field {name:?} has a control character in it"
                        )));
                    }
                    out.extend_from_slice(format!("Content-Type: {mime}\r\n").as_bytes());
                }
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(&part.data);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
            Ok((format!("multipart/form-data; boundary={boundary}"), out))
        }
    }

    impl Part {
        /// A text field's value.
        pub fn text(value: impl Into<String>) -> Part {
            Part { data: value.into().into_bytes(), file_name: None, mime: None }
        }

        /// Raw bytes, usually a file with a [name](Part::file_name).
        pub fn bytes(data: impl Into<Vec<u8>>) -> Part {
            Part { data: data.into(), file_name: None, mime: None }
        }

        /// Sends the part as a file with this name.
        pub fn file_name(mut self, name: impl Into<String>) -> Part {
            self.file_name = Some(name.into());
            self
        }

        /// The part's `Content-Type`; `application/octet-stream` for a file
        /// without one.
        pub fn mime(mut self, mime: impl Into<String>) -> Part {
            self.mime = Some(mime.into());
            self
        }
    }

    /// What Chrome does to a quote or line break inside a field or file name.
    fn escape(name: &str) -> String {
        name.replace('"', "%22").replace('\r', "%0D").replace('\n', "%0A")
    }

    /// Chrome's boundary: the literal prefix and 16 characters drawn through a
    /// 6-bit mask over Blink's 64-entry table (A-Z, a-z, 0-9, then A and B
    /// again), from blink/renderer/platform/network/form_data_encoder.cc.
    pub(crate) fn boundary() -> String {
        const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB";
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut bits: u128 = 0;
        for _ in 0..2 {
            // Each RandomState has fresh random keys; the counter and clock
            // keep two in the same instant apart anyway.
            let mut h = RandomState::new().build_hasher();
            h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
            h.write_u128(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_nanos());
            bits = (bits << 64) | u128::from(h.finish());
        }
        let mut out = String::from("----WebKitFormBoundary");
        for i in 0..16 {
            out.push(ALPHABET[((bits >> (i * 6)) & 0x3f) as usize] as char);
        }
        out
    }
}

pub use multipart::Form;

#[cfg(test)]
mod tests {
    use super::multipart::{Form, Part};
    use super::*;

    fn session() -> Session {
        // Encoding a request needs a session to hang it on, not a real one.
        // No session has handle -1, and freeing it is a no-op in the library.
        Session { inner: std::sync::Arc::new(crate::session::SessionInner { handle: -1 }) }
    }

    fn wire(b: RequestBuilder, stream: bool) -> serde_json::Value {
        serde_json::from_slice(b.prepare(stream).unwrap().json.as_bytes()).unwrap()
    }

    fn err(b: RequestBuilder) -> Error {
        b.prepare(false).err().expect("expected an error")
    }

    #[test]
    fn encodes_a_full_request() {
        let s = session();
        let v = wire(
            s.post("https://x.test/p?a=1#frag")
                .query(&[("q", "a b&c"), ("é", "1")])
                .header("X-One", "1")
                .header("x-one", "2")
                .cookie("c", "v")
                .bearer_auth("tok")
                .json(&serde_json::json!({"k": "v"}))
                .header_order(["x-one", "content-type"])
                .timeout(Duration::from_millis(1500))
                .fetch_mode(FetchMode::Cors)
                .follow_redirects(false)
                .disable_conditional_cache()
                .disable_client_hints()
                .disable_high_entropy_client_hints()
                .disable_redirect_referer(),
            false,
        );
        assert_eq!(
            v,
            serde_json::json!({
                "method": "POST",
                "url": "https://x.test/p?a=1&q=a+b%26c&%C3%A9=1#frag",
                "headers": {"x-one": "2", "Authorization": "Bearer tok", "Cookie": "c=v",
                            "Content-Type": "application/json"},
                "header_order": ["x-one", "content-type"],
                "body": "eyJrIjoidiJ9", "body_encoding": "base64",
                "timeout": 2, "fetch_mode": "cors", "follow_redirects": false,
                "disable_conditional_cache": true, "disable_client_hints": true,
                "disable_high_entropy_client_hints": true, "disable_redirect_referer": true
            })
        );
    }

    #[test]
    fn a_minimal_request_sends_only_method_and_url() {
        let s = session();
        assert_eq!(wire(s.get("http://x.test/"), false), serde_json::json!({"method": "GET", "url": "http://x.test/"}));
        // A stream with no timeout of its own gets an unbounded body read.
        assert_eq!(
            wire(s.get("http://x.test/"), true),
            serde_json::json!({"method": "GET", "url": "http://x.test/", "unbounded_body": true})
        );
        // With one, the library gets it, rounded up, for the body as well.
        assert_eq!(
            wire(s.get("http://x.test/").timeout(Duration::from_millis(100)), true),
            serde_json::json!({"method": "GET", "url": "http://x.test/", "timeout": 1})
        );
    }

    #[test]
    fn an_explicit_content_type_beats_the_implied_one() {
        let s = session();
        let v = wire(s.post("http://x/").header("content-type", "text/plain").json(&1), false);
        assert_eq!(v["headers"], serde_json::json!({"content-type": "text/plain"}));
        let v = wire(s.post("http://x/").form(&[("a", "1 2")]), false);
        assert_eq!(v["headers"]["Content-Type"], "application/x-www-form-urlencoded");
        assert_eq!(v["body"], base64::engine::general_purpose::STANDARD.encode("a=1+2"));
        // body() takes the implied type back off.
        let v = wire(s.post("http://x/").json(&1).body("raw"), false);
        assert!(v.get("headers").is_none());
    }

    #[test]
    fn header_values_are_trimmed_as_a_browser_trims_them() {
        let s = session();
        let v = wire(s.get("http://x/").header("A", " \tv w\t ").header("B", "\t"), false);
        assert_eq!(v["headers"], serde_json::json!({"A": "v w", "B": ""}));
        let v = wire(s.get("http://x/").exact_headers([("A", " v ")]), false);
        assert_eq!(v["exact_headers"], serde_json::json!([["A", " v "]]));
    }

    #[test]
    fn cookies_join_an_existing_cookie_header() {
        let s = session();
        let v = wire(s.get("http://x/").header("cookie", "a=1").cookie("b", "2").cookie("c", "3"), false);
        assert_eq!(v["headers"], serde_json::json!({"cookie": "a=1; b=2; c=3"}));
    }

    #[test]
    fn binary_bodies_survive_whole() {
        let s = session();
        let all: Vec<u8> = (0..=255).collect();
        let v = wire(s.put("http://x/").body(all.clone()), false);
        let decoded = base64::engine::general_purpose::STANDARD.decode(v["body"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, all);
        // An empty body sends none.
        assert!(wire(s.post("http://x/").body(Vec::new()), false).get("body").is_none());
    }

    #[test]
    fn exact_headers_go_through_as_given() {
        let s = session();
        let v = wire(
            s.get("http://x/")
                .exact_headers([("User-Agent", "a"), ("accept", "*/*"), ("X-Dup", "1"), ("X-Dup", "2")])
                .json(&1),
            false,
        );
        assert_eq!(
            v["exact_headers"],
            serde_json::json!([["User-Agent", "a"], ["accept", "*/*"], ["X-Dup", "1"], ["X-Dup", "2"]])
        );
        // A body helper's Content-Type is not added behind the caller's back.
        assert!(v.get("headers").is_none());
    }

    #[test]
    fn rejects_bad_input_before_sending() {
        let s = session();
        let cases = [
            s.get(""),
            s.get("http://x/\0"),
            s.get("ftp://x/"),
            s.get("x.test/path"),
            s.get("http://x/").header("bad name", "v"),
            s.get("http://x/").header("X", "a\r\nInjected: 1"),
            s.get("http://x/").header("X", "a\0"),
            s.get("http://x/").header("X", " a\r"),
            s.get("http://x/").exact_headers(Vec::<(String, String)>::new()),
            s.get("http://x/").exact_headers([("ok", "a\nb")]),
            s.get("http://x/").exact_headers([("A", "1")]).header("B", "2"),
            s.get("http://x/").exact_headers([("A", "1")]).cookie("c", "v"),
            s.get("http://x/").cookie("c", "v;x"),
            s.get("http://x/").header_order(["ok", "not ok"]),
            s.get("http://x/").timeout(Duration::ZERO),
            s.post("http://x/").multipart(Form::new().part("f", Part::bytes(vec![1]).mime("a\r\nb"))),
        ];
        for b in cases {
            let e = err(b);
            assert!(e.is_invalid_input(), "{e:?}");
        }
    }

    #[test]
    fn url_hosts() {
        assert_eq!(url_host("http://proxy:1/x").as_deref(), Some("proxy"));
        assert_eq!(url_host("socks5://u:p@tls:1080").as_deref(), Some("tls"));
        assert_eq!(url_host("https://[::1]:8443/").as_deref(), Some("::1"));
        assert_eq!(url_host("https://example.com?q#f").as_deref(), Some("example.com"));
        assert_eq!(url_host("http://"), None);
    }

    #[test]
    fn query_strings_keep_the_fragment_last() {
        let q = |url: &str| with_query(url, &[("k".into(), "v".into())]);
        assert_eq!(q("http://x/"), "http://x/?k=v");
        assert_eq!(q("http://x/?"), "http://x/?k=v");
        assert_eq!(q("http://x/?a=1&"), "http://x/?a=1&k=v");
        assert_eq!(q("http://x/?a=1"), "http://x/?a=1&k=v");
        assert_eq!(q("http://x/#f?g"), "http://x/?k=v#f?g");
        assert_eq!(with_query("http://x/", &[]), "http://x/");
    }

    #[test]
    fn multipart_matches_chrome() {
        let (content_type, body) = Form::new()
            .text("na\"me", "v1")
            .part("file", Part::bytes(vec![0, 1, 2]).file_name("a\r\n.bin"))
            .part("typed", Part::text("{}").mime("application/json"))
            .encode()
            .unwrap();
        let boundary = content_type.strip_prefix("multipart/form-data; boundary=").unwrap();
        assert!(boundary.starts_with("----WebKitFormBoundary") && boundary.len() == 38, "{boundary}");
        let expected = format!(
            "--{b}\r\nContent-Disposition: form-data; name=\"na%22me\"\r\n\r\nv1\r\n\
             --{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a%0D%0A.bin\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n\x00\x01\x02\r\n\
             --{b}\r\nContent-Disposition: form-data; name=\"typed\"\r\nContent-Type: application/json\r\n\r\n{{}}\r\n\
             --{b}--\r\n",
            b = boundary
        );
        assert_eq!(body, expected.as_bytes());
        assert_ne!(multipart::boundary(), multipart::boundary());
    }
}
