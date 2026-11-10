use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::sync::Arc;

use http::StatusCode;

use crate::ffi::ErrorObject;

/// A `Result` whose error is [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong in this crate.
///
/// The library reports what a failure's types say about it beside its
/// message: the [`kind`](Error::kind) where they tell it, whether the request
/// [was never sent](Error::is_not_sent), and the status a proxy refused it
/// with. Where they don't tell the kind, and from a library built before it
/// said any of this, the kind is worked out from the message. The message
/// itself is always kept, unchanged, as the error's `Display`.
///
/// Cloning is cheap: clones share one error.
#[derive(Clone)]
pub struct Error {
    inner: Arc<Inner>,
}

#[derive(Clone)]
struct Inner {
    kind: ErrorKind,
    /// The kind was read from a message the library worded, so it is read
    /// again knowing the request's host names.
    kind_from_message: bool,
    message: String,
    url: Option<String>,
    status: Option<StatusCode>,
    proxy_status: Option<StatusCode>,
    not_sent: bool,
    source: Option<Arc<dyn StdError + Send + Sync>>,
}

/// What kind of failure an [`Error`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An argument or option the library cannot use: a string with a NUL in
    /// it, an invalid header, an unknown preset, an out-of-range setting.
    /// Nothing was sent.
    InvalidInput,
    /// The request, or the connection for it, ran out of time.
    Timeout,
    /// The connection could not be made or broke: refused, reset, unreachable.
    Connect,
    /// The host name could not be resolved.
    Dns,
    /// The TLS handshake failed, including certificate verification.
    Tls,
    /// The proxy could not be reached or refused the request.
    Proxy,
    /// Too many redirects, or a redirect that could not be followed.
    Redirect,
    /// [`Response::error_for_status`](crate::Response::error_for_status) found
    /// a 4xx or 5xx status.
    Status,
    /// What the library returned could not be decoded, or a body was not in
    /// the encoding asked for.
    Decode,
    /// A body arrived incomplete, or reading a streamed body or writing an
    /// upload failed.
    Io,
    /// Any other failure the library reported.
    Other,
}

impl ErrorKind {
    /// The kind the library's code for it names (`ErrorResponse.Code` in
    /// clib/httpcloak.go); `None` for one this crate doesn't know, from a
    /// newer library.
    fn of_code(code: &str) -> Option<ErrorKind> {
        Some(match code {
            "timeout" => ErrorKind::Timeout,
            "proxy" => ErrorKind::Proxy,
            "dns" => ErrorKind::Dns,
            "tls" => ErrorKind::Tls,
            "connect" => ErrorKind::Connect,
            "redirect" => ErrorKind::Redirect,
            "io" => ErrorKind::Io,
            "decode" => ErrorKind::Decode,
            _ => return None,
        })
    }
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Error {
            inner: Arc::new(Inner {
                kind,
                kind_from_message: false,
                message: message.into(),
                url: None,
                status: None,
                proxy_status: None,
                not_sent: false,
                source: None,
            }),
        }
    }

    fn inner_mut(&mut self) -> &mut Inner {
        Arc::make_mut(&mut self.inner)
    }

    /// An error the library reported as a bare message, classified by its
    /// text.
    pub(crate) fn from_library(message: impl Into<String>) -> Self {
        let message = message.into();
        let mut e = Error::new(classify(&message, &[]), message);
        e.inner_mut().kind_from_message = true;
        e
    }

    /// An error the library reported as an error object: its kind from the
    /// object's code, or from its message when it has none this crate knows.
    pub(crate) fn from_library_object(object: ErrorObject) -> Self {
        let mut e = match object.code.as_deref().and_then(ErrorKind::of_code) {
            Some(kind) => Error::new(kind, object.error),
            None => Error::from_library(object.error),
        };
        let inner = e.inner_mut();
        inner.not_sent = object.not_sent;
        inner.proxy_status = object.proxy_status.and_then(|s| StatusCode::from_u16(s).ok());
        e
    }

    /// Reclassifies a library error whose kind was read from its message,
    /// knowing the host names the request involved, so that none of them is
    /// mistaken for the cause.
    pub(crate) fn with_hosts(mut self, hosts: &[String]) -> Self {
        if self.inner.kind_from_message {
            let kind = classify(&self.inner.message, hosts);
            self.inner_mut().kind = kind;
        }
        self
    }

    /// Marks an error raised before the request was handed to the library:
    /// nothing of it was sent.
    pub(crate) fn unsent(mut self) -> Self {
        self.inner_mut().not_sent = true;
        self
    }

    pub(crate) fn invalid_input(message: impl Into<String>) -> Self {
        Error::new(ErrorKind::InvalidInput, message)
    }

    pub(crate) fn decode(message: impl Into<String>) -> Self {
        Error::new(ErrorKind::Decode, message)
    }

    pub(crate) fn timeout(message: impl Into<String>) -> Self {
        Error::new(ErrorKind::Timeout, message)
    }

    pub(crate) fn from_status(status: StatusCode, url: &str) -> Self {
        let reason = status.canonical_reason().map(|r| format!(" {r}")).unwrap_or_default();
        let mut e = Error::new(ErrorKind::Status, format!("HTTP {}{reason} for {url}", status.as_u16()));
        e.inner_mut().status = Some(status);
        e.with_url(url)
    }

    pub(crate) fn with_url(mut self, url: impl Into<String>) -> Self {
        self.inner_mut().url = Some(url.into());
        self
    }

    pub(crate) fn with_source(mut self, source: impl StdError + Send + Sync + 'static) -> Self {
        self.inner_mut().source = Some(Arc::new(source));
        self
    }

    /// What kind of failure this is.
    pub fn kind(&self) -> ErrorKind {
        self.inner.kind
    }

    /// The URL of the request that failed, when the error came from one.
    pub fn url(&self) -> Option<&str> {
        self.inner.url.as_deref()
    }

    /// The status, for an error from
    /// [`Response::error_for_status`](crate::Response::error_for_status).
    pub fn status(&self) -> Option<StatusCode> {
        self.inner.status
    }

    /// The status an HTTP proxy refused to open the request's tunnel with:
    /// `407 Proxy Authentication Required` when it wants credentials or
    /// refused the ones it was given. The kind is then
    /// [`Proxy`](ErrorKind::Proxy).
    pub fn proxy_status(&self) -> Option<StatusCode> {
        self.inner.proxy_status
    }

    /// Whether the request is known never to have reached the server, so the
    /// server cannot have acted on it: no attempt at it (on any protocol,
    /// retry or redirect hop) had a connection to send it on, a proxy refused
    /// to open the tunnel for it, or it was refused before it was handed to
    /// the library. Such a request may be sent again whatever it does.
    ///
    /// It is `false` whenever that is not known, which includes every failure
    /// once the request was written or may have been, and a timeout this crate
    /// enforced: a request it is `false` for may have reached the server and
    /// been acted on. A library built before it said so reports `false` for
    /// all its failures.
    pub fn is_not_sent(&self) -> bool {
        self.inner.not_sent
    }

    /// The message, as the library or this crate worded it.
    pub fn message(&self) -> &str {
        &self.inner.message
    }

    pub fn is_timeout(&self) -> bool {
        self.inner.kind == ErrorKind::Timeout
    }

    pub fn is_connect(&self) -> bool {
        self.inner.kind == ErrorKind::Connect
    }

    pub fn is_dns(&self) -> bool {
        self.inner.kind == ErrorKind::Dns
    }

    pub fn is_tls(&self) -> bool {
        self.inner.kind == ErrorKind::Tls
    }

    pub fn is_proxy(&self) -> bool {
        self.inner.kind == ErrorKind::Proxy
    }

    pub fn is_redirect(&self) -> bool {
        self.inner.kind == ErrorKind::Redirect
    }

    pub fn is_status(&self) -> bool {
        self.inner.kind == ErrorKind::Status
    }

    pub fn is_invalid_input(&self) -> bool {
        self.inner.kind == ErrorKind::InvalidInput
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Error");
        d.field("kind", &self.inner.kind).field("message", &self.inner.message);
        if let Some(url) = &self.inner.url {
            d.field("url", url);
        }
        if let Some(status) = &self.inner.status {
            d.field("status", status);
        }
        if let Some(status) = &self.inner.proxy_status {
            d.field("proxy_status", status);
        }
        if self.inner.not_sent {
            d.field("not_sent", &true);
        }
        if let Some(source) = &self.inner.source {
            d.field("source", source);
        }
        d.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner.message)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.inner.source.as_deref().map(|s| s as &(dyn StdError + 'static))
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::new(io_kind(&e), e)
    }
}

/// The closest [`io::ErrorKind`] to an error.
pub(crate) fn io_kind(e: &Error) -> io::ErrorKind {
    let has = |phrase: &str| contains_word(&e.message().to_ascii_lowercase(), phrase);
    match e.kind() {
        ErrorKind::Timeout => io::ErrorKind::TimedOut,
        ErrorKind::InvalidInput => io::ErrorKind::InvalidInput,
        ErrorKind::Decode => io::ErrorKind::InvalidData,
        // Or as Windows words them (WSAECONNREFUSED, WSAECONNRESET).
        ErrorKind::Connect if has("connection refused") || has("actively refused") => io::ErrorKind::ConnectionRefused,
        ErrorKind::Connect if has("connection reset") || has("forcibly closed") => io::ErrorKind::ConnectionReset,
        ErrorKind::Connect if has("broken pipe") => io::ErrorKind::BrokenPipe,
        ErrorKind::Connect if has("eof") => io::ErrorKind::UnexpectedEof,
        ErrorKind::Connect => io::ErrorKind::ConnectionAborted,
        _ => io::ErrorKind::Other,
    }
}

/// Classifies an error message from the library, for a failure it gave no
/// code for, or a library that sends none.
///
/// Its messages are Go errors, usually wrapped by the transport as `op host [proto]: cause`,
/// where op is `dns_resolve`, `dial`, `dial_proxy`, `tls_handshake`,
/// `roundtrip` and so on, and the cause is whatever Go or the TLS stack said.
///
/// The text carries host names, which can be any of the words looked for here:
/// `tls.example.com`, or a single-label `proxy` or `timeout` on a private
/// network. So the host in the transport's prefix is set aside, `hosts` (the
/// ones the request named) are blanked wherever they appear as a host, and
/// what is left only counts as a word where it does not touch a character a
/// host name could continue with. Timeouts are checked first: a TLS handshake
/// that ran out of time is a timeout.
pub(crate) fn classify(message: &str, hosts: &[String]) -> ErrorKind {
    let lowered = message.to_ascii_lowercase();
    let op = transport_op(&lowered).map(|(op, _)| op.to_string());
    let m = scrub_hosts(&lowered, hosts);
    let has = |phrase: &str| contains_word(&m, phrase);
    let any = |phrases: &[&str]| phrases.iter().any(|p| has(p));

    if any(&["unknown preset", "invalid protocol", "invalid proxy url", "unsupported protocol scheme"]) {
        return ErrorKind::InvalidInput;
    }
    if any(&["context deadline exceeded", "deadline exceeded", "i/o timeout", "timeout", "timed out"]) {
        return ErrorKind::Timeout;
    }
    if has("too many redirects") || (has("redirect") && any(&["cannot follow", "no location"])) {
        return ErrorKind::Redirect;
    }

    // The transport's own operation names are the most reliable signal.
    match op.as_deref() {
        Some("dial_proxy") => return ErrorKind::Proxy,
        Some("dns_resolve") => return ErrorKind::Dns,
        Some("tls_handshake") => return ErrorKind::Tls,
        // The response had begun: its body broke off or would not decode.
        Some("read_body") => return ErrorKind::Io,
        Some("decompress") => return ErrorKind::Decode,
        _ => {}
    }

    if any(&["proxy", "socks", "socks5", "masque"]) {
        return ErrorKind::Proxy;
    }
    if any(&["no such host", "dns resolution failed", "dns error", "server misbehaving"]) {
        return ErrorKind::Dns;
    }
    if any(&["x509", "certificate", "tls", "handshake", "remote error", "crypto_error", "ech"]) {
        return ErrorKind::Tls;
    }
    if any(&[
        "connection refused",
        "connection reset",
        "connection reset by peer",
        "broken pipe",
        "no route to host",
        "network is unreachable",
        "host is unreachable",
        "tcp connect failed",
        "connection error",
        "dial",
        "eof",
        // Windows' wording of refused, reset, aborted (its broken pipe) and unreachable.
        "actively refused",
        // (Its messages end in a full stop, which a host name could go on
        // with, so the phrases stop short of their last word.)
        "forcibly closed by the remote",
        "established connection was aborted",
        "attempted to an unreachable",
    ]) || op.as_deref() == Some("dial")
    {
        return ErrorKind::Connect;
    }
    ErrorKind::Other
}

/// The message with the transport prefix's host, and every one of `hosts`
/// where it stands as a host, replaced by `<host>`. A host stands as one
/// before a port (`proxy:1080`), after `lookup `, `//` or `not ` (Go's DNS,
/// URL and x509 wording), or in quotes; elsewhere the same word is left, since
/// it may be the cause (`tls: handshake failure`).
fn scrub_hosts(m: &str, hosts: &[String]) -> String {
    let mut out = match transport_op(m) {
        Some((op, rest)) => format!("{op} <host> {rest}"),
        None => m.to_string(),
    };
    let mut names: Vec<String> = hosts.iter().map(|h| h.to_ascii_lowercase()).filter(|h| !h.is_empty()).collect();
    if let Some(prefix_host) = transport_host(m) {
        names.push(prefix_host);
    }
    for name in names {
        let mut scrubbed = String::with_capacity(out.len());
        let mut rest = out.as_str();
        while let Some(i) = find_word(rest, &name) {
            let (before, after) = (&rest[..i], &rest[i + name.len()..]);
            let as_host = after.starts_with('"')
                || after.strip_prefix(':').is_some_and(|a| a.starts_with(|c: char| c.is_ascii_digit()))
                || after.starts_with(" [h")
                || ["lookup ", "//", "not ", "\""].iter().any(|p| before.ends_with(p));
            scrubbed.push_str(before);
            scrubbed.push_str(if as_host { "<host>" } else { &name });
            rest = after;
        }
        scrubbed.push_str(rest);
        out = scrubbed;
    }
    out
}

/// The first place `word` occurs in `text` as a whole word, by the same rule
/// as [`contains_word`].
fn find_word(text: &str, word: &str) -> Option<usize> {
    let continues = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    text.match_indices(word)
        .find(|(i, _)| !continues(text[..*i].chars().next_back()) && !continues(text[i + word.len()..].chars().next()))
        .map(|(i, _)| i)
}

/// The op of a transport error and what follows its host:
/// `("dial", "[h1]: ...")` for `dial 127.0.0.1:1 [h1]: ...`.
fn transport_op(m: &str) -> Option<(&str, &str)> {
    let (op, rest) = m.split_once(' ')?;
    let (_host, rest) = rest.split_once(' ')?;
    let is_op = !op.is_empty() && op.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    (is_op && rest.starts_with("[h") && rest.contains("]:")).then_some((op, rest))
}

/// The host of a transport error, without its port.
fn transport_host(m: &str) -> Option<String> {
    transport_op(m)?;
    let host = m.split(' ').nth(1)?;
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(v6),
        None => host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map_or(host, |(h, _)| h),
    };
    Some(host.to_string())
}

/// Whether `phrase` occurs in `text` without touching a character a host name
/// or another word could continue with on either side.
fn contains_word(text: &str, phrase: &str) -> bool {
    let continues = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    text.match_indices(phrase)
        .any(|(i, _)| !continues(text[..i].chars().next_back()) && !continues(text[i + phrase.len()..].chars().next()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_library_messages() {
        let cases = [
            ("dial 127.0.0.1:1 [h1]: dial tcp4 127.0.0.1:1: connect: connection refused", ErrorKind::Connect),
            ("roundtrip 127.0.0.1:44329 [h1]: context deadline exceeded", ErrorKind::Timeout),
            ("tls_handshake example.com [h2]: context deadline exceeded", ErrorKind::Timeout),
            ("dns_resolve nope.invalid [h2]: lookup nope.invalid: no such host", ErrorKind::Dns),
            ("DNS resolution failed: lookup x.invalid: no such host", ErrorKind::Dns),
            ("tls_handshake self-signed.badssl.com [h2]: tls: failed to verify certificate: x509: certificate signed by unknown authority", ErrorKind::Tls),
            ("TLS handshake failed: remote error: tls: handshake failure", ErrorKind::Tls),
            ("httpcloak/transport: too many redirects (max 3)", ErrorKind::Redirect),
            ("dial_proxy 127.0.0.1:9 [h1]: dial tcp 127.0.0.1:9: connect: connection refused", ErrorKind::Proxy),
            ("proxy CONNECT failed with status 407: Proxy Authentication Required", ErrorKind::Proxy),
            ("HTTP/3 requires a SOCKS5 or MASQUE proxy (current proxy does not support UDP)", ErrorKind::Proxy),
            ("unknown preset \"nope\". Try \"chrome-latest\"", ErrorKind::InvalidInput),
            ("roundtrip 127.0.0.1:1 [h1]: unexpected EOF", ErrorKind::Connect),
            ("read_body 127.0.0.1:1 [h1]: unexpected EOF: the body ended after 13 of the 1000 bytes", ErrorKind::Io),
            ("read_body x.com [h2]: context deadline exceeded", ErrorKind::Timeout),
            ("decompress x.com [h2]: gzip: invalid header", ErrorKind::Decode),
            ("something else entirely", ErrorKind::Other),
            // Windows' wording, as Go reports the WSA errors.
            ("dial 127.0.0.1:1 [h1]: dial tcp4 127.0.0.1:1: connectex: No connection could be made because the target machine actively refused it.", ErrorKind::Connect),
            ("the upload failed: request 127.0.0.1:53499 [h1]: write tcp4 127.0.0.1:53514->127.0.0.1:53499: wsasend: An established connection was aborted by the software in your host machine.", ErrorKind::Connect),
            ("roundtrip 127.0.0.1:1 [h1]: read tcp4 127.0.0.1:2->127.0.0.1:1: wsarecv: An existing connection was forcibly closed by the remote host.", ErrorKind::Connect),
            ("dial 10.9.9.9:80 [h1]: dial tcp4 10.9.9.9:80: connectex: A socket operation was attempted to an unreachable network.", ErrorKind::Connect),
            // Host names that spell the words looked for must not decide it.
            ("dial tls.peet.ws [h2]: dial tcp 1.2.3.4:443: connect: connection refused", ErrorKind::Connect),
            ("dial proxy-1.example.net [h1]: connect: connection refused", ErrorKind::Connect),
            ("roundtrip timeout.example.com [h2]: stream reset", ErrorKind::Other),
            ("dns_resolve certificate.example [h2]: lookup certificate.example: no such host", ErrorKind::Dns),
        ];
        for (message, kind) in cases {
            assert_eq!(classify(message, &[]), kind, "{message}");
        }
    }

    #[test]
    fn windows_socket_errors_map_as_std_maps_their_codes() {
        let io = |message: &str| io_kind(&Error::new(classify(message, &[]), message));
        assert_eq!(
            io("connectex: No connection could be made because the target machine actively refused it."),
            io::ErrorKind::ConnectionRefused
        );
        assert_eq!(
            io("wsarecv: An existing connection was forcibly closed by the remote host."),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            io("wsasend: An established connection was aborted by the software in your host machine."),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[test]
    fn single_label_host_names_never_decide_the_kind() {
        let refused = |host: &str| format!("dial {host}:1 [h1]: dial tcp4 127.0.0.1:1: connect: connection refused");
        for host in ["timeout", "tls", "proxy", "socks", "eof", "dial", "x509", "certificate", "redirect", "ech"] {
            assert_eq!(classify(&refused(host), &[]), ErrorKind::Connect, "{host}");
            let hosts = [host.to_string()];
            // Unprefixed messages, where only the caller knows the host.
            let dns = format!("DNS resolution failed: lookup {host}: no such host");
            assert_eq!(classify(&dns, &hosts), ErrorKind::Dns, "{host}");
            let url = format!("Get \"http://{host}:1/\": dial tcp 127.0.0.1:1: connect: connection refused");
            assert_eq!(classify(&url, &hosts), ErrorKind::Connect, "{host}");
            let lookup = format!("dns_resolve {host} [h2]: lookup {host} on 127.0.0.53:53: no such host");
            assert_eq!(classify(&lookup, &hosts), ErrorKind::Dns, "{host}");
        }
        // The genuine causes still count when the host spells them too.
        let tls =
            "tls_handshake tls [h2]: tls: failed to verify certificate: x509: certificate is valid for a, not tls";
        assert_eq!(classify(tls, &["tls".into()]), ErrorKind::Tls);
        let slow = "roundtrip timeout:8080 [h1]: context deadline exceeded";
        assert_eq!(classify(slow, &["timeout".into()]), ErrorKind::Timeout);
        let via = "dial_proxy proxy:3128 [h1]: dial tcp 10.0.0.1:3128: connect: connection refused";
        assert_eq!(classify(via, &["proxy".into()]), ErrorKind::Proxy);
        assert_eq!(transport_host("dial [::1]:443 [h1]: x").as_deref(), Some("::1"));
        assert_eq!(transport_host("dial example.com [h2]: x").as_deref(), Some("example.com"));
    }

    #[test]
    fn status_errors_carry_the_status_and_url() {
        let e = Error::from_status(StatusCode::NOT_FOUND, "https://example.com/x");
        assert!(e.is_status());
        assert_eq!(e.status(), Some(StatusCode::NOT_FOUND));
        assert_eq!(e.url(), Some("https://example.com/x"));
        assert_eq!(e.to_string(), "HTTP 404 Not Found for https://example.com/x");
    }

    #[test]
    fn error_is_send_sync_clone_and_small() {
        fn assert_send_sync_clone<T: Send + Sync + Clone + 'static>() {}
        assert_send_sync_clone::<Error>();
        assert_eq!(std::mem::size_of::<Error>(), std::mem::size_of::<usize>());
    }

    fn object(json: &str) -> Error {
        Error::from_library_object(serde_json::from_str(json).unwrap())
    }

    /// The library's code decides the kind, whatever the message says, and
    /// the message is not read again knowing the hosts; without a code, or
    /// with one this crate doesn't know, the message decides.
    #[test]
    fn the_librarys_code_decides_the_kind() {
        let e = object(r#"{"error":"roundtrip proxy.example [h2]: something new","code":"timeout"}"#);
        assert_eq!(e.kind(), ErrorKind::Timeout);
        assert_eq!(e.with_hosts(&["proxy.example".into()]).kind(), ErrorKind::Timeout);
        let read = object(r#"{"error":"dial 127.0.0.1:1 [h1]: dial tcp4 127.0.0.1:1: connect: connection refused"}"#);
        assert_eq!(read.kind(), ErrorKind::Connect);
        let unknown = object(r#"{"error":"tls_handshake x [h2]: remote error","code":"from-a-newer-library"}"#);
        assert_eq!(unknown.kind(), ErrorKind::Tls);
        for (code, kind) in [
            ("timeout", ErrorKind::Timeout),
            ("proxy", ErrorKind::Proxy),
            ("dns", ErrorKind::Dns),
            ("tls", ErrorKind::Tls),
            ("connect", ErrorKind::Connect),
            ("redirect", ErrorKind::Redirect),
            ("io", ErrorKind::Io),
            ("decode", ErrorKind::Decode),
        ] {
            assert_eq!(object(&format!(r#"{{"error":"x","code":"{code}"}}"#)).kind(), kind, "{code}");
        }
    }

    /// Only the library's word makes a failure not sent, and a clone says
    /// what the original does.
    #[test]
    fn not_sent_and_the_proxy_status_are_the_librarys_word() {
        let e = object(
            r#"{"error":"proxy CONNECT failed with status 407: 407 Proxy Authentication Required","code":"proxy","not_sent":true,"proxy_status":407}"#,
        );
        assert!(e.is_not_sent() && e.is_proxy());
        assert_eq!(e.proxy_status(), Some(StatusCode::PROXY_AUTHENTICATION_REQUIRED));
        let clone = e.clone().with_url("https://x.test/");
        assert!(clone.is_not_sent() && clone.proxy_status().is_some() && e.url().is_none());
        assert!(format!("{e:?}").contains("not_sent"));
        let sent = object(r#"{"error":"roundtrip x [h2]: stream error","code":"connect"}"#);
        assert!(!sent.is_not_sent() && sent.proxy_status().is_none());
        assert!(!Error::from_library("dial x [h1]: connection refused").is_not_sent());
        assert!(!Error::timeout("the request timed out after 1s").is_not_sent());
    }
}
