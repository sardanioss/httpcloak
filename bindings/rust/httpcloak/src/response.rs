use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use http::{StatusCode, Version};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};

use crate::cookie::{Cookie, WireCookie};
use crate::error::{Error, Result};
use crate::headers::Headers;

/// A response whose body has been read in full.
pub struct Response {
    status: StatusCode,
    version: Version,
    url: String,
    headers: Headers,
    trailers: Headers,
    header_order: Vec<String>,
    header_casing: Vec<String>,
    cookies: Vec<Cookie>,
    history: Vec<Redirect>,
    body: Vec<u8>,
    elapsed: Duration,
}

/// A redirect followed on the way to a [`Response`].
#[derive(Clone, Debug)]
pub struct Redirect {
    status: StatusCode,
    url: String,
    headers: Headers,
}

impl Redirect {
    /// The redirect's status, a 3xx.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The URL that answered with the redirect.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The redirect response's headers, `Location` among them.
    pub fn headers(&self) -> &Headers {
        &self.headers
    }
}

impl Response {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The HTTP version the response came over: 1.1, 2 or 3.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The URL of the response, after any redirects.
    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// The first value of header `name`, ignoring case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }

    /// The trailing headers sent after the body, where gRPC puts its status.
    pub fn trailers(&self) -> &Headers {
        &self.trailers
    }

    /// The header names in the order the server sent them, lowercase, one per
    /// occurrence. Empty on HTTP/1.1, where the library does not keep it.
    pub fn header_order(&self) -> &[String] {
        &self.header_order
    }

    /// The header names as the server spelled them. HTTP/1.1 only, where
    /// names are case-insensitive but a relay may want the original casing.
    pub fn header_casing(&self) -> &[String] {
        &self.header_casing
    }

    /// The cookies this response set, whether or not the session kept them.
    pub fn cookies(&self) -> &[Cookie] {
        &self.cookies
    }

    /// The redirects followed to get here, oldest first.
    pub fn history(&self) -> &[Redirect] {
        &self.history
    }

    /// How long the request took, from sending it to having the whole body.
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// The body as text, decoded with the charset `Content-Type` names (with
    /// the `charset` feature, on by default) or as UTF-8. Bytes that do not
    /// decode become U+FFFD; use [`body`](Response::body) for exact bytes.
    pub fn text(&self) -> String {
        decode_text(&self.body, self.headers.get("content-type"))
    }

    /// The body parsed as JSON.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| Error::decode(format!("the response body is not the JSON expected: {e}")).with_source(e))
    }

    /// Fails with an [`ErrorKind::Status`](crate::ErrorKind::Status) error for
    /// a 4xx or 5xx status.
    pub fn error_for_status(self) -> Result<Response> {
        self.error_for_status_ref()?;
        Ok(self)
    }

    /// As [`error_for_status`](Response::error_for_status), by reference.
    pub fn error_for_status_ref(&self) -> Result<&Response> {
        if self.status.is_client_error() || self.status.is_server_error() {
            Err(Error::from_status(self.status, &self.url))
        } else {
            Ok(self)
        }
    }

    /// Fails if the body is shorter than its `Content-Length` said.
    ///
    /// The library fails such a response itself, as a browser does, but
    /// earlier builds returned a body cut short by the connection
    /// closing as if it were whole; this keeps a prebuilt library linked with
    /// `HTTPCLOAK_LIB_DIR` from passing one off. Only an unencoded body can be
    /// checked: the length of an encoded one is that of the compressed bytes,
    /// and the library's decoder already fails on a truncated stream.
    pub(crate) fn check_complete(self, method: &http::Method) -> Result<Response> {
        let bodiless = *method == http::Method::HEAD
            || self.status.is_informational()
            || self.status == StatusCode::NO_CONTENT
            || self.status == StatusCode::NOT_MODIFIED;
        let encoded = self.headers.get("content-encoding").is_some_and(|e| !e.trim().eq_ignore_ascii_case("identity"));
        let declared = self.headers.get("content-length").and_then(|v| v.trim().parse::<u64>().ok());
        match declared {
            Some(declared) if !bodiless && !encoded && (self.body.len() as u64) < declared => Err(Error::new(
                crate::ErrorKind::Io,
                format!(
                    "the response body was cut short: {} of the {declared} bytes its Content-Length announced arrived",
                    self.body.len()
                ),
            )
            .with_url(self.url)),
            _ => Ok(self),
        }
    }

    /// Builds a response from the library's response JSON.
    pub(crate) fn from_json(json: &str, elapsed: Duration) -> Result<Response> {
        let data: WireResponse = crate::ffi::parse_json(json, "the response")?;
        let body = match data.body_encoding.as_str() {
            "" | "text" => data.body.into_bytes(),
            "base64" => base64::engine::general_purpose::STANDARD
                .decode(data.body.as_bytes())
                .map_err(|e| Error::decode(format!("the response body is not valid base64: {e}")))?,
            other => return Err(Error::decode(format!("the library sent a body in an unknown encoding {other:?}"))),
        };
        Ok(Response {
            status: status(data.status_code)?,
            version: version(&data.protocol),
            headers: Headers::from_map(data.headers, &data.header_order),
            trailers: Headers::from_map(data.trailer, &[]),
            cookies: data.cookies.into_iter().map(Cookie::from_wire).collect(),
            history: data
                .history
                .into_iter()
                .map(|h| {
                    Ok(Redirect {
                        status: status(h.status_code)?,
                        url: h.url,
                        headers: Headers::from_map(h.headers, &[]),
                    })
                })
                .collect::<Result<_>>()?,
            url: data.final_url,
            header_order: data.header_order,
            header_casing: data.header_casing,
            body,
            elapsed,
        })
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("version", &self.version)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .field("elapsed", &self.elapsed)
            .finish_non_exhaustive()
    }
}

pub(crate) fn status(code: u16) -> Result<StatusCode> {
    StatusCode::from_u16(code).map_err(|_| Error::decode(format!("the library reported an invalid status {code}")))
}

/// The library reports "h1", "h2" or "h3", and nothing else.
pub(crate) fn version(protocol: &str) -> Version {
    match protocol {
        "h3" | "HTTP/3" | "http/3" => Version::HTTP_3,
        "h2" | "HTTP/2" | "http/2" | "HTTP/2.0" => Version::HTTP_2,
        "h1.0" | "HTTP/1.0" => Version::HTTP_10,
        _ => Version::HTTP_11,
    }
}

pub(crate) fn decode_text(body: &[u8], content_type: Option<&str>) -> String {
    #[cfg(feature = "charset")]
    if let Some(encoding) = charset(content_type).and_then(|c| encoding_rs::Encoding::for_label(c.as_bytes())) {
        return encoding.decode_with_bom_removal(body).0.into_owned();
    }
    #[cfg(not(feature = "charset"))]
    let _ = content_type;
    String::from_utf8_lossy(body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(body)).into_owned()
}

/// The `charset` parameter of a `Content-Type` value.
#[cfg_attr(not(feature = "charset"), allow(dead_code))]
fn charset(content_type: Option<&str>) -> Option<String> {
    content_type?.split(';').skip(1).find_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim().eq_ignore_ascii_case("charset").then(|| value.trim().trim_matches('"').to_string())
    })
}

/// Go marshals a nil map or slice as `null`.
pub(crate) fn null_as_default<'de, D, T>(d: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// The library's response JSON (`ResponseData` in clib/httpcloak.go).
#[derive(Deserialize)]
pub(crate) struct WireResponse {
    status_code: u16,
    #[serde(default, deserialize_with = "null_as_default")]
    headers: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    body: String,
    #[serde(default)]
    body_encoding: String,
    #[serde(default)]
    final_url: String,
    #[serde(default)]
    protocol: String,
    #[serde(default, deserialize_with = "null_as_default")]
    cookies: Vec<WireCookie>,
    #[serde(default, deserialize_with = "null_as_default")]
    history: Vec<WireRedirect>,
    #[serde(default, deserialize_with = "null_as_default")]
    header_order: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    header_casing: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    trailer: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct WireRedirect {
    status_code: u16,
    #[serde(default)]
    url: String,
    #[serde(default, deserialize_with = "null_as_default")]
    headers: BTreeMap<String, Vec<String>>,
}

/// The library's stream metadata JSON (`StreamMetadata`).
#[derive(Deserialize)]
pub(crate) struct WireStreamMetadata {
    pub(crate) status_code: u16,
    #[serde(default, deserialize_with = "null_as_default")]
    pub(crate) headers: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub(crate) final_url: String,
    #[serde(default)]
    pub(crate) protocol: String,
    #[serde(default = "unknown_length")]
    pub(crate) content_length: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub(crate) cookies: Vec<WireCookie>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub(crate) header_order: Vec<String>,
    #[serde(default)]
    pub(crate) stream_handle: i64,
}

fn unknown_length() -> i64 {
    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_library_json() {
        let json = r#"{"status_code":201,"headers":{"content-type":["text/plain"],"x-a":["1","2"]},
            "body":"aGk=","body_encoding":"base64","final_url":"https://x/y","protocol":"h2",
            "cookies":[{"name":"c","value":"v","secure":true}],
            "history":[{"status_code":302,"url":"https://x/","headers":{"location":["/y"]}}],
            "header_order":["x-a","content-type","x-a"],"trailer":{"grpc-status":["0"]}}"#;
        let r = Response::from_json(json, Duration::from_millis(5)).unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        assert_eq!(r.version(), Version::HTTP_2);
        assert_eq!(r.body(), b"hi");
        assert_eq!(r.url(), "https://x/y");
        assert_eq!(
            r.headers().iter().collect::<Vec<_>>(),
            [("x-a", "1"), ("content-type", "text/plain"), ("x-a", "2")]
        );
        assert_eq!(r.cookies()[0].name(), "c");
        assert!(r.cookies()[0].secure());
        assert_eq!(r.history()[0].status(), StatusCode::FOUND);
        assert_eq!(r.history()[0].headers().get("Location"), Some("/y"));
        assert_eq!(r.trailers().get("grpc-status"), Some("0"));
        assert_eq!(r.elapsed(), Duration::from_millis(5));
    }

    #[test]
    fn tolerates_go_nulls_and_missing_fields() {
        let json = r#"{"status_code":204,"headers":null,"body":"","final_url":"u","protocol":"h1",
            "cookies":null,"history":null}"#;
        let r = Response::from_json(json, Duration::ZERO).unwrap();
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        assert!(r.headers().is_empty() && r.cookies().is_empty() && r.history().is_empty());
        assert!(r.body().is_empty());
        assert_eq!(r.version(), Version::HTTP_11);
    }

    #[test]
    fn rejects_what_it_cannot_decode() {
        assert!(Response::from_json("{}", Duration::ZERO).unwrap_err().kind() == crate::ErrorKind::Decode);
        assert!(Response::from_json(r#"{"status_code":42}"#, Duration::ZERO).is_err());
        let bad_b64 = r#"{"status_code":200,"body":"!!","body_encoding":"base64"}"#;
        assert!(Response::from_json(bad_b64, Duration::ZERO).is_err());
        let unknown = r#"{"status_code":200,"body":"x","body_encoding":"rot13"}"#;
        assert!(Response::from_json(unknown, Duration::ZERO).is_err());
    }

    #[test]
    fn a_short_body_is_caught_where_it_can_be() {
        let r = |json: &str| Response::from_json(json, Duration::ZERO).unwrap();
        let short = r#"{"status_code":200,"headers":{"content-length":["10"]},"body":"abc"}"#;
        assert_eq!(r(short).check_complete(&http::Method::GET).unwrap_err().kind(), crate::ErrorKind::Io);
        assert!(r(short).check_complete(&http::Method::HEAD).is_ok());
        let whole = r#"{"status_code":200,"headers":{"content-length":["3"]},"body":"abc"}"#;
        assert!(r(whole).check_complete(&http::Method::GET).is_ok());
        let encoded =
            r#"{"status_code":200,"headers":{"content-length":["2"],"content-encoding":["gzip"]},"body":"abc"}"#;
        assert!(r(encoded).check_complete(&http::Method::GET).is_ok());
        let not_modified = r#"{"status_code":304,"headers":{"content-length":["99"]},"body":""}"#;
        assert!(r(not_modified).check_complete(&http::Method::GET).is_ok());
        let bogus = r#"{"status_code":200,"headers":{"content-length":["x"]},"body":""}"#;
        assert!(r(bogus).check_complete(&http::Method::GET).is_ok());
    }

    #[test]
    fn status_errors() {
        let ok = Response::from_json(r#"{"status_code":399}"#, Duration::ZERO).unwrap();
        assert!(ok.error_for_status().is_ok());
        let bad = Response::from_json(r#"{"status_code":503,"final_url":"https://x"}"#, Duration::ZERO).unwrap();
        let e = bad.error_for_status().unwrap_err();
        assert_eq!(e.status(), Some(StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(e.url(), Some("https://x"));
    }

    #[test]
    fn text_uses_the_charset() {
        assert_eq!(decode_text(b"\xEF\xBB\xBFhi", None), "hi");
        assert_eq!(decode_text(b"caf\xc3\xa9", Some("text/plain; charset=utf-8")), "café");
        #[cfg(feature = "charset")]
        assert_eq!(decode_text(b"caf\xe9", Some("text/plain; Charset=\"ISO-8859-1\"")), "café");
        assert_eq!(decode_text(b"caf\xe9", None), "caf\u{fffd}");
        assert_eq!(charset(Some("text/html;charset=Shift_JIS")).as_deref(), Some("Shift_JIS"));
        assert_eq!(charset(Some("text/html")), None);
    }
}
