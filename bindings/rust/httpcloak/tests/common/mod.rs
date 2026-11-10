//! Test servers: a hyper server over plain TCP and TLS (HTTP/1.1 and HTTP/2,
//! self-signed), for requests that should work, and a raw TCP server driven
//! by a script, for servers that misbehave and for checking the exact bytes a
//! request puts on the wire.

#![allow(dead_code)]

use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, LazyLock, Mutex};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};

pub use httpcloak::Session;

/// The shared servers, started once per test binary.
pub struct Servers {
    /// `http://127.0.0.1:port`
    pub http: String,
    /// `https://localhost:port`, self-signed.
    pub https: String,
    /// Requests the hyper server has seen whose client hung up early.
    pub disconnects: Arc<AtomicUsize>,
}

pub fn servers() -> &'static Servers {
    static SERVERS: LazyLock<Servers> = LazyLock::new(start_servers);
    &SERVERS
}

/// A session for the test servers: their certificate is self-signed.
pub fn session() -> Session {
    Session::builder().danger_accept_invalid_certs(true).timeout(Duration::from_secs(20)).build().unwrap()
}

pub fn http(path: &str) -> String {
    format!("{}{path}", servers().http)
}

pub fn https(path: &str) -> String {
    format!("{}{path}", servers().https)
}

/// The deterministic bytes `/bytes/N` serves: every byte value, over and over.
pub fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// FNV-1a, to check large bodies arrived intact without echoing them.
pub fn fnv(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf29ce484222325, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x100000001b3))
}

/// A port nothing listens on.
pub fn refused_url() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    format!("http://127.0.0.1:{port}/")
}

fn start_servers() -> Servers {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let disconnects = Arc::new(AtomicUsize::new(0));

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));

    // The servers run on a runtime of their own, on a thread of their own,
    // so that tests on any runtime, or none, can use them.
    let (tx, rx) = mpsc::channel();
    let d = disconnects.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
        runtime.block_on(async move {
            let plain = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let secure = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send((plain.local_addr().unwrap(), secure.local_addr().unwrap())).unwrap();
            let d2 = d.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = plain.accept().await else { continue };
                    tokio::spawn(serve(TokioIo::new(tcp), d2.clone()));
                }
            });
            loop {
                let Ok((tcp, _)) = secure.accept().await else { continue };
                let (acceptor, d) = (acceptor.clone(), d.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        serve(TokioIo::new(tls), d).await;
                    }
                });
            }
        });
    });
    let (http_addr, https_addr) = rx.recv().unwrap();

    Servers {
        http: format!("http://127.0.0.1:{}", http_addr.port()),
        https: format!("https://localhost:{}", https_addr.port()),
        disconnects,
    }
}

async fn serve<IO>(io: TokioIo<IO>, disconnects: Arc<AtomicUsize>)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |req| route(req, disconnects.clone()));
    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection(io, service).await;
}

type Body = BoxBody<Bytes, Infallible>;

fn full(body: impl Into<Bytes>) -> Body {
    Full::new(body.into()).boxed()
}

fn reply(status: u16, body: impl Into<Bytes>) -> Response<Body> {
    Response::builder().status(status).body(full(body)).unwrap()
}

/// A body sent as `chunks`, each after `delay`, then `trailers`.
fn chunked(chunks: Vec<Bytes>, delay: Duration, trailers: Option<hyper::HeaderMap>) -> Body {
    let frames = futures_util::stream::unfold(
        (chunks.into_iter(), trailers, false),
        move |(mut it, trailers, first)| async move {
            if first {
                tokio::time::sleep(delay).await;
            }
            match it.next() {
                Some(c) => Some((Ok::<_, Infallible>(Frame::data(c)), (it, trailers, true))),
                None => trailers.map(|t| (Ok(Frame::trailers(t)), (it, None, true))),
            }
        },
    );
    BodyExt::boxed(StreamBody::new(frames))
}

fn segment(path: &str, i: usize) -> Option<&str> {
    path.split('/').filter(|s| !s.is_empty()).nth(i)
}

fn number(path: &str, i: usize) -> u64 {
    segment(path, i).and_then(|s| s.parse().ok()).unwrap_or(0)
}

async fn route(req: Request<Incoming>, disconnects: Arc<AtomicUsize>) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_string();
    let first = segment(&path, 0).unwrap_or("").to_string();
    Ok(match first.as_str() {
        // The request as the server saw it.
        "echo" => {
            let method = req.method().to_string();
            let version = format!("{:?}", req.version());
            let query = req.uri().query().unwrap_or("").to_string();
            let headers: Vec<(String, String)> = req
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
                .collect();
            let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            let json = serde_json::json!({
                "method": method, "version": version, "path": path, "query": query, "headers": headers,
                "body": base64::engine::general_purpose::STANDARD.encode(&body),
            });
            Response::builder().header("content-type", "application/json").body(full(json.to_string())).unwrap()
        }
        "status" => reply(number(&path, 1) as u16, format!("status {}", number(&path, 1))),
        "redirect" => {
            let n = number(&path, 1);
            if n == 0 {
                reply(200, "landed")
            } else {
                Response::builder()
                    .status(302)
                    .header("location", format!("/redirect/{}", n - 1))
                    .body(full(""))
                    .unwrap()
            }
        }
        "redirect-to" => {
            let to = req.uri().query().and_then(|q| q.strip_prefix("url=")).unwrap_or("/").to_string();
            Response::builder().status(301).header("location", to).body(full("")).unwrap()
        }
        "sleep" => {
            let ms = number(&path, 1);
            let guard = DisconnectGuard(disconnects, false);
            tokio::time::sleep(Duration::from_millis(ms)).await;
            let mut guard = guard;
            guard.1 = true;
            reply(200, format!("slept {ms}"))
        }
        "bytes" => Response::builder()
            .header("content-type", "application/octet-stream")
            .body(full(pattern(number(&path, 1) as usize)))
            .unwrap(),
        "text" => Response::builder()
            .header("content-type", "text/plain; charset=utf-8")
            .body(full("héllo wörld ✓ \u{0} nul and \"quotes\" <tags> & \u{1F600}"))
            .unwrap(),
        "latin1" => Response::builder()
            .header("content-type", "text/plain; charset=ISO-8859-1")
            .body(full(&b"caf\xe9"[..]))
            .unwrap(),
        // /stream/<chunks>/<delay ms>: numbered lines, one per chunk.
        "stream" => {
            let (n, delay) = (number(&path, 1), Duration::from_millis(number(&path, 2)));
            let chunks = (0..n).map(|i| Bytes::from(format!("chunk {i}\n"))).collect();
            Response::builder().header("content-type", "text/plain").body(chunked(chunks, delay, None)).unwrap()
        }
        "trailers" => {
            let mut t = hyper::HeaderMap::new();
            t.insert("grpc-status", "0".parse().unwrap());
            t.insert("x-checksum", "abc".parse().unwrap());
            Response::builder()
                .header("trailer", "grpc-status, x-checksum")
                .body(chunked(vec![Bytes::from_static(b"body")], Duration::ZERO, Some(t)))
                .unwrap()
        }
        "set-cookie" => Response::builder()
            .header("set-cookie", "a=1; Path=/; HttpOnly")
            .header("set-cookie", "b=2; Path=/; Secure; SameSite=Lax; Max-Age=3600")
            .body(full("cookies set"))
            .unwrap(),
        "multi" => Response::builder()
            .header("x-multi", "one")
            .header("x-multi", "two")
            .header("x-single", "only")
            .body(full(""))
            .unwrap(),
        // Reads the whole body and reports its length and checksum.
        "upload" => {
            let method = req.method().to_string();
            let content_type = req.headers().get("content-type").map(|v| v.to_str().unwrap_or("").to_string());
            let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            let json = serde_json::json!({
                "method": method, "len": body.len(), "fnv": fnv(&body).to_string(), "content_type": content_type,
            });
            reply(200, json.to_string())
        }
        // The request body, back as the response body, unchanged.
        "reflect" => {
            let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            Response::builder().header("content-type", "application/octet-stream").body(full(body)).unwrap()
        }
        // Answers without reading the body.
        "reject" => reply(413, "too large"),
        "empty" => reply(204, ""),
        _ => reply(404, "not found"),
    })
}

/// Counts a `/sleep` request whose client left before it was answered.
struct DisconnectGuard(Arc<AtomicUsize>, bool);

impl Drop for DisconnectGuard {
    fn drop(&mut self) {
        if !self.1 {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// A TCP server that reads each request head and then hands the connection to
/// `script`, for responses no real server would send.
pub struct RawServer {
    pub addr: SocketAddr,
    heads: mpsc::Receiver<Vec<u8>>,
}

impl RawServer {
    pub fn start<F>(script: F) -> RawServer
    where
        F: Fn(&mut TcpStream, &[u8]) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, heads) = mpsc::channel();
        let tx = Arc::new(Mutex::new(tx));
        let script = Arc::new(script);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (script, tx) = (script.clone(), tx.clone());
                std::thread::spawn(move || {
                    let head = read_head(&mut stream);
                    let _ = tx.lock().unwrap().send(head.clone());
                    script(&mut stream, &head);
                });
            }
        });
        RawServer { addr, heads }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// The next request head the server received.
    pub fn next_head(&self) -> String {
        self.next_head_within(Duration::from_secs(10)).expect("no request arrived")
    }

    /// The next request head, if one arrives within `timeout`.
    pub fn next_head_within(&self, timeout: Duration) -> Option<String> {
        self.heads.recv_timeout(timeout).ok().map(|h| String::from_utf8_lossy(&h).into_owned())
    }
}

/// Reads up to the end of the request head.
pub fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    head
}

pub fn write(stream: &mut TcpStream, data: &[u8]) {
    let _ = stream.write_all(data);
    let _ = stream.flush();
}

/// The header lines of a request head, in order, as sent.
pub fn header_lines(head: &str) -> Vec<String> {
    head.split("\r\n").skip(1).filter(|l| !l.is_empty()).map(str::to_string).collect()
}

/// Parses `/echo`'s reply.
pub fn echo(response: &httpcloak::Response) -> serde_json::Value {
    assert_eq!(response.status(), 200, "{}", response.text());
    response.json().unwrap()
}

/// The value of header `name` in an `/echo` reply.
pub fn echoed_header(echo: &serde_json::Value, name: &str) -> Option<String> {
    echo["headers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h[0].as_str().unwrap().eq_ignore_ascii_case(name))
        .map(|h| h[1].as_str().unwrap().to_string())
}

/// Every cookie an `/echo` reply saw, joined: HTTP/2 sends each in a header
/// field of its own, as Chrome does.
pub fn echoed_cookies(echo: &serde_json::Value) -> String {
    echo["headers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h[0].as_str().unwrap().eq_ignore_ascii_case("cookie"))
        .map(|h| h[1].as_str().unwrap().to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn echoed_body(echo: &serde_json::Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(echo["body"].as_str().unwrap()).unwrap()
}

/// Waits until `cond` holds, for up to `timeout`.
pub fn eventually(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cond()
}
