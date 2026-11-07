use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read};
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use http::{StatusCode, Version};
use httpcloak_sys as sys;

use crate::call::{self, Deadline, Leftover, StreamDeadline, TimerKey};
use crate::cookie::Cookie;
use crate::error::{Error, Result};
use crate::ffi;
use crate::headers::Headers;
use crate::response::{decode_text, status, version, WireStreamMetadata};
use crate::session::Session;

/// A response whose body is read as it arrives, through [`Read`].
///
/// Reads block until data arrives. Dropping the response closes it and its
/// connection, whether or not the body was read to the end; for use from async
/// code, turn it into a [`BodyStream`] with
/// [`into_body_stream`](StreamResponse::into_body_stream).
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::io::{BufRead, BufReader};
///
/// let session = httpcloak::Session::new()?;
/// let stream = session.get("https://example.com/events").send_stream()?;
/// for line in BufReader::new(stream).lines() {
///     println!("{}", line?);
/// }
/// # Ok(())
/// # }
/// ```
pub struct StreamResponse {
    // Keeps the session, and with it the stream's connection, alive.
    _session: Session,
    handle: i64,
    status: StatusCode,
    version: Version,
    url: String,
    headers: Headers,
    header_order: Vec<String>,
    content_length: Option<u64>,
    cookies: Vec<Cookie>,
    eof: bool,
    /// The request's timeout, which bounds the body too, and its place in
    /// the timer that cancels a read still blocked when it passes.
    deadline: Option<(Arc<StreamDeadline>, Option<TimerKey>)>,
}

impl StreamResponse {
    /// Takes over the stream the library opened, from its metadata JSON.
    pub(crate) fn open(session: Session, json: &str, deadline: Option<Deadline>) -> Result<StreamResponse> {
        let meta: WireStreamMetadata = match ffi::parse_json(json, "the stream metadata") {
            Ok(meta) => meta,
            Err(e) => {
                // Close whatever stream the unreadable metadata names.
                Leftover::CloseStream.dispose(json);
                return Err(e);
            }
        };
        if meta.stream_handle <= 0 {
            return Err(Error::new_other("the library opened a stream but gave no handle for it"));
        }
        let handle = meta.stream_handle;
        let status = match status(meta.status_code) {
            Ok(s) => s,
            Err(e) => {
                // SAFETY: the stream is ours and nothing else knows its handle.
                unsafe { sys::httpcloak_stream_close(handle) };
                return Err(e);
            }
        };
        Ok(StreamResponse {
            _session: session,
            handle,
            status,
            version: version(&meta.protocol),
            url: meta.final_url,
            headers: Headers::from_map(meta.headers, &meta.header_order),
            header_order: meta.header_order,
            content_length: u64::try_from(meta.content_length).ok(),
            cookies: meta.cookies.into_iter().map(Cookie::from_wire).collect(),
            eof: false,
            deadline: deadline.map(|d| {
                let d = Arc::new(StreamDeadline::new(handle, d));
                let key = call::arm_stream(&d);
                (d, key)
            }),
        })
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn version(&self) -> Version {
        self.version
    }

    /// The URL of the response. Streamed requests do not follow redirects,
    /// so this is the URL requested.
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

    /// The header names in the order the server sent them; empty on HTTP/1.1.
    pub fn header_order(&self) -> &[String] {
        &self.header_order
    }

    /// The body's length, when the server said.
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// The cookies this response set.
    pub fn cookies(&self) -> &[Cookie] {
        &self.cookies
    }

    /// Fails with an [`ErrorKind::Status`](crate::ErrorKind::Status) error for
    /// a 4xx or 5xx status.
    pub fn error_for_status(self) -> Result<StreamResponse> {
        if self.status.is_client_error() || self.status.is_server_error() {
            Err(Error::from_status(self.status, &self.url))
        } else {
            Ok(self)
        }
    }

    /// The trailing headers. They arrive after the body, so this is complete
    /// only once the body has been read to the end; before that it is empty,
    /// or on HTTP/1.1 holds the announced names with empty values.
    pub fn trailers(&self) -> Headers {
        // SAFETY: our open stream's handle; the result is ours to free.
        let json = unsafe { ffi::take_string(sys::httpcloak_stream_trailer(self.handle)) };
        json.and_then(|j| serde_json::from_str(&j).ok()).map(|m| Headers::from_map(m, &[])).unwrap_or_default()
    }

    /// Reads the rest of the body.
    pub fn bytes(mut self) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(self.content_length.unwrap_or(0).min(64 << 20) as usize);
        self.read_to_end(&mut body).map_err(|e| read_error(e, &self.url))?;
        Ok(body)
    }

    /// Reads the rest of the body as text, as
    /// [`Response::text`](crate::Response::text) decodes it.
    pub fn text(self) -> Result<String> {
        let content_type = self.headers.get("content-type").map(str::to_string);
        let body = self.bytes()?;
        Ok(decode_text(&body, content_type.as_deref()))
    }

    /// The body as a [`futures_core::Stream`] of chunks, for async code.
    ///
    /// The library can only read a body by blocking, so the chunks are read
    /// on a thread of the stream's own, a few chunks ahead of the consumer.
    pub fn into_body_stream(self) -> BodyStream {
        BodyStream::start(self)
    }
}

impl Read for StreamResponse {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.eof {
            return Ok(0);
        }
        if let Some(e) = self.timed_out() {
            return Err(e);
        }
        let len = buf.len().min(i32::MAX as usize);
        // SAFETY: our open stream's handle, and a buffer valid for writes of
        // `len` bytes for the duration of the call, which is all the library
        // keeps it.
        let n = unsafe { sys::httpcloak_stream_read_raw(self.handle, buf.as_mut_ptr().cast(), len as i32) };
        match n {
            n if n < 0 => Err(self.timed_out().unwrap_or_else(|| {
                io::Error::other("reading the response body failed: the connection broke, or the request was cancelled")
            })),
            0 => {
                self.eof = true;
                Ok(0)
            }
            // The library never reports more than it was given room for.
            n => Ok((n as usize).min(len)),
        }
    }
}

impl StreamResponse {
    /// The error to report once the request's timeout has passed.
    fn timed_out(&self) -> Option<io::Error> {
        let (deadline, _) = self.deadline.as_ref()?;
        deadline.passed().then(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("the request timed out after {:?}, before its body was read", deadline.deadline.timeout),
            )
        })
    }
}

impl Drop for StreamResponse {
    fn drop(&mut self) {
        if let Some((_, Some(key))) = self.deadline.take() {
            call::disarm(key);
        }
        // SAFETY: our open stream's handle, closed once, here.
        unsafe { sys::httpcloak_stream_close(self.handle) }
    }
}

impl fmt::Debug for StreamResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamResponse")
            .field("status", &self.status)
            .field("version", &self.version)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("content_length", &self.content_length)
            .finish_non_exhaustive()
    }
}

fn read_error(e: io::Error, url: &str) -> Error {
    let kind = if e.kind() == io::ErrorKind::TimedOut { crate::ErrorKind::Timeout } else { crate::ErrorKind::Io };
    Error::new(kind, e.to_string()).with_url(url).with_source(e)
}

/// A streamed body as an async [`Stream`](futures_core::Stream) of chunks,
/// from [`StreamResponse::into_body_stream`].
///
/// Dropping it cancels a read in progress, and the reader thread then closes
/// the stream; a read is never interrupted by closing the stream under it.
pub struct BodyStream {
    shared: Arc<Pipe>,
    /// The stream the reader thread owns, to cancel a read it is blocked in.
    handle: i64,
}

/// Chunks read ahead, the most kept before the reader waits.
const READ_AHEAD: usize = 4;
const CHUNK: usize = 64 * 1024;

struct Pipe {
    state: Mutex<PipeState>,
    /// Wakes the reader thread when there is room, or the consumer has gone.
    room: Condvar,
}

#[derive(Default)]
struct PipeState {
    chunks: VecDeque<io::Result<Vec<u8>>>,
    ended: bool,
    trailers: Option<Headers>,
    consumer: Option<Waker>,
    dropped: bool,
}

fn lock(m: &Mutex<PipeState>) -> MutexGuard<'_, PipeState> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl BodyStream {
    fn start(mut response: StreamResponse) -> BodyStream {
        let handle = response.handle;
        let pipe = Arc::new(Pipe { state: Mutex::new(PipeState::default()), room: Condvar::new() });
        let for_thread = pipe.clone();
        let spawned = std::thread::Builder::new().name("httpcloak-body".into()).spawn(move || {
            let pipe = for_thread;
            loop {
                {
                    let mut state = lock(&pipe.state);
                    while state.chunks.len() >= READ_AHEAD && !state.dropped {
                        state = pipe.room.wait(state).unwrap_or_else(|e| e.into_inner());
                    }
                    if state.dropped {
                        return;
                    }
                }
                // The stream is only ever touched here, so a read and a close
                // never overlap: the close happens when this thread drops it.
                let mut chunk = vec![0; CHUNK];
                let item = match response.read(&mut chunk) {
                    Ok(0) => None,
                    Ok(n) => {
                        chunk.truncate(n);
                        Some(Ok(chunk))
                    }
                    Err(e) => Some(Err(e)),
                };
                let failed = matches!(item, Some(Err(_)));
                let trailers = item.is_none().then(|| response.trailers());
                let mut state = lock(&pipe.state);
                match item {
                    Some(item) => state.chunks.push_back(item),
                    None => {
                        state.ended = true;
                        state.trailers = trailers;
                    }
                }
                if failed {
                    state.ended = true;
                }
                let ended = state.ended;
                let waker = state.consumer.take();
                drop(state);
                if let Some(waker) = waker {
                    waker.wake();
                }
                if ended {
                    return;
                }
            }
        });
        if let Err(e) = spawned {
            // The response went with the closure, and is closed.
            let mut state = lock(&pipe.state);
            state.chunks.push_back(Err(io::Error::other(format!("could not start a thread to read the body: {e}"))));
            state.ended = true;
        }
        BodyStream { shared: pipe, handle }
    }

    /// The trailing headers, once the stream has ended; `None` before then,
    /// or if it ended in an error.
    pub fn trailers(&self) -> Option<Headers> {
        lock(&self.shared.state).trailers.clone()
    }
}

impl futures_core::Stream for BodyStream {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut state = lock(&self.shared.state);
        if let Some(item) = state.chunks.pop_front() {
            drop(state);
            self.shared.room.notify_one();
            return Poll::Ready(Some(item));
        }
        if state.ended {
            return Poll::Ready(None);
        }
        match &state.consumer {
            Some(w) if w.will_wake(cx.waker()) => {}
            _ => state.consumer = Some(cx.waker().clone()),
        }
        Poll::Pending
    }
}

impl Drop for BodyStream {
    fn drop(&mut self) {
        let mut state = lock(&self.shared.state);
        state.dropped = true;
        let finished = state.ended;
        drop(state);
        self.shared.room.notify_one();
        if !finished {
            // A read may be blocked on an idle connection, where the flag
            // alone would wait for the peer. Cancelling returns it, and the
            // reader thread, the stream's only user, closes the stream. A
            // stream it has already closed is a no-op: handles are not reused.
            // SAFETY: plain call; cancelling is safe beside a read.
            unsafe { sys::httpcloak_stream_cancel(self.handle) };
        }
    }
}

impl fmt::Debug for BodyStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyStream").finish_non_exhaustive()
    }
}
