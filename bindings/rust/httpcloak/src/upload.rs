use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use http::Method;
use httpcloak_sys as sys;
use serde::Serialize;

use crate::error::{Error, Result};
use crate::ffi::{self, cstring};
use crate::headers::{valid_name, valid_value};
use crate::response::Response;
use crate::session::Session;

/// An upload being set up, from [`Session::upload`].
#[derive(Clone, Debug)]
#[must_use = "an upload does nothing until it is started"]
pub struct UploadBuilder {
    session: Session,
    url: String,
    method: Method,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    timeout: Option<Duration>,
    error: Option<String>,
}

impl UploadBuilder {
    pub(crate) fn new(session: Session, url: String) -> UploadBuilder {
        UploadBuilder {
            session,
            url,
            method: Method::POST,
            headers: Vec::new(),
            content_type: None,
            timeout: None,
            error: None,
        }
    }

    /// The method, `POST` by default.
    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Sets a header, replacing any value set before under any spelling of
    /// the name.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let (name, value) = (name.into(), crate::headers::normalize_value(value.into()));
        if !valid_name(&name) {
            self.error.get_or_insert(format!("{name:?} is not a valid header name"));
        } else if !valid_value(&value) {
            self.error.get_or_insert(format!("the value of header {name:?} has a control character in it"));
        }
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&name));
        self.headers.push((name, value));
        self
    }

    /// The body's `Content-Type`.
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        let content_type = content_type.into();
        if !valid_value(&content_type) {
            self.error.get_or_insert("the content type has a control character in it".into());
        }
        self.content_type = Some(content_type);
        self
    }

    /// How long the whole upload may take, response included: five minutes
    /// by default, whatever the session's timeout. Over HTTP/1.1 the library
    /// also waits at most 60 seconds for the response once the body is sent.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        if timeout.is_zero() {
            self.error.get_or_insert("the upload timeout must be greater than zero".into());
        }
        self.timeout = Some(timeout);
        self
    }

    /// Sends the request headers and returns the upload, ready for the body.
    /// The connection is made in the background; a failure to make it is
    /// reported by the first write, or by [`Upload::finish`].
    pub fn start(self) -> Result<Upload> {
        if let Some(message) = self.error {
            return Err(Error::invalid_input(message).with_url(self.url));
        }
        if self.url.is_empty() {
            return Err(Error::invalid_input("the URL is empty"));
        }
        crate::request::check_scheme(&self.url)?;
        #[derive(Serialize)]
        struct Options<'a> {
            method: &'a str,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            headers: BTreeMap<&'a str, &'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            content_type: Option<&'a str>,
            /// Milliseconds, the unit of httpcloak_upload_start.
            #[serde(skip_serializing_if = "Option::is_none")]
            timeout: Option<u64>,
        }
        let options = Options {
            method: self.method.as_str(),
            headers: self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
            content_type: self.content_type.as_deref(),
            timeout: self
                .timeout
                .map(|t| u64::try_from(t.as_millis()).unwrap_or(u64::MAX).clamp(1, i64::MAX as u64 / 1_000_000)),
        };
        let options = serde_json::to_string(&options).expect("upload options always serialize");
        let c_url = cstring(&self.url, "the URL")?;
        let c_options = cstring(&options, "the upload options")?;
        let started = Instant::now();
        // SAFETY: the session is alive (we hold it), and both strings are
        // valid NUL-terminated strings the export copies before returning.
        let handle = unsafe { sys::httpcloak_upload_start(self.session.handle(), c_url.as_ptr(), c_options.as_ptr()) };
        if handle <= 0 {
            return Err(Error::new_other("the library could not start the upload").with_url(self.url));
        }
        Ok(Upload {
            _session: self.session,
            handle,
            url: self.url,
            method: self.method,
            started,
            ended: None,
            finished: false,
        })
    }
}

/// A request whose body is written as it goes, for bodies too large to hold
/// in memory. Write the body through [`Write`], then call
/// [`finish`](Upload::finish) for the response. Dropping an upload that was
/// not finished cancels it.
///
/// A write blocks until the server has taken the data, so the body flows at
/// the pace the server reads it.
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let session = httpcloak::Session::new()?;
/// let mut upload = session.upload("https://example.com/upload").content_type("application/zip").start()?;
/// std::io::copy(&mut std::fs::File::open("big.zip")?, &mut upload)?;
/// let response = upload.finish()?;
/// # Ok(())
/// # }
/// ```
pub struct Upload {
    // Keeps the session, and with it the upload's connection, alive.
    _session: Session,
    handle: i64,
    url: String,
    method: Method,
    started: Instant,
    /// The outcome, once the library has ended the upload early: the request
    /// failed, or the server answered before the body was done.
    ended: Option<Result<Response>>,
    finished: bool,
}

impl Upload {
    /// Ends the body and waits for the response.
    pub fn finish(mut self) -> Result<Response> {
        match self.ended.take() {
            Some(outcome) => {
                self.finished = true;
                outcome
            }
            None => self.collect(),
        }
    }

    /// Abandons the upload. The same as dropping it.
    pub fn cancel(self) {}

    /// Ends the upload in the library and returns its outcome.
    fn collect(&mut self) -> Result<Response> {
        self.finished = true;
        // SAFETY: our open upload's handle, finished once; the result is ours
        // to free. The library forgets the handle here.
        let json = unsafe { ffi::take_string(sys::httpcloak_upload_finish(self.handle)) };
        let hosts = || crate::request::hosts_involved(&self._session, &self.url);
        let json =
            ffi::checked(json, "finishing the upload").map_err(|e| e.with_hosts(&hosts()).with_url(&self.url))?;
        Response::from_json(&json, self.started.elapsed())
            .map_err(|e| e.with_url(&self.url))?
            .check_complete(&self.method)
    }
}

impl Write for Upload {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(outcome) = &self.ended {
            return Err(ended_error(outcome));
        }
        let len = buf.len().min(i32::MAX as usize);
        // SAFETY: our open upload's handle, and a buffer valid for reads of
        // `len` bytes, which the library copies before it returns.
        let n = unsafe { sys::httpcloak_upload_write_raw(self.handle, buf.as_ptr().cast(), len as i32) };
        if n >= 0 {
            return Ok((n as usize).min(len));
        }
        // A write fails because the request has ended. The library only says
        // -1; finishing gets the reason, or the response if the server
        // answered early, and finish() hands that over later.
        let outcome = self.collect();
        let e = ended_error(&outcome);
        self.ended = Some(outcome);
        Err(e)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn ended_error(outcome: &Result<Response>) -> io::Error {
    match outcome {
        Err(e) => io::Error::new(crate::error::io_kind(e), format!("the upload failed: {e}")),
        Ok(response) => io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!(
                "the server answered {} before the upload was finished; finish() returns the response",
                response.status()
            ),
        ),
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        if !self.finished {
            // SAFETY: our open upload's handle, which nothing has finished.
            unsafe { sys::httpcloak_upload_cancel(self.handle) }
        }
    }
}

impl fmt::Debug for Upload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Upload").field("url", &self.url).field("finished", &self.finished).finish_non_exhaustive()
    }
}
