//! Helpers for the C boundary. Every `unsafe` block that is not a plain call
//! with checked arguments lives here.

use std::ffi::{c_char, CStr, CString};
use std::path::Path;

use httpcloak_sys as sys;
use serde::Deserialize;

use crate::error::{Error, Result};

/// A string argument for the library, which takes NUL-terminated strings.
/// Fails for a string with a NUL in it rather than truncating it there.
pub(crate) fn cstring(value: &str, what: &str) -> Result<CString> {
    CString::new(value).map_err(|_| Error::invalid_input(format!("{what} contains a NUL byte")))
}

/// A path argument. The library reads paths as UTF-8 strings.
pub(crate) fn cpath(path: &Path, what: &str) -> Result<CString> {
    let s =
        path.to_str().ok_or_else(|| Error::invalid_input(format!("{what} {} is not valid UTF-8", path.display())))?;
    cstring(s, what)
}

/// A string the library allocated, freed with `httpcloak_free_string` when
/// dropped, however the caller leaves.
pub(crate) struct LibString(*mut c_char);

impl LibString {
    /// Takes ownership of `ptr`, which may be null.
    ///
    /// # Safety
    ///
    /// `ptr` must be null or a NUL-terminated string the library returned and
    /// nothing else owns.
    pub(crate) unsafe fn from_raw(ptr: *mut c_char) -> Option<LibString> {
        (!ptr.is_null()).then_some(LibString(ptr))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        // SAFETY: non-null and NUL-terminated by construction, and alive until
        // drop.
        unsafe { CStr::from_ptr(self.0) }.to_bytes()
    }

    /// The text, replacing invalid UTF-8. The library only produces UTF-8
    /// (JSON, Go strings), so nothing is lost in practice.
    pub(crate) fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(self.as_bytes()).into_owned()
    }
}

impl Drop for LibString {
    fn drop(&mut self) {
        // SAFETY: the library allocated it and this is its only owner.
        unsafe { sys::httpcloak_free_string(self.0) }
    }
}

/// Takes a returned string, copying it out and freeing the original.
///
/// # Safety
///
/// As [`LibString::from_raw`].
pub(crate) unsafe fn take_string(ptr: *mut c_char) -> Option<String> {
    // SAFETY: the caller's guarantee is from_raw's.
    unsafe { LibString::from_raw(ptr) }.map(|s| s.to_string_lossy())
}

/// Copies a string the library lends to a callback, without taking it.
///
/// # Safety
///
/// `ptr` must be null or a NUL-terminated string valid for the call.
pub(crate) unsafe fn borrow_string(ptr: *const c_char) -> Option<String> {
    // SAFETY: non-null, and valid for the call by the caller's guarantee.
    (!ptr.is_null()).then(|| String::from_utf8_lossy(unsafe { CStr::from_ptr(ptr) }.to_bytes()).into_owned())
}

#[derive(Deserialize)]
struct ErrorObject {
    error: String,
}

/// The message of an `{"error": "..."}` object, or `None` when `text` is not
/// one. Many exports return either their result or such an object.
pub(crate) fn error_in(text: &str) -> Option<String> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with('{') || !trimmed.contains("\"error\"") {
        return None;
    }
    serde_json::from_str::<ErrorObject>(trimmed).ok().map(|e| e.error)
}

/// The message of an async error, which is an error object or, from a few
/// paths, the bare message.
pub(crate) fn async_error_message(text: &str) -> String {
    match error_in(text) {
        Some(message) => message,
        None if text.is_empty() => "the request failed and the library gave no reason".to_string(),
        None => text.to_string(),
    }
}

/// The result of an export that returns text or an error object: the text,
/// or the error as an [`Error`] classified by its message.
pub(crate) fn checked(result: Option<String>, what: &str) -> Result<String> {
    let text = result.ok_or_else(|| Error::new_other(format!("{what}: the library returned nothing")))?;
    match error_in(&text) {
        Some(message) => Err(Error::from_library(message)),
        None => Ok(text),
    }
}

/// Parses JSON the library produced.
pub(crate) fn parse_json<T: serde::de::DeserializeOwned>(text: &str, what: &str) -> Result<T> {
    serde_json::from_str(text)
        .map_err(|e| Error::decode(format!("could not decode {what} from the library: {e}")).with_source(e))
}

impl Error {
    pub(crate) fn new_other(message: impl Into<String>) -> Self {
        Error::new(crate::ErrorKind::Other, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nul_bytes_are_rejected_not_truncated() {
        let e = cstring("http://a\0b", "the URL").unwrap_err();
        assert!(e.is_invalid_input());
        assert_eq!(e.to_string(), "the URL contains a NUL byte");
        assert_eq!(cstring("ok", "x").unwrap().as_bytes(), b"ok");
    }

    #[test]
    fn error_objects_are_recognised() {
        assert_eq!(error_in(r#"{"error":"boom"}"#).as_deref(), Some("boom"));
        assert_eq!(error_in(r#"  {"error":"boom","code":"x"}"#).as_deref(), Some("boom"));
        assert_eq!(error_in(r#"{"status_code":200}"#), None);
        assert_eq!(error_in("chrome-155"), None);
        assert_eq!(error_in("[]"), None);
        // A body that merely mentions the word is not an error object.
        assert_eq!(error_in(r#"{"note":"no \"error\" here"}"#), None);
    }

    #[test]
    fn async_errors_may_be_bare_text() {
        assert_eq!(async_error_message(r#"{"error":"x"}"#), "x");
        assert_eq!(async_error_message("invalid session handle"), "invalid session handle");
        assert!(!async_error_message("").is_empty());
    }
}
