use std::fmt;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A cookie, as held in a session's jar or set by a response.
///
/// ```
/// use httpcloak::Cookie;
///
/// let cookie = Cookie::new("session", "abc123")
///     .with_domain(".example.com")
///     .with_path("/")
///     .with_secure(true);
/// assert_eq!(cookie.name(), "session");
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Cookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    expires: Option<SystemTime>,
    max_age: Option<i64>,
    secure: bool,
    http_only: bool,
    same_site: Option<SameSite>,
}

/// The `SameSite` attribute.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SameSite {
    Strict,
    Lax,
    None,
    /// A value the attribute does not define, kept as sent.
    Other(String),
}

impl SameSite {
    pub fn as_str(&self) -> &str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
            SameSite::Other(s) => s,
        }
    }

    fn parse(s: &str) -> Option<SameSite> {
        match s.to_ascii_lowercase().as_str() {
            "" => None,
            "strict" => Some(SameSite::Strict),
            "lax" => Some(SameSite::Lax),
            "none" => Some(SameSite::None),
            _ => Some(SameSite::Other(s.to_string())),
        }
    }
}

impl Cookie {
    /// A cookie with no attributes.
    ///
    /// Without a [domain](Cookie::with_domain), a cookie put in a session's
    /// jar is sent to every host.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Cookie {
        Cookie {
            name: name.into(),
            value: value.into(),
            domain: String::new(),
            path: String::new(),
            expires: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    /// The domain, empty when the cookie has none. A leading `.` matches the
    /// domain and its subdomains; without one only that exact host matches.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The path, empty when the cookie has none.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// When the cookie expires; `None` for a session cookie, or when the
    /// server's date could not be read. For a cookie in a jar, the expiry its
    /// `Max-Age` or `Expires` gave it.
    pub fn expires(&self) -> Option<SystemTime> {
        self.expires
    }

    /// `Max-Age` in seconds, when set.
    pub fn max_age(&self) -> Option<i64> {
        self.max_age
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    pub fn http_only(&self) -> bool {
        self.http_only
    }

    pub fn same_site(&self) -> Option<&SameSite> {
        self.same_site.as_ref()
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Cookie {
        self.domain = domain.into();
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Cookie {
        self.path = path.into();
        self
    }

    /// Sets the expiry. It is kept to the second, as the `Expires` attribute
    /// is.
    pub fn with_expires(mut self, expires: SystemTime) -> Cookie {
        self.expires = Some(truncate_to_second(expires));
        self
    }

    /// Sets `Max-Age`. A jar takes the cookie as expiring that long after it
    /// takes it, whatever [`expires`](Cookie::with_expires) says, and at most
    /// 400 days on, as Chrome does; [`Duration::ZERO`] has it expired at once,
    /// which removes the cookie of the same name, domain and path instead. The
    /// jar keeps the expiry, so a cookie read back from it has none.
    ///
    /// `Max-Age` is whole seconds (RFC 6265's delta-seconds), so a fraction of
    /// a second is rounded up: the cookie lives at least as long as asked, and
    /// a duration under a second is one second, not zero, which would delete
    /// the cookie.
    pub fn with_max_age(mut self, max_age: Duration) -> Cookie {
        let seconds = max_age.as_secs().saturating_add(u64::from(max_age.subsec_nanos() > 0));
        self.max_age = Some(i64::try_from(seconds).unwrap_or(i64::MAX));
        self
    }

    pub fn with_secure(mut self, secure: bool) -> Cookie {
        self.secure = secure;
        self
    }

    pub fn with_http_only(mut self, http_only: bool) -> Cookie {
        self.http_only = http_only;
        self
    }

    pub fn with_same_site(mut self, same_site: SameSite) -> Cookie {
        self.same_site = Some(same_site);
        self
    }

    /// Checks the cookie can be put in a jar and sent: a name and value that
    /// cannot break out of a `Cookie` header.
    pub(crate) fn validate(&self) -> Result<()> {
        validate_pair(&self.name, &self.value)?;
        if self.expires.is_some_and(|e| !representable(e)) {
            return Err(Error::invalid_input(format!(
                "cookie {:?} expires after the last date an HTTP date can name (year 9999)",
                self.name
            )));
        }
        for (what, s) in [("domain", &self.domain), ("path", &self.path)] {
            if s.bytes().any(|b| b < 0x20 || b == 0x7f || b == b';') {
                return Err(Error::invalid_input(format!(
                    "cookie {:?} has a {what} with a control character or ';' in it",
                    self.name
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn to_wire(&self) -> WireCookie {
        WireCookie {
            name: self.name.clone(),
            value: self.value.clone(),
            domain: self.domain.clone(),
            path: self.path.clone(),
            expires: self.expires.map(httpdate::fmt_http_date).unwrap_or_default(),
            // The library reads 0 as no Max-Age, and one below zero as
            // expired now (net/http's convention).
            max_age: match self.max_age {
                None => 0,
                Some(0) => -1,
                Some(seconds) => seconds,
            },
            secure: self.secure,
            http_only: self.http_only,
            same_site: self.same_site.as_ref().map(|s| s.as_str().to_string()).unwrap_or_default(),
        }
    }

    pub(crate) fn from_wire(w: WireCookie) -> Cookie {
        Cookie {
            name: w.name,
            value: w.value,
            domain: w.domain,
            path: w.path,
            // Servers write dates every way RFC 6265 tolerates; what cannot be
            // read is dropped rather than failing the response.
            expires: (!w.expires.is_empty()).then(|| httpdate::parse_http_date(&w.expires).ok()).flatten(),
            max_age: (w.max_age != 0).then_some(w.max_age),
            secure: w.secure,
            http_only: w.http_only,
            same_site: SameSite::parse(&w.same_site),
        }
    }
}

/// Checks a cookie name and value for use in a jar or a `Cookie` header.
///
/// A name is what browsers take one to be (RFC 6265bis, as Chrome and Firefox
/// read `Set-Cookie`): anything but control characters, `;` and `=`, with no
/// space around it. That is wider than an HTTP token: Azure AD B2C, for one,
/// names its session `x-ms-cpim-sso:<tenant>_0`, and the jar stores such a
/// cookie from a response all the same.
pub(crate) fn validate_pair(name: &str, value: &str) -> Result<()> {
    let control = |b: u8| b < 0x20 || b == 0x7f;
    if name.is_empty() || name.trim() != name || name.bytes().any(|b| control(b) || b == b';' || b == b'=') {
        return Err(Error::invalid_input(format!("{name:?} is not a valid cookie name")));
    }
    if value.bytes().any(|b| b < 0x20 || b == 0x7f || b == b';') {
        return Err(Error::invalid_input(format!("the value of cookie {name:?} has a control character or ';' in it")));
    }
    Ok(())
}

/// The last instant an HTTP date can name: 9999-12-31 23:59:59 UTC.
const LAST_HTTP_DATE: u64 = 253_402_300_799;

/// Whether `t` can be written as an HTTP date, which `httpdate` panics on
/// otherwise.
fn representable(t: SystemTime) -> bool {
    t.duration_since(SystemTime::UNIX_EPOCH).is_ok_and(|d| d.as_secs() <= LAST_HTTP_DATE)
}

fn truncate_to_second(t: SystemTime) -> SystemTime {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => SystemTime::UNIX_EPOCH + Duration::from_secs(d.as_secs()),
        Err(_) => SystemTime::UNIX_EPOCH,
    }
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Cookie");
        d.field("name", &self.name).field("value", &self.value);
        if !self.domain.is_empty() {
            d.field("domain", &self.domain);
        }
        if !self.path.is_empty() {
            d.field("path", &self.path);
        }
        if let Some(e) = self.expires {
            // Debug must work for a cookie that would fail validation too.
            match representable(e) {
                true => d.field("expires", &httpdate::fmt_http_date(e)),
                false => d.field("expires", &e),
            };
        }
        if let Some(m) = self.max_age {
            d.field("max_age", &m);
        }
        if self.secure {
            d.field("secure", &true);
        }
        if self.http_only {
            d.field("http_only", &true);
        }
        if let Some(s) = &self.same_site {
            d.field("same_site", s);
        }
        d.finish()
    }
}

/// The library's cookie JSON.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub(crate) struct WireCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    /// RFC 1123, `Mon, 02 Jan 2006 15:04:05 GMT`, or empty.
    expires: String,
    max_age: i64,
    secure: bool,
    http_only: bool,
    same_site: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_the_wire_form() {
        let expires = SystemTime::UNIX_EPOCH + Duration::from_secs(1_900_000_000);
        let c = Cookie::new("id", "v")
            .with_domain(".example.com")
            .with_path("/a")
            .with_expires(expires + Duration::from_millis(400))
            .with_max_age(Duration::from_secs(60))
            .with_secure(true)
            .with_http_only(true)
            .with_same_site(SameSite::Lax);
        let json = serde_json::to_string(&c.to_wire()).unwrap();
        assert!(json.contains(r#""expires":"Sun, 17 Mar 2030 17:46:40 GMT""#), "{json}");
        let back = Cookie::from_wire(serde_json::from_str(&json).unwrap());
        assert_eq!(back, c);
        assert_eq!(back.expires(), Some(expires));
    }

    #[test]
    fn max_age_rounds_a_fraction_of_a_second_up() {
        let age = |d: Duration| Cookie::new("a", "b").with_max_age(d).max_age();
        assert_eq!(age(Duration::ZERO), Some(0), "zero, and only zero, deletes");
        assert_eq!(age(Duration::from_nanos(1)), Some(1));
        assert_eq!(age(Duration::from_millis(500)), Some(1));
        assert_eq!(age(Duration::from_secs(1)), Some(1));
        assert_eq!(age(Duration::from_millis(1500)), Some(2));
        assert_eq!(age(Duration::MAX), Some(i64::MAX));
    }

    #[test]
    fn reads_what_servers_send() {
        let w: WireCookie = serde_json::from_str(
            r#"{"name":"a","value":"b","expires":"Wed, 21-Oct-2015 07:28:00 GMT","same_site":"strict"}"#,
        )
        .unwrap();
        let c = Cookie::from_wire(w);
        assert_eq!(c.same_site(), Some(&SameSite::Strict));
        // The dashed form is not one httpdate reads; it is dropped, not fatal.
        let _ = c.expires();
        let w: WireCookie = serde_json::from_str(r#"{"name":"a","value":"b","same_site":"weird"}"#).unwrap();
        assert_eq!(Cookie::from_wire(w).same_site(), Some(&SameSite::Other("weird".into())));
    }

    #[test]
    fn expiries_past_year_9999_are_refused_not_a_panic() {
        let far = SystemTime::UNIX_EPOCH + Duration::from_secs(LAST_HTTP_DATE + 1);
        let c = Cookie::new("a", "b").with_expires(far);
        assert!(c.validate().unwrap_err().is_invalid_input());
        assert!(format!("{c:?}").contains("expires"));
        let last = Cookie::new("a", "b").with_expires(SystemTime::UNIX_EPOCH + Duration::from_secs(LAST_HTTP_DATE));
        assert!(last.validate().is_ok());
        let _ = serde_json::to_string(&last.to_wire()).unwrap();
    }

    #[test]
    fn rejects_cookies_that_would_break_a_header() {
        assert!(Cookie::new("ok", "fine value").validate().is_ok());
        assert!(Cookie::new("", "v").validate().is_err());
        assert!(Cookie::new(" a", "v").validate().is_err());
        assert!(Cookie::new("a=b", "v").validate().is_err());
        assert!(Cookie::new("a;b", "v").validate().is_err());
        assert!(Cookie::new("a\tb", "v").validate().is_err());
        // Names browsers keep that are no HTTP token.
        assert!(Cookie::new("x-ms-cpim-sso:jbhaub2cprod.onmicrosoft.com_0", "v").validate().is_ok());
        assert!(Cookie::new("a b", "v").validate().is_ok());
        assert!(Cookie::new("a", "v; other=1").validate().is_err());
        assert!(Cookie::new("a", "v\r\nSet-Cookie: x").validate().is_err());
        assert!(Cookie::new("a", "v").with_domain("x;y").validate().is_err());
    }
}
