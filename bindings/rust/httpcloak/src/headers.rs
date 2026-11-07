use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;

/// Response headers: an ordered multimap whose lookups ignore case.
///
/// Names are as the library reports them, which is lowercase. Entries are in
/// the order the server sent them when that is known (HTTP/2 and HTTP/3), and
/// sorted by name otherwise (HTTP/1.1, whose order the library does not keep).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    /// No headers.
    pub fn new() -> Headers {
        Headers::default()
    }

    /// Builds from the library's `name -> values` map, ordering the entries by
    /// `order` (one name per occurrence) where it covers them.
    pub(crate) fn from_map(map: BTreeMap<String, Vec<String>>, order: &[String]) -> Headers {
        let total = map.values().map(Vec::len).sum();
        let mut entries = Vec::with_capacity(total);
        let mut queues: HashMap<&str, VecDeque<&String>> =
            map.iter().map(|(k, v)| (k.as_str(), v.iter().collect())).collect();
        for name in order {
            let key = map.keys().find(|k| k.eq_ignore_ascii_case(name));
            if let Some(value) = key.and_then(|k| queues.get_mut(k.as_str())).and_then(VecDeque::pop_front) {
                entries.push((key.unwrap().clone(), value.clone()));
            }
        }
        // Anything the order did not account for follows, by name.
        for name in map.keys() {
            if let Some(rest) = queues.get_mut(name.as_str()) {
                entries.extend(rest.drain(..).map(|v| (name.clone(), v.clone())));
            }
        }
        Headers { entries }
    }

    /// The first value of header `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Every value of header `name`, in order.
    pub fn get_all<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a str> + 'a {
        let name = name.to_string();
        self.entries.iter().filter(move |(k, _)| k.eq_ignore_ascii_case(&name)).map(|(_, v)| v.as_str())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Every `(name, value)` pair, in order. A name appears once per value.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The number of `(name, value)` pairs.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Converts to an [`http::HeaderMap`]. Fails with
    /// [`ErrorKind::Decode`](crate::ErrorKind::Decode) if a name or value is
    /// not valid there, or there are more headers than a `HeaderMap` holds
    /// (32768), none of which a well-behaved server sends.
    pub fn to_header_map(&self) -> crate::Result<http::HeaderMap> {
        let too_many =
            |_| crate::Error::decode(format!("{} headers are more than an http::HeaderMap holds", self.len()));
        let mut map = http::HeaderMap::try_with_capacity(self.entries.len()).map_err(too_many)?;
        for (k, v) in &self.entries {
            let name = http::HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| crate::Error::decode(format!("{k:?} is not a valid header name: {e}")))?;
            let value = http::HeaderValue::from_str(v)
                .map_err(|e| crate::Error::decode(format!("the value of {k:?} is not a valid header value: {e}")))?;
            map.try_append(name, value).map_err(too_many)?;
        }
        Ok(map)
    }
}

impl fmt::Debug for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = (&'a str, &'a str);
    type IntoIter = Box<dyn ExactSizeIterator<Item = (&'a str, &'a str)> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

/// Whether `name` is a valid header name: an RFC 9110 token.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// A header value as Fetch normalises it: without the spaces and tabs around
/// it. HTTP/1.1 drops them on receipt anyway, and HTTP/2 and HTTP/3 forbid a
/// value that starts or ends with one.
pub(crate) fn normalize_value(value: String) -> String {
    let trimmed = value.trim_matches(|c| c == ' ' || c == '\t');
    if trimmed.len() == value.len() {
        value
    } else {
        trimmed.to_string()
    }
}

/// Whether `value` is a valid header value: no control characters but tab,
/// which keeps CR and LF from splitting it into a second header.
pub(crate) fn valid_value(value: &str) -> bool {
    value.bytes().all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect())).collect()
    }

    #[test]
    fn follows_the_wire_order_and_keeps_repeats() {
        let h = Headers::from_map(
            map(&[("set-cookie", &["a=1", "b=2"]), ("content-type", &["text/html"]), ("date", &["x"])]),
            &["date".into(), "set-cookie".into(), "content-type".into(), "set-cookie".into()],
        );
        let pairs: Vec<_> = h.iter().collect();
        assert_eq!(pairs, [("date", "x"), ("set-cookie", "a=1"), ("content-type", "text/html"), ("set-cookie", "b=2")]);
        assert_eq!(h.get("Set-Cookie"), Some("a=1"));
        assert_eq!(h.get_all("SET-COOKIE").collect::<Vec<_>>(), ["a=1", "b=2"]);
        assert!(h.contains("Date"));
        assert_eq!(h.get("missing"), None);
    }

    #[test]
    fn falls_back_to_name_order_without_a_wire_order() {
        let h = Headers::from_map(map(&[("b", &["2"]), ("a", &["1", "3"])]), &[]);
        assert_eq!(h.iter().collect::<Vec<_>>(), [("a", "1"), ("a", "3"), ("b", "2")]);
    }

    #[test]
    fn an_order_that_disagrees_with_the_map_loses_nothing() {
        let h = Headers::from_map(map(&[("a", &["1"]), ("b", &["2"])]), &["b".into(), "b".into(), "zzz".into()]);
        assert_eq!(h.iter().collect::<Vec<_>>(), [("b", "2"), ("a", "1")]);
    }

    #[test]
    fn converting_too_many_headers_fails_instead_of_panicking() {
        let one = |n: usize, distinct: bool| {
            let map: BTreeMap<String, Vec<String>> = if distinct {
                (0..n).map(|i| (format!("x-{i}"), vec!["a".into()])).collect()
            } else {
                [("x-a".to_string(), vec!["a".to_string(); n])].into_iter().collect()
            };
            Headers::from_map(map, &[]).to_header_map()
        };
        assert_eq!(one(1000, true).unwrap().len(), 1000);
        assert_eq!(one(1000, false).unwrap().len(), 1000);
        for distinct in [true, false] {
            let e = one(40_000, distinct).unwrap_err();
            assert_eq!(e.kind(), crate::ErrorKind::Decode, "{e}");
        }
    }

    #[test]
    fn validates_names_and_values() {
        assert!(valid_name("X-Custom_1"));
        assert!(!valid_name(""));
        assert!(!valid_name("bad name"));
        assert!(!valid_name(":authority"));
        assert!(!valid_name("a\r\nb"));
        assert!(valid_value("text/html; charset=utf-8\tok ünïcode"));
        assert!(!valid_value("a\r\nX-Injected: 1"));
        assert!(!valid_value("a\0b"));
        assert!(!valid_value("a\x7fb"));
    }
}
