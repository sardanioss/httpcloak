package client

import (
	"math"
	"net/url"
	"strings"
	"time"
)

// Cookie represents an HTTP cookie
type Cookie struct {
	Name     string
	Value    string
	Domain   string
	Path     string
	Expires  time.Time
	MaxAge   int // seconds; 0 means no Max-Age, -1 a Max-Age of 0 or less
	Secure   bool
	HttpOnly bool
	SameSite string // "Strict", "Lax", "None"
	Raw      string // original Set-Cookie header
}

// IsExpired returns true if the cookie has expired
func (c *Cookie) IsExpired() bool {
	if c.MaxAge < 0 {
		return true
	}
	if c.Expires.IsZero() {
		return false // Session cookie
	}
	return time.Now().After(c.Expires)
}

// String returns the cookie in "name=value" format for the Cookie header
func (c *Cookie) String() string {
	return c.Name + "=" + c.Value
}

// Matches returns true if this cookie should be sent for the given URL
func (c *Cookie) Matches(u *url.URL) bool {
	// Check domain
	if !c.matchesDomain(u.Host) {
		return false
	}

	// Check path
	if !c.matchesPath(u.Path) {
		return false
	}

	// Check secure
	if c.Secure && u.Scheme != "https" {
		return false
	}

	return true
}

func (c *Cookie) matchesDomain(host string) bool {
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	host = strings.ToLower(host)
	domain := strings.ToLower(c.Domain)

	// Exact match
	if host == domain {
		return true
	}

	// Domain cookie (starts with .)
	if strings.HasPrefix(domain, ".") {
		// host must end with domain or equal domain without leading dot
		if host == domain[1:] {
			return true
		}
		if strings.HasSuffix(host, domain) {
			return true
		}
	}

	return false
}

func (c *Cookie) matchesPath(path string) bool {
	if c.Path == "" || c.Path == "/" {
		return true
	}
	if path == "" {
		path = "/"
	}

	// Path must be a prefix (RFC 6265 Section 5.1.4)
	if strings.HasPrefix(path, c.Path) {
		// Exact match, followed by /, or cookie path already ends with /
		if len(path) == len(c.Path) || path[len(c.Path)] == '/' || c.Path[len(c.Path)-1] == '/' {
			return true
		}
	}

	return false
}

// ParseSetCookie parses a Set-Cookie header value into a Cookie
func ParseSetCookie(header string, requestURL *url.URL) *Cookie {
	if header == "" {
		return nil
	}

	cookie := &Cookie{
		Raw:  header,
		Path: "/",
	}

	// Get default domain from request URL
	if requestURL != nil {
		host := requestURL.Host
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}
		cookie.Domain = host
	}

	parts := strings.Split(header, ";")
	if len(parts) == 0 {
		return nil
	}

	// First part is name=value
	nameValue := strings.TrimSpace(parts[0])
	eqIdx := strings.Index(nameValue, "=")
	if eqIdx == -1 {
		return nil
	}

	cookie.Name = strings.TrimSpace(nameValue[:eqIdx])
	cookie.Value = strings.TrimSpace(nameValue[eqIdx+1:])

	// Parse attributes
	for i := 1; i < len(parts); i++ {
		attr := strings.TrimSpace(parts[i])
		if attr == "" {
			continue
		}

		var name, value string
		if eqIdx := strings.Index(attr, "="); eqIdx != -1 {
			name = strings.ToLower(strings.TrimSpace(attr[:eqIdx]))
			value = strings.TrimSpace(attr[eqIdx+1:])
		} else {
			name = strings.ToLower(attr)
		}

		switch name {
		case "domain":
			if value != "" {
				// Normalize domain
				value = strings.ToLower(value)
				if !strings.HasPrefix(value, ".") {
					value = "." + value
				}
				cookie.Domain = value
			}
		case "path":
			if value != "" {
				cookie.Path = value
			}
		case "expires":
			if t, err := parseExpires(value); err == nil {
				cookie.Expires = t
			}
		case "max-age":
			// RFC 6265 Section 5.2.2: a Max-Age of 0 or less expires the
			// cookie, and MaxAge 0 means none, so it is stored as -1. As in
			// Chrome and Firefox, the last Max-Age decides, and an invalid
			// one leaves none.
			maxAge, ok := parseInt(value)
			if !ok {
				maxAge = 0
			} else if maxAge <= 0 {
				maxAge = -1
			}
			cookie.MaxAge = maxAge
		case "secure":
			cookie.Secure = true
		case "httponly":
			cookie.HttpOnly = true
		case "samesite":
			cookie.SameSite = value
		}
	}

	// RFC 6265 Section 5.3: convert Max-Age to absolute Expires time
	// Max-Age takes precedence over Expires when both are present; a
	// negative MaxAge does too, since every expiry check tests it first
	if cookie.MaxAge > 0 {
		// A Max-Age longer than a time.Duration can hold gets the longest one
		lifetime := time.Duration(math.MaxInt64)
		if int64(cookie.MaxAge) < int64(lifetime/time.Second) {
			lifetime = time.Duration(cookie.MaxAge) * time.Second
		}
		cookie.Expires = time.Now().Add(lifetime)
	}

	return cookie
}

// parseExpires parses various date formats used in cookies
func parseExpires(s string) (time.Time, error) {
	formats := []string{
		time.RFC1123,
		time.RFC1123Z,
		"Mon, 02-Jan-2006 15:04:05 MST",
		"Mon, 02 Jan 2006 15:04:05 MST",
		"Monday, 02-Jan-06 15:04:05 MST",
		"Mon Jan 2 15:04:05 2006",
	}

	s = strings.TrimSpace(s)
	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, errorf("unable to parse expires: %s", s)
}

// parseInt parses a decimal integer with an optional leading "-". ok is false
// for anything else, such as "", "-", "+1" or "1abc". A value too large for an
// int stops at the largest one, so that it cannot wrap around
func parseInt(s string) (int, bool) {
	s = strings.TrimSpace(s)

	negative := false
	if strings.HasPrefix(s, "-") {
		negative = true
		s = s[1:]
	}
	if s == "" {
		return 0, false
	}

	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		if d := int(c - '0'); n <= (math.MaxInt-d)/10 {
			n = n*10 + d
		} else {
			n = math.MaxInt
		}
	}

	if negative {
		return -n, true
	}
	return n, true
}

// errorf creates an error with a formatted message
func errorf(format string, args ...interface{}) error {
	return &cookieError{msg: format}
}

type cookieError struct {
	msg string
}

func (e *cookieError) Error() string {
	return e.msg
}
