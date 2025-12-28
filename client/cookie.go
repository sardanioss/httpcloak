package client

import (
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
	MaxAge   int // seconds
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
	if c.MaxAge > 0 {
		return false // MaxAge takes precedence, handled by creation time
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

	// Path must be a prefix
	if strings.HasPrefix(path, c.Path) {
		// Exact match or followed by /
		if len(path) == len(c.Path) || path[len(c.Path)] == '/' {
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
			if maxAge := parseInt(value); maxAge != 0 || value == "0" {
				cookie.MaxAge = maxAge
			}
		case "secure":
			cookie.Secure = true
		case "httponly":
			cookie.HttpOnly = true
		case "samesite":
			cookie.SameSite = value
		}
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

// parseInt parses an integer, returning 0 on error
func parseInt(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	negative := false
	if s[0] == '-' {
		negative = true
		s = s[1:]
	}

	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}

	if negative {
		return -n
	}
	return n
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
