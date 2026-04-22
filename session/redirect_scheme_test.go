package session

import (
	"testing"
)

// Exercises the scheme-downgrade / cross-origin helpers that gate Referer /
// Authorization stripping in requestWithRedirects. See issue #52.

func TestParseOriginDefaultPorts(t *testing.T) {
	cases := []struct {
		in               string
		wantScheme, host string
		wantPort         string
	}{
		{"https://example.com/path", "https", "example.com", "443"},
		{"http://example.com/path", "http", "example.com", "80"},
		{"https://example.com:8443/x", "https", "example.com", "8443"},
		{"http://EXAMPLE.com", "http", "example.com", "80"},
	}
	for _, c := range cases {
		s, h, p := parseOrigin(c.in)
		if s != c.wantScheme || h != c.host || p != c.wantPort {
			t.Errorf("parseOrigin(%q) = (%q,%q,%q), want (%q,%q,%q)",
				c.in, s, h, p, c.wantScheme, c.host, c.wantPort)
		}
	}
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"https://a.com/x", "https://a.com/y", true},
		{"https://a.com/x", "https://a.com:443/y", true}, // default port normalizes
		{"http://a.com/x", "http://a.com:80/y", true},
		{"https://a.com/x", "http://a.com/x", false},       // scheme differs
		{"https://a.com/x", "https://b.com/x", false},      // host differs
		{"https://a.com:8443/x", "https://a.com/x", false}, // port differs
	}
	for _, c := range cases {
		if got := sameOrigin(c.a, c.b); got != c.want {
			t.Errorf("sameOrigin(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestIsSchemeDowngrade(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		{"https://a.com/x", "http://a.com/x", true},
		{"https://a.com/x", "http://b.com/x", true},  // any https→http
		{"http://a.com/x", "https://a.com/x", false}, // upgrade
		{"https://a.com/x", "https://b.com/x", false},
		{"http://a.com/x", "http://b.com/x", false},
	}
	for _, c := range cases {
		if got := isSchemeDowngrade(c.from, c.to); got != c.want {
			t.Errorf("isSchemeDowngrade(%q,%q) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}
