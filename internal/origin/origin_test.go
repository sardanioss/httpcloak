package origin

import "testing"

func TestParseFillsInDefaultPorts(t *testing.T) {
	cases := []struct {
		in                 string
		scheme, host, port string
	}{
		{"https://example.com/path", "https", "example.com", "443"},
		{"http://example.com/path", "http", "example.com", "80"},
		{"https://example.com:8443/x", "https", "example.com", "8443"},
		{"http://EXAMPLE.com", "http", "example.com", "80"},
		{"/relative", "", "", ""},
	}
	for _, c := range cases {
		s, h, p := Parse(c.in)
		if s != c.scheme || h != c.host || p != c.port {
			t.Errorf("Parse(%q) = (%q,%q,%q), want (%q,%q,%q)", c.in, s, h, p, c.scheme, c.host, c.port)
		}
	}
}

func TestSame(t *testing.T) {
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
		if got := Same(c.a, c.b); got != c.want {
			t.Errorf("Same(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestDowngrade(t *testing.T) {
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
		if got := Downgrade(c.from, c.to); got != c.want {
			t.Errorf("Downgrade(%q,%q) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

// The policy is Chrome's default, strict-origin-when-cross-origin, applied to
// the referrer the redirected request had: Chrome 156 follows a redirect with
// the page's URL when the hop stays on the page's origin, with the page's
// origin when it leaves it, and never with the URL that redirected.
func TestRedirectReferer(t *testing.T) {
	cases := []struct {
		name, referer, target, want string
	}{
		{"same origin keeps the whole URL", "https://example.com/a/b?q=1", "https://example.com/next", "https://example.com/a/b?q=1"},
		{"another origin gets the origin alone", "https://example.com/a/b?q=1", "https://other.example/next", "https://example.com/"},
		{"another port is another origin", "http://127.0.0.1:8731/start", "http://127.0.0.1:8732/land", "http://127.0.0.1:8731/"},
		{"a non-default port stays in the origin", "https://example.com:8443/x", "https://other.example/", "https://example.com:8443/"},
		{"a default port is left off the origin", "https://example.com:443/x", "https://other.example/", "https://example.com/"},
		{"an http default port is left off the origin", "http://example.com:80/a", "http://other.example/", "http://example.com/"},
		{"https to http sends none", "https://example.com/a", "http://example.com/a", ""},
		{"https to another site's http sends none", "https://example.com/a", "http://other.example/a", ""},
		{"http to https sends the http origin", "http://example.com/a", "https://example.com/a", "http://example.com/"},
		{"an origin-only referrer is kept as it is", "https://example.com/", "https://example.com/deep", "https://example.com/"},
		// Chrome never puts the fragment or credentials in a Referer, and
		// writes the URL without a default port.
		{"the fragment is dropped", "https://example.com/a#section", "https://example.com/b", "https://example.com/a"},
		{"credentials are dropped", "https://user:pass@example.com/a?q=1#f", "https://example.com/b", "https://example.com/a?q=1"},
		{"credentials are dropped from the origin", "https://user:pass@example.com:8443/a#f", "https://other.example/", "https://example.com:8443/"},
		{"a default port is left off the URL", "https://example.com:443/a", "https://example.com/b", "https://example.com/a"},
		{"an http default port is left off the URL", "http://example.com:80/a", "http://example.com/b", "http://example.com/a"},
		{"a non-default port stays in the URL", "http://example.com:8080/a", "http://example.com:8080/b", "http://example.com:8080/a"},
		{"an IPv6 origin keeps its brackets", "http://[::1]:8080/a", "http://example.com/", "http://[::1]:8080/"},
		{"an IPv6 URL keeps its brackets", "https://[::1]:443/a", "https://[::1]/b", "https://[::1]/a"},
		{"a referrer that is no URL sends none", "not a url", "https://example.com/", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RedirectReferer(c.referer, c.target); got != c.want {
				t.Fatalf("RedirectReferer(%q, %q) = %q, want %q", c.referer, c.target, got, c.want)
			}
		})
	}
}
