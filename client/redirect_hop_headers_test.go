package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A redirect and a Digest retry read what is left of the response before the
// next request, so HTTP/1.1 sends it on the same connection.
func TestRedirectAndDigestRetryReuseTheConnection(t *testing.T) {
	var conns atomic.Int32
	body := strings.Repeat("x", 4096)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r1", "/r2":
			w.Header().Set("Location", r.URL.Path+"x")
			w.WriteHeader(302)
			io.WriteString(w, body)
		case "/digest":
			if r.Header.Get("Authorization") == "" {
				w.Header().Set("WWW-Authenticate", `Digest realm="t", nonce="abc", qop="auth"`)
				w.WriteHeader(401)
				io.WriteString(w, body)
				return
			}
			io.WriteString(w, "ok")
		default:
			io.WriteString(w, "ok")
		}
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()

	for _, tc := range []struct{ path string }{{"/r1"}, {"/digest"}} {
		t.Run(tc.path, func(t *testing.T) {
			c := NewClient("chrome-latest", WithInsecureSkipVerify(), WithPreferIPv4(), WithTimeout(10*time.Second), WithForceHTTP1())
			defer c.Close()
			if tc.path == "/digest" {
				c.SetAuth(NewDigestAuth("u", "p"))
			}
			before := conns.Load()
			resp, err := c.Do(context.Background(), &Request{Method: "GET", URL: srv.URL + tc.path})
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			if n := conns.Load() - before; n != 1 {
				t.Errorf("%s took %d connections, want 1", tc.path, n)
			}
		})
	}
}

// A redirect hop carries the headers the caller set and nothing the request
// generated. Its Referer and Sec-Fetch-Site follow the chain as Chrome 158
// sent them on the same chain: the first request's referrer on every hop,
// under strict-origin-when-cross-origin for the hop's URL, and a
// Sec-Fetch-Site that stays "none" for a typed navigation and otherwise only
// grows less trusting.
func TestRedirectHopCarriesOnlyCallerHeaders(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]http.Header{}
	record := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Host+r.URL.Path] = r.Header.Clone()
		mu.Unlock()
	}
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(w, r)
		io.WriteString(w, "ok")
	}))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(w, r)
		switch r.URL.Path {
		case "/start":
			w.Header().Set("Location", "/same?q=1")
			w.WriteHeader(302)
		case "/same":
			w.Header().Set("Location", other.URL+"/far")
			w.WriteHeader(302)
		default:
			io.WriteString(w, "ok")
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	otherHost := strings.TrimPrefix(other.URL, "https://")

	for _, tc := range []struct {
		name, referer     string
		sameRef, farRef   string
		sameSite, farSite string
	}{
		// Typed: Chrome sent no Referer and "none" on all three requests.
		{"typed", "", "", "", "none", "none"},
		// From a page: the page's URL on the same origin, its origin on
		// the other one, and the site relation grows along the chain. Two
		// ports of 127.0.0.1 are one site.
		{"from a page", srv.URL + "/page#frag", srv.URL + "/page", srv.URL + "/", "same-origin", "same-site"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			clear(seen)
			mu.Unlock()
			c := NewClient("chrome-latest", WithInsecureSkipVerify(), WithPreferIPv4(), WithTimeout(10*time.Second), WithForceHTTP1())
			defer c.Close()
			_, err := c.Do(context.Background(), &Request{
				Method:  "GET",
				URL:     srv.URL + "/start#frag",
				Referer: tc.referer,
				Headers: map[string][]string{"X-Probe": {"1"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			same, far := seen[host+"/same"], seen[otherHost+"/far"]
			if same == nil || far == nil {
				t.Fatalf("hops not seen: %v", seen)
			}
			for _, h := range []struct {
				name          string
				hdr           http.Header
				referer, site string
			}{{"same-origin hop", same, tc.sameRef, tc.sameSite}, {"cross-origin hop", far, tc.farRef, tc.farSite}} {
				if got := h.hdr.Values("Referer"); (h.referer == "" && len(got) != 0) || (h.referer != "" && (len(got) != 1 || got[0] != h.referer)) {
					t.Errorf("%s: Referer %q, want %q", h.name, got, h.referer)
				}
				if got := h.hdr.Values("Sec-Fetch-Site"); len(got) != 1 || got[0] != h.site {
					t.Errorf("%s: Sec-Fetch-Site %q, want %q", h.name, got, h.site)
				}
				if h.hdr.Get("X-Probe") != "1" {
					t.Errorf("%s lost the caller's X-Probe", h.name)
				}
			}
		})
	}
}

func TestJoinURLResolvesLikeRFC3986(t *testing.T) {
	for _, c := range []struct{ base, ref, want string }{
		{"https://h/a/b?x=1#f", "/n?q=1", "https://h/n?q=1"},
		{"https://h/a/b", "c?q=1#g", "https://h/a/c?q=1#g"},
		{"https://h/a/b", "../c", "https://h/c"},
		{"https://h/a/b", "//o/p", "https://o/p"},
		{"https://h/a/b", "http://o/p", "http://o/p"},
		{"https://h/a/b", "?q=2", "https://h/a/b?q=2"},
		{"https://h/a/b", "", "https://h/a/b"},
		{"https://h/a/b", "/100%off", "https://h/100%25off"},
	} {
		if got := JoinURL(c.base, c.ref); got != c.want {
			t.Errorf("JoinURL(%q, %q) = %q, want %q", c.base, c.ref, got, c.want)
		}
	}
}
