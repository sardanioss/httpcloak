package session

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// Referer and Sec-Fetch-Site on a redirect chain, as Chrome 158 sent them on
// the same chain: every hop sends the first request's referrer under
// strict-origin-when-cross-origin for its own URL, so a typed navigation sends
// none, and a Sec-Fetch-Site stays "none" or only grows less trusting.
func TestRedirectChainRefererAndFetchSite(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]http.Header{}
	record := func(r *http.Request) {
		mu.Lock()
		seen[r.Host+r.URL.Path] = r.Header.Clone()
		mu.Unlock()
	}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		io.WriteString(w, "ok")
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/same?q=1", 302)
		case "/same":
			http.Redirect(w, r, other.URL+"/far", 302)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	otherHost := strings.TrimPrefix(other.URL, "http://")

	for _, tc := range []struct {
		name              string
		headers           map[string][]string
		sameRef, farRef   string
		sameSite, farSite string
	}{
		// Chrome: no Referer and "none" on every hop.
		{"typed", nil, "", "", "none", "none"},
		// The page's URL on its origin, its origin elsewhere. Two ports of
		// 127.0.0.1 are one site.
		{"from a page", map[string][]string{"Referer": {srv.URL + "/page"}, "Sec-Fetch-Site": {"same-origin"}},
			srv.URL + "/page", srv.URL + "/", "same-origin", "same-site"},
		{"from a page, typed site", map[string][]string{"referer": {srv.URL + "/page"}, "sec-fetch-site": {"none"}},
			srv.URL + "/page", srv.URL + "/", "none", "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			clear(seen)
			mu.Unlock()
			s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})
			if _, err := s.Request(context.Background(), &transport.Request{
				Method: "GET", URL: srv.URL + "/start", Headers: tc.headers,
			}); err != nil {
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
			}
		})
	}
}

func TestFetchSiteRelation(t *testing.T) {
	for _, c := range []struct{ ref, to, want string }{
		{"https://a.example.com/x", "https://a.example.com/y", "same-origin"},
		{"https://a.example.com/x", "https://b.example.com/y", "same-site"},
		{"https://a.example.com/x", "http://a.example.com/y", "cross-site"},
		{"https://example.com/x", "https://other.org/", "cross-site"},
		{"https://127.0.0.1:1/", "https://127.0.0.1:2/", "same-site"},
	} {
		if got := fetchSiteRelation(c.ref, c.to); got != c.want {
			t.Errorf("fetchSiteRelation(%q, %q) = %q, want %q", c.ref, c.to, got, c.want)
		}
	}
}
