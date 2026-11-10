package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

// The client used to give every body-less POST, PUT and PATCH an explicit
// "Content-Length: 0" header before the transport saw it, which is net/http's
// rule and no browser's. Which methods say it is the preset's to know (see
// TestEmptyBodyDeclaresItsLengthOnTheBrowsersMethods in transport), so a
// Chrome's PATCH goes without and a Safari's DELETE and OPTIONS carry it.
func TestClientLeavesAnEmptyBodysLengthToThePreset(t *testing.T) {
	var mu sync.Mutex
	seen := map[string][]string{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Proto+" "+r.Method] = r.Header.Values("Content-Length")
		mu.Unlock()
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	for _, c := range []struct {
		preset   string
		declares []string
	}{
		{"chrome-latest", []string{"POST", "PUT"}},
		{"safari-latest-ios", []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}},
	} {
		for _, p := range []struct {
			force Option
			proto string
		}{{WithForceHTTP1(), "HTTP/1.1"}, {WithForceHTTP2(), "HTTP/2.0"}} {
			cl := NewClient(c.preset, WithInsecureSkipVerify(), p.force)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
				if _, err := cl.Do(ctx, &Request{Method: method, URL: srv.URL}); err != nil {
					t.Fatalf("%s %s %s: %v", c.preset, p.proto, method, err)
				}
				mu.Lock()
				got, reached := seen[p.proto+" "+method]
				delete(seen, p.proto+" "+method)
				mu.Unlock()
				if !reached {
					t.Fatalf("%s: no %s %s reached the server", c.preset, p.proto, method)
				}
				var want []string
				if slices.Contains(c.declares, method) {
					want = []string{"0"}
				}
				if !slices.Equal(got, want) {
					t.Errorf("%s %s %s: content-length %q, want %q", c.preset, p.proto, method, got, want)
				}
			}
			cancel()
			cl.Close()
		}
	}
}
