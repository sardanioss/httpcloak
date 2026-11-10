package transport

import (
	"context"
	stdhttp "net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

// A request with no body says "content-length: 0" on the methods its browser
// says it on, which fetch() and XMLHttpRequest show on every method: Chrome
// 156 and Firefox 159 on a POST and a PUT alone, Safari 26.6 on a PATCH, a
// DELETE and an OPTIONS as well, none of them on a GET or a HEAD. Every preset
// used to have net/http's rule on HTTP/1.1 and HTTP/2 (POST, PUT and PATCH),
// so a Chrome sent a length Chrome does not and a Safari left two out.
func TestEmptyBodyDeclaresItsLengthOnTheBrowsersMethods(t *testing.T) {
	var mu sync.Mutex
	seen := map[string][]string{}
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		mu.Lock()
		seen[r.Proto+" "+r.Method] = r.Header.Values("Content-Length")
		mu.Unlock()
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	chrome := []string{"POST", "PUT"}
	safari := []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	for _, c := range []struct {
		preset   string
		declares []string
	}{
		{"chrome-latest", chrome},
		{"chrome-latest-android", chrome},
		{"firefox-latest", chrome},
		{"safari-latest", safari},
		{"safari-latest-ios", safari},
		// Chrome on iOS is WebKit over Apple's network stack, and its newest
		// presets inherit the rule from the one they are based on.
		{"chrome-latest-ios", safari},
	} {
		for _, p := range []struct {
			protocol Protocol
			proto    string
		}{{ProtocolHTTP1, "HTTP/1.1"}, {ProtocolHTTP2, "HTTP/2.0"}} {
			tr := NewTransport(c.preset)
			tr.SetInsecureSkipVerify(true)
			tr.SetProtocol(p.protocol)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			for _, stream := range []bool{false, true} {
				for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
					if stream {
						resp, err := tr.DoStream(ctx, &Request{Method: method, URL: srv.URL})
						if err != nil {
							t.Fatalf("%s %s DoStream %s: %v", c.preset, p.proto, method, err)
						}
						resp.ReadAll()
					} else if _, err := tr.Do(ctx, &Request{Method: method, URL: srv.URL}); err != nil {
						t.Fatalf("%s %s Do %s: %v", c.preset, p.proto, method, err)
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
						t.Errorf("%s %s stream=%v %s: content-length %q, want %q", c.preset, p.proto, stream, method, got, want)
					}
				}
			}
			cancel()
			tr.Close()
		}
	}
}
