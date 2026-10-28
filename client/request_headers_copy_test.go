package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// doOnce copies every header it sends into the request's Headers, so that
// Response.Request shows them. It used to write them into the caller's own
// Request and Headers map. The map grew from the caller's headers to every
// header the request was built with, and a caller reusing it for the next
// request sent that request the first one's Cookie, Referer and Sec-Fetch-*,
// to another host as readily as to the same one. The root package's Client.Do
// passes its caller's map straight through.
//
// Each test asserts what the receiving server saw, through a real send, for
// every browser family the library mimics over HTTP/1.1 and HTTP/2.

var headersCopyPresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

var headersCopyProtocols = []struct {
	name  string
	force Option
}{
	{"h1", WithForceHTTP1()},
	{"h2", WithForceHTTP2()},
}

// headersCopyOrigin records the headers of each request as it arrived, and
// answers a path it has a handler for with that handler and any other path
// with a 200.
type headersCopyOrigin struct {
	url string // https://127.0.0.1:port, no trailing slash

	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	seen     map[string]http.Header
}

func newHeadersCopyOrigin(t *testing.T) *headersCopyOrigin {
	t.Helper()
	o := &headersCopyOrigin{handlers: map[string]http.HandlerFunc{}, seen: map[string]http.Header{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		o.mu.Lock()
		o.seen[r.URL.Path] = r.Header.Clone()
		h := o.handlers[r.URL.Path]
		o.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	o.url = srv.URL
	return o
}

func (o *headersCopyOrigin) handle(path string, h http.HandlerFunc) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.handlers[path] = h
}

// header returns the headers the request for path arrived with, failing the
// test if that path was never requested.
func (o *headersCopyOrigin) header(t *testing.T, path string) http.Header {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	h, ok := o.seen[path]
	if !ok {
		t.Fatalf("%s%s was never requested", o.url, path)
	}
	return h
}

// newHeadersCopyClient returns a client with a cookie jar holding sid=secret
// for origin a, which is 127.0.0.1.
func newHeadersCopyClient(t *testing.T, preset string, a *headersCopyOrigin, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{
		WithInsecureSkipVerify(), // httptest's certificate
		WithPreferIPv4(),         // the servers listen on 127.0.0.1 only
		WithTimeout(10 * time.Second),
	}, opts...)
	c := NewClient(preset, opts...)
	c.EnableCookies()
	t.Cleanup(func() { c.Close() })
	a.handle("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sid=secret; Path=/")
		io.WriteString(w, "ok")
	})
	doHeadersCopy(t, c, &Request{Method: "GET", URL: a.url + "/login"})
	return c
}

func doHeadersCopy(t *testing.T, c *Client, req *Request) *Response {
	t.Helper()
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

// Before, the caller's map below grew to every header the request was built
// with, Cookie and Referer among them, and a Request sent with no Headers came
// back with a map of them.
func TestClientDoLeavesCallerRequestAlone(t *testing.T) {
	for _, preset := range headersCopyPresets {
		for _, p := range headersCopyProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a := newHeadersCopyOrigin(t)
				c := newHeadersCopyClient(t, preset, a, p.force)

				headers := map[string][]string{"X-Probe": {"1"}}
				req := &Request{Method: "GET", URL: a.url + "/page", Referer: a.url + "/", Headers: headers}
				resp := doHeadersCopy(t, c, req)
				if len(headers) != 1 || len(headers["X-Probe"]) != 1 || headers["X-Probe"][0] != "1" {
					t.Errorf("the caller's map is now %v, want only X-Probe: 1", headers)
				}
				if resp.Request == req {
					t.Error("Response.Request is the caller's Request, want a copy")
				}

				// Response.Request still shows every header that went out.
				wire := a.header(t, "/page")
				for _, name := range []string{"User-Agent", "Accept", "Accept-Language", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Referer", "Cookie", "X-Probe"} {
					got, want := resp.Request.GetHeader(name), wire.Get(name)
					if want == "" {
						t.Fatalf("the request went out with no %s", name)
					}
					if got != want {
						t.Errorf("Response.Request has %s %q, but %q went out", name, got, want)
					}
				}

				// The same with no Headers at all, and across a redirect.
				a.handle("/r", func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, "/land", http.StatusFound)
				})
				bare := &Request{Method: "GET", URL: a.url + "/r"}
				doHeadersCopy(t, c, bare)
				if bare.Headers != nil {
					t.Errorf("a Request sent with no Headers came back with %d of them", len(bare.Headers))
				}
			})
		}
	}
}

// Before, the second request below went to localhost with the first one's
// Cookie, which the jar holds for 127.0.0.1 only, its Referer, and
// Sec-Fetch-Site: same-origin.
func TestClientReusedHeaderMap(t *testing.T) {
	for _, preset := range headersCopyPresets {
		for _, p := range headersCopyProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a, b := newHeadersCopyOrigin(t), newHeadersCopyOrigin(t)
				c := newHeadersCopyClient(t, preset, a, p.force)
				bOnLocalhost := strings.Replace(b.url, "127.0.0.1", "localhost", 1)

				headers := map[string][]string{"X-Probe": {"1"}}
				doHeadersCopy(t, c, &Request{Method: "GET", URL: a.url + "/page", Referer: a.url + "/", Headers: headers})
				if got := a.header(t, "/page").Get("Cookie"); got != "sid=secret" {
					t.Fatalf("the first request sent Cookie %q, want the jar's sid=secret", got)
				}

				doHeadersCopy(t, c, &Request{Method: "GET", URL: bOnLocalhost + "/next", Headers: headers})
				next := b.header(t, "/next")
				if v := next.Values("Cookie"); len(v) != 0 {
					t.Errorf("the second request sent Cookie %q; the jar holds none for localhost", v)
				}
				if v := next.Values("Referer"); len(v) != 0 {
					t.Errorf("the second request sent Referer %q; it was sent with none", v)
				}
				if got := next.Get("Sec-Fetch-Site"); got != "none" {
					t.Errorf("the second request sent Sec-Fetch-Site %q, want none for a navigation with no Referer", got)
				}
				if got := next.Get("X-Probe"); got != "1" {
					t.Errorf("the second request sent X-Probe %q, want the caller's 1", got)
				}
			})
		}
	}
}
