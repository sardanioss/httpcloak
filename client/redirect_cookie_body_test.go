package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The client follows redirects in its own loop, and each hop started from the
// headers the request before it had sent, which doOnce copies into
// req.Headers for debugging. Two kinds of them must not be carried.
//
// The Cookie a request sent belongs to its own URL. Carried, it reached a hop
// to another host although the jar held nothing for that host, and a cookie
// the 3xx had just deleted came back on the hop. A browser builds each hop's
// Cookie from its cookie store, for the hop's URL, as the session does. A
// Cookie header the caller set stands in for a jar, so it follows the hops
// that stay on its origin.
//
// A hop that turns into a GET has no body, so nothing may describe one. The GET
// after a form POST's 303 kept the POST's Content-Length and Content-Type, and
// an HTTP/1.1 server waited for a body that never came. Fetch's HTTP-redirect
// fetch drops the request-body-header names when it changes the method to GET,
// and keeps the body whenever it keeps the method.
//
// Each test asserts what the receiving server saw, through a real send.

// The redirect code is the same for every preset, but each preset builds its
// own header block, so every browser family the library mimics is covered.
var hopCarryPresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

var hopCarryProtocols = []struct {
	name  string
	force Option
}{
	{"h1", WithForceHTTP1()},
	{"h2", WithForceHTTP2()},
}

// hopCarryOrigin is one origin of a redirect chain. It records each request
// as it arrived, and answers a path it has a handler for with that handler and
// any other path with a 200.
type hopCarryOrigin struct {
	url string // https://127.0.0.1:port, no trailing slash

	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	seen     map[string]hopCarryHit
}

type hopCarryHit struct {
	method string
	header http.Header
	body   string
}

func newHopCarryOrigin(t *testing.T) *hopCarryOrigin {
	t.Helper()
	o := &hopCarryOrigin{handlers: map[string]http.HandlerFunc{}, seen: map[string]hopCarryHit{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		o.mu.Lock()
		o.seen[r.URL.Path] = hopCarryHit{method: r.Method, header: r.Header.Clone(), body: string(body)}
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

// onLocalhost is the same server under the name localhost. To the cookie jar,
// 127.0.0.1 and localhost are two hosts.
func (o *hopCarryOrigin) onLocalhost() string {
	return strings.Replace(o.url, "127.0.0.1", "localhost", 1)
}

func (o *hopCarryOrigin) handle(path string, h http.HandlerFunc) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.handlers[path] = h
}

// redirect answers path with status and location, setting each of setCookie.
func (o *hopCarryOrigin) redirect(path string, status int, location string, setCookie ...string) {
	o.handle(path, func(w http.ResponseWriter, r *http.Request) {
		for _, c := range setCookie {
			w.Header().Add("Set-Cookie", c)
		}
		w.Header().Set("Location", location)
		w.WriteHeader(status)
	})
}

// hit returns the request for path as it arrived, failing the test if that
// path was never requested.
func (o *hopCarryOrigin) hit(t *testing.T, path string) hopCarryHit {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	h, ok := o.seen[path]
	if !ok {
		t.Fatalf("%s%s was never requested", o.url, path)
	}
	return h
}

func newHopCarryClient(t *testing.T, preset string, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{
		WithInsecureSkipVerify(), // httptest's certificate
		WithPreferIPv4(),         // the servers listen on 127.0.0.1 only
		WithTimeout(10 * time.Second),
	}, opts...)
	c := NewClient(preset, opts...)
	c.EnableCookies()
	t.Cleanup(func() { c.Close() })
	return c
}

// followHops sends req and follows its redirects. A hop that describes a body
// it does not have fails here, because an HTTP/1.1 server waits for the body
// until the client gives up.
func followHops(t *testing.T, c *Client, req *Request) {
	t.Helper()
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
}

// Before, the hop to localhost below sent "sid=secret", which the jar holds
// for 127.0.0.1 only, and the hop after the logout sent the cookie the 3xx had
// just deleted.
func TestClientRedirectHopCookie(t *testing.T) {
	for _, preset := range hopCarryPresets {
		for _, p := range hopCarryProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a, b := newHopCarryOrigin(t), newHopCarryOrigin(t)
				c := newHopCarryClient(t, preset, p.force)
				a.handle("/login", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Set-Cookie", "sid=secret; Path=/")
					io.WriteString(w, "ok")
				})
				followHops(t, c, &Request{Method: "GET", URL: a.url + "/login"})

				// Another host: the jar holds nothing for it.
				a.redirect("/away", 302, b.onLocalhost()+"/land")
				followHops(t, c, &Request{Method: "GET", URL: a.url + "/away"})
				if got := a.hit(t, "/away").header.Get("Cookie"); got != "sid=secret" {
					t.Fatalf("the first request sent Cookie %q, want the jar's sid=secret", got)
				}
				if got := b.hit(t, "/land").header.Values("Cookie"); len(got) != 0 {
					t.Errorf("the hop to localhost sent Cookie %q; the jar holds none for it", got)
				}

				// The same host, after a 3xx that deletes the cookie.
				a.redirect("/logout", 302, a.url+"/bye", "sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
				followHops(t, c, &Request{Method: "GET", URL: a.url + "/logout"})
				if got := a.hit(t, "/logout").header.Get("Cookie"); got != "sid=secret" {
					t.Fatalf("the logout request sent Cookie %q, want sid=secret", got)
				}
				if got := a.hit(t, "/bye").header.Values("Cookie"); len(got) != 0 {
					t.Errorf("the hop after the logout sent Cookie %q; the 3xx deleted it", got)
				}

				// A cookie the 3xx sets goes out on the hop, from the jar.
				a.redirect("/hello", 302, a.url+"/home", "hop=1; Path=/")
				followHops(t, c, &Request{Method: "GET", URL: a.url + "/hello"})
				if got := a.hit(t, "/home").header.Values("Cookie"); len(got) != 1 || got[0] != "hop=1" {
					t.Errorf("the hop sent Cookie %q, want the jar's hop=1", got)
				}
			})
		}
	}
}

// A Cookie header the caller set goes on every hop that stays on the first
// request's origin, as Authorization does, so a client without a jar keeps its
// login across a same-origin redirect. The first hop off the origin drops it,
// and no later hop gets it back, even one back on that origin. Before, it went
// to every hop, another host's included.
func TestClientRedirectHopCallerCookie(t *testing.T) {
	for _, preset := range hopCarryPresets {
		for _, p := range hopCarryProtocols {
			for _, jar := range []bool{true, false} {
				t.Run(preset+"/"+p.name+"/jar="+strconv.FormatBool(jar), func(t *testing.T) {
					a, b := newHopCarryOrigin(t), newHopCarryOrigin(t)
					c := newHopCarryClient(t, preset, p.force)
					if !jar {
						c.DisableCookies()
					}
					a.redirect("/away", 302, b.onLocalhost()+"/land")
					a.redirect("/stay", 302, a.url+"/home")
					a.redirect("/out", 302, b.onLocalhost()+"/turn")
					b.redirect("/turn", 302, a.url+"/back")
					a.redirect("/login", 302, a.url+"/account")

					for _, path := range []string{"/away", "/stay", "/out"} {
						followHops(t, c, &Request{Method: "GET", URL: a.url + path,
							Headers: map[string][]string{"Cookie": {"manual=1"}}})
						if got := a.hit(t, path).header.Get("Cookie"); got != "manual=1" {
							t.Fatalf("%s sent Cookie %q, want the caller's manual=1", path, got)
						}
					}
					// A form login's POST, answered with a 302 to the account page.
					followHops(t, c, &Request{Method: "POST", URL: a.url + "/login", Body: strings.NewReader("u=1"),
						Headers: map[string][]string{"cookie": {"session=1"}, "Content-Type": {"application/x-www-form-urlencoded"}}})

					for _, h := range []struct {
						o    *hopCarryOrigin
						path string
						want string // "" for no Cookie
					}{
						{b, "/land", ""},
						{a, "/home", "manual=1"},
						{b, "/turn", ""},
						{a, "/back", ""}, // back on the first origin, after leaving it
						{a, "/account", "session=1"},
					} {
						got := h.o.hit(t, h.path).header.Values("Cookie")
						if h.want == "" && len(got) != 0 {
							t.Errorf("the hop to %s sent Cookie %q, want none", h.path, got)
						}
						if h.want != "" && (len(got) != 1 || got[0] != h.want) {
							t.Errorf("the hop to %s sent Cookie %q, want the caller's %s", h.path, got, h.want)
						}
					}
				})
			}
		}
	}
}

// bodyHeaders are the headers that describe a request body: Fetch's
// request-body-header names, plus Content-Length.
var bodyHeaders = []string{"Content-Type", "Content-Length", "Content-Encoding", "Content-Language", "Content-Location"}

// A hop keeps the body, and the headers that describe it, exactly when it
// keeps the method. Before, a POST answered with 301, 302 or 303 sent its GET
// with the POST's Content-Length and Content-Type, and over HTTP/1.1 the
// server waited for a body until the client gave up. A PUT or PATCH answered
// with 301 or 302 went out again with no body.
func TestClientRedirectHopBody(t *testing.T) {
	const body = "a=1&b=22"
	cases := []struct {
		method     string
		status     int
		wantMethod string
	}{
		{"POST", 303, "GET"},
		{"POST", 302, "GET"},
		{"POST", 301, "GET"},
		{"PUT", 303, "GET"},
		{"PUT", 302, "PUT"},
		{"PATCH", 301, "PATCH"},
		{"POST", 307, "POST"},
		{"POST", 308, "POST"},
	}
	for _, preset := range hopCarryPresets {
		for _, p := range hopCarryProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a := newHopCarryOrigin(t)
				c := newHopCarryClient(t, preset, p.force)
				for i, tc := range cases {
					from, to := "/form"+strconv.Itoa(i), "/after"+strconv.Itoa(i)
					a.redirect(from, tc.status, a.url+to)
					followHops(t, c, &Request{Method: tc.method, URL: a.url + from, Body: strings.NewReader(body),
						Headers: map[string][]string{
							"Content-Type":     {"application/x-www-form-urlencoded"},
							"Content-Language": {"en-US"},
							"Content-Location": {"/form"},
						}})
					name := tc.method + " answered with " + strconv.Itoa(tc.status)
					if got := a.hit(t, from).body; got != body {
						t.Fatalf("%s: the first request sent body %q, want %q", name, got, body)
					}
					hop := a.hit(t, to)
					if hop.method != tc.wantMethod {
						t.Errorf("%s: the hop went out as %s, want %s", name, hop.method, tc.wantMethod)
					}
					if tc.wantMethod == "GET" {
						if hop.body != "" {
							t.Errorf("%s: the GET sent body %q", name, hop.body)
						}
						for _, h := range bodyHeaders {
							if v := hop.header.Values(h); len(v) != 0 {
								t.Errorf("%s: the GET sent %s %q", name, h, v)
							}
						}
						continue
					}
					if hop.body != body {
						t.Errorf("%s: the hop sent body %q, want %q", name, hop.body, body)
					}
					if got := hop.header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
						t.Errorf("%s: the hop sent Content-Type %q", name, got)
					}
					if got := hop.header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
						t.Errorf("%s: the hop sent Content-Length %q, want %d", name, got, len(body))
					}
				}
			})
		}
	}
}

// A fetch() POST answered with 303 is still a fetch() on the GET: Chrome 156
// and Firefox 159 sent cors and empty on both hops. The client sniffs a POST
// with a JSON body as cors, and the hop must not turn into a navigation now
// that the GET goes without the POST's Content-Type.
func TestClientRedirectHopBodyKeepsFetchShape(t *testing.T) {
	for _, preset := range hopCarryPresets {
		for _, p := range hopCarryProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a := newHopCarryOrigin(t)
				c := newHopCarryClient(t, preset, p.force)
				a.redirect("/api", 303, a.url+"/api-after")
				followHops(t, c, &Request{Method: "POST", URL: a.url + "/api", Body: strings.NewReader(`{"a":1}`),
					Referer: a.url + "/page",
					Headers: map[string][]string{"Content-Type": {"application/json"}}})
				first, hop := a.hit(t, "/api"), a.hit(t, "/api-after")
				for _, h := range []string{"Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
					if first.header.Get(h) == "" || hop.header.Get(h) != first.header.Get(h) {
						t.Errorf("%s: the POST sent %q and the GET %q, want the same", h, first.header.Get(h), hop.header.Get(h))
					}
				}
				if got := hop.header.Get("Sec-Fetch-Mode"); got != "cors" {
					t.Errorf("the GET went out as Sec-Fetch-Mode %q, want cors", got)
				}
				if v := hop.header.Values("Content-Type"); len(v) != 0 {
					t.Errorf("the GET sent Content-Type %q", v)
				}
			})
		}
	}
}

// WithTLSOnly builds no headers of its own, but the jar and the redirect loop
// are the same, and so is the carry.
func TestClientRedirectHopCookieBodyTLSOnly(t *testing.T) {
	for _, preset := range hopCarryPresets {
		for _, p := range hopCarryProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a, b := newHopCarryOrigin(t), newHopCarryOrigin(t)
				c := newHopCarryClient(t, preset, p.force, WithTLSOnly())
				a.handle("/login", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Set-Cookie", "sid=secret; Path=/")
					io.WriteString(w, "ok")
				})
				followHops(t, c, &Request{Method: "GET", URL: a.url + "/login"})

				a.redirect("/away", 302, b.onLocalhost()+"/land")
				followHops(t, c, &Request{Method: "GET", URL: a.url + "/away"})
				if got := b.hit(t, "/land").header.Values("Cookie"); len(got) != 0 {
					t.Errorf("the hop to localhost sent Cookie %q; the jar holds none for it", got)
				}

				a.redirect("/form", 303, a.url+"/after")
				followHops(t, c, &Request{Method: "POST", URL: a.url + "/form", Body: strings.NewReader("a=1"),
					Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}})
				hop := a.hit(t, "/after")
				for _, h := range bodyHeaders {
					if v := hop.header.Values(h); len(v) != 0 {
						t.Errorf("the GET after the 303 sent %s %q", h, v)
					}
				}
			})
		}
	}
}
