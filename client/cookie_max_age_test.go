package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// A Set-Cookie whose Max-Age is 0 or less deletes the cookie (RFC 6265 Section
// 5.2.2). The parse stored "0" as MaxAge 0, which means no Max-Age, so the jar
// kept the cookie as a session cookie with its new value, and the next request
// sent "Cookie: sid=". It now stores -1, which every expiry check reads as
// expired.
//
// Each case below was captured in Chrome 156 and Firefox 159, which agree on
// all of them. Max-Age wins over Expires, whichever of the two is in the past.
// With several Max-Age attributes the last one decides, and an invalid one
// leaves none, so Expires decides. A Max-Age too large for an int, or for a
// time.Duration, keeps the cookie; it used to wrap around and could delete it.

const (
	maxAgeFuture = "Fri, 01 Jan 2100 00:00:00 GMT"
	maxAgePast   = "Thu, 01 Jan 1970 00:00:00 GMT"
)

var maxAgeCases = []struct {
	attrs   string // after "sid=x; Path=/; "
	maxAge  int    // MaxAge as parsed
	deleted bool
}{
	{"Max-Age=0", -1, true},
	{"Max-Age=00", -1, true},
	{"Max-Age=-0", -1, true},
	{"Max-Age=-1", -1, true},
	{"Max-Age = 0", -1, true},
	{"Max-Age=0; Expires=" + maxAgeFuture, -1, true},
	{"Max-Age=3600; Expires=" + maxAgePast, 3600, false},
	{"Max-Age=3600; Max-Age=0", -1, true},
	{"Max-Age=0; Max-Age=3600", 3600, false},
	{"Max-Age=0; Max-Age=abc", 0, false},
	{"Max-Age=abc", 0, false},
	{"Max-Age=", 0, false},
	{"Max-Age=1abc", 0, false},
	{"Max-Age=-99999999999999999999", -1, true},
}

// Too large for an int on 32-bit, for a time.Duration on 64-bit, and for an
// int64. Each lasts at least the 68 years a 32-bit int holds.
var maxAgeHuge = []string{"3000000000", "10000000000", "99999999999999999999"}

func TestParseSetCookieMaxAge(t *testing.T) {
	u := mustParseURL(t, "https://example.com/")
	for _, tc := range maxAgeCases {
		t.Run(tc.attrs, func(t *testing.T) {
			before := time.Now()
			c := ParseSetCookie("sid=x; Path=/; "+tc.attrs, u)
			if c == nil {
				t.Fatal("ParseSetCookie returned nil")
			}
			if c.MaxAge != tc.maxAge {
				t.Errorf("MaxAge = %d, want %d", c.MaxAge, tc.maxAge)
			}
			if got := c.IsExpired(); got != tc.deleted {
				t.Errorf("IsExpired() = %v, want %v", got, tc.deleted)
			}
			if tc.maxAge > 0 {
				lo, hi := before.Add(time.Hour), time.Now().Add(time.Hour)
				if c.Expires.Before(lo) || c.Expires.After(hi) {
					t.Errorf("Expires = %v, want an hour from now", c.Expires)
				}
			}
		})
	}
}

// SetCookies, Cookies and ClearExpired each test expiry on their own. All three
// must read the parsed cookie the same way.
func TestCookieJarMaxAge(t *testing.T) {
	u := mustParseURL(t, "https://example.com/")
	for _, tc := range maxAgeCases {
		t.Run(tc.attrs, func(t *testing.T) {
			want := "sid=x"
			if tc.deleted {
				want = ""
			}

			// SetCookies replaces the stored cookie, or deletes it.
			jar := NewCookieJar()
			jar.SetCookiesFromHeaderList(u, []string{"sid=secret; Path=/"})
			jar.SetCookiesFromHeaderList(u, []string{"sid=x; Path=/; " + tc.attrs})
			if got := jar.CookieHeader(u); got != want {
				t.Errorf("after SetCookies, CookieHeader = %q, want %q", got, want)
			}

			// Cookies and ClearExpired, given the cookie past SetCookies' check.
			c := ParseSetCookie("sid=x; Path=/; "+tc.attrs, u)
			jar = NewCookieJar()
			jar.cookies[jar.domainKey(c.Domain)] = []*Cookie{c}
			if got := jar.CookieHeader(u); got != want {
				t.Errorf("Cookies sends %q, want %q", got, want)
			}
			jar.ClearExpired()
			wantCount := 1
			if tc.deleted {
				wantCount = 0
			}
			if got := jar.Count(); got != wantCount {
				t.Errorf("after ClearExpired, Count = %d, want %d", got, wantCount)
			}
		})
	}
}

func TestCookieMaxAgeHuge(t *testing.T) {
	u := mustParseURL(t, "https://example.com/")
	for _, v := range maxAgeHuge {
		t.Run(v, func(t *testing.T) {
			c := ParseSetCookie("sid=x; Path=/; Max-Age="+v, u)
			if c.IsExpired() || c.Expires.Before(time.Now().AddDate(68, 0, 0)) {
				t.Errorf("Expires = %v, want at least 68 years from now", c.Expires)
			}
			jar := NewCookieJar()
			jar.SetCookiesFromHeaderList(u, []string{"sid=x; Path=/; Max-Age=" + v})
			if got := jar.CookieHeader(u); got != "sid=x" {
				t.Errorf("CookieHeader = %q, want sid=x", got)
			}
		})
	}
}

// A cookie deleted with Max-Age is gone from the next request, and one that
// Max-Age keeps alive is still sent, through a real send. Each preset builds
// its own header block, so every browser family the library mimics is covered.
func TestClientCookieMaxAgeWire(t *testing.T) {
	cases := []struct{ setCookie, want string }{
		{"sid=; Path=/; Max-Age=0", ""},
		{"sid=; Path=/; Max-Age=-1", ""},
		{"sid=gone; Path=/; Max-Age=0; Expires=" + maxAgeFuture, ""},
		{"sid=kept; Path=/; Max-Age=3600; Expires=" + maxAgePast, "sid=kept"},
		{"sid=kept; Path=/; Max-Age=10000000000", "sid=kept"},
	}
	protocols := []struct {
		name  string
		force Option
		major int
	}{
		{"h1", WithForceHTTP1(), 1},
		{"h2", WithForceHTTP2(), 2},
	}
	for _, preset := range []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"} {
		for _, p := range protocols {
			for _, tc := range cases {
				t.Run(preset+"/"+p.name+"/"+tc.setCookie, func(t *testing.T) {
					var mu sync.Mutex
					sent := map[string][]string{}
					protoMajor := 0
					srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						sent[r.URL.Path] = r.Header.Values("Cookie")
						protoMajor = r.ProtoMajor
						mu.Unlock()
						switch r.URL.Path {
						case "/set":
							w.Header().Add("Set-Cookie", "sid=secret; Path=/")
						case "/delete":
							w.Header().Add("Set-Cookie", tc.setCookie)
						}
						io.WriteString(w, "ok")
					}))
					srv.EnableHTTP2 = true
					srv.StartTLS()
					t.Cleanup(srv.Close)

					c := NewClient(preset,
						WithInsecureSkipVerify(), // httptest's certificate
						WithPreferIPv4(),         // the server listens on 127.0.0.1 only
						WithTimeout(10*time.Second),
						p.force)
					c.EnableCookies()
					t.Cleanup(func() { c.Close() })

					for _, path := range []string{"/set", "/delete", "/next"} {
						if _, err := c.Do(context.Background(), &Request{Method: "GET", URL: srv.URL + path}); err != nil {
							t.Fatalf("GET %s: %v", path, err)
						}
					}

					mu.Lock()
					defer mu.Unlock()
					if protoMajor != p.major {
						t.Fatalf("the server saw HTTP/%d, want HTTP/%d", protoMajor, p.major)
					}
					if got := sent["/delete"]; len(got) != 1 || got[0] != "sid=secret" {
						t.Fatalf("the request before the delete sent Cookie %q, want sid=secret", got)
					}
					got := sent["/next"]
					switch {
					case tc.want == "" && len(got) != 0:
						t.Errorf("the next request sent Cookie %q; the Set-Cookie deleted it", got)
					case tc.want != "" && (len(got) != 1 || got[0] != tc.want):
						t.Errorf("the next request sent Cookie %q, want %s", got, tc.want)
					}
				})
			}
		}
	}
}
