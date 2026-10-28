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

// Auth set on the client itself (SetAuth, SetBasicAuth, SetBearerAuth) goes on
// every request that has no Request.Auth of its own. A redirect hop that
// leaves the origin its chain started on drops Request.Auth and a caller's
// Authorization header, so it had none, and the client's auth went to the
// other origin in their place.
//
// The rule is Fetch's: a hop that leaves the first request's origin sends no
// Authorization, and neither does any hop after it, even one that comes back
// to that origin. Request.Auth, a caller's header and the session already
// worked that way.
//
// Each test asserts what the receiving server saw, through a real send.

// The auth code is the same for every preset, but each preset builds its own
// header block, so every browser family the library mimics is covered.
var clientAuthHopPresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

var clientAuthHopProtocols = []struct {
	name  string
	force Option
}{
	{"h1", WithForceHTTP1()},
	{"h2", WithForceHTTP2()},
}

// clientAuthHopServer is one origin of a redirect chain. It records the
// Authorization each request arrived with, and answers a path it has a handler
// for with that handler and any other path with a 200.
type clientAuthHopServer struct {
	url string // https://127.0.0.1:port, no trailing slash

	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	auth     map[string][][]string // per path, each request's Authorization values, in arrival order
}

func newClientAuthHopServer(t *testing.T) *clientAuthHopServer {
	t.Helper()
	s := &clientAuthHopServer{handlers: map[string]http.HandlerFunc{}, auth: map[string][][]string{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.auth[r.URL.Path] = append(s.auth[r.URL.Path], r.Header.Values("Authorization"))
		h := s.handlers[r.URL.Path]
		s.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

// onLocalhost is the same server under the name localhost, which is another
// origin.
func (s *clientAuthHopServer) onLocalhost() string {
	return strings.Replace(s.url, "127.0.0.1", "localhost", 1)
}

func (s *clientAuthHopServer) handle(path string, h http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[path] = h
}

func (s *clientAuthHopServer) redirect(path string, status int, location string) {
	s.handle(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", location)
		w.WriteHeader(status)
	})
}

// requests returns the Authorization values each request for path arrived
// with, in arrival order, failing the test if path was never requested.
func (s *clientAuthHopServer) requests(t *testing.T, path string) [][]string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	got, ok := s.auth[path]
	if !ok {
		t.Fatalf("%s%s was never requested", s.url, path)
	}
	return got
}

// wantAuth fails unless every request for path arrived with want as its only
// Authorization, or with none when want is empty.
func (s *clientAuthHopServer) wantAuth(t *testing.T, path, want string) {
	t.Helper()
	for i, got := range s.requests(t, path) {
		if want == "" && len(got) > 0 {
			t.Errorf("request %d for %s sent Authorization %q, want none", i+1, path, got)
		}
		if want != "" && (len(got) != 1 || got[0] != want) {
			t.Errorf("request %d for %s sent Authorization %q, want %q", i+1, path, got, want)
		}
	}
}

func newClientAuthHopClient(t *testing.T, preset string, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{
		WithInsecureSkipVerify(), // httptest's certificate
		WithPreferIPv4(),         // the servers listen on 127.0.0.1 only
		WithTimeout(10 * time.Second),
	}, opts...)
	c := NewClient(preset, opts...)
	t.Cleanup(func() { c.Close() })
	return c
}

// TestClientAuthStaysOnFirstOrigin follows a chain that takes one hop on its
// first origin, leaves it for another host or another port, and comes back.
// Only the requests before it leaves get the client's auth.
func TestClientAuthStaysOnFirstOrigin(t *testing.T) {
	setups := []struct {
		name  string
		opts  []Option
		apply func(c *Client, req *Request)
		want  string // the Authorization the first origin gets
	}{
		{"SetBasicAuth", nil, func(c *Client, _ *Request) {
			c.SetBasicAuth("user", "pass")
		}, "Basic dXNlcjpwYXNz"},
		{"SetBearerAuth", nil, func(c *Client, _ *Request) {
			c.SetBearerAuth("client-token")
		}, "Bearer client-token"},
		{"SetAuth", nil, func(c *Client, _ *Request) {
			c.SetAuth(NewBearerAuth("set-auth-token"))
		}, "Bearer set-auth-token"},
		// The hop that drops Request.Auth must not take the client's instead.
		{"Request.Auth over SetBasicAuth", nil, func(c *Client, req *Request) {
			c.SetBasicAuth("user", "pass")
			req.Auth = NewBearerAuth("request-token")
		}, "Bearer request-token"},
		// TLS-only leaves the headers to the caller, but still applies auth.
		{"SetBasicAuth TLS-only", []Option{WithTLSOnly()}, func(c *Client, _ *Request) {
			c.SetBasicAuth("user", "pass")
		}, "Basic dXNlcjpwYXNz"},
	}
	departures := []struct {
		name string
		// away returns the origin the chain leaves for, and the server behind it.
		away func(first, second *clientAuthHopServer) (string, *clientAuthHopServer)
	}{
		{"other host", func(first, _ *clientAuthHopServer) (string, *clientAuthHopServer) {
			return first.onLocalhost(), first
		}},
		{"other port", func(_, second *clientAuthHopServer) (string, *clientAuthHopServer) {
			return second.url, second
		}},
	}

	for _, preset := range clientAuthHopPresets {
		for _, proto := range clientAuthHopProtocols {
			for _, dep := range departures {
				for _, setup := range setups {
					t.Run(preset+"/"+proto.name+"/"+dep.name+"/"+setup.name, func(t *testing.T) {
						first := newClientAuthHopServer(t)
						second := newClientAuthHopServer(t)
						awayURL, away := dep.away(first, second)
						first.redirect("/start", http.StatusMovedPermanently, first.url+"/same")
						first.redirect("/same", http.StatusFound, awayURL+"/away")
						away.redirect("/away", http.StatusTemporaryRedirect, first.url+"/back")

						c := newClientAuthHopClient(t, preset, append([]Option{proto.force}, setup.opts...)...)
						req := &Request{Method: "GET", URL: first.url + "/start"}
						setup.apply(c, req)
						resp, err := c.Do(context.Background(), req)
						if err != nil {
							t.Fatalf("Do: %v", err)
						}
						if resp.StatusCode != http.StatusOK {
							t.Fatalf("status = %d, want 200", resp.StatusCode)
						}

						first.wantAuth(t, "/start", setup.want)
						first.wantAuth(t, "/same", setup.want)
						away.wantAuth(t, "/away", "")
						first.wantAuth(t, "/back", "")
					})
				}
			}
		}
	}
}

// TestClientAuthDigestStaysOnFirstOrigin covers the challenge path. A client's
// DigestAuth keeps the last challenge it answered, so a hop off the origin
// sent the other host an answer to the first origin's challenge. And when the
// other host challenged the hop itself, the client answered with a response
// worked out from the password.
func TestClientAuthDigestStaysOnFirstOrigin(t *testing.T) {
	const (
		firstChallenge = `Digest realm="first", nonce="0123456789abcdef", qop="auth"`
		awayChallenge  = `Digest realm="away", nonce="fedcba9876543210", qop="auth"`
	)
	cases := []struct {
		name string
		// challengeFirst makes the first origin challenge the request before it
		// redirects.
		challengeFirst bool
	}{
		{"answered on the first origin", true},
		{"challenged off it", false},
	}

	for _, preset := range clientAuthHopPresets {
		for _, proto := range clientAuthHopProtocols {
			for _, tc := range cases {
				t.Run(preset+"/"+proto.name+"/"+tc.name, func(t *testing.T) {
					s := newClientAuthHopServer(t)
					s.handle("/start", func(w http.ResponseWriter, r *http.Request) {
						if tc.challengeFirst && !strings.HasPrefix(r.Header.Get("Authorization"), "Digest ") {
							w.Header().Set("WWW-Authenticate", firstChallenge)
							w.WriteHeader(http.StatusUnauthorized)
							return
						}
						w.Header().Set("Location", s.onLocalhost()+"/away")
						w.WriteHeader(http.StatusFound)
					})
					// It takes any credentials, so a leak ends the chain with a
					// 200 rather than with another challenge.
					s.handle("/away", func(w http.ResponseWriter, r *http.Request) {
						if r.Header.Get("Authorization") != "" {
							io.WriteString(w, "authenticated")
							return
						}
						w.Header().Set("WWW-Authenticate", awayChallenge)
						w.WriteHeader(http.StatusUnauthorized)
					})

					c := newClientAuthHopClient(t, preset, proto.force)
					c.SetAuth(NewDigestAuth("user", "pass"))
					resp, err := c.Do(context.Background(), &Request{Method: "GET", URL: s.url + "/start"})
					if err != nil {
						t.Fatalf("Do: %v", err)
					}
					if resp.StatusCode != http.StatusUnauthorized {
						t.Errorf("status = %d, want the other origin's 401, unanswered", resp.StatusCode)
					}

					s.wantAuth(t, "/away", "")
					if tc.challengeFirst {
						starts := s.requests(t, "/start")
						if len(starts) != 2 || len(starts[0]) != 0 || len(starts[1]) != 1 || !strings.HasPrefix(starts[1][0], "Digest ") {
							t.Errorf("/start sent Authorization %q, want none and then a Digest answer", starts)
						}
					}
				})
			}
		}
	}
}

// TestClientAuthRetryStartsOnFirstOrigin covers doWithRetry, which sends the
// chain again from its first request. That request is on the first origin
// again and gets the client's auth, and the hop off it still gets none.
func TestClientAuthRetryStartsOnFirstOrigin(t *testing.T) {
	for _, preset := range clientAuthHopPresets {
		for _, proto := range clientAuthHopProtocols {
			t.Run(preset+"/"+proto.name, func(t *testing.T) {
				s := newClientAuthHopServer(t)
				s.redirect("/start", http.StatusFound, s.onLocalhost()+"/away")
				var mu sync.Mutex
				awayHits := 0
				s.handle("/away", func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					awayHits++
					n := awayHits
					mu.Unlock()
					if n == 1 {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					w.Header().Set("Location", s.url+"/back")
					w.WriteHeader(http.StatusFound)
				})

				c := newClientAuthHopClient(t, preset, proto.force,
					WithRetryConfig(1, time.Millisecond, time.Millisecond, []int{http.StatusServiceUnavailable}))
				c.SetBasicAuth("user", "pass")
				resp, err := c.Do(context.Background(), &Request{Method: "GET", URL: s.url + "/start"})
				if err != nil {
					t.Fatalf("Do: %v", err)
				}
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status = %d, want 200 from the retried chain", resp.StatusCode)
				}

				if n := len(s.requests(t, "/start")); n != 2 {
					t.Fatalf("/start was requested %d times, want 2: once per attempt", n)
				}
				s.wantAuth(t, "/start", "Basic dXNlcjpwYXNz")
				s.wantAuth(t, "/away", "")
				s.wantAuth(t, "/back", "")
			})
		}
	}
}
