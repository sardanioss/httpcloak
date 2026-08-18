package transport

import (
	"context"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// Regression tests for the auto-mode protocol cache.
//
// doAuto learns the protocol a host speaks and caches it per session so later
// requests skip the negotiation. Two very different facts were being written
// into that cache under the same key: "this host negotiated http/1.1 via ALPN"
// (a property of the host, correct to cache) and "the H2 attempt failed this
// time and the HTTP/1.1 fallback got the request through" (a property of one
// attempt). The second one, written on the very first request to a host after
// a transient handshake failure, pinned the host to HTTP/1.1 for the rest of
// the session with nothing that would ever re-probe it. For a fingerprinting
// client that is a silent, permanent downgrade.
//
// The server below fails the first N TCP connections at accept time, which is
// what a reset or timed-out handshake looks like from the client. The H1
// fallback dials fresh, lands on connection N+1 and succeeds; the next request
// must attempt H2 again and land on it.

// dropFirstListener closes the first n accepted connections without serving
// them, then behaves normally.
type dropFirstListener struct {
	net.Listener
	remaining atomic.Int32
	dropped   atomic.Int32
}

func (l *dropFirstListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.remaining.Add(-1) >= 0 {
			l.dropped.Add(1)
			c.Close()
			continue
		}
		return c, nil
	}
}

// h2ServerDroppingFirst starts an HTTP/2-capable TLS server whose first n
// connections are refused at accept.
func h2ServerDroppingFirst(t *testing.T, n int32) (*httptest.Server, *dropFirstListener) {
	t.Helper()
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusOK)
	}))
	l := &dropFirstListener{Listener: srv.Listener}
	l.remaining.Store(n)
	srv.Listener = l
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, l
}

func autoTransport(t *testing.T, preset string) *Transport {
	t.Helper()
	if fingerprint.Get(preset) == nil {
		t.Skipf("%s preset unavailable", preset)
	}
	tr := NewTransport(preset)
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(ProtocolAuto)
	t.Cleanup(tr.Close)
	return tr
}

func cachedProtocol(tr *Transport, host string) (Protocol, bool) {
	tr.protocolSupportMu.RLock()
	defer tr.protocolSupportMu.RUnlock()
	p, ok := tr.protocolSupport[host]
	return p, ok
}

func doGet(t *testing.T, tr *Transport, rawURL string) *Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := tr.Do(ctx, &Request{Method: "GET", URL: rawURL})
	if err != nil {
		t.Fatalf("Do(%s): %v", rawURL, err)
	}
	if resp.StatusCode != stdhttp.StatusOK {
		t.Fatalf("Do(%s): status %d, want 200", rawURL, resp.StatusCode)
	}
	return resp
}

// A transient failure on the first request must not pin the host to HTTP/1.1.
// Both doAuto branches are exercised: the plain H2 attempt (a preset without
// H3 support) and the H3/H2 race (a preset with it). The race branch probes
// before it dials, so it needs one more connection dropped to fail through to
// the fallback.
func TestAutoDoesNotCacheSoftH1Fallback(t *testing.T) {
	cases := []struct {
		name   string
		preset string
		drop   int32
	}{
		{name: "h2 branch", preset: "firefox-148", drop: 1},
		{name: "h3 race branch", preset: "chrome-146", drop: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := autoTransport(t, tc.preset)
			srv, l := h2ServerDroppingFirst(t, tc.drop)
			host := extractHost(srv.URL)

			// First request: the H2 attempt hits the dropped connection(s), the
			// HTTP/1.1 fallback dials fresh and gets through.
			first := doGet(t, tr, srv.URL)
			if first.Protocol != "h1" {
				t.Fatalf("first request served over %q, want h1 (the fallback); dropped %d conns",
					first.Protocol, l.dropped.Load())
			}
			if p, ok := cachedProtocol(tr, host); ok {
				t.Fatalf("host cached as %v after a soft HTTP/1.1 fallback; a transient failure "+
					"must not pin the protocol", p)
			}

			// Second request: nothing cached, so H2 is attempted again and wins.
			second := doGet(t, tr, srv.URL)
			if second.Protocol != "h2" {
				t.Fatalf("second request served over %q, want h2: the host was pinned to the "+
					"fallback protocol", second.Protocol)
			}
			if p, ok := cachedProtocol(tr, host); !ok || p != ProtocolHTTP2 {
				t.Errorf("host cached as (%v, %v) after a successful H2 request, want ProtocolHTTP2",
					p, ok)
			}
		})
	}
}

// The other kind of HTTP/1.1, negotiated by ALPN, is a fact about the host and
// must still be cached, so an H1-only server does not pay a failed H2 attempt
// on every request.
func TestAutoStillCachesALPNDowngrade(t *testing.T) {
	for _, preset := range []string{"firefox-148", "chrome-146"} {
		t.Run(preset, func(t *testing.T) {
			tr := autoTransport(t, preset)
			// NewTLSServer negotiates http/1.1 only.
			srv := httptest.NewTLSServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				w.WriteHeader(stdhttp.StatusOK)
			}))
			t.Cleanup(srv.Close)
			host := extractHost(srv.URL)

			resp := doGet(t, tr, srv.URL)
			if resp.Protocol != "h1" {
				t.Fatalf("served over %q, want h1", resp.Protocol)
			}
			if p, ok := cachedProtocol(tr, host); !ok || p != ProtocolHTTP1 {
				t.Fatalf("host cached as (%v, %v) after an ALPN http/1.1 downgrade, want ProtocolHTTP1",
					p, ok)
			}
			// And it is served straight from the cache next time.
			if resp := doGet(t, tr, srv.URL); resp.Protocol != "h1" {
				t.Fatalf("second request served over %q, want h1", resp.Protocol)
			}
		})
	}
}

// A healthy H2 host is cached as H2 on the first request, as before.
func TestAutoCachesH2(t *testing.T) {
	tr := autoTransport(t, "firefox-148")
	srv, _ := h2ServerDroppingFirst(t, 0)
	host := extractHost(srv.URL)

	if resp := doGet(t, tr, srv.URL); resp.Protocol != "h2" {
		t.Fatalf("served over %q, want h2", resp.Protocol)
	}
	if p, ok := cachedProtocol(tr, host); !ok || p != ProtocolHTTP2 {
		t.Fatalf("host cached as (%v, %v), want ProtocolHTTP2", p, ok)
	}
}
