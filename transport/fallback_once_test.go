package transport

import (
	"context"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Regression tests: in auto mode a request makes the same attempts whichever
// doAuto branch it takes, and the HTTP/1.1 fallback runs once.
//
// raceH3H2 used to carry its own copies of the fallbacks doAuto already has
// (HTTP/1.1 on the ALPN-downgraded connection, then HTTP/1.1 on a fresh one).
// When such an internal fallback failed, doAuto saw a non-ALPN error and ran
// its own fresh-connection fallback on top, so an H3-capable preset made two
// HTTP/1.1 attempts where a preset without H3 support made one. Now raceH3H2
// races and makes one attempt on the winner; doAuto owns every fallback.
//
// The tests count accepted TCP connections, which is the number of attempts as
// the server sees them.

// countingListener counts accepted connections; with dropAll it also closes
// each one immediately, which the client sees as a handshake that died.
type countingListener struct {
	net.Listener
	accepted atomic.Int32
	dropAll  bool
}

func (l *countingListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.accepted.Add(1)
		if l.dropAll {
			c.Close()
			continue
		}
		return c, nil
	}
}

func doGetErr(t *testing.T, tr *Transport, rawURL string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := tr.Do(ctx, &Request{Method: "GET", URL: rawURL})
	return err
}

// Every connection dies at accept, so H2 fails for a non-ALPN reason and so
// does the HTTP/1.1 fallback. Presets with H3 support pay one extra connection
// for the H2 probe before the H2 dial; beyond that both branches make exactly
// one HTTP/1.1 attempt.
func TestAutoFreshH1FallbackRunsOnce(t *testing.T) {
	cases := []struct {
		preset string
		want   int32
	}{
		{preset: "firefox-148", want: 2}, // H2 dial + one H1 dial
		{preset: "chrome-146", want: 3},  // H2 probe + H2 dial + one H1 dial
	}
	for _, tc := range cases {
		t.Run(tc.preset, func(t *testing.T) {
			tr := autoTransport(t, tc.preset)
			srv := httptest.NewUnstartedServer(stdhttp.NotFoundHandler())
			l := &countingListener{Listener: srv.Listener, dropAll: true}
			srv.Listener = l
			srv.EnableHTTP2 = true
			srv.StartTLS()
			t.Cleanup(srv.Close)

			if err := doGetErr(t, tr, srv.URL); err == nil {
				t.Fatal("request against a server that drops every connection should fail")
			}
			if got := l.accepted.Load(); got != tc.want {
				t.Errorf("%s: server saw %d connection attempts, want %d (the HTTP/1.1 fallback must run once)",
					tc.preset, got, tc.want)
			}
		})
	}
}

// ALPN negotiates http/1.1, and the request on that connection then fails
// (the server hangs up before answering). That is a failed request on a live,
// correctly negotiated connection, not a failed negotiation, so it is returned
// to the caller: neither branch dials a fresh connection to try again.
func TestAutoALPNDowngradeFailureIsNotRetried(t *testing.T) {
	for _, preset := range []string{"firefox-148", "chrome-146"} {
		t.Run(preset, func(t *testing.T) {
			tr := autoTransport(t, preset)
			// NewUnstartedServer + StartTLS without EnableHTTP2 negotiates
			// http/1.1 only. The handler hijacks and closes without a response.
			srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				c, _, err := w.(stdhttp.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack: %v", err)
					return
				}
				c.Close()
			}))
			l := &countingListener{Listener: srv.Listener}
			srv.Listener = l
			srv.StartTLS()
			t.Cleanup(srv.Close)

			if err := doGetErr(t, tr, srv.URL); err == nil {
				t.Fatal("request whose HTTP/1.1 exchange was cut off should fail")
			}
			if got := l.accepted.Load(); got != 1 {
				t.Errorf("%s: server saw %d connections, want 1 (a failed request on an "+
					"ALPN-negotiated connection is not retried on a fresh one)", preset, got)
			}
			// And the host is not cached from a failed exchange.
			if p, ok := cachedProtocol(tr, extractHost(srv.URL)); ok {
				t.Errorf("host cached as %v after a failed request, want nothing cached", p)
			}
		})
	}
}
