package transport

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// TestH2TransportCloseClosedCheck regression-tests the closed-check guard in
// getOrCreateConn that prevents writing to a nil map after Close() has nilled
// it. Fix for issue #48 / commit 7d90792.
//
// Pre-fix, if Close() fired between the lock-release-for-dial and the
// lock-re-acquire-for-write, getOrCreateConn would panic with
// "assignment to entry in nil map" at http2_transport.go:260.
func TestH2TransportCloseClosedCheck(t *testing.T) {
	preset := fingerprint.Get("chrome-146")
	if preset == nil {
		t.Skip("chrome-146 preset unavailable")
	}

	// After Close(), getOrCreateConn must return an error instead of panicking.
	t.Run("getOrCreateConn after Close returns error", func(t *testing.T) {
		tr := NewHTTP2Transport(preset, dns.NewCache())
		tr.Close()

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("getOrCreateConn panicked after Close: %v", r)
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := tr.getOrCreateConn(ctx, "example.com", "443", "example.com:443")
		if err == nil {
			t.Fatal("expected error after Close, got nil")
		}
		if !strings.Contains(err.Error(), "closed") {
			t.Fatalf("expected 'closed' error, got: %v", err)
		}
	})

	// After Close(), Connect must also return an error instead of panicking.
	t.Run("Connect after Close returns error", func(t *testing.T) {
		tr := NewHTTP2Transport(preset, dns.NewCache())
		tr.Close()

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Connect panicked after Close: %v", r)
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		err := tr.Connect(ctx, "example.com", "443")
		if err == nil {
			t.Fatal("expected error after Close, got nil")
		}
		if !strings.Contains(err.Error(), "closed") {
			t.Fatalf("expected 'closed' error, got: %v", err)
		}
	})
}

// TestH2TransportConcurrentCloseAndRoundTrip actually hammers the race.
// Spins up a local TLS server, starts many in-flight RoundTrips, then calls
// Close. The dial to the local server succeeds quickly, so the window between
// "dial returned" and "write to map" is hit repeatedly. With the fix, no panic.
// Without the fix, eventually panics with "assignment to entry in nil map".
func TestH2TransportConcurrentCloseAndRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping race stress in short mode")
	}

	preset := fingerprint.Get("chrome-146")
	if preset == nil {
		t.Skip("chrome-146 preset unavailable")
	}

	// Local TLS server — gives deterministic successful dials
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(u.Host)

	const (
		iterations = 50
		goroutines = 32
	)

	var panics atomic.Int64
	var completed atomic.Int64

	// Extract the server's cert for our TLS verification
	// (httptest server uses a self-signed cert, so we need InsecureSkipVerify)
	_ = tls.Config{} // placeholder

	for i := 0; i < iterations; i++ {
		tr := NewHTTP2Transport(preset, dns.NewCache())
		tr.SetInsecureSkipVerify(true)

		var wg sync.WaitGroup

		for g := 0; g < goroutines; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						panics.Add(1)
						t.Errorf("panicked: %v", r)
					}
				}()

				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
				// Call getOrCreateConn directly — bypasses the actual HTTP
				// request so we stress the pool path specifically.
				_, _ = tr.getOrCreateConn(ctx, host, port, net.JoinHostPort(host, port))
				completed.Add(1)
			}()
		}

		// Fire Close with varying offsets so it lands at different points in
		// the dial lifecycle across iterations.
		time.Sleep(time.Duration(i%10) * 100 * time.Microsecond)
		tr.Close()

		wg.Wait()
	}

	if panics.Load() > 0 {
		t.Fatalf("%d panics across %d iterations — close-race regression",
			panics.Load(), iterations)
	}

	t.Logf("completed %d concurrent getOrCreateConn calls across %d Close races — no panics",
		completed.Load(), iterations)
}
