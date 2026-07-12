package transport

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Locks the classifier that decides whether a forced-H3 roundtrip failure is a
// stalled/dead QUIC path (retry biased to the other family) versus a definitive
// transport error (surface as-is). Regression guard for the IPv6-QUIC PMTU
// black-hole fallback: a path can complete its handshake but then blackhole the
// response, which surfaces here as a bounded-attempt deadline or QUIC's idle
// "no recent network activity" — both MUST be treated as stalls.
func TestIsH3Stall(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context deadline", context.DeadlineExceeded, true},
		{"wrapped context deadline", fmt.Errorf("roundtrip: %w", context.DeadlineExceeded), true},
		{"quic idle timeout", errors.New("timeout: no recent network activity"), true},
		{"generic timeout", errors.New("i/o timeout"), true},
		{"deadline exceeded text", errors.New("stream deadline exceeded"), true},
		// Definitive failures — NOT stalls, must not trigger a silent family flip.
		{"connection refused", errors.New("connect: connection refused"), false},
		{"request cancelled", errors.New("H3_REQUEST_CANCELLED (local)"), false},
		{"tls error", errors.New("tls: handshake failure"), false},
		{"http error", errors.New("server returned 503"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isH3Stall(tc.err); got != tc.want {
				t.Errorf("isH3Stall(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// Locks the transient IPv4-first override wiring on the H3 transport: the retry
// path flips it on to steer the Happy-Eyeballs redial away from the stalled
// family, then flips it back. preferIPv4Ordering must reflect the override even
// with no DNS cache present (a bare/standalone H3 transport), and the flag must
// be independently settable both ways.
func TestH3IPv4FirstOverride(t *testing.T) {
	tr := &HTTP3Transport{} // no dnsCache: isolates the override from PreferIPv4

	if tr.preferIPv4Ordering() {
		t.Fatal("default: preferIPv4Ordering should be false")
	}
	tr.SetIPv4FirstOverride(true)
	if !tr.preferIPv4Ordering() {
		t.Fatal("override on: preferIPv4Ordering should be true")
	}
	tr.SetIPv4FirstOverride(false)
	if tr.preferIPv4Ordering() {
		t.Fatal("override off: preferIPv4Ordering should be false again")
	}
}

// Sanity-check the stall window stays a small fraction of the default 30s QUIC
// idle timeout — if it ever drifts up to (or past) the idle timeout, a
// keepalive-kept-alive-but-dead path would no longer be caught before the full
// request deadline, silently reintroducing the hang.
func TestH3StallWindowBounds(t *testing.T) {
	if h3StallWindow <= 0 || h3StallWindow >= 15*time.Second {
		t.Errorf("h3StallWindow = %v, want a small positive window well under the 30s idle timeout", h3StallWindow)
	}
}
