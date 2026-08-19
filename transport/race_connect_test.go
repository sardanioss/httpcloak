package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	utls "github.com/sardanioss/utls"
)

// blockUntilCancel returns a probe that never connects: it blocks until the
// race context is cancelled, modelling an H3 handshake that idles out because
// QUIC cannot reach the server (firewall, VPN, or a proxy that does not relay
// UDP). This is exactly the case that used to cost ~5s on the sequential path.
func blockUntilCancel() func(context.Context) error {
	return func(c context.Context) error {
		<-c.Done()
		return c.Err()
	}
}

// connectAfter returns a probe that succeeds after d (respecting cancellation).
func connectAfter(d time.Duration) func(context.Context) error {
	return func(c context.Context) error {
		select {
		case <-time.After(d):
			return nil
		case <-c.Done():
			return c.Err()
		}
	}
}

// The whole point of #68: when H3 cannot connect, the racer must fall back to
// H2 as soon as H2 connects, NOT after the full budget. A sequential H3-first
// path would block on the H3 handshake for the budget before trying H2.
func TestRaceTwoProbes_H3BlockedH2Wins_NoStall(t *testing.T) {
	budget := 2 * time.Second
	t0 := time.Now()
	d := raceTwoProbes(context.Background(), budget,
		blockUntilCancel(),                // H3 never connects
		connectAfter(50*time.Millisecond), // H2 connects quickly
	)
	el := time.Since(t0)

	if d.err != nil {
		t.Fatalf("unexpected err: %v", d.err)
	}
	if d.alpnErr != nil {
		t.Fatalf("unexpected alpn mismatch")
	}
	if d.protocol != ProtocolHTTP2 {
		t.Fatalf("want H2 winner, got %v", d.protocol)
	}
	// Must return shortly after H2 connects, well under the budget. Old
	// sequential behaviour would have waited ~budget on H3 first.
	if el > 500*time.Millisecond {
		t.Fatalf("racer stalled: returned in %v (budget %v), expected ~50ms", el, budget)
	}
}

// When H3 connects first it wins, and the racer returns promptly.
func TestRaceTwoProbes_H3Wins(t *testing.T) {
	t0 := time.Now()
	d := raceTwoProbes(context.Background(), 2*time.Second,
		connectAfter(20*time.Millisecond), // H3 fast
		connectAfter(1*time.Second),       // H2 slow
	)
	el := time.Since(t0)
	if d.err != nil || d.alpnErr != nil {
		t.Fatalf("unexpected decision: %+v", d)
	}
	if d.protocol != ProtocolHTTP3 {
		t.Fatalf("want H3 winner, got %v", d.protocol)
	}
	if el > 400*time.Millisecond {
		t.Fatalf("H3 win returned late: %v", el)
	}
}

// When neither connects within the budget, default to H2 so the caller can run
// its H2 -> H1 fallback. Must return at ~budget, not hang.
func TestRaceTwoProbes_BothBlocked_DefaultsH2AtBudget(t *testing.T) {
	budget := 150 * time.Millisecond
	t0 := time.Now()
	d := raceTwoProbes(context.Background(), budget,
		blockUntilCancel(),
		blockUntilCancel(),
	)
	el := time.Since(t0)
	if d.err != nil || d.alpnErr != nil {
		t.Fatalf("unexpected decision: %+v", d)
	}
	if d.protocol != ProtocolHTTP2 {
		t.Fatalf("want H2 default, got %v", d.protocol)
	}
	if el < budget || el > budget+400*time.Millisecond {
		t.Fatalf("expected return near budget %v, got %v", budget, el)
	}
}

// Parent context cancellation surfaces as an error (caller aborts the request).
func TestRaceTwoProbes_ParentCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()
	d := raceTwoProbes(ctx, 5*time.Second, blockUntilCancel(), blockUntilCancel())
	if d.err == nil {
		t.Fatalf("expected error on parent cancel, got %+v", d)
	}
}

// An ALPN downgrade to HTTP/1.1 reported by the H2 probe is surfaced (with the
// live TLS conn) so the caller can reuse the connection for H1.
func TestRaceTwoProbes_ALPNDowngradeSurfaced(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	uconn := utls.UClient(clientConn, &utls.Config{InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	alpn := &ALPNMismatchError{TLSConn: uconn}

	d := raceTwoProbes(context.Background(), 2*time.Second,
		blockUntilCancel(), // H3 never connects
		func(c context.Context) error { return alpn }, // H2 negotiated H1
	)
	if d.alpnErr == nil {
		t.Fatalf("expected ALPN mismatch surfaced, got %+v", d)
	}
	if d.alpnErr.TLSConn != uconn {
		t.Fatalf("ALPN conn not preserved for reuse")
	}
	// Caller owns the conn now; close it.
	d.alpnErr.TLSConn.Close()
}

// Both probes failing fast must end the race immediately, not at the budget.
//
// Each goroutine used to signal only on success, so a plain error from either
// was dropped and the race waited out the whole budget even though nobody
// could win. Measured against a host that does not resolve: every forced
// protocol reported "no such host" in 20 to 130ms while auto mode took
// 6005ms, which is the 6s budget. Any caller with a timeout under that got
// "context deadline exceeded" and never saw the real reason.
//
// This is not specific to DNS. Connection refused, no route to host and a
// rejected handshake all fail fast and all hit the same wait.
func TestRaceTwoProbes_BothFailFast_NoBudgetWait(t *testing.T) {
	budget := 2 * time.Second
	failFast := func(context.Context) error { return errors.New("no such host") }

	t0 := time.Now()
	d := raceTwoProbes(context.Background(), budget, failFast, failFast)
	el := time.Since(t0)

	// Same decision as the budget path: the caller falls back to H2 then H1
	// and produces the real error. Only the waiting is gone.
	if d.err != nil || d.alpnErr != nil {
		t.Fatalf("unexpected decision: %+v", d)
	}
	if d.protocol != ProtocolHTTP2 {
		t.Fatalf("want H2 default, got %v", d.protocol)
	}
	if el > budget/4 {
		t.Fatalf("both probes failed immediately but the race took %v of a %v budget; "+
			"the failure signal is not resolving the race", el, budget)
	}
}

// One probe failing fast must NOT end the race. The other may still win, and
// cutting it short here would turn "H3 is blocked" into "no H3 for this host"
// on every connection.
func TestRaceTwoProbes_OneFailureDoesNotEndTheRace(t *testing.T) {
	budget := 2 * time.Second
	slowWinner := func(ctx context.Context) error {
		select {
		case <-time.After(200 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	d := raceTwoProbes(context.Background(), budget,
		func(context.Context) error { return errors.New("quic blocked") },
		slowWinner,
	)
	if d.protocol != ProtocolHTTP2 {
		t.Fatalf("H2 connected after H3 failed, want H2 as winner, got %+v", d)
	}
}

// An ALPN downgrade is not a failure. It resolves the race on its own channel
// and hands the caller a live connection, so counting it would race the two
// paths against each other.
func TestRaceTwoProbes_ALPNDowngradeIsNotCountedAsFailure(t *testing.T) {
	d := raceTwoProbes(context.Background(), 2*time.Second,
		func(context.Context) error { return errors.New("quic blocked") },
		func(context.Context) error { return &ALPNMismatchError{Negotiated: "http/1.1"} },
	)
	if d.alpnErr == nil {
		t.Fatalf("want the ALPN downgrade surfaced, got %+v", d)
	}
}
