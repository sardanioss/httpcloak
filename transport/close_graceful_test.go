package transport

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Tests for HTTP2Transport.CloseGraceful.
//
// Close tears the transport down immediately, which is right for shutdown but
// wrong for rotating a long-lived session: any response body still being read
// on one of its connections is cut off. The deferred close that #83 introduced
// (requestClose / retire) already knows how to let a busy connection finish
// first; CloseGraceful is that primitive applied to the whole transport.
//
// These lock the contract at the transport layer with fake connections, in the
// same style as the #83 tests. close_graceful_e2e_test.go drives the same path
// through a real HTTP/2 server.

// waitFor polls cond until it holds or the deadline passes. Socket closes are
// fired off the caller's goroutine, so tests observing conn.closed must wait.
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func connClosed(conn *persistentConn) func() bool {
	return func() bool {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		return conn.closed
	}
}

func cleanupStopped(tr *HTTP2Transport) bool {
	select {
	case <-tr.stopCleanup:
		return true
	default:
		return false
	}
}

func retiredCount(tr *HTTP2Transport) int {
	tr.retiredMu.Lock()
	defer tr.retiredMu.Unlock()
	return len(tr.retired)
}

// A connection with nothing on it closes right away, and with nothing left to
// drain the cleanup loop is released too.
func TestCloseGracefulClosesIdleConnNow(t *testing.T) {
	tr := testTransport(t)

	conn := streamingConn(0, time.Second, -1)
	tr.connsMu.Lock()
	tr.conns["example.com:443"] = conn
	tr.connsMu.Unlock()

	tr.CloseGraceful()

	if !waitFor(t, time.Second, connClosed(conn)) {
		t.Error("an idle connection should close as soon as CloseGraceful runs")
	}
	if n := retiredCount(tr); n != 0 {
		t.Errorf("an idle connection was tracked as retired (%d), it should simply close", n)
	}
	if !cleanupStopped(tr) {
		t.Error("with nothing left to drain, CloseGraceful should stop the cleanup loop")
	}
	if !tr.drained() {
		t.Error("transport should report drained")
	}
}

// The core of the feature: a connection with a response body still streaming
// is not closed under the reader. It is retired, keeps working until the body
// finishes, and only then closes.
func TestCloseGracefulDefersStreamingConn(t *testing.T) {
	tr := testTransport(t)

	conn := streamingConn(1, time.Second, 50*time.Millisecond)
	tr.connsMu.Lock()
	tr.conns["example.com:443"] = conn
	tr.connsMu.Unlock()

	tr.CloseGraceful()

	conn.mu.Lock()
	deferred := conn.closeRequested
	closed := conn.closed
	conn.mu.Unlock()
	if closed {
		t.Fatal("CloseGraceful closed a connection that still had a body streaming on it")
	}
	if !deferred {
		t.Error("a streaming connection should have its close deferred, not skipped")
	}
	if n := retiredCount(tr); n != 1 {
		t.Fatalf("streaming connection tracked in retired: got %d, want 1", n)
	}
	if cleanupStopped(tr) {
		t.Error("cleanup loop was stopped while a connection is still draining; " +
			"nothing would apply the abandoned-body bound to it")
	}
	if tr.drained() {
		t.Error("transport reported drained while a connection is still draining")
	}

	// New work is refused from the moment CloseGraceful returns.
	tr.connsMu.RLock()
	conns := tr.conns
	tr.connsMu.RUnlock()
	if conns != nil {
		t.Error("CloseGraceful should have taken every connection out of the pool")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := tr.getOrCreateConn(ctx, "example.com", "443", "example.com:443"); err == nil {
		t.Error("getOrCreateConn after CloseGraceful should fail")
	} else if !strings.Contains(err.Error(), "closed") {
		t.Errorf("getOrCreateConn after CloseGraceful: got %v, want a closed error", err)
	}

	// The body finishing is what fires the close.
	conn.release()
	if !waitFor(t, time.Second, connClosed(conn)) {
		t.Fatal("finishing the last in-flight request should close the retired connection")
	}

	// And the next cleanup pass forgets it and lets the loop exit.
	tr.cleanup()
	if n := retiredCount(tr); n != 0 {
		t.Errorf("sweep left %d drained connections tracked, want 0", n)
	}
	if !tr.drained() {
		t.Error("transport should report drained once the last retired connection is gone")
	}
}

// A body that is never closed must not pin its socket past CloseGraceful. The
// cleanup loop keeps running for exactly this reason: the abandoned-body bound
// has to reach connections left draining.
func TestCloseGracefulStillReclaimsAbandonedBody(t *testing.T) {
	tr := testTransport(t)

	conn := streamingConn(1, 30*time.Minute, tr.abandonedBodyTimeout+time.Minute)
	tr.connsMu.Lock()
	tr.conns["example.com:443"] = conn
	tr.connsMu.Unlock()

	tr.CloseGraceful()

	if n := retiredCount(tr); n != 1 {
		t.Fatalf("expected the abandoned connection to be draining, got %d retired", n)
	}
	if cleanupStopped(tr) {
		t.Fatal("cleanup loop stopped with a connection still draining")
	}

	// What the loop does on its next tick.
	tr.cleanup()

	if !waitFor(t, time.Second, connClosed(conn)) {
		t.Error("the abandoned-body bound never reached a connection left draining by CloseGraceful")
	}
	if n := retiredCount(tr); n != 0 {
		t.Errorf("sweep left %d connections tracked, want 0", n)
	}
	if !tr.drained() {
		t.Error("transport should report drained after the abandoned body was reclaimed")
	}
}

// Close after CloseGraceful is not a no-op: it forces whatever is still
// draining, exactly as it would have without the graceful step.
func TestCloseAfterCloseGracefulForcesDraining(t *testing.T) {
	tr := testTransport(t)

	conn := streamingConn(1, time.Second, 50*time.Millisecond)
	tr.connsMu.Lock()
	tr.conns["example.com:443"] = conn
	tr.connsMu.Unlock()

	tr.CloseGraceful()
	if connClosed(conn)() {
		t.Fatal("precondition: connection should be draining, not closed")
	}

	tr.Close()

	if !waitFor(t, time.Second, connClosed(conn)) {
		t.Error("Close after CloseGraceful left a draining connection open")
	}
	if n := retiredCount(tr); n != 0 {
		t.Errorf("Close left %d retired connections tracked, want 0", n)
	}
	if !cleanupStopped(tr) {
		t.Error("Close should stop the cleanup loop")
	}
}

// Both orders of the two calls, and repeats of each, are safe.
func TestCloseGracefulIdempotent(t *testing.T) {
	t.Run("graceful twice then close", func(t *testing.T) {
		tr := testTransport(t)
		tr.CloseGraceful()
		tr.CloseGraceful()
		tr.Close()
		tr.Close()
		if !cleanupStopped(tr) {
			t.Error("cleanup loop should be stopped")
		}
	})
	t.Run("close then graceful", func(t *testing.T) {
		tr := testTransport(t)
		tr.Close()
		tr.CloseGraceful()
		if !cleanupStopped(tr) {
			t.Error("cleanup loop should be stopped")
		}
	})
}
