package transport

import (
	"testing"
	"time"
)

// Regression lock: a connection evicted from the pool while a response body is
// still streaming must stay reachable.
//
// The 1.6.9 fix for #83 introduced a deferred close: requestClose() marks a
// busy connection and returns without closing, so the reader is not cut off.
// The eviction sites then delete the connection from t.conns. But cleanup()
// only walks t.conns, so once evicted nothing revisited the connection: if the
// caller never closed the body, inFlight never reached zero, release() never
// fired, and the socket, its h2 ClientConn and that connection's reader
// goroutine were pinned for the process lifetime. Close() could not reclaim
// them either, because it too only walked t.conns.
//
// That is the same hole PR #84 has in the other pool, so it is worth pinning
// here rather than relying on review to catch it again.
func TestEvictedStreamingConnStaysReclaimable(t *testing.T) {
	tr := testTransport(t)

	// A connection with a body still streaming on it.
	conn := &persistentConn{
		host:       "example.com",
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
		inFlight:   1,
	}
	conn.lastProgress.Store(time.Now().UnixNano())

	tr.connsMu.Lock()
	tr.conns["example.com:443"] = conn
	tr.connsMu.Unlock()

	// Evict it the way getOrCreateConn does.
	tr.retire(conn)
	tr.connsMu.Lock()
	delete(tr.conns, "example.com:443")
	tr.connsMu.Unlock()

	// The close must have been deferred, not performed: the reader is still
	// using this socket.
	conn.mu.Lock()
	deferred := conn.closeRequested
	closed := conn.closed
	conn.mu.Unlock()
	if !deferred {
		t.Error("evicting a streaming connection should defer its close, not skip it")
	}
	if closed {
		t.Fatal("evicting a streaming connection closed the socket under the reader")
	}

	// And it must still be tracked somewhere, or nothing can ever reclaim it.
	tr.retiredMu.Lock()
	tracked := len(tr.retired)
	tr.retiredMu.Unlock()
	if tracked == 0 {
		t.Fatal("an evicted-but-streaming connection is tracked nowhere: cleanup() only walks " +
			"t.conns, so its socket would be pinned for the process lifetime")
	}

	// Finishing the body fires the deferred close.
	conn.release()
	conn.mu.Lock()
	closedAfter := conn.closed
	conn.mu.Unlock()
	if !closedAfter {
		t.Error("finishing the last in-flight request should fire the deferred close")
	}

	// And the sweep drops the drained entry rather than growing the list forever.
	tr.sweepRetired()
	tr.retiredMu.Lock()
	remaining := len(tr.retired)
	tr.retiredMu.Unlock()
	if remaining != 0 {
		t.Errorf("sweepRetired left %d drained connections tracked, want 0", remaining)
	}
}

// The abandoned-body bound must still reach a connection after it was evicted.
// This is the case that would otherwise leak forever: evicted, body never
// closed, so inFlight never drops.
func TestEvictedAbandonedBodyIsReclaimed(t *testing.T) {
	tr := testTransport(t)

	conn := &persistentConn{
		host:       "example.com",
		createdAt:  time.Now().Add(-30 * time.Minute),
		lastUsedAt: time.Now().Add(-30 * time.Minute),
		inFlight:   1,
	}
	// No progress for far longer than the abandoned bound.
	conn.lastProgress.Store(time.Now().Add(-tr.abandonedBodyTimeout - time.Minute).UnixNano())

	tr.retire(conn)

	tr.retiredMu.Lock()
	tracked := len(tr.retired)
	tr.retiredMu.Unlock()
	if tracked != 1 {
		t.Fatalf("expected the evicted connection to be tracked, got %d", tracked)
	}

	if !tr.isConnDestroyable(conn) {
		t.Fatal("a body with no progress past abandonedBodyTimeout should be destroyable")
	}

	tr.sweepRetired()

	tr.retiredMu.Lock()
	remaining := len(tr.retired)
	tr.retiredMu.Unlock()
	if remaining != 0 {
		t.Error("the abandoned-body bound never reached an evicted connection, so its socket leaks")
	}
}

// Transport shutdown must reclaim evicted-but-draining connections too.
func TestCloseReclaimsRetiredConns(t *testing.T) {
	tr := testTransport(t)

	conn := &persistentConn{
		host:       "example.com",
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
		inFlight:   1,
	}
	conn.lastProgress.Store(time.Now().UnixNano())
	tr.retire(conn)

	tr.Close()

	tr.retiredMu.Lock()
	remaining := len(tr.retired)
	tr.retiredMu.Unlock()
	if remaining != 0 {
		t.Error("Close() left evicted-but-draining connections behind; their sockets outlive the transport")
	}
}
