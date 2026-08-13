package pool

import (
	"io"
	"testing"
	"time"
)

// Same issue #83 lifecycle locks for the QUIC/HTTP3 pool. HTTP3RT.Close() tears
// down every stream under the transport at once, so an idle reap during a
// download is just as fatal here.

func testQUICConn(inFlight int32, age, idle time.Duration) *QUICConn {
	now := time.Now()
	c := &QUICConn{
		Host:       "example.com",
		CreatedAt:  now.Add(-age),
		LastUsedAt: now.Add(-idle),
	}
	c.inFlight = inFlight
	return c
}

func testQUICHostPool(conns ...*QUICConn) *QUICHostPool {
	return &QUICHostPool{
		host:                 "example.com",
		port:                 "443",
		connections:          conns,
		maxIdleTime:          90 * time.Second,
		maxConnAge:           5 * time.Minute,
		abandonedBodyTimeout: 10 * time.Minute,
	}
}

func quicConnClosed(c *QUICConn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func quicConnInFlight(c *QUICConn) int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inFlight
}

func TestQUICCloseIdleSkipsStreamingConn(t *testing.T) {
	conn := testQUICConn(1, 10*time.Minute, 5*time.Minute)
	conn.lastProgress.Store(time.Now().UnixNano())
	p := testQUICHostPool(conn)

	p.CloseIdle()

	if len(p.connections) != 1 {
		t.Fatalf("streaming QUIC connection was dropped: %d tracked, want 1", len(p.connections))
	}
	if quicConnClosed(conn) {
		t.Fatal("streaming QUIC connection was closed underneath its reader")
	}
}

// No-regression lock: passes before and after the fix.
func TestQUICCloseIdleStillReapsIdleConn(t *testing.T) {
	conn := testQUICConn(0, 10*time.Minute, 5*time.Minute)
	p := testQUICHostPool(conn)

	p.CloseIdle()

	if len(p.connections) != 0 {
		t.Fatalf("idle QUIC connection survived the reaper: %d tracked, want 0", len(p.connections))
	}
}

func TestQUICAbandonedBodyIsReclaimed(t *testing.T) {
	conn := testQUICConn(1, 30*time.Minute, 20*time.Minute)
	conn.lastProgress.Store(time.Now().Add(-20 * time.Minute).UnixNano())
	p := testQUICHostPool(conn)

	if !p.isConnDestroyable(conn) {
		t.Fatal("an abandoned QUIC body must be reclaimable past abandonedBodyTimeout")
	}

	p.CloseIdle()
	if len(p.connections) != 0 {
		t.Fatalf("abandoned QUIC connection was not reclaimed: %d tracked, want 0", len(p.connections))
	}
}

func TestQUICBodyGuardReleasesOnce(t *testing.T) {
	conn := testQUICConn(1, 0, 0)
	guard := &quicConnBodyGuard{ReadCloser: &fakeBody{chunk: []byte("hello")}, conn: conn}

	buf := make([]byte, 8)
	if _, err := guard.Read(buf); err != nil {
		t.Fatalf("first read: %v", err)
	}
	if _, err := guard.Read(buf); err != io.EOF {
		t.Fatalf("second read err = %v, want io.EOF", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := quicConnInFlight(conn); got != 0 {
		t.Fatalf("in-flight after EOF then Close = %d, want 0 (double release)", got)
	}
}

func TestQUICRequestCloseDefersWhileStreaming(t *testing.T) {
	conn := testQUICConn(1, 0, 0)

	conn.requestClose()
	if quicConnClosed(conn) {
		t.Fatal("requestClose closed a QUIC connection that still had a body streaming")
	}

	conn.release()
	if !quicConnClosed(conn) {
		t.Fatal("release did not fire the deferred close for the QUIC connection")
	}
}

func TestQUICRoundTripRejectsRetiredConn(t *testing.T) {
	conn := testQUICConn(0, 0, 0)
	conn.closeRequested = true

	if _, err := conn.RoundTrip(nil); err != ErrConnRetired {
		t.Fatalf("RoundTrip on retired QUIC conn = %v, want ErrConnRetired", err)
	}
	if got := quicConnInFlight(conn); got != 0 {
		t.Fatalf("in-flight after a rejected RoundTrip = %d, want 0", got)
	}
}
