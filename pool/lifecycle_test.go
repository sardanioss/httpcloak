package pool

import (
	"context"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/dns"
)

// Lifecycle regression tests for issue #83 on the client.Client pools.
//
// The failure these lock down: HTTP/2 RoundTrip returns as soon as the response
// HEADERS arrive, so a connection streaming a long body looked idle to the pool
// reaper. CloseIdle then hard-closed the socket underneath the reader, which the
// caller saw as "use of closed network connection" at roughly 120s (90s idle
// plus the 30s cleanup tick).
//
// These use hand-built connections with forced timestamps and call CloseIdle()
// directly, so nothing here waits on the wall clock or touches the network.

// testConn builds a Conn with no real socket behind it. HTTP2Conn stays nil,
// which is exactly the case that must NOT short-circuit ahead of the in-flight
// check in isConnDestroyable.
func testConn(inFlight int32, age, idle time.Duration) *Conn {
	now := time.Now()
	c := &Conn{
		Host:       "example.com",
		CreatedAt:  now.Add(-age),
		LastUsedAt: now.Add(-idle),
	}
	c.inFlight = inFlight
	return c
}

func testHostPool(conns ...*Conn) *HostPool {
	return &HostPool{
		host:                 "example.com",
		port:                 "443",
		connections:          conns,
		maxIdleTime:          90 * time.Second,
		maxConnAge:           5 * time.Minute,
		abandonedBodyTimeout: 10 * time.Minute,
	}
}

func connClosed(c *Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func connInFlight(c *Conn) int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inFlight
}

// fakeBody yields chunk once, then io.EOF forever. It records how often Close
// was called so the guard cannot hide a double close.
type fakeBody struct {
	chunk  []byte
	done   bool
	closes int
}

func (b *fakeBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	b.done = true
	n := copy(p, b.chunk)
	return n, nil
}

func (b *fakeBody) Close() error {
	b.closes++
	return nil
}

// TestStreamingConnIsNotDestroyable is the core predicate split: a connection
// too old and too idle to take a NEW request is still not safe to CLOSE while a
// response body is streaming on it.
func TestStreamingConnIsNotDestroyable(t *testing.T) {
	p := testHostPool()
	conn := testConn(1, 10*time.Minute, 5*time.Minute)
	conn.lastProgress.Store(time.Now().UnixNano())

	if p.isConnUsable(conn) {
		t.Fatal("an aged connection must not be handed out for a new request")
	}
	if p.isConnDestroyable(conn) {
		t.Fatal("a connection with a streaming response body must never be destroyable")
	}
}

// TestCloseIdleSkipsStreamingConn is the direct reproduction of issue #83 on
// pool/pool.go: the reaper tick must not close a connection whose body is still
// being read.
func TestCloseIdleSkipsStreamingConn(t *testing.T) {
	conn := testConn(1, 10*time.Minute, 5*time.Minute)
	conn.lastProgress.Store(time.Now().UnixNano())
	p := testHostPool(conn)

	p.CloseIdle()

	if len(p.connections) != 1 {
		t.Fatalf("streaming connection was dropped from the pool: %d tracked, want 1", len(p.connections))
	}
	if connClosed(conn) {
		t.Fatal("streaming connection was closed underneath its reader")
	}
}

// TestCloseIdleStillReapsIdleConn is a no-regression lock, not a bug
// reproduction: it passes both before and after the fix. It exists so the new
// destroyable predicate cannot be loosened into never reaping anything.
func TestCloseIdleStillReapsIdleConn(t *testing.T) {
	conn := testConn(0, 10*time.Minute, 5*time.Minute)
	p := testHostPool(conn)

	p.CloseIdle()

	if len(p.connections) != 0 {
		t.Fatalf("idle connection survived the reaper: %d tracked, want 0", len(p.connections))
	}
}

// TestAbandonedBodyIsReclaimed bounds the protection above. A caller that walks
// away without closing the body must not pin the socket forever.
func TestAbandonedBodyIsReclaimed(t *testing.T) {
	conn := testConn(1, 30*time.Minute, 20*time.Minute)
	conn.lastProgress.Store(time.Now().Add(-20 * time.Minute).UnixNano())
	p := testHostPool(conn)

	if !p.isConnDestroyable(conn) {
		t.Fatal("a body with no progress past abandonedBodyTimeout must be reclaimable")
	}

	p.CloseIdle()
	if len(p.connections) != 0 {
		t.Fatalf("abandoned connection was not reclaimed: %d tracked, want 0", len(p.connections))
	}
}

// TestRetiredStreamingConnStaysTracked guards against PR #84's fd leak: an
// unusable-but-streaming connection is retired, never dropped from
// p.connections. Dropping it hides it from Stats(), from later CloseIdle passes
// (so the abandoned-body backstop can never fire) and from HostPool.Close().
func TestRetiredStreamingConnStaysTracked(t *testing.T) {
	conn := testConn(1, 10*time.Minute, 5*time.Minute)
	conn.lastProgress.Store(time.Now().UnixNano())
	p := testHostPool(conn)

	p.CloseIdle()

	total, _, _ := p.Stats()
	if total != 1 {
		t.Fatalf("retired streaming connection is invisible to Stats(): total=%d, want 1", total)
	}

	// Close() must still be able to reach it, so nothing survives client.Close().
	p.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !connClosed(conn) {
		if time.Now().After(deadline) {
			t.Fatal("HostPool.Close() did not reach the retired connection")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestBodyGuardReleasesOnce: reading to EOF and then closing must decrement the
// in-flight count exactly once, never twice.
func TestBodyGuardReleasesOnce(t *testing.T) {
	conn := testConn(1, 0, 0)
	body := &fakeBody{chunk: []byte("hello")}
	guard := &connBodyGuard{ReadCloser: body, conn: conn}

	buf := make([]byte, 8)
	if _, err := guard.Read(buf); err != nil {
		t.Fatalf("first read: %v", err)
	}
	if _, err := guard.Read(buf); err != io.EOF {
		t.Fatalf("second read err = %v, want io.EOF", err)
	}
	if got := connInFlight(conn); got != 0 {
		t.Fatalf("in-flight after EOF = %d, want 0", got)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := connInFlight(conn); got != 0 {
		t.Fatalf("in-flight after EOF then Close = %d, want 0 (double release)", got)
	}
}

// TestBodyGuardReleasesOnCloseWithoutRead covers the caller that closes the body
// without ever reading it.
func TestBodyGuardReleasesOnCloseWithoutRead(t *testing.T) {
	conn := testConn(1, 0, 0)
	guard := &connBodyGuard{ReadCloser: &fakeBody{}, conn: conn}

	_ = guard.Close()
	_ = guard.Close()

	if got := connInFlight(conn); got != 0 {
		t.Fatalf("in-flight after two Closes = %d, want 0", got)
	}
}

// TestBodyGuardRecordsProgress: a slow-but-live download must keep refreshing
// the progress stamp, otherwise the abandoned-body bound would reclaim it.
func TestBodyGuardRecordsProgress(t *testing.T) {
	conn := testConn(1, 0, 0)
	conn.lastProgress.Store(time.Now().Add(-time.Hour).UnixNano())
	before := conn.lastProgress.Load()

	guard := &connBodyGuard{ReadCloser: &fakeBody{chunk: []byte("data")}, conn: conn}
	if _, err := guard.Read(make([]byte, 8)); err != nil {
		t.Fatalf("read: %v", err)
	}

	if conn.lastProgress.Load() <= before {
		t.Fatal("a read that returned bytes did not record progress")
	}
}

// TestRequestCloseDefersWhileStreaming: eviction while a body is live defers the
// close, and release() fires it when the last request finishes.
func TestRequestCloseDefersWhileStreaming(t *testing.T) {
	conn := testConn(1, 0, 0)

	conn.requestClose()
	if connClosed(conn) {
		t.Fatal("requestClose closed a connection that still had a body streaming")
	}

	conn.release()
	if !connClosed(conn) {
		t.Fatal("release did not fire the deferred close when the last body finished")
	}
}

// TestRoundTripRejectsRetiredConn: the sentinel fires strictly before anything
// is written, so the caller may retry on a fresh connection. It must not leave
// the count incremented.
func TestRoundTripRejectsRetiredConn(t *testing.T) {
	conn := testConn(0, 0, 0)
	conn.closeRequested = true

	if _, err := conn.RoundTrip(nil); err != ErrConnRetired {
		t.Fatalf("RoundTrip on retired conn = %v, want ErrConnRetired", err)
	}
	if got := connInFlight(conn); got != 0 {
		t.Fatalf("in-flight after a rejected RoundTrip = %d, want 0", got)
	}

	closedConn := testConn(0, 0, 0)
	_ = closedConn.Close()
	if _, err := closedConn.RoundTrip(nil); err != ErrConnRetired {
		t.Fatalf("RoundTrip on closed conn = %v, want ErrConnRetired", err)
	}
}

// TestNoBareInFlightDecrement is a source-scan lock, mirroring the one the
// transport pool already carries (transport/tls_verify_rebuild_test.go).
//
// Behavioural tests cannot catch a decrement added in some future error path
// that happens not to be exercised; a bare `x.inFlight--` outside release()
// skips the deferred close and strands the socket. Cheapest durable guard is to
// assert the decrement appears exactly once per file, inside release().
func TestNoBareInFlightDecrement(t *testing.T) {
	for _, file := range []string{"pool.go", "quic_pool.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := string(src)

		matches := regexp.MustCompile(`(?m)^\s*\w+\.inFlight--`).FindAllStringIndex(text, -1)
		if len(matches) != 1 {
			t.Fatalf("%s: found %d inFlight decrements, want exactly 1 (inside release())", file, len(matches))
		}

		releaseIdx := strings.Index(text, ") release() {")
		if releaseIdx < 0 {
			t.Fatalf("%s: could not locate release()", file)
		}
		if matches[0][0] < releaseIdx {
			t.Fatalf("%s: inFlight is decremented outside release()", file)
		}
	}
}

// TestMaxConnsIgnoresRetiredStreamingConn: keeping a retired connection tracked
// must not consume a maxConns slot. Counting it would answer ErrNoConnections
// for the entire duration of a download instead of opening a replacement.
func TestMaxConnsIgnoresRetiredStreamingConn(t *testing.T) {
	streaming := testConn(1, 10*time.Minute, 5*time.Minute)
	streaming.lastProgress.Store(time.Now().UnixNano())

	p := testHostPool(streaming)
	p.maxConns = 1
	p.dnsCache = dns.NewCache()
	p.host = "no-such-host.invalid"
	p.sniHost = p.host

	_, err := p.GetConn(context.Background())
	if err == ErrNoConnections {
		t.Fatal("a retired, still-draining connection consumed the maxConns slot")
	}
	// Any other error is fine here: the pool got past the cap and tried to dial
	// a host that does not resolve.
	if err == nil {
		t.Fatal("expected the dial to fail for an unresolvable host")
	}
	if len(p.connections) != 1 {
		t.Fatalf("retired connection was dropped: %d tracked, want 1", len(p.connections))
	}
}
