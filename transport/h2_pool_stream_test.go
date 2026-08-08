package transport

import (
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// Regression tests for issue #83: the HTTP/2 connection pool closed a
// connection that was still streaming a response body, roughly 120 seconds in
// (90s maxIdleTime plus the 30s cleanup tick).
//
// The cause was that RoundTrip decremented inFlight as soon as it returned,
// which for HTTP/2 is when the *headers* arrive, not when the body is done. A
// multi-minute download therefore looked completely idle to the pool.
//
// These lock the fix at each layer it depends on: the destroyable/usable split,
// the cleanup pass that consults it, the body guard that holds the reference,
// and the abandoned-body backstop that stops the guard turning into a leak.

func testTransport(t *testing.T) *HTTP2Transport {
	t.Helper()
	preset := fingerprint.Get("chrome-146")
	if preset == nil {
		t.Skip("chrome-146 preset unavailable")
	}
	tr := NewHTTP2Transport(preset, dns.NewCache())
	t.Cleanup(tr.Close)
	return tr
}

// streamingConn fakes a connection whose response body started long ago and is
// still producing bytes right now.
func streamingConn(inFlight int32, startedAgo, lastProgressAgo time.Duration) *persistentConn {
	c := &persistentConn{
		host:       "example.com",
		createdAt:  time.Now().Add(-startedAgo),
		lastUsedAt: time.Now().Add(-startedAgo),
		inFlight:   inFlight,
	}
	if lastProgressAgo >= 0 {
		c.lastProgress.Store(time.Now().Add(-lastProgressAgo).UnixNano())
	}
	return c
}

// The core of #83: a connection streaming a body is not destroyable even when
// it is far past both the idle timeout and the max connection age.
func TestH2StreamingConnNotDestroyed(t *testing.T) {
	tr := testTransport(t)

	// Started 10 minutes ago (past maxConnAge=5m), last "used" 10 minutes ago
	// (past maxIdleTime=90s), but actively delivering bytes as of a moment ago.
	conn := streamingConn(1, 10*time.Minute, 50*time.Millisecond)

	if tr.isConnDestroyable(conn) {
		t.Fatal("connection with an active response body was reported destroyable; " +
			"this is issue #83 - cleanup would close the socket under the reader")
	}

	// It is correctly considered unusable for NEW requests (too old), and those
	// two answers must not be conflated.
	if tr.isConnUsable(conn) {
		t.Fatal("connection past maxConnAge should not be handed out for new requests")
	}
}

// The cleanup pass itself must leave a streaming connection alone.
func TestH2CleanupSkipsStreamingConn(t *testing.T) {
	tr := testTransport(t)

	conn := streamingConn(1, 10*time.Minute, 50*time.Millisecond)
	tr.connsMu.Lock()
	tr.conns["example.com:443"] = conn
	tr.connsMu.Unlock()

	tr.cleanup()

	tr.connsMu.Lock()
	_, stillPooled := tr.conns["example.com:443"]
	tr.connsMu.Unlock()

	if !stillPooled {
		t.Fatal("cleanup evicted a connection that was still streaming a response body")
	}
}

// An idle connection past maxIdleTime must still be reaped, otherwise the fix
// would just leak sockets instead.
func TestH2CleanupStillReapsIdleConn(t *testing.T) {
	tr := testTransport(t)

	idle := &persistentConn{
		host:       "example.com",
		createdAt:  time.Now().Add(-5 * time.Minute),
		lastUsedAt: time.Now().Add(-5 * time.Minute),
		inFlight:   0,
	}
	if !tr.isConnDestroyable(idle) {
		t.Fatal("idle connection past maxIdleTime should be destroyable")
	}

	tr.connsMu.Lock()
	tr.conns["example.com:443"] = idle
	tr.connsMu.Unlock()

	tr.cleanup()

	tr.connsMu.Lock()
	_, stillPooled := tr.conns["example.com:443"]
	tr.connsMu.Unlock()

	if stillPooled {
		t.Fatal("cleanup failed to reap an idle connection")
	}
}

// A body the caller abandoned without closing must eventually be reclaimed,
// so holding inFlight for the body's lifetime cannot pin a socket forever.
func TestH2AbandonedBodyIsReclaimed(t *testing.T) {
	tr := testTransport(t)

	// In flight, but no byte has moved for longer than abandonedBodyTimeout.
	conn := streamingConn(1, 30*time.Minute, tr.abandonedBodyTimeout+time.Minute)

	if !tr.isConnDestroyable(conn) {
		t.Fatal("a response body with no progress past abandonedBodyTimeout should be reclaimable")
	}
}

// Reading to EOF and then closing must release the connection exactly once.
// A double decrement would drive inFlight negative and let cleanup close
// connections that other requests are still using.
func TestH2BodyGuardReleasesOnce(t *testing.T) {
	conn := &persistentConn{inFlight: 1, lastUsedAt: time.Now()}
	guard := &connBodyGuard{
		ReadCloser: io.NopCloser(strings.NewReader("hello")),
		conn:       conn,
	}

	if _, err := io.ReadAll(guard); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	// Close again, as a defensive caller or a `defer` pair might.
	_ = guard.Close()

	conn.mu.Lock()
	got := conn.inFlight
	conn.mu.Unlock()

	if got != 0 {
		t.Fatalf("inFlight = %d after read+close, want 0 (released exactly once)", got)
	}
}

// Reading the body must keep the progress timestamp moving, which is what
// separates a slow download from an abandoned one.
func TestH2BodyGuardRecordsProgress(t *testing.T) {
	conn := &persistentConn{inFlight: 1, lastUsedAt: time.Now().Add(-time.Hour)}
	guard := &connBodyGuard{
		ReadCloser: io.NopCloser(strings.NewReader(strings.Repeat("x", 1024))),
		conn:       conn,
	}

	buf := make([]byte, 16)
	if _, err := guard.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if p := conn.lastProgress.Load(); p == 0 {
		t.Fatal("reading the body did not record progress")
	} else if time.Since(time.Unix(0, p)) > time.Minute {
		t.Fatal("progress timestamp was not updated by the read")
	}
}

// Evicting a connection that is mid-stream must defer the close rather than
// tearing the socket down under the reader.
func TestH2RequestCloseDefersWhileStreaming(t *testing.T) {
	conn := &persistentConn{inFlight: 1, lastUsedAt: time.Now()}

	conn.requestClose()

	conn.mu.Lock()
	deferred := conn.closeRequested
	conn.mu.Unlock()
	if !deferred {
		t.Fatal("requestClose on a streaming connection should defer, not close immediately")
	}

	// And it must no longer be offered for new requests once evicted.
	tr := testTransport(t)
	if tr.isConnUsable(conn) {
		t.Fatal("a connection pending close should not be reused for new requests")
	}

	// Finishing the body triggers the deferred close without panicking on the
	// nil h2/tls handles this fake connection carries.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn.release()
	}()
	wg.Wait()

	conn.mu.Lock()
	got := conn.inFlight
	conn.mu.Unlock()
	if got != 0 {
		t.Fatalf("inFlight = %d after release, want 0", got)
	}
}
