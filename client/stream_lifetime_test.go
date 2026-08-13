package client

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestDoStreamSurvivesConnectionRetirement is the end-to-end form of issue #83
// on the client.Client path: a stream that is still being read must survive the
// pool reaper deciding the connection is too old for new requests.
//
// The connection is force-aged past maxConnAge and CloseIdle() is called
// directly, so the 90s/5m timers never have to elapse.
//
// Test shape (real H2 httptest server driven with WithForceHTTP2) borrowed from
// PR #84.
func TestDoStreamSurvivesConnectionRetirement(t *testing.T) {
	writeSecondEvent := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()

		select {
		case <-writeSecondEvent:
			fmt.Fprint(w, "data: second\n\n")
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	c := NewClient("chrome-latest",
		WithForceHTTP2(),
		WithInsecureSkipVerify(),
		WithTimeout(30*time.Second),
	)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := c.DoStream(ctx, &Request{Method: http.MethodGet, URL: server.URL})
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()

	reader := bufio.NewReader(stream)
	if event := readSSEEvent(t, reader); event != "data: first\n\n" {
		t.Fatalf("first event = %q", event)
	}

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	host, port, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatalf("split server host: %v", err)
	}
	hostPool, err := c.poolManager.GetPool(host, port)
	if err != nil {
		t.Fatalf("get host pool: %v", err)
	}

	// The stream's connection is still usable (a live body means idle time does
	// not count), so GetConn hands back the very connection the stream is on.
	streamConn, err := hostPool.GetConn(ctx)
	if err != nil {
		t.Fatalf("get stream connection: %v", err)
	}

	// Age it past maxConnAge and run the reaper tick. Pre-fix this hard-closed
	// the TLS socket under the live stream and the next read failed with
	// "use of closed network connection".
	streamConn.CreatedAt = time.Now().Add(-10 * time.Minute)
	hostPool.CloseIdle()

	// CloseIdle tears connections down on a goroutine, so give any (wrong)
	// close time to actually land before the read below. Otherwise this
	// assertion could pass by winning a race rather than by being correct.
	time.Sleep(200 * time.Millisecond)

	// The live stream must keep working across the reap.
	close(writeSecondEvent)
	if event := readSSEEvent(t, reader); event != "data: second\n\n" {
		t.Fatalf("second event = %q", event)
	}

	// Retired, so no NEW request may land on it...
	replacement, err := hostPool.GetConn(ctx)
	if err != nil {
		t.Fatalf("get replacement connection: %v", err)
	}
	if replacement == streamConn {
		t.Fatal("an aged connection was handed out for a new request")
	}
	// ...but it must still be tracked, or nothing can ever close it and the fd
	// escapes client.Close() (the hole in PR #84).
	if total, _, _ := hostPool.Stats(); total < 2 {
		t.Fatalf("retired connection stopped being tracked: total=%d, want >= 2", total)
	}
}

func readSSEEvent(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	var event strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE event: %v", err)
		}
		event.WriteString(line)
		if line == "\n" {
			return event.String()
		}
	}
}

// TestPooledRoundTripGoesThroughConnGuard is a call-site lock.
//
// The body guard only exists if the client sends via conn.RoundTrip. Calling
// conn.HTTP2Conn.RoundTrip / conn.HTTP3RT.RoundTrip directly compiles fine and
// silently reintroduces issue #83, so pin the call sites in source.
func TestPooledRoundTripGoesThroughConnGuard(t *testing.T) {
	bare := regexp.MustCompile(`conn\.(HTTP2Conn|HTTP3RT)\.RoundTrip\(`)
	for _, file := range []string{"client.go", "http3_client.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if loc := bare.FindString(string(src)); loc != "" {
			t.Fatalf("%s: %s bypasses (*pool.Conn).RoundTrip, so the response body is "+
				"never guarded and the pool can reap the connection mid-stream (issue #83)", file, loc)
		}
	}
}

// TestBufferedDoReleasesConnection is a no-regression lock on the buffered Do
// path (passes before and after the fix). The guard must not leave the
// connection pinned after Do has read and closed the body, or every buffered
// request would slowly retire the pool.
func TestBufferedDoReleasesConnection(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	c := NewClient("chrome-latest",
		WithForceHTTP2(),
		WithInsecureSkipVerify(),
		WithTimeout(30*time.Second),
	)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := 0; i < 2; i++ {
		resp, err := c.Do(ctx, &Request{Method: http.MethodGet, URL: server.URL})
		if err != nil {
			t.Fatalf("Do %d: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Do %d status = %d", i, resp.StatusCode)
		}
	}

	serverURL, _ := url.Parse(server.URL)
	host, port, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatalf("split server host: %v", err)
	}
	hostPool, err := c.poolManager.GetPool(host, port)
	if err != nil {
		t.Fatalf("get host pool: %v", err)
	}

	// Both requests must have shared one connection, and it must still be idle
	// and reusable now.
	if total, _, _ := hostPool.Stats(); total != 1 {
		t.Fatalf("pool holds %d connections after two buffered requests, want 1", total)
	}
	conn, err := hostPool.GetConn(ctx)
	if err != nil {
		t.Fatalf("get conn: %v", err)
	}
	if total, _, _ := hostPool.Stats(); total != 1 {
		t.Fatalf("connection was not reusable after Do: pool grew to %d", total)
	}
	_ = conn
}
