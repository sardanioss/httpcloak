package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// TestPoolReuseSequential is an independent check that the issue #83 port
// did not turn every request into a fresh TCP+TLS connection.
func TestPoolReuseSequential(t *testing.T) {
	var mu sync.Mutex
	remotes := map[string]int{}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		remotes[r.RemoteAddr]++
		mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	c := NewClient("chrome-latest", WithForceHTTP2(), WithInsecureSkipVerify(), WithTimeout(20*time.Second))
	defer c.Close()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		resp, err := c.Do(ctx, &Request{Method: http.MethodGet, URL: server.URL})
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	t.Logf("distinct server-side connections: %d -> %v", len(remotes), remotes)
	if len(remotes) != 1 {
		t.Fatalf("expected 5 sequential requests to reuse ONE connection, got %d distinct: %v", len(remotes), remotes)
	}
}

// TestPoolReuseStreaming checks the streaming path reuses too, once each
// stream body has been closed.
func TestPoolReuseStreaming(t *testing.T) {
	var mu sync.Mutex
	remotes := map[string]int{}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		remotes[r.RemoteAddr]++
		mu.Unlock()
		fmt.Fprint(w, "hello world")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	c := NewClient("chrome-latest", WithForceHTTP2(), WithInsecureSkipVerify(), WithTimeout(20*time.Second))
	defer c.Close()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		s, err := c.DoStream(ctx, &Request{Method: http.MethodGet, URL: server.URL})
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		if _, err := s.ReadAll(); err != nil {
			t.Fatalf("stream %d read: %v", i, err)
		}
		s.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	t.Logf("distinct server-side connections: %d -> %v", len(remotes), remotes)
	if len(remotes) != 1 {
		t.Fatalf("expected 5 sequential streams to reuse ONE connection, got %d distinct: %v", len(remotes), remotes)
	}
}

// TestPoolIdleStillReaped confirms an idle connection is still closed on
// the normal schedule (nothing pinned it just because the port added refcounts).
func TestPoolIdleStillReaped(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	c := NewClient("chrome-latest", WithForceHTTP2(), WithInsecureSkipVerify(), WithTimeout(20*time.Second))
	defer c.Close()

	ctx := context.Background()
	if _, err := c.Do(ctx, &Request{Method: http.MethodGet, URL: server.URL}); err != nil {
		t.Fatalf("request: %v", err)
	}

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	hp, err := c.poolManager.GetPool(host, port)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	total, _, _ := hp.Stats()
	if total != 1 {
		t.Fatalf("want 1 pooled conn, got %d", total)
	}

	// Age the conn past maxIdleTime with nothing in flight, then reap.
	conn, err := hp.GetConn(context.Background())
	if err != nil {
		t.Fatalf("GetConn: %v", err)
	}
	conn.LastUsedAt = time.Now().Add(-10 * time.Minute)
	hp.CloseIdle()

	if total, _, _ := hp.Stats(); total != 0 {
		t.Fatalf("idle connection was NOT reaped: total=%d, want 0", total)
	}
}

// TestPoolReuseAcrossRedirects: the buffered Do path holds the parent response
// body open (defer resp.Body.Close()) across the whole redirect chain, so the
// parent request is still counted in-flight when the redirect is issued. Check
// that does not push the redirect onto a second socket.
func TestPoolReuseAcrossRedirects(t *testing.T) {
	var mu sync.Mutex
	remotes := map[string]int{}

	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		remotes[r.RemoteAddr]++
		mu.Unlock()
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		remotes[r.RemoteAddr]++
		mu.Unlock()
		fmt.Fprint(w, "done")
	})
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	c := NewClient("chrome-latest", WithForceHTTP2(), WithInsecureSkipVerify(), WithTimeout(20*time.Second))
	defer c.Close()

	for i := 0; i < 3; i++ {
		resp, err := c.Do(context.Background(), &Request{Method: http.MethodGet, URL: server.URL + "/a"})
		if err != nil {
			t.Fatalf("redirect request %d: %v", i, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	t.Logf("distinct connections across 3 redirect chains (6 requests): %d -> %v", len(remotes), remotes)
	if len(remotes) != 1 {
		t.Fatalf("redirect chain opened extra connections: %d distinct: %v", len(remotes), remotes)
	}
}

// TestPoolReuseConcurrent: overlapping requests must still multiplex onto
// one H2 connection. If the new retire-on-unusable branch fired on transient
// state this would fan out into many sockets.
func TestPoolReuseConcurrent(t *testing.T) {
	var mu sync.Mutex
	remotes := map[string]int{}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		remotes[r.RemoteAddr]++
		mu.Unlock()
		time.Sleep(150 * time.Millisecond)
		fmt.Fprint(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	c := NewClient("chrome-latest", WithForceHTTP2(), WithInsecureSkipVerify(), WithTimeout(20*time.Second))
	defer c.Close()

	// warm the pool so all 20 start from an established conn
	if _, err := c.Do(context.Background(), &Request{Method: http.MethodGet, URL: server.URL}); err != nil {
		t.Fatalf("warmup: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Do(context.Background(), &Request{Method: http.MethodGet, URL: server.URL}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent request: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	t.Logf("distinct connections for 21 overlapping requests: %d -> %v", len(remotes), remotes)
	if len(remotes) != 1 {
		t.Fatalf("concurrent requests fanned out to %d connections: %v", len(remotes), remotes)
	}
}
