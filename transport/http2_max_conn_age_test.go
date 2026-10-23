package transport

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

func TestHTTP2MaxConnAgeReusePolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		config  *TransportConfig
		age     time.Duration
		expired bool
	}{
		{"default_before_limit", nil, 4 * time.Minute, false},
		{"default_after_limit", nil, 6 * time.Minute, true},
		{"zero_keeps_default", &TransportConfig{}, 6 * time.Minute, true},
		{"longer_custom_limit", &TransportConfig{HTTP2MaxConnAge: 20 * time.Minute}, 10 * time.Minute, false},
		{"shorter_custom_limit", &TransportConfig{HTTP2MaxConnAge: time.Minute}, 2 * time.Minute, true},
		{"custom_limit_not_reached", &TransportConfig{HTTP2MaxConnAge: time.Minute}, 30 * time.Second, false},
		{"negative_disables_limit", &TransportConfig{HTTP2MaxConnAge: -1}, 24 * time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := startH2Server(t, h2Config{})
			tr := maxAgeTransport(t, tc.config)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			maxAgeRequest(t, ctx, tr, server)
			conn := maxAgeConnection(t, tr)
			conn.mu.Lock()
			conn.createdAt = time.Now().Add(-tc.age)
			conn.mu.Unlock()
			if got := tr.h2Transport.isConnUsable(conn); got == tc.expired {
				t.Fatalf("isConnUsable = %v, want %v", got, !tc.expired)
			}
			if got := tr.h2Transport.isConnDestroyable(conn); got != tc.expired {
				t.Fatalf("isConnDestroyable = %v, want %v", got, tc.expired)
			}

			// Exercise the cleanup path too: removing only the request-path age
			// check would still let the periodic reaper rotate a live connection.
			tr.h2Transport.cleanup()
			if tc.expired {
				waitMaxAgeConnectionClosed(t, ctx, conn)
			}
			maxAgeRequest(t, ctx, tr, server)
			attempts := server.attempts()
			if len(attempts) != 2 {
				t.Fatalf("request arrivals = %v, want two", attempts)
			}
			reused := attempts[0].Conn == attempts[1].Conn
			if reused == tc.expired {
				t.Fatalf("same TCP connection = %v, want %v; arrivals: %v", reused, !tc.expired, attempts)
			}
		})
	}
}

func TestHTTP2MaxConnAgeDisabledPreservesIdleAndClose(t *testing.T) {
	server := startH2Server(t, h2Config{})
	tr := maxAgeTransport(t, &TransportConfig{HTTP2MaxConnAge: -time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	maxAgeRequest(t, ctx, tr, server)
	idle := maxAgeConnection(t, tr)
	idle.mu.Lock()
	idle.lastUsedAt = time.Now().Add(-tr.h2Transport.maxIdleTime - time.Second)
	idle.mu.Unlock()
	if tr.h2Transport.isConnUsable(idle) || !tr.h2Transport.isConnDestroyable(idle) {
		t.Fatal("disabling age retirement must not disable the idle timeout")
	}
	tr.h2Transport.cleanup()
	waitMaxAgeConnectionClosed(t, ctx, idle)
	maxAgeRequest(t, ctx, tr, server)
	active := maxAgeConnection(t, tr)
	if active == idle || server.connCount() != 2 {
		t.Fatal("the idle connection was not replaced")
	}

	tr.Close()
	waitMaxAgeConnectionClosed(t, ctx, active)
	if resp, err := tr.DoStream(ctx, &Request{Method: "GET", URL: server.url("/closed")}); err == nil {
		resp.Close()
		t.Fatal("closed transport accepted another request")
	}
	if len(server.attempts()) != 2 {
		t.Fatal("closed transport sent another request")
	}
}

func TestHTTP2MaxConnAgeRetirementDrainsActiveBody(t *testing.T) {
	endStream := make(chan struct{})
	var endOnce sync.Once
	finish := func() { endOnce.Do(func() { close(endStream) }) }
	t.Cleanup(finish)
	server := startH2Server(t, h2Config{HoldEndStream: endStream})
	tr := maxAgeTransport(t, &TransportConfig{HTTP2MaxConnAge: time.Minute})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first, err := tr.DoStream(ctx, &Request{Method: "GET", URL: server.url("/first")})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := io.ReadFull(first, make([]byte, 2)); err != nil {
		t.Fatalf("read first body chunk: %v", err)
	}
	old := maxAgeConnection(t, tr)
	old.mu.Lock()
	old.createdAt = time.Now().Add(-2 * time.Minute)
	old.mu.Unlock()
	if tr.h2Transport.isConnUsable(old) || tr.h2Transport.isConnDestroyable(old) {
		t.Fatal("an aged connection must stop taking new requests without closing its active body")
	}
	tr.h2Transport.cleanup()
	if maxAgeConnection(t, tr) != old {
		t.Fatal("cleanup removed a connection while its body was active")
	}

	second, err := tr.DoStream(ctx, &Request{Method: "GET", URL: server.url("/second")})
	if err != nil {
		t.Fatalf("replacement request: %v", err)
	}
	defer second.Close()
	if maxAgeConnection(t, tr) == old || server.connCount() != 2 {
		t.Fatal("a new request reused the aged connection")
	}
	old.mu.Lock()
	closed := old.closed
	old.mu.Unlock()
	if closed {
		t.Fatal("retirement closed the connection before its body finished")
	}

	finish()
	if _, err := io.Copy(io.Discard, first); err != nil {
		t.Fatalf("first body did not survive retirement: %v", err)
	}
	if _, err := io.Copy(io.Discard, second); err != nil {
		t.Fatalf("replacement body: %v", err)
	}
	waitMaxAgeConnectionClosed(t, ctx, old)
}

func TestHTTP2MaxConnAgeDisabledPreservesAbandonedBodyLimit(t *testing.T) {
	tr := maxAgeTransport(t, &TransportConfig{HTTP2MaxConnAge: -1})
	conn := streamingConn(1, 24*time.Hour, time.Second)
	if tr.h2Transport.isConnDestroyable(conn) {
		t.Fatal("an active body was considered abandoned solely because of its age")
	}
	conn.lastProgress.Store(time.Now().Add(-tr.h2Transport.abandonedBodyTimeout - time.Second).UnixNano())
	if !tr.h2Transport.isConnDestroyable(conn) {
		t.Fatal("disabling age retirement also disabled abandoned-body cleanup")
	}
}

func TestHTTP2MaxConnAgeSurvivesTransportRebuilds(t *testing.T) {
	for _, age := range []time.Duration{0, 123456 * time.Nanosecond, -1} {
		t.Run(age.String(), func(t *testing.T) {
			tr := maxAgeTransport(t, &TransportConfig{HTTP2MaxConnAge: age})
			want := age
			if want == 0 {
				want = 5 * time.Minute
			}
			for _, step := range []struct {
				name string
				run  func()
			}{
				{"Refresh", tr.Refresh},
				{"RefreshWithProtocol", func() { tr.RefreshWithProtocol(ProtocolHTTP2) }},
				{"SetProxy", func() { tr.SetProxy(nil) }},
				{"SetPreset", func() { tr.SetPreset("firefox-latest") }},
			} {
				step.run()
				if got := tr.h2Transport.maxConnAge; got != want {
					t.Fatalf("effective age limit after %s = %v, want %v", step.name, got, want)
				}
			}
		})
	}
}

func maxAgeTransport(t *testing.T, config *TransportConfig) *Transport {
	t.Helper()
	tr := NewTransportWithConfig("chrome-latest", nil, config)
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(tr.Close)
	return tr
}

func maxAgeRequest(t *testing.T, ctx context.Context, tr *Transport, server *h2Server) {
	t.Helper()
	resp, err := tr.DoStream(ctx, &Request{Method: "GET", URL: server.url("/age")})
	if err != nil {
		t.Fatalf("streaming request: %v", err)
	}
	defer resp.Close()
	if _, err := io.Copy(io.Discard, resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 200 || resp.Protocol != "h2" {
		t.Fatalf("status = %d, protocol = %q", resp.StatusCode, resp.Protocol)
	}
}

func maxAgeConnection(t *testing.T, tr *Transport) *persistentConn {
	t.Helper()
	tr.h2Transport.connsMu.RLock()
	defer tr.h2Transport.connsMu.RUnlock()
	if len(tr.h2Transport.conns) != 1 {
		t.Fatalf("pooled connections = %d, want one", len(tr.h2Transport.conns))
	}
	for _, conn := range tr.h2Transport.conns {
		return conn
	}
	return nil
}

func waitMaxAgeConnectionClosed(t *testing.T, ctx context.Context, conn *persistentConn) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		conn.mu.Lock()
		closed := conn.closed
		conn.mu.Unlock()
		if closed && conn.h2Conn.State().Closed {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("retired connection was not closed")
		case <-ticker.C:
		}
	}
}
