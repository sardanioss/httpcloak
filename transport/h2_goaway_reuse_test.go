package transport

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A server that closes an idle HTTP/2 connection sends GOAWAY first, and the
// connection stays in the pool until something evicts it. It must not be
// handed to the next request: that request would fail and only get through on
// the retry, which a body that can't be replayed doesn't get (#141).
func TestHTTP2SkipsConnectionAfterGoAway(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.Copy(io.Discard, r.Body)
		w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.Config.IdleTimeout = 100 * time.Millisecond
	srv.StartTLS()
	defer srv.Close()

	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := tr.Do(ctx, &Request{Method: "GET", URL: srv.URL + "/a"})
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp.Close()

	h2 := tr.h2Transport
	h2.connsMu.RLock()
	var conn *persistentConn
	for _, c := range h2.conns {
		conn = c
	}
	h2.connsMu.RUnlock()
	if conn == nil {
		t.Fatal("no pooled HTTP/2 connection after the first request")
	}
	if !h2.isConnUsable(conn) {
		t.Fatal("a fresh connection is not usable")
	}

	deadline := time.Now().Add(3 * time.Second)
	for !connClosing(conn) {
		if time.Now().After(deadline) {
			t.Fatal("the server never sent GOAWAY on the idle connection")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h2.isConnUsable(conn) {
		t.Fatal("a connection that received GOAWAY is still handed out")
	}

	// And the next request goes out on a new connection.
	resp, err = tr.Do(ctx, &Request{Method: "POST", URL: srv.URL + "/b", BodyReader: strings.NewReader("payload")})
	if err != nil {
		t.Fatalf("request after GOAWAY: %v", err)
	}
	resp.Close()
	if n := hits.Load(); n != 2 {
		t.Fatalf("server saw %d requests, want 2", n)
	}
}
