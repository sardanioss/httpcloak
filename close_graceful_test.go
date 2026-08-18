package httpcloak

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/session"
)

// Session.CloseGraceful through the public API: a streamed response that is
// mid-body when the session is closed gracefully is delivered in full, the
// session refuses new requests from that moment, and Close afterwards is still
// available to force anything left draining.
func TestSessionCloseGracefulKeepsStreamingBody(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "first-")
		w.(http.Flusher).Flush()
		close(started)
		<-release
		io.WriteString(w, "second")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	s := NewSession("chrome-latest", WithForceHTTP2(), WithInsecureSkipVerify())
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := s.DoStream(ctx, &Request{Method: http.MethodGet, URL: srv.URL})
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	if stream.Protocol != "h2" {
		t.Fatalf("expected an HTTP/2 stream, got %q", stream.Protocol)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("server never flushed the first half of the body")
	}

	s.CloseGraceful()

	if s.IsActive() {
		t.Error("session should be inactive after CloseGraceful")
	}
	if _, err := s.Get(ctx, srv.URL); !errors.Is(err, session.ErrSessionClosed) {
		t.Errorf("Get after CloseGraceful: got %v, want ErrSessionClosed", err)
	}

	close(release)
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := stream.ReadAll()
		done <- result{b, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("reading the stream after CloseGraceful: %v", res.err)
		}
		if got, want := string(res.b), "first-second"; got != want {
			t.Fatalf("stream body after CloseGraceful = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not finish within 5s after CloseGraceful")
	}
	stream.Close()

	// Close after CloseGraceful is the hard close, and is safe to repeat.
	s.Close()
	s.Close()
	s.CloseGraceful()
}

// Close after CloseGraceful runs the transport's hard close a second time. On a
// default session that means every sub-transport, HTTP/3 included, has to take
// a repeated Close; pin that it does, in both orders and repeatedly.
func TestSessionCloseGracefulThenCloseIsSafe(t *testing.T) {
	t.Run("auto protocol", func(t *testing.T) {
		s := NewSession("chrome-latest")
		s.CloseGraceful()
		s.Close()
		s.Close()
		s.CloseGraceful()
		if s.IsActive() {
			t.Error("session should be inactive")
		}
	})
	t.Run("close then graceful", func(t *testing.T) {
		s := NewSession("chrome-latest")
		s.Close()
		s.CloseGraceful()
		s.Close()
		if s.IsActive() {
			t.Error("session should be inactive")
		}
	})
	t.Run("forced h3", func(t *testing.T) {
		s := NewSession("chrome-latest", WithForceHTTP3())
		s.CloseGraceful()
		s.Close()
	})
}
