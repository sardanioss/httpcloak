package transport

import (
	"context"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// The HTTP/1.1 response timeout (60s in production, shortened here) used to be
// armed before the request was written and left on the socket while the body
// was read, so it capped the whole exchange: every HTTP/1.1 stream, upload and
// large download died at 60s with "i/o timeout", whatever its context allowed.
// It now bounds only the wait for the response headers.

func h1TransportWithResponseTimeout(t *testing.T, d time.Duration) *Transport {
	t.Helper()
	if fingerprint.Get("chrome-146") == nil {
		t.Skip("chrome-146 preset unavailable")
	}
	tr := NewTransport("chrome-146")
	tr.SetProtocol(ProtocolHTTP1)
	tr.h1Transport.responseTimeout = d
	t.Cleanup(tr.Close)
	return tr
}

// A stream that keeps sending outlives the response timeout.
func TestH1StreamBodyOutlivesTheResponseTimeout(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		for i := 0; i < 6; i++ {
			io.WriteString(w, "tick\n")
			w.(stdhttp.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	defer srv.Close()

	tr := h1TransportWithResponseTimeout(t, 250*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := tr.DoStream(ctx, &Request{Method: http.MethodGet, URL: srv.URL})
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()
	body, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("reading a 600ms stream with a 250ms response timeout: %v", err)
	}
	if got := strings.Count(string(body), "tick"); got != 6 {
		t.Errorf("read %d ticks, want 6", got)
	}
}

// A buffered body slower than the response timeout still arrives whole.
func TestH1BufferedBodyOutlivesTheResponseTimeout(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Length", "10")
		io.WriteString(w, "01234")
		w.(stdhttp.Flusher).Flush()
		time.Sleep(500 * time.Millisecond)
		io.WriteString(w, "56789")
	}))
	defer srv.Close()

	tr := h1TransportWithResponseTimeout(t, 250*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := tr.Do(ctx, &Request{Method: http.MethodGet, URL: srv.URL})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "0123456789" {
		t.Errorf("body = %q, %v", body, err)
	}
}

// The response timeout still bounds a server that never answers.
func TestH1ResponseTimeoutStillBoundsTheWaitForHeaders(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	tr := h1TransportWithResponseTimeout(t, 250*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := tr.Do(ctx, &Request{Method: http.MethodGet, URL: srv.URL}); err == nil {
		t.Fatal("a server that never answered was not timed out")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v to time out, want about 250ms", elapsed)
	}
}

// And the context still bounds the body.
func TestH1ContextStillBoundsTheBody(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		for {
			if _, err := io.WriteString(w, "tick\n"); err != nil {
				return
			}
			w.(stdhttp.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer srv.Close()

	tr := h1TransportWithResponseTimeout(t, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	stream, err := tr.DoStream(ctx, &Request{Method: http.MethodGet, URL: srv.URL})
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	defer stream.Close()
	start := time.Now()
	if _, err := io.ReadAll(stream); err == nil {
		t.Fatal("an endless stream ended without error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("the 400ms context ended the stream after %v", elapsed)
	}
}
