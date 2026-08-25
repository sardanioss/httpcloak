package transport

import (
	"context"
	"strconv"
	"testing"
	"time"
)

// Wire locks on what the HTTP/2 transport does when a request fails before its
// response headers arrive.
//
// The retry used to re-send the same *http.Request with no inspection of why
// the first attempt failed. That was wrong twice over.
//
// The body: RoundTrip streams the body out as it writes, so by the time the
// retry goes out the first attempt has consumed it. The replay carried the
// content-length it had already computed with zero DATA behind it. Malformed
// under RFC 9113 8.1.1, trivially visible server-side, and a silent
// correctness bug in its own right, because every retried request with a body
// lost the body.
//
// The classification: a browser replays a refused stream and a graceful
// GOAWAY, gives up on RST_STREAM(INTERNAL_ERROR) before headers, and never
// makes a second HTTP/2 attempt after HTTP_1_1_REQUIRED. Retrying everything
// produced two HEADERS arrivals where a real client produces one, on exactly
// the error codes a server chooses to send.

const (
	errCodeInternal       = 0x2
	errCodeRefusedStream  = 0x7
	errCodeHTTP11Required = 0xd
)

func retryTransport(t *testing.T) *Transport {
	t.Helper()
	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(tr.Close)
	return tr
}

// A refused stream is retried, and the retry carries the body it declares.
//
// This is both the positive control for the locks below and the body lock. The
// server refuses stream 1 after reading the whole request, so the client has
// genuinely spent the body before the retry begins.
func TestRetryReplaysTheBody(t *testing.T) {
	body := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	s := startH2Server(t, h2Config{
		ReadToEndStream: true,
		GrantCredit:     true,
		ResetStreams:    map[int]uint32{1: errCodeRefusedStream},
	})

	tr := retryTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := tr.Do(ctx, &Request{Method: "POST", URL: s.url("/upload"), Body: body})
	if err != nil {
		t.Fatalf("POST: %v\n%s", err, s.dump())
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	time.Sleep(100 * time.Millisecond)

	streams := s.attempts()
	if len(streams) != 2 {
		t.Fatalf("got %d HEADERS arrivals, want 2 (the refusal and the retry)\n%s",
			len(streams), s.dump())
	}

	blocks := s.decoded()
	if len(blocks) != 2 {
		t.Fatalf("decoded %d header blocks, want 2", len(blocks))
	}
	for i, h := range blocks {
		declared, err := strconv.Atoi(h["content-length"])
		if err != nil {
			t.Fatalf("attempt %d: content-length %q: %v", i+1, h["content-length"], err)
		}
		if declared != len(body) {
			t.Fatalf("attempt %d declared content-length %d, want %d", i+1, declared, len(body))
		}
		if got := s.dataBytes(streams[i]); got != declared {
			t.Fatalf("attempt %d (conn %d stream %d) declared content-length %d and sent "+
				"%d DATA bytes; a request that declares a length and does not "+
				"deliver it is malformed under RFC 9113 8.1.1\n%s",
				i+1, streams[i].Conn, streams[i].Stream, declared, got, s.dump())
		}
	}
}

// RST_STREAM(INTERNAL_ERROR) before headers is not retried. A real client
// surfaces the protocol error; we used to send the request again.
func TestNoRetryOnInternalError(t *testing.T) {
	s := startH2Server(t, h2Config{
		ResetStreams: map[int]uint32{1: errCodeInternal},
	})

	tr := retryTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/boom")}); err == nil {
		t.Fatal("expected an error for RST_STREAM(INTERNAL_ERROR) before headers")
	}
	time.Sleep(100 * time.Millisecond)

	if n := len(s.attempts()); n != 1 {
		t.Fatalf("got %d HEADERS arrivals for a stream reset with INTERNAL_ERROR, "+
			"want 1\n%s", n, s.dump())
	}
	if n := s.connCount(); n != 1 {
		t.Fatalf("server saw %d connections, want 1\n%s", n, s.dump())
	}
}

// HTTP_1_1_REQUIRED means the server has told us HTTP/2 is not on offer for
// this resource. A second HTTP/2 attempt is wasted and visible: the fallback
// belongs one layer up, on a connection whose ALPN offers http/1.1 alone.
func TestNoSecondHTTP2AttemptOnHTTP11Required(t *testing.T) {
	s := startH2Server(t, h2Config{
		ResetStreams: map[int]uint32{1: errCodeHTTP11Required},
	})

	tr := retryTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// The fallback has nowhere to go against an h2-only server, so the request
	// itself fails. What matters is how many HTTP/2 attempts it made first.
	tr.Do(ctx, &Request{Method: "GET", URL: s.url("/h1only")})
	time.Sleep(100 * time.Millisecond)

	if n := len(s.attempts()); n != 1 {
		t.Fatalf("got %d HTTP/2 HEADERS arrivals after HTTP_1_1_REQUIRED, want 1\n%s",
			n, s.dump())
	}
}

// A GET on a refused stream is retried, which keeps the two locks above from
// passing simply because nothing is ever retried any more.
func TestRefusedStreamIsStillRetried(t *testing.T) {
	s := startH2Server(t, h2Config{
		ResetStreams: map[int]uint32{1: errCodeRefusedStream},
	})

	tr := retryTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/refused")})
	if err != nil {
		t.Fatalf("GET: %v\n%s", err, s.dump())
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if n := len(s.attempts()); n != 2 {
		t.Fatalf("got %d HEADERS arrivals for a refused stream, want 2\n%s",
			n, s.dump())
	}
}
