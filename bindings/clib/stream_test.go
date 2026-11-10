//go:build hctest

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A read blocked on an idle stream had no safe way to be stopped from another
// thread: closing tears down the reader under the read. Cancelling must
// return the read, leave the stream for its owner to close, and leave the
// peer disconnected.
//
// Run with: go test -tags hctest -run Stream .
func TestStreamCancelReturnsABlockedRead(t *testing.T) {
	gone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done() // never send the byte; wait for the client to leave
		close(gone)
	}))
	defer srv.Close()

	h := hcTestSessionNew(`{"preset":"chrome-latest","timeout":10}`)
	defer hcTestSessionFree(h)
	stream, errMsg := hcTestStreamRequest(h, `{"method":"GET","url":"`+srv.URL+`","unbounded_body":true}`)
	if errMsg != "" {
		t.Fatal(errMsg)
	}

	read := make(chan int, 1)
	go func() { read <- hcTestStreamRead(stream, 64) }()
	time.Sleep(200 * time.Millisecond)
	select {
	case n := <-read:
		t.Fatalf("the read returned %d before anything was sent or cancelled", n)
	default:
	}

	hcTestStreamCancel(stream)
	select {
	case n := <-read:
		if n >= 0 {
			t.Errorf("a cancelled read returned %d, want -1", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream_cancel did not return the blocked read")
	}
	hcTestStreamClose(stream)
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("the peer was never disconnected")
	}
	hcTestStreamCancel(stream) // a closed handle is a no-op
}

// A stream's own timeout bounds its connection and headers too, so one longer
// than the session's is not cut off at the session's.
func TestStreamTimeoutOutlivesTheSessionTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		io.WriteString(w, "late")
	}))
	defer srv.Close()

	h := hcTestSessionNew(`{"preset":"chrome-latest","timeout":1}`)
	defer hcTestSessionFree(h)
	stream, errMsg := hcTestStreamRequest(h, `{"method":"GET","url":"`+srv.URL+`","timeout":5}`)
	if errMsg != "" {
		t.Fatalf("a 5s stream on a 1s session failed: %s", errMsg)
	}
	defer hcTestStreamClose(stream)
	if n := hcTestStreamRead(stream, 64); n != 4 {
		t.Errorf("read %d bytes, want 4", n)
	}
}

// Without a timeout of its own, the session's still bounds the headers, an
// unbounded body or not.
func TestStreamHeadersStillBoundedBySessionWhenUnbounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
	}))
	defer srv.Close()

	h := hcTestSessionNew(`{"preset":"chrome-latest","timeout":1}`)
	defer hcTestSessionFree(h)
	start := time.Now()
	_, errMsg := hcTestStreamRequest(h, `{"method":"GET","url":"`+srv.URL+`","unbounded_body":true}`)
	if errMsg == "" {
		t.Fatal("a 3s header wait beat a 1s session timeout")
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Errorf("the session timeout fired after %v", elapsed)
	}
}
