//go:build hctest

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A request that fails before it reads the body used to leave the upload
// wedged: the write blocked forever on a pipe nobody would drain, and cancel
// and finish waited behind it on the upload's mutex. Seen with a refused
// connection; an unknown preset or a bad URL does the same.
//
// Run with: go test -tags hctest -run Upload .
func TestUploadWriteFailsWhenTheRequestFailsFirst(t *testing.T) {
	h := hcTestSessionNew(`{"preset":"chrome-latest","timeout":10}`)
	if h <= 0 {
		t.Fatalf("session_new returned %d", h)
	}
	defer hcTestSessionFree(h)

	up := hcTestUploadStart(h, "http://"+refusedAddr(t)+"/", `{}`)
	if up <= 0 {
		t.Fatalf("upload_start returned %d", up)
	}

	// Large enough that the pipe cannot have taken it before the request
	// failed: a write is only accepted once something reads it.
	done := make(chan int, 1)
	go func() { done <- hcTestUploadWrite(up, make([]byte, 1<<20)) }()
	select {
	case n := <-done:
		if n >= 0 {
			t.Errorf("upload_write_raw returned %d for a request that never connected, want -1", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upload_write_raw is still blocked 10s after the request failed")
	}

	finished := make(chan string, 1)
	go func() { finished <- hcTestUploadFinish(up) }()
	select {
	case res := <-finished:
		if !strings.Contains(res, `"error"`) || !strings.Contains(res, "refused") {
			t.Errorf("upload_finish = %s, want the connection error", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upload_finish blocked")
	}
}

// Cancelling an upload whose write is blocked, because the server has not read
// the body yet, must unblock that write rather than wait for it.
func TestUploadCancelUnblocksAPendingWrite(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // read nothing until the test is over
		w.WriteHeader(200)
	}))
	defer srv.Close()
	defer close(release)

	h := hcTestSessionNew(`{"preset":"chrome-latest","timeout":10}`)
	defer hcTestSessionFree(h)
	up := hcTestUploadStart(h, srv.URL, `{}`)

	// Far more than socket buffers hold, so the write blocks on the server.
	done := make(chan int, 1)
	go func() { done <- hcTestUploadWrite(up, make([]byte, 64<<20)) }()
	time.Sleep(300 * time.Millisecond)

	cancelled := make(chan struct{})
	go func() { hcTestUploadCancel(up); close(cancelled) }()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("upload_cancel blocked behind the pending write")
	}
	select {
	case n := <-done:
		if n >= 0 {
			t.Errorf("the cancelled write returned %d, want -1", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pending write was not released by cancel")
	}
}

// A successful upload still works, and the body arrives whole.
func TestUploadRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s %d", r.Method, len(b))
	}))
	defer srv.Close()

	h := hcTestSessionNew(`{"preset":"chrome-latest","timeout":10}`)
	defer hcTestSessionFree(h)
	up := hcTestUploadStart(h, srv.URL, `{"method":"PUT"}`)
	for i := 0; i < 4; i++ {
		if n := hcTestUploadWrite(up, make([]byte, 100_000)); n != 100_000 {
			t.Fatalf("write %d returned %d", i, n)
		}
	}
	res := hcTestUploadFinish(up)
	if !strings.Contains(res, `"body":"PUT 400000"`) {
		t.Errorf("upload_finish = %s", res)
	}
}

// The upload's own timeout bounds it, not the session's: the 5 minute default
// was cut to the session's 30s (here 1s) because the request carried none.
func TestUploadTimeoutOutlivesTheSessionTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		time.Sleep(1500 * time.Millisecond)
		w.Write([]byte("late"))
	}))
	defer srv.Close()

	h := hcTestSessionNew(`{"preset":"chrome-latest","timeout":1}`)
	defer hcTestSessionFree(h)
	up := hcTestUploadStart(h, srv.URL, `{"timeout":5000}`)
	hcTestUploadWrite(up, []byte("x"))
	if res := hcTestUploadFinish(up); !strings.Contains(res, `"body":"late"`) {
		t.Errorf("upload_finish = %s, want the response the 5s upload timeout allows", res)
	}
}

func refusedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
