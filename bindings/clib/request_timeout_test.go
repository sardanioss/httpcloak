//go:build hctest

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A request's own timeout used to bound only the context the clib built for
// it. Session.Do then applied Request.Timeout, which the clib never set, so it
// fell back to the session's timeout and the earlier deadline won: a request
// asking for longer than its session was cut off at the session's.
//
// Run with: go test -tags hctest -run RequestTimeout .
func TestRequestTimeoutOutlivesTheSessionTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		w.Write([]byte("late"))
	}))
	defer srv.Close()

	h := hcTestSessionNew(`{"preset":"chrome-latest","timeout":1}`)
	defer hcTestSessionFree(h)

	// httpcloak_request_raw reads the timeout in milliseconds.
	if meta, errMsg := hcTestRequestRaw(h, `{"method":"GET","url":"`+srv.URL+`","timeout":5000}`); errMsg != "" {
		t.Errorf("request_raw with a 5s timeout on a 1s session failed: %s", errMsg)
	} else if !strings.Contains(meta, `"status_code":200`) {
		t.Errorf("request_raw metadata = %s", meta)
	}

	// httpcloak_request reads it in seconds.
	if res := hcTestRequest(h, `{"method":"GET","url":"`+srv.URL+`","timeout":5}`); !strings.Contains(res, `"body":"late"`) {
		t.Errorf("request with a 5s timeout on a 1s session = %s", res)
	}
}

// A shorter request timeout still wins over the session's.
func TestRequestTimeoutShorterThanTheSessionStillApplies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	h := hcTestSessionNew(`{"preset":"chrome-latest","timeout":30}`)
	defer hcTestSessionFree(h)

	start := time.Now()
	_, errMsg := hcTestRequestRaw(h, `{"method":"GET","url":"`+srv.URL+`","timeout":300}`)
	if errMsg == "" {
		t.Fatal("a 300ms request timeout against a 2s handler succeeded")
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Errorf("the 300ms request timeout fired after %v", elapsed)
	}
}

// With no timeout of its own, the session's still applies.
func TestRequestWithoutTimeoutUsesTheSessions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
	}))
	defer srv.Close()

	h := hcTestSessionNew(`{"preset":"chrome-latest","timeout":1}`)
	defer hcTestSessionFree(h)

	start := time.Now()
	if _, errMsg := hcTestRequestRaw(h, `{"method":"GET","url":"`+srv.URL+`"}`); errMsg == "" {
		t.Fatal("a 3s handler beat a 1s session timeout")
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Errorf("the 1s session timeout fired after %v", elapsed)
	}
}
