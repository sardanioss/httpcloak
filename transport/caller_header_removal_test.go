package transport

import (
	"context"
	"testing"
	"time"

	http "github.com/sardanioss/http"
)

// A name whose only value is "" removes the header, preset or not, and touches
// nothing else.
func TestMergeCallerHeadersEmptyValueRemoves(t *testing.T) {
	httpReq := &http.Request{Header: http.Header{
		"Priority":   {"u=1"},
		"Accept":     {"*/*"},
		"User-Agent": {"preset-agent"},
	}}
	mergeCallerHeaders(httpReq, &Request{Headers: map[string][]string{
		"priority":  {""},
		"x-absent":  {""},
		"accept":    {"text/css"},
		"x-twofold": {"", "kept"},
	}})
	want := http.Header{
		"Accept":     {"text/css"},
		"User-Agent": {"preset-agent"},
		"X-Twofold":  {"", "kept"},
	}
	if len(httpReq.Header) != len(want) {
		t.Fatalf("header = %v, want %v", httpReq.Header, want)
	}
	for k, v := range want {
		if got := httpReq.Header[k]; len(got) != len(v) || (len(v) > 0 && got[len(got)-1] != v[len(v)-1]) {
			t.Errorf("header[%q] = %v, want %v", k, got, v)
		}
	}
}

// Chrome sends no Priority with an async <script>, though its priority table
// gives every script one. Dropping the preset's with "" has to reach the wire:
// the field must be gone from the HEADERS frame, not sent empty.
func TestEmptyCallerHeaderLeavesThePresetsOffTheWire(t *testing.T) {
	srv := startH2CaptureServer(t)
	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	send := func(headers map[string][]string) h2Capture {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + srv.addr + "/script.js", Headers: headers}); err != nil {
			t.Fatalf("request: %v", err)
		}
		select {
		case c := <-srv.captures:
			return c
		case <-time.After(5 * time.Second):
			t.Fatal("no HEADERS frame captured")
			return h2Capture{}
		}
	}
	script := func(extra ...string) map[string][]string {
		h := map[string][]string{"Sec-Fetch-Dest": {"script"}, "Sec-Fetch-Mode": {"no-cors"}}
		for i := 0; i+1 < len(extra); i += 2 {
			h[extra[i]] = []string{extra[i+1]}
		}
		return h
	}

	if c := send(script()); c.Headers["priority"] == "" {
		t.Fatalf("the preset sends no Priority for a script, so this test checks nothing: %v", c.HeaderOrder)
	}
	c := send(script("Priority", ""))
	for _, name := range c.HeaderOrder {
		if name == "priority" {
			t.Fatalf("priority still on the wire (%q): %v", c.Headers["priority"], c.HeaderOrder)
		}
	}
	if c.Headers["sec-fetch-dest"] != "script" || c.Headers["user-agent"] == "" {
		t.Errorf("removing one header disturbed the rest: %v", c.HeaderOrder)
	}
}
