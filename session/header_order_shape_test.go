package session

import (
	"context"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// Chrome emits a different header order for a top-level navigation than for
// anything the page then fetches. Captured from Chrome 152 on Windows over 20
// requests: script, style, image, font, manifest and empty all produce one
// order, document produces another, and the difference is confined to the
// leading block.
//
// httpcloak carried a single order and applied it to every request, so a
// subresource went out with navigation ordering. Everything else about it was
// already right, the values and the Sec-Fetch-* set included, which is what made
// the ordering the only thing left saying "this request was not built the way a
// browser builds one".
func orderOf(t *testing.T, dest string) []string {
	t.Helper()
	srv := newBodyCapture(t, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{})
	req := &transport.Request{Method: "GET", URL: srv.url + "x"}
	if dest != "" {
		req.Headers = map[string][]string{
			"Sec-Fetch-Dest": {dest},
			"Sec-Fetch-Mode": {"no-cors"},
			"Sec-Fetch-Site": {"same-origin"},
			"Referer":        {"https://example.com/page"},
		}
	}
	if _, err := s.Request(context.Background(), req); err != nil {
		t.Fatalf("dest=%q: %v", dest, err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.hops) != 1 {
		t.Fatalf("dest=%q: server saw %d requests, want 1", dest, len(srv.hops))
	}
	return srv.hops[0].headers
}

func idx(order []string, name string) int {
	for i, h := range order {
		if h == name {
			return i
		}
	}
	return -1
}

func TestNavigationKeepsItsCapturedOrder(t *testing.T) {
	got := orderOf(t, "")
	want := []string{
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"upgrade-insecure-requests", "user-agent", "accept",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
		"accept-encoding", "accept-language",
	}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("navigation order is\n  %v\nwant it to start\n  %v", got, want)
		}
	}
}

// A subresource leads with the platform hint and the user agent, not with the
// sec-ch-ua trio. That single fact is the whole divergence, so it is what this
// asserts: on a navigation sec-ch-ua comes first, on a subresource it does not.
func TestSubresourceLeadsWithPlatformAndUserAgent(t *testing.T) {
	got := orderOf(t, "image")

	if len(got) < 4 {
		t.Fatalf("subresource sent only %d headers: %v", len(got), got)
	}
	if got[0] != "sec-ch-ua-platform" {
		t.Errorf("subresource leads with %q, want sec-ch-ua-platform; it is still "+
			"using the navigation order", got[0])
	}
	if got[1] != "user-agent" {
		t.Errorf("second header is %q, want user-agent", got[1])
	}
	if p, u, c := idx(got, "sec-ch-ua-platform"), idx(got, "user-agent"), idx(got, "sec-ch-ua"); !(p < u && u < c) {
		t.Errorf("want sec-ch-ua-platform < user-agent < sec-ch-ua, got positions %d, %d, %d in %v", p, u, c, got)
	}

	// Chrome does not send these two on a subresource at all.
	for _, absent := range []string{"upgrade-insecure-requests", "sec-fetch-user"} {
		if idx(got, absent) >= 0 {
			t.Errorf("subresource carries %q, which Chrome sends only on a navigation", absent)
		}
	}

	// referer has a reserved slot rather than landing in the sorted tail.
	if r, ae := idx(got, "referer"), idx(got, "accept-encoding"); r < 0 || ae < 0 || r > ae {
		t.Errorf("referer at %d, accept-encoding at %d; want referer immediately before "+
			"the accept-encoding block, not appended to the tail: %v", r, ae, got)
	}
}

// And the two shapes must actually differ, so a change that quietly collapses
// them back to one order fails rather than passing on the navigation assertions.
func TestTheTwoShapesDiffer(t *testing.T) {
	nav := strings.Join(orderOf(t, ""), ",")
	sub := strings.Join(orderOf(t, "image"), ",")
	if nav == sub {
		t.Errorf("navigation and subresource produced the same order:\n  %s", nav)
	}
}

// Exact-headers mode promises nothing the caller did not list reaches the wire.
// The HTTP/1.1 writer supplies Connection on every request, which is right for
// the normal path and wrong here: a caller reproducing a captured request that
// carries no Connection cannot have one added back.
//
// Nothing is lost by leaving it out. HTTP/1.1 keeps connections alive by
// default, so the header restates the default rather than causing it.
func TestExactHeadersSuppressesConnection(t *testing.T) {
	srv := newBodyCapture(t, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{})
	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "x",
		ExactHeaders: []fingerprint.HeaderPair{
			{Key: "user-agent", Value: "mirror/1"},
			{Key: "accept", Value: "*/*"},
		},
	}); err != nil {
		t.Fatalf("request: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, h := range srv.hops[0].allHeaders {
		if h == "connection" {
			t.Error("exact headers still emitted Connection; the caller did not list it")
		}
	}
	// Host is protocol framing and stays, per the documented contract.
	found := false
	for _, h := range srv.hops[0].allHeaders {
		if h == "host" {
			found = true
		}
	}
	if !found {
		t.Error("Host was dropped; it is protocol framing, not a caller header")
	}
}

// And a caller who does list Connection gets exactly what they asked for.
func TestExactHeadersHonoursAListedConnection(t *testing.T) {
	srv := newBodyCapture(t, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{})
	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "x",
		ExactHeaders: []fingerprint.HeaderPair{
			{Key: "user-agent", Value: "mirror/1"},
			{Key: "Connection", Value: "close"},
		},
	}); err != nil {
		t.Fatalf("request: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	found := false
	for _, h := range srv.hops[0].allHeaders {
		if h == "connection" {
			found = true
		}
	}
	if !found {
		t.Error("a listed Connection was dropped")
	}
}

// The normal path keeps Connection, since Chrome sends it on every H1 request.
func TestNormalPathStillSendsConnection(t *testing.T) {
	srv := newBodyCapture(t, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{})
	if _, err := s.Request(context.Background(), &transport.Request{Method: "GET", URL: srv.url + "x"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, h := range srv.hops[0].allHeaders {
		if h == "connection" {
			return
		}
	}
	t.Error("the normal path stopped sending Connection; only exact headers should suppress it")
}

// Exact-headers mode exists so a captured request can be replayed byte for
// byte, and a capture routinely carries two fields of one name with something
// else between them. A map cannot hold that, so the order list has to: one slot
// per pair, each slot taking the value at its own index.
//
// The old form gave a name one slot and emitted all of its values there, which
// silently rewrote cookie, accept, cookie into cookie, cookie, accept. The
// request still succeeded, which is why this asserts on what the SERVER read
// rather than on the request object.
func TestExactHeadersKeepInterleavedDuplicates(t *testing.T) {
	srv := newBodyCapture(t, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{})
	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "x",
		ExactHeaders: []fingerprint.HeaderPair{
			{Key: "cookie", Value: "a=1"},
			{Key: "accept", Value: "*/*"},
			{Key: "cookie", Value: "b=2"},
			{Key: "user-agent", Value: "mirror/1"},
		},
	}); err != nil {
		t.Fatalf("request: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	var got []string
	for _, p := range srv.hops[0].pairs {
		if strings.HasPrefix(p, "host:") {
			continue
		}
		got = append(got, p)
	}
	want := []string{"cookie: a=1", "accept: */*", "cookie: b=2", "user-agent: mirror/1"}
	if strings.Join(got, " | ") != strings.Join(want, " | ") {
		t.Errorf("wire fields =\n  %v\nwant\n  %v", got, want)
	}
}

// Exact mode promises nothing the caller did not list reaches the wire, and the
// session's own cookie jar is the loudest counter-example: it writes a Cookie
// header into Request.Headers on every attempt, and the transport merged that
// map over the exact set unconditionally. A request built to mirror a capture
// went out with a jar cookie appended to it.
func TestExactHeadersIgnoreTheCallerHeaderMap(t *testing.T) {
	srv := newBodyCapture(t, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{})
	host, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimSuffix(srv.url, "/"), "http://"), ":")
	s.SetCookie("jar", "yes", host, "/", false, false, "", 0, nil)
	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "x",
		Headers: map[string][]string{"X-Extra": {"1"}},
		ExactHeaders: []fingerprint.HeaderPair{
			{Key: "user-agent", Value: "mirror/1"},
			{Key: "accept", Value: "*/*"},
		},
	}); err != nil {
		t.Fatalf("request: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, h := range srv.hops[0].headers {
		if h == "x-extra" {
			t.Error("Request.Headers was merged over the exact set")
		}
		if h == "cookie" {
			t.Error("the session cookie jar added a Cookie to an exact-headers request")
		}
	}
	if len(srv.hops[0].headers) != 2 {
		t.Errorf("wire carried %v, want exactly the two listed pairs", srv.hops[0].headers)
	}
}
