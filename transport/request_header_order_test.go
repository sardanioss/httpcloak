package transport

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
)

// SetHeaderOrder is session-wide state behind a mutex: a caller who needs one
// request ordered differently — because they add a header no browser sends and
// want it slotted somewhere specific — has to install the order, send, and
// restore it, serializing every concurrent request on the session in the
// process. Request.HeaderOrder is the per-request alternative. These tests pin
// the two properties that make it usable: it wins over the session order, and it
// touches nothing shared, so parallel requests each keep their own.

func TestEffectiveHeaderOrder_RequestOverridesSession(t *testing.T) {
	tr := &Transport{}
	tr.SetHeaderOrder([]string{"accept", "user-agent"})

	got := tr.effectiveHeaderOrder(&Request{HeaderOrder: []string{"x-alpha", "cookie"}})
	assertOrder(t, got, []string{"x-alpha", "cookie"})

	// The session order is read, never written, by a per-request override.
	assertOrder(t, tr.GetHeaderOrder(), []string{"accept", "user-agent"})
}

func TestEffectiveHeaderOrder_FallsBackToSessionOrder(t *testing.T) {
	tr := &Transport{}
	tr.SetHeaderOrder([]string{"accept", "user-agent"})

	for name, req := range map[string]*Request{
		"nil request":    nil,
		"unset field":    {},
		"empty, non-nil": {HeaderOrder: []string{}},
	} {
		t.Run(name, func(t *testing.T) {
			assertOrder(t, tr.effectiveHeaderOrder(req), []string{"accept", "user-agent"})
		})
	}
}

// With no order anywhere, the resolver must stay empty so CompleteHeaderOrder
// falls through to the preset's own table rather than pinning some subset.
func TestEffectiveHeaderOrder_EmptyWithoutAnyOrder(t *testing.T) {
	if got := (&Transport{}).effectiveHeaderOrder(&Request{}); len(got) != 0 {
		t.Errorf("expected no order, got %v", got)
	}
}

// End-to-end over the HTTP/1.1 wire: what the server reads must be the order the
// request named, and the session order must still govern the next request that
// does not name one.
func TestRequestHeaderOrder_AppliedOnTheWire(t *testing.T) {
	srv := newH1OrderCapture(t)
	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetHeaderOrder([]string{"x-alpha", "user-agent", "accept"})

	probe := map[string][]string{"x-alpha": {"1"}, "x-zulu": {"26"}}

	sessionOrder := srv.do(t, tr, &Request{Method: "GET", URL: srv.url, Headers: probe})
	assertPrefix(t, sessionOrder, []string{"x-alpha", "user-agent", "accept"})

	perRequest := srv.do(t, tr, &Request{
		Method:      "GET",
		URL:         srv.url,
		Headers:     probe,
		HeaderOrder: []string{"x-zulu", "accept", "x-alpha", "user-agent"},
	})
	assertPrefix(t, perRequest, []string{"x-zulu", "accept", "x-alpha", "user-agent"})

	// Back to the session order — the override left nothing behind.
	after := srv.do(t, tr, &Request{Method: "GET", URL: srv.url, Headers: probe})
	assertOrder(t, after, sessionOrder)
}

// The per-request list is a prefix, exactly like SetHeaderOrder: naming two
// headers must not cost the caller the preset's placement for everything else.
func TestRequestHeaderOrder_IsPrefixNotReplacement(t *testing.T) {
	srv := newH1OrderCapture(t)
	tr := NewTransport("chrome-latest")
	defer tr.Close()

	baseline := srv.do(t, tr, &Request{Method: "GET", URL: srv.url})
	got := srv.do(t, tr, &Request{
		Method:      "GET",
		URL:         srv.url,
		HeaderOrder: []string{"accept-language", "user-agent"},
	})
	assertPrefix(t, got, []string{"accept-language", "user-agent"})

	// Everything the request did not name keeps its preset-relative order.
	assertOrder(t, without(got, "accept-language", "user-agent"),
		without(baseline, "accept-language", "user-agent"))
}

// Names are matched case-insensitively, so callers can pass the casing they use
// in their Headers map.
func TestRequestHeaderOrder_CaseInsensitive(t *testing.T) {
	srv := newH1OrderCapture(t)
	tr := NewTransport("chrome-latest")
	defer tr.Close()

	got := srv.do(t, tr, &Request{
		Method:      "GET",
		URL:         srv.url,
		Headers:     map[string][]string{"X-Alpha": {"1"}},
		HeaderOrder: []string{"X-Alpha", "User-Agent", "Accept"},
	})
	assertPrefix(t, got, []string{"x-alpha", "user-agent", "accept"})
}

// The point of the feature: concurrent requests each carry their own order with
// no lock held across the call, so none of them can see another's. Run under
// -race, this also covers the read of the session order alongside them.
func TestRequestHeaderOrder_ConcurrentRequestsKeepTheirOwnOrder(t *testing.T) {
	srv := newH1OrderCapture(t)
	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetHeaderOrder([]string{"user-agent", "accept"})

	// Each worker pins a different header first; the marker header ties the
	// server's capture back to the request that produced it.
	leads := []string{"x-alpha", "x-bravo", "x-charlie", "x-delta", "x-echo", "x-foxtrot"}
	headers := map[string][]string{}
	for _, h := range leads {
		headers[h] = []string{"1"}
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(leads)*4)
	for round := 0; round < 4; round++ {
		for _, lead := range leads {
			wg.Add(1)
			go func(lead, marker string) {
				defer wg.Done()
				h := map[string][]string{"x-probe": {marker}}
				for k, v := range headers {
					h[k] = v
				}
				resp, err := tr.Do(context.Background(), &Request{
					Method:      "GET",
					URL:         srv.url,
					Headers:     h,
					HeaderOrder: []string{lead, "user-agent", "accept"},
				})
				if err != nil {
					errs <- fmt.Errorf("%s: %w", marker, err)
					return
				}
				resp.Close()
			}(lead, fmt.Sprintf("%s-%d", lead, round))
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("request failed: %v", err)
	}

	captured := srv.byProbe()
	if len(captured) != len(leads)*4 {
		t.Fatalf("captured %d requests, want %d", len(captured), len(leads)*4)
	}
	for marker, order := range captured {
		lead := marker[:strings.LastIndex(marker, "-")]
		assertPrefix(t, order, []string{lead, "user-agent", "accept"})
	}
}

// --- helpers ---

// h1OrderCapture is a plaintext HTTP/1.1 server that records the header names of
// every request it reads, in wire order. Plaintext keeps the test off TLS: an
// http:// URL routes straight to doHTTP1, which is the path under test.
type h1OrderCapture struct {
	url string
	ln  net.Listener

	mu       sync.Mutex
	captures [][]string
	probes   map[string][]string // x-probe value -> header order
}

func newH1OrderCapture(t *testing.T) *h1OrderCapture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &h1OrderCapture{
		url:    "http://" + ln.Addr().String() + "/",
		ln:     ln,
		probes: map[string][]string{},
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *h1OrderCapture) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil { // request line
		return
	}

	var names []string
	var probe string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		// Host and Connection are written ahead of the ordered block by the H1
		// writer and are not part of what the order list controls.
		if name == "host" || name == "connection" {
			continue
		}
		if name == "x-probe" {
			probe = strings.TrimSpace(value)
		}
		names = append(names, name)
	}

	s.mu.Lock()
	s.captures = append(s.captures, names)
	if probe != "" {
		s.probes[probe] = names
	}
	s.mu.Unlock()

	fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

// do sends req and returns the header order the server read for it.
func (s *h1OrderCapture) do(t *testing.T, tr *Transport, req *Request) []string {
	t.Helper()
	resp, err := tr.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Close()

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.captures) == 0 {
		t.Fatal("server captured no request")
	}
	return s.captures[len(s.captures)-1]
}

func (s *h1OrderCapture) byProbe() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]string, len(s.probes))
	for k, v := range s.probes {
		out[k] = v
	}
	return out
}

// assertPrefix checks that got starts with want. The wire only carries the
// headers the request actually has, so a caller's order list is asserted as a
// leading run, not as the whole thing.
func assertPrefix(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) < len(want) {
		t.Fatalf("wire order too short\n got: %s\nwant prefix: %s",
			strings.Join(got, " → "), strings.Join(want, " → "))
	}
	assertOrder(t, got[:len(want)], want)
}

func without(order []string, drop ...string) []string {
	skip := make(map[string]bool, len(drop))
	for _, d := range drop {
		skip[d] = true
	}
	out := make([]string, 0, len(order))
	for _, name := range order {
		if !skip[name] {
			out = append(out, name)
		}
	}
	return out
}
