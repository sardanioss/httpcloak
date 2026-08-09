package session

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// requestWithRedirects replays the caller's headers onto every hop of a chain,
// so it has to replay their ordering too. Without that, a header the caller
// slotted explicitly on hop 0 is still sent on hop 1 but re-placed by the preset
// table or the sorted tail — the two would disagree mid-chain, which is the
// header-order drift this feature exists to prevent.
func TestRequestHeaderOrder_SurvivesRedirects(t *testing.T) {
	srv := newRedirectOrderCapture(t, 2)
	s := NewSession("", &protocol.SessionConfig{
		Preset:          "chrome-latest",
		ForceHTTP1:      true,
		FollowRedirects: true,
	})
	defer s.Close()
	s.SetHeaderOrder([]string{"user-agent", "accept"})

	resp, err := s.Request(context.Background(), &transport.Request{
		Method:      "GET",
		URL:         srv.url + "hop0",
		Headers:     map[string][]string{"x-alpha": {"1"}},
		HeaderOrder: []string{"x-alpha", "accept", "user-agent"},
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Close()

	hops := srv.all()
	if len(hops) != 3 {
		t.Fatalf("captured %d hops, want 3 (initial + 2 redirects)", len(hops))
	}
	for i, order := range hops {
		assertPrefixf(t, order, []string{"x-alpha", "accept", "user-agent"},
			"hop %d did not keep the per-request order", i)
	}
}

// assertPrefixf checks that got starts with want. The wire only carries the
// headers the request actually has, so an order list is asserted as a leading
// run, not as the whole thing.
func assertPrefixf(t *testing.T, got, want []string, format string, args ...any) {
	t.Helper()
	if len(got) < len(want) || strings.Join(got[:len(want)], ",") != strings.Join(want, ",") {
		t.Errorf("%s\n got: %s\nwant prefix: %s", fmt.Sprintf(format, args...),
			strings.Join(got, " → "), strings.Join(want, " → "))
	}
}

// redirectOrderCapture answers the first `redirects` requests with a 302 to the
// next hop and the last one with a 200, recording the header order of each.
type redirectOrderCapture struct {
	url       string
	redirects int

	mu   sync.Mutex
	hops [][]string
}

func newRedirectOrderCapture(t *testing.T, redirects int) *redirectOrderCapture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &redirectOrderCapture{url: "http://" + ln.Addr().String() + "/", redirects: redirects}
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

func (s *redirectOrderCapture) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil { // request line
		return
	}

	var names []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		// Host and Connection are written ahead of the ordered block by the H1
		// writer and are not part of what the order list controls.
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "host" || name == "connection" {
			continue
		}
		names = append(names, name)
	}

	s.mu.Lock()
	s.hops = append(s.hops, names)
	hop := len(s.hops)
	s.mu.Unlock()

	if hop <= s.redirects {
		next := fmt.Sprintf("%shop%d", s.url, hop)
		fmt.Fprintf(conn, "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", next)
		return
	}
	fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

func (s *redirectOrderCapture) all() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]string, len(s.hops))
	copy(out, s.hops)
	return out
}
