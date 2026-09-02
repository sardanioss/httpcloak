package httpcloak

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The user-facing formulation of the 307 bug: a POST through Session.Do whose
// Body is an io.Reader. Session.Do populates the transport request's BodyReader
// while the redirect path used to copy only its []byte Body, so the second hop
// went out empty with the caller's Content-Type still on it.
//
// Asserting what the SERVER received is the only formulation that catches this.
// The request object looks right either way, and the bodiless hop still came
// back 200.

type rootHop struct {
	method        string
	contentLength string
	chunked       bool
	body          []byte
}

type rootRedirectServer struct {
	url      string
	statuses []int

	mu   sync.Mutex
	hops []rootHop
}

func newRootRedirectServer(t *testing.T, statuses ...int) *rootRedirectServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &rootRedirectServer{url: "http://" + ln.Addr().String() + "/", statuses: statuses}
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

func (s *rootRedirectServer) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	hop := rootHop{method: strings.Fields(strings.TrimSpace(line))[0]}

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if name, value, ok := strings.Cut(line, ":"); ok {
			switch {
			case strings.EqualFold(strings.TrimSpace(name), "content-length"):
				hop.contentLength = strings.TrimSpace(value)
			case strings.EqualFold(strings.TrimSpace(name), "transfer-encoding"):
				hop.chunked = strings.Contains(strings.ToLower(value), "chunked")
			}
		}
	}

	// Drain the body before answering, or the client is reset mid-write.
	//
	// Both framings, not just Content-Length. A caller who hides the concrete
	// reader type behind an interface gets no Content-Length, so the request
	// goes out chunked; draining only the sized case left those bodies in the
	// socket, and answering then closing reset the client mid-write. That
	// surfaced as an intermittent "write: broken pipe" on loopback, which reads
	// like a transport defect and is a gap in this server.
	switch {
	case hop.chunked:
		hop.body = readChunkedBody(br)
	case hop.contentLength != "":
		if n, _ := strconv.Atoi(hop.contentLength); n > 0 {
			buf := make([]byte, n)
			if _, err := io.ReadFull(br, buf); err != nil {
				return
			}
			hop.body = buf
		}
	}

	s.mu.Lock()
	s.hops = append(s.hops, hop)
	n := len(s.hops)
	s.mu.Unlock()

	status := 200
	if n <= len(s.statuses) {
		status = s.statuses[n-1]
	}
	if status >= 300 && status < 400 {
		fmt.Fprintf(conn, "HTTP/1.1 %d Redirect\r\nLocation: %shop%d\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, s.url, n)
		return
	}
	fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
}

func (s *rootRedirectServer) recorded() []rootHop {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]rootHop, len(s.hops))
	copy(out, s.hops)
	return out
}

func TestSessionDo_307PreservesBody(t *testing.T) {
	const payload = `{"amount":4200,"currency":"eur"}`
	srv := newRootRedirectServer(t, 307, 200)

	s := NewSession("chrome-latest", WithForceHTTP1())
	defer s.Close()

	resp, err := s.Do(context.Background(), &Request{
		Method:  "POST",
		URL:     srv.url + "hop0",
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    strings.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("final status = %d, want 200", resp.StatusCode)
	}

	hops := srv.recorded()
	if len(hops) != 2 {
		t.Fatalf("got %d hops, want 2", len(hops))
	}
	if got := string(hops[1].body); got != payload {
		t.Errorf("hop 1 body = %q, want %q — the 307 hop lost the body", got, payload)
	}
	if hops[1].method != "POST" {
		t.Errorf("hop 1 method = %q, want POST", hops[1].method)
	}
	if want := strconv.Itoa(len(payload)); hops[1].contentLength != want {
		t.Errorf("hop 1 Content-Length = %q, want %q", hops[1].contentLength, want)
	}
}

func TestSessionDo_OnRedirectHalts(t *testing.T) {
	srv := newRootRedirectServer(t, 302, 302, 200)

	s := NewSession("chrome-latest", WithForceHTTP1())
	defer s.Close()

	var seen []*Redirect
	resp, err := s.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.url + "hop0",
		OnRedirect: func(r *Redirect) error {
			seen = append(seen, r)
			return ErrUseLastResponse
		},
	})
	if err != nil {
		t.Fatalf("halting must not be an error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode != 302 {
		t.Errorf("status = %d, want the 302 handed back", resp.StatusCode)
	}
	if len(seen) != 1 {
		t.Fatalf("callback fired %d times, want 1", len(seen))
	}
	if seen[0].To != srv.url+"hop1" {
		t.Errorf("To = %q, want %q", seen[0].To, srv.url+"hop1")
	}
	if loc, err := resp.Location(); err != nil || loc.String() != srv.url+"hop1" {
		t.Errorf("Location() = %v, %v; want %s", loc, err, srv.url+"hop1")
	}
	if n := len(srv.recorded()); n != 1 {
		t.Errorf("%d requests reached the server, want 1", n)
	}
}

func TestSessionDo_TooManyRedirectsSentinel(t *testing.T) {
	srv := newRootRedirectServer(t, 302, 302, 302, 302, 302)

	s := NewSession("chrome-latest", WithForceHTTP1(), WithRedirects(true, 2))
	defer s.Close()

	resp, err := s.Do(context.Background(), &Request{Method: "GET", URL: srv.url + "hop0"})
	if !errors.Is(err, ErrTooManyRedirects) {
		t.Fatalf("err = %v, want ErrTooManyRedirects", err)
	}
	if resp == nil {
		t.Fatal("want the last response returned alongside the error, got nil")
	}
	defer resp.Close()
	if resp.StatusCode != 302 {
		t.Errorf("resp.StatusCode = %d, want 302", resp.StatusCode)
	}
}

func TestSessionDo_NonReplayableBodyOn307(t *testing.T) {
	srv := newRootRedirectServer(t, 307, 200)

	s := NewSession("chrome-latest", WithForceHTTP1())
	defer s.Close()

	// A reader the in-memory type switch cannot see, standing in for an *os.File.
	body := struct{ io.Reader }{strings.NewReader(`{"a":1}`)}

	resp, err := s.Do(context.Background(), &Request{
		Method:  "POST",
		URL:     srv.url + "hop0",
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    body,
	})
	if !errors.Is(err, ErrBodyNotReplayable) {
		t.Fatalf("err = %v, want ErrBodyNotReplayable", err)
	}
	if resp == nil {
		t.Fatal("want the 3xx returned alongside the error, got nil")
	}
	defer resp.Close()
	if resp.StatusCode != 307 {
		t.Errorf("resp.StatusCode = %d, want 307", resp.StatusCode)
	}
	if n := len(srv.recorded()); n != 1 {
		t.Errorf("%d requests reached the server, want 1: the hop must not go out bodiless", n)
	}
}

// A caller with a genuine stream can opt back in by supplying GetBody.
func TestSessionDo_GetBodyEscapeHatch(t *testing.T) {
	const payload = `{"a":1}`
	srv := newRootRedirectServer(t, 307, 200)

	s := NewSession("chrome-latest", WithForceHTTP1())
	defer s.Close()

	resp, err := s.Do(context.Background(), &Request{
		Method:  "POST",
		URL:     srv.url + "hop0",
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    struct{ io.Reader }{strings.NewReader(payload)},
		GetBody: func() (io.Reader, error) { return strings.NewReader(payload), nil },
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Close()

	hops := srv.recorded()
	if len(hops) != 2 {
		t.Fatalf("got %d hops, want 2", len(hops))
	}
	if got := string(hops[1].body); got != payload {
		t.Errorf("hop 1 body = %q, want %q", got, payload)
	}
}

// readChunkedBody drains a chunked request body, returning what it carried.
func readChunkedBody(br *bufio.Reader) []byte {
	var out []byte
	for {
		sizeLine, err := br.ReadString('\n')
		if err != nil {
			return out
		}
		n, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
		if err != nil || n == 0 {
			return out
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return out
		}
		out = append(out, buf...)
		br.ReadString('\n') // trailing CRLF
	}
}
