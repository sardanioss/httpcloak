package session

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// A gRPC response is a 200 whose real outcome lives in the trailing block, so a
// client that drops trailers reports every failed call as a success. This is
// that shape: chunked, a declared Trailer header, and the values after the
// final chunk.
func newTrailerServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				fmt.Fprint(c,
					"HTTP/1.1 200 OK\r\n"+
						"Content-Type: application/grpc\r\n"+
						"Trailer: Grpc-Status, Grpc-Message\r\n"+
						"Transfer-Encoding: chunked\r\n"+
						"Connection: close\r\n\r\n"+
						"2\r\nok\r\n"+
						"0\r\n"+
						"Grpc-Status: 14\r\n"+
						"Grpc-Message: unavailable\r\n"+
						"\r\n")
			}(c)
		}
	}()
	return "http://" + ln.Addr().String() + "/"
}

func TestResponseCarriesTrailers(t *testing.T) {
	url := newTrailerServer(t)
	s := newBodyTestSession(t, &protocol.SessionConfig{})

	resp, err := s.Request(context.Background(), &transport.Request{Method: "GET", URL: url})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if resp.Trailer == nil {
		t.Fatal("Trailer is nil; the server sent grpc-status in the trailing block " +
			"and a caller has no way to see the call actually failed")
	}
	if got := resp.Trailer["grpc-status"]; len(got) != 1 || got[0] != "14" {
		t.Errorf("grpc-status = %v, want [14]", got)
	}
	if got := resp.Trailer["grpc-message"]; len(got) != 1 || got[0] != "unavailable" {
		t.Errorf("grpc-message = %v, want [unavailable]", got)
	}
}

// A response with no trailing block reports nil rather than an empty map, so a
// plain nil check tells the two apart.
func TestNoTrailersReportsNil(t *testing.T) {
	srv := newBodyCapture(t, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{})
	resp, err := s.Request(context.Background(), &transport.Request{Method: "GET", URL: srv.url + "x"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.Trailer != nil {
		t.Errorf("Trailer = %v on a response with no trailing block, want nil", resp.Trailer)
	}
}

// HTTP/1.1 is the only protocol where response header casing exists at all, and
// the parse underneath canonicalises it away: a server sending X-FOO is reported
// as X-Foo. Anything relaying the response onward then emits a spelling the
// origin never used.
func newCasingServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				fmt.Fprint(c,
					"HTTP/1.1 200 OK\r\n"+
						"X-FOO: 1\r\n"+
						"etag: \"abc\"\r\n"+
						"CONTENT-LENGTH: 2\r\n"+
						"Connection: close\r\n\r\nok")
			}(c)
		}
	}()
	return "http://" + ln.Addr().String() + "/"
}

func TestHTTP1ReportsTheServersOwnHeaderCasing(t *testing.T) {
	url := newCasingServer(t)
	s := newBodyTestSession(t, &protocol.SessionConfig{})
	resp, err := s.Request(context.Background(), &transport.Request{Method: "GET", URL: url})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.HeaderCasing == nil {
		t.Fatal("HeaderCasing is nil; the server's own spelling is unrecoverable " +
			"once the parse canonicalises it")
	}
	got := map[string]bool{}
	for _, n := range resp.HeaderCasing {
		got[n] = true
	}
	for _, want := range []string{"X-FOO", "etag", "CONTENT-LENGTH"} {
		if !got[want] {
			t.Errorf("HeaderCasing %v does not carry %q as the server spelled it",
				resp.HeaderCasing, want)
		}
	}
	// And the canonical map is still there and still canonical.
	if len(resp.Headers["x-foo"]) != 1 {
		t.Errorf("Headers lost x-foo: %v", resp.Headers)
	}
	// The bookkeeping key must never surface as a header.
	for k := range resp.Headers {
		if strings.Contains(k, ":") {
			t.Errorf("internal key %q leaked into Headers", k)
		}
	}
}
