package session

import (
	"bufio"
	"context"
	"fmt"
	"net"
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
