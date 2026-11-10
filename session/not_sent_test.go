package session

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// A request is not sent only when none of its attempts was: a redirect hop or
// a retry after an attempt that reached the server leaves the request sent,
// even when the next attempt could not get a connection.

// unusedAddr is a local address nothing listens on.
func unusedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// answerOnce serves one request with answer, closing the connection after it,
// and then stops listening.
func answerOnce(t *testing.T, answer string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		ln.Close()
		if err != nil {
			return
		}
		defer c.Close()
		if req, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
			io.Copy(io.Discard, req.Body)
			io.WriteString(c, answer)
		}
	}()
	return ln.Addr().String()
}

func post(t *testing.T, s *Session, url string) error {
	t.Helper()
	return failed(t, s, "POST", url)
}

func failed(t *testing.T, s *Session, method, url string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := s.Request(ctx, &transport.Request{Method: method, URL: url, Body: []byte("charge=100")})
	if err == nil {
		t.Fatal("the request should have failed")
	}
	return err
}

func retrying() *protocol.SessionConfig {
	return &protocol.SessionConfig{
		FollowRedirects: true,
		RetryEnabled:    true,
		MaxRetries:      2,
		RetryWaitMin:    1,
		RetryWaitMax:    5,
		RetryOnStatus:   []int{503},
	}
}

func TestARequestNoAttemptReachedIsNotSent(t *testing.T) {
	closed := "http://" + unusedAddr(t) + "/pay"
	if err := post(t, newBodyTestSession(t, &protocol.SessionConfig{}), closed); !transport.RequestNotSent(err) {
		t.Fatalf("not marked as not sent: %v", err)
	}
	if err := post(t, newBodyTestSession(t, retrying()), closed); !transport.RequestNotSent(err) {
		t.Fatalf("after retries that all failed to connect, not marked as not sent: %v", err)
	}
}

func TestARequestAnEarlierAttemptReachedIsNotMarked(t *testing.T) {
	t.Run("redirect to a host that cannot be reached", func(t *testing.T) {
		addr := answerOnce(t, fmt.Sprintf("HTTP/1.1 303 See Other\r\nLocation: http://%s/done\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", unusedAddr(t)))
		if err := post(t, newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true}), "http://"+addr+"/pay"); transport.RequestNotSent(err) {
			t.Fatalf("marked as not sent: %v", err)
		}
	})

	// A PUT, since only an idempotent request is retried once it was answered.
	t.Run("retry that cannot connect", func(t *testing.T) {
		addr := answerOnce(t, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		if err := failed(t, newBodyTestSession(t, retrying()), "PUT", "http://"+addr+"/pay"); transport.RequestNotSent(err) {
			t.Fatalf("marked as not sent: %v", err)
		}
	})
}
