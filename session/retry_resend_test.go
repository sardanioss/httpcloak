package session

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// What a session's retries send again. They used to retry every transport
// error, and every status on the retry list, whatever the method, so with
// retries on a POST the server read before the connection dropped went out
// three times. They now follow the transport's rule (transport.CanResend): a
// failure is retried when it proves the request was never sent, or when the
// request is idempotent; an answer only when it is idempotent.

// methodCounter serves each connection with serve, and counts the requests
// it read by method.
type methodCounter struct {
	mu   sync.Mutex
	seen map[string]int
}

func (c *methodCounter) add(method string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]int{}
	}
	c.seen[method]++
}

func (c *methodCounter) count(method string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen[method]
}

// countingServer reads each request on its own connection, counts it, and
// then writes answer, or hangs up without one when answer is empty.
func countingServer(t *testing.T, answer string) (string, *methodCounter) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	counter := &methodCounter{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				io.Copy(io.Discard, req.Body)
				counter.add(req.Method)
				io.WriteString(c, answer)
			}(c)
		}
	}()
	return "http://" + ln.Addr().String(), counter
}

func send(t *testing.T, s *Session, method, url string) (*transport.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.Request(ctx, &transport.Request{Method: method, URL: url + "/pay", Body: []byte("charge=100")})
}

func TestARetryDoesNotSendAgainARequestTheServerHad(t *testing.T) {
	const unavailable = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	cases := []struct {
		name, method, answer string
		want                 int // times the server reads the request
	}{
		{"POST, hung up on after it was read", "POST", "", 1},
		{"PATCH, hung up on after it was read", "PATCH", "", 1},
		{"POST, answered with a retry status", "POST", unavailable, 1},
		{"GET, hung up on after it was read", "GET", "", 3},
		{"PUT, answered with a retry status", "PUT", unavailable, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			url, counter := countingServer(t, c.answer)
			resp, err := send(t, newBodyTestSession(t, retrying()), c.method, url)
			if err != nil && transport.RequestNotSent(err) {
				t.Fatalf("the server read the request, but the error says it was not sent: %v", err)
			}
			if c.answer != "" && (err != nil || resp.StatusCode != 503) {
				t.Fatalf("want the 503 back, got %v, %v", resp, err)
			}
			if n := counter.count(c.method); n != c.want {
				t.Fatalf("server read the %s %d times, want %d (MaxRetries is 2)", c.method, n, c.want)
			}
		})
	}
}

// A POST that was never sent may be retried, and is: its first attempt finds
// nothing listening, and the retry finds the server.
func TestARetrySendsAPostThatWasNeverSent(t *testing.T) {
	addr := unusedAddr(t)
	var counter methodCounter
	listening := make(chan struct{})
	time.AfterFunc(50*time.Millisecond, func() {
		defer close(listening)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Errorf("listen again on %s: %v", addr, err)
			return
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
					if req, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
						io.Copy(io.Discard, req.Body)
						counter.add(req.Method)
						io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
					}
				}(c)
			}
		}()
	})
	s := newBodyTestSession(t, &protocol.SessionConfig{RetryEnabled: true, MaxRetries: 2, RetryWaitMin: 300, RetryWaitMax: 500})
	resp, err := send(t, s, "POST", "http://"+addr)
	<-listening
	if err != nil {
		t.Fatalf("the POST should have been retried once the server listened: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if n := counter.count("POST"); n != 1 {
		t.Fatalf("server read the POST %d times, want once", n)
	}
}
