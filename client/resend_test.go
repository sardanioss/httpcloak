package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/transport"
)

// What the client sends again. Its retries used to retry every failure, every
// status on the retry list and every bot challenge, whatever the method, and
// its automatic protocol choice sent a request that failed over HTTP/2 again
// over HTTP/3 and HTTP/1.1 whatever had happened to it, so a POST the server
// read before resetting its stream went out up to four times. Both now follow
// the transport's rule (transport.CanResend).

// resendServer serves HTTP/2 and HTTP/1.1 over TLS. Over HTTP/2 it reads each
// request and then resets its stream (the server read the request and went
// away), or answers with status when one is given; over HTTP/1.1 it answers
// 200. It counts what it read by protocol and method.
type resendServer struct {
	url  string
	mu   sync.Mutex
	seen map[string]int
}

func newResendServer(t *testing.T, status int, header http.Header) *resendServer {
	t.Helper()
	s := &resendServer{seen: map[string]int{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		s.mu.Lock()
		s.seen[r.Proto+" "+r.Method]++
		s.mu.Unlock()
		if r.ProtoMajor != 2 {
			io.WriteString(w, "ok")
			return
		}
		if status == 0 {
			panic(http.ErrAbortHandler)
		}
		for k, v := range header {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

func (s *resendServer) count(method string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, v := range s.seen {
		if k[len(k)-len(method)-1:] == " "+method {
			n += v
		}
	}
	return n
}

func resendClient(t *testing.T, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{WithInsecureSkipVerify(), WithTimeout(10 * time.Second), WithDisableHTTP3()}, opts...)
	c := NewClient("chrome-latest", opts...)
	t.Cleanup(func() { c.Close() })
	return c
}

func TestClientRetriesDoNotSendAgainARequestTheServerHad(t *testing.T) {
	cases := []struct {
		name   string
		method string
		status int
		header http.Header
		want   int // times the server reads the request
	}{
		{"POST, stream reset after it was read", "POST", 0, nil, 1},
		{"POST, answered with a retry status", "POST", 503, nil, 1},
		{"POST, answered with a bot challenge", "POST", 403, http.Header{"Set-Cookie": {"bm=1"}}, 1},
		{"GET, stream reset after it was read", "GET", 0, nil, 4},
		{"PUT, answered with a retry status", "PUT", 503, nil, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newResendServer(t, c.status, c.header)
			cl := resendClient(t, WithForceHTTP2(), WithRetryConfig(3, time.Millisecond, 5*time.Millisecond, []int{503}))
			resp, err := cl.Do(context.Background(), &Request{Method: c.method, URL: srv.url + "/pay", Body: strings.NewReader("charge=100")})
			if err != nil && transport.RequestNotSent(err) {
				t.Fatalf("the server read the request, but the error says it was not sent: %v", err)
			}
			if c.status != 0 && (err != nil || resp.StatusCode != c.status) {
				t.Fatalf("want the %d back, got %v, %v", c.status, resp, err)
			}
			if n := srv.count(c.method); n != c.want {
				t.Fatalf("server read the %s %d times, want %d (MaxRetries is 3)", c.method, n, c.want)
			}
		})
	}
}

// Choosing the protocol itself, the client sent a request that failed over
// HTTP/2 again over HTTP/1.1 whatever had become of it. A POST the server read
// goes once; a GET still falls back and succeeds.
func TestClientAutoProtocolDoesNotResendAPostThatWasSent(t *testing.T) {
	srv := newResendServer(t, 0, nil)
	cl := resendClient(t)

	_, err := cl.Do(context.Background(), &Request{Method: "POST", URL: srv.url + "/pay", Body: strings.NewReader("charge=100")})
	if err == nil {
		t.Fatal("a POST whose HTTP/2 stream was reset after it was read should fail")
	}
	if transport.RequestNotSent(err) {
		t.Fatalf("the server read the POST, but the error says it was not sent: %v", err)
	}
	if n := srv.count("POST"); n != 1 {
		t.Fatalf("server read the POST %d times, want once: %v", n, srv.seen)
	}

	resp, err := cl.Do(context.Background(), &Request{Method: "GET", URL: srv.url + "/"})
	if err != nil {
		t.Fatalf("a GET should fall back to HTTP/1.1: %v", err)
	}
	if resp.StatusCode != 200 || srv.seen["HTTP/1.1 GET"] != 1 {
		t.Fatalf("got %d, server saw %v; want the GET over HTTP/2, then HTTP/1.1", resp.StatusCode, srv.seen)
	}
}

// A request that could get no connection was not sent, which its error says,
// and so a POST still falls back from HTTP/2 to HTTP/1.1 and is retried.
func TestClientARequestThatGotNoConnectionIsNotSent(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens there now

	for _, opts := range [][]Option{nil, {WithRetryConfig(2, time.Millisecond, 5*time.Millisecond, nil)}} {
		cl := resendClient(t, opts...)
		_, err := cl.Do(context.Background(), &Request{Method: "POST", URL: url + "/pay", Body: strings.NewReader("charge=100")})
		if err == nil || !transport.RequestNotSent(err) {
			t.Fatalf("want a failure marked as not sent, got %v", err)
		}
	}
}

// closedHost is a local address nothing listens on.
func closedHost(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// clientMakers are the two ways to build a client: NewSession turns retries
// on by default, NewClient leaves them off.
var clientMakers = []struct {
	name string
	make func(...Option) *Client
}{
	{"NewSession (retries on)", func(o ...Option) *Client { return NewSession("chrome-latest", o...) }},
	{"NewClient", func(o ...Option) *Client { return NewClient("chrome-latest", o...) }},
}

func postOnce(t *testing.T, cl *Client, url string, read *atomic.Int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := cl.Do(ctx, &Request{Method: "POST", URL: url, Body: strings.NewReader("charge=100")})
	if err == nil {
		t.Fatal("the request should have failed")
	}
	if transport.RequestNotSent(err) {
		t.Fatalf("the server read the POST, but the error says it was not sent: %v", err)
	}
	if n := read.Load(); n != 1 {
		t.Fatalf("server read the POST %d times, want once: %v", n, err)
	}
}

// A POST the server read and answered with a redirect, whose next hop cannot
// be had, was sent. The next hop's failure said it was not, so a retry sent
// the POST again, once per retry.
func TestClientARedirectHopsFailureIsNotMarkedNotSent(t *testing.T) {
	for _, status := range []int{303, 307} {
		for _, maker := range clientMakers {
			t.Run(fmt.Sprintf("%d, %s", status, maker.name), func(t *testing.T) {
				var read atomic.Int32
				closed := closedHost(t)
				srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.Copy(io.Discard, r.Body)
					read.Add(1)
					w.Header().Set("Location", "https://"+closed+"/done")
					w.WriteHeader(status)
				}))
				srv.EnableHTTP2 = true
				srv.StartTLS()
				t.Cleanup(srv.Close)
				cl := maker.make(WithInsecureSkipVerify(), WithTimeout(10*time.Second), WithDisableHTTP3(),
					WithRetryConfig(3, time.Millisecond, 5*time.Millisecond, nil))
				t.Cleanup(func() { cl.Close() })
				postOnce(t, cl, srv.URL+"/pay", &read)
			})
		}
	}
}

// firstConnOnly passes its first connection and closes every later one at
// once, so a second attempt cannot be had.
type firstConnOnly struct {
	net.Listener
	accepted atomic.Int32
}

func (l *firstConnOnly) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil || l.accepted.Add(1) == 1 {
			return c, err
		}
		c.Close()
	}
}

// digestServer answers every request with a Digest challenge, closing the
// connection after it, and counts the requests it read.
func digestServer(t *testing.T, onlyOneConn bool) (string, *atomic.Int32) {
	t.Helper()
	read := new(atomic.Int32)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		read.Add(1)
		w.Header().Set("WWW-Authenticate", `Digest realm="pay", nonce="abc", qop="auth"`)
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	if onlyOneConn {
		srv.Listener = &firstConnOnly{Listener: srv.Listener}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL, read
}

func digestClient(t *testing.T, maker func(...Option) *Client) *Client {
	t.Helper()
	cl := maker(WithInsecureSkipVerify(), WithTimeout(10*time.Second), WithForceHTTP1(),
		WithRetryConfig(3, time.Millisecond, 5*time.Millisecond, nil))
	cl.SetAuth(NewDigestAuth("user", "pass"))
	t.Cleanup(func() { cl.Close() })
	return cl
}

// A POST answered with a Digest challenge goes again with the credentials. When
// that second attempt cannot connect, the POST was still sent (the server read
// and answered it), which the error says, and no retry sends it again.
func TestClientADigestResendsFailureIsNotMarkedNotSent(t *testing.T) {
	for _, maker := range clientMakers {
		t.Run(maker.name, func(t *testing.T) {
			url, read := digestServer(t, true)
			postOnce(t, digestClient(t, maker.make), url+"/pay", read)
		})
	}
}

// The challenge is answered once: a second 401 is the server refusing the
// credentials, and comes back as the answer. Every challenge used to be
// answered, which sent the POST again until the request's deadline.
func TestClientADigestChallengeIsAnsweredOnce(t *testing.T) {
	url, read := digestServer(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := digestClient(t, clientMakers[1].make).Do(ctx, &Request{Method: "POST", URL: url + "/pay", Body: strings.NewReader("charge=100")})
	if err != nil {
		t.Fatalf("want the second 401 back: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
	if n := read.Load(); n != 2 {
		t.Fatalf("server read the POST %d times, want twice (the request, then the answer to the challenge)", n)
	}
}
