package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
