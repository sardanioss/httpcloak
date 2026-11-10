package transport

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
)

// A request the server had (read in full, then the exchange failed) on every
// path a request can take: each protocol, forced or chosen by auto mode, a
// host auto mode has cached, through a proxy, buffered or streamed. It must
// reach the server once unless it may go again (CanResend), and its failure
// must not say it was not sent, also when a later attempt, on another
// protocol or a retry, could not get a connection.

// h3Aborting serves HTTP/3, counting each request it reads in full and then
// aborting its stream.
func h3Aborting(t *testing.T) (url string, read *atomic.Int32) {
	t.Helper()
	read = new(atomic.Int32)
	url = startH3Origin(t, shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		io.Copy(io.Discard, r.Body)
		read.Add(1)
		panic(shttp.ErrAbortHandler)
	}))
	return url, read
}

// countingTLSH1 is an HTTP/1.1 site over TLS that reads one request on each
// connection, counts it, and hangs up without an answer.
func countingTLSH1(t *testing.T) (url string, read *atomic.Int32) {
	t.Helper()
	read = new(atomic.Int32)
	url = tlsH1Server(t, func(c net.Conn) {
		defer c.Close()
		if req, err := stdhttp.ReadRequest(bufio.NewReader(c)); err == nil {
			io.Copy(io.Discard, req.Body)
			read.Add(1)
		}
	})
	return url, read
}

// sentOnce checks a failure of a request the server read: read times, and
// not marked as not sent.
func sentOnce(t *testing.T, err error, read, want int32) {
	t.Helper()
	if err == nil {
		t.Fatal("the request should have failed")
	}
	if RequestNotSent(err) {
		t.Fatalf("the server read the request, but the error says it was not sent: %v", err)
	}
	if read != want {
		t.Fatalf("server read the request %d times, want %d: %v", read, want, err)
	}
}

func stream(tr *Transport, req *Request) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := tr.DoStream(ctx, req)
	if resp != nil {
		resp.Close()
	}
	return err
}

func TestARequestTheServerHadIsSentOnceAndNotMarked(t *testing.T) {
	post := func(url string) *Request {
		return &Request{Method: "POST", URL: url, Body: []byte("charge=100"), Timeout: 8 * time.Second}
	}

	for _, proto := range []Protocol{ProtocolHTTP2, ProtocolAuto} {
		t.Run(fmt.Sprintf("h2 through a CONNECT proxy, stream reset after it was read (%s)", proto), func(t *testing.T) {
			srv, seen := resetOnH2Server(t)
			tr := NewTransportWithConfig("chrome-146", &ProxyConfig{URL: connectProxy(t, "")}, nil)
			tr.SetInsecureSkipVerify(true)
			tr.SetProtocol(proto)
			t.Cleanup(tr.Close)
			err := doReq(tr, post(srv.URL+"/pay"))
			sentOnce(t, err, int32(len(seen())), 1)
		})
	}

	t.Run("h1 through a CONNECT proxy, hung up on after it was read", func(t *testing.T) {
		url, read := countingTLSH1(t)
		tr := h1Transport(t, connectProxy(t, ""))
		err := doReq(tr, post(url+"/pay"))
		sentOnce(t, err, read.Load(), 1)
	})

	t.Run("auto, an HTTP/1.1-only site through a CONNECT proxy, hung up on after it was read", func(t *testing.T) {
		url, read := countingTLSH1(t)
		tr := NewTransportWithConfig("chrome-146", &ProxyConfig{URL: connectProxy(t, "")}, nil)
		tr.SetInsecureSkipVerify(true)
		tr.SetProtocol(ProtocolAuto)
		t.Cleanup(tr.Close)
		err := doReq(tr, post(url+"/pay"))
		sentOnce(t, err, read.Load(), 1)
	})

	t.Run("h3, stream aborted after it was read", func(t *testing.T) {
		url, read := h3Aborting(t)
		tr := h3Transport(t, ProtocolHTTP3)
		err := doReq(tr, post(url+"pay"))
		sentOnce(t, err, read.Load(), 1)
	})

	// An HTTP/2 server on the HTTP/3 origin's port: a POST HTTP/3 delivered
	// must not go to it as well.
	t.Run("auto, host cached as HTTP/3, stream aborted after it was read, not sent again over HTTP/2", func(t *testing.T) {
		url, read := h3Aborting(t)
		port := url[len("https://127.0.0.1:") : len(url)-1]
		ln, err := net.Listen("tcp", "127.0.0.1:"+port)
		if err != nil {
			t.Skipf("the HTTP/3 origin's port is taken on TCP: %v", err)
		}
		var overTCP atomic.Int32
		h2 := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			io.Copy(io.Discard, r.Body)
			overTCP.Add(1)
		}))
		h2.Listener = ln
		h2.EnableHTTP2 = true
		h2.StartTLS()
		t.Cleanup(h2.Close)

		tr := h3Transport(t, ProtocolAuto)
		tr.cacheProtocol(extractHost(url), ProtocolHTTP3)
		err = doReq(tr, post(url+"pay"))
		sentOnce(t, err, read.Load()+overTCP.Load(), 1)
	})

	// HTTP/3 connects first (nothing listens on TCP), delivers the GET and
	// has its stream aborted; the GET may go again, but HTTP/2 and HTTP/1.1
	// get no connection.
	t.Run("auto race won by HTTP/3, GET aborted, then no connection for the fallback", func(t *testing.T) {
		url, read := h3Aborting(t)
		tr := h3Transport(t, ProtocolAuto)
		err := doReq(tr, &Request{Method: "GET", URL: url, Timeout: 8 * time.Second})
		sentOnce(t, err, read.Load(), 1)
	})

	// doHTTP2OrHTTP1, for a host known to be HTTP/2 and behind an HTTP proxy:
	// the GET was delivered over HTTP/2, and HTTP/1.1 then got no connection.
	for _, viaProxy := range []bool{false, true} {
		name := "auto, host cached as HTTP/2"
		if viaProxy {
			name = "auto through an HTTP proxy"
		}
		t.Run(name+", GET reset after it was read, then no HTTP/1.1 connection", func(t *testing.T) {
			s := startH2Server(t, h2Config{ResetStreams: map[int]uint32{1: errCodeInternal}, MaxConns: 1})
			var proxy *ProxyConfig
			if viaProxy {
				proxy = &ProxyConfig{URL: connectProxy(t, "")}
			}
			tr := NewTransportWithConfig("chrome-146", proxy, nil)
			tr.SetInsecureSkipVerify(true)
			tr.SetProtocol(ProtocolAuto)
			t.Cleanup(tr.Close)
			tr.cacheProtocol(extractHost(s.url("/")), ProtocolHTTP2)
			err := doReq(tr, &Request{Method: "GET", URL: s.url("/page"), Timeout: 8 * time.Second})
			sentOnce(t, err, int32(len(s.attempts())), 1)
		})
	}

	// The server answered the GET with GOAWAY naming no stream as processed,
	// so HTTP/2 sends it again, on a new connection, which it cannot have.
	t.Run("h2 GOAWAY, then no connection for the retry", func(t *testing.T) {
		s := startH2Server(t, h2Config{GoAwayOn: 1, MaxConns: 1})
		tr := retryTransport(t)
		err := doReq(tr, &Request{Method: "GET", URL: s.url("/page"), Timeout: 8 * time.Second})
		sentOnce(t, err, int32(len(s.attempts())), 1)
	})

	t.Run("stream, h2, reset after it was read", func(t *testing.T) {
		srv, seen := resetOnH2Server(t)
		tr := NewTransport("firefox-148")
		tr.SetInsecureSkipVerify(true)
		tr.SetProtocol(ProtocolHTTP2)
		t.Cleanup(tr.Close)
		err := stream(tr, post(srv.URL+"/pay"))
		sentOnce(t, err, int32(len(seen())), 1)
	})

	t.Run("stream, auto, host cached as HTTP/3, POST aborted", func(t *testing.T) {
		url, read := h3Aborting(t)
		tr := h3Transport(t, ProtocolAuto)
		tr.cacheProtocol(extractHost(url), ProtocolHTTP3)
		err := stream(tr, post(url+"pay"))
		sentOnce(t, err, read.Load(), 1)
	})

	// doStreamAuto's two fallbacks after HTTP/3: for a host cached as HTTP/3,
	// and after HTTP/3 won the race.
	for _, cached := range []bool{true, false} {
		name := "stream, auto race won by HTTP/3"
		if cached {
			name = "stream, auto, host cached as HTTP/3"
		}
		t.Run(name+", GET aborted, then no connection for the fallback", func(t *testing.T) {
			url, read := h3Aborting(t)
			tr := h3Transport(t, ProtocolAuto)
			if cached {
				tr.cacheProtocol(extractHost(url), ProtocolHTTP3)
			}
			err := stream(tr, &Request{Method: "GET", URL: url, Timeout: 8 * time.Second})
			sentOnce(t, err, read.Load(), 1)
		})
	}
}
