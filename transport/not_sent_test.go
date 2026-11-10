package transport

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// What a failed request says about whether it reached the server. A caller
// told that a request was not sent may send it again, so a payment wrongly
// told so is paid twice. The mark is therefore set only where no attempt at
// the request ever had a connection to write it on, and these tests hold both
// directions: the failures that prove nothing was sent are marked, and none
// is once the request was or may have been written, on any attempt.

// closedAddr is a local address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

const proxyAuthRequired = "HTTP/1.1 407 Proxy Authentication Required\r\n" +
	"Proxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n"

func failedPost(t *testing.T, preset string, proto Protocol, proxyURL, url string) error {
	t.Helper()
	var proxy *ProxyConfig
	if proxyURL != "" {
		proxy = &ProxyConfig{URL: proxyURL}
	}
	tr := NewTransportWithConfig(preset, proxy, nil)
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(proto)
	t.Cleanup(tr.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := tr.Do(ctx, &Request{Method: "POST", URL: url, Body: []byte("charge=100"), Timeout: 10 * time.Second})
	if err == nil {
		t.Fatal("the request should have failed")
	}
	return err
}

func TestAFailureBeforeAnyConnectionIsNotSent(t *testing.T) {
	closed := closedAddr(t)
	refusing := connectProxy(t, proxyAuthRequired)
	cases := []struct {
		name   string
		preset string
		proto  Protocol
		proxy  string
		url    string
	}{
		{"http dial", "chrome-146", ProtocolAuto, "", "http://" + closed + "/pay"},
		{"h1 dial", "chrome-146", ProtocolHTTP1, "", "https://" + closed + "/pay"},
		{"h2 dial", "chrome-146", ProtocolHTTP2, "", "https://" + closed + "/pay"},
		{"auto h2 then h1 dial", "firefox-148", ProtocolAuto, "", "https://" + closed + "/pay"},
		{"auto race then h1 dial", "chrome-146", ProtocolAuto, "", "https://" + closed + "/pay"},
		{"h1 proxy dial", "chrome-146", ProtocolHTTP1, "http://" + closed, "https://pay.test/pay"},
		{"auto proxy dial", "chrome-146", ProtocolAuto, "http://" + closed, "https://pay.test/pay"},
		{"h1 proxy 407", "chrome-146", ProtocolHTTP1, refusing, "https://pay.test/pay"},
		{"h2 proxy 407", "chrome-146", ProtocolHTTP2, refusing, "https://pay.test/pay"},
		{"auto proxy 407", "chrome-146", ProtocolAuto, refusing, "https://pay.test/pay"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := failedPost(t, c.preset, c.proto, c.proxy, c.url)
			if !RequestNotSent(err) {
				t.Fatalf("not marked as not sent: %v", err)
			}
			if c.proxy == refusing {
				var refused *ProxyStatusError
				if !errors.As(err, &refused) || refused.StatusCode != 407 {
					t.Fatalf("want the proxy's 407 in the error, got %v", err)
				}
			}
		})
	}
}

// rawServer answers each connection with handle, on plain HTTP.
func rawServer(t *testing.T, handle func(net.Conn)) (string, net.Listener) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	return ln.Addr().String(), ln
}

// readsAndHangsUp reads a request and closes the connection without answering.
func readsAndHangsUp(c net.Conn) {
	defer c.Close()
	if req, err := stdhttp.ReadRequest(bufio.NewReader(c)); err == nil {
		io.Copy(io.Discard, req.Body)
	}
}

// firstOnlyListener passes on its first connection and closes every later one
// as soon as it is accepted, so a second attempt cannot get a connection.
type firstOnlyListener struct {
	net.Listener
	once sync.Once
}

func (l *firstOnlyListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		first := false
		l.once.Do(func() { first = true })
		if first {
			return c, nil
		}
		c.Close()
	}
}

func TestAFailureOnceTheRequestMayHaveBeenWrittenIsNotMarked(t *testing.T) {
	t.Run("h2 stream reset after the request was read", func(t *testing.T) {
		srv, _ := resetOnH2Server(t)
		if err := failedPost(t, "firefox-148", ProtocolHTTP2, "", srv.URL+"/pay"); RequestNotSent(err) {
			t.Fatalf("marked as not sent: %v", err)
		}
	})

	t.Run("h1 hung up after the request was read", func(t *testing.T) {
		addr, _ := rawServer(t, readsAndHangsUp)
		if err := failedPost(t, "chrome-146", ProtocolHTTP1, "", "http://"+addr+"/pay"); RequestNotSent(err) {
			t.Fatalf("marked as not sent: %v", err)
		}
	})

	t.Run("h1 timed out waiting for the answer", func(t *testing.T) {
		addr, _ := rawServer(t, func(c net.Conn) {
			defer c.Close()
			stdhttp.ReadRequest(bufio.NewReader(c))
			time.Sleep(3 * time.Second)
		})
		tr := NewTransport("chrome-146")
		t.Cleanup(tr.Close)
		_, err := tr.Do(context.Background(), &Request{Method: "POST", URL: "http://" + addr + "/pay", Body: []byte("x"), Timeout: 300 * time.Millisecond})
		if err == nil || RequestNotSent(err) {
			t.Fatalf("want a failure not marked as not sent, got %v", err)
		}
	})

	// The request went out on an idle connection the server then dropped, and
	// the new connection for the second attempt could not be had: the first
	// attempt may have reached the server. A GET, since only an idempotent
	// request written to the idle connection goes again on a new one.
	t.Run("h1 idle connection, then no new one", func(t *testing.T) {
		var ln net.Listener
		requests := 0
		var mu sync.Mutex
		addr, ln := rawServer(t, func(c net.Conn) {
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				req, err := stdhttp.ReadRequest(br)
				if err != nil {
					return
				}
				io.Copy(io.Discard, req.Body)
				mu.Lock()
				requests++
				n := requests
				mu.Unlock()
				if n > 1 {
					ln.Close()
					return
				}
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}
		})
		tr := NewTransport("chrome-146")
		tr.SetProtocol(ProtocolHTTP1)
		t.Cleanup(tr.Close)
		if _, err := tr.Do(context.Background(), &Request{Method: "GET", URL: "http://" + addr + "/"}); err != nil {
			t.Fatalf("first request: %v", err)
		}
		_, err := tr.Do(context.Background(), &Request{Method: "GET", URL: "http://" + addr + "/page", Timeout: 5 * time.Second})
		if err == nil || RequestNotSent(err) {
			t.Fatalf("want a failure not marked as not sent, got %v", err)
		}
	})

	// HTTP/2 delivered the request and the server reset its stream; the GET
	// then fell back to HTTP/1.1, which could not connect. That attempt sent
	// nothing, but the request reached the server all the same.
	t.Run("auto h2 reset, then no h1 connection", func(t *testing.T) {
		srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			panic(stdhttp.ErrAbortHandler)
		}))
		srv.Listener = &firstOnlyListener{Listener: srv.Listener}
		srv.EnableHTTP2 = true
		srv.StartTLS()
		t.Cleanup(srv.Close)
		tr := autoTransport(t, "firefox-148")
		_, err := tr.Do(context.Background(), &Request{Method: "GET", URL: srv.URL, Timeout: 10 * time.Second})
		if err == nil || RequestNotSent(err) {
			t.Fatalf("want a failure not marked as not sent, got %v", err)
		}
		if !strings.Contains(err.Error(), "h1") {
			t.Fatalf("want the HTTP/1.1 fallback's failure, got %v", err)
		}
	})
}
