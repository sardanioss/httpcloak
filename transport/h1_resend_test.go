package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// When HTTP/1.1 sends a request again on a new connection after its pooled
// one failed. It used to after any failure at all, whatever the method: a POST
// the server had read before dropping the connection, or had not answered
// within the response timeout, went out twice, and the caller got the second
// answer as an ordinary success. It now does only when nothing of the request
// was written, or when the connection failed before any answer and the
// request is idempotent (resend.go), and a connection the server closed while
// idle is not written to at all.

// requestLog records the requests a test server read, by method and body.
type requestLog struct {
	mu   sync.Mutex
	seen []string
}

func (l *requestLog) add(r *stdhttp.Request, body []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, r.Method+" "+string(body))
}

func (l *requestLog) count(method string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.seen {
		if len(s) > len(method) && s[:len(method)+1] == method+" " {
			n++
		}
	}
	return n
}

func (l *requestLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.seen...)
}

// servesThenDrops serves keep-alive requests on each connection. A request on
// a connection that already served one, and whose method is drop, is read in
// full and the connection is closed without an answer: the server acted on it
// and then went away, or a load balancer dropped the connection after
// forwarding the request. Every other request is answered.
func servesThenDrops(log *requestLog, drop string) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		br := bufio.NewReader(c)
		for served := 0; ; served++ {
			req, err := stdhttp.ReadRequest(br)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(req.Body)
			log.add(req, body)
			if served > 0 && req.Method == drop {
				return
			}
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
	}
}

// tlsH1Server serves handle on TLS connections that negotiate http/1.1, and
// returns the https URL.
func tlsH1Server(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS() // for its certificate
	cert := ts.TLS.Certificates[0]
	ts.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
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
	return "https://" + ln.Addr().String()
}

func h1Transport(t *testing.T, proxyURL string) *Transport {
	t.Helper()
	var proxy *ProxyConfig
	if proxyURL != "" {
		proxy = &ProxyConfig{URL: proxyURL}
	}
	tr := NewTransportWithConfig("chrome-146", proxy, nil)
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(ProtocolHTTP1)
	t.Cleanup(tr.Close)
	return tr
}

// warm sends a GET, which leaves a connection to the server in the pool.
func warm(t *testing.T, tr *Transport, url string) {
	t.Helper()
	if _, err := tr.Do(context.Background(), &Request{Method: "GET", URL: url + "/"}); err != nil {
		t.Fatalf("warm-up GET: %v", err)
	}
}

func TestAPostAServerDroppedOnAPooledConnectionGoesOnce(t *testing.T) {
	cases := []struct {
		name  string
		https bool
		proxy bool
		body  func(*Request)
	}{
		{"http, bytes body", false, false, func(r *Request) { r.Body = []byte("charge=100") }},
		{"http, reader body (as the C library passes it)", false, false, func(r *Request) { r.BodyReader = bytes.NewReader([]byte("charge=100")) }},
		{"https through a CONNECT proxy", true, true, func(r *Request) { r.Body = []byte("charge=100") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var log requestLog
			url := ""
			if c.https {
				url = tlsH1Server(t, servesThenDrops(&log, "POST"))
			} else {
				addr, _ := rawServer(t, servesThenDrops(&log, "POST"))
				url = "http://" + addr
			}
			proxy := ""
			if c.proxy {
				proxy = connectProxy(t, "")
			}
			tr := h1Transport(t, proxy)
			warm(t, tr, url)

			req := &Request{Method: "POST", URL: url + "/pay", Timeout: 10 * time.Second}
			c.body(req)
			_, err := tr.Do(context.Background(), req)
			if err == nil {
				t.Fatal("a POST the server dropped the connection on should fail")
			}
			if RequestNotSent(err) {
				t.Fatalf("the server read the POST, but the error says it was not sent: %v", err)
			}
			if n := log.count("POST"); n != 1 {
				t.Fatalf("server read the POST %d times, want once: %q", n, log.all())
			}
		})
	}
}

// A GET may be sent again: the same drop is retried on a new connection and
// succeeds, as in net/http and Chrome.
func TestAGetAServerDroppedOnAPooledConnectionGoesAgain(t *testing.T) {
	var log requestLog
	addr, _ := rawServer(t, servesThenDrops(&log, "GET"))
	tr := h1Transport(t, "")
	warm(t, tr, "http://"+addr)

	resp, err := tr.Do(context.Background(), &Request{Method: "GET", URL: "http://" + addr + "/page", Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("the GET should have gone again on a new connection: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if n := log.count("GET"); n != 3 {
		t.Fatalf("server read %d GETs, want 3 (warm-up, dropped, resent): %q", n, log.all())
	}
}

// A slow answer on a pooled connection: the response timeout runs out, and the
// request is not sent again, whatever its method. A slow server may be at work
// on the request.
func TestNothingIsSentAgainAfterTheAnswerTimedOut(t *testing.T) {
	for _, method := range []string{"POST", "GET"} {
		t.Run(method, func(t *testing.T) {
			var log requestLog
			addr, _ := rawServer(t, func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for served := 0; ; served++ {
					req, err := stdhttp.ReadRequest(br)
					if err != nil {
						return
					}
					body, _ := io.ReadAll(req.Body)
					log.add(req, body)
					if served > 0 {
						time.Sleep(1500 * time.Millisecond)
					}
					io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				}
			})
			tr := h1Transport(t, "")
			tr.GetHTTP1Transport().responseTimeout = time.Second // stands in for the 60 s default
			warm(t, tr, "http://"+addr)

			_, err := tr.Do(context.Background(), &Request{Method: method, URL: "http://" + addr + "/slow", Body: []byte("charge=100"), Timeout: 10 * time.Second})
			if err == nil || RequestNotSent(err) {
				t.Fatalf("want a timeout not marked as not sent, got %v", err)
			}
			time.Sleep(700 * time.Millisecond) // past the server's answer to a second request, had there been one
			if got := log.all(); len(got) != 2 {
				t.Fatalf("server read %q, want the warm-up and the %s once", got, method)
			}
		})
	}
}

// A server that closes a keep-alive connection while it is idle (its own
// keep-alive timeout), or sends something on it first, as servers that answer
// an idle timeout with a 408 do: the next request goes on a new connection,
// and so a POST still goes out once and succeeds. Written to the closed
// connection, it would have failed, since it may not be sent again.
func TestAPostAfterTheServerClosedAnIdleConnectionGoesOnANewOne(t *testing.T) {
	for _, farewell := range []string{"", "HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"} {
		name := "closed"
		if farewell != "" {
			name = "408 then closed"
		}
		t.Run(name, func(t *testing.T) {
			var log requestLog
			var conns sync.WaitGroup
			addr, _ := rawServer(t, func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := stdhttp.ReadRequest(br)
				if err != nil {
					return
				}
				body, _ := io.ReadAll(req.Body)
				log.add(req, body)
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				if req.Method == "GET" {
					// The warm-up's connection goes idle, and the server ends it.
					time.Sleep(50 * time.Millisecond)
					io.WriteString(c, farewell)
					conns.Done()
				}
			})
			tr := h1Transport(t, "")
			conns.Add(1)
			warm(t, tr, "http://"+addr)
			conns.Wait()
			time.Sleep(50 * time.Millisecond) // for the FIN to arrive

			resp, err := tr.Do(context.Background(), &Request{Method: "POST", URL: "http://" + addr + "/pay", Body: []byte("charge=100"), Timeout: 10 * time.Second})
			if err != nil {
				t.Fatalf("the POST should have gone on a new connection: %v", err)
			}
			if resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			if n := log.count("POST"); n != 1 {
				t.Fatalf("server read the POST %d times, want once: %q", n, log.all())
			}
		})
	}
}

// A write to a pooled connection that fails before its first byte sent
// nothing, so even a POST goes again on a new connection; and when that one
// cannot be had either, nothing was sent at all, which the error says.
func TestAPostWhoseWriteFailedBeforeAnyByteGoesAgain(t *testing.T) {
	// breakIdleWrites makes every write on the pooled connections fail at
	// once, as one to a connection the peer reset does.
	breakIdleWrites := func(t *testing.T, tr *Transport) {
		h1 := tr.GetHTTP1Transport()
		h1.idleConnsMu.Lock()
		defer h1.idleConnsMu.Unlock()
		n := 0
		for _, conns := range h1.idleConns {
			for _, c := range conns {
				c.conn.(*net.TCPConn).CloseWrite()
				n++
			}
		}
		if n == 0 {
			t.Fatal("no pooled connection")
		}
	}

	// The first connection answers the warm-up and then neither reads nor
	// closes, so the pooled connection still looks alive when it is taken,
	// and the request is written to it. Later connections answer.
	server := func(t *testing.T, log *requestLog) (string, net.Listener) {
		var first sync.Once
		hold := make(chan struct{})
		t.Cleanup(func() { close(hold) })
		answer := servesThenDrops(log, "")
		return rawServer(t, func(c net.Conn) {
			isFirst := false
			first.Do(func() { isFirst = true })
			if !isFirst {
				answer(c)
				return
			}
			defer c.Close()
			req, err := stdhttp.ReadRequest(bufio.NewReader(c))
			if err != nil {
				return
			}
			log.add(req, nil)
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			<-hold
		})
	}

	t.Run("a new connection", func(t *testing.T) {
		var log requestLog
		addr, _ := server(t, &log)
		tr := h1Transport(t, "")
		warm(t, tr, "http://"+addr)
		breakIdleWrites(t, tr)

		resp, err := tr.Do(context.Background(), &Request{Method: "POST", URL: "http://" + addr + "/pay", Body: []byte("charge=100"), Timeout: 10 * time.Second})
		if err != nil {
			t.Fatalf("the POST should have gone on a new connection: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if got := log.all(); len(got) != 2 || got[1] != "POST charge=100" {
			t.Fatalf("server read %q, want the warm-up and the POST once, whole", got)
		}
	})

	t.Run("no new connection", func(t *testing.T) {
		var log requestLog
		addr, ln := server(t, &log)
		tr := h1Transport(t, "")
		warm(t, tr, "http://"+addr)
		breakIdleWrites(t, tr)
		ln.Close()

		_, err := tr.Do(context.Background(), &Request{Method: "POST", URL: "http://" + addr + "/pay", Body: []byte("charge=100"), Timeout: 10 * time.Second})
		if err == nil || !RequestNotSent(err) {
			t.Fatalf("want a failure marked as not sent, got %v", err)
		}
		if n := log.count("POST"); n != 0 {
			t.Fatalf("server read the POST %d times, want never", n)
		}
	})
}

// A connection whose answer said "Connection: close" is not pooled, so the
// request after it goes on a new connection, and a POST goes once. It used to
// be pooled (the parse removes the header the check looked for), and the next
// request was written to a connection the server had closed.
func TestAPostAfterAConnectionCloseAnswerGoesOnANewOne(t *testing.T) {
	var log requestLog
	addr, _ := rawServer(t, func(c net.Conn) {
		defer c.Close()
		req, err := stdhttp.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		body, _ := io.ReadAll(req.Body)
		log.add(req, body)
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	tr := h1Transport(t, "")
	for i := 0; i < 20; i++ {
		if _, err := tr.Do(context.Background(), &Request{Method: "POST", URL: "http://" + addr + "/pay", Body: []byte("charge=100"), Timeout: 10 * time.Second}); err != nil {
			t.Fatalf("POST %d: %v", i, err)
		}
	}
	if n := log.count("POST"); n != 20 {
		t.Fatalf("server read %d POSTs, want 20", n)
	}
	if stats := tr.GetHTTP1Transport().Stats(); len(stats) != 0 {
		t.Fatalf("connections the server closed were pooled: %+v", stats)
	}
}

// h1OnlyServer is a net/http server that speaks only HTTP/1.1, over TLS or
// not, closes keep-alive connections idle longer than idle, and counts the
// requests it read by method.
func h1OnlyServer(t *testing.T, useTLS bool, idle time.Duration) (url string, log *requestLog) {
	t.Helper()
	log = &requestLog{}
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		body, _ := io.ReadAll(r.Body)
		log.add(r, body)
		io.WriteString(w, "ok")
	}))
	srv.Config.IdleTimeout = idle
	srv.Config.TLSNextProto = map[string]func(*stdhttp.Server, *tls.Conn, stdhttp.Handler){} // no HTTP/2
	if useTLS {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return srv.URL, log
}

// The same through a real server's keep-alive timeout, over TLS (where the
// close arrives as a close_notify alert before the FIN) and through a CONNECT
// proxy (where the proxy, not the server, closes the client's connection).
func TestAPostAfterTheServersKeepAliveTimeoutGoesOnANewOne(t *testing.T) {
	for _, c := range []struct {
		name       string
		tls, proxy bool
	}{
		{"plain", false, false},
		{"TLS", true, false},
		{"plain through a CONNECT proxy", false, true},
		{"TLS through a CONNECT proxy", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			url, log := h1OnlyServer(t, c.tls, 150*time.Millisecond)
			proxy := ""
			if c.proxy {
				proxy = connectProxy(t, "")
			}
			tr := h1Transport(t, proxy)
			warm(t, tr, url)
			time.Sleep(500 * time.Millisecond) // past the server's keep-alive timeout

			resp, err := tr.Do(context.Background(), &Request{Method: "POST", URL: url + "/pay", Body: []byte("charge=100"), Timeout: 10 * time.Second})
			if err != nil {
				t.Fatalf("the POST should have gone on a new connection: %v", err)
			}
			if resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			if n := log.count("POST"); n != 1 {
				t.Fatalf("server read the POST %d times, want once", n)
			}
		})
	}
}

// Bytes a server sent past its answer (a body longer than its Content-Length,
// say) would be read as the next request's answer: the connection is not used
// again, and the POST goes once on a new one.
func TestBytesPastAnAnswerKeepTheConnectionFromBeingUsedAgain(t *testing.T) {
	var log requestLog
	addr, _ := rawServer(t, func(c net.Conn) {
		defer c.Close()
		br := bufio.NewReader(c)
		for {
			req, err := stdhttp.ReadRequest(br)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(req.Body)
			log.add(req, body)
			if req.Method == "POST" {
				io.WriteString(c, "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
				continue
			}
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
	})
	tr := h1Transport(t, "")
	warm(t, tr, "http://"+addr)

	resp, err := tr.Do(context.Background(), &Request{Method: "POST", URL: "http://" + addr + "/pay", Body: []byte("charge=100"), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("status %d: the leftover bytes were read as the POST's answer", resp.StatusCode)
	}
	if n := log.count("POST"); n != 1 {
		t.Fatalf("server read the POST %d times, want once", n)
	}
}

// Every idle connection's watch ends when the transport closes.
func TestIdleWatchesEndWithTheTransport(t *testing.T) {
	url, _ := h1OnlyServer(t, true, time.Minute)
	tr := NewTransport("chrome-146")
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(ProtocolHTTP1)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ { // eight connections at once, each pooled after
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.Do(context.Background(), &Request{Method: "GET", URL: url + "/"})
		}()
	}
	wg.Wait()
	watching := func() int {
		buf := make([]byte, 1<<20)
		return strings.Count(string(buf[:runtime.Stack(buf, true)]), "(*http1Conn).watchIdle")
	}
	if n := watching(); n == 0 {
		t.Fatal("no idle connection is watched")
	}
	tr.Close()
	for deadline := time.Now().Add(3 * time.Second); watching() > 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if n := watching(); n > 0 {
		t.Fatalf("%d idle watches outlived the transport", n)
	}
}
