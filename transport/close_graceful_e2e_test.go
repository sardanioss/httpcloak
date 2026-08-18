package transport

import (
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// End-to-end check of CloseGraceful against a real HTTP/2 server: a response
// body that is mid-stream when the transport is closed gracefully is delivered
// in full, the transport refuses new requests from that moment, and the
// connection closes once the body is done. The same scenario under Close is
// included for contrast, so the two behaviours are pinned side by side.

// slowH2Server serves one response whose body arrives in two halves: the first
// half at once, the second only after release is closed.
type slowH2Server struct {
	srv     *httptest.Server
	host    string
	port    string
	started chan struct{} // closed once the first half has been flushed
	release chan struct{} // close to let the handler send the second half
}

const (
	slowBodyFirstHalf  = "first-half-"
	slowBodySecondHalf = "second-half"
)

func newSlowH2Server(t *testing.T) *slowH2Server {
	t.Helper()
	s := &slowH2Server{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	s.srv = httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.ProtoMajor != 2 {
			stdhttp.Error(w, "expected HTTP/2, got "+r.Proto, stdhttp.StatusBadRequest)
			return
		}
		w.WriteHeader(stdhttp.StatusOK)
		io.WriteString(w, slowBodyFirstHalf)
		w.(stdhttp.Flusher).Flush()
		close(s.started)
		<-s.release
		io.WriteString(w, slowBodySecondHalf)
	}))
	s.srv.EnableHTTP2 = true
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)

	u, err := url.Parse(s.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	s.host, s.port, err = net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *slowH2Server) request(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, s.srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func newE2ETransport(t *testing.T) *HTTP2Transport {
	t.Helper()
	preset := fingerprint.Get("chrome-146")
	if preset == nil {
		t.Skip("chrome-146 preset unavailable")
	}
	tr := NewHTTP2Transport(preset, dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(tr.Close)
	return tr
}

// readWithin reads r to EOF in the background and fails the test if that does
// not finish within d, so a body that hangs is reported rather than blocking.
func readWithin(t *testing.T, r io.Reader, d time.Duration) ([]byte, error) {
	t.Helper()
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := io.ReadAll(r)
		done <- result{b, err}
	}()
	select {
	case res := <-done:
		return res.b, res.err
	case <-time.After(d):
		t.Fatalf("reading the response body did not finish within %s", d)
		return nil, nil
	}
}

func TestCloseGracefulE2E(t *testing.T) {
	srv := newSlowH2Server(t)
	tr := newE2ETransport(t)

	resp, err := tr.RoundTrip(srv.request(t))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected an HTTP/2 response, got %s", resp.Proto)
	}
	select {
	case <-srv.started:
	case <-time.After(5 * time.Second):
		t.Fatal("server never flushed the first half of the body")
	}

	// The connection carrying the response, so we can watch it after it leaves
	// the pool.
	key := net.JoinHostPort(srv.host, srv.port)
	tr.connsMu.RLock()
	conn := tr.conns[key]
	tr.connsMu.RUnlock()
	if conn == nil {
		t.Fatalf("no pooled connection for %s", key)
	}

	tr.CloseGraceful()

	// From here on: no new requests ...
	if _, err := tr.RoundTrip(srv.request(t)); err == nil {
		t.Error("RoundTrip after CloseGraceful should fail")
	} else if !strings.Contains(err.Error(), "closed") {
		t.Errorf("RoundTrip after CloseGraceful: got %v, want a closed error", err)
	}
	// ... but the response in flight is untouched.
	if connClosed(conn)() {
		t.Fatal("CloseGraceful closed the connection under a body still streaming")
	}
	if n := retiredCount(tr); n != 1 {
		t.Fatalf("streaming connection should be retired, got %d retired", n)
	}

	// Let the server finish; the reader gets the whole body with no error.
	close(srv.release)
	body, err := readWithin(t, resp.Body, 5*time.Second)
	if err != nil {
		t.Fatalf("reading body after CloseGraceful: %v", err)
	}
	if got, want := string(body), slowBodyFirstHalf+slowBodySecondHalf; got != want {
		t.Fatalf("body after CloseGraceful = %q, want %q", got, want)
	}
	if err := resp.Body.Close(); err != nil {
		t.Errorf("Body.Close: %v", err)
	}

	// And now, with the body done, the connection goes away on its own.
	if !waitFor(t, 2*time.Second, connClosed(conn)) {
		t.Error("connection did not close after its last body finished")
	}
	tr.cleanup()
	if !tr.drained() {
		t.Error("transport should be drained once the last body finished")
	}
}

// The behaviour CloseGraceful exists to avoid: Close cuts the reader off.
func TestCloseInterruptsStreamingBodyE2E(t *testing.T) {
	srv := newSlowH2Server(t)
	tr := newE2ETransport(t)

	resp, err := tr.RoundTrip(srv.request(t))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	select {
	case <-srv.started:
	case <-time.After(5 * time.Second):
		t.Fatal("server never flushed the first half of the body")
	}

	tr.Close()
	defer close(srv.release) // let the handler return so the server can shut down

	body, err := readWithin(t, resp.Body, 5*time.Second)
	if err == nil {
		t.Fatalf("Close should have interrupted the body read; got a clean %q", body)
	}
	if errors.Is(err, io.EOF) {
		t.Fatal("Close should surface an error to the reader, not a clean EOF")
	}
}

// Session-level shape of the same guarantee, through Transport.CloseGraceful:
// DoStream's body outlives the call, so it is the reader most likely to be cut
// off by a rotation.
func TestTransportCloseGracefulStreamE2E(t *testing.T) {
	srv := newSlowH2Server(t)
	if fingerprint.Get("chrome-146") == nil {
		t.Skip("chrome-146 preset unavailable")
	}
	tr := NewTransport("chrome-146")
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(ProtocolHTTP2)
	t.Cleanup(tr.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := tr.DoStream(ctx, &Request{Method: http.MethodGet, URL: srv.srv.URL})
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	select {
	case <-srv.started:
	case <-time.After(5 * time.Second):
		t.Fatal("server never flushed the first half of the body")
	}

	tr.CloseGraceful()

	if _, err := tr.Do(ctx, &Request{Method: http.MethodGet, URL: srv.srv.URL}); err == nil {
		t.Error("Do after CloseGraceful should fail")
	}

	close(srv.release)
	body, err := readWithin(t, stream, 5*time.Second)
	if err != nil {
		t.Fatalf("reading stream after CloseGraceful: %v", err)
	}
	if got, want := string(body), slowBodyFirstHalf+slowBodySecondHalf; got != want {
		t.Fatalf("stream body after CloseGraceful = %q, want %q", got, want)
	}
	stream.Close()
}

// The rotation case: a plain Do that is still reading its response when the
// transport is closed gracefully returns the full response, not an error.
func TestTransportCloseGracefulDoInFlightE2E(t *testing.T) {
	srv := newSlowH2Server(t)
	if fingerprint.Get("chrome-146") == nil {
		t.Skip("chrome-146 preset unavailable")
	}
	tr := NewTransport("chrome-146")
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(ProtocolHTTP2)
	t.Cleanup(tr.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		resp *Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := tr.Do(ctx, &Request{Method: http.MethodGet, URL: srv.srv.URL})
		done <- result{resp, err}
	}()
	select {
	case <-srv.started:
	case <-time.After(5 * time.Second):
		t.Fatal("server never flushed the first half of the body")
	}

	tr.CloseGraceful()
	close(srv.release)

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("Do in flight across CloseGraceful: %v", res.err)
		}
		body, err := io.ReadAll(res.resp.Body)
		if err != nil {
			t.Fatalf("reading Do body: %v", err)
		}
		if got, want := string(body), slowBodyFirstHalf+slowBodySecondHalf; got != want {
			t.Fatalf("Do body across CloseGraceful = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Do did not return within 5s of the server finishing")
	}
}

// Same hammer as TestH2TransportConcurrentCloseAndRoundTrip, for the graceful
// path: dials racing a CloseGraceful must neither panic nor leak a connection
// that was published after the transport closed.
func TestH2TransportConcurrentCloseGracefulAndDial(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping race stress in short mode")
	}
	preset := fingerprint.Get("chrome-146")
	if preset == nil {
		t.Skip("chrome-146 preset unavailable")
	}

	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(u.Host)
	key := net.JoinHostPort(host, port)

	const (
		iterations = 30
		goroutines = 16
	)
	for i := 0; i < iterations; i++ {
		tr := NewHTTP2Transport(preset, dns.NewCache())
		tr.SetInsecureSkipVerify(true)

		var wg sync.WaitGroup
		for g := 0; g < goroutines; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panicked: %v", r)
					}
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
				_, _ = tr.getOrCreateConn(ctx, host, port, key)
			}()
		}
		time.Sleep(time.Duration(i%10) * 100 * time.Microsecond)
		tr.CloseGraceful()
		wg.Wait()

		// Whatever the interleaving, nothing may remain in the pool: a dial
		// that lost the race to CloseGraceful must have closed its connection.
		tr.connsMu.RLock()
		leaked := len(tr.conns)
		tr.connsMu.RUnlock()
		if leaked != 0 {
			t.Fatalf("iteration %d: %d connection(s) published into a gracefully closed transport", i, leaked)
		}
		tr.Close()
	}
}

// HTTP/1.1 gets the same guarantee through Transport.CloseGraceful without any
// H1-specific code: its transport only ever closes idle connections, and a
// checked-out one closes itself on return once the transport is closed. This
// pins that, so a change to the H1 pool cannot silently break the contract.
func TestTransportCloseGracefulH1StreamE2E(t *testing.T) {
	if fingerprint.Get("chrome-146") == nil {
		t.Skip("chrome-146 preset unavailable")
	}
	started := make(chan struct{})
	release := make(chan struct{})
	// NewTLSServer negotiates http/1.1 only.
	srv := httptest.NewTLSServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusOK)
		io.WriteString(w, slowBodyFirstHalf)
		w.(stdhttp.Flusher).Flush()
		close(started)
		<-release
		io.WriteString(w, slowBodySecondHalf)
	}))
	defer srv.Close()

	tr := NewTransport("chrome-146")
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(ProtocolHTTP1)
	t.Cleanup(tr.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := tr.DoStream(ctx, &Request{Method: http.MethodGet, URL: srv.URL})
	if err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	if stream.Protocol != "h1" {
		t.Fatalf("expected an HTTP/1.1 stream, got %q", stream.Protocol)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("server never flushed the first half of the body")
	}

	tr.CloseGraceful()

	if _, err := tr.Do(ctx, &Request{Method: http.MethodGet, URL: srv.URL}); err == nil {
		t.Error("Do after CloseGraceful should fail")
	}

	close(release)
	body, err := readWithin(t, stream, 5*time.Second)
	if err != nil {
		t.Fatalf("reading H1 stream after CloseGraceful: %v", err)
	}
	if got, want := string(body), slowBodyFirstHalf+slowBodySecondHalf; got != want {
		t.Fatalf("H1 stream body after CloseGraceful = %q, want %q", got, want)
	}
	stream.Close()
}
