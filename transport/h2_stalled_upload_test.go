package transport

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// stallRelay forwards TCP to a backend. set(true) stops it reading what the
// client sends, so the client's socket send buffer fills and its writes block.
type stallRelay struct {
	ln     net.Listener
	mu     sync.Mutex
	frozen bool
	cond   *sync.Cond
}

func newStallRelay(t *testing.T, backend string) *stallRelay {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &stallRelay{ln: ln}
	r.cond = sync.NewCond(&r.mu)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetReadBuffer(16 << 10)
			}
			b, err := net.Dial("tcp", backend)
			if err != nil {
				c.Close()
				continue
			}
			go func() { io.Copy(c, b); c.Close() }()
			go func() {
				buf := make([]byte, 4096)
				for {
					r.mu.Lock()
					for r.frozen {
						r.cond.Wait()
					}
					r.mu.Unlock()
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := b.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						b.Close()
						return
					}
				}
			}()
		}
	}()
	return r
}

func (r *stallRelay) set(f bool) { r.mu.Lock(); r.frozen = f; r.mu.Unlock(); r.cond.Broadcast() }

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// A request to a host must keep its own deadline while another request on
// the same HTTP/2 connection is stuck uploading to a peer that stopped
// reading. The stuck writer holds the HTTP/2 write lock; anything on the
// path to RoundTrip that waits on that lock (ClientConn.State did) makes the
// new request hang until the upload gives up, past its own timeout.
func TestHTTP2StalledUploadDoesNotBlockNewRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("takes a few seconds")
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write([]byte("ok"))
	})
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.Config.HTTP2 = &http.HTTP2Config{MaxReceiveBufferPerConnection: 1 << 30, MaxReceiveBufferPerStream: 1 << 30}
	srv.StartTLS()
	defer srv.Close()

	relay := newStallRelay(t, srv.Listener.Addr().String())
	defer relay.ln.Close()
	defer relay.set(false)
	base := "https://" + relay.ln.Addr().String()

	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	resp, err := tr.Do(ctx, &Request{Method: "GET", URL: base + "/warm"})
	cancel()
	if err != nil {
		t.Fatalf("warm-up request: %v", err)
	}
	resp.Close()

	relay.set(true)
	upCtx, upCancel := context.WithCancel(context.Background())
	defer upCancel()
	go func() {
		resp, err := tr.Do(upCtx, &Request{Method: "POST", URL: base + "/upload", BodyReader: io.LimitReader(zeroReader{}, 512<<20)})
		if err == nil {
			resp.Close()
		}
	}()
	time.Sleep(1500 * time.Millisecond) // let the send buffer fill

	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if resp, err := tr.Do(ctx, &Request{Method: "GET", URL: base + "/b"}); err == nil {
			resp.Close()
		}
	}()
	select {
	case <-done:
		if d := time.Since(start); d > 4*time.Second {
			t.Fatalf("request with a 2s timeout returned after %v", d)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("request with a 2s timeout is still blocked after 8s behind a stalled upload")
	}
}
