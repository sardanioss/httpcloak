package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// An HTTP/1.1 exchange blocks in a socket read that only a deadline can
// interrupt, so without a watchdog a cancelled context is invisible to it and
// the caller waits out the full response timeout instead.
func TestWatchContext_CancelUnblocksBlockedRead(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	conn := &http1Conn{conn: local}
	ctx, cancel := context.WithCancel(context.Background())
	stop := watchContext(ctx, conn)
	defer stop()

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := local.Read(buf) // nothing is ever written
		readErr <- err
	}()

	select {
	case err := <-readErr:
		t.Fatalf("read returned before cancellation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("expected the interrupted read to fail")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling the context did not unblock the read")
	}

	if !conn.poisoned.Load() {
		t.Error("connection not marked poisoned; it would go back to the pool mid-response")
	}
}

// doHTTP1 cancels its derived context on return, microseconds after the body is
// read. The watchdog must not act on that: poisoning a connection that has just
// been returned to the pool would silently destroy keep-alive.
func TestWatchContext_DoesNotPoisonAfterExchangeCompletes(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	conn := &http1Conn{conn: local}
	ctx, cancel := context.WithCancel(context.Background())

	stop := watchContext(ctx, conn)
	stop()   // exchange finished, connection headed for the pool
	cancel() // doHTTP1's deferred cancel fires right behind it

	time.Sleep(50 * time.Millisecond)
	if conn.poisoned.Load() {
		t.Error("watchdog poisoned a connection whose exchange had already completed")
	}
}

// A context with no Done channel needs no watchdog goroutine at all.
func TestWatchContext_BackgroundContextIsANoop(t *testing.T) {
	conn := &http1Conn{}
	stop := watchContext(context.Background(), conn)
	stop()
	stop() // must be idempotent
	if conn.poisoned.Load() {
		t.Error("background context poisoned the connection")
	}
}

// A flagged-but-live connection is a landmine: any ordering accident that gets
// it past the poisoned check hands the next request a socket carrying a
// deadline in the past. poison therefore retires the socket outright.
func TestPoison_RetiresTheSocket(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(2 * time.Second)
		}
	}()

	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	conn := &http1Conn{conn: c}
	conn.poison()

	if !conn.poisoned.Load() {
		t.Error("poison did not flag the connection")
	}
	// handleClose clears the deadline before pooling, and the next request arms
	// its own. Neither may resurrect the socket. A live socket would block here
	// and come back with a timeout; a retired one fails at once.
	c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("socket still readable after poison")
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		t.Errorf("socket still open after poison (read merely timed out: %v): a stale watchdog "+
			"could hand a live connection to the pool", err)
	}
}

// handleClose reads conn.poisoned the instant stopWatch() returns, and pools the
// connection on the strength of it. That read is only trustworthy if stopWatch
// has waited for the watchdog to make up its mind; a flag the watchdog may not
// have acted on yet lets a poisoned connection race into the pool.
func TestWatchContext_StopSettlesTheWatchdog(t *testing.T) {
	const iters = 1000
	for i := 0; i < iters; i++ {
		local, remote := net.Pipe()
		conn := &http1Conn{conn: local}
		ctx, cancel := context.WithCancel(context.Background())

		stop := watchContext(ctx, conn)
		go cancel()
		stop()

		// This is exactly the check handleClose performs before pooling.
		decided := conn.poisoned.Load()
		time.Sleep(20 * time.Microsecond)
		if got := conn.poisoned.Load(); got != decided {
			t.Fatalf("iteration %d: poisoned flipped from %v to %v after stop() returned; "+
				"handleClose would already have pooled the connection", i, decided, got)
		}

		cancel()
		local.Close()
		remote.Close()
	}
}

func TestTranslateBodyError(t *testing.T) {
	netErr := errors.New("read tcp 1.2.3.4:80: i/o timeout")

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()

	live, cancelLive := context.WithTimeout(context.Background(), time.Hour)
	defer cancelLive()

	tests := []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"cancelled context claims the read error", cancelled, context.Canceled},
		{"expired deadline claims the read error", expired, context.DeadlineExceeded},
		{"live context leaves a genuine network error alone", live, netErr},
		{"no context leaves the error alone", nil, netErr},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := translateBodyError(tc.ctx, netErr)
			if !errors.Is(got, tc.want) {
				t.Errorf("translateBodyError() = %v, want %v", got, tc.want)
			}
		})
	}
}

// stalledBodyServer answers with headers and a sliver of body, then goes quiet
// forever — the shape that makes a caller cancel mid-download.
func stalledBodyServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
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
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 10000000\r\n\r\n")
				c.Write(make([]byte, 4096))
				c.Read(make([]byte, 1)) // hold the connection until the client leaves
			}(c)
		}
	}()
	return "http://" + ln.Addr().String() + "/"
}

// The point of the watchdog is that a caller can tell their own cancellation
// from a network fault. Interrupting the header wait was never the hard part —
// cancelling mid-download is the common case, and the raw socket error the
// watchdog produces there ("i/o timeout") is indistinguishable from a genuine
// fault, so callers retry a request the user deliberately abandoned.
func TestHTTP1_BodyReadReportsContextError(t *testing.T) {
	url := stalledBodyServer(t)

	tests := []struct {
		name    string
		newCtx  func() (context.Context, context.CancelFunc)
		want    error
		trigger bool // cancel explicitly after the body starts
	}{
		{
			name:    "cancelled during the body read",
			newCtx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			want:    context.Canceled,
			trigger: true,
		},
		{
			name: "deadline expires during the body read",
			newCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 200*time.Millisecond)
			},
			want: context.DeadlineExceeded,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewHTTP1Transport(fingerprint.Chrome146(), dns.NewCache())
			defer tr.Close()

			ctx, cancel := tc.newCtx()
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatalf("headers should have arrived: %v", err)
			}
			defer resp.Body.Close()

			if tc.trigger {
				go func() { time.Sleep(200 * time.Millisecond); cancel() }()
			}

			var readErr error
			buf := make([]byte, 32*1024)
			deadline := time.Now().Add(5 * time.Second)
			for readErr == nil {
				_, readErr = resp.Body.Read(buf)
				if time.Now().After(deadline) {
					t.Fatal("body read never unblocked")
				}
			}

			if !errors.Is(readErr, tc.want) {
				t.Errorf("body read error = %v; errors.Is(err, %v) = false, so a caller cannot "+
					"tell their own cancellation from a network fault", readErr, tc.want)
			}
		})
	}
}

func TestContextError(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()

	future, cancelFuture := context.WithTimeout(context.Background(), time.Hour)
	defer cancelFuture()

	tests := []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"live background context", context.Background(), nil},
		{"deadline still in the future", future, nil},
		{"cancelled", cancelled, context.Canceled},
		{"deadline passed", expired, context.DeadlineExceeded},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := contextError(tc.ctx)
			if tc.want == nil {
				if got != nil {
					t.Errorf("contextError() = %v, want nil", got)
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Errorf("contextError() = %v, want %v", got, tc.want)
			}
		})
	}
}
