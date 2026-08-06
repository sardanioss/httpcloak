package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
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
