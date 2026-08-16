package pool

import (
	"sync"
	"testing"
	"time"
)

// Regression locks for the UseCount data race.
//
// MarkUsed() writes LastUsedAt and UseCount under c.mu, and GetConn calls it on
// whichever connection it hands out. client/ then read conn.UseCount straight
// off the struct to decide whether the connection was brand new, purely to
// attribute the connect time across the Timing fields. Two requests multiplexing
// on the same HTTP/2 connection therefore raced: one inside the guarded write,
// the other reading the field bare. The visible damage was only wrong timing
// attribution, but -race builds failed on it roughly one run in four to eight
// (TestPoolReuseConcurrent in client/).
//
// Every read outside the write itself now goes through Uses(). These tests are
// only meaningful under -race; without it they just check the arithmetic.

func TestConnUsesUnderConcurrentMarkUsed(t *testing.T) {
	conn := &Conn{Host: "example.com", CreatedAt: time.Now(), LastUsedAt: time.Now()}
	p := testHostPool(conn)

	const goroutines, iterations = 8, 250

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				conn.MarkUsed()
			}
		}()
	}
	// Both paths that used to touch the fields directly: the client's
	// "is this connection new" timing branch, and HostPool.Stats.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = conn.Uses() == 1
				_ = conn.IdleTime()
				p.Stats()
			}
		}()
	}
	wg.Wait()

	if got, want := conn.Uses(), int64(goroutines*iterations); got != want {
		t.Errorf("UseCount after concurrent MarkUsed: got %d, want %d", got, want)
	}
}

func TestQUICConnUsesUnderConcurrentMarkUsed(t *testing.T) {
	conn := &QUICConn{Host: "example.com", CreatedAt: time.Now(), LastUsedAt: time.Now()}
	p := testQUICHostPool(conn)

	const goroutines, iterations = 8, 250

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				conn.MarkUsed()
			}
		}()
	}
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = conn.Uses() == 1
				_ = conn.IdleTime()
				p.Stats()
			}
		}()
	}
	wg.Wait()

	if got, want := conn.Uses(), int64(goroutines*iterations); got != want {
		t.Errorf("UseCount after concurrent MarkUsed: got %d, want %d", got, want)
	}
}
