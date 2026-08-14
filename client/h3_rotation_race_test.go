package client

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Regression lock: rotating the UDP proxy while requests are in flight must not
// crash the process.
//
// SetUDPProxy closes and nils the three HTTP/3 transports and then rebuilds
// them. doHTTP3 re-read those fields after shouldTryHTTP3's nil check had
// already passed, so a rotation landing in that window was a nil dereference:
//
//	panic: runtime error: invalid memory address or nil pointer dereference
//	pool.(*QUICManager).GetPool(0x0, ...) -> GetConn -> client.doHTTP3
//
// A Go panic is not recoverable from the caller's perspective here: in the
// Python, Node and .NET packages the library is a shared object inside the host
// process, so this takes the whole host down. Proxy rotation under load is the
// pattern this client exists for, which makes the window ordinary rather than
// exotic.
//
// The requests are expected to FAIL (there is no reachable target); the
// assertion is that the process survives and no nil dereference occurs.
func TestH3TransportRotationUnderLoad(t *testing.T) {
	c := NewClient("chrome-latest", WithTimeout(2*time.Second))
	defer c.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				resp, err := c.Get(ctx, "https://127.0.0.1:1/never", nil)
				if err == nil && resp != nil {
					resp.Close()
				}
				cancel()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 60; i++ {
			select {
			case <-stop:
				return
			default:
			}
			c.SetUDPProxy("")
			time.Sleep(2 * time.Millisecond)
		}
	}()

	time.Sleep(1500 * time.Millisecond)
	close(stop)
	wg.Wait()
	// Reaching here without a panic is the assertion.
}
