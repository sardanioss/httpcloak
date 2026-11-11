//go:build hctest

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Issue #114. Host callbacks used to run on whichever Go thread finished the
// work. A .NET host treats a thread that has run its code as one of its own
// and later sends it GC-suspension APCs; delivered while the thread runs Go
// code on a goroutine stack, they end the process with 0xC000000D. Every host
// callback now runs on a thread the shim created, which can be checked here
// even though the crash itself is Windows-only.
//
// Run with: go test -tags hctest -run Callback .
func TestHostCallbacksRunOnShimThreads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	h := hcTestSessionNew(`{"preset":"chrome-155-windows","timeout":10}`)
	if h <= 0 {
		t.Fatalf("session_new returned %d", h)
	}
	defer hcTestSessionFree(h)

	// The C counters live as long as the process (other tests and -count
	// runs add to them), so everything below counts from here.
	calls0, onWorker0, gets0, getsOnWorker0 := hcTestCounts()

	const n = 20
	for i := 0; i < n; i++ {
		id := hcTestRegisterAsync()
		hcTestRequestAsync(h, fmt.Sprintf(`{"method":"GET","url":%q}`, srv.URL), id)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		calls, onWorker, _, _ := hcTestCounts()
		calls, onWorker = calls-calls0, onWorker-onWorker0
		if calls >= n {
			if onWorker != calls {
				t.Errorf("%d of %d async callbacks ran on a Go thread", calls-onWorker, calls)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d async callbacks arrived", calls, n)
		}
		time.Sleep(20 * time.Millisecond)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); hcTestCacheGet(false) }()
	}
	wg.Wait()
	_, _, gets, getsOnWorker := hcTestCounts()
	gets, getsOnWorker = gets-gets0, getsOnWorker-getsOnWorker0
	if gets != 16 || getsOnWorker != gets {
		t.Errorf("sync cache callbacks: %d calls, %d on shim threads; want 16 and 16", gets, getsOnWorker)
	}
}

// A callback that re-enters the library and triggers another callback must
// not wait behind itself: the pool keeps a free worker for every queued job.
func TestReentrantCallbackDoesNotDeadlock(t *testing.T) {
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); hcTestCacheGet(true) }()
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("re-entrant callbacks deadlocked")
	}
}

// Issue #147. The other direction: a .NET thread that calls into the library
// ran Go on that thread, and the same APC ends the process. Every public
// function is now a C wrapper that runs the Go code on a library thread. The
// hctest build forces that hop on Linux too, so it is exercised here.

func TestExportsRunOnExportThreads(t *testing.T) {
	before := hcTestExportHops()
	if v := hcTestPublicVersion(); v == "" {
		t.Fatal("httpcloak_version through the wrapper returned nothing")
	}
	if got := hcTestExportHops() - before; got != 1 {
		t.Fatalf("httpcloak_version ran on an export thread %d times; want 1", got)
	}
}

// Many host threads at once, each blocked in a request: the export pool must
// grow rather than queue them, or a slow request would hold up every caller.
// The server answers only once all of them have arrived.
func TestConcurrentExportCallsFromHostThreads(t *testing.T) {
	const n = 32
	var arrived sync.WaitGroup
	arrived.Add(n)
	release := make(chan struct{})
	go func() { arrived.Wait(); close(release) }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived.Done()
		select {
		case <-release:
		case <-time.After(20 * time.Second):
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	before := hcTestExportHops()
	done := make(chan int, 1)
	go func() { done <- hcTestGetFromThreads(`{"preset":"chrome-155-windows","timeout":30}`, srv.URL, n) }()
	select {
	case ok := <-done:
		if ok != n {
			t.Fatalf("%d of %d threads got a 200", ok, n)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent export calls from host threads did not finish")
	}
	// session_new, get and session_free per thread.
	if got := hcTestExportHops() - before; got < 3*n {
		t.Errorf("%d exports ran on export threads; want at least %d", got, 3*n)
	}
}

// A host callback that calls the library while Go waits on it: the call hops
// from a callback thread to an export thread and must not deadlock.
func TestExportCalledFromHostCallback(t *testing.T) {
	// The C counter lives as long as the process, so count from here.
	before := hcTestExportFromCallbackCount()
	done := make(chan int, 1)
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); hcTestExportFromCallback() }()
		}
		wg.Wait()
		done <- hcTestExportFromCallback() - before
	}()
	select {
	case ok := <-done:
		if ok != 9 {
			t.Fatalf("%d of 9 exports called from a callback succeeded", ok)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("export called from a host callback deadlocked")
	}
}

// What the hop costs per call: a public wrapper against the Go function.
func BenchmarkExportHop(b *testing.B) {
	b.Run("hop", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			hcTestPublicVersion()
		}
	})
	b.Run("direct", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			hcTestDirectVersion()
		}
	})
}
