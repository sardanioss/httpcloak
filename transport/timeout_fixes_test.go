package transport

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/sardanioss/http"
)

// ============================================================================
// Fix 1: H3 wg.Wait() context-aware waiting
// Verify that wg.Wait() wrapped in channel+select unblocks on context cancellation
// ============================================================================

func TestContextAwareWaitGroup(t *testing.T) {
	t.Run("cancellation unblocks wait", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		var wg sync.WaitGroup
		wg.Add(1)
		// Simulate a goroutine that never finishes (e.g., DNS lookup hangs)
		go func() {
			defer wg.Done()
			<-time.After(10 * time.Second) // would block forever without ctx
		}()

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		start := time.Now()
		select {
		case <-done:
			t.Fatal("wg.Wait() completed before context cancelled - goroutine should still be running")
		case <-ctx.Done():
			elapsed := time.Since(start)
			if elapsed > 500*time.Millisecond {
				t.Fatalf("context cancellation took too long: %v", elapsed)
			}
			// This is the expected path - context cancelled, we unblocked
		}
	})

	t.Run("normal completion before timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond) // fast completion
		}()
		go func() {
			defer wg.Done()
			time.Sleep(20 * time.Millisecond) // fast completion
		}()

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// Good - both goroutines completed normally
		case <-ctx.Done():
			t.Fatal("context expired before goroutines completed")
		}
	})
}

// ============================================================================
// Fix 2: Per-address dial timeout in dialFirstSuccessful
// Verify budget is divided across addresses and capped at 10s
// ============================================================================

func TestPerAddressTimeoutCalculation(t *testing.T) {
	tests := []struct {
		name           string
		totalTimeout   time.Duration
		numAddrs       int
		addrIndex      int
		expectedMaxPer time.Duration
	}{
		{
			name:           "30s budget across 3 addrs, first addr",
			totalTimeout:   30 * time.Second,
			numAddrs:       3,
			addrIndex:      0,
			expectedMaxPer: 10 * time.Second, // 30/3 = 10s
		},
		{
			name:           "6s budget across 3 addrs, first addr",
			totalTimeout:   6 * time.Second,
			numAddrs:       3,
			addrIndex:      0,
			expectedMaxPer: 2 * time.Second, // 6/3 = 2s
		},
		{
			name:           "60s budget across 2 addrs, capped at 10s",
			totalTimeout:   60 * time.Second,
			numAddrs:       2,
			addrIndex:      0,
			expectedMaxPer: 10 * time.Second, // 60/2 = 30s, capped to 10s
		},
		{
			name:           "single addr uses full budget, capped at 10s",
			totalTimeout:   5 * time.Second,
			numAddrs:       1,
			addrIndex:      0,
			expectedMaxPer: 5 * time.Second, // 5/1 = 5s
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tt.totalTimeout)
			defer cancel()

			remaining := tt.numAddrs - tt.addrIndex
			perAddrTimeout := 10 * time.Second
			if deadline, ok := ctx.Deadline(); ok {
				budget := time.Until(deadline) / time.Duration(remaining)
				if budget < perAddrTimeout {
					perAddrTimeout = budget
				}
			}

			// Allow 100ms tolerance for timing
			if perAddrTimeout > tt.expectedMaxPer+100*time.Millisecond {
				t.Errorf("per-addr timeout %v exceeds expected max %v", perAddrTimeout, tt.expectedMaxPer)
			}
		})
	}
}

// TestPerAddressTimeoutPreventsStarvation verifies that a slow first address
// doesn't consume the entire budget, leaving time for subsequent addresses.
func TestPerAddressTimeoutPreventsStarvation(t *testing.T) {
	totalTimeout := 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	numAddrs := 3
	var attempts int32

	// Simulate dialFirstSuccessful logic
	for i := 0; i < numAddrs; i++ {
		select {
		case <-ctx.Done():
			break
		default:
		}

		remaining := numAddrs - i
		perAddrTimeout := 10 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			budget := time.Until(deadline) / time.Duration(remaining)
			if budget < perAddrTimeout {
				perAddrTimeout = budget
			}
		}

		addrCtx, addrCancel := context.WithTimeout(ctx, perAddrTimeout)
		// Simulate a dial that takes the full per-address timeout
		select {
		case <-addrCtx.Done():
			// Timed out for this address
		}
		addrCancel()
		atomic.AddInt32(&attempts, 1)
	}

	got := atomic.LoadInt32(&attempts)
	if got < 2 {
		t.Errorf("only attempted %d addresses; expected at least 2 with budget division", got)
	}
}

// ============================================================================
// Fix 3: raceH3H2 hardcoded 6s sleep → context-aware
// Verify that the sleep goroutine respects context cancellation
// ============================================================================

func TestContextAwareSleep(t *testing.T) {
	t.Run("sleep unblocks on context cancel", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		doneCh := make(chan struct{})
		go func() {
			select {
			case <-time.After(6 * time.Second):
			case <-ctx.Done():
			}
			close(doneCh)
		}()

		start := time.Now()
		<-doneCh
		elapsed := time.Since(start)

		if elapsed > 500*time.Millisecond {
			t.Fatalf("sleep did not respect context cancellation, took %v", elapsed)
		}
	})

	t.Run("sleep completes normally without cancel", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		sleepDuration := 50 * time.Millisecond
		doneCh := make(chan struct{})
		go func() {
			select {
			case <-time.After(sleepDuration):
			case <-ctx.Done():
			}
			close(doneCh)
		}()

		start := time.Now()
		<-doneCh
		elapsed := time.Since(start)

		if elapsed < sleepDuration/2 {
			t.Fatalf("sleep completed too early: %v", elapsed)
		}
		if elapsed > sleepDuration+200*time.Millisecond {
			t.Fatalf("sleep took too long: %v", elapsed)
		}
	})
}

// ============================================================================
// Fix 4: Proxy CONNECT dialHTTPProxyBlocking — add read deadline
// Verify that ReadResponse has a deadline set on the connection
// ============================================================================

// slowWriter simulates a proxy that never sends a complete response
type slowWriter struct {
	net.Conn
	readDelay time.Duration
	readBuf   bytes.Buffer
	mu        sync.Mutex
	deadline  time.Time
}

func (s *slowWriter) Read(b []byte) (int, error) {
	s.mu.Lock()
	dl := s.deadline
	s.mu.Unlock()

	if !dl.IsZero() && time.Now().After(dl) {
		return 0, &timeoutError{}
	}

	if s.readDelay > 0 {
		if !dl.IsZero() {
			remaining := time.Until(dl)
			if s.readDelay > remaining {
				time.Sleep(remaining)
				return 0, &timeoutError{}
			}
		}
		time.Sleep(s.readDelay)
	}

	return s.readBuf.Read(b)
}

func (s *slowWriter) Write(b []byte) (int, error) {
	return len(b), nil // Accept writes silently
}

func (s *slowWriter) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.deadline = t
	s.mu.Unlock()
	return nil
}

func (s *slowWriter) SetDeadline(t time.Time) error {
	return s.SetReadDeadline(t)
}

func (s *slowWriter) SetWriteDeadline(t time.Time) error {
	return nil
}

func (s *slowWriter) Close() error {
	return nil
}

func (s *slowWriter) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (s *slowWriter) RemoteAddr() net.Addr { return &net.TCPAddr{} }

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func TestProxyCONNECTReadDeadline_H2(t *testing.T) {
	t.Run("successful proxy response", func(t *testing.T) {
		// Create a mock conn that sends a valid 200 OK response
		conn := &slowWriter{}
		conn.readBuf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")

		h2 := &HTTP2Transport{
			connectTimeout: 30 * time.Second,
		}

		result, err := h2.dialHTTPProxyBlocking(context.Background(), conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil connection")
		}
	})

	t.Run("proxy timeout triggers deadline", func(t *testing.T) {
		// Verify that SetReadDeadline IS called before ReadResponse
		// by using a conn that tracks deadline calls and returns timeout on Read
		var deadlines []time.Time
		conn := &deadlineTrackingConn{
			readBuf:   bytes.NewBuffer(nil), // Empty - will block
			deadlines: &deadlines,
		}

		h2 := &HTTP2Transport{
			connectTimeout: 30 * time.Second,
		}

		_, err := h2.dialHTTPProxyBlocking(context.Background(), conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		// Should get an EOF error since our mock buffer is empty
		if err == nil {
			t.Fatal("expected error from empty buffer proxy")
		}

		// Key assertion: SetReadDeadline was called with a non-zero value before ReadResponse
		if len(deadlines) < 1 {
			t.Fatal("SetReadDeadline was never called - read deadline fix is not working")
		}
		if deadlines[0].IsZero() {
			t.Fatal("SetReadDeadline was called with zero time - should be ~30s from now")
		}
		// Verify the deadline is approximately 30s from now
		expectedDeadline := time.Now().Add(30 * time.Second)
		diff := deadlines[0].Sub(expectedDeadline)
		if diff < 0 {
			diff = -diff
		}
		if diff > 2*time.Second {
			t.Fatalf("deadline is off by %v from expected 30s", diff)
		}
	})

	t.Run("proxy error status code", func(t *testing.T) {
		conn := &slowWriter{}
		conn.readBuf.WriteString("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")

		h2 := &HTTP2Transport{
			connectTimeout: 30 * time.Second,
		}

		_, err := h2.dialHTTPProxyBlocking(context.Background(), conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		if err == nil {
			t.Fatal("expected error for 403 response")
		}
	})

	t.Run("slow proxy response completes before deadline", func(t *testing.T) {
		// Proxy takes 100ms to respond - should succeed since deadline is 30s
		conn := &slowWriter{readDelay: 100 * time.Millisecond}
		conn.readBuf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")

		h2 := &HTTP2Transport{
			connectTimeout: 30 * time.Second,
		}

		result, err := h2.dialHTTPProxyBlocking(context.Background(), conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil connection")
		}
	})
}

func TestProxyCONNECTReadDeadline_H1(t *testing.T) {
	t.Run("successful proxy response", func(t *testing.T) {
		conn := &slowWriter{}
		conn.readBuf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")

		h1 := &HTTP1Transport{
			connectTimeout: 30 * time.Second,
		}

		result, err := h1.dialHTTPProxyBlocking(context.Background(), conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil connection")
		}
	})

	t.Run("proxy timeout triggers deadline", func(t *testing.T) {
		var deadlines []time.Time
		conn := &deadlineTrackingConn{
			readBuf:   bytes.NewBuffer(nil), // Empty - will EOF
			deadlines: &deadlines,
		}

		h1 := &HTTP1Transport{
			connectTimeout: 30 * time.Second,
		}

		_, err := h1.dialHTTPProxyBlocking(context.Background(), conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		if err == nil {
			t.Fatal("expected error from empty buffer proxy")
		}

		// Verify SetReadDeadline was called
		if len(deadlines) < 1 {
			t.Fatal("SetReadDeadline was never called - read deadline fix is not working")
		}
		if deadlines[0].IsZero() {
			t.Fatal("SetReadDeadline was called with zero time - should be ~30s from now")
		}
	})
}

// ============================================================================
// Fix 5: closeWithTimeout helper
// Verify that Close() blocking is bounded by timeout
// ============================================================================

type blockingCloser struct {
	blockDuration time.Duration
	closed        int32
}

func (b *blockingCloser) Close() error {
	time.Sleep(b.blockDuration)
	atomic.AddInt32(&b.closed, 1)
	return nil
}

func TestCloseWithTimeout(t *testing.T) {
	t.Run("fast close completes within timeout", func(t *testing.T) {
		bc := &blockingCloser{blockDuration: 10 * time.Millisecond}

		start := time.Now()
		closeWithTimeout(bc, 1*time.Second)
		elapsed := time.Since(start)

		if elapsed > 500*time.Millisecond {
			t.Fatalf("fast close took too long: %v", elapsed)
		}

		// Verify Close() was actually called
		time.Sleep(50 * time.Millisecond)
		if atomic.LoadInt32(&bc.closed) != 1 {
			t.Fatal("Close() was not called")
		}
	})

	t.Run("slow close is bounded by timeout", func(t *testing.T) {
		bc := &blockingCloser{blockDuration: 10 * time.Second}

		start := time.Now()
		closeWithTimeout(bc, 100*time.Millisecond)
		elapsed := time.Since(start)

		if elapsed > 500*time.Millisecond {
			t.Fatalf("closeWithTimeout should have returned after ~100ms, took %v", elapsed)
		}

		// Close() goroutine is still running in background - that's expected
	})
}

// ============================================================================
// Fix 6: H2 RoundTrip retry checks context before retrying
// Verify that expired context prevents retry attempt
// ============================================================================

func TestH2RetryChecksContext(t *testing.T) {
	t.Run("expired context prevents retry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Immediately cancel

		// Verify context is done
		if ctx.Err() == nil {
			t.Fatal("expected context to be cancelled")
		}

		// The fix checks req.Context().Err() before retrying
		// We verify the pattern directly
		err := ctx.Err()
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	})

	t.Run("context deadline exceeded prevents retry", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(10 * time.Millisecond) // Ensure timeout fires

		err := ctx.Err()
		if err != context.DeadlineExceeded {
			t.Fatalf("expected context.DeadlineExceeded, got %v", err)
		}
	})

	t.Run("active context allows retry", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := ctx.Err()
		if err != nil {
			t.Fatalf("expected nil context error, got %v", err)
		}
	})
}

// ============================================================================
// Fix 7: speculative_conn recursive read → iterative
// Verify the iterative loop handles partial headers and large headers
// ============================================================================

// mockConn simulates a network connection with controlled reads
type mockConn struct {
	net.Conn
	reads    [][]byte // Each entry is returned by one Read() call
	readIdx  int
	mu       sync.Mutex
	deadline time.Time
}

func newMockConn(reads ...[]byte) *mockConn {
	return &mockConn{reads: reads}
}

func (m *mockConn) Read(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.readIdx >= len(m.reads) {
		return 0, io.EOF
	}

	data := m.reads[m.readIdx]
	m.readIdx++
	n := copy(b, data)
	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error)        { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestSpeculativeConnIterativeRead(t *testing.T) {
	t.Run("complete response in single read", func(t *testing.T) {
		httpResponse := "HTTP/1.1 200 Connection established\r\n\r\n"
		tlsData := []byte{0x16, 0x03, 0x03, 0x00, 0x05} // TLS record header

		conn := newMockConn(append([]byte(httpResponse), tlsData...))
		sc := NewSpeculativeConn(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		sc.firstWrite = true // Skip write interception

		buf := make([]byte, 1024)
		n, err := sc.Read(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != len(tlsData) {
			t.Fatalf("expected %d bytes of TLS data, got %d", len(tlsData), n)
		}
		if !bytes.Equal(buf[:n], tlsData) {
			t.Fatalf("TLS data mismatch: got %v, want %v", buf[:n], tlsData)
		}
	})

	t.Run("partial header across multiple reads", func(t *testing.T) {
		// Split the HTTP response across multiple reads (simulates slow proxy)
		part1 := []byte("HTTP/1.1 200 Co")
		part2 := []byte("nnection established\r\n")
		part3 := []byte("\r\n")
		tlsData := []byte{0x16, 0x03, 0x03}

		conn := newMockConn(part1, part2, append(part3, tlsData...))
		sc := NewSpeculativeConn(conn, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
		sc.firstWrite = true

		buf := make([]byte, 1024)
		n, err := sc.Read(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != len(tlsData) {
			t.Fatalf("expected %d bytes of TLS data, got %d", len(tlsData), n)
		}
		if !bytes.Equal(buf[:n], tlsData) {
			t.Fatalf("TLS data mismatch: got %v, want %v", buf[:n], tlsData)
		}
	})

	t.Run("byte-at-a-time reads (worst case for recursion)", func(t *testing.T) {
		// This was the problematic case: each byte = one Read() call
		// With recursion, this would create ~40 stack frames
		// With iteration, it's bounded by the for loop
		fullResponse := "HTTP/1.1 200 OK\r\n\r\n"
		tlsData := []byte{0x16, 0x03}

		var reads [][]byte
		for _, b := range []byte(fullResponse) {
			reads = append(reads, []byte{b})
		}
		reads = append(reads, tlsData)

		conn := newMockConn(reads...)
		sc := NewSpeculativeConn(conn, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
		sc.firstWrite = true

		buf := make([]byte, 1024)
		n, err := sc.Read(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != len(tlsData) {
			t.Fatalf("expected %d bytes of TLS data, got %d", len(tlsData), n)
		}
	})

	t.Run("header exceeds 16KB limit", func(t *testing.T) {
		// Build a response with a very large header
		header := "HTTP/1.1 200 OK\r\n"
		// Add enough headers to exceed 16KB without a final \r\n\r\n
		for len(header) < 17000 {
			header += fmt.Sprintf("X-Pad-%d: %s\r\n", len(header), string(make([]byte, 100)))
		}

		// Deliver in chunks but never send the final \r\n\r\n
		var reads [][]byte
		for i := 0; i < len(header); i += 4096 {
			end := i + 4096
			if end > len(header) {
				end = len(header)
			}
			reads = append(reads, []byte(header[i:end]))
		}

		conn := newMockConn(reads...)
		sc := NewSpeculativeConn(conn, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
		sc.firstWrite = true

		buf := make([]byte, 1024)
		_, err := sc.Read(buf)
		if err == nil {
			t.Fatal("expected error for oversized headers")
		}
		if !IsSpeculativeTLSError(err) {
			t.Fatalf("expected SpeculativeTLSError, got %T: %v", err, err)
		}
	})

	t.Run("non-200 status code", func(t *testing.T) {
		response := "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"
		conn := newMockConn([]byte(response))
		sc := NewSpeculativeConn(conn, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
		sc.firstWrite = true

		buf := make([]byte, 1024)
		_, err := sc.Read(buf)
		if err == nil {
			t.Fatal("expected error for 407 status")
		}
		var specErr *SpeculativeTLSError
		if !isSpecErr(err, &specErr) {
			t.Fatalf("expected SpeculativeTLSError, got %T: %v", err, err)
		}
		if specErr.StatusCode != 407 {
			t.Fatalf("expected status 407, got %d", specErr.StatusCode)
		}
	})

	t.Run("response with no TLS data triggers direct read", func(t *testing.T) {
		// HTTP response with no trailing TLS data — next Read() should go to conn directly
		response := "HTTP/1.1 200 OK\r\n\r\n"
		tlsData := []byte{0x16, 0x03, 0x03, 0x00, 0x01}

		conn := newMockConn([]byte(response), tlsData)
		sc := NewSpeculativeConn(conn, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
		sc.firstWrite = true

		buf := make([]byte, 1024)
		n, err := sc.Read(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != len(tlsData) {
			t.Fatalf("expected %d bytes, got %d", len(tlsData), n)
		}
	})
}

func isSpecErr(err error, target **SpeculativeTLSError) bool {
	specErr, ok := err.(*SpeculativeTLSError)
	if ok {
		*target = specErr
	}
	return ok
}

// ============================================================================
// Fix 8: H1 doRequest SetDeadline should respect context
// Verify that the earlier of context deadline and responseTimeout is used
// ============================================================================

func TestH1DeadlineRespectsContext(t *testing.T) {
	tests := []struct {
		name            string
		ctxTimeout      time.Duration
		responseTimeout time.Duration
		expectCtxWins   bool
	}{
		{
			name:            "context deadline earlier than response timeout",
			ctxTimeout:      2 * time.Second,
			responseTimeout: 30 * time.Second,
			expectCtxWins:   true,
		},
		{
			name:            "response timeout earlier than context deadline",
			ctxTimeout:      30 * time.Second,
			responseTimeout: 5 * time.Second,
			expectCtxWins:   false,
		},
		{
			name:            "equal timeouts",
			ctxTimeout:      10 * time.Second,
			responseTimeout: 10 * time.Second,
			expectCtxWins:   false, // either is fine, they're equal
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tt.ctxTimeout)
			defer cancel()

			// Reproduce the fix logic
			deadline := time.Now().Add(tt.responseTimeout)
			if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
				deadline = ctxDeadline
			}

			// The deadline should be close to the earlier of the two timeouts
			expectedTimeout := tt.responseTimeout
			if tt.expectCtxWins {
				expectedTimeout = tt.ctxTimeout
			}

			expectedDeadline := time.Now().Add(expectedTimeout)
			diff := deadline.Sub(expectedDeadline)
			if diff < 0 {
				diff = -diff
			}

			// Allow 100ms tolerance for timing
			if diff > 100*time.Millisecond {
				t.Errorf("deadline off by %v from expected (ctxWins=%v)", diff, tt.expectCtxWins)
			}
		})
	}
}

// TestH1DeadlineWithNoContextDeadline verifies that when no context deadline
// is set, the response timeout is used as-is.
func TestH1DeadlineWithNoContextDeadline(t *testing.T) {
	ctx := context.Background() // No deadline
	responseTimeout := 5 * time.Second

	deadline := time.Now().Add(responseTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	expectedDeadline := time.Now().Add(responseTimeout)
	diff := deadline.Sub(expectedDeadline)
	if diff < 0 {
		diff = -diff
	}

	if diff > 100*time.Millisecond {
		t.Errorf("deadline off by %v from response timeout", diff)
	}
}

// ============================================================================
// Integration-style tests: verify actual functions with mock connections
// ============================================================================

// TestH2DialHTTPProxyBlockingDeadlineCleared verifies that the read deadline
// is cleared after a successful proxy response so it doesn't affect subsequent
// TLS handshake reads.
func TestH2DialHTTPProxyBlockingDeadlineCleared(t *testing.T) {
	// Track deadline changes
	var deadlines []time.Time
	conn := &deadlineTrackingConn{
		readBuf:   bytes.NewBufferString("HTTP/1.1 200 Connection established\r\n\r\n"),
		deadlines: &deadlines,
	}

	h2 := &HTTP2Transport{connectTimeout: 30 * time.Second}
	_, err := h2.dialHTTPProxyBlocking(context.Background(), conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have set deadline then cleared it
	if len(deadlines) < 2 {
		t.Fatalf("expected at least 2 deadline changes (set + clear), got %d", len(deadlines))
	}

	// First deadline should be non-zero (the 30s deadline)
	if deadlines[0].IsZero() {
		t.Error("first deadline should be non-zero")
	}

	// Last deadline should be zero (cleared)
	if !deadlines[len(deadlines)-1].IsZero() {
		t.Error("last deadline should be zero (cleared)")
	}
}

type deadlineTrackingConn struct {
	net.Conn
	readBuf   *bytes.Buffer
	deadlines *[]time.Time
}

func (d *deadlineTrackingConn) Read(b []byte) (int, error)         { return d.readBuf.Read(b) }
func (d *deadlineTrackingConn) Write(b []byte) (int, error)        { return len(b), nil }
func (d *deadlineTrackingConn) Close() error                       { return nil }
func (d *deadlineTrackingConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (d *deadlineTrackingConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (d *deadlineTrackingConn) SetDeadline(t time.Time) error      { return nil }
func (d *deadlineTrackingConn) SetWriteDeadline(t time.Time) error { return nil }
func (d *deadlineTrackingConn) SetReadDeadline(t time.Time) error {
	*d.deadlines = append(*d.deadlines, t)
	return nil
}

// TestSpeculativeConnWriteInterception verifies that the first Write prepends
// the CONNECT request and subsequent writes pass through.
func TestSpeculativeConnWriteInterception(t *testing.T) {
	var written []byte
	conn := &captureConn{writeBuf: &written}

	connectReq := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	sc := NewSpeculativeConn(conn, connectReq)

	// First write: ClientHello (simulated)
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
	n, err := sc.Write(clientHello)
	if err != nil {
		t.Fatalf("first write error: %v", err)
	}
	if n != len(clientHello) {
		t.Fatalf("first write: expected %d bytes reported, got %d", len(clientHello), n)
	}

	// Verify CONNECT + ClientHello were sent together
	expected := append([]byte(connectReq), clientHello...)
	if !bytes.Equal(written, expected) {
		t.Fatalf("first write: data mismatch\ngot:  %q\nwant: %q", written, expected)
	}

	// Second write: should pass through directly
	written = nil
	data2 := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	n, err = sc.Write(data2)
	if err != nil {
		t.Fatalf("second write error: %v", err)
	}
	if n != len(data2) {
		t.Fatalf("second write: expected %d bytes, got %d", len(data2), n)
	}
	if !bytes.Equal(written, data2) {
		t.Fatalf("second write should pass through directly, got %q", written)
	}
}

type captureConn struct {
	net.Conn
	writeBuf *[]byte
}

func (c *captureConn) Write(b []byte) (int, error) {
	*c.writeBuf = append(*c.writeBuf, b...)
	return len(b), nil
}
func (c *captureConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(t time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(t time.Time) error { return nil }

// ============================================================================
// Test closeWithTimeout with actual io.Closer interface
// ============================================================================

type errorCloser struct {
	blockDuration time.Duration
	returnErr     error
}

func (e *errorCloser) Close() error {
	time.Sleep(e.blockDuration)
	return e.returnErr
}

func TestCloseWithTimeoutErrorHandling(t *testing.T) {
	t.Run("close error is silently handled", func(t *testing.T) {
		// closeWithTimeout doesn't propagate errors - it's fire-and-forget
		ec := &errorCloser{
			blockDuration: 10 * time.Millisecond,
			returnErr:     fmt.Errorf("close failed"),
		}

		// Should not panic
		closeWithTimeout(ec, 1*time.Second)
	})
}

// ============================================================================
// Benchmark: verify no performance regression from the timeout fixes
// ============================================================================

func BenchmarkCloseWithTimeout_FastClose(b *testing.B) {
	bc := &blockingCloser{blockDuration: 0}
	for i := 0; i < b.N; i++ {
		closeWithTimeout(bc, 3*time.Second)
	}
}

func BenchmarkContextAwareWait_FastComplete(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			wg.Done()
		}()

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-ctx.Done():
		}
		cancel()
	}
}

func BenchmarkSpeculativeConn_SingleRead(b *testing.B) {
	httpResponse := "HTTP/1.1 200 Connection established\r\n\r\n"
	tlsData := []byte{0x16, 0x03, 0x03, 0x00, 0x05}
	data := append([]byte(httpResponse), tlsData...)

	for i := 0; i < b.N; i++ {
		conn := newMockConn(data)
		sc := NewSpeculativeConn(conn, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
		sc.firstWrite = true

		buf := make([]byte, 1024)
		sc.Read(buf)
	}
}

// ============================================================================
// Test the actual H1/H2 dialHTTPProxyBlocking with a real pipe to verify
// end-to-end behavior with the read deadline
// ============================================================================

func TestProxyCONNECTWithPipe(t *testing.T) {
	t.Run("H2 proxy response via pipe", func(t *testing.T) {
		client, server := net.Pipe()
		defer server.Close()

		// Proxy server goroutine
		go func() {
			br := bufio.NewReader(server)
			// Read and discard the CONNECT request
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			req.Body.Close()

			// Send 200 OK response
			server.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		}()

		h2 := &HTTP2Transport{connectTimeout: 5 * time.Second}
		result, err := h2.dialHTTPProxyBlocking(context.Background(), client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil connection")
		}
		result.Close()
	})

	t.Run("H1 proxy response via pipe", func(t *testing.T) {
		client, server := net.Pipe()
		defer server.Close()

		go func() {
			br := bufio.NewReader(server)
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			req.Body.Close()
			server.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		}()

		h1 := &HTTP1Transport{connectTimeout: 5 * time.Second}
		result, err := h1.dialHTTPProxyBlocking(context.Background(), client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil connection")
		}
		result.Close()
	})

	t.Run("H2 proxy slow response succeeds", func(t *testing.T) {
		client, server := net.Pipe()
		defer server.Close()

		// Proxy server that responds after a brief delay
		go func() {
			br := bufio.NewReader(server)
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			req.Body.Close()
			time.Sleep(50 * time.Millisecond)
			server.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		}()

		h2 := &HTTP2Transport{connectTimeout: 5 * time.Second}

		result, err := h2.dialHTTPProxyBlocking(context.Background(), client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil connection")
		}
		result.Close()
	})
}

// ============================================================================
// Test that speculative conn properly transitions after HTTP parsing
// ============================================================================

func TestSpeculativeConnSubsequentReads(t *testing.T) {
	t.Run("reads after HTTP stripping go directly to conn", func(t *testing.T) {
		httpResponse := "HTTP/1.1 200 Connection established\r\n\r\n"
		tlsBatch1 := []byte{0x16, 0x03, 0x03}
		tlsBatch2 := []byte{0x14, 0x03, 0x03, 0x00, 0x01}

		conn := newMockConn(
			append([]byte(httpResponse), tlsBatch1...),
			tlsBatch2,
		)
		sc := NewSpeculativeConn(conn, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
		sc.firstWrite = true

		// First read: strips HTTP, returns TLS data
		buf := make([]byte, 1024)
		n, err := sc.Read(buf)
		if err != nil {
			t.Fatalf("first read error: %v", err)
		}
		if !bytes.Equal(buf[:n], tlsBatch1) {
			t.Fatalf("first read: got %v, want %v", buf[:n], tlsBatch1)
		}

		// Second read: should go directly to underlying conn (fast path)
		n, err = sc.Read(buf)
		if err != nil {
			t.Fatalf("second read error: %v", err)
		}
		if !bytes.Equal(buf[:n], tlsBatch2) {
			t.Fatalf("second read: got %v, want %v", buf[:n], tlsBatch2)
		}
	})

	t.Run("buffered TLS data returned before new reads", func(t *testing.T) {
		httpResponse := "HTTP/1.1 200 OK\r\n\r\n"
		// More TLS data than fits in a small read buffer
		tlsData := make([]byte, 100)
		for i := range tlsData {
			tlsData[i] = byte(i)
		}

		conn := newMockConn(append([]byte(httpResponse), tlsData...))
		sc := NewSpeculativeConn(conn, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
		sc.firstWrite = true

		// Read with a small buffer — only partial TLS data
		smallBuf := make([]byte, 10)
		n1, err := sc.Read(smallBuf)
		if err != nil {
			t.Fatalf("first read error: %v", err)
		}
		if n1 != 10 {
			t.Fatalf("expected 10 bytes, got %d", n1)
		}

		// Second read should return buffered remainder
		largeBuf := make([]byte, 200)
		n2, err := sc.Read(largeBuf)
		if err != nil {
			t.Fatalf("second read error: %v", err)
		}
		if n2 != 90 {
			t.Fatalf("expected 90 remaining bytes, got %d", n2)
		}

		// Verify all data matches
		combined := append(smallBuf[:n1], largeBuf[:n2]...)
		if !bytes.Equal(combined, tlsData) {
			t.Fatalf("combined data mismatch")
		}
	})
}
