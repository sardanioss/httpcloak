package pool

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

func TestProxyHandshakeDeadlineInterruptsStalledRead(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	clearDeadline, err := armProxyHandshakeDeadline(ctx, client, time.Second)
	if err != nil {
		t.Fatalf("armProxyHandshakeDeadline() error = %v", err)
	}
	defer clearDeadline()

	startedAt := time.Now()
	_, err = client.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("Read() unexpectedly succeeded")
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("stalled read exceeded context deadline: %v", elapsed)
	}
	select {
	case <-ctx.Done():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("context deadline did not fire")
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("context error = %v, want DeadlineExceeded", ctx.Err())
	}
}

func TestProxyHandshakeCancellationInterruptsStalledWrite(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	clearDeadline, err := armProxyHandshakeDeadline(ctx, client, time.Second)
	if err != nil {
		t.Fatalf("armProxyHandshakeDeadline() error = %v", err)
	}
	defer clearDeadline()

	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(make([]byte, 1024))
		writeDone <- err
	}()
	cancel()

	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("Write() unexpectedly succeeded")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancelled proxy write did not return")
	}
}

func TestProxyHandshakeClearsDeadlineAfterNegotiation(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clearDeadline, err := armProxyHandshakeDeadline(context.Background(), client, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("armProxyHandshakeDeadline() error = %v", err)
	}
	clearDeadline()
	time.Sleep(30 * time.Millisecond)

	go func() {
		_, _ = server.Write([]byte{1})
	}()
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); err != nil {
		t.Fatalf("Read() after clearing deadline error = %v", err)
	}
}

func TestHTTPProxyHandshakeUsesContextDeadline(t *testing.T) {
	t.Parallel()

	proxy, done := newStalledProxy(t)
	host, port, err := net.SplitHostPort(proxy)
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	pool := &HostPool{
		host:           "example.invalid",
		port:           "443",
		preset:         fingerprint.GetStrict("chrome-150-windows"),
		connectTimeout: time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	startedAt := time.Now()
	_, err = pool.dialHTTPProxy(ctx, &proxyConfig{
		Scheme: "http",
		Host:   host,
		Port:   port,
	})
	if err == nil {
		t.Fatal("dialHTTPProxy() unexpectedly succeeded")
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("HTTP proxy handshake exceeded context deadline: %v", elapsed)
	}
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("HTTP proxy connection remained open after deadline")
	}
}

func TestSOCKS5ProxyHandshakeUsesContextDeadline(t *testing.T) {
	t.Parallel()

	proxy, done := newStalledProxy(t)
	host, port, err := net.SplitHostPort(proxy)
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	pool := &HostPool{
		host:           "example.invalid",
		port:           "443",
		preset:         fingerprint.GetStrict("chrome-150-windows"),
		connectTimeout: time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	startedAt := time.Now()
	_, err = pool.dialSOCKS5Proxy(ctx, &proxyConfig{
		Scheme: "socks5",
		Host:   host,
		Port:   port,
	})
	if err == nil {
		t.Fatal("dialSOCKS5Proxy() unexpectedly succeeded")
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("SOCKS5 proxy handshake exceeded context deadline: %v", elapsed)
	}
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SOCKS5 proxy connection remained open after deadline")
	}
}

func newStalledProxy(t *testing.T) (string, <-chan struct{}) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, connection)
		_ = connection.Close()
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("stalled proxy fixture did not stop")
		}
	})
	return listener.Addr().String(), done
}
