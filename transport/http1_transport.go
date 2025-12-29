package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	utls "github.com/refraction-networking/utls"
)

// HTTP1Transport is a custom HTTP/1.1 transport with uTLS fingerprinting
// and connection pooling with keep-alive support
type HTTP1Transport struct {
	preset   *fingerprint.Preset
	dnsCache *dns.Cache
	proxy    *ProxyConfig

	// Connection pool
	idleConns   map[string][]*http1Conn
	idleConnsMu sync.Mutex

	// TLS session cache for resumption
	sessionCache utls.ClientSessionCache

	// Configuration
	maxIdleConnsPerHost int
	maxIdleTime         time.Duration
	connectTimeout      time.Duration
	responseTimeout     time.Duration
	insecureSkipVerify  bool

	// Cleanup
	stopCleanup chan struct{}
	closed      bool
	closedMu    sync.RWMutex
}

// http1Conn represents a persistent HTTP/1.1 connection
type http1Conn struct {
	host       string
	port       string
	conn       net.Conn
	tlsConn    *utls.UConn
	br         *bufio.Reader
	bw         *bufio.Writer
	createdAt  time.Time
	lastUsedAt time.Time
	useCount   int64
	mu         sync.Mutex
	closed     bool
}

// NewHTTP1Transport creates a new HTTP/1.1 transport with uTLS
func NewHTTP1Transport(preset *fingerprint.Preset, dnsCache *dns.Cache) *HTTP1Transport {
	return NewHTTP1TransportWithProxy(preset, dnsCache, nil)
}

// NewHTTP1TransportWithProxy creates a new HTTP/1.1 transport with optional proxy
func NewHTTP1TransportWithProxy(preset *fingerprint.Preset, dnsCache *dns.Cache, proxy *ProxyConfig) *HTTP1Transport {
	t := &HTTP1Transport{
		preset:              preset,
		dnsCache:            dnsCache,
		proxy:               proxy,
		idleConns:           make(map[string][]*http1Conn),
		sessionCache:        utls.NewLRUClientSessionCache(64),
		maxIdleConnsPerHost: 6, // Browser-like limit
		maxIdleTime:         90 * time.Second,
		connectTimeout:      30 * time.Second,
		responseTimeout:     60 * time.Second,
		stopCleanup:         make(chan struct{}),
	}

	go t.cleanupLoop()

	return t
}

// SetInsecureSkipVerify sets whether to skip TLS verification
func (t *HTTP1Transport) SetInsecureSkipVerify(skip bool) {
	t.insecureSkipVerify = skip
}

// RoundTrip implements http.RoundTripper
func (t *HTTP1Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		return nil, &TransportError{
			Op:       "roundtrip",
			Host:     req.URL.Hostname(),
			Protocol: "h1",
			Cause:    ErrClosed,
			Category: ErrClosed,
		}
	}
	t.closedMu.RUnlock()

	host := req.URL.Hostname()
	port := req.URL.Port()
	scheme := req.URL.Scheme

	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	key := fmt.Sprintf("%s://%s:%s", scheme, host, port)

	// Try to get an idle connection
	conn, err := t.getIdleConn(key)
	if err == nil && conn != nil {
		resp, err := t.doRequest(conn, req)
		if err == nil {
			t.putIdleConn(key, conn)
			return resp, nil
		}
		// Connection failed, close it and try new one
		conn.close()
	}

	// Create new connection
	conn, err = t.createConn(req.Context(), host, port, scheme)
	if err != nil {
		return nil, err
	}

	resp, err := t.doRequest(conn, req)
	if err != nil {
		conn.close()
		return nil, WrapError("request", host, port, "h1", err)
	}

	// Check if connection should be kept alive
	if t.shouldKeepAlive(req, resp) {
		t.putIdleConn(key, conn)
	} else {
		conn.close()
	}

	return resp, nil
}

// createConn creates a new HTTP/1.1 connection
func (t *HTTP1Transport) createConn(ctx context.Context, host, port, scheme string) (*http1Conn, error) {
	var rawConn net.Conn
	var err error

	targetAddr := net.JoinHostPort(host, port)

	if t.proxy != nil && t.proxy.URL != "" {
		rawConn, err = t.dialThroughProxy(ctx, host, port)
		if err != nil {
			return nil, NewProxyError("dial_proxy", host, port, err)
		}
	} else {
		// Direct connection with DNS resolution
		ip, err := t.dnsCache.ResolveOne(ctx, host)
		if err != nil {
			return nil, NewDNSError(host, err)
		}

		addr := net.JoinHostPort(ip.String(), port)
		dialer := &net.Dialer{
			Timeout:   t.connectTimeout,
			KeepAlive: 30 * time.Second,
		}

		rawConn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, NewConnectionError("dial", host, port, "h1", err)
		}
	}

	// Set TCP options
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
	}

	conn := &http1Conn{
		host:       host,
		port:       port,
		conn:       rawConn,
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
	}

	// For HTTPS, wrap with uTLS
	if scheme == "https" {
		tlsConfig := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: t.insecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			ClientSessionCache: t.sessionCache,
			// Force HTTP/1.1 by not including h2 in ALPN
			NextProtos: []string{"http/1.1"},
		}

		// Use HTTP/1.1 specific ClientHelloID if available, otherwise use preset
		clientHelloID := t.getHTTP1ClientHelloID()

		tlsConn := utls.UClient(rawConn, tlsConfig, clientHelloID)
		tlsConn.SetSessionCache(t.sessionCache)

		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, NewTLSError("tls_handshake", host, port, "h1", err)
		}

		conn.tlsConn = tlsConn
		conn.conn = tlsConn
	}

	conn.br = bufio.NewReaderSize(conn.conn, 4096)
	conn.bw = bufio.NewWriterSize(conn.conn, 4096)

	_ = targetAddr // suppress unused warning

	return conn, nil
}

// getHTTP1ClientHelloID returns an appropriate ClientHelloID for HTTP/1.1
// We modify the preset's ClientHelloID to not include h2 in ALPN
func (t *HTTP1Transport) getHTTP1ClientHelloID() utls.ClientHelloID {
	// Use the same TLS fingerprint but ensure we don't negotiate h2
	return t.preset.ClientHelloID
}

// dialThroughProxy establishes a connection through an HTTP proxy
func (t *HTTP1Transport) dialThroughProxy(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	proxyURL, err := url.Parse(t.proxy.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	proxyHost := proxyURL.Hostname()
	proxyPort := proxyURL.Port()
	if proxyPort == "" {
		if proxyURL.Scheme == "https" {
			proxyPort = "443"
		} else {
			proxyPort = "8080"
		}
	}

	dialer := &net.Dialer{
		Timeout:   t.connectTimeout,
		KeepAlive: 30 * time.Second,
	}

	proxyAddr := net.JoinHostPort(proxyHost, proxyPort)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	// Send CONNECT request
	targetAddr := net.JoinHostPort(targetHost, targetPort)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	// Add proxy authentication if needed
	proxyAuth := t.getProxyAuth(proxyURL)
	if proxyAuth != "" {
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", proxyAuth)
	}

	connectReq += "Connection: keep-alive\r\n\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT: %w", err)
	}

	// Read response
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	return conn, nil
}

// getProxyAuth returns base64-encoded proxy credentials
func (t *HTTP1Transport) getProxyAuth(proxyURL *url.URL) string {
	username := t.proxy.Username
	password := t.proxy.Password

	if proxyURL.User != nil {
		if u := proxyURL.User.Username(); u != "" {
			username = u
		}
		if p, ok := proxyURL.User.Password(); ok {
			password = p
		}
	}

	if username == "" {
		return ""
	}

	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// doRequest performs the HTTP request on the connection
func (t *HTTP1Transport) doRequest(conn *http1Conn, req *http.Request) (*http.Response, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.closed {
		return nil, fmt.Errorf("connection closed")
	}

	conn.lastUsedAt = time.Now()
	conn.useCount++

	// Set deadline
	deadline := time.Now().Add(t.responseTimeout)
	conn.conn.SetDeadline(deadline)
	defer conn.conn.SetDeadline(time.Time{})

	// Write request
	if err := t.writeRequest(conn, req); err != nil {
		return nil, err
	}

	// Read response
	resp, err := http.ReadResponse(conn.br, req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// writeRequest writes an HTTP/1.1 request with browser-like header ordering
func (t *HTTP1Transport) writeRequest(conn *http1Conn, req *http.Request) error {
	// Request line
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	fmt.Fprintf(conn.bw, "%s %s HTTP/1.1\r\n", req.Method, uri)

	// Host header first (browser behavior)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	fmt.Fprintf(conn.bw, "Host: %s\r\n", host)

	// Write headers in browser-like order
	t.writeHeadersInOrder(conn.bw, req)

	// End headers
	conn.bw.WriteString("\r\n")

	// Flush headers
	if err := conn.bw.Flush(); err != nil {
		return err
	}

	// Write body if present
	if req.Body != nil {
		_, err := io.Copy(conn.bw, req.Body)
		if err != nil {
			return err
		}
		conn.bw.Flush()
	}

	return nil
}

// writeHeadersInOrder writes headers in a browser-like order
func (t *HTTP1Transport) writeHeadersInOrder(w *bufio.Writer, req *http.Request) {
	// Browser-like header order for HTTP/1.1
	headerOrder := []string{
		"Connection",
		"Cache-Control",
		"Upgrade-Insecure-Requests",
		"User-Agent",
		"Accept",
		"Accept-Encoding",
		"Accept-Language",
		"Cookie",
		"Referer",
		"Origin",
		"Sec-Fetch-Dest",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Site",
		"Sec-Fetch-User",
		"Content-Type",
		"Content-Length",
	}

	written := make(map[string]bool)

	// Write headers in preferred order
	for _, key := range headerOrder {
		// Special handling for Content-Length - also check req.ContentLength
		if key == "Content-Length" {
			// First check if header is set
			if values, ok := req.Header[key]; ok {
				for _, v := range values {
					fmt.Fprintf(w, "%s: %s\r\n", key, v)
				}
				written[key] = true
			} else if req.ContentLength > 0 {
				// Fallback to ContentLength field
				fmt.Fprintf(w, "Content-Length: %d\r\n", req.ContentLength)
				written[key] = true
			} else if req.ContentLength == 0 && req.Body != nil {
				// Empty body but Body is set (POST/PUT/PATCH with empty body)
				fmt.Fprintf(w, "Content-Length: 0\r\n")
				written[key] = true
			}
			continue
		}

		if values, ok := req.Header[key]; ok {
			for _, v := range values {
				fmt.Fprintf(w, "%s: %s\r\n", key, v)
			}
			written[key] = true
		}
		// Also check lowercase
		if values, ok := req.Header[strings.ToLower(key)]; ok && !written[key] {
			for _, v := range values {
				fmt.Fprintf(w, "%s: %s\r\n", key, v)
			}
			written[strings.ToLower(key)] = true
		}
	}

	// Write remaining headers
	for key, values := range req.Header {
		if written[key] || written[strings.ToLower(key)] {
			continue
		}
		// Skip Host (already written) and certain headers
		if strings.EqualFold(key, "Host") {
			continue
		}
		for _, v := range values {
			fmt.Fprintf(w, "%s: %s\r\n", key, v)
		}
	}

	// Ensure Connection header
	if _, ok := req.Header["Connection"]; !ok {
		fmt.Fprintf(w, "Connection: keep-alive\r\n")
	}
}

// shouldKeepAlive determines if connection should be reused
func (t *HTTP1Transport) shouldKeepAlive(req *http.Request, resp *http.Response) bool {
	// Check response Connection header
	if resp.Header.Get("Connection") == "close" {
		return false
	}

	// Check request Connection header
	if req.Header.Get("Connection") == "close" {
		return false
	}

	// HTTP/1.1 defaults to keep-alive
	if resp.ProtoMajor == 1 && resp.ProtoMinor >= 1 {
		return true
	}

	// HTTP/1.0 with explicit keep-alive
	if strings.ToLower(resp.Header.Get("Connection")) == "keep-alive" {
		return true
	}

	return false
}

// getIdleConn retrieves an idle connection from the pool
func (t *HTTP1Transport) getIdleConn(key string) (*http1Conn, error) {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	conns := t.idleConns[key]
	if len(conns) == 0 {
		return nil, nil
	}

	// Get the most recently used connection
	conn := conns[len(conns)-1]
	t.idleConns[key] = conns[:len(conns)-1]

	// Check if connection is still valid
	if time.Since(conn.lastUsedAt) > t.maxIdleTime {
		conn.close()
		return nil, nil
	}

	return conn, nil
}

// putIdleConn returns a connection to the pool
func (t *HTTP1Transport) putIdleConn(key string, conn *http1Conn) {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		conn.close()
		return
	}
	t.closedMu.RUnlock()

	conns := t.idleConns[key]
	if len(conns) >= t.maxIdleConnsPerHost {
		// Pool is full, close oldest connection
		oldConn := conns[0]
		conns = conns[1:]
		go oldConn.close()
	}

	conn.lastUsedAt = time.Now()
	t.idleConns[key] = append(conns, conn)
}

// close closes an http1Conn
func (c *http1Conn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	c.closed = true

	if c.tlsConn != nil {
		c.tlsConn.Close()
	} else if c.conn != nil {
		c.conn.Close()
	}
}

// cleanupLoop periodically removes stale connections
func (t *HTTP1Transport) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCleanup:
			return
		case <-ticker.C:
			t.cleanup()
		}
	}
}

// cleanup removes stale connections
func (t *HTTP1Transport) cleanup() {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	for key, conns := range t.idleConns {
		var active []*http1Conn
		for _, conn := range conns {
			if time.Since(conn.lastUsedAt) > t.maxIdleTime {
				go conn.close()
			} else {
				active = append(active, conn)
			}
		}
		if len(active) > 0 {
			t.idleConns[key] = active
		} else {
			delete(t.idleConns, key)
		}
	}
}

// Close shuts down the transport
func (t *HTTP1Transport) Close() {
	t.closedMu.Lock()
	if t.closed {
		t.closedMu.Unlock()
		return
	}
	t.closed = true
	t.closedMu.Unlock()

	close(t.stopCleanup)

	t.idleConnsMu.Lock()
	for _, conns := range t.idleConns {
		for _, conn := range conns {
			go conn.close()
		}
	}
	t.idleConns = nil
	t.idleConnsMu.Unlock()
}

// Stats returns transport statistics
func (t *HTTP1Transport) Stats() map[string]HTTP1ConnStats {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	stats := make(map[string]HTTP1ConnStats)
	for key, conns := range t.idleConns {
		var totalUseCount int64
		var oldestCreated time.Time
		var newestUsed time.Time

		for _, conn := range conns {
			conn.mu.Lock()
			totalUseCount += conn.useCount
			if oldestCreated.IsZero() || conn.createdAt.Before(oldestCreated) {
				oldestCreated = conn.createdAt
			}
			if conn.lastUsedAt.After(newestUsed) {
				newestUsed = conn.lastUsedAt
			}
			conn.mu.Unlock()
		}

		stats[key] = HTTP1ConnStats{
			IdleConns:      len(conns),
			TotalUseCount:  totalUseCount,
			OldestCreated:  oldestCreated,
			NewestLastUsed: newestUsed,
		}
	}

	return stats
}

// HTTP1ConnStats contains HTTP/1.1 connection statistics
type HTTP1ConnStats struct {
	IdleConns      int
	TotalUseCount  int64
	OldestCreated  time.Time
	NewestLastUsed time.Time
}

// GetDNSCache returns the DNS cache
func (t *HTTP1Transport) GetDNSCache() *dns.Cache {
	return t.dnsCache
}
