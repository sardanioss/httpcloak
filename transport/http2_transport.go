package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/net/http2"
	utls "github.com/refraction-networking/utls"
)

// HTTP2Transport is a custom HTTP/2 transport with uTLS fingerprinting
// and proper connection reuse
type HTTP2Transport struct {
	preset   *fingerprint.Preset
	dnsCache *dns.Cache
	proxy    *ProxyConfig

	// Connection tracking
	conns   map[string]*persistentConn
	connsMu sync.RWMutex

	// TLS session resumption cache (shared across connections)
	sessionCache utls.ClientSessionCache

	// Configuration
	maxIdleTime    time.Duration
	maxConnAge     time.Duration
	connectTimeout time.Duration

	// Cleanup
	stopCleanup chan struct{}
	closed      bool
}

// persistentConn represents a persistent HTTP/2 connection
type persistentConn struct {
	host            string
	tlsConn         *utls.UConn
	h2Conn          *http2.ClientConn
	createdAt       time.Time
	lastUsedAt      time.Time
	useCount        int64
	sessionResumed  bool // True if TLS session was resumed (faster handshake)
	tlsVersion      uint16
	cipherSuite     uint16
	mu              sync.Mutex
}

// NewHTTP2Transport creates a new HTTP/2 transport with uTLS
func NewHTTP2Transport(preset *fingerprint.Preset, dnsCache *dns.Cache) *HTTP2Transport {
	return NewHTTP2TransportWithProxy(preset, dnsCache, nil)
}

// NewHTTP2TransportWithProxy creates a new HTTP/2 transport with optional proxy support
func NewHTTP2TransportWithProxy(preset *fingerprint.Preset, dnsCache *dns.Cache, proxy *ProxyConfig) *HTTP2Transport {
	t := &HTTP2Transport{
		preset:         preset,
		dnsCache:       dnsCache,
		proxy:          proxy,
		conns:          make(map[string]*persistentConn),
		sessionCache:   utls.NewLRUClientSessionCache(64), // Cache up to 64 sessions for resumption
		maxIdleTime:    90 * time.Second,
		maxConnAge:     5 * time.Minute,
		connectTimeout: 30 * time.Second,
		stopCleanup:    make(chan struct{}),
	}

	// Start background cleanup
	go t.cleanupLoop()

	return t
}

// RoundTrip implements http.RoundTripper
func (t *HTTP2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	key := net.JoinHostPort(host, port)

	// Try to get existing connection
	conn, err := t.getOrCreateConn(req.Context(), host, port, key)
	if err != nil {
		return nil, err
	}

	// Make request
	resp, err := conn.h2Conn.RoundTrip(req)
	if err != nil {
		// Connection might be dead, remove it and retry once
		t.removeConn(key)

		conn, err = t.getOrCreateConn(req.Context(), host, port, key)
		if err != nil {
			return nil, err
		}
		resp, err = conn.h2Conn.RoundTrip(req)
		if err != nil {
			t.removeConn(key)
			return nil, err
		}
	}

	// Update last used time
	conn.mu.Lock()
	conn.lastUsedAt = time.Now()
	conn.useCount++
	conn.mu.Unlock()

	return resp, nil
}

// getOrCreateConn gets an existing connection or creates a new one
func (t *HTTP2Transport) getOrCreateConn(ctx context.Context, host, port, key string) (*persistentConn, error) {
	// Try to get existing connection
	t.connsMu.RLock()
	conn, exists := t.conns[key]
	t.connsMu.RUnlock()

	if exists && t.isConnUsable(conn) {
		return conn, nil
	}

	// Need to create new connection
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	// Double-check after acquiring write lock
	if conn, exists = t.conns[key]; exists && t.isConnUsable(conn) {
		return conn, nil
	}

	// Close old connection if exists
	if exists {
		go conn.close()
	}

	// Create new connection
	newConn, err := t.createConn(ctx, host, port)
	if err != nil {
		return nil, err
	}

	t.conns[key] = newConn
	return newConn, nil
}

// isConnUsable checks if a connection is still usable
// Note: We don't check CanTakeNewRequest() here because it can return false
// even when the connection is fine. We'll handle errors during actual use.
func (t *HTTP2Transport) isConnUsable(conn *persistentConn) bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Check age
	if time.Since(conn.createdAt) > t.maxConnAge {
		return false
	}

	// Check idle time
	if time.Since(conn.lastUsedAt) > t.maxIdleTime {
		return false
	}

	// Just check if connection object exists - we'll handle errors during RoundTrip
	if conn.h2Conn == nil {
		return false
	}

	return true
}

// createConn creates a new persistent connection
func (t *HTTP2Transport) createConn(ctx context.Context, host, port string) (*persistentConn, error) {
	var rawConn net.Conn
	var err error

	targetAddr := net.JoinHostPort(host, port)

	if t.proxy != nil && t.proxy.URL != "" {
		// Connect through proxy
		rawConn, err = t.dialThroughProxy(ctx, host, port)
		if err != nil {
			return nil, fmt.Errorf("proxy connection failed: %w", err)
		}
	} else {
		// Direct connection
		ip, err := t.dnsCache.ResolveOne(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}

		addr := net.JoinHostPort(ip.String(), port)
		dialer := &net.Dialer{
			Timeout:   t.connectTimeout,
			KeepAlive: 30 * time.Second,
		}

		rawConn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("TCP connect failed: %w", err)
		}
	}

	// Set TCP keepalive
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// Wrap with uTLS for fingerprinting
	tlsConfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		ClientSessionCache: t.sessionCache, // Enable TLS session resumption
	}

	tlsConn := utls.UClient(rawConn, tlsConfig, t.preset.ClientHelloID)

	// Set session cache for TLS resumption (faster subsequent connections)
	tlsConn.SetSessionCache(t.sessionCache)

	// Perform TLS handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Verify ALPN negotiated HTTP/2
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return nil, fmt.Errorf("server does not support HTTP/2 (got: %s)", state.NegotiatedProtocol)
	}

	// Wrap TLS connection with HTTP/2 frame interception for Chrome fingerprinting
	wrappedConn := wrapTLSConn(tlsConn, t.preset)

	// Create HTTP/2 client connection with wrapped connection
	h2Transport := &http2.Transport{
		AllowHTTP:                    false,
		DisableCompression:           false,
		StrictMaxConcurrentStreams:   false,
		ReadIdleTimeout:              t.maxIdleTime,
		PingTimeout:                  15 * time.Second,
	}

	h2Conn, err := h2Transport.NewClientConn(wrappedConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("HTTP/2 setup failed: %w", err)
	}

	_ = targetAddr // Used in proxy connection

	// Check if session was resumed (faster TLS handshake)
	connState := tlsConn.ConnectionState()
	sessionResumed := connState.DidResume

	return &persistentConn{
		host:           host,
		tlsConn:        tlsConn,
		h2Conn:         h2Conn,
		createdAt:      time.Now(),
		lastUsedAt:     time.Now(),
		useCount:       0,
		sessionResumed: sessionResumed,
		tlsVersion:     connState.Version,
		cipherSuite:    connState.CipherSuite,
	}, nil
}

// dialThroughProxy establishes a connection through an HTTP proxy using CONNECT
func (t *HTTP2Transport) dialThroughProxy(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	// Parse proxy URL
	proxyURL, err := url.Parse(t.proxy.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	// Determine proxy address
	proxyHost := proxyURL.Hostname()
	proxyPort := proxyURL.Port()
	if proxyPort == "" {
		if proxyURL.Scheme == "https" {
			proxyPort = "443"
		} else {
			proxyPort = "8080"
		}
	}

	// Connect to proxy
	dialer := &net.Dialer{
		Timeout:   t.connectTimeout,
		KeepAlive: 30 * time.Second,
	}

	proxyAddr := net.JoinHostPort(proxyHost, proxyPort)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	// Build CONNECT request
	targetAddr := net.JoinHostPort(targetHost, targetPort)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	// Add proxy authentication if provided
	proxyAuth := t.getProxyAuth(proxyURL)
	if proxyAuth != "" {
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", proxyAuth)
	}

	connectReq += "\r\n"

	// Send CONNECT request
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed with status %d: %s", resp.StatusCode, resp.Status)
	}

	// Connection established - tunnel is now open
	return conn, nil
}

// getProxyAuth returns base64-encoded proxy authentication credentials
func (t *HTTP2Transport) getProxyAuth(proxyURL *url.URL) string {
	// First check struct fields
	username := t.proxy.Username
	password := t.proxy.Password

	// Override with URL credentials if present
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

// removeConn removes a connection from the pool
func (t *HTTP2Transport) removeConn(key string) {
	t.connsMu.Lock()
	conn, exists := t.conns[key]
	if exists {
		delete(t.conns, key)
	}
	t.connsMu.Unlock()

	if exists && conn != nil {
		go conn.close()
	}
}

// close closes the persistent connection
func (c *persistentConn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tlsConn != nil {
		c.tlsConn.Close()
	}
}

// cleanupLoop periodically cleans up stale connections
func (t *HTTP2Transport) cleanupLoop() {
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
func (t *HTTP2Transport) cleanup() {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	for key, conn := range t.conns {
		if !t.isConnUsable(conn) {
			delete(t.conns, key)
			go conn.close()
		}
	}
}

// Close shuts down the transport
func (t *HTTP2Transport) Close() {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.closed {
		return
	}
	t.closed = true

	close(t.stopCleanup)

	for _, conn := range t.conns {
		go conn.close()
	}
	t.conns = nil
}

// Stats returns transport statistics
func (t *HTTP2Transport) Stats() map[string]ConnStats {
	t.connsMu.RLock()
	defer t.connsMu.RUnlock()

	stats := make(map[string]ConnStats)
	for key, conn := range t.conns {
		conn.mu.Lock()
		stats[key] = ConnStats{
			Host:           conn.host,
			CreatedAt:      conn.createdAt,
			LastUsedAt:     conn.lastUsedAt,
			UseCount:       conn.useCount,
			Age:            time.Since(conn.createdAt),
			IdleTime:       time.Since(conn.lastUsedAt),
			IsReused:       conn.useCount > 1,
			SessionResumed: conn.sessionResumed,
			TLSVersion:     conn.tlsVersion,
			CipherSuite:    conn.cipherSuite,
		}
		conn.mu.Unlock()
	}

	return stats
}

// IsConnectionReused checks if the connection for a host will be reused
// Returns true if a usable connection already exists in the pool
func (t *HTTP2Transport) IsConnectionReused(host, port string) bool {
	key := net.JoinHostPort(host, port)
	t.connsMu.RLock()
	conn, exists := t.conns[key]
	t.connsMu.RUnlock()

	if !exists {
		return false
	}
	// If connection exists and is usable, it will be reused
	return t.isConnUsable(conn)
}

// GetConnectionUseCount returns how many times a connection has been used
func (t *HTTP2Transport) GetConnectionUseCount(host, port string) int64 {
	key := net.JoinHostPort(host, port)
	t.connsMu.RLock()
	conn, exists := t.conns[key]
	t.connsMu.RUnlock()

	if !exists {
		return 0
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.useCount
}

// ConnStats contains connection statistics
type ConnStats struct {
	Host           string
	CreatedAt      time.Time
	LastUsedAt     time.Time
	UseCount       int64
	Age            time.Duration
	IdleTime       time.Duration
	IsReused       bool
	SessionResumed bool   // True if TLS session was resumed
	TLSVersion     uint16 // TLS version (e.g., 0x0304 for TLS 1.3)
	CipherSuite    uint16 // Negotiated cipher suite
}

// GetDNSCache returns the DNS cache
func (t *HTTP2Transport) GetDNSCache() *dns.Cache {
	return t.dnsCache
}
