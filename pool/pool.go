package pool

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
	utls "github.com/refraction-networking/utls"
)

var (
	ErrPoolClosed    = errors.New("connection pool is closed")
	ErrNoConnections = errors.New("no available connections")
)

// Conn represents a persistent connection
type Conn struct {
	Host       string
	RemoteAddr net.Addr
	TLSConn    *utls.UConn
	HTTP2Conn  *http2.ClientConn
	CreatedAt  time.Time
	LastUsedAt time.Time
	UseCount   int64
	mu         sync.Mutex
	closed     bool
}

// IsHealthy checks if the connection is still usable
func (c *Conn) IsHealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return false
	}

	// Check if HTTP/2 connection is usable
	if c.HTTP2Conn != nil {
		return c.HTTP2Conn.CanTakeNewRequest()
	}

	return false
}

// Age returns how long the connection has been open
func (c *Conn) Age() time.Duration {
	return time.Since(c.CreatedAt)
}

// IdleTime returns how long since the connection was last used
func (c *Conn) IdleTime() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.LastUsedAt)
}

// MarkUsed updates the last used timestamp
func (c *Conn) MarkUsed() {
	c.mu.Lock()
	c.LastUsedAt = time.Now()
	c.UseCount++
	c.mu.Unlock()
}

// Close closes the connection
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	var errs []error
	if c.HTTP2Conn != nil {
		// HTTP/2 connection close is handled by the underlying TLS conn
	}
	if c.TLSConn != nil {
		if err := c.TLSConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// HostPool manages connections to a single host
type HostPool struct {
	host        string
	port        string
	preset      *fingerprint.Preset
	dnsCache    *dns.Cache
	connections []*Conn
	mu          sync.Mutex

	// TLS session cache for PSK/session resumption
	// Chrome reuses sessions - this makes subsequent connections look like real browser
	sessionCache utls.ClientSessionCache

	// Configuration
	maxConns           int
	maxIdleTime        time.Duration
	maxConnAge         time.Duration
	connectTimeout     time.Duration
	insecureSkipVerify bool
	proxyURL           string
}

// NewHostPool creates a new pool for a specific host
func NewHostPool(host, port string, preset *fingerprint.Preset, dnsCache *dns.Cache) *HostPool {
	return NewHostPoolWithConfig(host, port, preset, dnsCache, false, "")
}

// NewHostPoolWithConfig creates a pool with TLS and proxy configuration
func NewHostPoolWithConfig(host, port string, preset *fingerprint.Preset, dnsCache *dns.Cache, insecureSkipVerify bool, proxyURL string) *HostPool {
	return &HostPool{
		host:               host,
		port:               port,
		preset:             preset,
		dnsCache:           dnsCache,
		connections:        make([]*Conn, 0),
		sessionCache:       utls.NewLRUClientSessionCache(32), // Cache up to 32 sessions per host
		maxConns:           0,                                 // 0 = unlimited connections
		maxIdleTime:        90 * time.Second,
		maxConnAge:         5 * time.Minute,
		connectTimeout:     30 * time.Second,
		insecureSkipVerify: insecureSkipVerify,
		proxyURL:           proxyURL,
	}
}

// SetMaxConns sets the maximum connections for this pool (0 = unlimited)
func (p *HostPool) SetMaxConns(max int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxConns = max
}

// GetConn returns an available connection or creates a new one
func (p *HostPool) GetConn(ctx context.Context) (*Conn, error) {
	p.mu.Lock()

	// First, try to find an existing healthy connection
	for i, conn := range p.connections {
		if conn.IsHealthy() && conn.IdleTime() < p.maxIdleTime && conn.Age() < p.maxConnAge {
			// Move to end (LRU)
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			p.connections = append(p.connections, conn)
			p.mu.Unlock()
			conn.MarkUsed()
			return conn, nil
		}
	}

	// Clean up unhealthy connections
	healthy := make([]*Conn, 0, len(p.connections))
	for _, conn := range p.connections {
		if conn.IsHealthy() && conn.Age() < p.maxConnAge {
			healthy = append(healthy, conn)
		} else {
			go conn.Close()
		}
	}
	p.connections = healthy

	// Check if we can create a new connection (0 = unlimited)
	if p.maxConns > 0 && len(p.connections) >= p.maxConns {
		p.mu.Unlock()
		return nil, ErrNoConnections
	}

	p.mu.Unlock()

	// Create new connection (outside lock to avoid blocking)
	conn, err := p.createConn(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.connections = append(p.connections, conn)
	p.mu.Unlock()

	return conn, nil
}

// createConn creates a new connection to the host
// Implements Happy Eyeballs (RFC 8305) for IPv6/IPv4 connection racing
func (p *HostPool) createConn(ctx context.Context) (*Conn, error) {
	var rawConn net.Conn
	var err error

	if p.proxyURL != "" {
		// Connect through proxy
		rawConn, err = p.dialThroughProxy(ctx)
		if err != nil {
			return nil, fmt.Errorf("proxy connect failed: %w", err)
		}
	} else {
		// Direct connection - resolve DNS and use Happy Eyeballs
		ips, err := p.dnsCache.ResolveAllSorted(ctx, p.host)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}

		// Use Happy Eyeballs to establish connection
		rawConn, err = p.dialHappyEyeballs(ctx, ips)
		if err != nil {
			return nil, fmt.Errorf("TCP connect failed: %w", err)
		}
	}

	// Wrap with uTLS for fingerprinting
	// Enable session tickets for PSK resumption (Chrome does this)
	tlsConfig := &utls.Config{
		ServerName:             p.host,
		InsecureSkipVerify:     p.insecureSkipVerify,
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: false,          // Enable session tickets
		ClientSessionCache:     p.sessionCache, // Use per-host session cache
	}

	tlsConn := utls.UClient(rawConn, tlsConfig, p.preset.ClientHelloID)

	// Set session cache on the connection for PSK/resumption
	// This enables pre_shared_key extension on subsequent connections
	tlsConn.SetSessionCache(p.sessionCache)

	// Perform TLS handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Wrap TLS connection with HTTP/2 frame interception for Chrome fingerprinting
	wrappedConn := wrapTLSConn(tlsConn, p.preset)

	// Create HTTP/2 connection with Chrome-like settings
	h2Transport := &http2.Transport{
		AllowHTTP:                  false,
		DisableCompression:         false,
		StrictMaxConcurrentStreams: false,
		MaxHeaderListSize:          p.preset.HTTP2Settings.MaxHeaderListSize,
		MaxReadFrameSize:           p.preset.HTTP2Settings.MaxFrameSize,
		MaxDecoderHeaderTableSize:  p.preset.HTTP2Settings.HeaderTableSize,
		MaxEncoderHeaderTableSize:  p.preset.HTTP2Settings.HeaderTableSize,
	}

	h2Conn, err := h2Transport.NewClientConn(wrappedConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("HTTP/2 setup failed: %w", err)
	}

	conn := &Conn{
		Host:       p.host,
		RemoteAddr: rawConn.RemoteAddr(),
		TLSConn:    tlsConn,
		HTTP2Conn:  h2Conn,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
		UseCount:   0,
	}

	return conn, nil
}

// dialIPv6First tries IPv6 addresses first, falls back to IPv4 only if all IPv6 fail
// This matches modern browser behavior where IPv6 is strongly preferred
func (p *HostPool) dialHappyEyeballs(ctx context.Context, ips []net.IP) (net.Conn, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses available")
	}

	// Separate IPv6 and IPv4 from the provided IPs (already resolved, no second lookup)
	var ipv6, ipv4 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip)
		} else {
			ipv6 = append(ipv6, ip)
		}
	}

	dialer := &net.Dialer{Timeout: p.connectTimeout}

	// Try all IPv6 addresses first
	for _, ip := range ipv6 {
		addr := net.JoinHostPort(ip.String(), p.port)
		conn, err := dialer.DialContext(ctx, "tcp6", addr)
		if err == nil {
			return conn, nil
		}
	}

	// If no IPv6 worked, try IPv4 addresses
	var lastErr error
	for _, ip := range ipv4 {
		addr := net.JoinHostPort(ip.String(), p.port)
		conn, err := dialer.DialContext(ctx, "tcp4", addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no IP addresses available for connection")
}

// dialThroughProxy connects to the target host through a proxy
// Supports HTTP/HTTPS (CONNECT) and SOCKS5 proxies
func (p *HostPool) dialThroughProxy(ctx context.Context) (net.Conn, error) {
	proxyURL, err := parseProxyURL(p.proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	switch proxyURL.Scheme {
	case "http", "https":
		return p.dialHTTPProxy(ctx, proxyURL)
	case "socks5", "socks5h":
		return p.dialSOCKS5Proxy(ctx, proxyURL)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", proxyURL.Scheme)
	}
}

// parseProxyURL parses the proxy URL
func parseProxyURL(proxyURL string) (*proxyConfig, error) {
	// Simple parser for proxy URLs
	// Format: scheme://[user:pass@]host:port
	if !hasScheme(proxyURL) {
		proxyURL = "http://" + proxyURL
	}

	scheme := "http"
	rest := proxyURL

	if idx := indexOf(proxyURL, "://"); idx != -1 {
		scheme = proxyURL[:idx]
		rest = proxyURL[idx+3:]
	}

	var username, password string
	if idx := indexOf(rest, "@"); idx != -1 {
		userInfo := rest[:idx]
		rest = rest[idx+1:]
		if pwIdx := indexOf(userInfo, ":"); pwIdx != -1 {
			username = userInfo[:pwIdx]
			password = userInfo[pwIdx+1:]
		} else {
			username = userInfo
		}
	}

	host := rest
	port := ""
	if idx := lastIndexOf(rest, ":"); idx != -1 {
		host = rest[:idx]
		port = rest[idx+1:]
	}

	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		}
	}

	return &proxyConfig{
		Scheme:   scheme,
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
	}, nil
}

// proxyConfig holds parsed proxy configuration
type proxyConfig struct {
	Scheme   string
	Host     string
	Port     string
	Username string
	Password string
}

// Addr returns the proxy address as host:port
func (p *proxyConfig) Addr() string {
	return net.JoinHostPort(p.Host, p.Port)
}

// hasScheme checks if URL has a scheme
func hasScheme(url string) bool {
	return indexOf(url, "://") != -1
}

// indexOf returns index of substr in s, or -1 if not found
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// lastIndexOf returns last index of substr in s, or -1 if not found
func lastIndexOf(s, substr string) int {
	for i := len(s) - len(substr); i >= 0; i-- {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// dialHTTPProxy establishes a connection through an HTTP CONNECT proxy
func (p *HostPool) dialHTTPProxy(ctx context.Context, proxy *proxyConfig) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: p.connectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxy.Addr())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	// Send CONNECT request
	targetAddr := net.JoinHostPort(p.host, p.port)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	// Add proxy authentication if provided
	if proxy.Username != "" {
		auth := proxy.Username + ":" + proxy.Password
		encoded := base64Encode([]byte(auth))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encoded)
	}

	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}

	response := string(buf[:n])
	if !isHTTP200(response) {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", getFirstLine(response))
	}

	return conn, nil
}

// dialSOCKS5Proxy establishes a connection through a SOCKS5 proxy
func (p *HostPool) dialSOCKS5Proxy(ctx context.Context, proxy *proxyConfig) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: p.connectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxy.Addr())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
	}

	// SOCKS5 handshake
	// Version 5, 1 auth method (no auth or username/password)
	var authMethods []byte
	if proxy.Username != "" {
		authMethods = []byte{0x05, 0x02, 0x00, 0x02} // No auth and username/password
	} else {
		authMethods = []byte{0x05, 0x01, 0x00} // No auth only
	}

	if _, err := conn.Write(authMethods); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
	}

	// Read server's chosen auth method
	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 auth response failed: %w", err)
	}

	if resp[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: invalid version: %d", resp[0])
	}

	// Handle authentication
	switch resp[1] {
	case 0x00:
		// No authentication required
	case 0x02:
		// Username/password authentication
		if err := p.socks5Auth(conn, proxy); err != nil {
			conn.Close()
			return nil, err
		}
	case 0xFF:
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: no acceptable auth methods")
	default:
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: unsupported auth method: %d", resp[1])
	}

	// Send CONNECT request
	// Version 5, CMD connect (1), reserved (0), address type
	targetPort, _ := parsePort(p.port)
	var connectReq []byte

	// Try to parse as IP address first
	if ip := net.ParseIP(p.host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			connectReq = append([]byte{0x05, 0x01, 0x00, 0x01}, ip4...)
		} else {
			// IPv6
			connectReq = append([]byte{0x05, 0x01, 0x00, 0x04}, ip...)
		}
	} else {
		// Domain name
		connectReq = []byte{0x05, 0x01, 0x00, 0x03, byte(len(p.host))}
		connectReq = append(connectReq, []byte(p.host)...)
	}

	// Append port (big endian)
	connectReq = append(connectReq, byte(targetPort>>8), byte(targetPort))

	if _, err := conn.Write(connectReq); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect request failed: %w", err)
	}

	// Read connect response (minimum 10 bytes for IPv4)
	respBuf := make([]byte, 10)
	if _, err := conn.Read(respBuf); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect response failed: %w", err)
	}

	if respBuf[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: invalid version in response")
	}

	if respBuf[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed with code: %d", respBuf[1])
	}

	return conn, nil
}

// socks5Auth performs SOCKS5 username/password authentication
func (p *HostPool) socks5Auth(conn net.Conn, proxy *proxyConfig) error {
	// Version 1, username length, username, password length, password
	authReq := []byte{0x01, byte(len(proxy.Username))}
	authReq = append(authReq, []byte(proxy.Username)...)
	authReq = append(authReq, byte(len(proxy.Password)))
	authReq = append(authReq, []byte(proxy.Password)...)

	if _, err := conn.Write(authReq); err != nil {
		return fmt.Errorf("SOCKS5 auth request failed: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return fmt.Errorf("SOCKS5 auth response failed: %w", err)
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 authentication failed")
	}

	return nil
}

// parsePort parses port string to int
func parsePort(port string) (int, error) {
	var p int
	for _, c := range port {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port: %s", port)
		}
		p = p*10 + int(c-'0')
	}
	return p, nil
}

// base64Encode encodes data as base64
func base64Encode(data []byte) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, ((len(data)+2)/3)*4)

	for i := 0; i < len(data); i += 3 {
		var b uint32
		remaining := len(data) - i
		if remaining >= 3 {
			b = uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
			result = append(result, base64Chars[b>>18], base64Chars[(b>>12)&0x3F], base64Chars[(b>>6)&0x3F], base64Chars[b&0x3F])
		} else if remaining == 2 {
			b = uint32(data[i])<<16 | uint32(data[i+1])<<8
			result = append(result, base64Chars[b>>18], base64Chars[(b>>12)&0x3F], base64Chars[(b>>6)&0x3F], '=')
		} else {
			b = uint32(data[i]) << 16
			result = append(result, base64Chars[b>>18], base64Chars[(b>>12)&0x3F], '=', '=')
		}
	}

	return string(result)
}

// isHTTP200 checks if response starts with HTTP/1.x 200
func isHTTP200(response string) bool {
	return len(response) >= 12 && response[9] == '2' && response[10] == '0' && response[11] == '0'
}

// getFirstLine returns the first line of a string
func getFirstLine(s string) string {
	for i, c := range s {
		if c == '\r' || c == '\n' {
			return s[:i]
		}
	}
	return s
}

// CloseIdle closes connections that have been idle too long
func (p *HostPool) CloseIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()

	active := make([]*Conn, 0, len(p.connections))
	for _, conn := range p.connections {
		if conn.IdleTime() > p.maxIdleTime || conn.Age() > p.maxConnAge || !conn.IsHealthy() {
			go conn.Close()
		} else {
			active = append(active, conn)
		}
	}
	p.connections = active
}

// Close closes all connections in the pool
func (p *HostPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		go conn.Close()
	}
	p.connections = nil
}

// Stats returns pool statistics
func (p *HostPool) Stats() (total int, healthy int, totalRequests int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		total++
		if conn.IsHealthy() {
			healthy++
		}
		totalRequests += conn.UseCount
	}
	return
}

// Manager manages connection pools for multiple hosts
type Manager struct {
	pools    map[string]*HostPool
	mu       sync.RWMutex
	dnsCache *dns.Cache
	preset   *fingerprint.Preset
	closed   bool

	// Configuration
	maxConnsPerHost    int    // 0 = unlimited
	proxyURL           string // Proxy URL (optional)
	insecureSkipVerify bool   // Skip TLS verification

	// Background cleanup
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// NewManager creates a new connection pool manager
func NewManager(preset *fingerprint.Preset) *Manager {
	return NewManagerWithTLSConfig(preset, false)
}

// NewManagerWithTLSConfig creates a manager with TLS configuration
func NewManagerWithTLSConfig(preset *fingerprint.Preset, insecureSkipVerify bool) *Manager {
	m := &Manager{
		pools:              make(map[string]*HostPool),
		dnsCache:           dns.NewCache(),
		preset:             preset,
		maxConnsPerHost:    0, // 0 = unlimited by default
		insecureSkipVerify: insecureSkipVerify,
		cleanupInterval:    30 * time.Second,
		stopCleanup:        make(chan struct{}),
	}

	// Start background cleanup
	go m.cleanupLoop()

	return m
}

// NewManagerWithProxy creates a manager with proxy support
func NewManagerWithProxy(preset *fingerprint.Preset, proxyURL string, insecureSkipVerify bool) *Manager {
	m := &Manager{
		pools:              make(map[string]*HostPool),
		dnsCache:           dns.NewCache(),
		preset:             preset,
		maxConnsPerHost:    0, // 0 = unlimited by default
		proxyURL:           proxyURL,
		insecureSkipVerify: insecureSkipVerify,
		cleanupInterval:    30 * time.Second,
		stopCleanup:        make(chan struct{}),
	}

	// Start background cleanup
	go m.cleanupLoop()

	return m
}

// SetMaxConnsPerHost sets the max connections per host for new pools (0 = unlimited)
func (m *Manager) SetMaxConnsPerHost(max int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxConnsPerHost = max
}

// GetPool returns a pool for the given host, creating one if needed
func (m *Manager) GetPool(host, port string) (*HostPool, error) {
	if port == "" {
		port = "443"
	}
	key := net.JoinHostPort(host, port)

	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrPoolClosed
	}
	pool, exists := m.pools[key]
	m.mu.RUnlock()

	if exists {
		return pool, nil
	}

	// Create new pool
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrPoolClosed
	}

	// Double-check after acquiring write lock
	if pool, exists = m.pools[key]; exists {
		return pool, nil
	}

	pool = NewHostPoolWithConfig(host, port, m.preset, m.dnsCache, m.insecureSkipVerify, m.proxyURL)
	if m.maxConnsPerHost > 0 {
		pool.SetMaxConns(m.maxConnsPerHost)
	}
	m.pools[key] = pool
	return pool, nil
}

// GetConn gets a connection to the specified host
func (m *Manager) GetConn(ctx context.Context, host, port string) (*Conn, error) {
	pool, err := m.GetPool(host, port)
	if err != nil {
		return nil, err
	}
	return pool.GetConn(ctx)
}

// SetPreset changes the fingerprint preset for new connections
func (m *Manager) SetPreset(preset *fingerprint.Preset) {
	m.mu.Lock()
	m.preset = preset
	m.mu.Unlock()
}

// GetDNSCache returns the DNS cache
func (m *Manager) GetDNSCache() *dns.Cache {
	return m.dnsCache
}

// cleanupLoop periodically cleans up idle connections
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCleanup:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

// cleanup removes idle connections and empty pools
func (m *Manager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, pool := range m.pools {
		pool.CloseIdle()
		total, _, _ := pool.Stats()
		if total == 0 {
			delete(m.pools, key)
		}
	}

	// Also cleanup DNS cache
	m.dnsCache.Cleanup()
}

// Close shuts down the manager and all pools
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}
	m.closed = true

	close(m.stopCleanup)

	for _, pool := range m.pools {
		pool.Close()
	}
	m.pools = nil
}

// Stats returns overall manager statistics
func (m *Manager) Stats() map[string]struct {
	Total    int
	Healthy  int
	Requests int64
} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]struct {
		Total    int
		Healthy  int
		Requests int64
	})

	for key, pool := range m.pools {
		t, h, r := pool.Stats()
		stats[key] = struct {
			Total    int
			Healthy  int
			Requests int64
		}{t, h, r}
	}

	return stats
}

// HTTP/2 frame types
const (
	frameTypeSettings     = 0x4
	frameTypeWindowUpdate = 0x8
	frameTypeHeaders      = 0x1
)

// HTTP/2 settings identifiers
const (
	settingHeaderTableSize      = 0x1
	settingEnablePush           = 0x2
	settingMaxConcurrentStreams = 0x3
	settingInitialWindowSize    = 0x4
	settingMaxFrameSize         = 0x5
	settingMaxHeaderListSize    = 0x6
)

// HTTP/2 frame header size
const frameHeaderLen = 9

// http2Conn wraps a connection to intercept and modify HTTP/2 frames
type http2Conn struct {
	net.Conn
	preset        *fingerprint.Preset
	buf           bytes.Buffer
	mu            sync.Mutex
	wrotePreface  bool
	wroteSettings bool
	wroteWindow   bool
	hpackEncoder  *hpack.Encoder
	hpackBuf      bytes.Buffer
}

// newHTTP2Conn creates a new HTTP/2 connection wrapper
func newHTTP2Conn(conn net.Conn, preset *fingerprint.Preset) *http2Conn {
	c := &http2Conn{
		Conn:   conn,
		preset: preset,
	}
	c.hpackEncoder = hpack.NewEncoder(&c.hpackBuf)
	return c
}

// Write intercepts writes to modify HTTP/2 frames
func (c *http2Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.buf.Write(p)
	originalLen := len(p)

	for c.buf.Len() > 0 {
		data := c.buf.Bytes()

		if !c.wrotePreface {
			preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
			if len(data) >= len(preface) && bytes.Equal(data[:len(preface)], preface) {
				if _, err := c.Conn.Write(preface); err != nil {
					return 0, err
				}
				c.buf.Next(len(preface))
				c.wrotePreface = true
				continue
			}
			break
		}

		if len(data) < frameHeaderLen {
			break
		}

		length := (uint32(data[0]) << 16) | (uint32(data[1]) << 8) | uint32(data[2])
		frameType := data[3]

		frameSize := int(frameHeaderLen + length)
		if len(data) < frameSize {
			break
		}

		switch frameType {
		case frameTypeSettings:
			if !c.wroteSettings {
				customFrame := c.buildCustomSettingsFrame()
				if _, err := c.Conn.Write(customFrame); err != nil {
					return 0, err
				}
				c.wroteSettings = true
				c.buf.Next(frameSize)
				continue
			}

		case frameTypeWindowUpdate:
			if !c.wroteWindow {
				customFrame := c.buildCustomWindowUpdateFrame()
				if _, err := c.Conn.Write(customFrame); err != nil {
					return 0, err
				}
				c.wroteWindow = true
				c.buf.Next(frameSize)
				continue
			}

		case frameTypeHeaders:
			flags := data[4]
			streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF
			hasEndHeaders := flags&0x4 != 0
			if hasEndHeaders && streamID > 0 {
				customFrame, err := c.buildCustomHeadersFrame(data[:frameSize])
				if err == nil {
					if _, err := c.Conn.Write(customFrame); err != nil {
						return 0, err
					}
					c.buf.Next(frameSize)
					continue
				}
			}
		}

		if _, err := c.Conn.Write(data[:frameSize]); err != nil {
			return 0, err
		}
		c.buf.Next(frameSize)
	}

	return originalLen, nil
}

// buildCustomSettingsFrame builds a SETTINGS frame with Chrome values
// Chrome order: HEADER_TABLE_SIZE, ENABLE_PUSH, MAX_CONCURRENT_STREAMS (if non-zero), INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE
// IMPORTANT: Chrome does NOT send MAX_CONCURRENT_STREAMS initially - sending 3:0 is a bot fingerprint!
func (c *http2Conn) buildCustomSettingsFrame() []byte {
	settings := c.preset.HTTP2Settings
	var payload bytes.Buffer

	// 1. HEADER_TABLE_SIZE (Chrome sends 65536)
	if settings.HeaderTableSize > 0 {
		binary.Write(&payload, binary.BigEndian, uint16(settingHeaderTableSize))
		binary.Write(&payload, binary.BigEndian, settings.HeaderTableSize)
	}

	// 2. ENABLE_PUSH (Chrome sends 0)
	binary.Write(&payload, binary.BigEndian, uint16(settingEnablePush))
	if settings.EnablePush {
		binary.Write(&payload, binary.BigEndian, uint32(1))
	} else {
		binary.Write(&payload, binary.BigEndian, uint32(0))
	}

	// 3. MAX_CONCURRENT_STREAMS - Chrome does NOT send this initially!
	// Only send if explicitly set to a non-zero value (not for Chrome presets)
	// This was causing bot detection - browsers never send 3:0
	if settings.MaxConcurrentStreams > 0 {
		binary.Write(&payload, binary.BigEndian, uint16(settingMaxConcurrentStreams))
		binary.Write(&payload, binary.BigEndian, settings.MaxConcurrentStreams)
	}

	// 4. INITIAL_WINDOW_SIZE (Chrome sends 6291456)
	if settings.InitialWindowSize > 0 {
		binary.Write(&payload, binary.BigEndian, uint16(settingInitialWindowSize))
		binary.Write(&payload, binary.BigEndian, settings.InitialWindowSize)
	}

	// 5. MAX_HEADER_LIST_SIZE (Chrome sends 262144)
	if settings.MaxHeaderListSize > 0 {
		binary.Write(&payload, binary.BigEndian, uint16(settingMaxHeaderListSize))
		binary.Write(&payload, binary.BigEndian, settings.MaxHeaderListSize)
	}

	payloadLen := payload.Len()
	frame := make([]byte, frameHeaderLen+payloadLen)
	frame[0] = byte(payloadLen >> 16)
	frame[1] = byte(payloadLen >> 8)
	frame[2] = byte(payloadLen)
	frame[3] = frameTypeSettings
	frame[4] = 0
	copy(frame[frameHeaderLen:], payload.Bytes())

	return frame
}

// buildCustomHeadersFrame rebuilds HEADERS frame with Chrome pseudo-header order
// Modern Chrome (131+) does NOT send explicit PRIORITY frames on stream 1
// Sending priority data on stream 1 is a bot fingerprint!
func (c *http2Conn) buildCustomHeadersFrame(originalFrame []byte) ([]byte, error) {
	originalFlags := originalFrame[4]
	streamID := binary.BigEndian.Uint32(originalFrame[5:9]) & 0x7FFFFFFF

	hasPadding := originalFlags&0x8 != 0
	hasPriority := originalFlags&0x20 != 0

	headerBlockStart := frameHeaderLen
	if hasPadding {
		headerBlockStart++
	}
	if hasPriority {
		headerBlockStart += 5
	}

	headerBlock := originalFrame[headerBlockStart:]
	if hasPadding && len(originalFrame) > frameHeaderLen {
		padLen := int(originalFrame[frameHeaderLen])
		if padLen < len(headerBlock) {
			headerBlock = headerBlock[:len(headerBlock)-padLen]
		}
	}

	decoder := hpack.NewDecoder(65536, nil)
	headers, err := decoder.DecodeFull(headerBlock)
	if err != nil {
		return nil, err
	}

	var method, authority, scheme, path string
	headerMap := make(map[string]string)
	for _, h := range headers {
		switch h.Name {
		case ":method":
			method = h.Value
		case ":authority":
			authority = h.Value
		case ":scheme":
			scheme = h.Value
		case ":path":
			path = h.Value
		default:
			headerMap[h.Name] = h.Value
		}
	}

	// Chrome 143 header order (extracted from real Chrome request to tls.peet.ws)
	chromeHeaderOrder := []string{
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"upgrade-insecure-requests", "user-agent", "accept",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
		"accept-encoding", "accept-language", "priority",
		// High-entropy Client Hints (only sent when requested via Accept-CH)
		"sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version-list",
		"sec-ch-ua-model", "sec-ch-ua-platform-version",
		// Other headers
		"cache-control", "cookie", "origin", "pragma", "referer",
	}

	c.hpackBuf.Reset()
	c.hpackEncoder.WriteField(hpack.HeaderField{Name: ":method", Value: method})
	c.hpackEncoder.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	c.hpackEncoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: scheme})
	c.hpackEncoder.WriteField(hpack.HeaderField{Name: ":path", Value: path})

	written := make(map[string]bool)
	for _, name := range chromeHeaderOrder {
		if val, ok := headerMap[name]; ok {
			c.hpackEncoder.WriteField(hpack.HeaderField{Name: name, Value: val})
			written[name] = true
		}
	}

	for name, val := range headerMap {
		if !written[name] {
			c.hpackEncoder.WriteField(hpack.HeaderField{Name: name, Value: val})
		}
	}
	newHeaderBlock := c.hpackBuf.Bytes()

	// Chrome 143 DOES send priority data on HEADERS frames
	// Verified from real Chrome 143 request to tls.peet.ws:
	// "priority": {"weight": 256, "depends_on": 0, "exclusive": 1}
	priorityData := make([]byte, 5)
	binary.BigEndian.PutUint32(priorityData[0:4], 0x80000000) // exclusive=1, depends_on=0
	weight := c.preset.HTTP2Settings.StreamWeight
	if weight == 0 {
		weight = 256
	}
	priorityData[4] = byte(weight - 1) // Wire format is weight-1

	newFlags := (originalFlags & 0x05) | 0x20 // Keep END_STREAM, END_HEADERS, add PRIORITY
	newPayloadLen := 5 + len(newHeaderBlock)

	frame := make([]byte, frameHeaderLen+newPayloadLen)
	frame[0] = byte(newPayloadLen >> 16)
	frame[1] = byte(newPayloadLen >> 8)
	frame[2] = byte(newPayloadLen)
	frame[3] = frameTypeHeaders
	frame[4] = newFlags
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	copy(frame[frameHeaderLen:], priorityData)
	copy(frame[frameHeaderLen+5:], newHeaderBlock)

	return frame, nil
}

// buildCustomWindowUpdateFrame builds WINDOW_UPDATE frame with Chrome value
func (c *http2Conn) buildCustomWindowUpdateFrame() []byte {
	increment := c.preset.HTTP2Settings.ConnectionWindowUpdate
	if increment == 0 {
		increment = 15663105
	}

	frame := make([]byte, frameHeaderLen+4)
	frame[0] = 0
	frame[1] = 0
	frame[2] = 4
	frame[3] = frameTypeWindowUpdate
	frame[4] = 0
	binary.BigEndian.PutUint32(frame[frameHeaderLen:], increment&0x7FFFFFFF)

	return frame
}

func (c *http2Conn) Read(p []byte) (int, error)            { return c.Conn.Read(p) }
func (c *http2Conn) Close() error                          { return c.Conn.Close() }
func (c *http2Conn) LocalAddr() net.Addr                   { return c.Conn.LocalAddr() }
func (c *http2Conn) RemoteAddr() net.Addr                  { return c.Conn.RemoteAddr() }
func (c *http2Conn) SetDeadline(t time.Time) error         { return c.Conn.SetDeadline(t) }
func (c *http2Conn) SetReadDeadline(t time.Time) error     { return c.Conn.SetReadDeadline(t) }
func (c *http2Conn) SetWriteDeadline(t time.Time) error    { return c.Conn.SetWriteDeadline(t) }

type tlsConnWrapper struct {
	*http2Conn
	tlsConn *utls.UConn
}

func (w *tlsConnWrapper) ConnectionState() utls.ConnectionState {
	return w.tlsConn.ConnectionState()
}

func wrapTLSConn(tlsConn *utls.UConn, preset *fingerprint.Preset) net.Conn {
	h2Conn := newHTTP2Conn(tlsConn, preset)
	return &tlsConnWrapper{
		http2Conn: h2Conn,
		tlsConn:   tlsConn,
	}
}
