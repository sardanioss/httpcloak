package pool

import (
	"context"
	crand "crypto/rand"
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
	tls "github.com/sardanioss/utls"
	utls "github.com/sardanioss/utls"
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

	// Cached ClientHelloSpec - shuffled once on pool creation, reused for all connections
	// This matches Chrome's behavior: shuffle TLS extensions once per session, not per connection
	cachedSpec    *utls.ClientHelloSpec
	cachedPSKSpec *utls.ClientHelloSpec

	// Configuration
	maxConns           int
	maxIdleTime        time.Duration
	maxConnAge         time.Duration
	connectTimeout     time.Duration
	insecureSkipVerify bool
	proxyURL           string
}

// NewHostPool creates a new pool for a specific host
// Note: This generates its own shuffled specs. For consistent session fingerprinting,
// use Manager.GetPool() instead which shares cached specs across all hosts.
func NewHostPool(host, port string, preset *fingerprint.Preset, dnsCache *dns.Cache) *HostPool {
	// Generate specs for standalone usage (backward compatibility)
	var cachedSpec, cachedPSKSpec *utls.ClientHelloSpec
	if spec, err := utls.UTLSIdToSpec(preset.ClientHelloID); err == nil {
		cachedSpec = &spec
	}
	if preset.PSKClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpec(preset.PSKClientHelloID); err == nil {
			cachedPSKSpec = &spec
		}
	}
	return NewHostPoolWithConfig(host, port, preset, dnsCache, false, "", cachedSpec, cachedPSKSpec)
}

// NewHostPoolWithConfig creates a pool with TLS and proxy configuration
func NewHostPoolWithConfig(host, port string, preset *fingerprint.Preset, dnsCache *dns.Cache, insecureSkipVerify bool, proxyURL string, cachedSpec, cachedPSKSpec *utls.ClientHelloSpec) *HostPool {
	pool := &HostPool{
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
		cachedSpec:         cachedSpec,    // Use manager's cached spec for consistent shuffle
		cachedPSKSpec:      cachedPSKSpec, // Use manager's cached PSK spec
	}

	return pool
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
		ipv6, ipv4, err := p.dnsCache.ResolveIPv6First(ctx, p.host)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}

		// Order IPs based on preference
		var preferredIPs, fallbackIPs []net.IP
		if p.dnsCache.PreferIPv4() {
			preferredIPs = ipv4
			fallbackIPs = ipv6
		} else {
			preferredIPs = ipv6
			fallbackIPs = ipv4
		}

		// Use Happy Eyeballs to establish connection
		rawConn, err = p.dialHappyEyeballs(ctx, preferredIPs, fallbackIPs)
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
		OmitEmptyPsk:           true,           // Chrome doesn't send empty PSK on first connection
	}

	// Determine which cached spec to use:
	// - If we have a cached session for this host and PSK spec available, use PSK spec
	// - Otherwise use the regular cached spec
	// Using cached specs ensures TLS extension order is consistent (shuffled once per session, like Chrome)
	var specToUse *utls.ClientHelloSpec
	usePSK := false
	if p.cachedPSKSpec != nil {
		// Check if there's a cached session (key is ServerName)
		if session, ok := p.sessionCache.Get(p.host); ok && session != nil {
			specToUse = p.cachedPSKSpec
			usePSK = true
		}
	}
	if specToUse == nil {
		specToUse = p.cachedSpec
	}

	// Create UClient with HelloCustom and apply our cached spec
	// This ensures the TLS extension order is consistent across all connections
	var tlsConn *utls.UConn
	if specToUse != nil {
		// Use cached spec - extension order is preserved from pool creation
		tlsConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
		if err := tlsConn.ApplyPreset(specToUse); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to apply TLS preset: %w", err)
		}
	} else {
		// Fallback to ClientHelloID if spec caching failed
		clientHelloID := p.preset.ClientHelloID
		if usePSK && p.preset.PSKClientHelloID.Client != "" {
			clientHelloID = p.preset.PSKClientHelloID
		}
		tlsConn = utls.UClient(rawConn, tlsConfig, clientHelloID)
	}

	// Set session cache on the connection for PSK/resumption
	// This enables pre_shared_key extension on subsequent connections
	tlsConn.SetSessionCache(p.sessionCache)

	// Perform TLS handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Build HTTP/2 settings from preset
	settings := p.preset.HTTP2Settings

	// Create HTTP/2 transport with native fingerprinting (no frame interception needed)
	h2Transport := &http2.Transport{
		AllowHTTP:                  false,
		DisableCompression:         false,
		StrictMaxConcurrentStreams: false,
		MaxHeaderListSize:          settings.MaxHeaderListSize,
		MaxReadFrameSize:           settings.MaxFrameSize,
		MaxDecoderHeaderTableSize:  settings.HeaderTableSize,
		MaxEncoderHeaderTableSize:  settings.HeaderTableSize,

		// Native fingerprinting via sardanioss/net
		ConnectionFlow: settings.ConnectionWindowUpdate,
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   settings.HeaderTableSize,
			http2.SettingEnablePush:        boolToUint32(settings.EnablePush),
			http2.SettingInitialWindowSize: settings.InitialWindowSize,
			http2.SettingMaxHeaderListSize: settings.MaxHeaderListSize,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"}, // Chrome order (m,a,s,p)
		HeaderPriority: &http2.PriorityParam{
			Weight:    uint8(settings.StreamWeight - 1), // Wire format is weight-1
			Exclusive: settings.StreamExclusive,
			StreamDep: 0,
		},
		HeaderOrder: []string{
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"upgrade-insecure-requests", "user-agent", "accept",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
			"accept-encoding", "accept-language",
			"cookie", "priority",
		},
		UserAgent:           p.preset.UserAgent,
		StreamPriorityMode:  http2.StreamPriorityChrome,
		HPACKIndexingPolicy: hpack.IndexingChrome,
	}

	h2Conn, err := h2Transport.NewClientConn(tlsConn)
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

// dialHappyEyeballs implements RFC 8305 Happy Eyeballs v2
// Starts preferred IPs first, waits 250ms, then starts fallback IPs
func (p *HostPool) dialHappyEyeballs(ctx context.Context, preferredIPs, fallbackIPs []net.IP) (net.Conn, error) {
	totalIPs := len(preferredIPs) + len(fallbackIPs)
	if totalIPs == 0 {
		return nil, fmt.Errorf("no IP addresses available")
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}

	dialCtx, cancel := context.WithCancel(ctx)
	resultCh := make(chan dialResult, totalIPs)
	perAddrTimeout := 5 * time.Second
	started := 0

	// Helper to start a dial
	startDial := func(ip net.IP) {
		go func(ip net.IP) {
			network := "tcp4"
			if ip.To4() == nil {
				network = "tcp6"
			}
			addr := net.JoinHostPort(ip.String(), p.port)
			dialer := &net.Dialer{Timeout: perAddrTimeout}
			conn, err := dialer.DialContext(dialCtx, network, addr)
			select {
			case resultCh <- dialResult{conn: conn, err: err}:
			case <-dialCtx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}(ip)
	}

	// Start preferred IPs (IPv6 by default) in parallel
	for _, ip := range preferredIPs {
		startDial(ip)
		started++
	}

	// RFC 8305: Wait 250ms before starting fallback IPs
	if len(fallbackIPs) > 0 {
		select {
		case result := <-resultCh:
			if result.conn != nil {
				cancel()
				return result.conn, nil
			}
			started-- // One failed, adjust count
		case <-time.After(250 * time.Millisecond):
			// Preferred IPs haven't succeeded yet, start fallback
		case <-ctx.Done():
			cancel()
			return nil, ctx.Err()
		}

		// Start fallback IPs in parallel
		for _, ip := range fallbackIPs {
			startDial(ip)
			started++
		}
	}

	// Wait for first success or all failures
	var lastErr error
	for i := 0; i < started; i++ {
		select {
		case result := <-resultCh:
			if result.conn != nil {
				cancel()
				return result.conn, nil
			}
			lastErr = result.err
		case <-ctx.Done():
			cancel()
			return nil, ctx.Err()
		}
	}

	cancel()
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("all connection attempts failed")
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
	// Pre-resolve proxy hostname using CGO-compatible resolver
	// Required for shared library usage where Go's pure-Go resolver doesn't work
	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxy.Host, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxy.Host)
	}

	dialer := &net.Dialer{Timeout: p.connectTimeout}
	proxyAddr := net.JoinHostPort(proxyIPs[0], proxy.Port)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
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
	// Pre-resolve proxy hostname using CGO-compatible resolver
	// Required for shared library usage where Go's pure-Go resolver doesn't work
	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxy.Host, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxy.Host)
	}

	dialer := &net.Dialer{Timeout: p.connectTimeout}
	proxyAddr := net.JoinHostPort(proxyIPs[0], proxy.Port)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
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
	maxConnsPerHost    int               // 0 = unlimited
	proxyURL           string            // Proxy URL (optional)
	insecureSkipVerify bool              // Skip TLS verification
	connectTo          map[string]string // Domain fronting: request host -> connect host
	echConfig          []byte            // Custom ECH configuration
	echConfigDomain    string            // Domain to fetch ECH config from

	// Cached TLS specs - shared across all HostPools for consistent fingerprint
	// Chrome shuffles extension order once per session, not per connection
	cachedSpec    *utls.ClientHelloSpec
	cachedPSKSpec *utls.ClientHelloSpec
	shuffleSeed   int64 // Seed used for extension shuffling

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
	// Generate random seed for extension shuffling
	// This seed is used for all connections in this manager (session)
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	m := &Manager{
		pools:              make(map[string]*HostPool),
		dnsCache:           dns.NewCache(),
		preset:             preset,
		maxConnsPerHost:    0, // 0 = unlimited by default
		insecureSkipVerify: insecureSkipVerify,
		shuffleSeed:        shuffleSeed,
		cleanupInterval:    30 * time.Second,
		stopCleanup:        make(chan struct{}),
	}

	// Generate and cache ClientHelloSpec with shuffled extensions
	// Chrome shuffles extensions once per session, not per connection
	if spec, err := utls.UTLSIdToSpecWithSeed(preset.ClientHelloID, shuffleSeed); err == nil {
		m.cachedSpec = &spec
	}

	// Also cache PSK variant if available
	if preset.PSKClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.PSKClientHelloID, shuffleSeed); err == nil {
			m.cachedPSKSpec = &spec
		}
	}

	// Start background cleanup
	go m.cleanupLoop()

	return m
}

// NewManagerWithProxy creates a manager with proxy support
func NewManagerWithProxy(preset *fingerprint.Preset, proxyURL string, insecureSkipVerify bool) *Manager {
	// Generate random seed for extension shuffling
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	m := &Manager{
		pools:              make(map[string]*HostPool),
		dnsCache:           dns.NewCache(),
		preset:             preset,
		maxConnsPerHost:    0, // 0 = unlimited by default
		proxyURL:           proxyURL,
		insecureSkipVerify: insecureSkipVerify,
		shuffleSeed:        shuffleSeed,
		cleanupInterval:    30 * time.Second,
		stopCleanup:        make(chan struct{}),
	}

	// Generate and cache ClientHelloSpec with shuffled extensions
	if spec, err := utls.UTLSIdToSpecWithSeed(preset.ClientHelloID, shuffleSeed); err == nil {
		m.cachedSpec = &spec
	}

	// Also cache PSK variant if available
	if preset.PSKClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.PSKClientHelloID, shuffleSeed); err == nil {
			m.cachedPSKSpec = &spec
		}
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

	pool = NewHostPoolWithConfig(host, port, m.preset, m.dnsCache, m.insecureSkipVerify, m.proxyURL, m.cachedSpec, m.cachedPSKSpec)
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

// SetConnectTo sets a host mapping for domain fronting
func (m *Manager) SetConnectTo(requestHost, connectHost string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connectTo == nil {
		m.connectTo = make(map[string]string)
	}
	m.connectTo[requestHost] = connectHost
}

// SetECHConfig sets a custom ECH configuration
func (m *Manager) SetECHConfig(echConfig []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.echConfig = echConfig
}

// SetECHConfigDomain sets a domain to fetch ECH config from
func (m *Manager) SetECHConfigDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.echConfigDomain = domain
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

// boolToUint32 converts a bool to uint32 (for HTTP/2 SETTINGS)
func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}
