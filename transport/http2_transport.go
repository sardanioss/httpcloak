package transport

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/proxy"
	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
	tls "github.com/sardanioss/utls"
	utls "github.com/sardanioss/utls"
)

// HTTP2Transport is a custom HTTP/2 transport with uTLS fingerprinting
// and proper connection reuse
type HTTP2Transport struct {
	preset   *fingerprint.Preset
	dnsCache *dns.Cache
	proxy    *ProxyConfig
	config   *TransportConfig

	// Connection tracking
	conns   map[string]*persistentConn
	connsMu sync.RWMutex

	// TLS session resumption cache (shared across connections)
	sessionCache utls.ClientSessionCache

	// Shuffle seed for consistent TLS extension order across all connections
	// Chrome shuffles extensions once per session, not per connection
	// Each connection needs a fresh spec (ApplyPreset mutates it), but same seed
	shuffleSeed int64

	// Cached spec presence flags - indicate if preset supports these specs
	// We don't cache the actual spec objects as ApplyPreset mutates them
	hasPSKSpec bool

	// Configuration
	maxIdleTime        time.Duration
	maxConnAge         time.Duration
	connectTimeout     time.Duration
	insecureSkipVerify bool

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
	return NewHTTP2TransportWithConfig(preset, dnsCache, proxy, nil)
}

// NewHTTP2TransportWithConfig creates a new HTTP/2 transport with proxy and advanced config
func NewHTTP2TransportWithConfig(preset *fingerprint.Preset, dnsCache *dns.Cache, proxy *ProxyConfig, config *TransportConfig) *HTTP2Transport {
	// Create session cache - with optional distributed backend
	var sessionCache *PersistableSessionCache
	if config != nil && config.SessionCacheBackend != nil {
		sessionCache = NewPersistableSessionCacheWithBackend(
			config.SessionCacheBackend,
			preset.Name,
			"h2",
			config.SessionCacheErrorCallback,
		)
	} else {
		sessionCache = NewPersistableSessionCache()
	}

	// Generate random seed for TLS extension shuffling
	// Chrome shuffles extensions once per session, not per connection
	// This seed ensures consistent ordering across all connections in this transport
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	// Check if PSK spec is available for this preset
	hasPSKSpec := preset.PSKClientHelloID.Client != ""

	t := &HTTP2Transport{
		preset:         preset,
		dnsCache:       dnsCache,
		proxy:          proxy,
		config:         config,
		conns:          make(map[string]*persistentConn),
		sessionCache:   sessionCache,
		shuffleSeed:    shuffleSeed,
		hasPSKSpec:     hasPSKSpec,
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

	// Get the connection host (may be different for domain fronting)
	connectHost := t.getConnectHost(host)

	targetAddr := net.JoinHostPort(host, port)

	if t.proxy != nil && t.proxy.URL != "" {
		// Connect through proxy - use connectHost for proxy CONNECT
		rawConn, err = t.dialThroughProxy(ctx, connectHost, port)
		if err != nil {
			return nil, fmt.Errorf("proxy connection failed: %w", err)
		}
	} else {
		// Direct connection with DNS resolution and IPv4/IPv6 fallback
		// Resolve the connection host, not request host
		ips, err := t.dnsCache.ResolveAllSorted(ctx, connectHost)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("DNS resolution failed: no IP addresses found")
		}

		dialer := &net.Dialer{
			Timeout:   t.connectTimeout,
			KeepAlive: 30 * time.Second,
		}

		// Try each IP address in order (preferred first based on PreferIPv4 setting)
		var lastErr error
		for _, ip := range ips {
			network := "tcp4"
			if ip.To4() == nil {
				network = "tcp6"
			}
			addr := net.JoinHostPort(ip.String(), port)

			rawConn, err = dialer.DialContext(ctx, network, addr)
			if err == nil {
				break // Connection successful
			}
			lastErr = err
		}

		if rawConn == nil {
			if lastErr != nil {
				return nil, fmt.Errorf("TCP connect failed: %w", lastErr)
			}
			return nil, fmt.Errorf("TCP connect failed: all connection attempts failed")
		}
	}

	// Set TCP keepalive
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// Generate fresh spec for this connection to avoid race condition
	// utls's ApplyPreset mutates the spec (clears KeyShares.Data, etc.), so each
	// connection needs its own copy. Use same shuffleSeed for consistent ordering.
	var specToUse *utls.ClientHelloSpec
	if t.hasPSKSpec {
		// Generate fresh PSK spec for this connection
		if spec, err := utls.UTLSIdToSpecWithSeed(t.preset.PSKClientHelloID, t.shuffleSeed); err == nil {
			specToUse = &spec
		}
	}
	if specToUse == nil {
		// Generate fresh regular spec
		if spec, err := utls.UTLSIdToSpecWithSeed(t.preset.ClientHelloID, t.shuffleSeed); err == nil {
			specToUse = &spec
		}
	}

	// Fetch ECH config if needed
	var echConfigList []byte
	if t.config != nil {
		if len(t.config.ECHConfig) > 0 {
			echConfigList = t.config.ECHConfig
		} else if t.config.ECHConfigDomain != "" {
			// Fetch ECH config from DNS
			echConfigList, _ = dns.FetchECHConfigs(ctx, t.config.ECHConfigDomain)
			// ECH fetch failed - continue without ECH (SNI will be visible)
		}
	}

	// Determine MinVersion based on ECH usage
	// ECH requires TLS 1.3, so set MinVersion accordingly
	minVersion := uint16(tls.VersionTLS12)
	if len(echConfigList) > 0 {
		minVersion = tls.VersionTLS13
	}

	// Wrap with uTLS for fingerprinting
	tlsConfig := &utls.Config{
		ServerName:                         host,
		InsecureSkipVerify:                 t.insecureSkipVerify,
		MinVersion:                         minVersion,
		MaxVersion:                         tls.VersionTLS13,
		OmitEmptyPsk:                       true,          // Chrome doesn't send empty PSK on first connection
		PreferSkipResumptionOnNilExtension: true,          // Skip resumption if spec has no PSK extension instead of panicking
		EncryptedClientHelloConfigList:     echConfigList, // ECH configuration (if available)
	}

	// Only enable session cache if we have PSK spec - prevents panic when session
	// is cached but spec doesn't have PSK extension (TOCTOU race mitigation)
	if t.hasPSKSpec {
		tlsConfig.ClientSessionCache = t.sessionCache
	}

	// Create UClient with HelloCustom and apply our fresh spec
	// This ensures the TLS extension order is consistent across all connections (same seed)
	var tlsConn *utls.UConn
	if specToUse != nil {
		// Use fresh spec - extension order is consistent from shuffle seed
		tlsConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
		if err := tlsConn.ApplyPreset(specToUse); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to apply TLS preset: %w", err)
		}
	} else {
		// Fallback to ClientHelloID if spec generation failed
		tlsConn = utls.UClient(rawConn, tlsConfig, t.preset.ClientHelloID)
	}

	// Set session cache for TLS resumption (only if PSK spec available)
	if t.hasPSKSpec {
		tlsConn.SetSessionCache(t.sessionCache)
	}

	// Perform TLS handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Check ALPN negotiation result
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		// Return ALPNMismatchError with the TLS connection so caller can reuse it for H1
		// DO NOT close the connection - caller is responsible for closing or reusing
		return nil, &ALPNMismatchError{
			Expected:   "h2",
			Negotiated: state.NegotiatedProtocol,
			TLSConn:    tlsConn,
			Host:       host,
			Port:       port,
		}
	}

	// Build HTTP/2 settings from preset
	settings := t.preset.HTTP2Settings

	// Check TLSOnly mode - disables automatic compression and user-agent
	tlsOnly := t.config != nil && t.config.TLSOnly
	userAgent := t.preset.UserAgent
	if tlsOnly {
		userAgent = "" // Don't set default User-Agent in TLS-only mode
	}

	// Create HTTP/2 transport with native fingerprinting (no frame interception needed)
	h2Transport := &http2.Transport{
		AllowHTTP:                  false,
		DisableCompression:         tlsOnly, // Disable auto Accept-Encoding in TLS-only mode
		StrictMaxConcurrentStreams: false,
		ReadIdleTimeout:            t.maxIdleTime,
		PingTimeout:                15 * time.Second,

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
			// Chrome 143 header order (verified via tls.peet.ws)
			"cache-control", // appears on reload/session resumption
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"upgrade-insecure-requests", "user-agent",
			"content-type", "content-length", // for POST requests
			"accept", "origin", // origin for CORS
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
			"referer",
			"accept-encoding", "accept-language",
			"cookie", "priority",
		},
		UserAgent:           userAgent,
		StreamPriorityMode:  http2.StreamPriorityChrome,
		HPACKIndexingPolicy: hpack.IndexingChrome,
	}

	h2Conn, err := h2Transport.NewClientConn(tlsConn)
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

// dialThroughProxy establishes a connection through a proxy using CONNECT
// Supports both HTTP proxies (HTTP CONNECT) and SOCKS5 proxies (SOCKS5 CONNECT)
func (t *HTTP2Transport) dialThroughProxy(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	// Check if it's a SOCKS5 proxy
	if proxy.IsSOCKS5URL(t.proxy.URL) {
		return t.dialThroughSOCKS5(ctx, targetHost, targetPort)
	}

	// HTTP proxy - use HTTP CONNECT
	return t.dialThroughHTTPProxy(ctx, targetHost, targetPort)
}

// dialThroughSOCKS5 establishes a connection through a SOCKS5 proxy
func (t *HTTP2Transport) dialThroughSOCKS5(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	socks5Dialer, err := proxy.NewSOCKS5Dialer(t.proxy.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	targetAddr := net.JoinHostPort(targetHost, targetPort)
	conn, err := socks5Dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 CONNECT failed: %w", err)
	}

	return conn, nil
}

// dialThroughHTTPProxy establishes a connection through an HTTP proxy using CONNECT
func (t *HTTP2Transport) dialThroughHTTPProxy(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
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

	// Pre-resolve proxy hostname using CGO-compatible resolver
	// Required for shared library usage where Go's pure-Go resolver doesn't work
	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, proxyHost)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxyHost, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxyHost)
	}

	// Connect to proxy using resolved IP
	dialer := &net.Dialer{
		Timeout:   t.connectTimeout,
		KeepAlive: 30 * time.Second,
	}

	proxyAddr := net.JoinHostPort(proxyIPs[0], proxyPort)
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

// Refresh closes all connections but keeps the TLS session cache intact.
// This simulates a browser page refresh - new TCP connections but TLS resumption.
func (t *HTTP2Transport) Refresh() {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.closed {
		return
	}

	// Close all connections
	for _, conn := range t.conns {
		go conn.close()
	}
	// Reset the map but keep session cache
	t.conns = make(map[string]*persistentConn)
}

// GetSessionCache returns the TLS session cache
func (t *HTTP2Transport) GetSessionCache() utls.ClientSessionCache {
	return t.sessionCache
}

// SetSessionCache sets the TLS session cache
func (t *HTTP2Transport) SetSessionCache(cache utls.ClientSessionCache) {
	t.sessionCache = cache
}

// SetInsecureSkipVerify sets whether to skip TLS certificate verification
func (t *HTTP2Transport) SetInsecureSkipVerify(skip bool) {
	t.insecureSkipVerify = skip
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

// SetConnectTo sets a host mapping for domain fronting
func (t *HTTP2Transport) SetConnectTo(requestHost, connectHost string) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	if t.config.ConnectTo == nil {
		t.config.ConnectTo = make(map[string]string)
	}
	t.config.ConnectTo[requestHost] = connectHost
}

// SetECHConfigDomain sets a domain to fetch ECH config from
func (t *HTTP2Transport) SetECHConfigDomain(domain string) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfigDomain = domain
}

// SetECHConfig sets a custom ECH configuration
func (t *HTTP2Transport) SetECHConfig(echConfig []byte) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfig = echConfig
}

// getConnectHost returns the connection host for DNS resolution
func (t *HTTP2Transport) getConnectHost(requestHost string) string {
	if t.config == nil || t.config.ConnectTo == nil {
		return requestHost
	}
	if connectHost, ok := t.config.ConnectTo[requestHost]; ok {
		return connectHost
	}
	return requestHost
}

// Connect establishes a connection to the host without making a request.
// This is used for protocol racing - the first protocol to connect wins.
func (t *HTTP2Transport) Connect(ctx context.Context, host, port string) error {
	key := net.JoinHostPort(host, port)

	// Check if we already have a usable connection
	t.connsMu.RLock()
	existingConn, exists := t.conns[key]
	t.connsMu.RUnlock()

	if exists && t.isConnUsable(existingConn) {
		return nil // Already connected
	}

	// Create new connection
	conn, err := t.createConn(ctx, host, port)
	if err != nil {
		return err
	}

	// Store connection for reuse
	t.connsMu.Lock()
	// Check again in case another goroutine created one
	if oldConn, exists := t.conns[key]; exists {
		// Close the old one if not usable
		if !t.isConnUsable(oldConn) {
			oldConn.tlsConn.Close()
		} else {
			// Old one is still good, close the new one we just created
			conn.tlsConn.Close()
			t.connsMu.Unlock()
			return nil
		}
	}
	t.conns[key] = conn
	t.connsMu.Unlock()

	return nil
}

// boolToUint32 converts a bool to uint32 (for HTTP/2 SETTINGS)
func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}
