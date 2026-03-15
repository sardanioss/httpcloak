package httpcloak

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sardanioss/httpcloak/proxy"
	"github.com/sardanioss/httpcloak/transport"
)

const (
	// HeaderUpstreamProxy is the header name for per-request proxy override (HTTP only).
	// For HTTPS/CONNECT requests, use Proxy-Authorization header instead.
	HeaderUpstreamProxy = "X-Upstream-Proxy"

	// HeaderTLSOnly is the header name for per-request TLS-only mode override.
	// When set to "true", TLS fingerprinting is applied but preset HTTP headers are skipped.
	// When set to "false", normal mode is used (preset headers applied).
	// If not set, uses the proxy's global TLSOnly setting.
	HeaderTLSOnly = "X-HTTPCloak-TlsOnly"

	// HeaderSession is the header name for per-request session selection.
	// When set, the proxy uses the specified session ID to route the request.
	// Sessions must be registered via RegisterSession() before use.
	// Example: X-HTTPCloak-Session: my-session-id
	HeaderSession = "X-HTTPCloak-Session"

	// HeaderScheme upgrades HTTP requests to HTTPS with TLS fingerprinting.
	// When set to "https", LocalProxy converts http:// URLs to https:// and uses
	// Session.DoStream() with full fingerprinting. This allows standard HTTP proxy
	// clients to get HTTPS fingerprinting without using CONNECT tunneling.
	// Example: X-HTTPCloak-Scheme: https
	HeaderScheme = "X-HTTPCloak-Scheme"

	// ProxyAuthScheme is the authentication scheme for upstream proxy selection.
	// Format: "Proxy-Authorization: HTTPCloak http://user:pass@proxy:8080"
	// This works for both HTTP and HTTPS (CONNECT) requests since Proxy-Authorization
	// is sent with CONNECT requests by standard HTTP clients.
	ProxyAuthScheme = "HTTPCloak"
)

// LocalProxy is an HTTP proxy server that forwards requests through httpcloak
// sessions with TLS fingerprinting.
//
// Architecture:
// - For HTTP requests: Forwards through httpcloak Session (fingerprinting applied)
// - For HTTPS (CONNECT): Tunnels TCP (client does TLS, fingerprinting via upstream proxy only)
//
// Usage with C# HttpClient:
//
//	proxy := httpcloak.StartLocalProxy(8080, "chrome-146")
//	defer proxy.Stop()
//	// Configure HttpClient to use http://localhost:8080 as proxy
type LocalProxy struct {
	listener net.Listener
	port     int

	// Configuration
	preset         string
	timeout        time.Duration
	maxConnections int
	tcpProxy       string // Upstream proxy for TCP connections
	udpProxy       string // Upstream proxy for UDP connections
	tlsOnly        bool   // TLS-only mode: skip preset HTTP headers

	// Session for making requests (HTTP forwarding with fingerprinting)
	session   *Session
	sessionMu sync.RWMutex

	// Session registry for per-request session selection
	// Key: session ID, Value: Session
	sessionRegistry   map[string]*Session
	sessionRegistryMu sync.RWMutex

	// Fast HTTP client for plain HTTP forwarding (no fingerprinting overhead)
	httpClient *http.Client
	transport  *http.Transport

	// State
	running      atomic.Bool
	activeConns  atomic.Int64
	totalReqs    atomic.Int64
	shuttingDown atomic.Bool

	// Shutdown
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// LocalProxyConfig holds configuration for the local proxy
type LocalProxyConfig struct {
	// Port to listen on (0 = auto-select)
	Port int

	// Browser fingerprint preset (default: chrome-146)
	Preset string

	// Request timeout
	Timeout time.Duration

	// Maximum concurrent connections
	MaxConnections int

	// Upstream proxy (optional)
	TCPProxy string
	UDPProxy string

	// TLSOnly mode: only apply TLS fingerprinting, pass HTTP headers through unchanged.
	// Useful when the client (e.g., Playwright) already provides authentic browser headers.
	TLSOnly bool

	// SessionCacheBackend is an optional distributed cache for TLS sessions.
	// Enables session sharing across multiple LocalProxy instances.
	SessionCacheBackend transport.SessionCacheBackend

	// SessionCacheErrorCallback is called when backend operations fail.
	SessionCacheErrorCallback transport.ErrorCallback
}

// LocalProxyOption configures the local proxy
type LocalProxyOption func(*LocalProxyConfig)

// WithProxyPreset sets the browser fingerprint preset
func WithProxyPreset(preset string) LocalProxyOption {
	return func(c *LocalProxyConfig) {
		c.Preset = preset
	}
}

// WithProxyTimeout sets the request timeout
func WithProxyTimeout(d time.Duration) LocalProxyOption {
	return func(c *LocalProxyConfig) {
		c.Timeout = d
	}
}

// WithProxyMaxConnections sets the maximum concurrent connections
func WithProxyMaxConnections(n int) LocalProxyOption {
	return func(c *LocalProxyConfig) {
		c.MaxConnections = n
	}
}

// WithProxyUpstream sets upstream proxy URLs for the httpcloak session
func WithProxyUpstream(tcpProxy, udpProxy string) LocalProxyOption {
	return func(c *LocalProxyConfig) {
		c.TCPProxy = tcpProxy
		c.UDPProxy = udpProxy
	}
}

// WithProxyTLSOnly enables TLS-only mode where only TLS fingerprinting is applied.
// HTTP headers from the client pass through unchanged - useful when using Playwright
// or other browsers that already provide authentic headers.
func WithProxyTLSOnly() LocalProxyOption {
	return func(c *LocalProxyConfig) {
		c.TLSOnly = true
	}
}

// WithProxySessionCache sets a distributed TLS session cache backend for the proxy.
// This enables TLS session ticket sharing across multiple proxy instances.
func WithProxySessionCache(backend transport.SessionCacheBackend, errorCallback transport.ErrorCallback) LocalProxyOption {
	return func(c *LocalProxyConfig) {
		c.SessionCacheBackend = backend
		c.SessionCacheErrorCallback = errorCallback
	}
}

// StartLocalProxy creates and starts a local HTTP proxy on the specified port.
// The proxy forwards requests through httpcloak sessions with TLS fingerprinting.
//
// Example:
//
//	proxy, err := httpcloak.StartLocalProxy(8080, httpcloak.WithProxyPreset("chrome-146"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer proxy.Stop()
//	fmt.Printf("Proxy running on port %d\n", proxy.Port())
func StartLocalProxy(port int, opts ...LocalProxyOption) (*LocalProxy, error) {
	config := &LocalProxyConfig{
		Port:           port,
		Preset:         "chrome-146",
		Timeout:        30 * time.Second,
		MaxConnections: 1000,
	}

	for _, opt := range opts {
		opt(config)
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &LocalProxy{
		port:            config.Port,
		preset:          config.Preset,
		timeout:         config.Timeout,
		maxConnections:  config.MaxConnections,
		tcpProxy:        config.TCPProxy,
		udpProxy:        config.UDPProxy,
		tlsOnly:         config.TLSOnly,
		sessionRegistry: make(map[string]*Session),
		ctx:             ctx,
		cancel:          cancel,
	}

	// Create session for HTTP forwarding
	sessionOpts := []SessionOption{
		WithSessionTimeout(config.Timeout),
	}
	if config.TCPProxy != "" {
		sessionOpts = append(sessionOpts, WithSessionTCPProxy(config.TCPProxy))
	}
	if config.UDPProxy != "" {
		sessionOpts = append(sessionOpts, WithSessionUDPProxy(config.UDPProxy))
	}
	if config.TLSOnly {
		sessionOpts = append(sessionOpts, WithTLSOnly())
	}
	if config.SessionCacheBackend != nil {
		sessionOpts = append(sessionOpts, WithSessionCache(config.SessionCacheBackend, config.SessionCacheErrorCallback))
	}
	p.session = NewSession(config.Preset, sessionOpts...)

	// Create fast HTTP transport for plain HTTP forwarding
	p.transport = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true, // Let client handle compression
		WriteBufferSize:     64 * 1024,
		ReadBufferSize:      64 * 1024,
		ForceAttemptHTTP2:   false, // Keep HTTP/1.1 for simplicity
	}
	p.httpClient = &http.Client{
		Transport: p.transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Start the server
	if err := p.start(); err != nil {
		p.session.Close()
		p.transport.CloseIdleConnections()
		cancel()
		return nil, err
	}

	return p, nil
}

// start starts the proxy server
func (p *LocalProxy) start() error {
	if p.running.Load() {
		return errors.New("proxy already running")
	}

	// Listen on localhost only (security)
	addr := fmt.Sprintf("127.0.0.1:%d", p.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	p.listener = listener
	p.running.Store(true)

	// Update port if auto-selected
	if p.port == 0 {
		p.port = listener.Addr().(*net.TCPAddr).Port
	}

	// Start accept loop
	p.wg.Add(1)
	go p.acceptLoop()

	return nil
}

// Stop stops the local proxy server gracefully
func (p *LocalProxy) Stop() error {
	if !p.running.Load() {
		return nil
	}

	p.shuttingDown.Store(true)
	p.cancel()

	if p.listener != nil {
		p.listener.Close()
	}

	// Wait for all connections to finish (with timeout)
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		// Force close after timeout
	}

	// Close session and transport
	if p.session != nil {
		p.session.Close()
	}
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}

	p.running.Store(false)
	return nil
}

// Port returns the port the proxy is listening on
func (p *LocalProxy) Port() int {
	return p.port
}

// IsRunning returns whether the proxy is running
func (p *LocalProxy) IsRunning() bool {
	return p.running.Load()
}

// Stats returns proxy statistics
func (p *LocalProxy) Stats() map[string]interface{} {
	p.sessionRegistryMu.RLock()
	sessionCount := len(p.sessionRegistry)
	p.sessionRegistryMu.RUnlock()

	return map[string]interface{}{
		"running":           p.running.Load(),
		"port":              p.port,
		"active_conns":      p.activeConns.Load(),
		"total_requests":    p.totalReqs.Load(),
		"preset":            p.preset,
		"max_connections":   p.maxConnections,
		"registered_sessions": sessionCount,
	}
}

// RegisterSession registers a session with the given ID for per-request session selection.
// The session can then be selected via the X-HTTPCloak-Session header.
// Returns an error if a session with the same ID already exists.
//
// Example:
//
//	session := httpcloak.NewSession("chrome-146", httpcloak.WithSessionProxy("..."))
//	proxy.RegisterSession("session-1", session)
//	// Client can now use: X-HTTPCloak-Session: session-1
func (p *LocalProxy) RegisterSession(sessionID string, session *Session) error {
	p.sessionRegistryMu.Lock()
	defer p.sessionRegistryMu.Unlock()

	if _, exists := p.sessionRegistry[sessionID]; exists {
		return fmt.Errorf("session with ID %q already exists", sessionID)
	}

	// Set session identifier for TLS cache key isolation in distributed caches
	session.SetSessionIdentifier(sessionID)

	p.sessionRegistry[sessionID] = session
	return nil
}

// UnregisterSession removes a session from the registry.
// The session is NOT closed - caller is responsible for closing it.
// Returns the session if found, nil otherwise.
func (p *LocalProxy) UnregisterSession(sessionID string) *Session {
	p.sessionRegistryMu.Lock()
	defer p.sessionRegistryMu.Unlock()

	session, exists := p.sessionRegistry[sessionID]
	if !exists {
		return nil
	}

	// Clear the session identifier (session may be reused elsewhere)
	session.SetSessionIdentifier("")

	delete(p.sessionRegistry, sessionID)
	return session
}

// GetSession returns a registered session by ID.
// Returns nil if the session is not found.
func (p *LocalProxy) GetSession(sessionID string) *Session {
	p.sessionRegistryMu.RLock()
	defer p.sessionRegistryMu.RUnlock()
	return p.sessionRegistry[sessionID]
}

// ListSessions returns all registered session IDs.
func (p *LocalProxy) ListSessions() []string {
	p.sessionRegistryMu.RLock()
	defer p.sessionRegistryMu.RUnlock()

	ids := make([]string, 0, len(p.sessionRegistry))
	for id := range p.sessionRegistry {
		ids = append(ids, id)
	}
	return ids
}

// extractSessionID extracts the session ID from the X-HTTPCloak-Session header.
// Returns empty string if the header is not set.
func (p *LocalProxy) extractSessionID(req *http.Request) string {
	return req.Header.Get(HeaderSession)
}

// acceptLoop accepts incoming connections
func (p *LocalProxy) acceptLoop() {
	defer p.wg.Done()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.shuttingDown.Load() {
				return
			}
			continue
		}

		// Check connection limit
		if p.activeConns.Load() >= int64(p.maxConnections) {
			conn.Close()
			continue
		}

		p.activeConns.Add(1)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.activeConns.Add(-1)
			p.handleConnection(conn)
		}()
	}
}

// handleConnection handles a single client connection
func (p *LocalProxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set read deadline for initial request
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read the HTTP request
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		p.sendError(conn, http.StatusBadRequest, "Bad Request")
		return
	}

	// Clear deadline
	conn.SetReadDeadline(time.Time{})

	p.totalReqs.Add(1)

	// Handle based on method
	if req.Method == http.MethodConnect {
		p.handleCONNECT(conn, req)
	} else {
		p.handleHTTP(conn, req, reader)
	}
}

// handleCONNECT handles HTTP CONNECT requests (HTTPS tunneling)
// Note: For CONNECT, we just tunnel - the client does its own TLS.
// Fingerprinting only works if an upstream proxy is configured.
//
// Supports per-request proxy override via:
//   - Proxy-Authorization: HTTPCloak http://user:pass@proxy:8080 (recommended for HTTPS)
//   - X-Upstream-Proxy header (fallback, but only works if client sets it on CONNECT)
func (p *LocalProxy) handleCONNECT(clientConn net.Conn, req *http.Request) {
	// Parse target host:port
	targetHost := req.Host
	if targetHost == "" {
		targetHost = req.URL.Host
	}

	host, port, err := net.SplitHostPort(targetHost)
	if err != nil {
		host = targetHost
		port = "443"
		targetHost = net.JoinHostPort(host, port)
	}

	// Security check
	if !p.isPortAllowed(port) {
		p.sendError(clientConn, http.StatusForbidden, "Port not allowed")
		return
	}

	// Check for per-request proxy override
	// Priority: Proxy-Authorization (HTTPCloak scheme) > X-Upstream-Proxy header
	proxyOverride := p.extractUpstreamProxy(req)

	// Connect to target
	ctx, cancel := context.WithTimeout(p.ctx, p.timeout)
	defer cancel()

	targetConn, err := p.dialTarget(ctx, host, port, proxyOverride)
	if err != nil {
		p.sendError(clientConn, http.StatusBadGateway, fmt.Sprintf("Failed to connect: %v", err))
		return
	}
	defer targetConn.Close()

	// Send 200 Connection Established
	response := "HTTP/1.1 200 Connection Established\r\n\r\n"
	if _, err := clientConn.Write([]byte(response)); err != nil {
		return
	}

	// Bidirectional tunnel
	p.tunnel(clientConn, targetConn)
}

// handleHTTP handles HTTP requests with TLS fingerprinting via httpcloak Session.
//
// For HTTPS targets: Uses Session.DoStream() with full TLS fingerprinting and header handling.
// For HTTP targets with X-HTTPCloak-Scheme: https: Upgrades to HTTPS with fingerprinting.
// For HTTP targets: Uses fast direct forwarding (no TLS fingerprinting needed).
//
// Supports:
//   - X-HTTPCloak-Session header for per-request session selection
//   - X-HTTPCloak-TlsOnly header for per-request TLS-only mode
//   - X-HTTPCloak-Scheme header to upgrade HTTP to HTTPS with fingerprinting
//   - Per-request proxy override via registered sessions
func (p *LocalProxy) handleHTTP(clientConn net.Conn, req *http.Request, reader *bufio.Reader) {
	// Build target URL
	targetURL := req.URL.String()
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		if req.URL.Host != "" {
			targetURL = "http://" + req.URL.Host + req.URL.RequestURI()
		} else if req.Host != "" {
			targetURL = "http://" + req.Host + req.URL.RequestURI()
		} else {
			p.sendError(clientConn, http.StatusBadRequest, "Missing host")
			return
		}
	}

	// Check for scheme upgrade header (X-HTTPCloak-Scheme: https)
	// This allows HTTP proxy clients to get HTTPS fingerprinting without CONNECT
	schemeOverride := req.Header.Get(HeaderScheme)
	if strings.EqualFold(schemeOverride, "https") && strings.HasPrefix(targetURL, "http://") {
		targetURL = "https://" + strings.TrimPrefix(targetURL, "http://")
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(p.ctx, p.timeout)
	defer cancel()

	// For HTTPS targets, use Session with fingerprinting
	if strings.HasPrefix(targetURL, "https://") {
		p.handleHTTPWithSession(ctx, clientConn, req, targetURL)
		return
	}

	// For plain HTTP targets, use fast direct forwarding (no fingerprinting needed)
	p.handleHTTPDirect(ctx, clientConn, req, targetURL)
}

// handleHTTPWithSession handles requests using httpcloak Session with TLS fingerprinting.
// This provides full browser fingerprint emulation for HTTPS requests.
func (p *LocalProxy) handleHTTPWithSession(ctx context.Context, clientConn net.Conn, req *http.Request, targetURL string) {
	// Select session: registered session > default session
	session := p.session
	sessionID := p.extractSessionID(req)
	if sessionID != "" {
		if registeredSession := p.GetSession(sessionID); registeredSession != nil {
			session = registeredSession
		} else {
			p.sendError(clientConn, http.StatusBadRequest, fmt.Sprintf("Session not found: %s", sessionID))
			return
		}
	}

	// Extract per-request TLS-only mode override
	var tlsOnlyOverride *bool
	if tlsOnlyValue, hasTLSOnlyHeader := p.extractTLSOnly(req); hasTLSOnlyHeader {
		tlsOnlyOverride = &tlsOnlyValue
	}

	// Build headers map (skip hop-by-hop and internal headers)
	headers := make(map[string][]string)
	for key, values := range req.Header {
		// Skip hop-by-hop headers
		if isHopByHopHeader(key) {
			continue
		}
		// Skip internal HTTPCloak headers
		if strings.EqualFold(key, HeaderUpstreamProxy) ||
			strings.EqualFold(key, HeaderTLSOnly) ||
			strings.EqualFold(key, HeaderSession) ||
			strings.EqualFold(key, HeaderScheme) {
			continue
		}
		// Skip Proxy-Authorization with HTTPCloak scheme
		if strings.EqualFold(key, "Proxy-Authorization") {
			if len(values) > 0 && strings.HasPrefix(values[0], ProxyAuthScheme+" ") {
				continue
			}
		}
		headers[key] = values
	}

	// Build httpcloak request with per-request TLS-only override
	hcReq := &Request{
		Method:  req.Method,
		URL:     targetURL,
		Headers: headers,
		Body:    req.Body,    // Streaming request body
		TLSOnly: tlsOnlyOverride,
	}

	// Execute request with fingerprinting
	resp, err := session.DoStream(ctx, hcReq)
	if err != nil {
		p.sendError(clientConn, http.StatusBadGateway, fmt.Sprintf("Request failed: %v", err))
		return
	}
	defer resp.Close()

	// Use buffered writer for better performance
	bufWriter := bufio.NewWriterSize(clientConn, 64*1024)

	// Write status line
	fmt.Fprintf(bufWriter, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))

	// Write headers (skip hop-by-hop and Content-Encoding since body is already decompressed)
	for key, values := range resp.Headers {
		if isHopByHopHeader(key) {
			continue
		}
		// Skip Content-Encoding since we already decompressed the body
		if strings.EqualFold(key, "Content-Encoding") {
			continue
		}
		for _, value := range values {
			fmt.Fprintf(bufWriter, "%s: %s\r\n", key, value)
		}
	}
	bufWriter.WriteString("\r\n")
	bufWriter.Flush()

	// Stream response body
	buf := make([]byte, 64*1024) // 64KB buffer
	io.CopyBuffer(clientConn, resp, buf)
}

// handleHTTPDirect handles plain HTTP requests with fast direct forwarding.
// No TLS fingerprinting is applied (not needed for plain HTTP).
func (p *LocalProxy) handleHTTPDirect(ctx context.Context, clientConn net.Conn, req *http.Request, targetURL string) {
	// Check for per-request proxy override
	proxyOverride := p.extractUpstreamProxy(req)

	outReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, req.Body)
	if err != nil {
		p.sendError(clientConn, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	// Copy headers (skip hop-by-hop and internal headers)
	for key, values := range req.Header {
		if isHopByHopHeader(key) {
			continue
		}
		if strings.EqualFold(key, HeaderUpstreamProxy) ||
			strings.EqualFold(key, HeaderTLSOnly) ||
			strings.EqualFold(key, HeaderSession) ||
			strings.EqualFold(key, HeaderScheme) {
			continue
		}
		if strings.EqualFold(key, "Proxy-Authorization") {
			if len(values) > 0 && strings.HasPrefix(values[0], ProxyAuthScheme+" ") {
				continue
			}
		}
		for _, value := range values {
			outReq.Header.Add(key, value)
		}
	}
	outReq.ContentLength = req.ContentLength

	// Choose HTTP client
	client := p.httpClient
	if proxyOverride != "" {
		client = p.createProxyClient(proxyOverride)
	}

	// Execute request
	resp, err := client.Do(outReq)
	if err != nil {
		p.sendError(clientConn, http.StatusBadGateway, fmt.Sprintf("Request failed: %v", err))
		return
	}
	defer resp.Body.Close()

	// Use buffered writer for better performance
	bufWriter := bufio.NewWriterSize(clientConn, 64*1024)

	// Write status line
	fmt.Fprintf(bufWriter, "HTTP/1.1 %d %s\r\n", resp.StatusCode, resp.Status)

	// Write headers (skip hop-by-hop)
	for key, values := range resp.Header {
		if isHopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			fmt.Fprintf(bufWriter, "%s: %s\r\n", key, value)
		}
	}
	bufWriter.WriteString("\r\n")
	bufWriter.Flush()

	// Stream body with large buffer
	if resp.Body != nil {
		buf := make([]byte, 64*1024) // 64KB buffer
		io.CopyBuffer(clientConn, resp.Body, buf)
	}
}

// dialTarget connects to the target, optionally through upstream proxy.
// If proxyOverride is non-empty, it takes precedence over the configured proxy.
func (p *LocalProxy) dialTarget(ctx context.Context, host, port, proxyOverride string) (net.Conn, error) {
	targetAddr := net.JoinHostPort(host, port)

	// Determine which proxy to use (override takes precedence)
	proxyURL := p.tcpProxy
	if proxyOverride != "" {
		proxyURL = proxyOverride
	}

	// If upstream SOCKS5 proxy configured, use it
	if proxyURL != "" && proxy.IsSOCKS5URL(proxyURL) {
		socks5Dialer, err := proxy.NewSOCKS5Dialer(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}
		return socks5Dialer.DialContext(ctx, "tcp", targetAddr)
	}

	// If HTTP proxy configured, use CONNECT method
	if proxyURL != "" && (strings.HasPrefix(proxyURL, "http://") || strings.HasPrefix(proxyURL, "https://")) {
		return p.dialThroughHTTPProxy(ctx, proxyURL, targetAddr)
	}

	// Direct connection
	dialer := &net.Dialer{
		Timeout:   p.timeout,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, "tcp", targetAddr)
}

// createProxyClient creates an http.Client configured with the specified proxy URL.
func (p *LocalProxy) createProxyClient(proxyURL string) *http.Client {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return p.httpClient // Fallback to default
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(parsed),
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
		WriteBufferSize:     64 * 1024,
		ReadBufferSize:      64 * 1024,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   p.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// dialThroughHTTPProxy connects to the target through an HTTP proxy using CONNECT.
func (p *LocalProxy) dialThroughHTTPProxy(ctx context.Context, proxyURL, targetAddr string) (net.Conn, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	proxyHost := parsed.Host
	if parsed.Port() == "" {
		if parsed.Scheme == "https" {
			proxyHost = net.JoinHostPort(parsed.Hostname(), "443")
		} else {
			proxyHost = net.JoinHostPort(parsed.Hostname(), "80")
		}
	}

	// Connect to proxy
	dialer := &net.Dialer{
		Timeout:   p.timeout,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	// Add proxy authentication if provided
	if parsed.User != nil {
		username := parsed.User.Username()
		password, _ := parsed.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT: %w", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read proxy response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	return conn, nil
}

// extractUpstreamProxy extracts upstream proxy URL from request headers.
// Priority: Proxy-Authorization (HTTPCloak scheme) > X-Upstream-Proxy header
//
// Supported formats:
//   - Proxy-Authorization: HTTPCloak http://user:pass@proxy:8080
//   - X-Upstream-Proxy: http://user:pass@proxy:8080
func (p *LocalProxy) extractUpstreamProxy(req *http.Request) string {
	// Check Proxy-Authorization header first (works for CONNECT requests)
	proxyAuth := req.Header.Get("Proxy-Authorization")
	if proxyAuth != "" {
		// Parse "HTTPCloak <proxy-url>" format
		if strings.HasPrefix(proxyAuth, ProxyAuthScheme+" ") {
			proxyURL := strings.TrimPrefix(proxyAuth, ProxyAuthScheme+" ")
			proxyURL = strings.TrimSpace(proxyURL)
			if proxyURL != "" {
				return proxyURL
			}
		}
	}

	// Fallback to X-Upstream-Proxy header
	return req.Header.Get(HeaderUpstreamProxy)
}

// extractTLSOnly extracts the per-request TLS-only mode override.
// Returns (value, exists):
//   - ("true", true): Enable TLS-only mode for this request
//   - ("false", true): Disable TLS-only mode for this request
//   - ("", false): No override, use proxy's global setting
func (p *LocalProxy) extractTLSOnly(req *http.Request) (bool, bool) {
	value := req.Header.Get(HeaderTLSOnly)
	if value == "" {
		return false, false // No override
	}
	return strings.EqualFold(value, "true"), true
}

// tunnel performs bidirectional data transfer with large buffers
func (p *LocalProxy) tunnel(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Large buffer for high throughput
	const bufSize = 64 * 1024 // 64KB

	// Client -> Target
	go func() {
		defer wg.Done()
		buf := make([]byte, bufSize)
		io.CopyBuffer(target, client, buf)
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		buf := make([]byte, bufSize)
		io.CopyBuffer(client, target, buf)
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

// isPortAllowed checks if a port is allowed
func (p *LocalProxy) isPortAllowed(port string) bool {
	blocked := map[string]bool{
		"25": true, "465": true, "587": true, // SMTP
		"23": true, // Telnet
	}
	return !blocked[port]
}

// sendError sends an HTTP error response
func (p *LocalProxy) sendError(conn net.Conn, status int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(message), message)
	conn.Write([]byte(response))
}

// isHopByHopHeader returns true for hop-by-hop headers that shouldn't be forwarded
func isHopByHopHeader(header string) bool {
	hopByHop := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Proxy-Connection":    true,
		"Te":                  true,
		"Trailer":             true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}
	return hopByHop[http.CanonicalHeaderKey(header)]
}
