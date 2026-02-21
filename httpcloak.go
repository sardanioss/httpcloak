// Package httpcloak provides an HTTP client with perfect browser TLS/HTTP fingerprinting.
//
// httpcloak allows you to make HTTP requests that are indistinguishable from real browsers,
// bypassing TLS fingerprinting, HTTP/2 fingerprinting, and header-based bot detection.
//
// Basic usage:
//
//	client := httpcloak.New("chrome-131")
//	defer client.Close()
//
//	resp, err := client.Get(ctx, "https://example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(string(resp.Body))
//
// With options:
//
//	client := httpcloak.New("chrome-131",
//	    httpcloak.WithTimeout(30*time.Second),
//	    httpcloak.WithProxy("http://user:pass@proxy:8080"),
//	)
package httpcloak

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak/client"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/session"
	"github.com/sardanioss/httpcloak/transport"
)

// systemRoots is pre-loaded at init time to avoid ~40ms delay on first TLS connection
var systemRoots *x509.CertPool

func init() {
	// Pre-load system root CA certificates at package init time.
	// This normally takes ~40ms on first TLS connection, so we do it eagerly.
	// The result is cached by the Go runtime, so subsequent calls are instant.
	systemRoots, _ = x509.SystemCertPool()
}

// Client is an HTTP client with browser fingerprint spoofing
type Client struct {
	inner   *client.Client
	timeout time.Duration
}

// Option configures the Client
type Option func(*clientConfig)

type clientConfig struct {
	timeout time.Duration
	proxy   string
}

// WithTimeout sets the request timeout
func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) {
		c.timeout = d
	}
}

// WithProxy sets an HTTP/HTTPS/SOCKS5 proxy
func WithProxy(proxyURL string) Option {
	return func(c *clientConfig) {
		c.proxy = proxyURL
	}
}

// New creates a new HTTP client with the specified browser fingerprint.
//
// Available presets:
//   - "chrome-latest" (recommended), "chrome-latest-windows", "chrome-latest-linux", "chrome-latest-macos"
//   - "chrome-144", "chrome-143", "chrome-141", "chrome-133"
//   - "firefox-latest", "firefox-133"
//   - "safari-latest", "safari-18"
//   - "ios-chrome-latest", "ios-safari-latest"
//   - "android-chrome-latest"
//
// The -latest aliases always resolve to the newest version in the library.
//
// Example:
//
//	client := httpcloak.New("chrome-latest")
//	defer client.Close()
func New(preset string, opts ...Option) *Client {
	cfg := &clientConfig{
		timeout: 30 * time.Second,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Build client options
	var clientOpts []client.Option
	if cfg.proxy != "" {
		clientOpts = append(clientOpts, client.WithProxy(cfg.proxy))
	}

	return &Client{
		inner:   client.NewClient(preset, clientOpts...),
		timeout: cfg.timeout,
	}
}

// Request represents an HTTP request
type Request struct {
	Method  string
	URL     string
	Headers map[string][]string // Multi-value headers (matches http.Header)
	Body    io.Reader           // Streaming body for uploads
	Timeout time.Duration

	// TLSOnly is a per-request override for TLS-only mode.
	// When set to true, preset HTTP headers are NOT applied - only TLS fingerprinting is used.
	// When nil, the session's TLSOnly setting is used.
	// This is useful for LocalProxy where each request can have different TLS-only settings
	// via the X-HTTPCloak-TlsOnly header.
	TLSOnly *bool
}

// RedirectInfo contains information about a redirect response
type RedirectInfo struct {
	StatusCode int
	URL        string
	Headers    map[string][]string // Multi-value headers
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Headers    map[string][]string // Multi-value headers (matches http.Header)
	Body       io.ReadCloser       // Streaming body - call Close() when done
	FinalURL   string
	Protocol   string
	History    []*RedirectInfo

	// bodyBytes caches the body after reading
	bodyBytes []byte
	bodyRead  bool
}

// Close closes the response body.
func (r *Response) Close() error {
	if r.Body != nil {
		return r.Body.Close()
	}
	return nil
}

// Bytes reads and returns the entire response body.
// The body can only be read once unless cached.
func (r *Response) Bytes() ([]byte, error) {
	if r.bodyRead {
		return r.bodyBytes, nil
	}
	if r.Body == nil {
		return nil, nil
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body.Close()
	r.bodyBytes = data
	r.bodyRead = true
	return data, nil
}

// Text reads and returns the response body as a string.
func (r *Response) Text() (string, error) {
	data, err := r.Bytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// JSON decodes the response body into the given interface.
func (r *Response) JSON(v interface{}) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// GetHeader returns the first value for the given header key.
func (r *Response) GetHeader(key string) string {
	if values := r.Headers[strings.ToLower(key)]; len(values) > 0 {
		return values[0]
	}
	return ""
}

// GetHeaders returns all values for the given header key.
func (r *Response) GetHeaders(key string) []string {
	return r.Headers[strings.ToLower(key)]
}

// Do executes an HTTP request
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	timeout := req.Timeout
	if timeout == 0 {
		timeout = c.timeout
	}

	cReq := &client.Request{
		Method:  req.Method,
		URL:     req.URL,
		Headers: req.Headers,
		Body:    req.Body,
		Timeout: timeout,
	}

	resp, err := c.inner.Do(ctx, cReq)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
		FinalURL:   resp.FinalURL,
		Protocol:   resp.Protocol,
	}, nil
}

// Get performs a GET request
func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method: "GET",
		URL:    url,
	})
}

// GetWithHeaders performs a GET request with custom headers
func (c *Client) GetWithHeaders(ctx context.Context, url string, headers map[string][]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, url string, body io.Reader, contentType string) (*Response, error) {
	headers := map[string][]string{}
	if contentType != "" {
		headers["Content-Type"] = []string{contentType}
	}
	return c.Do(ctx, &Request{
		Method:  "POST",
		URL:     url,
		Headers: headers,
		Body:    body,
	})
}

// PostJSON performs a POST request with JSON body
func (c *Client) PostJSON(ctx context.Context, url string, body []byte) (*Response, error) {
	return c.Post(ctx, url, bytes.NewReader(body), "application/json")
}

// PostForm performs a POST request with form data
func (c *Client) PostForm(ctx context.Context, url string, body []byte) (*Response, error) {
	return c.Post(ctx, url, bytes.NewReader(body), "application/x-www-form-urlencoded")
}

// Close releases all resources held by the client
func (c *Client) Close() {
	c.inner.Close()
}

// Session represents a persistent HTTP session with cookie management
type Session struct {
	inner *session.Session
}

// SessionOption configures a session
type SessionOption func(*sessionConfig)

type sessionConfig struct {
	preset             string
	proxy              string
	tcpProxy           string // Proxy for TCP-based protocols (HTTP/1.1, HTTP/2)
	udpProxy           string // Proxy for UDP-based protocols (HTTP/3 via MASQUE)
	timeout            time.Duration
	forceHTTP1         bool
	forceHTTP2         bool
	forceHTTP3         bool
	insecureSkipVerify bool
	disableRedirects   bool
	maxRedirects       int
	retryCount         int
	retryWaitMin       time.Duration
	retryWaitMax       time.Duration
	retryOnStatus      []int
	preferIPv4         bool
	connectTo          map[string]string // Domain fronting: request_host -> connect_host
	echConfigDomain    string            // Domain to fetch ECH config from
	tlsOnly            bool              // TLS-only mode: skip preset headers, set all manually
	quicIdleTimeout    time.Duration     // QUIC idle timeout (default: 30s)
	localAddr          string            // Local IP address to bind outgoing connections
	keyLogFile         string            // Path to write TLS key log for Wireshark decryption
	disableECH            bool   // Disable ECH lookup for faster first request
	enableSpeculativeTLS bool   // Enable speculative TLS optimization for proxy connections
	switchProtocol        string // Protocol to switch to after Refresh() (e.g. "h1", "h2", "h3")

	// Distributed session cache
	sessionCacheBackend       transport.SessionCacheBackend
	sessionCacheErrorCallback transport.ErrorCallback
}

// WithSessionProxy sets a proxy for the session
func WithSessionProxy(proxyURL string) SessionOption {
	return func(c *sessionConfig) {
		c.proxy = proxyURL
	}
}

// WithSessionTCPProxy sets a proxy for TCP-based protocols (HTTP/1.1 and HTTP/2).
// Use this with WithSessionUDPProxy for split proxy configuration.
func WithSessionTCPProxy(proxyURL string) SessionOption {
	return func(c *sessionConfig) {
		c.tcpProxy = proxyURL
	}
}

// WithSessionUDPProxy sets a proxy for UDP-based protocols (HTTP/3 via MASQUE).
// Use this with WithSessionTCPProxy for split proxy configuration.
func WithSessionUDPProxy(proxyURL string) SessionOption {
	return func(c *sessionConfig) {
		c.udpProxy = proxyURL
	}
}

// WithSessionTimeout sets the timeout for session requests
func WithSessionTimeout(d time.Duration) SessionOption {
	return func(c *sessionConfig) {
		c.timeout = d
	}
}

// WithForceHTTP1 forces HTTP/1.1 protocol
func WithForceHTTP1() SessionOption {
	return func(c *sessionConfig) {
		c.forceHTTP1 = true
	}
}

// WithForceHTTP2 forces HTTP/2 protocol
func WithForceHTTP2() SessionOption {
	return func(c *sessionConfig) {
		c.forceHTTP2 = true
	}
}

// WithForceHTTP3 forces HTTP/3 protocol (QUIC)
func WithForceHTTP3() SessionOption {
	return func(c *sessionConfig) {
		c.forceHTTP3 = true
	}
}

// WithInsecureSkipVerify disables SSL certificate verification
func WithInsecureSkipVerify() SessionOption {
	return func(c *sessionConfig) {
		c.insecureSkipVerify = true
	}
}

// WithoutRedirects disables automatic redirect following
func WithoutRedirects() SessionOption {
	return func(c *sessionConfig) {
		c.disableRedirects = true
	}
}

// WithRedirects configures redirect behavior
func WithRedirects(follow bool, maxRedirects int) SessionOption {
	return func(c *sessionConfig) {
		c.disableRedirects = !follow
		c.maxRedirects = maxRedirects
	}
}

// WithRetry enables retry with default settings
func WithRetry(count int) SessionOption {
	return func(c *sessionConfig) {
		c.retryCount = count
	}
}

// WithoutRetry explicitly disables retry
func WithoutRetry() SessionOption {
	return func(c *sessionConfig) {
		c.retryCount = 0
	}
}

// WithRetryConfig configures retry behavior
func WithRetryConfig(count int, waitMin, waitMax time.Duration, retryOnStatus []int) SessionOption {
	return func(c *sessionConfig) {
		c.retryCount = count
		c.retryWaitMin = waitMin
		c.retryWaitMax = waitMax
		c.retryOnStatus = retryOnStatus
	}
}

// WithSessionPreferIPv4 makes the session prefer IPv4 addresses over IPv6.
// Use this on networks with poor IPv6 connectivity.
func WithSessionPreferIPv4() SessionOption {
	return func(c *sessionConfig) {
		c.preferIPv4 = true
	}
}

// WithLocalAddress binds outgoing connections to a specific local IP address.
// Useful for IPv6 rotation when you have a large IPv6 prefix and want to
// rotate source IPs per session. Works with IP_FREEBIND on Linux.
// Supports both IPv4 and IPv6 addresses (e.g., "192.168.1.100" or "2001:db8::1").
func WithLocalAddress(addr string) SessionOption {
	return func(c *sessionConfig) {
		c.localAddr = addr
	}
}

// WithKeyLogFile sets the path to write TLS key log for Wireshark decryption.
// This overrides the global SSLKEYLOGFILE environment variable for this session.
func WithKeyLogFile(path string) SessionOption {
	return func(c *sessionConfig) {
		c.keyLogFile = path
	}
}

// WithDisableECH disables ECH (Encrypted Client Hello) lookup for faster first request.
// ECH is an optional privacy feature that adds ~15-20ms to first connection.
// Disabling it has no security impact, only privacy implications.
func WithDisableECH() SessionOption {
	return func(c *sessionConfig) {
		c.disableECH = true
	}
}

// WithEnableSpeculativeTLS enables the speculative TLS optimization for proxy connections.
// When enabled, the CONNECT request and TLS ClientHello are sent together, saving one
// round-trip (~25% faster). Disabled by default due to compatibility issues with some proxies.
func WithEnableSpeculativeTLS() SessionOption {
	return func(c *sessionConfig) {
		c.enableSpeculativeTLS = true
	}
}

// WithSwitchProtocol sets the protocol to switch to after Refresh().
// This enables warming up TLS tickets on one protocol (e.g. H3) then serving
// requests on another (e.g. H2) with TLS session resumption.
// Valid values: "h1", "h2", "h3".
func WithSwitchProtocol(protocol string) SessionOption {
	return func(c *sessionConfig) {
		c.switchProtocol = protocol
	}
}

// WithConnectTo sets a host mapping for domain fronting.
// Requests to requestHost will connect to connectHost instead.
// The TLS SNI and Host header will still use requestHost.
func WithConnectTo(requestHost, connectHost string) SessionOption {
	return func(c *sessionConfig) {
		if c.connectTo == nil {
			c.connectTo = make(map[string]string)
		}
		c.connectTo[requestHost] = connectHost
	}
}

// WithECHFrom sets a domain to fetch ECH config from.
// Instead of fetching ECH from the target domain's DNS,
// the config will be fetched from this domain.
// Useful for Cloudflare domains - use "cloudflare-ech.com" to get
// ECH config that works for any Cloudflare-proxied domain.
func WithECHFrom(domain string) SessionOption {
	return func(c *sessionConfig) {
		c.echConfigDomain = domain
	}
}

// WithTLSOnly enables TLS-only mode.
// In this mode, the preset's TLS fingerprint is used but its default HTTP headers
// are NOT applied. You must set all headers manually per-request.
// Useful when you need full control over HTTP headers while keeping the TLS fingerprint.
func WithTLSOnly() SessionOption {
	return func(c *sessionConfig) {
		c.tlsOnly = true
	}
}

// WithQuicIdleTimeout sets the QUIC connection idle timeout.
// Default is 30 seconds (matches Chrome). Connections are closed after
// this duration of inactivity. Set higher values if you need longer-lived
// HTTP/3 connections with gaps between requests.
func WithQuicIdleTimeout(d time.Duration) SessionOption {
	return func(c *sessionConfig) {
		c.quicIdleTimeout = d
	}
}

// WithSessionCache sets a distributed TLS session cache backend.
// This enables TLS session ticket sharing across multiple instances (e.g., via Redis).
// The errorCallback is optional and will be called when backend operations fail.
func WithSessionCache(backend transport.SessionCacheBackend, errorCallback transport.ErrorCallback) SessionOption {
	return func(c *sessionConfig) {
		c.sessionCacheBackend = backend
		c.sessionCacheErrorCallback = errorCallback
	}
}

// NewSession creates a new persistent session with cookie management
func NewSession(preset string, opts ...SessionOption) *Session {
	cfg := &sessionConfig{
		preset:  preset,
		timeout: 30 * time.Second,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	sessionCfg := &protocol.SessionConfig{
		Preset:             cfg.preset,
		Proxy:              cfg.proxy,
		TCPProxy:           cfg.tcpProxy,
		UDPProxy:           cfg.udpProxy,
		Timeout:            int(cfg.timeout.Seconds()),
		InsecureSkipVerify: cfg.insecureSkipVerify,
		FollowRedirects:    !cfg.disableRedirects,
		MaxRedirects:       cfg.maxRedirects,
		PreferIPv4:         cfg.preferIPv4,
		ConnectTo:          cfg.connectTo,
		ECHConfigDomain:    cfg.echConfigDomain,
		TLSOnly:            cfg.tlsOnly,
		QuicIdleTimeout:    int(cfg.quicIdleTimeout.Seconds()),
		LocalAddress:       cfg.localAddr,
		KeyLogFile:         cfg.keyLogFile,
		DisableECH:            cfg.disableECH,
		EnableSpeculativeTLS: cfg.enableSpeculativeTLS,
		SwitchProtocol:        cfg.switchProtocol,
	}

	// Retry configuration
	if cfg.retryCount > 0 {
		sessionCfg.RetryEnabled = true
		sessionCfg.MaxRetries = cfg.retryCount
		if cfg.retryWaitMin > 0 {
			sessionCfg.RetryWaitMin = int(cfg.retryWaitMin.Milliseconds())
		}
		if cfg.retryWaitMax > 0 {
			sessionCfg.RetryWaitMax = int(cfg.retryWaitMax.Milliseconds())
		}
		if len(cfg.retryOnStatus) > 0 {
			sessionCfg.RetryOnStatus = cfg.retryOnStatus
		}
	}

	// Protocol forcing
	if cfg.forceHTTP1 {
		sessionCfg.ForceHTTP1 = true
		sessionCfg.DisableHTTP3 = true
	}
	if cfg.forceHTTP2 {
		sessionCfg.ForceHTTP2 = true
		sessionCfg.DisableHTTP3 = true
	}
	if cfg.forceHTTP3 {
		sessionCfg.ForceHTTP3 = true
	}

	// Create session with optional distributed cache
	var s *session.Session
	if cfg.sessionCacheBackend != nil {
		opts := &session.SessionOptions{
			SessionCacheBackend:       cfg.sessionCacheBackend,
			SessionCacheErrorCallback: cfg.sessionCacheErrorCallback,
		}
		s = session.NewSessionWithOptions("", sessionCfg, opts)
	} else {
		s = session.NewSession("", sessionCfg)
	}
	return &Session{inner: s}
}

// Do executes a request within the session, maintaining cookies
func (s *Session) Do(ctx context.Context, req *Request) (*Response, error) {
	sReq := &transport.Request{
		Method:     req.Method,
		URL:        req.URL,
		Headers:    req.Headers,
		BodyReader: req.Body,
		TLSOnly:    req.TLSOnly,
	}

	resp, err := s.inner.Request(ctx, sReq)
	if err != nil {
		return nil, err
	}

	// Convert redirect history
	var history []*RedirectInfo
	if len(resp.History) > 0 {
		history = make([]*RedirectInfo, len(resp.History))
		for i, h := range resp.History {
			history[i] = &RedirectInfo{
				StatusCode: h.StatusCode,
				URL:        h.URL,
				Headers:    h.Headers,
			}
		}
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
		FinalURL:   resp.FinalURL,
		Protocol:   resp.Protocol,
		History:    history,
	}, nil
}

// DoWithBody executes a request with an io.Reader as the body for streaming uploads
func (s *Session) DoWithBody(ctx context.Context, req *Request, bodyReader io.Reader) (*Response, error) {
	sReq := &transport.Request{
		Method:     req.Method,
		URL:        req.URL,
		Headers:    req.Headers,
		BodyReader: bodyReader,
		TLSOnly:    req.TLSOnly,
	}

	resp, err := s.inner.Request(ctx, sReq)
	if err != nil {
		return nil, err
	}

	// Convert redirect history
	var history []*RedirectInfo
	if len(resp.History) > 0 {
		history = make([]*RedirectInfo, len(resp.History))
		for i, h := range resp.History {
			history[i] = &RedirectInfo{
				StatusCode: h.StatusCode,
				URL:        h.URL,
				Headers:    h.Headers,
			}
		}
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
		FinalURL:   resp.FinalURL,
		Protocol:   resp.Protocol,
		History:    history,
	}, nil
}

// Get performs a GET request within the session
func (s *Session) Get(ctx context.Context, url string) (*Response, error) {
	return s.Do(ctx, &Request{Method: "GET", URL: url})
}

// GetCookies returns all cookies stored in the session
func (s *Session) GetCookies() map[string]string {
	return s.inner.GetCookies()
}

// SetCookie sets a cookie in the session
func (s *Session) SetCookie(name, value string) {
	s.inner.SetCookie(name, value)
}

// SetProxy sets or updates the proxy for all protocols (HTTP/1.1, HTTP/2, HTTP/3)
// This closes existing connections and recreates transports with the new proxy
// Pass empty string to switch to direct connection
func (s *Session) SetProxy(proxyURL string) {
	s.inner.SetProxy(proxyURL)
}

// SetTCPProxy sets the proxy for TCP protocols (HTTP/1.1, HTTP/2)
func (s *Session) SetTCPProxy(proxyURL string) {
	s.inner.SetTCPProxy(proxyURL)
}

// SetUDPProxy sets the proxy for UDP protocols (HTTP/3 via SOCKS5 or MASQUE)
func (s *Session) SetUDPProxy(proxyURL string) {
	s.inner.SetUDPProxy(proxyURL)
}

// GetProxy returns the current proxy URL (unified proxy or TCP proxy)
func (s *Session) GetProxy() string {
	return s.inner.GetProxy()
}

// GetTCPProxy returns the current TCP proxy URL
func (s *Session) GetTCPProxy() string {
	return s.inner.GetTCPProxy()
}

// GetUDPProxy returns the current UDP proxy URL
func (s *Session) GetUDPProxy() string {
	return s.inner.GetUDPProxy()
}

// SetHeaderOrder sets a custom header order for all requests.
// Pass nil or empty slice to reset to preset's default order.
// Order should contain lowercase header names.
func (s *Session) SetHeaderOrder(order []string) {
	s.inner.SetHeaderOrder(order)
}

// GetHeaderOrder returns the current header order.
// Returns preset's default order if no custom order is set.
func (s *Session) GetHeaderOrder() []string {
	return s.inner.GetHeaderOrder()
}

// SetSessionIdentifier sets a session identifier for TLS cache key isolation.
// This is used when the session is registered with a LocalProxy to ensure
// TLS sessions are isolated per proxy/session configuration in distributed caches.
func (s *Session) SetSessionIdentifier(sessionId string) {
	s.inner.SetSessionIdentifier(sessionId)
}

// Warmup simulates a real browser page load to warm TLS sessions, cookies,
// and cache state. Fetches the HTML page and its subresources (CSS, JS, images)
// with realistic headers, priorities, and timing.
func (s *Session) Warmup(ctx context.Context, url string) error {
	return s.inner.Warmup(ctx, url)
}

// Fork creates n new sessions that share cookies and TLS session caches with
// the parent, but have independent connections. This simulates multiple browser
// tabs — same cookies, same TLS resumption tickets, same fingerprint, but
// independent TCP/QUIC connections for parallel requests.
func (s *Session) Fork(n int) []*Session {
	innerForks := s.inner.Fork(n)
	if innerForks == nil {
		return nil
	}
	forks := make([]*Session, len(innerForks))
	for i, inner := range innerForks {
		forks[i] = &Session{inner: inner}
	}
	return forks
}

// Close closes the session and releases resources
func (s *Session) Close() {
	s.inner.Close()
}

// Refresh closes all connections but keeps TLS session caches and cookies intact.
// This simulates a browser page refresh - new TCP/QUIC connections but TLS resumption.
// If a switchProtocol was configured, the session switches to that protocol.
func (s *Session) Refresh() {
	s.inner.Refresh()
}

// RefreshWithProtocol closes all connections and switches to a new protocol.
// The protocol change persists for future Refresh() calls as well.
// Valid protocols: "h1", "h2", "h3", "auto".
func (s *Session) RefreshWithProtocol(protocol string) error {
	return s.inner.RefreshWithProtocol(protocol)
}

// Save exports session state (cookies, TLS sessions) to a file
func (s *Session) Save(path string) error {
	return s.inner.Save(path)
}

// Marshal exports session state to JSON bytes
func (s *Session) Marshal() ([]byte, error) {
	return s.inner.Marshal()
}

// LoadSession loads a session from a file
func LoadSession(path string) (*Session, error) {
	inner, err := session.LoadSession(path)
	if err != nil {
		return nil, err
	}
	return &Session{inner: inner}, nil
}

// UnmarshalSession loads a session from JSON bytes
func UnmarshalSession(data []byte) (*Session, error) {
	inner, err := session.UnmarshalSession(data)
	if err != nil {
		return nil, err
	}
	return &Session{inner: inner}, nil
}

// StreamResponse represents a streaming HTTP response where the body
// is read incrementally. Use this for large file downloads.
type StreamResponse struct {
	StatusCode    int
	Headers       map[string][]string
	FinalURL      string
	Protocol      string
	ContentLength int64 // -1 if unknown (chunked encoding)

	inner *transport.StreamResponse
}

// Read reads data from the response body
func (r *StreamResponse) Read(p []byte) (n int, err error) {
	return r.inner.Read(p)
}

// Close closes the response body - must be called when done
func (r *StreamResponse) Close() error {
	return r.inner.Close()
}

// ReadAll reads the entire response body into memory
// This defeats the purpose of streaming but is useful for small responses
func (r *StreamResponse) ReadAll() ([]byte, error) {
	return r.inner.ReadAll()
}

// ReadChunk reads up to size bytes from the response
func (r *StreamResponse) ReadChunk(size int) ([]byte, error) {
	return r.inner.ReadChunk(size)
}

// DoStream executes an HTTP request and returns a streaming response
// The caller is responsible for closing the response when done
// Note: Streaming does NOT support redirects - use Do() for redirect handling
func (s *Session) DoStream(ctx context.Context, req *Request) (*StreamResponse, error) {
	sReq := &transport.Request{
		Method:     req.Method,
		URL:        req.URL,
		Headers:    req.Headers,
		BodyReader: req.Body,
		TLSOnly:    req.TLSOnly,
	}

	resp, err := s.inner.RequestStream(ctx, sReq)
	if err != nil {
		return nil, err
	}

	return &StreamResponse{
		StatusCode:    resp.StatusCode,
		Headers:       resp.Headers,
		FinalURL:      resp.FinalURL,
		Protocol:      resp.Protocol,
		ContentLength: resp.ContentLength,
		inner:         resp,
	}, nil
}

// GetStream performs a streaming GET request
func (s *Session) GetStream(ctx context.Context, url string) (*StreamResponse, error) {
	return s.DoStream(ctx, &Request{Method: "GET", URL: url})
}

// GetStreamWithHeaders performs a streaming GET request with custom headers
func (s *Session) GetStreamWithHeaders(ctx context.Context, url string, headers map[string][]string) (*StreamResponse, error) {
	return s.DoStream(ctx, &Request{Method: "GET", URL: url, Headers: headers})
}

// Presets returns available fingerprint presets
func Presets() []string {
	return fingerprint.Available()
}
