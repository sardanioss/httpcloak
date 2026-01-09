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
	"context"
	"time"

	"github.com/sardanioss/httpcloak/client"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/session"
	"github.com/sardanioss/httpcloak/transport"
)

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
//   - "chrome-131" (recommended)
//   - "chrome-131-windows"
//   - "chrome-131-macos"
//   - "chrome-133"
//   - "chrome-133-windows"
//
// Example:
//
//	client := httpcloak.New("chrome-131")
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
	Headers map[string]string
	Body    []byte
	Timeout time.Duration
}

// RedirectInfo contains information about a redirect response
type RedirectInfo struct {
	StatusCode int
	URL        string
	Headers    map[string]string
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
	FinalURL   string
	Protocol   string
	History    []*RedirectInfo
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
func (c *Client) GetWithHeaders(ctx context.Context, url string, headers map[string]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, url string, body []byte, contentType string) (*Response, error) {
	headers := map[string]string{}
	if contentType != "" {
		headers["Content-Type"] = contentType
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
	return c.Post(ctx, url, body, "application/json")
}

// PostForm performs a POST request with form data
func (c *Client) PostForm(ctx context.Context, url string, body []byte) (*Response, error) {
	return c.Post(ctx, url, body, "application/x-www-form-urlencoded")
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
}

// WithSessionProxy sets a proxy for the session
func WithSessionProxy(proxyURL string) SessionOption {
	return func(c *sessionConfig) {
		c.proxy = proxyURL
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
		Timeout:            int(cfg.timeout.Seconds()),
		InsecureSkipVerify: cfg.insecureSkipVerify,
		FollowRedirects:    !cfg.disableRedirects,
		MaxRedirects:       cfg.maxRedirects,
		PreferIPv4:         cfg.preferIPv4,
		ConnectTo:          cfg.connectTo,
		ECHConfigDomain:    cfg.echConfigDomain,
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
	if cfg.forceHTTP1 || cfg.forceHTTP2 {
		sessionCfg.DisableHTTP3 = true
	}
	if cfg.forceHTTP3 {
		sessionCfg.ForceHTTP3 = true
	}

	s := session.NewSession("", sessionCfg)
	return &Session{inner: s}
}

// Do executes a request within the session, maintaining cookies
func (s *Session) Do(ctx context.Context, req *Request) (*Response, error) {
	sReq := &transport.Request{
		Method:  req.Method,
		URL:     req.URL,
		Headers: req.Headers,
		Body:    req.Body,
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

// Close closes the session and releases resources
func (s *Session) Close() {
	s.inner.Close()
}

// Presets returns available fingerprint presets
func Presets() []string {
	return fingerprint.Available()
}
