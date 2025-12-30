// Package client provides an HTTP client with browser TLS/HTTP fingerprint spoofing.
//
// This package is the core of httpcloak. It provides an HTTP client that mimics
// real browser fingerprints at the TLS and HTTP/2 protocol levels, making requests
// indistinguishable from actual Chrome, Firefox, or Safari browsers.
//
// # Why Fingerprint Spoofing Matters
//
// Modern bot detection systems analyze multiple layers of your HTTP connection:
//
//  1. TLS Fingerprint (JA3/JA4): Cipher suites, extensions, elliptic curves
//  2. HTTP/2 Fingerprint (Akamai): SETTINGS frame values, WINDOW_UPDATE, PRIORITY
//  3. Header Fingerprint: Order, format, and values of HTTP headers
//
// Go's standard library has a distinct fingerprint that bot detection systems
// (Cloudflare, Akamai, PerimeterX) can identify instantly. This package solves
// that by using uTLS for TLS spoofing and custom HTTP/2 framing.
//
// # Basic Usage
//
//	c := client.NewClient("chrome-143")
//	defer c.Close()
//
//	resp, err := c.Get(ctx, "https://example.com", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(resp.Text())
//
// # Session Usage (with cookies)
//
//	session := client.NewSession("chrome-143")
//	defer session.Close()
//
//	// Login - cookies are persisted
//	session.Post(ctx, "https://example.com/login", body, headers)
//
//	// Subsequent requests include cookies
//	resp, _ := session.Get(ctx, "https://example.com/dashboard", nil)
package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/pool"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// Note: As of Go 1.20, the global random generator is automatically seeded.
// No manual seeding needed for organic jitter in header values.

// Client is an HTTP client with connection pooling and fingerprint spoofing
// By default, it tries HTTP/3 first, then HTTP/2, then HTTP/1.1 as fallback
type Client struct {
	poolManager *pool.Manager
	quicManager *pool.QUICManager
	h1Transport *transport.HTTP1Transport
	preset      *fingerprint.Preset
	config      *ClientConfig

	// Authentication
	auth Auth

	// Cookie jar for session persistence (nil = no cookie handling)
	cookies *CookieJar

	// Request hooks for pre/post processing
	hooks *Hooks

	// Certificate pinning
	certPinner *CertPinner

	// Track which hosts don't support HTTP/3 to avoid repeated failures
	h3Failures   map[string]time.Time
	h3FailuresMu sync.RWMutex

	// Track which hosts need HTTP/1.1 (don't support HTTP/2)
	h2Failures   map[string]time.Time
	h2FailuresMu sync.RWMutex
}

// NewClient creates a new HTTP client with default configuration
// Tries HTTP/3 first, then HTTP/2, then HTTP/1.1 as fallback
func NewClient(presetName string, opts ...Option) *Client {
	config := DefaultConfig()
	config.Preset = presetName
	for _, opt := range opts {
		opt(config)
	}

	preset := fingerprint.Get(config.Preset)

	var h2Manager *pool.Manager
	if config.Proxy != "" {
		h2Manager = pool.NewManagerWithProxy(preset, config.Proxy, config.InsecureSkipVerify)
	} else {
		h2Manager = pool.NewManagerWithTLSConfig(preset, config.InsecureSkipVerify)
	}

	// Only create QUIC manager if H3 is not disabled AND no proxy is configured
	// QUIC uses UDP and cannot be tunneled through HTTP proxies
	var quicManager *pool.QUICManager
	if !config.DisableH3 && config.Proxy == "" {
		quicManager = pool.NewQUICManager(preset, h2Manager.GetDNSCache())
	}

	// Create HTTP/1.1 transport for fallback or when explicitly requested
	var proxyConfig *transport.ProxyConfig
	if config.Proxy != "" {
		proxyConfig = &transport.ProxyConfig{URL: config.Proxy}
	}
	h1Transport := transport.NewHTTP1TransportWithProxy(preset, h2Manager.GetDNSCache(), proxyConfig)
	h1Transport.SetInsecureSkipVerify(config.InsecureSkipVerify)

	return &Client{
		poolManager: h2Manager,
		quicManager: quicManager,
		h1Transport: h1Transport,
		preset:      preset,
		config:      config,
		h3Failures:  make(map[string]time.Time),
		h2Failures:  make(map[string]time.Time),
	}
}

// NewSession creates a new HTTP client with cookie jar enabled (like requests.Session())
// Cookies are automatically persisted between requests
func NewSession(presetName string, opts ...Option) *Client {
	client := NewClient(presetName, opts...)
	client.cookies = NewCookieJar()
	return client
}

// SetPreset changes the fingerprint preset
func (c *Client) SetPreset(presetName string) {
	c.preset = fingerprint.Get(presetName)
	c.poolManager.SetPreset(c.preset)
}

// SetTimeout sets the request timeout
func (c *Client) SetTimeout(timeout time.Duration) {
	c.config.Timeout = timeout
}

// SetAuth sets authentication for all requests
func (c *Client) SetAuth(auth Auth) {
	c.auth = auth
}

// SetBasicAuth sets Basic authentication
func (c *Client) SetBasicAuth(username, password string) {
	c.auth = NewBasicAuth(username, password)
}

// SetBearerAuth sets Bearer token authentication
func (c *Client) SetBearerAuth(token string) {
	c.auth = NewBearerAuth(token)
}

// EnableCookies enables cookie jar for session persistence
func (c *Client) EnableCookies() {
	if c.cookies == nil {
		c.cookies = NewCookieJar()
	}
}

// DisableCookies disables cookie handling
func (c *Client) DisableCookies() {
	c.cookies = nil
}

// Cookies returns the cookie jar (nil if cookies are disabled)
func (c *Client) Cookies() *CookieJar {
	return c.cookies
}

// ClearCookies removes all cookies from the jar
func (c *Client) ClearCookies() {
	if c.cookies != nil {
		c.cookies.Clear()
	}
}

// Hooks returns the client's hooks instance, creating one if needed
func (c *Client) Hooks() *Hooks {
	if c.hooks == nil {
		c.hooks = NewHooks()
	}
	return c.hooks
}

// OnPreRequest adds a pre-request hook
// Hook is called before each request is sent
func (c *Client) OnPreRequest(hook PreRequestHook) *Client {
	c.Hooks().OnPreRequest(hook)
	return c
}

// OnPostResponse adds a post-response hook
// Hook is called after each response is received
func (c *Client) OnPostResponse(hook PostResponseHook) *Client {
	c.Hooks().OnPostResponse(hook)
	return c
}

// ClearHooks removes all hooks
func (c *Client) ClearHooks() {
	if c.hooks != nil {
		c.hooks.Clear()
	}
}

// CertPinner returns the certificate pinner, creating one if needed
func (c *Client) CertPinner() *CertPinner {
	if c.certPinner == nil {
		c.certPinner = NewCertPinner()
	}
	return c.certPinner
}

// PinCertificate adds a certificate pin
// hash should be base64-encoded SHA256 of the certificate's SPKI
// Example: c.PinCertificate("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ForHost("example.com"))
func (c *Client) PinCertificate(hash string, opts ...PinOption) *Client {
	c.CertPinner().AddPin(hash, opts...)
	return c
}

// PinCertificateFromFile loads a certificate from file and pins its public key
func (c *Client) PinCertificateFromFile(certPath string, opts ...PinOption) error {
	return c.CertPinner().AddPinFromCertFile(certPath, opts...)
}

// ClearPins removes all certificate pins
func (c *Client) ClearPins() {
	if c.certPinner != nil {
		c.certPinner.Clear()
	}
}

// FetchMode specifies the Sec-Fetch-Mode behavior
type FetchMode int

const (
	FetchModeNavigate FetchMode = iota // Default: human clicked link (sec-fetch-mode: navigate)
	FetchModeCORS                      // XHR/fetch call (sec-fetch-mode: cors)
)

// FetchSite specifies the Sec-Fetch-Site value
type FetchSite int

const (
	FetchSiteAuto       FetchSite = iota // Auto-detect based on Referer header
	FetchSiteNone                        // Direct navigation (typed URL, bookmark)
	FetchSiteSameOrigin                  // Same origin request
	FetchSiteSameSite                    // Same site but different subdomain
	FetchSiteCrossSite                   // Different site
)

// Request represents an HTTP request
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Timeout time.Duration

	// Customization options
	UserAgent     string    // Override User-Agent (empty = use preset)
	ForceProtocol Protocol  // Force specific protocol (ProtocolAuto = auto)
	FetchMode     FetchMode // Fetch mode: Navigate (default, human click) or CORS (XHR/fetch)
	FetchSite     FetchSite // Sec-Fetch-Site: Auto (default), None, SameOrigin, SameSite, CrossSite
	Referer       string    // Referer header (used for auto-detecting FetchSite)

	// Authentication (overrides client-level auth)
	Auth Auth

	// Params adds query parameters to the URL
	Params map[string]string

	// Per-request redirect override (nil = use client config)
	FollowRedirects *bool
	MaxRedirects    int

	// Per-request retry override (nil = use client config)
	DisableRetry bool
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
	FinalURL   string
	Timing     *protocol.Timing
	Protocol   string // "h3" or "h2"

	// Request info
	Request *Request

	// Redirect history
	RedirectHistory []*RedirectInfo
}

// RedirectInfo stores information about a redirect
type RedirectInfo struct {
	StatusCode int
	URL        string
	Headers    map[string]string
}

// JSON decodes the response body as JSON into the given interface
func (r *Response) JSON(v interface{}) error {
	return json.Unmarshal(r.Body, v)
}

// Text returns the response body as a string
func (r *Response) Text() string {
	return string(r.Body)
}

// IsSuccess returns true if the status code is 2xx
func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// IsRedirect returns true if the status code is 3xx
func (r *Response) IsRedirect() bool {
	return r.StatusCode >= 300 && r.StatusCode < 400
}

// IsClientError returns true if the status code is 4xx
func (r *Response) IsClientError() bool {
	return r.StatusCode >= 400 && r.StatusCode < 500
}

// IsServerError returns true if the status code is 5xx
func (r *Response) IsServerError() bool {
	return r.StatusCode >= 500 && r.StatusCode < 600
}

// Do executes an HTTP request
// Tries HTTP/3 first, falls back to HTTP/2 if HTTP/3 fails
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	// Handle retries
	if c.config.RetryEnabled && !req.DisableRetry {
		return c.doWithRetry(ctx, req)
	}
	return c.doOnce(ctx, req, nil)
}

// doWithRetry executes request with retry logic
func (c *Client) doWithRetry(ctx context.Context, req *Request) (*Response, error) {
	var lastErr error
	var lastResp *Response

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Calculate wait time with exponential backoff and jitter
			wait := c.calculateRetryWait(attempt)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}

		resp, err := c.doOnce(ctx, req, nil)
		if err != nil {
			lastErr = err
			continue
		}

		// Check if we should retry based on status code
		if c.shouldRetryStatus(resp.StatusCode) && attempt < c.config.MaxRetries {
			lastResp = resp
			lastErr = fmt.Errorf("server returned status %d", resp.StatusCode)
			continue
		}

		return resp, nil
	}

	if lastResp != nil {
		return lastResp, nil
	}
	return nil, fmt.Errorf("request failed after %d retries: %w", c.config.MaxRetries, lastErr)
}

// calculateRetryWait calculates wait time for retry with exponential backoff
func (c *Client) calculateRetryWait(attempt int) time.Duration {
	// Exponential backoff: min * 2^attempt
	wait := float64(c.config.RetryWaitMin) * math.Pow(2, float64(attempt-1))

	// Add jitter (±20%)
	jitter := wait * 0.2 * (rand.Float64()*2 - 1)
	wait += jitter

	// Cap at max
	if wait > float64(c.config.RetryWaitMax) {
		wait = float64(c.config.RetryWaitMax)
	}

	return time.Duration(wait)
}

// shouldRetryStatus checks if status code should trigger retry
func (c *Client) shouldRetryStatus(statusCode int) bool {
	for _, code := range c.config.RetryOnStatus {
		if statusCode == code {
			return true
		}
	}
	return false
}

// doOnce executes a single request (with redirect following)
func (c *Client) doOnce(ctx context.Context, req *Request, redirectHistory []*RedirectInfo) (*Response, error) {
	startTime := time.Now()

	// Build URL with params
	reqURL := req.URL
	if len(req.Params) > 0 {
		reqURL = NewURLBuilder(req.URL).Params(req.Params).Build()
	}

	// Parse URL
	parsedURL, err := url.Parse(reqURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("only HTTPS is supported")
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	// Set timeout
	timeout := c.config.Timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Check if HTTP/3 has failed for this host recently (within 5 minutes)
	hostKey := host + ":" + port
	useH3 := c.shouldTryHTTP3(hostKey)

	// Build HTTP request
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		// POST/PUT/PATCH with empty body must send Content-Length: 0
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Normalize request (Content-Length: 0 for empty POST/PUT/PATCH, Content-Type detection, etc.)
	normalizeRequestWithBody(httpReq, req.Body)

	// Apply headers based on FetchMode - this sets EVERYTHING correctly
	// The library is smart: pick a mode, get coherent headers automatically
	applyModeHeaders(httpReq, c.preset, req, parsedURL)

	// Apply authentication
	auth := req.Auth
	if auth == nil {
		auth = c.auth
	}
	if auth != nil {
		if err := auth.Apply(httpReq); err != nil {
			return nil, fmt.Errorf("failed to apply authentication: %w", err)
		}
	}

	// Apply cookies from jar
	if c.cookies != nil {
		cookieHeader := c.cookies.CookieHeader(parsedURL)
		if cookieHeader != "" {
			httpReq.Header.Set("Cookie", cookieHeader)
		}
	}

	// Add organic jitter to mimic real browser behavior (browsers aren't perfectly consistent)
	// Browsers have slight variations in quality values and timing
	applyOrganicJitter(httpReq)

	// Run pre-request hooks
	if c.hooks != nil {
		if err := c.hooks.RunPreRequest(httpReq); err != nil {
			return nil, fmt.Errorf("pre-request hook failed: %w", err)
		}
	}

	var resp *http.Response
	var usedProtocol string
	timing := &protocol.Timing{}

	// Determine protocol based on ForceProtocol option
	switch req.ForceProtocol {
	case ProtocolHTTP1:
		// Force HTTP/1.1 only
		resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
		if err != nil {
			return nil, err
		}
	case ProtocolHTTP3:
		// Force HTTP/3 only - but not possible with proxy
		if c.config.Proxy != "" {
			return nil, fmt.Errorf("HTTP/3 cannot be used with proxy: QUIC uses UDP which cannot tunnel through HTTP proxies")
		}
		if c.quicManager == nil {
			return nil, fmt.Errorf("HTTP/3 is disabled (no QUIC manager available)")
		}
		resp, usedProtocol, err = c.doHTTP3(ctx, host, port, httpReq, timing, startTime)
		if err != nil {
			return nil, fmt.Errorf("HTTP/3 failed: %w", err)
		}
	case ProtocolHTTP2:
		// Force HTTP/2 only
		resp, usedProtocol, err = c.doHTTP2(ctx, host, port, httpReq, timing, startTime)
		if err != nil {
			return nil, err
		}
	default:
		// Auto: Try HTTP/3 -> HTTP/2 -> HTTP/1.1 with smart fallback
		useH1 := c.shouldUseH1(hostKey)

		if useH1 {
			// Known to need HTTP/1.1
			resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
			if err != nil {
				return nil, err
			}
		} else if useH3 {
			// Try HTTP/3 first
			resp, usedProtocol, err = c.doHTTP3(ctx, host, port, httpReq, timing, startTime)
			if err != nil {
				// HTTP/3 failed, mark it and fall back to HTTP/2
				c.markH3Failed(hostKey)

				// Reset request body for retry
				resetRequestBody(httpReq, req.Body)

				resp, usedProtocol, err = c.doHTTP2(ctx, host, port, httpReq, timing, startTime)
				if err != nil {
					// HTTP/2 also failed, try HTTP/1.1
					c.markH2Failed(hostKey)

					resetRequestBody(httpReq, req.Body)

					resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
					if err != nil {
						return nil, err
					}
				}
			}
		} else {
			// Try HTTP/2 first
			resp, usedProtocol, err = c.doHTTP2(ctx, host, port, httpReq, timing, startTime)
			if err != nil {
				// HTTP/2 failed, try HTTP/1.1
				c.markH2Failed(hostKey)

				resetRequestBody(httpReq, req.Body)

				resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	// Verify certificate pinning
	if c.certPinner != nil && c.certPinner.HasPins() && resp.TLS != nil {
		if err := c.certPinner.Verify(host, resp.TLS.PeerCertificates); err != nil {
			resp.Body.Close()
			return nil, err
		}
	}

	defer resp.Body.Close()

	// Build response headers map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[strings.ToLower(key)] = strings.Join(values, ", ")
	}

	// Store cookies from response
	if c.cookies != nil {
		setCookies := resp.Header["Set-Cookie"]
		if len(setCookies) > 0 {
			c.cookies.SetCookiesFromHeaderList(parsedURL, setCookies)
		}
	}

	// Handle redirects
	if isRedirect(resp.StatusCode) {
		// Check if we should follow redirects
		followRedirects := c.config.FollowRedirects
		if req.FollowRedirects != nil {
			followRedirects = *req.FollowRedirects
		}

		if followRedirects {
			maxRedirects := c.config.MaxRedirects
			if req.MaxRedirects > 0 {
				maxRedirects = req.MaxRedirects
			}

			if redirectHistory == nil {
				redirectHistory = make([]*RedirectInfo, 0)
			}

			if len(redirectHistory) >= maxRedirects {
				return nil, fmt.Errorf("too many redirects (max %d)", maxRedirects)
			}

			// Get redirect location
			location := resp.Header.Get("Location")
			if location == "" {
				return nil, fmt.Errorf("redirect response missing Location header")
			}

			// Resolve relative URL
			redirectURL := JoinURL(reqURL, location)

			// Add to redirect history
			redirectHistory = append(redirectHistory, &RedirectInfo{
				StatusCode: resp.StatusCode,
				URL:        reqURL,
				Headers:    headers,
			})

			// Determine new method based on redirect code
			newMethod := method
			if resp.StatusCode == 303 || (resp.StatusCode == 301 || resp.StatusCode == 302) && method == "POST" {
				// 303 always changes to GET
				// 301/302 change POST to GET (browser behavior)
				newMethod = "GET"
			}

			// Create new request for redirect
			newReq := &Request{
				Method:          newMethod,
				URL:             redirectURL,
				Headers:         req.Headers,
				Timeout:         req.Timeout,
				UserAgent:       req.UserAgent,
				ForceProtocol:   req.ForceProtocol,
				FetchMode:       req.FetchMode,
				FetchSite:       FetchSiteCrossSite, // Redirects are usually cross-site
				Referer:         reqURL,
				Auth:            req.Auth,
				FollowRedirects: req.FollowRedirects,
				MaxRedirects:    req.MaxRedirects,
				DisableRetry:    true, // Don't retry redirects
			}

			// 307/308 preserve body
			if resp.StatusCode == 307 || resp.StatusCode == 308 {
				newReq.Body = req.Body
			}

			// Follow redirect
			return c.doOnce(ctx, newReq, redirectHistory)
		}
	}

	// Handle 401 with Digest auth (challenge-response)
	if resp.StatusCode == http.StatusUnauthorized && auth != nil {
		shouldRetry, err := auth.HandleChallenge(resp, httpReq)
		if err != nil {
			return nil, fmt.Errorf("failed to handle auth challenge: %w", err)
		}
		if shouldRetry {
			// Reset request body for retry
			resetRequestBody(httpReq, req.Body)
			// Apply auth again with challenge info
			if err := auth.Apply(httpReq); err != nil {
				return nil, fmt.Errorf("failed to apply authentication after challenge: %w", err)
			}
			// Retry request
			return c.doOnce(ctx, req, redirectHistory)
		}
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	body, err = decompress(body, contentEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress response: %w", err)
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	response := &Response{
		StatusCode:      resp.StatusCode,
		Headers:         headers,
		Body:            body,
		FinalURL:        reqURL,
		Timing:          timing,
		Protocol:        usedProtocol,
		Request:         req,
		RedirectHistory: redirectHistory,
	}

	// Run post-response hooks
	if c.hooks != nil {
		if err := c.hooks.RunPostResponse(response); err != nil {
			// Log but don't fail - response is still valid
			// Hooks are for observability, not control flow
		}
	}

	return response, nil
}

// isRedirect checks if status code is a redirect
func isRedirect(statusCode int) bool {
	return statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308
}

// shouldTryHTTP3 checks if we should try HTTP/3 for this host
func (c *Client) shouldTryHTTP3(hostKey string) bool {
	// If QUIC manager is nil (H3 disabled or proxy configured), don't try HTTP/3
	if c.quicManager == nil {
		return false
	}

	c.h3FailuresMu.RLock()
	defer c.h3FailuresMu.RUnlock()

	if failTime, exists := c.h3Failures[hostKey]; exists {
		// Retry after 5 minutes
		if time.Since(failTime) < 5*time.Minute {
			return false
		}
	}
	return true
}

// markH3Failed marks a host as not supporting HTTP/3
func (c *Client) markH3Failed(hostKey string) {
	c.h3FailuresMu.Lock()
	defer c.h3FailuresMu.Unlock()
	c.h3Failures[hostKey] = time.Now()
}

// doHTTP3 executes the request over HTTP/3
func (c *Client) doHTTP3(ctx context.Context, host, port string, httpReq *http.Request, timing *protocol.Timing, startTime time.Time) (*http.Response, string, error) {
	connStart := time.Now()

	conn, err := c.quicManager.GetConn(ctx, host, port)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get QUIC connection: %w", err)
	}

	// Calculate timing
	if conn.UseCount == 1 {
		connTime := float64(time.Since(connStart).Milliseconds())
		timing.DNSLookup = connTime / 3
		timing.TCPConnect = 0
		timing.TLSHandshake = connTime * 2 / 3
	}

	firstByteTime := time.Now()
	resp, err := conn.HTTP3RT.RoundTrip(httpReq)
	if err != nil {
		return nil, "", err
	}

	timing.FirstByte = float64(time.Since(firstByteTime).Milliseconds())
	return resp, "h3", nil
}

// doHTTP2 executes the request over HTTP/2
func (c *Client) doHTTP2(ctx context.Context, host, port string, httpReq *http.Request, timing *protocol.Timing, startTime time.Time) (*http.Response, string, error) {
	connStart := time.Now()

	conn, err := c.poolManager.GetConn(ctx, host, port)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get connection: %w", err)
	}

	// Calculate timing
	if conn.UseCount == 1 {
		connTime := float64(time.Since(connStart).Milliseconds())
		timing.DNSLookup = connTime / 3
		timing.TCPConnect = connTime / 3
		timing.TLSHandshake = connTime / 3
	}

	firstByteTime := time.Now()
	resp, err := conn.HTTP2Conn.RoundTrip(httpReq)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}

	timing.FirstByte = float64(time.Since(firstByteTime).Milliseconds())
	return resp, "h2", nil
}

// doHTTP1 performs HTTP/1.1 request using the h1Transport
func (c *Client) doHTTP1(ctx context.Context, host, port string, httpReq *http.Request, timing *protocol.Timing, startTime time.Time) (*http.Response, string, error) {
	firstByteTime := time.Now()

	resp, err := c.h1Transport.RoundTrip(httpReq)
	if err != nil {
		return nil, "", fmt.Errorf("HTTP/1.1 request failed: %w", err)
	}

	timing.FirstByte = float64(time.Since(firstByteTime).Milliseconds())
	return resp, "h1", nil
}

// markH2Failed marks a host as not supporting HTTP/2
func (c *Client) markH2Failed(hostKey string) {
	c.h2FailuresMu.Lock()
	c.h2Failures[hostKey] = time.Now()
	c.h2FailuresMu.Unlock()
}

// shouldUseH1 checks if HTTP/1.1 should be used for this host (H2 known to fail)
func (c *Client) shouldUseH1(hostKey string) bool {
	c.h2FailuresMu.RLock()
	failTime, failed := c.h2Failures[hostKey]
	c.h2FailuresMu.RUnlock()

	if !failed {
		return false
	}

	// Cache H2 failure for 5 minutes
	if time.Since(failTime) > 5*time.Minute {
		c.h2FailuresMu.Lock()
		delete(c.h2Failures, hostKey)
		c.h2FailuresMu.Unlock()
		return false
	}

	return true
}

// Get performs a GET request
func (c *Client) Get(ctx context.Context, url string, headers map[string]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, url string, body []byte, headers map[string]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:  "POST",
		URL:     url,
		Body:    body,
		Headers: headers,
	})
}

// Close shuts down the client and all connections
func (c *Client) Close() {
	c.poolManager.Close()
	if c.quicManager != nil {
		c.quicManager.Close()
	}
	if c.h1Transport != nil {
		c.h1Transport.Close()
	}
}

// Stats returns connection pool statistics
func (c *Client) Stats() map[string]struct {
	Total    int
	Healthy  int
	Requests int64
} {
	return c.poolManager.Stats()
}

// applyModeHeaders sets ALL headers correctly based on FetchMode
// This is the smart part - the library auto-detects the right mode and ensures coherence
func applyModeHeaders(httpReq *http.Request, preset *fingerprint.Preset, req *Request, parsedURL *url.URL) {
	// Set User-Agent (custom or preset)
	userAgent := preset.UserAgent
	if req.UserAgent != "" {
		userAgent = req.UserAgent
	}
	httpReq.Header.Set("User-Agent", userAgent)

	// Set Host header
	httpReq.Header.Set("Host", parsedURL.Hostname())

	// Set Referer if provided
	if req.Referer != "" {
		httpReq.Header.Set("Referer", req.Referer)
	}

	// FIRST: Determine effective mode (BEFORE setting sec-fetch-site!)
	// Smart mode detection: if user sets API-style Accept header, treat as CORS
	// This prevents the "I want JSON but I'm navigating a document" incoherence
	effectiveMode := req.FetchMode
	if effectiveMode == FetchModeNavigate {
		if accept, ok := req.Headers["Accept"]; ok {
			if isAPIAcceptHeader(accept) {
				effectiveMode = FetchModeCORS
			}
		}
	}

	// THEN: Set Sec-Fetch-Site based on the ACTUAL mode
	// sec-fetch-site: none is ONLY valid for navigation, never for CORS
	secFetchSite := detectSecFetchSiteForMode(req.FetchSite, parsedURL, req.Referer, effectiveMode)
	httpReq.Header.Set("Sec-Fetch-Site", secFetchSite)

	// Apply mode-specific headers - EVERYTHING is coherent
	switch effectiveMode {
	case FetchModeCORS:
		applyCORSModeHeaders(httpReq, preset, req, parsedURL)
	default:
		applyNavigationModeHeaders(httpReq, preset, req)
	}

	// Apply user custom headers, but BLOCK any that would break coherence
	for key, value := range req.Headers {
		lowerKey := strings.ToLower(key)
		// Skip headers that would break mode coherence
		if isModeCriticalHeader(lowerKey) {
			continue
		}
		httpReq.Header.Set(key, value)
	}
}

// isAPIAcceptHeader returns true if the Accept header looks like an API request
func isAPIAcceptHeader(accept string) bool {
	lower := strings.ToLower(accept)
	// API-style accept headers that are NOT navigation
	return strings.Contains(lower, "application/json") ||
		strings.Contains(lower, "application/xml") ||
		strings.Contains(lower, "text/plain") ||
		strings.Contains(lower, "application/octet-stream") ||
		(lower == "*/*")
}

// isModeCriticalHeader returns true if this header is controlled by the mode
// These headers MUST be coherent with each other - user cannot override individually
func isModeCriticalHeader(lowerKey string) bool {
	critical := map[string]bool{
		"accept":                    true,
		"sec-fetch-mode":            true,
		"sec-fetch-dest":            true,
		"sec-fetch-user":            true,
		"sec-fetch-site":            true,
		"upgrade-insecure-requests": true,
		"cache-control":             true,
		"origin":                    true,
	}
	return critical[lowerKey]
}

// applyNavigationModeHeaders sets headers for page navigation (human clicked link)
func applyNavigationModeHeaders(httpReq *http.Request, preset *fingerprint.Preset, req *Request) {
	// Client hints (low-entropy only)
	if v, ok := preset.Headers["sec-ch-ua"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua", v)
	}
	if v, ok := preset.Headers["sec-ch-ua-mobile"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua-Mobile", v)
	}
	if v, ok := preset.Headers["sec-ch-ua-platform"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua-Platform", v)
	}

	// Navigation headers - THE coherent set for "human clicked a link"
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	httpReq.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	httpReq.Header.Set("Cache-Control", "max-age=0")
	httpReq.Header.Set("Sec-Fetch-Dest", "document")
	httpReq.Header.Set("Sec-Fetch-Mode", "navigate")
	httpReq.Header.Set("Sec-Fetch-User", "?1")
	httpReq.Header.Set("Upgrade-Insecure-Requests", "1")

	// Priority header (newer Chrome)
	if v, ok := preset.Headers["Priority"]; ok {
		httpReq.Header.Set("Priority", v)
	}
}

// applyCORSModeHeaders sets headers for XHR/fetch() calls (JavaScript API request)
func applyCORSModeHeaders(httpReq *http.Request, preset *fingerprint.Preset, req *Request, parsedURL *url.URL) {
	// Client hints (low-entropy only)
	if v, ok := preset.Headers["sec-ch-ua"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua", v)
	}
	if v, ok := preset.Headers["sec-ch-ua-mobile"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua-Mobile", v)
	}
	if v, ok := preset.Headers["sec-ch-ua-platform"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua-Platform", v)
	}

	// CORS headers - THE coherent set for "JavaScript fetch() call"
	// Use user's Accept if they set one (it's valid for CORS), otherwise default to */*
	if accept, ok := req.Headers["Accept"]; ok && accept != "" {
		httpReq.Header.Set("Accept", accept)
	} else {
		httpReq.Header.Set("Accept", "*/*")
	}
	httpReq.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	httpReq.Header.Set("Sec-Fetch-Dest", "empty")
	httpReq.Header.Set("Sec-Fetch-Mode", "cors")
	// NO Sec-Fetch-User for CORS
	// NO Upgrade-Insecure-Requests for CORS
	// NO Cache-Control for CORS

	// Origin header - required for CORS
	if req.Referer != "" {
		if refURL, err := url.Parse(req.Referer); err == nil {
			httpReq.Header.Set("Origin", refURL.Scheme+"://"+refURL.Host)
		}
	} else {
		httpReq.Header.Set("Origin", parsedURL.Scheme+"://"+parsedURL.Host)
	}
}

// detectSecFetchSiteForMode determines the Sec-Fetch-Site header value
// CRITICAL: sec-fetch-site: none is ONLY valid for navigation mode
// For CORS mode, JavaScript always runs in a page context, so it can NEVER be "none"
func detectSecFetchSiteForMode(fetchSite FetchSite, requestURL *url.URL, referer string, mode FetchMode) string {
	// Handle explicit user override (user knows what they're doing)
	switch fetchSite {
	case FetchSiteNone:
		// Only allow "none" for navigation mode
		if mode == FetchModeCORS {
			// CORS + none is impossible - JS can't run without a page origin
			// Fall through to auto-detect or default to cross-site
		} else {
			return "none"
		}
	case FetchSiteSameOrigin:
		return "same-origin"
	case FetchSiteSameSite:
		return "same-site"
	case FetchSiteCrossSite:
		return "cross-site"
	}

	// Auto-detect based on Referer
	if referer == "" {
		// No referer...
		if mode == FetchModeCORS {
			// CORS mode: JS is running on SOME page, we just don't know which
			// Default to "cross-site" since most API calls are cross-origin
			// (same-origin fetch would typically have a Referer)
			return "cross-site"
		}
		// Navigation mode: direct navigation (typed URL, bookmark)
		return "none"
	}

	refererURL, err := url.Parse(referer)
	if err != nil {
		if mode == FetchModeCORS {
			return "cross-site"
		}
		return "none"
	}

	// Same origin check: scheme + host + port must match
	if requestURL.Scheme == refererURL.Scheme &&
		requestURL.Host == refererURL.Host {
		return "same-origin"
	}

	// Same site check: compare eTLD+1 (simplified - handles most common cases)
	requestSite := extractSite(requestURL.Hostname())
	refererSite := extractSite(refererURL.Hostname())

	if requestSite == refererSite && requestURL.Scheme == refererURL.Scheme {
		return "same-site"
	}

	// Different sites
	return "cross-site"
}

// extractSite extracts the registrable domain (eTLD+1) from a hostname
// This is a simplified version - handles most common cases like:
// - example.com -> example.com
// - sub.example.com -> example.com
// - sub.example.co.uk -> example.co.uk (simplified, treats .co.uk as two parts)
func extractSite(hostname string) string {
	// Handle IP addresses
	if net.ParseIP(hostname) != nil {
		return hostname
	}

	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}

	// Simple heuristic: take last 2 parts, or last 3 if second-to-last is short (like co, com, org in .co.uk)
	if len(parts) >= 3 && len(parts[len(parts)-2]) <= 3 {
		// Likely a two-part TLD like .co.uk, .com.au
		return strings.Join(parts[len(parts)-3:], ".")
	}

	return strings.Join(parts[len(parts)-2:], ".")
}

// applyOrganicJitter adds slight randomization to headers to mimic real browser behavior.
// Real browsers have minor variations in header values - perfect consistency is a bot fingerprint.
func applyOrganicJitter(req *http.Request) {
	// Randomly vary Accept-Language quality values slightly
	// e.g., "en-US,en;q=0.9" might become "en-US,en;q=0.8" or stay the same
	acceptLang := req.Header.Get("Accept-Language")
	if acceptLang != "" {
		// 30% chance to slightly modify quality value
		if rand.Float32() < 0.3 {
			// Replace q=0.9 with q=0.8 or q=0.85 occasionally
			variants := []string{"0.9", "0.8", "0.85", "0.9"}
			choice := variants[rand.Intn(len(variants))]
			acceptLang = strings.Replace(acceptLang, "q=0.9", "q="+choice, 1)
			req.Header.Set("Accept-Language", acceptLang)
		}
	}

	// Occasionally vary Cache-Control (browsers are inconsistent)
	// Default is max-age=0, but sometimes browsers send no-cache
	cacheControl := req.Header.Get("Cache-Control")
	if cacheControl != "" && rand.Float32() < 0.15 {
		req.Header.Set("Cache-Control", "no-cache")
	}

	// Occasionally add Pragma header (older compatibility, Chrome sometimes does this)
	if rand.Float32() < 0.1 {
		req.Header.Set("Pragma", "no-cache")
	}

	// Very rarely, some users have DNT enabled (about 5% of users)
	if rand.Float32() < 0.05 {
		req.Header.Set("DNT", "1")
	}
}

// decompress decompresses response body based on Content-Encoding
func decompress(data []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)

	case "br":
		reader := brotli.NewReader(bytes.NewReader(data))
		return io.ReadAll(reader)

	case "zstd":
		decoder, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer decoder.Close()
		return io.ReadAll(decoder)

	case "deflate":
		// For deflate, just return as-is for now
		// (proper deflate handling would need zlib)
		return data, nil

	case "", "identity":
		return data, nil

	default:
		// Unknown encoding, return as-is
		return data, nil
	}
}
