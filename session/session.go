package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// generateID generates a random session ID (16 bytes = 32 hex chars)
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var (
	ErrSessionClosed = errors.New("session is closed")
)

// cacheEntry stores cache validation headers for a URL
type cacheEntry struct {
	etag         string // ETag header value
	lastModified string // Last-Modified header value
}

// Session represents a persistent HTTP session with connection affinity
type Session struct {
	ID           string
	CreatedAt    time.Time
	LastUsed     time.Time
	RequestCount int64
	Config       *protocol.SessionConfig

	// Session's own transport with dedicated connection pool
	transport *transport.Transport
	cookies   map[string]string

	// Cache validation headers per URL (for If-None-Match, If-Modified-Since)
	cacheEntries map[string]*cacheEntry

	mu     sync.RWMutex
	active bool
}

// NewSession creates a new session with its own connection pool
func NewSession(id string, config *protocol.SessionConfig) *Session {
	if id == "" {
		id = generateID()
	}

	presetName := "chrome-131"
	if config != nil && config.Preset != "" {
		presetName = config.Preset
	}

	if config == nil {
		config = &protocol.SessionConfig{
			Preset:  presetName,
			Timeout: 30,
		}
	}

	// Create transport config with ConnectTo and ECH settings
	var transportConfig *transport.TransportConfig
	if len(config.ConnectTo) > 0 || config.ECHConfigDomain != "" {
		transportConfig = &transport.TransportConfig{
			ConnectTo:       config.ConnectTo,
			ECHConfigDomain: config.ECHConfigDomain,
		}
	}

	// Create transport with optional proxy and config
	var t *transport.Transport
	var proxy *transport.ProxyConfig
	if config.Proxy != "" || config.TCPProxy != "" || config.UDPProxy != "" {
		proxy = &transport.ProxyConfig{
			URL:      config.Proxy,
			TCPProxy: config.TCPProxy,
			UDPProxy: config.UDPProxy,
		}
	}
	t = transport.NewTransportWithConfig(presetName, proxy, transportConfig)

	// Set protocol preference
	if config.ForceHTTP3 {
		t.SetProtocol(transport.ProtocolHTTP3)
	} else if config.DisableHTTP3 {
		t.SetProtocol(transport.ProtocolHTTP2)
	}

	// Set IPv4 preference
	if config.PreferIPv4 {
		if dnsCache := t.GetDNSCache(); dnsCache != nil {
			dnsCache.SetPreferIPv4(true)
		}
	}

	return &Session{
		ID:           id,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		RequestCount: 0,
		Config:       config,
		transport:    t,
		cookies:      make(map[string]string),
		cacheEntries: make(map[string]*cacheEntry),
		active:       true,
	}
}

// Request executes an HTTP request within this session
func (s *Session) Request(ctx context.Context, req *transport.Request) (*transport.Response, error) {
	return s.requestWithRedirects(ctx, req, 0, nil)
}

// requestWithRedirects handles the actual request with redirect following
func (s *Session) requestWithRedirects(ctx context.Context, req *transport.Request, redirectCount int, history []*transport.RedirectInfo) (*transport.Response, error) {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return nil, ErrSessionClosed
	}
	s.LastUsed = time.Now()
	s.RequestCount++

	if req.Headers == nil {
		req.Headers = make(map[string][]string)
	}

	// Add cache validation headers (If-None-Match, If-Modified-Since)
	// This makes requests look like a real browser that caches resources
	if cached, exists := s.cacheEntries[req.URL]; exists {
		if cached.etag != "" {
			req.Headers["If-None-Match"] = []string{cached.etag}
		}
		if cached.lastModified != "" {
			req.Headers["If-Modified-Since"] = []string{cached.lastModified}
		}
	}
	s.mu.Unlock()

	// Execute request with retry logic if configured
	var resp *transport.Response
	var err error

	maxRetries := 0
	retryWaitMin := 500 * time.Millisecond
	retryWaitMax := 10 * time.Second
	var retryOnStatus []int

	if s.Config != nil && s.Config.RetryEnabled && s.Config.MaxRetries > 0 {
		maxRetries = s.Config.MaxRetries
		if s.Config.RetryWaitMin > 0 {
			retryWaitMin = time.Duration(s.Config.RetryWaitMin) * time.Millisecond
		}
		if s.Config.RetryWaitMax > 0 {
			retryWaitMax = time.Duration(s.Config.RetryWaitMax) * time.Millisecond
		}
		if len(s.Config.RetryOnStatus) > 0 {
			retryOnStatus = s.Config.RetryOnStatus
		} else {
			// Default retry status codes
			retryOnStatus = []int{429, 500, 502, 503, 504}
		}
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Add session cookies to request headers BEFORE each attempt
		// Merge with any existing Cookie header (from per-request cookies)
		s.mu.RLock()
		if len(s.cookies) > 0 {
			sessionCookies := ""
			for name, value := range s.cookies {
				if sessionCookies != "" {
					sessionCookies += "; "
				}
				sessionCookies += name + "=" + value
			}
			// Merge with existing cookies (per-request cookies take precedence for same name)
			existingCookies := req.Headers["Cookie"]
			if len(existingCookies) > 0 && existingCookies[0] != "" {
				req.Headers["Cookie"] = []string{existingCookies[0] + "; " + sessionCookies}
			} else {
				req.Headers["Cookie"] = []string{sessionCookies}
			}
		}
		s.mu.RUnlock()

		resp, err = s.transport.Do(ctx, req)

		// If no error and no retry config, or this is the last attempt, break
		if maxRetries == 0 {
			break
		}

		// Extract cookies from EVERY response (even 429s, 500s, etc.)
		// This mimics browser behavior where cookies are stored regardless of status
		if resp != nil {
			s.extractCookies(resp.Headers)
		}

		// Check if we should retry
		shouldRetry := false
		if err != nil {
			// Retry on network errors
			shouldRetry = true
		} else if resp != nil {
			// Check if status code is in retry list
			for _, status := range retryOnStatus {
				if resp.StatusCode == status {
					shouldRetry = true
					break
				}
			}
		}

		if !shouldRetry || attempt >= maxRetries {
			break
		}

		// Calculate wait time with exponential backoff and jitter
		waitTime := retryWaitMin * time.Duration(1<<uint(attempt))
		if waitTime > retryWaitMax {
			waitTime = retryWaitMax
		}

		// Add some jitter (±25%)
		jitter := time.Duration(float64(waitTime) * 0.25)
		waitTime = waitTime - jitter + time.Duration(randInt64(int64(jitter*2)))

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(waitTime):
			// Continue to next retry attempt
		}
	}

	if err != nil {
		return nil, err
	}

	// Extract cookies from final response (in case we didn't retry or it's a success)
	s.extractCookies(resp.Headers)

	// Store cache validation headers from response for future requests
	s.storeCacheHeaders(req.URL, resp.Headers)

	// Handle redirects
	if isRedirectStatus(resp.StatusCode) {
		// Check if we should follow redirects
		followRedirects := true
		maxRedirects := 10
		if s.Config != nil {
			followRedirects = s.Config.FollowRedirects
			if s.Config.MaxRedirects > 0 {
				maxRedirects = s.Config.MaxRedirects
			}
		}

		if followRedirects {
			if redirectCount >= maxRedirects {
				return nil, errors.New("too many redirects")
			}

			// Get Location header (first value from slice)
			location := ""
			if locs := resp.Headers["Location"]; len(locs) > 0 {
				location = locs[0]
			}
			if location == "" {
				if locs := resp.Headers["location"]; len(locs) > 0 {
					location = locs[0]
				}
			}
			if location == "" {
				// No Location header, set history and return as-is
				resp.History = history
				return resp, nil
			}

			// Add current response to redirect history
			redirectInfo := &transport.RedirectInfo{
				StatusCode: resp.StatusCode,
				URL:        req.URL,
				Headers:    resp.Headers,
			}
			history = append(history, redirectInfo)

			// Resolve relative URL
			redirectURL := resolveURL(req.URL, location)

			// Determine new method
			newMethod := req.Method
			if resp.StatusCode == 303 || ((resp.StatusCode == 301 || resp.StatusCode == 302) && req.Method == "POST") {
				newMethod = "GET"
			}

			// Create redirect request
			newReq := &transport.Request{
				Method:  newMethod,
				URL:     redirectURL,
				Headers: make(map[string][]string),
			}

			// Copy safe headers
			for k, v := range req.Headers {
				// Don't copy Content-* headers on method change
				if newMethod != req.Method && (k == "Content-Type" || k == "Content-Length" || k == "content-type" || k == "content-length") {
					continue
				}
				// Don't copy Cookie header (will be re-added from session)
				if k == "Cookie" || k == "cookie" {
					continue
				}
				newReq.Headers[k] = v
			}

			// 307/308 preserve body
			if resp.StatusCode == 307 || resp.StatusCode == 308 {
				newReq.Body = req.Body
			}

			// Follow redirect with accumulated history
			return s.requestWithRedirects(ctx, newReq, redirectCount+1, history)
		}
	}

	// Set history on final response
	resp.History = history
	return resp, nil
}

// randInt64 generates a random int64 in range [0, n)
func randInt64(n int64) int64 {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 8)
	rand.Read(b)
	v := int64(b[0]) | int64(b[1])<<8 | int64(b[2])<<16 | int64(b[3])<<24 |
		int64(b[4])<<32 | int64(b[5])<<40 | int64(b[6])<<48 | int64(b[7]&0x7f)<<56
	return v % n
}

// Get performs a GET request
func (s *Session) Get(ctx context.Context, url string, headers map[string][]string) (*transport.Response, error) {
	return s.Request(ctx, &transport.Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// Post performs a POST request
func (s *Session) Post(ctx context.Context, url string, body []byte, headers map[string][]string) (*transport.Response, error) {
	return s.Request(ctx, &transport.Request{
		Method:  "POST",
		URL:     url,
		Body:    body,
		Headers: headers,
	})
}

// extractCookies extracts cookies from response headers
func (s *Session) extractCookies(headers map[string][]string) {
	// Try both cases - some responses might have different casing
	setCookies, exists := headers["set-cookie"]
	if !exists {
		setCookies, exists = headers["Set-Cookie"]
	}
	if !exists || len(setCookies) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Each Set-Cookie header is now a separate element in the slice
	for _, cookie := range setCookies {
		cookie = trim(cookie)
		if cookie == "" {
			continue
		}

		// Get name=value before any semicolon (attributes like path, expires, etc.)
		idx := indexOf(cookie, ";")
		if idx != -1 {
			cookie = cookie[:idx]
		}

		eqIdx := indexOf(cookie, "=")
		if eqIdx != -1 {
			name := trim(cookie[:eqIdx])
			value := trim(cookie[eqIdx+1:])
			if name != "" {
				s.cookies[name] = value
			}
		}
	}
}

// storeCacheHeaders extracts and stores cache validation headers from response
// These headers will be sent on subsequent requests to the same URL
func (s *Session) storeCacheHeaders(url string, headers map[string][]string) {
	// Helper to get first value from header (case-insensitive)
	getHeader := func(key string) string {
		if values := headers[key]; len(values) > 0 {
			return values[0]
		}
		return ""
	}

	// Look for ETag header (case-insensitive)
	etag := getHeader("etag")
	if etag == "" {
		etag = getHeader("ETag")
	}

	// Look for Last-Modified header (case-insensitive)
	lastModified := getHeader("last-modified")
	if lastModified == "" {
		lastModified = getHeader("Last-Modified")
	}

	// Only store if we have at least one cache header
	if etag == "" && lastModified == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cacheEntries[url] = &cacheEntry{
		etag:         etag,
		lastModified: lastModified,
	}
}

// IsActive returns whether the session is active
func (s *Session) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

// Close marks the session as inactive and closes connections
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return
	}
	s.active = false

	if s.transport != nil {
		s.transport.Close()
	}
}

// Touch updates the last used timestamp
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastUsed = time.Now()
}

// GetCookies returns all cookies for this session
func (s *Session) GetCookies() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cookies := make(map[string]string)
	for k, v := range s.cookies {
		cookies[k] = v
	}
	return cookies
}

// SetCookie sets a cookie for this session
func (s *Session) SetCookie(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cookies[name] = value
}

// SetCookies sets multiple cookies for this session
func (s *Session) SetCookies(cookies map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range cookies {
		s.cookies[k] = v
	}
}

// ClearCookies removes all cookies from this session
func (s *Session) ClearCookies() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cookies = make(map[string]string)
}

// ClearCache clears all cached URLs (removes If-None-Match/If-Modified-Since headers)
func (s *Session) ClearCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cacheEntries = make(map[string]*cacheEntry)
}

// SetProxy sets or updates the proxy for all protocols (HTTP/1.1, HTTP/2, HTTP/3)
// This closes existing connections and recreates transports with the new proxy
func (s *Session) SetProxy(proxyURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.transport != nil {
		var proxy *transport.ProxyConfig
		if proxyURL != "" {
			proxy = &transport.ProxyConfig{URL: proxyURL}
		}
		s.transport.SetProxy(proxy)
	}

	// Update config
	if s.Config != nil {
		s.Config.Proxy = proxyURL
		s.Config.TCPProxy = ""
		s.Config.UDPProxy = ""
	}
}

// SetTCPProxy sets the proxy for TCP protocols (HTTP/1.1, HTTP/2)
func (s *Session) SetTCPProxy(proxyURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.transport != nil {
		// Get current UDP proxy
		udpProxy := ""
		if s.Config != nil {
			udpProxy = s.Config.UDPProxy
		}

		proxy := &transport.ProxyConfig{
			TCPProxy: proxyURL,
			UDPProxy: udpProxy,
		}
		s.transport.SetProxy(proxy)
	}

	// Update config
	if s.Config != nil {
		s.Config.TCPProxy = proxyURL
		s.Config.Proxy = ""
	}
}

// SetUDPProxy sets the proxy for UDP protocols (HTTP/3 via SOCKS5 or MASQUE)
func (s *Session) SetUDPProxy(proxyURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.transport != nil {
		// Get current TCP proxy
		tcpProxy := ""
		if s.Config != nil {
			tcpProxy = s.Config.TCPProxy
		}

		proxy := &transport.ProxyConfig{
			TCPProxy: tcpProxy,
			UDPProxy: proxyURL,
		}
		s.transport.SetProxy(proxy)
	}

	// Update config
	if s.Config != nil {
		s.Config.UDPProxy = proxyURL
		s.Config.Proxy = ""
	}
}

// GetProxy returns the current proxy URL (unified proxy or TCP proxy)
func (s *Session) GetProxy() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Config == nil {
		return ""
	}
	if s.Config.Proxy != "" {
		return s.Config.Proxy
	}
	return s.Config.TCPProxy
}

// GetTCPProxy returns the current TCP proxy URL
func (s *Session) GetTCPProxy() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Config == nil {
		return ""
	}
	if s.Config.TCPProxy != "" {
		return s.Config.TCPProxy
	}
	return s.Config.Proxy
}

// GetUDPProxy returns the current UDP proxy URL
func (s *Session) GetUDPProxy() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Config == nil {
		return ""
	}
	if s.Config.UDPProxy != "" {
		return s.Config.UDPProxy
	}
	return s.Config.Proxy
}

// IdleTime returns how long since the session was last used
func (s *Session) IdleTime() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.LastUsed)
}

// GetTransport returns the session's transport
func (s *Session) GetTransport() *transport.Transport {
	return s.transport
}

// Stats returns session statistics
func (s *Session) Stats() SessionStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var transportStats map[string]interface{}
	if s.transport != nil {
		transportStats = s.transport.Stats()
	}

	return SessionStats{
		ID:              s.ID,
		Preset:          s.Config.Preset,
		CreatedAt:       s.CreatedAt,
		LastUsed:        s.LastUsed,
		RequestCount:    s.RequestCount,
		Active:          s.active,
		CookieCount:     len(s.cookies),
		CacheEntryCount: len(s.cacheEntries),
		Age:             time.Since(s.CreatedAt),
		IdleTime:        time.Since(s.LastUsed),
		TransportStats:  transportStats,
	}
}

// SessionStats contains session statistics
type SessionStats struct {
	ID              string
	Preset          string
	CreatedAt       time.Time
	LastUsed        time.Time
	RequestCount    int64
	Active          bool
	CookieCount     int
	CacheEntryCount int // Number of cached URLs (for If-None-Match/If-Modified-Since)
	Age             time.Duration
	IdleTime        time.Duration
	TransportStats  map[string]interface{}
}

// Helper functions
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func splitByNewline(s string) []string {
	var result []string
	var current string
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			result = append(result, current)
			current = ""
		} else if s[i] != '\r' { // Skip carriage returns
			current += string(s[i])
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func trim(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func splitCookies(s string) []string {
	var result []string
	var current string
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			// Check if this looks like a date separator
			rest := s[i+1:]
			if len(rest) > 0 && rest[0] == ' ' && len(rest) > 3 {
				next := rest[1:4]
				if len(next) > 0 && isDigit(next[0]) {
					current += ","
					continue
				}
			}
			result = append(result, trim(current))
			current = ""
		} else {
			current += string(s[i])
		}
	}
	if current != "" {
		result = append(result, trim(current))
	}
	return result
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// isRedirectStatus returns true for 3xx redirect status codes
func isRedirectStatus(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// StreamResponse wraps transport.StreamResponse for session-level streaming
type StreamResponse = transport.StreamResponse

// RequestStream executes an HTTP request and returns a streaming response
// The caller is responsible for closing the response when done
// Note: Streaming does NOT support redirects - use Request() for redirect handling
func (s *Session) RequestStream(ctx context.Context, req *transport.Request) (*StreamResponse, error) {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return nil, ErrSessionClosed
	}
	s.LastUsed = time.Now()
	s.RequestCount++

	if req.Headers == nil {
		req.Headers = make(map[string][]string)
	}

	// Add session cookies to request headers
	if len(s.cookies) > 0 {
		sessionCookies := ""
		for name, value := range s.cookies {
			if sessionCookies != "" {
				sessionCookies += "; "
			}
			sessionCookies += name + "=" + value
		}
		existingCookies := req.Headers["Cookie"]
		if len(existingCookies) > 0 && existingCookies[0] != "" {
			req.Headers["Cookie"] = []string{existingCookies[0] + "; " + sessionCookies}
		} else {
			req.Headers["Cookie"] = []string{sessionCookies}
		}
	}
	s.mu.Unlock()

	// Execute streaming request (no retry or redirect support for streams)
	resp, err := s.transport.DoStream(ctx, req)
	if err != nil {
		return nil, err
	}

	// Extract cookies from response
	s.extractCookies(resp.Headers)

	return resp, nil
}

// GetStream performs a streaming GET request
func (s *Session) GetStream(ctx context.Context, url string, headers map[string][]string) (*StreamResponse, error) {
	return s.RequestStream(ctx, &transport.Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// PostStream performs a streaming POST request
func (s *Session) PostStream(ctx context.Context, url string, body []byte, headers map[string][]string) (*StreamResponse, error) {
	return s.RequestStream(ctx, &transport.Request{
		Method:  "POST",
		URL:     url,
		Body:    body,
		Headers: headers,
	})
}

// resolveURL resolves a possibly relative URL against a base URL
func resolveURL(base, ref string) string {
	// If ref is absolute, return it
	if len(ref) > 7 && (ref[:7] == "http://" || ref[:8] == "https://") {
		return ref
	}

	// Parse base URL to get scheme and host
	schemeEnd := indexOf(base, "://")
	if schemeEnd == -1 {
		return ref
	}
	scheme := base[:schemeEnd]

	rest := base[schemeEnd+3:]
	pathStart := indexOf(rest, "/")

	var host, basePath string
	if pathStart == -1 {
		host = rest
		basePath = "/"
	} else {
		host = rest[:pathStart]
		basePath = rest[pathStart:]
	}

	// Handle different reference types
	if len(ref) > 0 && ref[0] == '/' {
		// Absolute path
		if len(ref) > 1 && ref[1] == '/' {
			// Protocol-relative URL (//example.com/path)
			return scheme + ":" + ref
		}
		return scheme + "://" + host + ref
	}

	// Relative path - resolve against base path
	lastSlash := -1
	for i := len(basePath) - 1; i >= 0; i-- {
		if basePath[i] == '/' {
			lastSlash = i
			break
		}
	}

	if lastSlash >= 0 {
		return scheme + "://" + host + basePath[:lastSlash+1] + ref
	}

	return scheme + "://" + host + "/" + ref
}

// ==================== Session Persistence ====================

// exportCookies exports all cookies as a slice of CookieState
func (s *Session) exportCookies() []CookieState {
	cookies := make([]CookieState, 0, len(s.cookies))
	for name, value := range s.cookies {
		cookies = append(cookies, CookieState{
			Name:  name,
			Value: value,
			Path:  "/", // Default path
		})
	}
	return cookies
}

// importCookies imports cookies from a slice of CookieState
func (s *Session) importCookies(cookies []CookieState) {
	for _, cookie := range cookies {
		s.cookies[cookie.Name] = cookie.Value
	}
}

// exportTLSSessions exports TLS sessions from all transport caches
func (s *Session) exportTLSSessions() (map[string]transport.TLSSessionState, error) {
	allSessions := make(map[string]transport.TLSSessionState)

	// Export from HTTP/1.1 transport session cache
	if h1 := s.transport.GetHTTP1Transport(); h1 != nil {
		if cache, ok := h1.GetSessionCache().(*transport.PersistableSessionCache); ok {
			sessions, err := cache.Export()
			if err == nil {
				for k, v := range sessions {
					allSessions["h1:"+k] = v
				}
			}
		}
	}

	// Export from HTTP/2 transport session cache
	if h2 := s.transport.GetHTTP2Transport(); h2 != nil {
		if cache, ok := h2.GetSessionCache().(*transport.PersistableSessionCache); ok {
			sessions, err := cache.Export()
			if err == nil {
				for k, v := range sessions {
					allSessions["h2:"+k] = v
				}
			}
		}
	}

	// Export from HTTP/3 transport session cache
	if h3 := s.transport.GetHTTP3Transport(); h3 != nil {
		if cache, ok := h3.GetSessionCache().(*transport.PersistableSessionCache); ok {
			sessions, err := cache.Export()
			if err == nil {
				for k, v := range sessions {
					allSessions["h3:"+k] = v
				}
			}
		}
	}

	return allSessions, nil
}

// importTLSSessions imports TLS sessions into transport caches
func (s *Session) importTLSSessions(sessions map[string]transport.TLSSessionState) error {
	// Group sessions by protocol
	h1Sessions := make(map[string]transport.TLSSessionState)
	h2Sessions := make(map[string]transport.TLSSessionState)
	h3Sessions := make(map[string]transport.TLSSessionState)

	for key, session := range sessions {
		if len(key) > 3 && key[2] == ':' {
			prefix := key[:2]
			actualKey := key[3:]
			switch prefix {
			case "h1":
				h1Sessions[actualKey] = session
			case "h2":
				h2Sessions[actualKey] = session
			case "h3":
				h3Sessions[actualKey] = session
			}
		}
	}

	// Import to HTTP/1.1 transport
	if h1 := s.transport.GetHTTP1Transport(); h1 != nil && len(h1Sessions) > 0 {
		if cache, ok := h1.GetSessionCache().(*transport.PersistableSessionCache); ok {
			cache.Import(h1Sessions)
		}
	}

	// Import to HTTP/2 transport
	if h2 := s.transport.GetHTTP2Transport(); h2 != nil && len(h2Sessions) > 0 {
		if cache, ok := h2.GetSessionCache().(*transport.PersistableSessionCache); ok {
			cache.Import(h2Sessions)
		}
	}

	// Import to HTTP/3 transport
	if h3 := s.transport.GetHTTP3Transport(); h3 != nil && len(h3Sessions) > 0 {
		if cache, ok := h3.GetSessionCache().(*transport.PersistableSessionCache); ok {
			cache.Import(h3Sessions)
		}
	}

	return nil
}

// exportECHConfigs exports ECH configs from HTTP/3 transport
// These are essential for session resumption - the same ECH config must be used
func (s *Session) exportECHConfigs() map[string]string {
	h3 := s.transport.GetHTTP3Transport()
	if h3 == nil {
		return nil
	}

	rawConfigs := h3.GetECHConfigCache()
	if len(rawConfigs) == 0 {
		return nil
	}

	// Base64 encode the configs for JSON storage
	result := make(map[string]string, len(rawConfigs))
	for host, config := range rawConfigs {
		result[host] = base64.StdEncoding.EncodeToString(config)
	}
	return result
}

// importECHConfigs imports ECH configs into HTTP/3 transport
// This must be called BEFORE importing TLS sessions
func (s *Session) importECHConfigs(configs map[string]string) {
	if len(configs) == 0 {
		return
	}

	h3 := s.transport.GetHTTP3Transport()
	if h3 == nil {
		return
	}

	// Decode base64 configs
	rawConfigs := make(map[string][]byte, len(configs))
	for host, b64Config := range configs {
		if decoded, err := base64.StdEncoding.DecodeString(b64Config); err == nil {
			rawConfigs[host] = decoded
		}
	}

	h3.SetECHConfigCache(rawConfigs)
}

// Marshal exports session state to JSON bytes
func (s *Session) Marshal() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Export TLS sessions
	tlsSessions, err := s.exportTLSSessions()
	if err != nil {
		// Continue without TLS sessions - cookies are more important
		tlsSessions = make(map[string]transport.TLSSessionState)
	}

	// Export cookies
	cookies := s.exportCookies()

	// Export ECH configs from HTTP/3 transport
	// This is critical for session resumption - we must save the ECH configs
	// that were used when creating the TLS session tickets
	echConfigs := s.exportECHConfigs()

	// Save the full config
	config := s.Config
	if config == nil {
		config = &protocol.SessionConfig{
			Preset: "chrome-131",
		}
	}

	state := &SessionState{
		Version:     SessionStateVersion,
		CreatedAt:   s.CreatedAt,
		UpdatedAt:   time.Now(),
		Config:      config,
		Cookies:     cookies,
		TLSSessions: tlsSessions,
		ECHConfigs:  echConfigs,
	}

	return json.MarshalIndent(state, "", "  ")
}

// Save exports session state to a file
func (s *Session) Save(path string) error {
	data, err := s.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	// Write with restrictive permissions (owner read/write only)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	return nil
}

// LoadSession loads a session from a file
func LoadSession(path string) (*Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	return UnmarshalSession(data)
}

// sessionStateV3 represents the old v3 session format for backwards compatibility
type sessionStateV3 struct {
	Version         int                                  `json:"version"`
	Preset          string                               `json:"preset"`
	ForceHTTP3      bool                                 `json:"force_http3"`
	ECHConfigDomain string                               `json:"ech_config_domain,omitempty"`
	CreatedAt       time.Time                            `json:"created_at"`
	UpdatedAt       time.Time                            `json:"updated_at"`
	Cookies         []CookieState                        `json:"cookies"`
	TLSSessions     map[string]transport.TLSSessionState `json:"tls_sessions"`
	ECHConfigs      map[string]string                    `json:"ech_configs,omitempty"`
	Proxy           string                               `json:"proxy,omitempty"`
	TCPProxy        string                               `json:"tcp_proxy,omitempty"`
	UDPProxy        string                               `json:"udp_proxy,omitempty"`
}

// UnmarshalSession loads a session from JSON bytes
func UnmarshalSession(data []byte) (*Session, error) {
	// First, check the version
	var versionCheck struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &versionCheck); err != nil {
		return nil, fmt.Errorf("failed to parse session data: %w", err)
	}

	if versionCheck.Version > SessionStateVersion {
		return nil, fmt.Errorf("session file version %d is newer than supported version %d",
			versionCheck.Version, SessionStateVersion)
	}

	// Handle v3 format (backwards compatibility)
	if versionCheck.Version <= 3 {
		return unmarshalSessionV3(data)
	}

	// Handle v4+ format (full config)
	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse session data: %w", err)
	}

	// Use the full config from the saved state
	config := state.Config
	if config == nil {
		config = &protocol.SessionConfig{
			Preset: "chrome-131",
		}
	}

	session := NewSession("", config)
	session.CreatedAt = state.CreatedAt

	// Import cookies
	session.mu.Lock()
	session.importCookies(state.Cookies)
	session.mu.Unlock()

	// Import ECH configs FIRST - this must be done before TLS sessions
	// because the TLS session tickets need the correct ECH config for resumption
	session.importECHConfigs(state.ECHConfigs)

	// Import TLS sessions
	if err := session.importTLSSessions(state.TLSSessions); err != nil {
		// Log but don't fail - cookies are the main thing
	}

	return session, nil
}

// unmarshalSessionV3 handles loading old v3 format sessions
func unmarshalSessionV3(data []byte) (*Session, error) {
	var state sessionStateV3
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse v3 session data: %w", err)
	}

	// Convert v3 fields to full config
	config := &protocol.SessionConfig{
		Preset:          state.Preset,
		ForceHTTP3:      state.ForceHTTP3,
		ECHConfigDomain: state.ECHConfigDomain,
		Proxy:           state.Proxy,
		TCPProxy:        state.TCPProxy,
		UDPProxy:        state.UDPProxy,
	}

	session := NewSession("", config)
	session.CreatedAt = state.CreatedAt

	// Import cookies
	session.mu.Lock()
	session.importCookies(state.Cookies)
	session.mu.Unlock()

	// Import ECH configs
	session.importECHConfigs(state.ECHConfigs)

	// Import TLS sessions
	if err := session.importTLSSessions(state.TLSSessions); err != nil {
		// Log but don't fail
	}

	return session, nil
}

// ValidateSessionFile validates a session file without loading it
func ValidateSessionFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read session file: %w", err)
	}

	// Check version first
	var versionCheck struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &versionCheck); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	if versionCheck.Version > SessionStateVersion {
		return fmt.Errorf("session file version %d is newer than supported version %d",
			versionCheck.Version, SessionStateVersion)
	}

	// Validate based on version
	if versionCheck.Version <= 3 {
		var state sessionStateV3
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if state.Preset == "" {
			return fmt.Errorf("missing preset in session file")
		}
	} else {
		var state SessionState
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if state.Config == nil || state.Config.Preset == "" {
			return fmt.Errorf("missing preset in session file")
		}
	}

	return nil
}
