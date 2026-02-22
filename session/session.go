package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
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

// SessionOptions contains additional options that can't be expressed in protocol.SessionConfig
// (e.g., interfaces and callbacks that can't be JSON serialized)
type SessionOptions struct {
	// SessionCacheBackend is an optional distributed cache for TLS sessions
	SessionCacheBackend transport.SessionCacheBackend

	// SessionCacheErrorCallback is called when backend operations fail
	SessionCacheErrorCallback transport.ErrorCallback

	// CustomJA3 is a JA3 fingerprint string for custom TLS fingerprinting
	CustomJA3 string

	// CustomJA3Extras provides extension data that JA3 cannot capture
	CustomJA3Extras *fingerprint.JA3Extras

	// CustomH2Settings overrides the preset's HTTP/2 settings (from Akamai fingerprint)
	CustomH2Settings *fingerprint.HTTP2Settings

	// CustomPseudoOrder overrides the pseudo-header order (from Akamai fingerprint)
	CustomPseudoOrder []string
}

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
	cookies   *CookieJar

	// Cache validation headers per URL (for If-None-Match, If-Modified-Since)
	cacheEntries map[string]*cacheEntry

	// Client hints requested by each host via Accept-CH header
	// Key: host (e.g., "example.com"), Value: set of requested hint names
	clientHints map[string]map[string]bool

	// Key log writer for TLS traffic decryption (Wireshark)
	keyLogWriter io.WriteCloser

	// refreshed indicates Refresh() was called - adds cache-control: max-age=0 to requests
	refreshed bool

	// switchProtocol is the protocol to switch to on Refresh()
	switchProtocol transport.Protocol

	mu     sync.RWMutex
	active bool
}

// NewSession creates a new session with its own connection pool
func NewSession(id string, config *protocol.SessionConfig) *Session {
	return NewSessionWithOptions(id, config, nil)
}

// NewSessionWithOptions creates a new session with additional options for distributed caching etc.
func NewSessionWithOptions(id string, config *protocol.SessionConfig, opts *SessionOptions) *Session {
	if id == "" {
		id = generateID()
	}

	presetName := "chrome-latest"
	if config != nil && config.Preset != "" {
		presetName = config.Preset
	}

	if config == nil {
		config = &protocol.SessionConfig{
			Preset:  presetName,
			Timeout: 30,
		}
	}

	// Create key log writer if KeyLogFile is specified
	var keyLogWriter io.WriteCloser
	if config.KeyLogFile != "" {
		var err error
		keyLogWriter, err = transport.NewKeyLogFileWriter(config.KeyLogFile)
		if err != nil {
			// Log error but continue - key logging is optional
			keyLogWriter = nil
		}
	}

	// Create transport config with ConnectTo, ECH, TLS-only, QUIC timeout, localAddr, and session cache settings
	var transportConfig *transport.TransportConfig
	needsConfig := len(config.ConnectTo) > 0 || config.ECHConfigDomain != "" || config.TLSOnly || config.QuicIdleTimeout > 0 || config.LocalAddress != "" || keyLogWriter != nil || config.EnableSpeculativeTLS
	if opts != nil && (opts.SessionCacheBackend != nil || opts.CustomJA3 != "" || opts.CustomH2Settings != nil || len(opts.CustomPseudoOrder) > 0) {
		needsConfig = true
	}

	if needsConfig {
		transportConfig = &transport.TransportConfig{
			ConnectTo:             config.ConnectTo,
			ECHConfigDomain:       config.ECHConfigDomain,
			TLSOnly:              config.TLSOnly,
			QuicIdleTimeout:      time.Duration(config.QuicIdleTimeout) * time.Second,
			LocalAddr:            config.LocalAddress,
			KeyLogWriter:         keyLogWriter,
			EnableSpeculativeTLS: config.EnableSpeculativeTLS,
		}
		// Add session cache backend if provided
		if opts != nil {
			transportConfig.SessionCacheBackend = opts.SessionCacheBackend
			transportConfig.SessionCacheErrorCallback = opts.SessionCacheErrorCallback
			// Add custom fingerprint settings
			transportConfig.CustomJA3 = opts.CustomJA3
			transportConfig.CustomJA3Extras = opts.CustomJA3Extras
			transportConfig.CustomH2Settings = opts.CustomH2Settings
			transportConfig.CustomPseudoOrder = opts.CustomPseudoOrder
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

	// Disable TLS certificate verification if requested
	if config.InsecureSkipVerify {
		t.SetInsecureSkipVerify(true)
	}

	// Set protocol preference
	if config.ForceHTTP1 {
		t.SetProtocol(transport.ProtocolHTTP1)
	} else if config.ForceHTTP2 {
		t.SetProtocol(transport.ProtocolHTTP2)
	} else if config.ForceHTTP3 {
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

	// Disable ECH lookup for faster first request
	if config.DisableECH {
		t.SetDisableECH(true)
	}

	// Parse switch protocol if configured
	switchProto := transport.ProtocolAuto
	if config.SwitchProtocol != "" {
		p, err := parseProtocol(config.SwitchProtocol)
		if err == nil {
			switchProto = p
		}
	}

	return &Session{
		ID:             id,
		CreatedAt:      time.Now(),
		LastUsed:       time.Now(),
		RequestCount:   0,
		Config:         config,
		transport:      t,
		cookies:        NewCookieJar(),
		cacheEntries:   make(map[string]*cacheEntry),
		clientHints:    make(map[string]map[string]bool),
		keyLogWriter:   keyLogWriter,
		switchProtocol: switchProto,
		active:         true,
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

	// Add cache-control: max-age=0 if session was refreshed (simulates browser F5)
	if s.refreshed {
		req.Headers["cache-control"] = []string{"max-age=0"}
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

	// Extract host for client hints
	host := extractHost(req.URL)

	// Parse request URL for cookie matching
	requestHost := extractHost(req.URL)
	requestPath := extractPath(req.URL)
	requestSecure := isSecureURL(req.URL)

	// Save original per-request Cookie header before retry loop to prevent accumulation
	var origCookie string
	if c := req.Headers["Cookie"]; len(c) > 0 {
		origCookie = c[0]
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Build Cookie header fresh each attempt from original + session cookies
		sessionCookies := s.cookies.BuildCookieHeader(requestHost, requestPath, requestSecure)
		if sessionCookies != "" {
			if origCookie != "" {
				req.Headers["Cookie"] = []string{origCookie + "; " + sessionCookies}
			} else {
				req.Headers["Cookie"] = []string{sessionCookies}
			}
		} else if origCookie != "" {
			req.Headers["Cookie"] = []string{origCookie}
		}

		// Apply high-entropy client hints if the host requested them via Accept-CH
		s.applyClientHints(host, req.Headers)

		resp, err = s.transport.Do(ctx, req)

		// If no error and no retry config, or this is the last attempt, break
		if maxRetries == 0 {
			break
		}

		// Extract cookies from EVERY response (even 429s, 500s, etc.)
		// This mimics browser behavior where cookies are stored regardless of status
		if resp != nil {
			s.extractCookies(resp.Headers, req.URL)
			// Also parse Accept-CH from intermediate responses
			s.parseAcceptCH(host, resp.Headers)
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
	s.extractCookies(resp.Headers, req.URL)

	// Parse Accept-CH header to store requested client hints for this host
	s.parseAcceptCH(host, resp.Headers)

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

// extractCookies extracts cookies with full metadata from response headers
// requestURL is the URL that was requested (needed for domain scoping)
func (s *Session) extractCookies(headers map[string][]string, requestURL string) {
	// Try both cases - some responses might have different casing
	setCookies, exists := headers["set-cookie"]
	if !exists {
		setCookies, exists = headers["Set-Cookie"]
	}
	if !exists || len(setCookies) == 0 {
		return
	}

	requestHost := extractHost(requestURL)
	requestSecure := isSecureURL(requestURL)

	// Each Set-Cookie header is now a separate element in the slice
	for _, line := range setCookies {
		line = trim(line)
		if line == "" {
			continue
		}

		cookie := &CookieData{}

		// Split by semicolon to get name=value and attributes
		parts := splitBySemicolon(line)
		if len(parts) == 0 {
			continue
		}

		// First part is name=value
		firstPart := trim(parts[0])
		eqIdx := indexOf(firstPart, "=")
		if eqIdx == -1 {
			continue
		}
		cookie.Name = trim(firstPart[:eqIdx])
		cookie.Value = trim(firstPart[eqIdx+1:])
		if cookie.Name == "" {
			continue
		}

		// Parse attributes
		for i := 1; i < len(parts); i++ {
			attr := trim(parts[i])
			if attr == "" {
				continue
			}

			attrLower := toLowerASCII(attr)

			// Check for flag attributes (no value)
			if attrLower == "secure" {
				cookie.Secure = true
				continue
			}
			if attrLower == "httponly" {
				cookie.HttpOnly = true
				continue
			}

			// Check for key=value attributes
			attrEqIdx := indexOf(attr, "=")
			if attrEqIdx == -1 {
				continue
			}

			attrName := toLowerASCII(trim(attr[:attrEqIdx]))
			attrValue := trim(attr[attrEqIdx+1:])

			switch attrName {
			case "domain":
				cookie.Domain = attrValue
			case "path":
				cookie.Path = attrValue
			case "expires":
				// Parse expiration time
				if t, err := parseHTTPDate(attrValue); err == nil {
					cookie.Expires = &t
				}
			case "max-age":
				cookie.MaxAge = parseIntSimple(attrValue)
			case "samesite":
				// Normalize to capitalized form
				sameSiteLower := toLowerASCII(attrValue)
				switch sameSiteLower {
				case "strict":
					cookie.SameSite = "Strict"
				case "lax":
					cookie.SameSite = "Lax"
				case "none":
					cookie.SameSite = "None"
				default:
					cookie.SameSite = attrValue
				}
			}
		}

		// Use CookieJar to store with proper domain scoping
		s.cookies.Set(requestHost, cookie, requestSecure)
	}
}

// splitBySemicolon splits a string by semicolon
func splitBySemicolon(s string) []string {
	var result []string
	var current string
	for i := 0; i < len(s); i++ {
		if s[i] == ';' {
			result = append(result, current)
			current = ""
		} else {
			current += string(s[i])
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// parseIntSimple parses an integer from a string, returns 0 on error
func parseIntSimple(s string) int {
	result := 0
	negative := false
	start := 0
	if len(s) > 0 && s[0] == '-' {
		negative = true
		start = 1
	}
	for i := start; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			result = result*10 + int(s[i]-'0')
		} else {
			break
		}
	}
	if negative {
		result = -result
	}
	return result
}

// parseHTTPDate parses an HTTP date string (RFC1123 format)
func parseHTTPDate(s string) (time.Time, error) {
	// Try RFC1123 format first (most common)
	if t, err := time.Parse(time.RFC1123, s); err == nil {
		return t, nil
	}
	// Try RFC1123Z (with numeric timezone)
	if t, err := time.Parse(time.RFC1123Z, s); err == nil {
		return t, nil
	}
	// Try RFC850 (obsolete but still used)
	if t, err := time.Parse(time.RFC850, s); err == nil {
		return t, nil
	}
	// Try ANSI C format
	if t, err := time.Parse(time.ANSIC, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unable to parse date: %s", s)
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

// parseAcceptCH parses the Accept-CH response header and stores the requested client hints
// for the given host. On subsequent requests to this host, the session will send the
// high-entropy client hints that were requested.
func (s *Session) parseAcceptCH(host string, headers map[string][]string) {
	// Helper to get first value from header (case-insensitive)
	getHeader := func(key string) string {
		if values := headers[key]; len(values) > 0 {
			return values[0]
		}
		return ""
	}

	// Look for Accept-CH header (case-insensitive)
	acceptCH := getHeader("accept-ch")
	if acceptCH == "" {
		acceptCH = getHeader("Accept-CH")
	}
	if acceptCH == "" {
		return
	}

	// Parse the comma-separated list of hint names
	hints := make(map[string]bool)
	for _, hint := range splitByComma(acceptCH) {
		hint = trim(toLowerASCII(hint))
		if hint != "" {
			hints[hint] = true
		}
	}

	if len(hints) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.clientHints[host] = hints
}

// applyClientHints adds high-entropy client hints headers to the request if the host
// has previously requested them via Accept-CH header
func (s *Session) applyClientHints(host string, headers map[string][]string) {
	s.mu.RLock()
	hints, exists := s.clientHints[host]
	s.mu.RUnlock()

	if !exists || len(hints) == 0 {
		return
	}

	// Get platform info for generating hint values
	platform := s.getPlatform()

	// Map of hint names to their header names and values
	// Only add hints that were explicitly requested via Accept-CH
	hintValues := map[string]struct {
		header string
		value  string
	}{
		"sec-ch-ua-arch":              {"Sec-Ch-Ua-Arch", platform.Arch},
		"sec-ch-ua-bitness":           {"Sec-Ch-Ua-Bitness", platform.Bitness},
		"sec-ch-ua-full-version-list": {"Sec-Ch-Ua-Full-Version-List", platform.FullVersionList},
		"sec-ch-ua-model":             {"Sec-Ch-Ua-Model", platform.Model},
		"sec-ch-ua-platform-version":  {"Sec-Ch-Ua-Platform-Version", platform.PlatformVersion},
		"sec-ch-ua-wow64":             {"Sec-Ch-Ua-Wow64", platform.Wow64},
	}

	for hintName, hintInfo := range hintValues {
		if hints[hintName] && hintInfo.value != "" {
			headers[hintInfo.header] = []string{hintInfo.value}
		}
	}
}

// platformInfo holds platform-specific values for client hints
type platformInfo struct {
	Arch            string // e.g., `"x86"`
	Bitness         string // e.g., `"64"`
	FullVersionList string // e.g., `"Google Chrome";v="131.0.0.0", ...`
	Model           string // e.g., `""` for desktop
	PlatformVersion string // e.g., `"15.0.0"` for macOS, `"10.0.0"` for Windows
	Wow64           string // e.g., `?0` or `?1`
}

// getPlatform returns platform info based on the preset being used
func (s *Session) getPlatform() platformInfo {
	// Default values for Chrome on Linux x86_64
	info := platformInfo{
		Arch:            `"x86"`,
		Bitness:         `"64"`,
		Model:           `""`,
		PlatformVersion: `"6.5.0"`, // Linux kernel version
		Wow64:           "?0",
	}

	// Get full version list based on preset
	presetName := "chrome-latest"
	if s.Config != nil && s.Config.Preset != "" {
		presetName = s.Config.Preset
	}

	// Generate full version list based on preset
	// Format: "Brand";v="full.version", ...
	if contains(presetName, "chrome-131") {
		info.FullVersionList = `"Google Chrome";v="131.0.6778.86", "Chromium";v="131.0.6778.86", "Not_A Brand";v="24.0.0.0"`
	} else if contains(presetName, "chrome-133") {
		info.FullVersionList = `"Google Chrome";v="133.0.6943.98", "Chromium";v="133.0.6943.98", "Not_A Brand";v="24.0.0.0"`
	} else if contains(presetName, "chrome-141") {
		info.FullVersionList = `"Google Chrome";v="141.0.7254.112", "Chromium";v="141.0.7254.112", "Not_A Brand";v="24.0.0.0"`
	} else if contains(presetName, "chrome-143") {
		info.FullVersionList = `"Google Chrome";v="143.0.7312.86", "Chromium";v="143.0.7312.86", "Not A(Brand";v="24.0.0.0"`
	} else if contains(presetName, "chrome-144") {
		info.FullVersionList = `"Not(A:Brand";v="8.0.0.0", "Chromium";v="144.0.7559.132", "Google Chrome";v="144.0.7559.132"`
	} else {
		// Default: Chrome 145
		info.FullVersionList = `"Not:A-Brand";v="99.0.0.0", "Google Chrome";v="145.0.7632.75", "Chromium";v="145.0.7632.75"`
	}

	// Adjust platform-specific values
	if contains(presetName, "windows") {
		info.PlatformVersion = `"15.0.0"` // Windows 11
	} else if contains(presetName, "macos") {
		info.PlatformVersion = `"14.5.0"` // macOS Sonoma
	}

	return info
}

// Helper functions for client hints
func splitByComma(s string) []string {
	var result []string
	var current string
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(s[i])
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func toLowerASCII(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + 32
		}
		result[i] = c
	}
	return string(result)
}

func contains(s, substr string) bool {
	return indexOf(s, substr) != -1
}

// extractHost extracts the host from a URL string
func extractHost(urlStr string) string {
	// Remove protocol prefix
	host := urlStr
	if idx := indexOf(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	// Remove path
	if idx := indexOf(host, "/"); idx != -1 {
		host = host[:idx]
	}
	// Remove port for matching (IPv6-aware)
	if len(host) > 0 && host[0] == '[' {
		// IPv6 bracketed: [::1]:443 → ::1
		if idx := indexOf(host, "]"); idx != -1 {
			host = host[1:idx]
		}
	} else if idx := indexOf(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}

// extractPath extracts the path from a URL string
func extractPath(urlStr string) string {
	// Remove protocol prefix
	path := urlStr
	if idx := indexOf(path, "://"); idx != -1 {
		path = path[idx+3:]
	}
	// Find path start
	if idx := indexOf(path, "/"); idx != -1 {
		path = path[idx:]
		// Remove query string
		if qIdx := indexOf(path, "?"); qIdx != -1 {
			path = path[:qIdx]
		}
		// Remove fragment
		if fIdx := indexOf(path, "#"); fIdx != -1 {
			path = path[:fIdx]
		}
		return path
	}
	return "/"
}

// isSecureURL returns true if the URL uses HTTPS
func isSecureURL(urlStr string) bool {
	return len(urlStr) >= 8 && urlStr[:8] == "https://"
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

	// Close key log writer if we opened one
	if s.keyLogWriter != nil {
		s.keyLogWriter.Close()
		s.keyLogWriter = nil
	}
}

// parseProtocol converts a protocol string to transport.Protocol.
func parseProtocol(proto string) (transport.Protocol, error) {
	switch proto {
	case "h1", "http1", "1":
		return transport.ProtocolHTTP1, nil
	case "h2", "http2", "2":
		return transport.ProtocolHTTP2, nil
	case "h3", "http3", "3":
		return transport.ProtocolHTTP3, nil
	case "auto", "":
		return transport.ProtocolAuto, nil
	default:
		return transport.ProtocolAuto, fmt.Errorf("invalid protocol %q: must be h1, h2, h3, or auto", proto)
	}
}

// Refresh closes all connections but keeps TLS session caches and cookies intact.
// This simulates a browser page refresh - new TCP/QUIC connections but TLS resumption.
// If a switchProtocol was configured, the session switches to that protocol.
func (s *Session) Refresh() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return
	}

	// Set refreshed flag - adds cache-control: max-age=0 to subsequent requests
	s.refreshed = true

	if s.transport != nil {
		if s.switchProtocol != transport.ProtocolAuto {
			s.transport.RefreshWithProtocol(s.switchProtocol)
		} else {
			s.transport.Refresh()
		}
	}
}

// RefreshWithProtocol closes all connections and switches to a new protocol.
// The protocol change persists for future Refresh() calls as well.
// Valid protocols: "h1", "h2", "h3", "auto".
func (s *Session) RefreshWithProtocol(proto string) error {
	p, err := parseProtocol(proto)
	if err != nil {
		return err
	}

	// Validate H3 support if switching to H3
	if p == transport.ProtocolHTTP3 && s.Config != nil {
		preset := fingerprint.Get(s.Config.Preset)
		if preset != nil && !preset.SupportHTTP3 {
			return fmt.Errorf("preset %q does not support HTTP/3", s.Config.Preset)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return ErrSessionClosed
	}

	s.refreshed = true
	s.switchProtocol = p

	if s.transport != nil {
		s.transport.RefreshWithProtocol(p)
	}

	return nil
}

// Touch updates the last used timestamp
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastUsed = time.Now()
}

// GetCookies returns all cookies for this session (name -> value)
// Note: This returns a flat map for backward compatibility. Multiple cookies
// with the same name from different domains will only show the last one.
func (s *Session) GetCookies() map[string]string {
	return s.cookies.GetAll()
}

// SetCookie sets a cookie for this session
// Note: This sets a "global" cookie that will be sent to all domains.
// For domain-specific cookies, use Set-Cookie headers from responses.
func (s *Session) SetCookie(name, value string) {
	s.cookies.SetSimple(name, value)
}

// SetCookies sets multiple cookies for this session
// Note: These are "global" cookies that will be sent to all domains.
func (s *Session) SetCookies(cookies map[string]string) {
	for k, v := range cookies {
		s.cookies.SetSimple(k, v)
	}
}

// ClearCookies removes all cookies from this session
func (s *Session) ClearCookies() {
	s.cookies.Clear()
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

// SetHeaderOrder sets a custom header order for all requests.
// Pass nil or empty slice to reset to preset's default order.
// Order should contain lowercase header names.
func (s *Session) SetHeaderOrder(order []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.transport != nil {
		s.transport.SetHeaderOrder(order)
	}
}

// GetHeaderOrder returns the current header order.
// Returns preset's default order if no custom order is set.
func (s *Session) GetHeaderOrder() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.transport != nil {
		return s.transport.GetHeaderOrder()
	}
	return nil
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

// SetSessionIdentifier sets a session identifier for TLS cache key isolation.
// This is used when the session is registered with a LocalProxy to ensure
// TLS sessions are isolated per proxy/session configuration.
func (s *Session) SetSessionIdentifier(sessionId string) {
	if s.transport != nil {
		s.transport.SetSessionIdentifier(sessionId)
	}
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
		CookieCount:     s.cookies.Count(),
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

	// Add session cookies to request headers using proper domain/path matching
	requestHost := extractHost(req.URL)
	requestPath := extractPath(req.URL)
	requestSecure := isSecureURL(req.URL)
	sessionCookies := s.cookies.BuildCookieHeader(requestHost, requestPath, requestSecure)
	if sessionCookies != "" {
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
	s.extractCookies(resp.Headers, req.URL)

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

// resolveURL resolves a possibly relative URL against a base URL (RFC 3986)
func resolveURL(base, ref string) string {
	if len(ref) > 7 && (ref[:7] == "http://" || ref[:8] == "https://") {
		return ref
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return base + "/" + ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return base + "/" + ref
	}
	return baseURL.ResolveReference(refURL).String()
}

// ==================== Session Persistence ====================

// exportCookies exports all cookies in v5 format (domain-keyed)
func (s *Session) exportCookies() map[string][]CookieState {
	return s.cookies.Export()
}

// importCookies imports cookies from v5 format (domain-keyed)
func (s *Session) importCookies(cookies map[string][]CookieState) {
	s.cookies.Import(cookies)
}

// importCookiesV4 imports cookies from v4 format (flat list)
func (s *Session) importCookiesV4(cookies []CookieState) {
	s.cookies.ImportV4(cookies)
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
			Preset: "chrome-145",
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

	// Handle v4 format (flat cookie list)
	if versionCheck.Version == 4 {
		return unmarshalSessionV4(data)
	}

	// Handle v5 format (domain-keyed cookies)
	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse session data: %w", err)
	}

	// Use the full config from the saved state
	config := state.Config
	if config == nil {
		config = &protocol.SessionConfig{
			Preset: "chrome-145",
		}
	}

	session := NewSession("", config)
	session.CreatedAt = state.CreatedAt

	// Import cookies (v5 format)
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

// unmarshalSessionV4 handles loading v4 format sessions (flat cookie list)
func unmarshalSessionV4(data []byte) (*Session, error) {
	var state SessionStateV4
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse v4 session data: %w", err)
	}

	// Use the full config from the saved state
	config := state.Config
	if config == nil {
		config = &protocol.SessionConfig{
			Preset: "chrome-145",
		}
	}

	session := NewSession("", config)
	session.CreatedAt = state.CreatedAt

	// Import cookies from v4 format (flat list)
	session.mu.Lock()
	session.importCookiesV4(state.Cookies)
	session.mu.Unlock()

	// Import ECH configs FIRST
	session.importECHConfigs(state.ECHConfigs)

	// Import TLS sessions
	if err := session.importTLSSessions(state.TLSSessions); err != nil {
		// Log but don't fail
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

	// Import cookies from v3 format (flat list, same as v4)
	session.mu.Lock()
	session.importCookiesV4(state.Cookies)
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
	} else if versionCheck.Version == 4 {
		var state SessionStateV4
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if state.Config == nil || state.Config.Preset == "" {
			return fmt.Errorf("missing preset in session file")
		}
	} else {
		// v5+
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
