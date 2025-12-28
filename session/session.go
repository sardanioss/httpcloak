package session

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

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
		id = uuid.New().String()
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

	// Create transport with optional proxy
	var t *transport.Transport
	if config.Proxy != "" {
		proxy := &transport.ProxyConfig{
			URL: config.Proxy,
		}
		t = transport.NewTransportWithProxy(presetName, proxy)
	} else {
		t = transport.NewTransport(presetName)
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
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return nil, ErrSessionClosed
	}
	s.LastUsed = time.Now()
	s.RequestCount++

	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}

	// Add cookies to request headers
	if len(s.cookies) > 0 {
		cookieHeader := ""
		for name, value := range s.cookies {
			if cookieHeader != "" {
				cookieHeader += "; "
			}
			cookieHeader += name + "=" + value
		}
		req.Headers["Cookie"] = cookieHeader
	}

	// Add cache validation headers (If-None-Match, If-Modified-Since)
	// This makes requests look like a real browser that caches resources
	if cached, exists := s.cacheEntries[req.URL]; exists {
		if cached.etag != "" {
			req.Headers["If-None-Match"] = cached.etag
		}
		if cached.lastModified != "" {
			req.Headers["If-Modified-Since"] = cached.lastModified
		}
	}
	s.mu.Unlock()

	// Execute request using session's dedicated transport
	resp, err := s.transport.Do(ctx, req)
	if err != nil {
		return nil, err
	}

	// Extract and store cookies from response
	s.extractCookies(resp.Headers)

	// Store cache validation headers from response for future requests
	s.storeCacheHeaders(req.URL, resp.Headers)

	return resp, nil
}

// Get performs a GET request
func (s *Session) Get(ctx context.Context, url string, headers map[string]string) (*transport.Response, error) {
	return s.Request(ctx, &transport.Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// Post performs a POST request
func (s *Session) Post(ctx context.Context, url string, body []byte, headers map[string]string) (*transport.Response, error) {
	return s.Request(ctx, &transport.Request{
		Method:  "POST",
		URL:     url,
		Body:    body,
		Headers: headers,
	})
}

// extractCookies extracts cookies from response headers
func (s *Session) extractCookies(headers map[string]string) {
	// Try both cases - some responses might have different casing
	setCookie, exists := headers["set-cookie"]
	if !exists {
		setCookie, exists = headers["Set-Cookie"]
	}
	if !exists {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Set-Cookie headers are joined with newlines (one cookie per line)
	cookies := splitByNewline(setCookie)
	for _, cookie := range cookies {
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
func (s *Session) storeCacheHeaders(url string, headers map[string]string) {
	// Look for ETag header (case-insensitive)
	etag := headers["etag"]
	if etag == "" {
		etag = headers["ETag"]
	}

	// Look for Last-Modified header (case-insensitive)
	lastModified := headers["last-modified"]
	if lastModified == "" {
		lastModified = headers["Last-Modified"]
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
