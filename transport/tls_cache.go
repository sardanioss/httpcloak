package transport

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	tls "github.com/sardanioss/utls"
)

// SessionCacheBackend is the interface for distributed TLS session storage.
// Implementations can use Redis, Memcached, or any other distributed cache.
// All methods should be safe for concurrent use.
type SessionCacheBackend interface {
	// Get retrieves a TLS session for the given key.
	// Returns nil, nil if not found.
	// Returns nil, error if backend error (will be propagated to caller).
	Get(ctx context.Context, key string) (*TLSSessionState, error)

	// Put stores a TLS session with the given TTL.
	// TTL should typically be ~24 hours (TLS session ticket lifetime).
	// Returns error if backend error (will be propagated to caller).
	Put(ctx context.Context, key string, session *TLSSessionState, ttl time.Duration) error

	// Delete removes a session from the cache.
	// Returns error if backend error.
	Delete(ctx context.Context, key string) error

	// GetECHConfig retrieves ECH config for a host (required for HTTP/3).
	// Returns nil, nil if not found.
	GetECHConfig(ctx context.Context, key string) ([]byte, error)

	// PutECHConfig stores ECH config for a host.
	PutECHConfig(ctx context.Context, key string, config []byte, ttl time.Duration) error
}

// CacheKeyPrefix constants for distributed cache
const (
	CacheKeyPrefixSession = "httpcloak:sessions"
	CacheKeyPrefixECH     = "httpcloak:ech"
)

// FormatSessionCacheKey creates a cache key for TLS sessions.
// Format: httpcloak:sessions:{preset}:{protocol}:{host}:{port}
func FormatSessionCacheKey(preset, protocol, host, port string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%s", CacheKeyPrefixSession, preset, protocol, host, port)
}

// FormatSessionCacheKeyWithID creates a cache key for TLS sessions that includes a session identifier.
// This is used when sessions need to be isolated per proxy/session (e.g., different upstream proxies).
// Format: httpcloak:sessions:{sessionId}:{preset}:{protocol}:{host}:{port}
func FormatSessionCacheKeyWithID(sessionId, preset, protocol, host, port string) string {
	if sessionId == "" {
		return FormatSessionCacheKey(preset, protocol, host, port)
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s", CacheKeyPrefixSession, sessionId, preset, protocol, host, port)
}

// FormatECHCacheKey creates a cache key for ECH configs.
// Format: httpcloak:ech:{preset}:{host}:{port}
func FormatECHCacheKey(preset, host, port string) string {
	return fmt.Sprintf("%s:%s:%s:%s", CacheKeyPrefixECH, preset, host, port)
}

// TLSSessionMaxAge is the maximum age for TLS sessions (24 hours)
// TLS session tickets typically expire after 24-48 hours
const TLSSessionMaxAge = 24 * time.Hour

// TLSSessionCacheMaxSize is the maximum number of sessions to cache
// Matches the size used by pool/pool.go for LRU session cache
const TLSSessionCacheMaxSize = 32

// TLSSessionState represents a serializable TLS session
type TLSSessionState struct {
	Ticket    string    `json:"ticket"`     // base64 encoded
	State     string    `json:"state"`      // base64 encoded
	CreatedAt time.Time `json:"created_at"`
}

// ToClientSessionState converts a serialized TLS session back to a ClientSessionState.
func (s *TLSSessionState) ToClientSessionState() (*tls.ClientSessionState, error) {
	// Decode ticket
	ticket, err := base64.StdEncoding.DecodeString(s.Ticket)
	if err != nil {
		return nil, fmt.Errorf("decode ticket: %w", err)
	}

	// Decode state
	stateBytes, err := base64.StdEncoding.DecodeString(s.State)
	if err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}

	// Parse session state
	state, err := tls.ParseSessionState(stateBytes)
	if err != nil {
		return nil, fmt.Errorf("parse session state: %w", err)
	}

	// Create resumption state
	clientState, err := tls.NewResumptionState(ticket, state)
	if err != nil {
		return nil, fmt.Errorf("create resumption state: %w", err)
	}

	return clientState, nil
}

// NewTLSSessionState creates a TLSSessionState from a ClientSessionState.
func NewTLSSessionState(cs *tls.ClientSessionState) (*TLSSessionState, error) {
	if cs == nil {
		return nil, fmt.Errorf("client session state is nil")
	}

	// Get resumption state
	ticket, state, err := cs.ResumptionState()
	if err != nil {
		return nil, fmt.Errorf("get resumption state: %w", err)
	}

	if state == nil || ticket == nil {
		return nil, fmt.Errorf("invalid session state")
	}

	// Serialize the SessionState to bytes
	stateBytes, err := state.Bytes()
	if err != nil {
		return nil, fmt.Errorf("serialize session state: %w", err)
	}

	return &TLSSessionState{
		Ticket:    base64.StdEncoding.EncodeToString(ticket),
		State:     base64.StdEncoding.EncodeToString(stateBytes),
		CreatedAt: time.Now(),
	}, nil
}

// ErrorCallback is called when a backend operation fails.
// This allows users to handle errors from async backend operations.
type ErrorCallback func(operation string, key string, err error)

// PersistableSessionCache implements tls.ClientSessionCache
// with export/import capabilities for session persistence and LRU eviction.
// Optionally supports a distributed backend for cross-instance session sharing.
type PersistableSessionCache struct {
	mu          sync.RWMutex
	sessions    map[string]*cachedSession
	accessOrder []string // LRU order: oldest at front, newest at back

	// Optional distributed cache backend
	backend       SessionCacheBackend
	preset        string        // Preset name for cache key generation
	protocol      string        // Protocol identifier (h1, h2, h3)
	sessionId     string        // Optional session identifier for cache key isolation
	errorCallback atomic.Pointer[ErrorCallback] // Optional callback for backend errors (lock-free)
}

type cachedSession struct {
	state     *tls.ClientSessionState
	createdAt time.Time
}

// NewPersistableSessionCache creates a new persistable session cache
func NewPersistableSessionCache() *PersistableSessionCache {
	return &PersistableSessionCache{
		sessions: make(map[string]*cachedSession),
	}
}

// NewPersistableSessionCacheWithBackend creates a session cache with a distributed backend.
// The preset and protocol are used to generate cache keys for the backend.
// Protocol should be one of: "h1", "h2", "h3"
// The errorCallback is optional and will be called when backend operations fail.
func NewPersistableSessionCacheWithBackend(backend SessionCacheBackend, preset, protocol string, errorCallback ErrorCallback) *PersistableSessionCache {
	cache := &PersistableSessionCache{
		sessions: make(map[string]*cachedSession),
		backend:  backend,
		preset:   preset,
		protocol: protocol,
	}
	if errorCallback != nil {
		cache.errorCallback.Store(&errorCallback)
	}
	return cache
}

// SetBackend configures a distributed cache backend for this session cache.
// This allows setting the backend after construction.
func (c *PersistableSessionCache) SetBackend(backend SessionCacheBackend, preset, protocol string, errorCallback ErrorCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backend = backend
	c.preset = preset
	c.protocol = protocol
	if errorCallback != nil {
		c.errorCallback.Store(&errorCallback)
	} else {
		c.errorCallback.Store(nil)
	}
}

// SetSessionIdentifier sets an optional session identifier for cache key isolation.
// When set, cache keys will include this identifier to prevent TLS session sharing
// across different proxy configurations (e.g., when using different upstream proxies).
// This is useful in distributed scenarios where different "sessions" should have
// isolated TLS session caches even when targeting the same host.
func (c *PersistableSessionCache) SetSessionIdentifier(sessionId string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionId = sessionId
}

// GetSessionIdentifier returns the current session identifier.
func (c *PersistableSessionCache) GetSessionIdentifier() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionId
}

// SetErrorCallback sets the callback for backend errors.
func (c *PersistableSessionCache) SetErrorCallback(callback ErrorCallback) {
	if callback != nil {
		c.errorCallback.Store(&callback)
	} else {
		c.errorCallback.Store(nil)
	}
}

// reportError reports an error via the error callback if configured.
// Lock-free: uses atomic load so it's safe to call from any context
// (including while holding mu).
func (c *PersistableSessionCache) reportError(operation, key string, err error) {
	if err == nil {
		return
	}
	if cb := c.errorCallback.Load(); cb != nil {
		(*cb)(operation, key, err)
	}
}

// Get implements tls.ClientSessionCache.
// If a backend is configured, it will also check the backend on local cache miss.
func (c *PersistableSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check local cache first (fast path)
	if cached, ok := c.sessions[sessionKey]; ok {
		// Move to end of accessOrder (most recently used)
		c.moveToEnd(sessionKey)
		return cached.state, true
	}

	// Check backend if configured (slow path)
	if c.backend != nil {
		state, err := c.getFromBackend(sessionKey)
		if err != nil {
			// Report error via callback
			c.reportError("get", sessionKey, err)
		}
		if state != nil {
			return state, true
		}
	}

	return nil, false
}

// getFromBackend retrieves a session from the distributed backend.
// Must be called with lock held.
func (c *PersistableSessionCache) getFromBackend(sessionKey string) (*tls.ClientSessionState, error) {
	// Parse host:port from sessionKey
	host, port := parseSessionKey(sessionKey)
	if host == "" {
		return nil, nil
	}

	// Create backend cache key (includes session ID if set for isolation)
	backendKey := FormatSessionCacheKeyWithID(c.sessionId, c.preset, c.protocol, host, port)

	// Use background context with timeout for backend operations
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Fetch from backend
	sessionState, err := c.backend.Get(ctx, backendKey)
	if err != nil {
		return nil, err
	}
	if sessionState == nil {
		return nil, nil
	}

	// Check if session is expired
	if time.Since(sessionState.CreatedAt) > TLSSessionMaxAge {
		return nil, nil
	}

	// Convert to ClientSessionState
	clientState, err := sessionState.ToClientSessionState()
	if err != nil {
		return nil, err
	}

	// Promote to local cache
	c.sessions[sessionKey] = &cachedSession{
		state:     clientState,
		createdAt: sessionState.CreatedAt,
	}
	c.accessOrder = append(c.accessOrder, sessionKey)

	// Enforce max size
	c.evictIfNeeded()

	return clientState, nil
}

// parseSessionKey extracts host and port from a session key.
// Session keys can be in formats like "host:port" or "scheme://host:port"
func parseSessionKey(key string) (host, port string) {
	// Handle scheme://host:port format
	if idx := len("https://"); len(key) > idx && key[:idx] == "https://" {
		key = key[idx:]
	} else if idx := len("http://"); len(key) > idx && key[:idx] == "http://" {
		key = key[idx:]
	}

	// Find last colon for port
	lastColon := -1
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == ':' {
			lastColon = i
			break
		}
	}

	if lastColon == -1 {
		return key, "443" // Default to HTTPS port
	}

	return key[:lastColon], key[lastColon+1:]
}

// evictIfNeeded removes oldest entries if over capacity.
// Must be called with lock held.
func (c *PersistableSessionCache) evictIfNeeded() {
	for len(c.sessions) > TLSSessionCacheMaxSize && len(c.accessOrder) > 0 {
		oldest := c.accessOrder[0]
		c.accessOrder = c.accessOrder[1:]
		delete(c.sessions, oldest)
	}
}

// moveToEnd moves a key to the end of accessOrder (must be called with lock held)
func (c *PersistableSessionCache) moveToEnd(key string) {
	for i, k := range c.accessOrder {
		if k == key {
			c.accessOrder = append(c.accessOrder[:i], c.accessOrder[i+1:]...)
			c.accessOrder = append(c.accessOrder, key)
			return
		}
	}
}

// Put implements tls.ClientSessionCache.
// If a backend is configured, it will also store the session in the backend.
func (c *PersistableSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Check if key already exists
	if _, exists := c.sessions[sessionKey]; exists {
		// Update existing entry and move to end
		c.sessions[sessionKey] = &cachedSession{
			state:     cs,
			createdAt: now,
		}
		c.moveToEnd(sessionKey)
	} else {
		// Evict oldest if at capacity
		c.evictIfNeeded()

		// Add new entry
		c.sessions[sessionKey] = &cachedSession{
			state:     cs,
			createdAt: now,
		}
		c.accessOrder = append(c.accessOrder, sessionKey)
	}

	// Store in backend if configured (async, don't block on errors)
	if c.backend != nil {
		go c.putToBackend(sessionKey, cs)
	}
}

// putToBackend stores a session in the distributed backend.
// This runs asynchronously to avoid blocking the TLS handshake.
func (c *PersistableSessionCache) putToBackend(sessionKey string, cs *tls.ClientSessionState) {
	// Parse host:port from sessionKey
	host, port := parseSessionKey(sessionKey)
	if host == "" {
		return
	}

	// Create TLSSessionState
	sessionState, err := NewTLSSessionState(cs)
	if err != nil {
		c.reportError("put_serialize", sessionKey, err)
		return
	}

	// Create backend cache key (includes session ID if set for isolation)
	backendKey := FormatSessionCacheKeyWithID(c.sessionId, c.preset, c.protocol, host, port)

	// Use background context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Store in backend
	if err := c.backend.Put(ctx, backendKey, sessionState, TLSSessionMaxAge); err != nil {
		c.reportError("put", backendKey, err)
	}
}

// Export serializes all TLS sessions for persistence
// Returns a map of session keys to serialized TLS session state
func (c *PersistableSessionCache) Export() (map[string]TLSSessionState, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]TLSSessionState)

	for key, cached := range c.sessions {
		if cached.state == nil {
			continue
		}

		// Get resumption state from ClientSessionState
		ticket, state, err := cached.state.ResumptionState()
		if err != nil {
			continue // Skip invalid sessions
		}

		if state == nil || ticket == nil {
			continue
		}

		// Serialize the SessionState to bytes
		stateBytes, err := state.Bytes()
		if err != nil {
			continue // Skip sessions that can't be serialized
		}

		result[key] = TLSSessionState{
			Ticket:    base64.StdEncoding.EncodeToString(ticket),
			State:     base64.StdEncoding.EncodeToString(stateBytes),
			CreatedAt: cached.createdAt,
		}
	}

	return result, nil
}

// Import loads TLS sessions from serialized state
// Sessions older than TLSSessionMaxAge are skipped
func (c *PersistableSessionCache) Import(sessions map[string]TLSSessionState) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, serialized := range sessions {
		// Skip expired sessions
		if time.Since(serialized.CreatedAt) > TLSSessionMaxAge {
			continue
		}

		// Decode ticket
		ticket, err := base64.StdEncoding.DecodeString(serialized.Ticket)
		if err != nil {
			continue
		}

		// Decode state
		stateBytes, err := base64.StdEncoding.DecodeString(serialized.State)
		if err != nil {
			continue
		}

		// Parse session state
		state, err := tls.ParseSessionState(stateBytes)
		if err != nil {
			continue
		}

		// Create resumption state
		clientState, err := tls.NewResumptionState(ticket, state)
		if err != nil {
			continue
		}

		c.sessions[key] = &cachedSession{
			state:     clientState,
			createdAt: serialized.CreatedAt,
		}
		c.accessOrder = append(c.accessOrder, key)
	}

	// Enforce max size limit after import (evict oldest if over limit)
	for len(c.sessions) > TLSSessionCacheMaxSize && len(c.accessOrder) > 0 {
		oldest := c.accessOrder[0]
		c.accessOrder = c.accessOrder[1:]
		delete(c.sessions, oldest)
	}

	return nil
}

// Clear removes all cached sessions
func (c *PersistableSessionCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions = make(map[string]*cachedSession)
	c.accessOrder = nil
}

// Count returns the number of cached sessions
func (c *PersistableSessionCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}
