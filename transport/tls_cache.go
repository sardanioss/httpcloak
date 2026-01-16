package transport

import (
	"encoding/base64"
	"sync"
	"time"

	tls "github.com/sardanioss/utls"
)

// TLSSessionMaxAge is the maximum age for TLS sessions (24 hours)
// TLS session tickets typically expire after 24-48 hours
const TLSSessionMaxAge = 24 * time.Hour

// TLSSessionState represents a serializable TLS session
type TLSSessionState struct {
	Ticket    string    `json:"ticket"`     // base64 encoded
	State     string    `json:"state"`      // base64 encoded
	CreatedAt time.Time `json:"created_at"`
}

// PersistableSessionCache implements tls.ClientSessionCache
// with export/import capabilities for session persistence
type PersistableSessionCache struct {
	mu       sync.RWMutex
	sessions map[string]*cachedSession
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

// Get implements tls.ClientSessionCache
func (c *PersistableSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if cached, ok := c.sessions[sessionKey]; ok {
		return cached.state, true
	}
	return nil, false
}

// Put implements tls.ClientSessionCache
func (c *PersistableSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sessions[sessionKey] = &cachedSession{
		state:     cs,
		createdAt: time.Now(),
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
	}

	return nil
}

// Clear removes all cached sessions
func (c *PersistableSessionCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions = make(map[string]*cachedSession)
}

// Count returns the number of cached sessions
func (c *PersistableSessionCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}
