package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sardanioss/httpcloak/protocol"
)

// Manager manages all active sessions
type Manager struct {
	sessions map[string]*Session
	mu       sync.RWMutex

	// Configuration
	maxSessions     int
	sessionTimeout  time.Duration
	cleanupInterval time.Duration

	// Shutdown signal
	shutdown chan struct{}
}

// NewManager creates a new session manager
func NewManager() *Manager {
	m := &Manager{
		sessions:        make(map[string]*Session),
		maxSessions:     100,              // Max concurrent sessions
		sessionTimeout:  30 * time.Minute, // Session idle timeout
		cleanupInterval: 1 * time.Minute,  // Cleanup check interval
		shutdown:        make(chan struct{}),
	}

	// Start background cleanup
	go m.cleanupLoop()

	return m
}

// CreateSession creates a new session and returns its ID
func (m *Manager) CreateSession(config *protocol.SessionConfig) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check session limit
	if len(m.sessions) >= m.maxSessions {
		return "", fmt.Errorf("maximum sessions limit reached (%d)", m.maxSessions)
	}

	// Generate unique session ID
	sessionID := uuid.New().String()

	// Create session
	session := NewSession(sessionID, config)
	m.sessions[sessionID] = session

	return sessionID, nil
}

// GetSession retrieves a session by ID
func (m *Manager) GetSession(sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	if !session.IsActive() {
		return nil, fmt.Errorf("session is closed: %s", sessionID)
	}

	return session, nil
}

// CloseSession closes and removes a session
func (m *Manager) CloseSession(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	session.Close()
	delete(m.sessions, sessionID)

	return nil
}

// ListSessions returns stats for all active sessions
func (m *Manager) ListSessions() []SessionStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make([]SessionStats, 0, len(m.sessions))
	for _, session := range m.sessions {
		stats = append(stats, session.Stats())
	}

	return stats
}

// SessionCount returns the number of active sessions
func (m *Manager) SessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// cleanupLoop periodically removes expired sessions
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanupExpiredSessions()
		case <-m.shutdown:
			return
		}
	}
}

// cleanupExpiredSessions removes sessions that have been idle too long
func (m *Manager) cleanupExpiredSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for id, session := range m.sessions {
		if now.Sub(session.LastUsed) > m.sessionTimeout {
			session.Close()
			delete(m.sessions, id)
		}
	}
}

// Shutdown closes all sessions and stops the manager
func (m *Manager) Shutdown() {
	close(m.shutdown)

	m.mu.Lock()
	defer m.mu.Unlock()

	for id, session := range m.sessions {
		session.Close()
		delete(m.sessions, id)
	}
}

// SetMaxSessions sets the maximum number of concurrent sessions
func (m *Manager) SetMaxSessions(max int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxSessions = max
}

// SetSessionTimeout sets the session idle timeout
func (m *Manager) SetSessionTimeout(timeout time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessionTimeout = timeout
}
