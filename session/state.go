package session

import (
	"time"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

const SessionStateVersion = 5

// SessionState represents the complete saveable session state
type SessionState struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Full session configuration - saves everything
	Config *protocol.SessionConfig `json:"config"`

	// Session data - v5 format: cookies keyed by domain
	// Key is the domain (e.g., ".example.com" for domain cookies, "example.com" for host-only)
	Cookies map[string][]CookieState `json:"cookies"`

	// TLS Sessions keyed by origin "protocol:host:port"
	// e.g., "h2:example.com:443", "h3:api.example.com:443"
	TLSSessions map[string]transport.TLSSessionState `json:"tls_sessions"`

	// ECHConfigs stores ECH configurations per domain (base64 encoded)
	// This is essential for session resumption - the same ECH config must be used
	// when resuming as was used when creating the session ticket
	ECHConfigs map[string]string `json:"ech_configs,omitempty"`

	// TLSVerify records which certificate verification hooks the session had
	// configured when it was saved. The hooks themselves are Go functions and a
	// *x509.CertPool, so JSON cannot carry them; this records that they existed
	// so a later load can refuse rather than silently give back a session that
	// verifies less than the one that was saved.
	//
	// Absent on files written before this existed, which is the honest answer
	// for them: nothing was recorded either way.
	TLSVerify *TLSVerifyState `json:"tls_verify,omitempty"`
}

// TLSVerifyState records which non-serialisable verification hooks a saved
// session carried. Each field means "this one was configured", never what it
// did.
type TLSVerifyState struct {
	PeerCertificate bool `json:"peer_certificate,omitempty"`
	Connection      bool `json:"connection,omitempty"`
	RootCAs         bool `json:"root_cas,omitempty"`
}

// SessionStateV4 represents the v4 format for migration
type SessionStateV4 struct {
	Version     int                                  `json:"version"`
	CreatedAt   time.Time                            `json:"created_at"`
	UpdatedAt   time.Time                            `json:"updated_at"`
	Config      *protocol.SessionConfig              `json:"config"`
	Cookies     []CookieState                        `json:"cookies"` // v4: flat list
	TLSSessions map[string]transport.TLSSessionState `json:"tls_sessions"`
	ECHConfigs  map[string]string                    `json:"ech_configs,omitempty"`
}

// CookieState represents a serializable cookie with full metadata
type CookieState struct {
	Name      string     `json:"name"`
	Value     string     `json:"value"`
	Domain    string     `json:"domain,omitempty"`
	Path      string     `json:"path,omitempty"`
	Expires   *time.Time `json:"expires,omitempty"`
	MaxAge    int        `json:"max_age,omitempty"`
	Secure    bool       `json:"secure,omitempty"`
	HttpOnly  bool       `json:"http_only,omitempty"`
	SameSite  string     `json:"same_site,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"` // v5: for sorting
}
