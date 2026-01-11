package session

import (
	"time"

	"github.com/sardanioss/httpcloak/transport"
)

const SessionStateVersion = 1

// SessionState represents the complete saveable session state
type SessionState struct {
	Version         int                                  `json:"version"`
	Preset          string                               `json:"preset"`
	ForceHTTP3      bool                                 `json:"force_http3"`
	ECHConfigDomain string                               `json:"ech_config_domain,omitempty"`
	CreatedAt       time.Time                            `json:"created_at"`
	UpdatedAt       time.Time                            `json:"updated_at"`
	Cookies         []CookieState                        `json:"cookies"`
	TLSSessions     map[string]transport.TLSSessionState `json:"tls_sessions"`
}

// CookieState represents a serializable cookie
type CookieState struct {
	Domain   string     `json:"domain"`
	Path     string     `json:"path"`
	Name     string     `json:"name"`
	Value    string     `json:"value"`
	Expires  *time.Time `json:"expires,omitempty"`
	Secure   bool       `json:"secure,omitempty"`
	HttpOnly bool       `json:"http_only,omitempty"`
}
