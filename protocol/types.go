// Package protocol defines the IPC message types for communication between
// the httpcloak daemon and language SDKs (Python, Node.js, etc.)
//
// The daemon reads JSON messages from stdin and writes responses to stdout.
// Each message is a single JSON object followed by a newline.
package protocol

// MessageType represents the type of IPC message
type MessageType string

const (
	// Request/Response types
	TypeRequest  MessageType = "request"
	TypeResponse MessageType = "response"

	// Session management
	TypeSessionCreate MessageType = "session.create"
	TypeSessionClose  MessageType = "session.close"
	TypeSessionList   MessageType = "session.list"

	// Cookie management
	TypeCookieGet   MessageType = "cookie.get"
	TypeCookieSet   MessageType = "cookie.set"
	TypeCookieClear MessageType = "cookie.clear"
	TypeCookieAll   MessageType = "cookie.all"

	// Control messages
	TypePing     MessageType = "ping"
	TypePong     MessageType = "pong"
	TypeError    MessageType = "error"
	TypeShutdown MessageType = "shutdown"

	// Info
	TypePresetList MessageType = "preset.list"
)

// Request represents an incoming IPC request
type Request struct {
	ID      string            `json:"id"`                // Unique request ID for correlation
	Type    MessageType       `json:"type"`              // Message type
	Session string            `json:"session,omitempty"` // Session ID (empty for one-shot requests)
	Method  string            `json:"method,omitempty"`  // HTTP method (GET, POST, etc.)
	URL     string            `json:"url,omitempty"`     // Target URL
	Headers map[string]string `json:"headers,omitempty"` // Custom headers
	Body    string            `json:"body,omitempty"`    // Request body (base64 encoded for binary)
	Options *RequestOptions   `json:"options,omitempty"` // Request options
}

// RequestOptions contains optional request configuration
type RequestOptions struct {
	// Timeout in milliseconds (0 = use session/default timeout)
	Timeout int `json:"timeout,omitempty"`

	// Redirect behavior
	FollowRedirects *bool `json:"followRedirects,omitempty"` // nil = use session default
	MaxRedirects    int   `json:"maxRedirects,omitempty"`

	// Protocol forcing
	ForceProtocol string `json:"forceProtocol,omitempty"` // "auto", "h2", "h3"

	// Fetch mode (affects Sec-Fetch-* headers)
	FetchMode string `json:"fetchMode,omitempty"` // "navigate" (default), "cors"
	FetchSite string `json:"fetchSite,omitempty"` // "auto", "none", "same-origin", "same-site", "cross-site"
	Referer   string `json:"referer,omitempty"`   // Referer header

	// Authentication
	Auth *AuthConfig `json:"auth,omitempty"`

	// Query parameters (merged with URL params)
	Params map[string]string `json:"params,omitempty"`

	// Disable retry for this request
	DisableRetry bool `json:"disableRetry,omitempty"`

	// User-Agent override (empty = use preset)
	UserAgent string `json:"userAgent,omitempty"`

	// Body encoding: "text" (default), "base64" (for binary data)
	BodyEncoding string `json:"bodyEncoding,omitempty"`
}

// AuthConfig specifies authentication
type AuthConfig struct {
	Type     string `json:"type"`               // "basic", "bearer", "digest"
	Username string `json:"username,omitempty"` // For basic/digest
	Password string `json:"password,omitempty"` // For basic/digest
	Token    string `json:"token,omitempty"`    // For bearer
}

// Response represents an outgoing IPC response
type Response struct {
	ID       string            `json:"id"`                 // Correlates with request ID
	Type     MessageType       `json:"type"`               // Message type
	Session  string            `json:"session,omitempty"`  // Session ID if applicable
	Status   int               `json:"status,omitempty"`   // HTTP status code
	Headers  map[string]string `json:"headers,omitempty"`  // Response headers
	Body     string            `json:"body,omitempty"`     // Response body
	URL      string            `json:"url,omitempty"`      // Final URL after redirects
	Protocol string            `json:"protocol,omitempty"` // "h2" or "h3"
	Timing   *Timing           `json:"timing,omitempty"`   // Request timing breakdown
	Error    *ErrorInfo        `json:"error,omitempty"`    // Error details if failed

	// Body metadata
	BodyEncoding string `json:"bodyEncoding,omitempty"` // "text" or "base64"
	BodySize     int    `json:"bodySize,omitempty"`     // Original body size in bytes
}

// Timing contains request timing breakdown in milliseconds
type Timing struct {
	DNSLookup    float64 `json:"dnsLookup"`    // DNS lookup time (0 = cached/reused)
	TCPConnect   float64 `json:"tcpConnect"`   // TCP connection time (0 = reused)
	TLSHandshake float64 `json:"tlsHandshake"` // TLS handshake time (0 = reused)
	FirstByte    float64 `json:"firstByte"`    // Time to first response byte
	Total        float64 `json:"total"`        // Total request time
}

// ErrorInfo contains error details
type ErrorInfo struct {
	Code    string `json:"code"`              // Error code (e.g., "TIMEOUT", "CONNECTION_REFUSED")
	Message string `json:"message"`           // Human-readable error message
	Details string `json:"details,omitempty"` // Additional details
}

// SessionCreateRequest creates a new session with optional configuration
type SessionCreateRequest struct {
	ID      string         `json:"id"`
	Type    MessageType    `json:"type"`
	Options *SessionConfig `json:"options,omitempty"`
}

// SessionConfig contains session configuration
type SessionConfig struct {
	// Browser fingerprint preset (e.g., "chrome-143", "firefox-133")
	Preset string `json:"preset,omitempty"`

	// Base URL for relative paths
	BaseURL string `json:"baseUrl,omitempty"`

	// Proxy URL (http://, https://, socks5://)
	Proxy string `json:"proxy,omitempty"`

	// Default timeout in milliseconds
	Timeout int `json:"timeout,omitempty"`

	// Redirect behavior
	FollowRedirects bool `json:"followRedirects,omitempty"`
	MaxRedirects    int  `json:"maxRedirects,omitempty"`

	// Retry configuration
	RetryEnabled  bool  `json:"retryEnabled,omitempty"`
	MaxRetries    int   `json:"maxRetries,omitempty"`
	RetryWaitMin  int   `json:"retryWaitMin,omitempty"`  // Milliseconds
	RetryWaitMax  int   `json:"retryWaitMax,omitempty"`  // Milliseconds
	RetryOnStatus []int `json:"retryOnStatus,omitempty"` // Status codes to retry

	// TLS options
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// Connection options
	DisableKeepAlives bool `json:"disableKeepAlives,omitempty"`
	DisableHTTP3      bool `json:"disableHttp3,omitempty"`
	ForceHTTP3        bool `json:"forceHttp3,omitempty"`

	// Network options
	PreferIPv4 bool `json:"preferIpv4,omitempty"` // Prefer IPv4 addresses over IPv6

	// Domain fronting: request_host -> connect_host mapping
	ConnectTo map[string]string `json:"connectTo,omitempty"`

	// Domain to fetch ECH config from (e.g., "cloudflare-ech.com")
	ECHConfigDomain string `json:"echConfigDomain,omitempty"`

	// Default authentication (can be overridden per-request)
	Auth *AuthConfig `json:"auth,omitempty"`
}

// SessionCreateResponse contains the created session info
type SessionCreateResponse struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Session string      `json:"session"`
	Error   *ErrorInfo  `json:"error,omitempty"`
}

// SessionCloseRequest closes a session
type SessionCloseRequest struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Session string      `json:"session"`
}

// SessionListResponse lists all active sessions
type SessionListResponse struct {
	ID       string      `json:"id"`
	Type     MessageType `json:"type"`
	Sessions []string    `json:"sessions"`
}

// CookieGetRequest gets cookies for a URL
type CookieGetRequest struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Session string      `json:"session"`
	URL     string      `json:"url"` // URL to get cookies for
}

// CookieSetRequest sets a cookie
type CookieSetRequest struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Session string      `json:"session"`
	URL     string      `json:"url"`    // URL domain for the cookie
	Name    string      `json:"name"`   // Cookie name
	Value   string      `json:"value"`  // Cookie value
	Path    string      `json:"path"`   // Cookie path (optional)
	Domain  string      `json:"domain"` // Cookie domain (optional)
	Secure  bool        `json:"secure"` // Secure flag
	Expires int64       `json:"expires,omitempty"` // Unix timestamp (0 = session cookie)
}

// CookieClearRequest clears all cookies for a session
type CookieClearRequest struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Session string      `json:"session"`
}

// CookieAllRequest gets all cookies for a session
type CookieAllRequest struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Session string      `json:"session"`
}

// Cookie represents a single cookie
type Cookie struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Domain  string `json:"domain"`
	Path    string `json:"path"`
	Secure  bool   `json:"secure"`
	Expires int64  `json:"expires,omitempty"` // Unix timestamp
}

// CookieResponse contains cookie data
type CookieResponse struct {
	ID      string            `json:"id"`
	Type    MessageType       `json:"type"`
	Cookies map[string]string `json:"cookies,omitempty"` // For simple get (name -> value)
	All     map[string][]Cookie `json:"all,omitempty"`   // For all cookies (domain -> cookies)
	Error   *ErrorInfo        `json:"error,omitempty"`
}

// PresetListResponse lists available presets
type PresetListResponse struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Presets []string    `json:"presets"`
}

// PingResponse responds to ping
type PingResponse struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Version string      `json:"version"`
}

// Helper functions

// NewResponse creates a new response for a request
func NewResponse(reqID string) *Response {
	return &Response{
		ID:   reqID,
		Type: TypeResponse,
	}
}

// NewErrorResponse creates an error response
func NewErrorResponse(reqID string, code string, message string) *Response {
	return &Response{
		ID:   reqID,
		Type: TypeError,
		Error: &ErrorInfo{
			Code:    code,
			Message: message,
		},
	}
}

// NewSessionResponse creates a session create response
func NewSessionResponse(reqID string, sessionID string) *SessionCreateResponse {
	return &SessionCreateResponse{
		ID:      reqID,
		Type:    TypeSessionCreate,
		Session: sessionID,
	}
}

// Common error codes
const (
	ErrCodeTimeout           = "TIMEOUT"
	ErrCodeConnectionRefused = "CONNECTION_REFUSED"
	ErrCodeDNSFailure        = "DNS_FAILURE"
	ErrCodeTLSFailure        = "TLS_FAILURE"
	ErrCodeInvalidURL        = "INVALID_URL"
	ErrCodeInvalidSession    = "INVALID_SESSION"
	ErrCodeInvalidRequest    = "INVALID_REQUEST"
	ErrCodeInternal          = "INTERNAL_ERROR"
)
