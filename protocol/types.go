// Package protocol defines the JSON-shaped session configuration types that
// the cgo entry points in bindings/clib consume from the language SDKs.
//
// The original design called for a separate httpcloak-daemon binary that
// would speak JSON over stdin/stdout, which is why this package still ships
// the MessageType / SessionCreateRequest / Response shapes. That daemon was
// never released. The bindings (Python, Node.js, .NET) link against the
// cgo-built shared library directly and call the C entry points; SessionConfig
// here is the shape the root package's NewSession marshals internally.
package protocol

import (
	"crypto/tls"
	"crypto/x509"
)

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

	// DisableConditionalCache skips injection of If-None-Match / If-Modified-Since
	// headers from the session's per-URL cache for this request AND skips storing
	// any ETag / Last-Modified from the response. Lets callers force a fresh fetch
	// without touching the session-wide setting.
	DisableConditionalCache bool `json:"disableConditionalCache,omitempty"`

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
	// Every field is measured. A zero means the phase did not happen on this
	// request (a reused connection) or is not separable on the path taken, and
	// never that a number was unavailable and got estimated.
	//
	// These three used to be computed as fixed fractions of FirstByte, so they
	// were a reshaped copy of one measurement presented as a breakdown. Anyone
	// diagnosing latency from them was reading invented numbers.
	DNSLookup    float64 `json:"dnsLookup"`    // DNS lookup (0 = cached, reused, or not separable)
	TCPConnect   float64 `json:"tcpConnect"`   // TCP connect (0 = reused, or QUIC, or not separable)
	TLSHandshake float64 `json:"tlsHandshake"` // TLS handshake (0 = reused or not separable)

	// Connect is the whole connection setup where the phases above cannot be
	// split: QUIC folds transport and TLS into one exchange, and a proxy dial
	// hides DNS and TCP behind the proxy. Zero on a reused connection.
	Connect float64 `json:"connect"`

	FirstByte float64 `json:"firstByte"` // Time to first response byte
	Total     float64 `json:"total"`     // Total request time
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

	// Proxy URL (http://, https://, socks5://) - used for all protocols
	Proxy string `json:"proxy,omitempty"`

	// TCPProxy is the proxy URL for TCP-based protocols (HTTP/1.1 and HTTP/2)
	// Use with UDPProxy for split proxy configuration
	TCPProxy string `json:"tcpProxy,omitempty"`

	// UDPProxy is the proxy URL for UDP-based protocols (HTTP/3 via MASQUE)
	// Use with TCPProxy for split proxy configuration
	UDPProxy string `json:"udpProxy,omitempty"`

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

	// TLSVerifyPeerCertificate and TLSVerifyConnection are caller-supplied
	// certificate verification hooks. Not serialisable, so they carry no JSON
	// tag and are ignored by any config that round-trips through JSON.
	TLSVerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error `json:"-"`
	TLSVerifyConnection      func(cs tls.ConnectionState) error                                  `json:"-"`
	TLSRootCAs               *x509.CertPool                                                      `json:"-"`

	// Connection options
	DisableKeepAlives bool `json:"disableKeepAlives,omitempty"`
	DisableHTTP3      bool `json:"disableHttp3,omitempty"`
	ForceHTTP1        bool `json:"forceHttp1,omitempty"`
	ForceHTTP2        bool `json:"forceHttp2,omitempty"`
	ForceHTTP3        bool `json:"forceHttp3,omitempty"`

	// Network options
	PreferIPv4   bool   `json:"preferIpv4,omitempty"`   // Prefer IPv4 addresses over IPv6
	LocalAddress string `json:"localAddress,omitempty"` // Local IP to bind outgoing connections (for IPv6 rotation)

	// Domain fronting: request_host -> connect_host mapping
	ConnectTo map[string]string `json:"connectTo,omitempty"`

	// Domain to fetch ECH config from (e.g., "cloudflare-ech.com")
	ECHConfigDomain string `json:"echConfigDomain,omitempty"`

	// TLS-only mode: use TLS fingerprint but skip preset HTTP headers
	// Useful when you want to set all headers manually
	TLSOnly bool `json:"tlsOnly,omitempty"`

	// QUIC idle timeout in seconds (default: 30)
	// Connections are closed after this duration of inactivity
	QuicIdleTimeout int `json:"quicIdleTimeout,omitempty"`

	// KeyLogFile is the path to write TLS key log for Wireshark decryption.
	// If set, overrides the global SSLKEYLOGFILE environment variable for this session.
	KeyLogFile string `json:"keyLogFile,omitempty"`

	// DisableECH skips ECH (Encrypted Client Hello) DNS lookup for faster first request
	// ECH adds ~15-20ms to first connection but provides extra privacy
	DisableECH bool `json:"disableEch,omitempty"`

	// EnableSpeculativeTLS enables the speculative TLS optimization for proxy connections.
	// When true, CONNECT request and TLS ClientHello are sent together, saving one
	// round-trip (~25% faster proxy connections). Disabled by default due to
	// compatibility issues with some proxies.
	EnableSpeculativeTLS bool `json:"enableSpeculativeTls,omitempty"`

	// SwitchProtocol is the protocol to switch to after Refresh().
	// Valid values: "h1", "h2", "h3", "" (no switch).
	// When set, Refresh() will close connections and switch to this protocol,
	// enabling warm-up on one protocol (e.g. H3) then serving on another (e.g. H2)
	// with TLS session resumption.
	SwitchProtocol string `json:"switchProtocol,omitempty"`

	// WithoutCookieJar disables the session's internal cookie jar entirely.
	// When true, Set-Cookie headers from responses are NOT stored in the jar
	// and the jar's contents are NOT injected as Cookie headers on subsequent
	// requests. Cookie management is left fully to the caller via per-request
	// headers — useful when an application maintains its own jar (database,
	// shared cache) and wants the lib to be byte-transparent.
	WithoutCookieJar bool `json:"withoutCookieJar,omitempty"`

	// WithoutConditionalCache disables the session's per-URL ETag /
	// Last-Modified handling entirely. When true, the session never injects
	// If-None-Match or If-Modified-Since headers and never stores those
	// validators from responses. Toggle at runtime with
	// Session.SetConditionalCacheEnabled(bool).
	WithoutConditionalCache bool `json:"withoutConditionalCache,omitempty"`

	// WithoutClientHints disables ALL UA client hints for the session: the
	// always-on sec-ch-ua / sec-ch-ua-mobile / sec-ch-ua-platform trio AND the
	// high-entropy hints. Only headers the caller sets explicitly are sent.
	// Toggle at runtime with Session.SetClientHintsEnabled(bool).
	WithoutClientHints bool `json:"withoutClientHints,omitempty"`

	// WithoutHighEntropyClientHints keeps the always-on sec-ch-ua trio but
	// suppresses the high-entropy hints (sec-ch-ua-full-version-list, -arch,
	// -platform-version, -bitness, -model, -wow64) that Chrome only sends after
	// a host advertises Accept-CH. Toggle at runtime with
	// Session.SetHighEntropyClientHintsEnabled(bool).
	WithoutHighEntropyClientHints bool `json:"withoutHighEntropyClientHints,omitempty"`

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
	URL     string      `json:"url"`               // URL domain for the cookie
	Name    string      `json:"name"`              // Cookie name
	Value   string      `json:"value"`             // Cookie value
	Path    string      `json:"path"`              // Cookie path (optional)
	Domain  string      `json:"domain"`            // Cookie domain (optional)
	Secure  bool        `json:"secure"`            // Secure flag
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
	ID      string              `json:"id"`
	Type    MessageType         `json:"type"`
	Cookies map[string]string   `json:"cookies,omitempty"` // For simple get (name -> value)
	All     map[string][]Cookie `json:"all,omitempty"`     // For all cookies (domain -> cookies)
	Error   *ErrorInfo          `json:"error,omitempty"`
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
