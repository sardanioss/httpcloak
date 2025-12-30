// Package client options - configuration for the HTTP client.
//
// The client uses functional options pattern for configuration.
// All options have sensible defaults, so you can create a client with just:
//
//	c := client.NewClient("chrome-143")
//
// Or customize with options:
//
//	c := client.NewClient("chrome-143",
//	    client.WithTimeout(60*time.Second),
//	    client.WithProxy("http://proxy:8080"),
//	    client.WithRetry(3),
//	)
package client

import (
	"crypto/tls"
	"time"
)

// ClientConfig holds all configuration options for the HTTP client.
// Use functional options (WithTimeout, WithProxy, etc.) to set these values.
type ClientConfig struct {
	// Preset is the browser fingerprint preset name (e.g., "chrome-143", "firefox-133").
	// This determines the TLS fingerprint (JA3/JA4), HTTP/2 settings, and default headers.
	Preset string

	// Timeout is the maximum duration for a request including redirects.
	// Default: 30 seconds.
	Timeout time.Duration

	// Proxy is the URL of the proxy server.
	// Supports http://, https://, and socks5:// schemes.
	// Example: "http://user:pass@proxy.example.com:8080"
	Proxy string

	// FollowRedirects controls whether the client follows HTTP redirects (3xx responses).
	// Default: true.
	FollowRedirects bool

	// MaxRedirects is the maximum number of redirects to follow.
	// Prevents infinite redirect loops.
	// Default: 10.
	MaxRedirects int

	// RetryEnabled enables automatic retry on transient failures.
	// When enabled, uses exponential backoff with jitter.
	// Default: false.
	RetryEnabled bool

	// MaxRetries is the maximum number of retry attempts.
	// Default: 3.
	MaxRetries int

	// RetryWaitMin is the minimum wait time between retries.
	// The actual wait is calculated using exponential backoff.
	// Default: 1 second.
	RetryWaitMin time.Duration

	// RetryWaitMax is the maximum wait time between retries.
	// Caps the exponential backoff.
	// Default: 30 seconds.
	RetryWaitMax time.Duration

	// RetryOnStatus is the list of HTTP status codes that trigger a retry.
	// Default: [429, 500, 502, 503, 504].
	RetryOnStatus []int

	// InsecureSkipVerify disables TLS certificate verification.
	// WARNING: This makes the connection insecure. Only use for testing.
	// Default: false.
	InsecureSkipVerify bool

	// TLSConfig is a custom TLS configuration for advanced use cases.
	// Most users should not need to set this.
	TLSConfig *tls.Config

	// DisableKeepAlives disables HTTP keep-alives.
	// When true, each request opens a new connection.
	// Default: false.
	DisableKeepAlives bool

	// DisableH3 disables HTTP/3 (QUIC) and forces HTTP/2.
	// Useful if HTTP/3 causes issues with certain servers.
	// Default: false.
	DisableH3 bool
}

// DefaultConfig returns default client configuration
func DefaultConfig() *ClientConfig {
	return &ClientConfig{
		Preset:          "chrome-143",
		Timeout:         30 * time.Second,
		FollowRedirects: true,
		MaxRedirects:    10,
		RetryEnabled:    false,
		MaxRetries:      3,
		RetryWaitMin:    1 * time.Second,
		RetryWaitMax:    30 * time.Second,
		RetryOnStatus:   []int{429, 500, 502, 503, 504},
		InsecureSkipVerify: false,
		DisableKeepAlives:  false,
		DisableH3:          false,
	}
}

// Option is a function that modifies ClientConfig
type Option func(*ClientConfig)

// WithPreset sets the fingerprint preset
func WithPreset(preset string) Option {
	return func(c *ClientConfig) {
		c.Preset = preset
	}
}

// WithTimeout sets the request timeout
func WithTimeout(timeout time.Duration) Option {
	return func(c *ClientConfig) {
		c.Timeout = timeout
	}
}

// WithProxy sets the proxy URL
func WithProxy(proxyURL string) Option {
	return func(c *ClientConfig) {
		c.Proxy = proxyURL
	}
}

// WithRedirects configures redirect behavior
func WithRedirects(follow bool, maxRedirects int) Option {
	return func(c *ClientConfig) {
		c.FollowRedirects = follow
		c.MaxRedirects = maxRedirects
	}
}

// WithoutRedirects disables automatic redirect following
func WithoutRedirects() Option {
	return func(c *ClientConfig) {
		c.FollowRedirects = false
	}
}

// WithRetry enables retry with default settings
func WithRetry(maxRetries int) Option {
	return func(c *ClientConfig) {
		c.RetryEnabled = true
		c.MaxRetries = maxRetries
	}
}

// WithRetryConfig configures retry behavior
func WithRetryConfig(maxRetries int, waitMin, waitMax time.Duration, retryOnStatus []int) Option {
	return func(c *ClientConfig) {
		c.RetryEnabled = true
		c.MaxRetries = maxRetries
		c.RetryWaitMin = waitMin
		c.RetryWaitMax = waitMax
		if len(retryOnStatus) > 0 {
			c.RetryOnStatus = retryOnStatus
		}
	}
}

// WithInsecureSkipVerify disables TLS certificate verification
// WARNING: This makes the connection insecure and should only be used for testing
func WithInsecureSkipVerify() Option {
	return func(c *ClientConfig) {
		c.InsecureSkipVerify = true
	}
}

// WithTLSConfig sets a custom TLS configuration
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(c *ClientConfig) {
		c.TLSConfig = tlsConfig
	}
}

// WithDisableKeepAlives disables HTTP keep-alives
func WithDisableKeepAlives() Option {
	return func(c *ClientConfig) {
		c.DisableKeepAlives = true
	}
}

// WithDisableHTTP3 disables HTTP/3 and forces HTTP/2
func WithDisableHTTP3() Option {
	return func(c *ClientConfig) {
		c.DisableH3 = true
	}
}

// WithForceHTTP2 forces HTTP/2 for all requests (disables HTTP/3, still allows HTTP/1.1 fallback)
// This is useful when you want to ensure HTTP/2 is used without attempting HTTP/3
func WithForceHTTP2() Option {
	return func(c *ClientConfig) {
		c.DisableH3 = true
	}
}

// Protocol enum for forcing specific HTTP protocol versions
type Protocol int

const (
	ProtocolAuto  Protocol = iota // Auto-detect (H3 -> H2 -> H1 fallback)
	ProtocolHTTP1                 // Force HTTP/1.1
	ProtocolHTTP2                 // Force HTTP/2
	ProtocolHTTP3                 // Force HTTP/3
)

// String returns the string representation of the protocol
func (p Protocol) String() string {
	switch p {
	case ProtocolAuto:
		return "auto"
	case ProtocolHTTP1:
		return "h1"
	case ProtocolHTTP2:
		return "h2"
	case ProtocolHTTP3:
		return "h3"
	default:
		return "unknown"
	}
}

// WithForceHTTP1 forces HTTP/1.1 for all requests
func WithForceHTTP1() Option {
	return func(c *ClientConfig) {
		c.DisableH3 = true
		// Note: Client will check for ForceHTTP1 flag
	}
}

// EnableCookies is a marker to enable cookie jar in NewClient
// Use NewSession() instead for simpler API, or call client.EnableCookies() after creation
var EnableCookies = struct{}{}
