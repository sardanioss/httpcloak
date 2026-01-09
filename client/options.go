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

	// PreferIPv4 makes the client prefer IPv4 addresses over IPv6.
	// Useful on networks with poor IPv6 connectivity.
	// Default: false (prefers IPv6 like modern browsers).
	PreferIPv4 bool

	// ConnectTo maps request hosts to connection hosts.
	// Key: request host (e.g., "claude.ai")
	// Value: connection host (e.g., "www.cloudflare.com")
	// The TLS SNI and Host header use the request host, but DNS resolution
	// and TCP/QUIC connection use the connection host.
	// Similar to curl's --connect-to option.
	ConnectTo map[string]string

	// ECHConfig is a custom ECH (Encrypted Client Hello) configuration.
	// When set, this overrides automatic ECH fetching from DNS.
	// Use this to force ECH with a known config (e.g., from cloudflare-ech.com).
	ECHConfig []byte

	// ECHConfigDomain specifies a domain to fetch ECH config from.
	// When set, ECH config is fetched from this domain's DNS HTTPS records
	// instead of the target domain. Useful for Cloudflare domains where
	// you can use cloudflare-ech.com's ECH config for any CF-proxied domain.
	ECHConfigDomain string

	// ForceProtocol forces a specific HTTP protocol for all requests.
	// ProtocolAuto (default): Auto-detect with fallback (H3 -> H2 -> H1)
	// ProtocolHTTP1: Force HTTP/1.1 only
	// ProtocolHTTP2: Force HTTP/2 only
	// ProtocolHTTP3: Force HTTP/3 only
	// Per-request ForceProtocol in Request struct takes precedence.
	ForceProtocol Protocol
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

// WithProxy sets the proxy URL.
// Supported proxy types:
//   - HTTP/HTTPS proxy: "http://host:port" or "https://host:port"
//   - SOCKS5 proxy: "socks5://host:port" (supports HTTP/3 via UDP relay)
//   - MASQUE proxy: "masque://host:port" or "https://brd.superproxy.io:port" (HTTP/3 via CONNECT-UDP)
//
// For HTTP/3 through a proxy, use either:
//   - SOCKS5 proxy with UDP relay support
//   - MASQUE proxy (known providers like Bright Data are auto-detected with https:// scheme)
//
// Authentication can be included in the URL: "http://user:pass@host:port"
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

// WithoutRetry explicitly disables retry
func WithoutRetry() Option {
	return func(c *ClientConfig) {
		c.RetryEnabled = false
		c.MaxRetries = 0
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

// WithDisableHTTP3 disables HTTP/3, allowing HTTP/2 with HTTP/1.1 fallback.
// Use WithForceHTTP2() if you want HTTP/2 only without fallback.
func WithDisableHTTP3() Option {
	return func(c *ClientConfig) {
		c.DisableH3 = true
	}
}

// WithForceHTTP2 forces HTTP/2 for all requests.
// The client will only use HTTP/2, no HTTP/3 or HTTP/1.1 fallback.
// Use WithDisableHTTP3() if you want H2 with H1 fallback.
func WithForceHTTP2() Option {
	return func(c *ClientConfig) {
		c.ForceProtocol = ProtocolHTTP2
		c.DisableH3 = true // Also disable H3 for consistency
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

// WithForceHTTP1 forces HTTP/1.1 for all requests.
// The client will only use HTTP/1.1, no HTTP/2 or HTTP/3.
func WithForceHTTP1() Option {
	return func(c *ClientConfig) {
		c.ForceProtocol = ProtocolHTTP1
		c.DisableH3 = true // Also disable H3 for consistency
	}
}

// WithForceHTTP3 forces HTTP/3 (QUIC) for all requests.
// The client will only use HTTP/3, no HTTP/2 or HTTP/1.1 fallback.
// Requires a SOCKS5 or MASQUE proxy if using a proxy.
func WithForceHTTP3() Option {
	return func(c *ClientConfig) {
		c.ForceProtocol = ProtocolHTTP3
	}
}

// WithPreferIPv4 makes the client prefer IPv4 addresses over IPv6.
// Use this on networks with poor IPv6 connectivity.
func WithPreferIPv4() Option {
	return func(c *ClientConfig) {
		c.PreferIPv4 = true
	}
}

// WithDisableH3 is an alias for WithDisableHTTP3.
// Disables HTTP/3, allowing HTTP/2 with HTTP/1.1 fallback.
var WithDisableH3 = WithDisableHTTP3

// WithConnectTo sets a host mapping for domain fronting.
// Requests to requestHost will connect to connectHost instead.
// The TLS SNI and Host header will still use requestHost.
// Similar to curl's --connect-to option.
//
// Example:
//
//	// Connect to cloudflare.com but request claude.ai
//	client.WithConnectTo("claude.ai", "www.cloudflare.com")
func WithConnectTo(requestHost, connectHost string) Option {
	return func(c *ClientConfig) {
		if c.ConnectTo == nil {
			c.ConnectTo = make(map[string]string)
		}
		c.ConnectTo[requestHost] = connectHost
	}
}

// WithECHConfig sets a custom ECH configuration.
// This overrides automatic ECH fetching from DNS.
// The config should be the raw ECHConfigList bytes.
//
// Example:
//
//	// Use ECH config fetched from cloudflare-ech.com
//	echConfig, _ := dns.FetchECHConfigs(ctx, "cloudflare-ech.com")
//	client.WithECHConfig(echConfig)
func WithECHConfig(echConfig []byte) Option {
	return func(c *ClientConfig) {
		c.ECHConfig = echConfig
	}
}

// WithECHFrom sets a domain to fetch ECH config from.
// Instead of fetching ECH from the target domain's DNS,
// the config will be fetched from this domain.
// Useful for Cloudflare domains - use "cloudflare-ech.com" to get
// ECH config that works for any Cloudflare-proxied domain.
//
// Example:
//
//	// Use Cloudflare's shared ECH config for any CF domain
//	client.WithECHFrom("cloudflare-ech.com")
func WithECHFrom(domain string) Option {
	return func(c *ClientConfig) {
		c.ECHConfigDomain = domain
	}
}

// EnableCookies is a marker to enable cookie jar in NewClient
// Use NewSession() instead for simpler API, or call client.EnableCookies() after creation
var EnableCookies = struct{}{}
