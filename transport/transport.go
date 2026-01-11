package transport

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	http "github.com/sardanioss/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
)

// Protocol represents the HTTP protocol version
type Protocol int

const (
	// ProtocolAuto automatically selects the best protocol (H3 -> H2 -> H1)
	ProtocolAuto Protocol = iota
	// ProtocolHTTP1 forces HTTP/1.1 over TCP
	ProtocolHTTP1
	// ProtocolHTTP2 forces HTTP/2 over TCP
	ProtocolHTTP2
	// ProtocolHTTP3 forces HTTP/3 over QUIC
	ProtocolHTTP3
)

// Buffer pools for high-performance body reading
// Tiered pools minimize memory waste for different response sizes
var (
	// Pool for bodies up to 1MB
	bodyPool1MB = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 1*1024*1024)
			return &buf
		},
	}
	// Pool for bodies up to 10MB
	bodyPool10MB = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 10*1024*1024)
			return &buf
		},
	}
	// Pool for bodies up to 100MB
	bodyPool100MB = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 100*1024*1024)
			return &buf
		},
	}
)

// getPooledBuffer gets a buffer from the appropriate pool based on size
func getPooledBuffer(size int64) (*[]byte, func()) {
	if size <= 1*1024*1024 {
		buf := bodyPool1MB.Get().(*[]byte)
		return buf, func() { bodyPool1MB.Put(buf) }
	}
	if size <= 10*1024*1024 {
		buf := bodyPool10MB.Get().(*[]byte)
		return buf, func() { bodyPool10MB.Put(buf) }
	}
	if size <= 100*1024*1024 {
		buf := bodyPool100MB.Get().(*[]byte)
		return buf, func() { bodyPool100MB.Put(buf) }
	}
	// For very large bodies, allocate directly (rare case)
	buf := make([]byte, size)
	return &buf, func() {} // No-op release for non-pooled buffers
}

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

// ProxyConfig contains proxy server configuration
type ProxyConfig struct {
	URL      string // Proxy URL (e.g., "http://proxy:8080" or "http://user:pass@proxy:8080")
	Username string // Proxy username (optional, can also be in URL)
	Password string // Proxy password (optional, can also be in URL)

	// TCPProxy is the proxy URL for TCP-based protocols (HTTP/1.1 and HTTP/2)
	// When set, overrides URL for TCP transports
	TCPProxy string

	// UDPProxy is the proxy URL for UDP-based protocols (HTTP/3 via MASQUE)
	// When set, overrides URL for UDP transports
	UDPProxy string
}

// TransportConfig contains advanced transport configuration
type TransportConfig struct {
	// ConnectTo maps request hosts to connection hosts (domain fronting).
	// Key: request host, Value: connection host for DNS resolution
	ConnectTo map[string]string

	// ECHConfig is a custom ECH configuration (overrides DNS fetch)
	ECHConfig []byte

	// ECHConfigDomain is a domain to fetch ECH config from instead of target
	ECHConfigDomain string
}

// Request represents an HTTP request
type Request struct {
	Method     string
	URL        string
	Headers    map[string][]string // Multi-value headers (matches http.Header)
	Body       []byte
	BodyReader io.Reader // For streaming uploads - used instead of Body if set
	Timeout    time.Duration
}

// RedirectInfo contains information about a redirect response
type RedirectInfo struct {
	StatusCode int
	URL        string
	Headers    map[string][]string // Multi-value headers
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Headers    map[string][]string // Multi-value headers (matches http.Header)
	Body       io.ReadCloser       // Streaming body - call Close() when done
	FinalURL   string
	Timing     *protocol.Timing
	Protocol   string // "h1", "h2", or "h3"
	History    []*RedirectInfo

	// bodyBytes caches the body after reading for multiple access
	bodyBytes []byte
	bodyRead  bool
}

// Close closes the response body.
// Should be called when done reading the body.
func (r *Response) Close() error {
	if r.Body != nil {
		return r.Body.Close()
	}
	return nil
}

// GetHeader returns the first value for the given header key (case-insensitive).
// Use GetHeaders() for multi-value headers like Set-Cookie.
func (r *Response) GetHeader(key string) string {
	if values := r.Headers[strings.ToLower(key)]; len(values) > 0 {
		return values[0]
	}
	return ""
}

// GetHeaders returns all values for the given header key (case-insensitive).
func (r *Response) GetHeaders(key string) []string {
	return r.Headers[strings.ToLower(key)]
}

// Bytes returns the response body as a byte slice.
// If the body has already been read, returns the cached bytes.
// Otherwise reads the body and caches it.
func (r *Response) Bytes() ([]byte, error) {
	if r.bodyRead {
		return r.bodyBytes, nil
	}
	if r.Body == nil {
		return nil, nil
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body.Close()
	r.bodyBytes = data
	r.bodyRead = true
	return data, nil
}

// Text returns the response body as a string.
func (r *Response) Text() (string, error) {
	data, err := r.Bytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Transport is a unified HTTP transport supporting HTTP/1.1, HTTP/2, and HTTP/3
type Transport struct {
	h1Transport *HTTP1Transport
	h2Transport *HTTP2Transport
	h3Transport *HTTP3Transport
	dnsCache    *dns.Cache
	preset      *fingerprint.Preset
	timeout     time.Duration
	protocol    Protocol
	proxy       *ProxyConfig
	config      *TransportConfig

	// Track protocol support per host
	protocolSupport   map[string]Protocol // Best known protocol per host
	protocolSupportMu sync.RWMutex

	// Configuration
	insecureSkipVerify bool

	// H3 proxy initialization error - if set, H3 requests will fail with this error
	// instead of silently bypassing the proxy
	h3ProxyError error
}

// NewTransport creates a new unified transport
func NewTransport(presetName string) *Transport {
	return NewTransportWithConfig(presetName, nil, nil)
}

// NewTransportWithProxy creates a new unified transport with optional proxy
func NewTransportWithProxy(presetName string, proxy *ProxyConfig) *Transport {
	return NewTransportWithConfig(presetName, proxy, nil)
}

// NewTransportWithConfig creates a new unified transport with proxy and config
func NewTransportWithConfig(presetName string, proxy *ProxyConfig, config *TransportConfig) *Transport {
	preset := fingerprint.Get(presetName)
	dnsCache := dns.NewCache()

	t := &Transport{
		dnsCache:        dnsCache,
		preset:          preset,
		timeout:         30 * time.Second,
		protocol:        ProtocolAuto,
		protocolSupport: make(map[string]Protocol),
		proxy:           proxy,
		config:          config,
	}

	// Determine effective TCP and UDP proxy URLs
	// TCPProxy/UDPProxy take precedence over URL for split proxy configuration
	var tcpProxyURL, udpProxyURL string
	if proxy != nil {
		tcpProxyURL = proxy.TCPProxy
		if tcpProxyURL == "" {
			tcpProxyURL = proxy.URL
		}
		udpProxyURL = proxy.UDPProxy
		if udpProxyURL == "" {
			udpProxyURL = proxy.URL
		}
	}

	// Create TCP proxy config for H1/H2 transports
	var tcpProxy *ProxyConfig
	if tcpProxyURL != "" {
		tcpProxy = &ProxyConfig{URL: tcpProxyURL}
	}

	// Create HTTP/1.1 and HTTP/2 transports with TCP proxy
	t.h1Transport = NewHTTP1TransportWithConfig(preset, dnsCache, tcpProxy, config)
	t.h2Transport = NewHTTP2TransportWithConfig(preset, dnsCache, tcpProxy, config)

	// Create HTTP/3 transport - with UDP proxy support if applicable
	if udpProxyURL != "" {
		udpProxy := &ProxyConfig{URL: udpProxyURL}
		if isSOCKS5Proxy(udpProxyURL) {
			// SOCKS5 supports UDP relay for HTTP/3
			h3Transport, err := NewHTTP3TransportWithConfig(preset, dnsCache, udpProxy, config)
			if err != nil {
				// Store the error - don't silently fallback to direct connection!
				// H3 requests will fail with explicit error instead of bypassing proxy
				t.h3ProxyError = fmt.Errorf("SOCKS5 UDP proxy initialization failed: %w", err)
				// Still create a basic H3 transport for non-proxied use cases
				// but h3ProxyError will prevent it from being used when proxy is expected
				t.h3Transport = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
			} else {
				t.h3Transport = h3Transport
			}
		} else if isMASQUEProxy(udpProxyURL) {
			// MASQUE supports HTTP/3 through HTTP/3 proxy
			h3Transport, err := NewHTTP3TransportWithMASQUE(preset, dnsCache, udpProxy, config)
			if err != nil {
				// Store the error - don't silently fallback to direct connection!
				t.h3ProxyError = fmt.Errorf("MASQUE proxy initialization failed: %w", err)
				t.h3Transport = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
			} else {
				t.h3Transport = h3Transport
			}
		} else {
			// HTTP proxy - HTTP/3 doesn't work through HTTP proxies
			// Store error so H3 requests fail explicitly
			t.h3ProxyError = fmt.Errorf("HTTP proxy does not support HTTP/3 (QUIC requires UDP)")
			t.h3Transport = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
		}
	} else {
		// No proxy - HTTP/3 works directly
		t.h3Transport = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
	}

	return t
}

// SetProtocol sets the preferred protocol
func (t *Transport) SetProtocol(p Protocol) {
	t.protocol = p
}

// SetInsecureSkipVerify sets whether to skip TLS certificate verification
func (t *Transport) SetInsecureSkipVerify(skip bool) {
	t.insecureSkipVerify = skip
	t.h1Transport.SetInsecureSkipVerify(skip)
}

// SetProxy sets or updates the proxy configuration
// Note: This recreates the underlying transports
func (t *Transport) SetProxy(proxy *ProxyConfig) {
	t.proxy = proxy

	// Close existing transports
	t.h1Transport.Close()
	t.h2Transport.Close()
	t.h3Transport.Close()

	// Recreate HTTP/1.1 and HTTP/2 with new proxy config
	t.h1Transport = NewHTTP1TransportWithProxy(t.preset, t.dnsCache, proxy)
	t.h2Transport = NewHTTP2TransportWithProxy(t.preset, t.dnsCache, proxy)

	// Recreate HTTP/3 - with proxy support if applicable
	if proxy != nil && proxy.URL != "" {
		if isSOCKS5Proxy(proxy.URL) {
			h3Transport, err := NewHTTP3TransportWithProxy(t.preset, t.dnsCache, proxy)
			if err != nil {
				// Fall back to non-proxied HTTP/3
				t.h3Transport = NewHTTP3Transport(t.preset, t.dnsCache)
			} else {
				t.h3Transport = h3Transport
			}
		} else if isMASQUEProxy(proxy.URL) {
			h3Transport, err := NewHTTP3TransportWithMASQUE(t.preset, t.dnsCache, proxy, nil)
			if err != nil {
				t.h3Transport = NewHTTP3Transport(t.preset, t.dnsCache)
			} else {
				t.h3Transport = h3Transport
			}
		} else {
			t.h3Transport = NewHTTP3Transport(t.preset, t.dnsCache)
		}
	} else {
		t.h3Transport = NewHTTP3Transport(t.preset, t.dnsCache)
	}
}

// SetPreset changes the fingerprint preset
func (t *Transport) SetPreset(presetName string) {
	t.preset = fingerprint.Get(presetName)

	// Close all transports
	t.h1Transport.Close()
	t.h2Transport.Close()
	t.h3Transport.Close()

	// Recreate HTTP/1.1 and HTTP/2 with new preset
	t.h1Transport = NewHTTP1TransportWithProxy(t.preset, t.dnsCache, t.proxy)
	t.h2Transport = NewHTTP2TransportWithProxy(t.preset, t.dnsCache, t.proxy)

	// Recreate HTTP/3 - with proxy support if applicable
	if t.proxy != nil && t.proxy.URL != "" {
		if isSOCKS5Proxy(t.proxy.URL) {
			h3Transport, err := NewHTTP3TransportWithProxy(t.preset, t.dnsCache, t.proxy)
			if err != nil {
				t.h3Transport = NewHTTP3Transport(t.preset, t.dnsCache)
			} else {
				t.h3Transport = h3Transport
			}
		} else if isMASQUEProxy(t.proxy.URL) {
			h3Transport, err := NewHTTP3TransportWithMASQUE(t.preset, t.dnsCache, t.proxy, nil)
			if err != nil {
				t.h3Transport = NewHTTP3Transport(t.preset, t.dnsCache)
			} else {
				t.h3Transport = h3Transport
			}
		} else {
			t.h3Transport = NewHTTP3Transport(t.preset, t.dnsCache)
		}
	} else {
		t.h3Transport = NewHTTP3Transport(t.preset, t.dnsCache)
	}
}

// isSOCKS5Proxy checks if the proxy URL is a SOCKS5 proxy
func isSOCKS5Proxy(proxyURL string) bool {
	return IsSOCKS5Proxy(proxyURL)
}

// IsSOCKS5Proxy checks if the proxy URL is a SOCKS5 proxy (exported version)
func IsSOCKS5Proxy(proxyURL string) bool {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}
	return parsed.Scheme == "socks5" || parsed.Scheme == "socks5h"
}

// isMASQUEProxy checks if the proxy URL should use MASQUE protocol.
// Returns true for masque:// scheme or known MASQUE providers with https://
func isMASQUEProxy(proxyURL string) bool {
	return IsMASQUEProxy(proxyURL)
}

// IsMASQUEProxy checks if the proxy URL should use MASQUE protocol (exported version).
// Returns true for masque:// scheme or known MASQUE providers with https://
func IsMASQUEProxy(proxyURL string) bool {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}

	// Explicit masque:// scheme
	if parsed.Scheme == "masque" {
		return true
	}

	// Auto-detect known MASQUE providers with https:// scheme
	if parsed.Scheme == "https" {
		// Check against known MASQUE proxy providers
		host := parsed.Hostname()
		knownProviders := []string{
			"brd.superproxy.io",
			"zproxy.lum-superproxy.io",
			"lum-superproxy.io",
			"pr.oxylabs.io",
		}
		for _, provider := range knownProviders {
			if strings.Contains(host, provider) || strings.HasSuffix(host, provider) {
				return true
			}
		}
	}

	return false
}

// SupportsQUIC checks if the proxy URL supports QUIC/HTTP3 tunneling.
// Returns true for SOCKS5 (UDP relay) or MASQUE (CONNECT-UDP) proxies.
func SupportsQUIC(proxyURL string) bool {
	return IsSOCKS5Proxy(proxyURL) || IsMASQUEProxy(proxyURL)
}

// SetTimeout sets the request timeout
func (t *Transport) SetTimeout(timeout time.Duration) {
	t.timeout = timeout
}

// SetConnectTo sets a host mapping for domain fronting
func (t *Transport) SetConnectTo(requestHost, connectHost string) {
	if t.config == nil {
		t.config = &TransportConfig{}
	}
	if t.config.ConnectTo == nil {
		t.config.ConnectTo = make(map[string]string)
	}
	t.config.ConnectTo[requestHost] = connectHost

	// Update all transports
	if t.h1Transport != nil {
		t.h1Transport.SetConnectTo(requestHost, connectHost)
	}
	if t.h2Transport != nil {
		t.h2Transport.SetConnectTo(requestHost, connectHost)
	}
	if t.h3Transport != nil {
		t.h3Transport.SetConnectTo(requestHost, connectHost)
	}
}

// SetECHConfig sets a custom ECH configuration
func (t *Transport) SetECHConfig(echConfig []byte) {
	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfig = echConfig

	// Update HTTP/2 transport
	if t.h2Transport != nil {
		t.h2Transport.SetECHConfig(echConfig)
	}
	// Update HTTP/3 transport
	if t.h3Transport != nil {
		t.h3Transport.SetECHConfig(echConfig)
	}
}

// SetECHConfigDomain sets a domain to fetch ECH config from
func (t *Transport) SetECHConfigDomain(domain string) {
	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfigDomain = domain

	// Update HTTP/2 transport
	if t.h2Transport != nil {
		t.h2Transport.SetECHConfigDomain(domain)
	}
	// Update HTTP/3 transport
	if t.h3Transport != nil {
		t.h3Transport.SetECHConfigDomain(domain)
	}
}

// GetConnectHost returns the connection host for a request host.
// If there's a ConnectTo mapping, returns the mapped host.
// Otherwise returns the original host.
func (c *TransportConfig) GetConnectHost(requestHost string) string {
	if c == nil || c.ConnectTo == nil {
		return requestHost
	}
	if connectHost, ok := c.ConnectTo[requestHost]; ok {
		return connectHost
	}
	return requestHost
}

// GetECHConfig returns the ECH config to use for a host.
// Returns custom config if set, otherwise fetches from ECHConfigDomain or target host.
func (c *TransportConfig) GetECHConfig(ctx context.Context, targetHost string) []byte {
	if c == nil {
		// No config - fetch from target host
		echConfig, _ := dns.FetchECHConfigs(ctx, targetHost)
		return echConfig
	}

	// Custom ECH config takes priority
	if len(c.ECHConfig) > 0 {
		return c.ECHConfig
	}

	// ECH from different domain
	if c.ECHConfigDomain != "" {
		echConfig, _ := dns.FetchECHConfigs(ctx, c.ECHConfigDomain)
		return echConfig
	}

	// Default: fetch from target host
	echConfig, _ := dns.FetchECHConfigs(ctx, targetHost)
	return echConfig
}

// Do executes an HTTP request
func (t *Transport) Do(ctx context.Context, req *Request) (*Response, error) {
	// Parse URL to determine scheme
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "", err)
	}

	// For HTTP (non-TLS), only HTTP/1.1 is supported
	if parsedURL.Scheme == "http" {
		return t.doHTTP1(ctx, req)
	}

	// When proxy is configured, respect user's protocol choice
	// Check for any proxy (URL, TCPProxy, or UDPProxy)
	if t.proxy != nil && (t.proxy.URL != "" || t.proxy.TCPProxy != "" || t.proxy.UDPProxy != "") {
		// Get effective proxy URL for protocol detection
		effectiveProxyURL := t.proxy.URL
		if effectiveProxyURL == "" {
			effectiveProxyURL = t.proxy.TCPProxy
		}
		if effectiveProxyURL == "" {
			effectiveProxyURL = t.proxy.UDPProxy
		}

		// Respect user's explicit protocol choice
		switch t.protocol {
		case ProtocolHTTP1:
			return t.doHTTP1(ctx, req)

		case ProtocolHTTP2:
			return t.doHTTP2(ctx, req)

		case ProtocolHTTP3:
			// Check if H3 is possible with this proxy
			if t.h3ProxyError != nil {
				return nil, t.h3ProxyError
			}
			if !SupportsQUIC(effectiveProxyURL) {
				return nil, fmt.Errorf("HTTP/3 requires a SOCKS5 or MASQUE proxy (current proxy does not support UDP)")
			}
			return t.doHTTP3(ctx, req)

		case ProtocolAuto:
			// Auto-select based on proxy capabilities
			if t.h3ProxyError != nil {
				// H3 proxy failed during init - use H2/H1 only
				resp, err := t.doHTTP2(ctx, req)
				if err == nil {
					return resp, nil
				}
				return t.doHTTP1(ctx, req)
			}

			if SupportsQUIC(effectiveProxyURL) {
				// SOCKS5 or MASQUE proxy - prefer HTTP/3 for best fingerprinting
				resp, err := t.doHTTP3(ctx, req)
				if err == nil {
					return resp, nil
				}
				// Fallback to HTTP/2 if HTTP/3 fails
				resp, err = t.doHTTP2(ctx, req)
				if err == nil {
					return resp, nil
				}
				return t.doHTTP1(ctx, req)
			}
			// HTTP proxy - only supports H2/H1
			resp, err := t.doHTTP2(ctx, req)
			if err == nil {
				return resp, nil
			}
			return t.doHTTP1(ctx, req)

		default:
			return t.doHTTP2(ctx, req)
		}
	}

	switch t.protocol {
	case ProtocolHTTP1:
		return t.doHTTP1(ctx, req)
	case ProtocolHTTP2:
		return t.doHTTP2(ctx, req)
	case ProtocolHTTP3:
		return t.doHTTP3(ctx, req)
	case ProtocolAuto:
		return t.doAuto(ctx, req)
	default:
		return t.doHTTP2(ctx, req)
	}
}

// doAuto races HTTP/3 and HTTP/2 in parallel, using whichever succeeds first.
// This avoids the 5-second HTTP/3 timeout delay when QUIC is blocked.
func (t *Transport) doAuto(ctx context.Context, req *Request) (*Response, error) {
	host := extractHost(req.URL)

	// Check if we already know the best protocol for this host
	t.protocolSupportMu.RLock()
	knownProtocol, known := t.protocolSupport[host]
	t.protocolSupportMu.RUnlock()

	if known {
		switch knownProtocol {
		case ProtocolHTTP3:
			return t.doHTTP3(ctx, req)
		case ProtocolHTTP2:
			resp, err := t.doHTTP2(ctx, req)
			if err == nil {
				return resp, nil
			}
			// H2 failed, try H1
			return t.doHTTP1(ctx, req)
		case ProtocolHTTP1:
			return t.doHTTP1(ctx, req)
		}
	}

	// Race HTTP/3 and HTTP/2 in parallel if H3 is supported
	if t.preset.SupportHTTP3 {
		resp, protocol, err := t.raceH3H2(ctx, req)
		if err == nil {
			t.protocolSupportMu.Lock()
			t.protocolSupport[host] = protocol
			t.protocolSupportMu.Unlock()
			return resp, nil
		}
		// Both failed, try HTTP/1.1
	} else {
		// No H3 support, just try H2
		resp, err := t.doHTTP2(ctx, req)
		if err == nil {
			t.protocolSupportMu.Lock()
			t.protocolSupport[host] = ProtocolHTTP2
			t.protocolSupportMu.Unlock()
			return resp, nil
		}
	}

	// Fallback to HTTP/1.1
	resp, err := t.doHTTP1(ctx, req)
	if err == nil {
		t.protocolSupportMu.Lock()
		t.protocolSupport[host] = ProtocolHTTP1
		t.protocolSupportMu.Unlock()
		return resp, nil
	}

	return nil, err
}

// connectResult holds the result of a connection race
type connectResult struct {
	protocol Protocol
	err      error
}

// raceH3H2 races HTTP/3 and HTTP/2 connections in parallel, then makes the request
// on whichever protocol connects first. This eliminates the 5-second delay when
// HTTP/3 (QUIC) is blocked by firewalls or VPNs.
func (t *Transport) raceH3H2(ctx context.Context, req *Request) (*Response, Protocol, error) {
	// Parse URL to get host:port
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, ProtocolHTTP2, err
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	// Create cancellable context for the race
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Channel to receive the winning protocol
	winnerCh := make(chan Protocol, 1)
	doneCh := make(chan struct{})

	// Race HTTP/3 connection
	go func() {
		err := t.h3Transport.Connect(raceCtx, host, port)
		if err == nil {
			select {
			case winnerCh <- ProtocolHTTP3:
			default:
			}
		}
	}()

	// Race HTTP/2 connection
	go func() {
		err := t.h2Transport.Connect(raceCtx, host, port)
		if err == nil {
			select {
			case winnerCh <- ProtocolHTTP2:
			default:
			}
		}
	}()

	// Goroutine to signal when both attempts are likely done
	go func() {
		// Give both a chance to connect (with H3 timeout being the limiting factor)
		// H3 typically times out in 5s if blocked, H2 connects in <1s
		time.Sleep(6 * time.Second)
		close(doneCh)
	}()

	// Wait for a winner or timeout
	var winningProtocol Protocol
	select {
	case winningProtocol = <-winnerCh:
		// We have a winner!
		cancel() // Cancel the other connection attempt
	case <-doneCh:
		// Timeout - no winner, try H2 directly
		cancel()
		resp, err := t.doHTTP2(ctx, req)
		if err != nil {
			resp, err = t.doHTTP1(ctx, req)
			return resp, ProtocolHTTP1, err
		}
		return resp, ProtocolHTTP2, nil
	case <-ctx.Done():
		return nil, ProtocolHTTP2, ctx.Err()
	}

	// Make the actual request using the winning protocol
	switch winningProtocol {
	case ProtocolHTTP3:
		resp, err := t.doHTTP3(ctx, req)
		return resp, ProtocolHTTP3, err
	case ProtocolHTTP2:
		resp, err := t.doHTTP2(ctx, req)
		if err != nil {
			// H2 failed after connect succeeded, try H1
			resp, err = t.doHTTP1(ctx, req)
			return resp, ProtocolHTTP1, err
		}
		return resp, ProtocolHTTP2, nil
	default:
		resp, err := t.doHTTP2(ctx, req)
		return resp, ProtocolHTTP2, err
	}
}

// isProtocolError checks if the error indicates protocol negotiation failure
func isProtocolError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "protocol") ||
		strings.Contains(errStr, "alpn") ||
		strings.Contains(errStr, "http2") ||
		strings.Contains(errStr, "does not support")
}

// doHTTP1 executes the request over HTTP/1.1
func (t *Transport) doHTTP1(ctx context.Context, req *Request) (*Response, error) {
	startTime := time.Now()
	timing := &protocol.Timing{}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "h1", err)
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Set timeout
	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build HTTP request
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, "h1", err)
	}

	// Set preset headers (with ordering for fingerprinting)
	applyPresetHeaders(httpReq, t.preset)

	// Override with custom headers (multi-value support)
	for key, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}

	// Record timing before request
	reqStart := time.Now()

	// Make request
	resp, err := t.h1Transport.RoundTrip(httpReq)
	if err != nil {
		return nil, WrapError("roundtrip", host, port, "h1", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	// Read response body with pre-allocation for known content length
	body, releaseBody, err := readBodyOptimized(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h1", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" {
		decompressed, err := decompress(body, contentEncoding)
		if err != nil {
			releaseBody() // Release pooled buffer on error
			return nil, NewRequestError("decompress", host, port, "h1", err)
		}
		releaseBody() // Release original pooled buffer after decompression
		body = decompressed
		releaseBody = func() {} // Decompressed buffer is not pooled
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   req.URL,
		Timing:     timing,
		Protocol:   "h1",
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

// doHTTP2 executes the request over HTTP/2
func (t *Transport) doHTTP2(ctx context.Context, req *Request) (*Response, error) {
	startTime := time.Now()
	timing := &protocol.Timing{}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "h2", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, NewProtocolError("", "", "h2",
			&TransportError{Op: "scheme_check", Cause: ErrProtocol, Category: ErrProtocol})
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	// Get connection use count BEFORE the request
	useCountBefore := t.h2Transport.GetConnectionUseCount(host, port)

	// Set timeout
	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build HTTP request
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, "h2", err)
	}

	// Set preset headers (with ordering for fingerprinting)
	applyPresetHeaders(httpReq, t.preset)

	// Override with custom headers (multi-value support)
	for key, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}

	// Record timing before request
	reqStart := time.Now()

	// Make request
	resp, err := t.h2Transport.RoundTrip(httpReq)
	if err != nil {
		return nil, WrapError("roundtrip", host, port, "h2", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	// Read response body with pre-allocation for known content length
	body, releaseBody, err := readBodyOptimized(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h2", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" {
		decompressed, err := decompress(body, contentEncoding)
		if err != nil {
			releaseBody()
			return nil, NewRequestError("decompress", host, port, "h2", err)
		}
		releaseBody()
		body = decompressed
		releaseBody = func() {}
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Calculate timing breakdown
	wasReused := useCountBefore >= 1
	if wasReused {
		timing.DNSLookup = 0
		timing.TCPConnect = 0
		timing.TLSHandshake = 0
	} else {
		connectionOverhead := timing.FirstByte * 0.7
		if connectionOverhead > 10 {
			timing.DNSLookup = connectionOverhead * 0.2
			timing.TCPConnect = connectionOverhead * 0.3
			timing.TLSHandshake = connectionOverhead * 0.5
		}
	}

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   req.URL,
		Timing:     timing,
		Protocol:   "h2",
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

// doHTTP3 executes the request over HTTP/3
func (t *Transport) doHTTP3(ctx context.Context, req *Request) (*Response, error) {
	startTime := time.Now()
	timing := &protocol.Timing{}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "h3", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, NewProtocolError("", "", "h3",
			&TransportError{Op: "scheme_check", Cause: ErrProtocol, Category: ErrProtocol})
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	// Get dial count BEFORE the request
	dialCountBefore := t.h3Transport.GetDialCount()

	// Set timeout
	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build HTTP request
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, "h3", err)
	}

	// Set preset headers (with ordering for fingerprinting)
	applyPresetHeaders(httpReq, t.preset)

	// Override with custom headers (multi-value support)
	for key, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}

	// Record timing before request
	reqStart := time.Now()

	// Make request
	resp, err := t.h3Transport.RoundTrip(httpReq)
	if err != nil {
		return nil, WrapError("roundtrip", host, port, "h3", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	// Read response body with pre-allocation for known content length
	body, releaseBody, err := readBodyOptimized(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h3", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" {
		decompressed, err := decompress(body, contentEncoding)
		if err != nil {
			releaseBody()
			return nil, NewRequestError("decompress", host, port, "h3", err)
		}
		releaseBody()
		body = decompressed
		releaseBody = func() {}
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Calculate timing breakdown (HTTP/3 uses QUIC, no TCP)
	dialCountAfter := t.h3Transport.GetDialCount()
	wasReused := dialCountAfter == dialCountBefore
	timing.TCPConnect = 0

	if wasReused {
		timing.DNSLookup = 0
		timing.TLSHandshake = 0
	} else {
		connectionOverhead := timing.FirstByte * 0.7
		if connectionOverhead > 10 {
			timing.DNSLookup = connectionOverhead * 0.3
			timing.TLSHandshake = connectionOverhead * 0.7
		}
	}

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   req.URL,
		Timing:     timing,
		Protocol:   "h3",
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

// Close shuts down the transport
func (t *Transport) Close() {
	t.h1Transport.Close()
	t.h2Transport.Close()
	t.h3Transport.Close()
}

// Stats returns transport statistics
func (t *Transport) Stats() map[string]interface{} {
	return map[string]interface{}{
		"http1": t.h1Transport.Stats(),
		"http2": t.h2Transport.Stats(),
		"http3": t.h3Transport.Stats(),
	}
}

// GetDNSCache returns the DNS cache
func (t *Transport) GetDNSCache() *dns.Cache {
	return t.dnsCache
}

// ClearProtocolCache clears the learned protocol support cache
func (t *Transport) ClearProtocolCache() {
	t.protocolSupportMu.Lock()
	t.protocolSupport = make(map[string]Protocol)
	t.protocolSupportMu.Unlock()
}

// GetHTTP1Transport returns the HTTP/1.1 transport for TLS session cache access
func (t *Transport) GetHTTP1Transport() *HTTP1Transport {
	return t.h1Transport
}

// GetHTTP2Transport returns the HTTP/2 transport for TLS session cache access
func (t *Transport) GetHTTP2Transport() *HTTP2Transport {
	return t.h2Transport
}

// GetHTTP3Transport returns the HTTP/3 transport for TLS session cache access
func (t *Transport) GetHTTP3Transport() *HTTP3Transport {
	return t.h3Transport
}

// Helper functions

// applyPresetHeaders applies headers from the preset to the request.
// Uses ordered headers (HeaderOrder) if available, otherwise falls back to the map.
func applyPresetHeaders(httpReq *http.Request, preset *fingerprint.Preset) {
	if len(preset.HeaderOrder) > 0 {
		// Use ordered headers for HTTP/2 and HTTP/3 fingerprinting
		for _, hp := range preset.HeaderOrder {
			httpReq.Header.Set(hp.Key, hp.Value)
		}
	} else {
		// Fallback to unordered headers map
		for key, value := range preset.Headers {
			httpReq.Header.Set(key, value)
		}
	}
	httpReq.Header.Set("User-Agent", preset.UserAgent)
}

func extractHost(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// buildHeadersMap converts http.Header to map[string][]string.
// Preserves all values for multi-value headers (Set-Cookie, etc.)
func buildHeadersMap(h http.Header) map[string][]string {
	headers := make(map[string][]string)
	for key, values := range h {
		lowerKey := strings.ToLower(key)
		// Copy values to avoid sharing underlying array
		headerValues := make([]string, len(values))
		copy(headerValues, values)
		headers[lowerKey] = headerValues
	}
	return headers
}

// readBodyOptimized reads the response body with pooled buffers when Content-Length is known
// Returns the body slice, a release function to return the buffer to the pool, and any error.
// The release function should be called when the body is no longer needed to enable buffer reuse.
func readBodyOptimized(body io.Reader, contentLength int64) ([]byte, func(), error) {
	if contentLength > 0 {
		// Use pooled buffer for known sizes up to 100MB
		if contentLength <= 100*1024*1024 {
			bufPtr, release := getPooledBuffer(contentLength)
			buf := (*bufPtr)[:contentLength]
			n, err := io.ReadFull(body, buf)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				release()
				return nil, nil, err
			}
			return buf[:n], release, nil
		}
		// For very large bodies, allocate directly
		buf := make([]byte, contentLength)
		n, err := io.ReadFull(body, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, nil, err
		}
		return buf[:n], func() {}, nil
	}
	// Fall back to io.ReadAll for unknown/chunked content length
	data, err := io.ReadAll(body)
	return data, func() {}, err
}

func decompress(data []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)

	case "br":
		reader := brotli.NewReader(bytes.NewReader(data))
		return io.ReadAll(reader)

	case "zstd":
		decoder, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer decoder.Close()
		return io.ReadAll(decoder)

	case "deflate":
		reader := flate.NewReader(bytes.NewReader(data))
		defer reader.Close()
		return io.ReadAll(reader)

	case "", "identity":
		return data, nil

	default:
		return data, nil
	}
}
