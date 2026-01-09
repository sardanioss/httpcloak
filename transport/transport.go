package transport

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
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
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Timeout time.Duration
}

// RedirectInfo contains information about a redirect response
type RedirectInfo struct {
	StatusCode int
	URL        string
	Headers    map[string]string
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
	FinalURL   string
	Timing     *protocol.Timing
	Protocol   string // "h1", "h2", or "h3"
	History    []*RedirectInfo
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

	// Create HTTP/1.1 and HTTP/2 transports with config
	t.h1Transport = NewHTTP1TransportWithConfig(preset, dnsCache, proxy, config)
	t.h2Transport = NewHTTP2TransportWithConfig(preset, dnsCache, proxy, config)

	// Create HTTP/3 transport - with proxy support if applicable
	if proxy != nil && proxy.URL != "" {
		if isSOCKS5Proxy(proxy.URL) {
			// SOCKS5 supports UDP relay for HTTP/3
			h3Transport, err := NewHTTP3TransportWithConfig(preset, dnsCache, proxy, config)
			if err != nil {
				// Log error but continue without HTTP/3 proxy support
				// HTTP/3 will work for direct connections, just not through proxy
				t.h3Transport = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
			} else {
				t.h3Transport = h3Transport
			}
		} else if isMASQUEProxy(proxy.URL) {
			// MASQUE supports HTTP/3 through HTTP/3 proxy
			h3Transport, err := NewHTTP3TransportWithMASQUE(preset, dnsCache, proxy, config)
			if err != nil {
				// Fall back to non-proxied HTTP/3
				t.h3Transport = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
			} else {
				t.h3Transport = h3Transport
			}
		} else {
			// HTTP proxy - HTTP/3 only works without proxy
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

	// Update HTTP/3 transport (ECH is only used for QUIC/TLS 1.3)
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

	// When proxy is configured, select protocol based on proxy capabilities
	if t.proxy != nil && t.proxy.URL != "" {
		if SupportsQUIC(t.proxy.URL) {
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
		// Fallback to HTTP/1.1 if HTTP/2 fails through proxy
		return t.doHTTP1(ctx, req)
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
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, "h1", err)
	}

	// Set preset headers (with ordering for fingerprinting)
	applyPresetHeaders(httpReq, t.preset)

	// Override with custom headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
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

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h1", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	body, err = decompress(body, contentEncoding)
	if err != nil {
		return nil, NewRequestError("decompress", host, port, "h1", err)
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
		FinalURL:   req.URL,
		Timing:     timing,
		Protocol:   "h1",
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
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, "h2", err)
	}

	// Set preset headers (with ordering for fingerprinting)
	applyPresetHeaders(httpReq, t.preset)

	// Override with custom headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
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

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h2", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	body, err = decompress(body, contentEncoding)
	if err != nil {
		return nil, NewRequestError("decompress", host, port, "h2", err)
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
		Body:       body,
		FinalURL:   req.URL,
		Timing:     timing,
		Protocol:   "h2",
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
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, "h3", err)
	}

	// Set preset headers (with ordering for fingerprinting)
	applyPresetHeaders(httpReq, t.preset)

	// Override with custom headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
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

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h3", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	body, err = decompress(body, contentEncoding)
	if err != nil {
		return nil, NewRequestError("decompress", host, port, "h3", err)
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
		Body:       body,
		FinalURL:   req.URL,
		Timing:     timing,
		Protocol:   "h3",
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

func buildHeadersMap(h http.Header) map[string]string {
	headers := make(map[string]string)
	for key, values := range h {
		lowerKey := strings.ToLower(key)
		if lowerKey == "set-cookie" {
			headers[lowerKey] = strings.Join(values, "\n")
		} else {
			headers[lowerKey] = strings.Join(values, ", ")
		}
	}
	return headers
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
