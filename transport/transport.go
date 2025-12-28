package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
)

// Protocol represents the HTTP protocol version
type Protocol int

const (
	// ProtocolAuto automatically selects HTTP/3 or HTTP/2
	ProtocolAuto Protocol = iota
	// ProtocolHTTP2 forces HTTP/2 over TCP
	ProtocolHTTP2
	// ProtocolHTTP3 forces HTTP/3 over QUIC
	ProtocolHTTP3
)

// ProxyConfig contains proxy server configuration
type ProxyConfig struct {
	URL      string // Proxy URL (e.g., "http://proxy:8080" or "http://user:pass@proxy:8080")
	Username string // Proxy username (optional, can also be in URL)
	Password string // Proxy password (optional, can also be in URL)
}

// Request represents an HTTP request
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Timeout time.Duration
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
	FinalURL   string
	Timing     *protocol.Timing
	Protocol   string // "h2" or "h3"
}

// Transport is a unified HTTP transport supporting both HTTP/2 and HTTP/3
type Transport struct {
	h2Transport *HTTP2Transport
	h3Transport *HTTP3Transport
	dnsCache    *dns.Cache
	preset      *fingerprint.Preset
	timeout     time.Duration
	protocol    Protocol
	proxy       *ProxyConfig

	// Track HTTP/3 support per host
	http3Support map[string]bool
	http3Mu      sync.RWMutex
}

// NewTransport creates a new unified transport
func NewTransport(presetName string) *Transport {
	return NewTransportWithProxy(presetName, nil)
}

// NewTransportWithProxy creates a new unified transport with optional proxy
func NewTransportWithProxy(presetName string, proxy *ProxyConfig) *Transport {
	preset := fingerprint.Get(presetName)
	dnsCache := dns.NewCache()

	t := &Transport{
		dnsCache:     dnsCache,
		preset:       preset,
		timeout:      30 * time.Second,
		protocol:     ProtocolAuto, // Try HTTP/3 first, fallback to HTTP/2
		http3Support: make(map[string]bool),
		proxy:        proxy,
	}

	// Create transports with proxy config
	t.h2Transport = NewHTTP2TransportWithProxy(preset, dnsCache, proxy)
	t.h3Transport = NewHTTP3Transport(preset, dnsCache) // HTTP/3 doesn't support traditional proxies

	return t
}

// SetProtocol sets the preferred protocol
func (t *Transport) SetProtocol(p Protocol) {
	t.protocol = p
}

// SetProxy sets or updates the proxy configuration
// Note: This recreates the underlying transports
func (t *Transport) SetProxy(proxy *ProxyConfig) {
	t.proxy = proxy
	// Recreate HTTP/2 transport with new proxy config
	t.h2Transport.Close()
	t.h2Transport = NewHTTP2TransportWithProxy(t.preset, t.dnsCache, proxy)
	// HTTP/3 doesn't support traditional proxies, so it remains unchanged
}

// SetPreset changes the fingerprint preset
func (t *Transport) SetPreset(presetName string) {
	t.preset = fingerprint.Get(presetName)
	// Recreate transports with new preset
	t.h2Transport.Close()
	t.h3Transport.Close()
	t.h2Transport = NewHTTP2TransportWithProxy(t.preset, t.dnsCache, t.proxy)
	t.h3Transport = NewHTTP3Transport(t.preset, t.dnsCache)
}

// SetTimeout sets the request timeout
func (t *Transport) SetTimeout(timeout time.Duration) {
	t.timeout = timeout
}

// Do executes an HTTP request
func (t *Transport) Do(ctx context.Context, req *Request) (*Response, error) {
	// When proxy is configured, always use HTTP/2 (proxies don't support QUIC)
	if t.proxy != nil && t.proxy.URL != "" {
		return t.doHTTP2(ctx, req)
	}

	switch t.protocol {
	case ProtocolHTTP3:
		return t.doHTTP3(ctx, req)
	case ProtocolHTTP2:
		return t.doHTTP2(ctx, req)
	case ProtocolAuto:
		return t.doAuto(ctx, req)
	default:
		return t.doHTTP2(ctx, req)
	}
}

// doAuto tries HTTP/3 first if supported, falls back to HTTP/2
func (t *Transport) doAuto(ctx context.Context, req *Request) (*Response, error) {
	host := extractHost(req.URL)

	t.http3Mu.RLock()
	supportsHTTP3, known := t.http3Support[host]
	t.http3Mu.RUnlock()

	// If we know HTTP/3 is not supported, use HTTP/2
	if known && !supportsHTTP3 {
		return t.doHTTP2(ctx, req)
	}

	// If preset doesn't support HTTP/3, use HTTP/2
	if !t.preset.SupportHTTP3 {
		return t.doHTTP2(ctx, req)
	}

	// Try HTTP/3 first
	resp, err := t.doHTTP3(ctx, req)
	if err == nil {
		t.http3Mu.Lock()
		t.http3Support[host] = true
		t.http3Mu.Unlock()
		return resp, nil
	}

	// HTTP/3 failed, mark as not supported and fallback to HTTP/2
	t.http3Mu.Lock()
	t.http3Support[host] = false
	t.http3Mu.Unlock()

	return t.doHTTP2(ctx, req)
}

// doHTTP2 executes the request over HTTP/2
func (t *Transport) doHTTP2(ctx context.Context, req *Request) (*Response, error) {
	startTime := time.Now()
	timing := &protocol.Timing{}

	// Parse URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("only HTTPS is supported")
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	// Get connection use count BEFORE the request to detect if new connection was created
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
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set preset headers
	for key, value := range t.preset.Headers {
		httpReq.Header.Set(key, value)
	}
	httpReq.Header.Set("User-Agent", t.preset.UserAgent)

	// Override with custom headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Record timing before request
	reqStart := time.Now()

	// Make request via transport (handles connection reuse)
	resp, err := t.h2Transport.RoundTrip(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	body, err = decompress(body, contentEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress response: %w", err)
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Check if connection was reused by comparing use counts
	// If useCountBefore was 0, a new connection was created
	// If useCountBefore >= 1, the existing connection was reused
	wasReused := useCountBefore >= 1

	// Set timing based on actual connection reuse
	if wasReused {
		// Reused connection - no connection overhead
		timing.DNSLookup = 0
		timing.TCPConnect = 0
		timing.TLSHandshake = 0
	} else {
		// New connection - the firstByte time includes DNS/TCP/TLS overhead
		// Estimate breakdown based on typical ratios
		connectionOverhead := timing.FirstByte * 0.7 // ~70% of first byte is connection setup
		if connectionOverhead > 10 {                 // Only show if significant (>10ms)
			timing.DNSLookup = connectionOverhead * 0.2    // ~20% DNS
			timing.TCPConnect = connectionOverhead * 0.3   // ~30% TCP
			timing.TLSHandshake = connectionOverhead * 0.5 // ~50% TLS
		}
	}

	// Build response headers map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		lowerKey := strings.ToLower(key)
		// Set-Cookie headers need special handling - join with newline to preserve each cookie
		if lowerKey == "set-cookie" {
			headers[lowerKey] = strings.Join(values, "\n")
		} else {
			headers[lowerKey] = strings.Join(values, ", ")
		}
	}

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

	// Parse URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("only HTTPS is supported")
	}

	// Get dial count BEFORE the request to detect if new connection was created
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
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set preset headers
	for key, value := range t.preset.Headers {
		httpReq.Header.Set(key, value)
	}
	httpReq.Header.Set("User-Agent", t.preset.UserAgent)

	// Override with custom headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Record timing before request
	reqStart := time.Now()

	// Make request via transport (custom dialer handles connection reuse)
	resp, err := t.h3Transport.RoundTrip(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP/3 request failed: %w", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	body, err = decompress(body, contentEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress response: %w", err)
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Check if connection was reused by comparing dial counts
	// If dialCount increased, a new connection was created
	dialCountAfter := t.h3Transport.GetDialCount()
	wasReused := dialCountAfter == dialCountBefore

	// HTTP/3 uses QUIC over UDP - no TCP connect
	timing.TCPConnect = 0

	if wasReused {
		// Reused QUIC connection - no DNS or handshake overhead
		timing.DNSLookup = 0
		timing.TLSHandshake = 0
	} else {
		// New QUIC connection - the firstByte time includes DNS and QUIC handshake
		connectionOverhead := timing.FirstByte * 0.7 // ~70% of first byte is connection setup
		if connectionOverhead > 10 {                 // Only show if significant (>10ms)
			timing.DNSLookup = connectionOverhead * 0.3    // ~30% DNS
			timing.TLSHandshake = connectionOverhead * 0.7 // ~70% QUIC/TLS (combined in QUIC)
		}
	}

	// Build response headers map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		lowerKey := strings.ToLower(key)
		// Set-Cookie headers need special handling - join with newline to preserve each cookie
		if lowerKey == "set-cookie" {
			headers[lowerKey] = strings.Join(values, "\n")
		} else {
			headers[lowerKey] = strings.Join(values, ", ")
		}
	}

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
	t.h2Transport.Close()
	t.h3Transport.Close()
}

// Stats returns transport statistics
func (t *Transport) Stats() map[string]interface{} {
	return map[string]interface{}{
		"http2": t.h2Transport.Stats(),
		"http3": t.h3Transport.Stats(),
	}
}

// GetDNSCache returns the DNS cache
func (t *Transport) GetDNSCache() *dns.Cache {
	return t.dnsCache
}

// Helper functions

func extractHost(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
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

	case "deflate":
		return data, nil

	case "", "identity":
		return data, nil

	default:
		return data, nil
	}
}
