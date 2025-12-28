package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/pool"
	"github.com/sardanioss/httpcloak/protocol"
)

// HTTP3Client is an HTTP/3 client with QUIC connection pooling
type HTTP3Client struct {
	quicManager *pool.QUICManager
	preset      *fingerprint.Preset
	timeout     time.Duration
}

// NewHTTP3Client creates a new HTTP/3 client
func NewHTTP3Client(presetName string) *HTTP3Client {
	preset := fingerprint.Get(presetName)
	// Create a shared DNS cache
	h2Manager := pool.NewManager(preset)

	return &HTTP3Client{
		quicManager: pool.NewQUICManager(preset, h2Manager.GetDNSCache()),
		preset:      preset,
		timeout:     30 * time.Second,
	}
}

// NewHTTP3ClientWithDNS creates a new HTTP/3 client with shared DNS cache
func NewHTTP3ClientWithDNS(presetName string, dnsCache interface{}) *HTTP3Client {
	preset := fingerprint.Get(presetName)

	// Type assert to get the actual DNS cache
	var quicMgr *pool.QUICManager
	if dc, ok := dnsCache.(*pool.Manager); ok {
		quicMgr = pool.NewQUICManager(preset, dc.GetDNSCache())
	} else {
		// Fallback: create new manager to get DNS cache
		h2Manager := pool.NewManager(preset)
		quicMgr = pool.NewQUICManager(preset, h2Manager.GetDNSCache())
	}

	return &HTTP3Client{
		quicManager: quicMgr,
		preset:      preset,
		timeout:     30 * time.Second,
	}
}

// SetPreset changes the fingerprint preset
func (c *HTTP3Client) SetPreset(presetName string) {
	c.preset = fingerprint.Get(presetName)
}

// SetTimeout sets the request timeout
func (c *HTTP3Client) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// Do executes an HTTP/3 request
func (c *HTTP3Client) Do(ctx context.Context, req *Request) (*Response, error) {
	startTime := time.Now()

	// Parse URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("HTTP/3 only supports HTTPS")
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	// Set timeout
	timeout := c.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track timing
	timing := &protocol.Timing{}
	connStart := time.Now()

	// Get QUIC connection from pool
	conn, err := c.quicManager.GetConn(ctx, host, port)
	if err != nil {
		return nil, fmt.Errorf("failed to get QUIC connection: %w", err)
	}

	// Calculate timing based on whether this is a new connection
	if conn.UseCount == 1 {
		// New connection - estimate timing breakdown
		connTime := float64(time.Since(connStart).Milliseconds())
		timing.DNSLookup = connTime / 3
		timing.TCPConnect = 0 // QUIC doesn't use TCP
		timing.TLSHandshake = connTime * 2 / 3 // QUIC combines connection + TLS
	} else {
		// Reused connection - no overhead
		timing.DNSLookup = 0
		timing.TCPConnect = 0
		timing.TLSHandshake = 0
	}

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

	// Set preset headers first
	for key, value := range c.preset.Headers {
		httpReq.Header.Set(key, value)
	}

	// Set User-Agent
	httpReq.Header.Set("User-Agent", c.preset.UserAgent)

	// Set Host header
	httpReq.Header.Set("Host", host)

	// Override with custom headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Send request via HTTP/3
	firstByteTime := time.Now()
	resp, err := conn.HTTP3RT.RoundTrip(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP/3 request failed: %w", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(firstByteTime).Milliseconds())

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	body, err = decompressHTTP3(body, contentEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress response: %w", err)
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Build response headers map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[strings.ToLower(key)] = strings.Join(values, ", ")
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
		FinalURL:   req.URL,
		Timing:     timing,
	}, nil
}

// Get performs a GET request over HTTP/3
func (c *HTTP3Client) Get(ctx context.Context, url string, headers map[string]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// Post performs a POST request over HTTP/3
func (c *HTTP3Client) Post(ctx context.Context, url string, body []byte, headers map[string]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:  "POST",
		URL:     url,
		Body:    body,
		Headers: headers,
	})
}

// Close shuts down the client and all connections
func (c *HTTP3Client) Close() {
	c.quicManager.Close()
}

// Stats returns QUIC connection pool statistics
func (c *HTTP3Client) Stats() map[string]struct {
	Total    int
	Healthy  int
	Requests int64
} {
	return c.quicManager.Stats()
}

// decompressHTTP3 decompresses response body based on Content-Encoding
func decompressHTTP3(data []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "br":
		reader := brotli.NewReader(bytes.NewReader(data))
		return io.ReadAll(reader)

	case "gzip":
		return decompressGzip(data)

	case "deflate":
		return data, nil

	case "", "identity":
		return data, nil

	default:
		return data, nil
	}
}

// decompressGzip decompresses gzip data
func decompressGzip(data []byte) ([]byte, error) {
	// Import gzip in the main client file
	return data, nil // Placeholder - actual implementation in client.go
}
