package client

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	http "github.com/sardanioss/http"
	"net/url"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/sardanioss/httpcloak/protocol"
)

// StreamResponse represents a streaming HTTP response
type StreamResponse struct {
	StatusCode int
	Headers    map[string]string
	FinalURL   string
	Timing     *protocol.Timing
	Protocol   string

	// Request info
	Request *Request

	// The underlying response body reader
	reader       io.ReadCloser
	decompressor io.Closer
	rawReader    io.ReadCloser

	// Context cancel function - must be called when response is closed
	cancel context.CancelFunc
}

// Read reads data from the response body
func (r *StreamResponse) Read(p []byte) (n int, err error) {
	return r.reader.Read(p)
}

// Close closes the response body and cancels the context
func (r *StreamResponse) Close() error {
	if r.cancel != nil {
		r.cancel()
	}
	if r.decompressor != nil {
		r.decompressor.Close()
	}
	return r.rawReader.Close()
}

// ReadAll reads the entire response body into memory
func (r *StreamResponse) ReadAll() ([]byte, error) {
	defer r.Close()
	return io.ReadAll(r.reader)
}

// Scanner returns a bufio.Scanner for line-by-line reading
func (r *StreamResponse) Scanner() *bufio.Scanner {
	return bufio.NewScanner(r.reader)
}

// Lines returns a channel that yields lines from the response
// Close the response when done to stop iteration
func (r *StreamResponse) Lines() <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(r.reader)
		for scanner.Scan() {
			ch <- scanner.Text()
		}
	}()
	return ch
}

// IsSuccess returns true if the status code is 2xx
func (r *StreamResponse) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// DoStream executes an HTTP request and returns a streaming response
// The caller is responsible for closing the response
func (c *Client) DoStream(ctx context.Context, req *Request) (*StreamResponse, error) {
	startTime := time.Now()

	// Build URL with params
	reqURL := req.URL
	if len(req.Params) > 0 {
		reqURL = NewURLBuilder(req.URL).Params(req.Params).Build()
	}

	// Parse URL
	parsedURL, err := url.Parse(reqURL)
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

	// Set timeout
	timeout := c.config.Timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	// cancel is passed to StreamResponse and called when Close() is invoked

	// Check if HTTP/3 has failed for this host recently
	hostKey := host + ":" + port
	useH3 := c.shouldTryHTTP3(hostKey)

	// Build HTTP request
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		// POST/PUT/PATCH with empty body must send Content-Length: 0
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Normalize request (Content-Length: 0 for empty POST/PUT/PATCH, Content-Type detection, etc.)
	normalizeRequestWithBody(httpReq, req.Body)

	// Apply headers based on FetchMode
	applyModeHeaders(httpReq, c.preset, req, parsedURL)

	// Apply authentication
	auth := req.Auth
	if auth == nil {
		auth = c.auth
	}
	if auth != nil {
		if err := auth.Apply(httpReq); err != nil {
			cancel()
			return nil, fmt.Errorf("failed to apply authentication: %w", err)
		}
	}

	// Add organic jitter
	applyOrganicJitter(httpReq)

	var resp *http.Response
	var usedProtocol string
	timing := &protocol.Timing{}

	// Determine effective protocol: request-level takes precedence over client-level
	effectiveProtocol := req.ForceProtocol
	if effectiveProtocol == ProtocolAuto && c.config.ForceProtocol != ProtocolAuto {
		effectiveProtocol = c.config.ForceProtocol
	}

	// Determine protocol based on ForceProtocol option
	switch effectiveProtocol {
	case ProtocolHTTP3:
		// Force HTTP/3 only - but not possible with proxy
		if c.config.Proxy != "" {
			cancel()
			return nil, fmt.Errorf("HTTP/3 cannot be used with proxy: QUIC uses UDP which cannot tunnel through HTTP proxies")
		}
		if c.quicManager == nil {
			cancel()
			return nil, fmt.Errorf("HTTP/3 is disabled (no QUIC manager available)")
		}
		resp, usedProtocol, err = c.doHTTP3(ctx, host, port, httpReq, timing, startTime)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("HTTP/3 failed: %w", err)
		}
	case ProtocolHTTP2:
		resp, usedProtocol, err = c.doHTTP2(ctx, host, port, httpReq, timing, startTime)
		if err != nil {
			cancel()
			return nil, err
		}
	case ProtocolHTTP1:
		resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("HTTP/1.1 failed: %w", err)
		}
	default:
		// Auto mode: try H3 -> H2 -> H1 with fallback
		if useH3 {
			resp, usedProtocol, err = c.doHTTP3(ctx, host, port, httpReq, timing, startTime)
			if err != nil {
				c.markH3Failed(hostKey)
				resetRequestBody(httpReq, req.Body)
				
				resp, usedProtocol, err = c.doHTTP2(ctx, host, port, httpReq, timing, startTime)
			}
		} else {
			resp, usedProtocol, err = c.doHTTP2(ctx, host, port, httpReq, timing, startTime)
		}

		// If H2 failed and we should try H1, attempt fallback
		if err != nil && c.shouldUseH1(hostKey) {
			c.markH2Failed(hostKey)
			resetRequestBody(httpReq, req.Body)
			
			resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
		}

		if err != nil {
			cancel()
			return nil, err
		}
	}

	// Build response headers map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[strings.ToLower(key)] = strings.Join(values, ", ")
	}

	// Setup decompression reader
	reader, decompressor := setupDecompressor(resp.Body, resp.Header.Get("Content-Encoding"))

	timing.FirstByte = float64(time.Since(startTime).Milliseconds())

	return &StreamResponse{
		StatusCode:   resp.StatusCode,
		Headers:      headers,
		FinalURL:     reqURL,
		Timing:       timing,
		Protocol:     usedProtocol,
		Request:      req,
		reader:       reader,
		decompressor: decompressor,
		rawReader:    resp.Body,
		cancel:       cancel,
	}, nil
}

// setupDecompressor creates a decompression reader based on Content-Encoding
func setupDecompressor(body io.ReadCloser, encoding string) (io.ReadCloser, io.Closer) {
	switch strings.ToLower(encoding) {
	case "gzip":
		reader, err := gzip.NewReader(body)
		if err != nil {
			return body, nil
		}
		return reader, reader
	case "br":
		return &brotliReadCloser{brotli.NewReader(body)}, nil
	case "zstd":
		decoder, err := zstd.NewReader(body)
		if err != nil {
			return body, nil
		}
		return &zstdReadCloser{decoder}, nil
	default:
		return body, nil
	}
}

// brotliReadCloser wraps brotli.Reader to implement io.ReadCloser
type brotliReadCloser struct {
	reader *brotli.Reader
}

func (b *brotliReadCloser) Read(p []byte) (n int, err error) {
	return b.reader.Read(p)
}

func (b *brotliReadCloser) Close() error {
	return nil // brotli.Reader doesn't need closing
}

// zstdReadCloser wraps zstd.Decoder to implement io.ReadCloser
type zstdReadCloser struct {
	*zstd.Decoder
}

func (z *zstdReadCloser) Close() error {
	z.Decoder.Close()
	return nil
}

// GetStream performs a streaming GET request
func (c *Client) GetStream(ctx context.Context, url string, headers map[string]string) (*StreamResponse, error) {
	return c.DoStream(ctx, &Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// SSEEvent represents a Server-Sent Event
type SSEEvent struct {
	Event string
	Data  string
	ID    string
	Retry int
}

// SSEReader provides Server-Sent Events parsing
type SSEReader struct {
	scanner *bufio.Scanner
	resp    *StreamResponse
}

// NewSSEReader creates an SSE reader from a streaming response
func NewSSEReader(resp *StreamResponse) *SSEReader {
	return &SSEReader{
		scanner: bufio.NewScanner(resp.reader),
		resp:    resp,
	}
}

// Next reads the next SSE event
// Returns nil, io.EOF when stream ends
func (r *SSEReader) Next() (*SSEEvent, error) {
	event := &SSEEvent{}
	var dataLines []string

	for r.scanner.Scan() {
		line := r.scanner.Text()

		// Empty line marks end of event
		if line == "" {
			if len(dataLines) > 0 {
				event.Data = strings.Join(dataLines, "\n")
				return event, nil
			}
			continue
		}

		// Parse field
		if strings.HasPrefix(line, ":") {
			// Comment, ignore
			continue
		}

		colonIdx := strings.Index(line, ":")
		var field, value string
		if colonIdx == -1 {
			field = line
			value = ""
		} else {
			field = line[:colonIdx]
			value = line[colonIdx+1:]
			// Remove leading space if present
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
		}

		switch field {
		case "event":
			event.Event = value
		case "data":
			dataLines = append(dataLines, value)
		case "id":
			event.ID = value
		case "retry":
			// Parse retry as integer
			var retry int
			for _, c := range value {
				if c >= '0' && c <= '9' {
					retry = retry*10 + int(c-'0')
				} else {
					break
				}
			}
			event.Retry = retry
		}
	}

	if err := r.scanner.Err(); err != nil {
		return nil, err
	}

	// Check if we have partial data
	if len(dataLines) > 0 {
		event.Data = strings.Join(dataLines, "\n")
		return event, nil
	}

	return nil, io.EOF
}

// Close closes the underlying response
func (r *SSEReader) Close() error {
	return r.resp.Close()
}

// Events returns a channel that yields SSE events
// Close the reader when done to stop iteration
func (r *SSEReader) Events() <-chan *SSEEvent {
	ch := make(chan *SSEEvent)
	go func() {
		defer close(ch)
		for {
			event, err := r.Next()
			if err != nil {
				return
			}
			ch <- event
		}
	}()
	return ch
}
