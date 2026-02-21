package transport

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/protocol"
)

// StreamResponse represents a streaming HTTP response where the body
// is read incrementally rather than all at once.
type StreamResponse struct {
	StatusCode int
	Headers    map[string][]string // Multi-value headers
	FinalURL   string
	Timing     *protocol.Timing
	Protocol   string // "h1", "h2", or "h3"

	// ContentLength is the expected total size (-1 if unknown/chunked)
	ContentLength int64

	// The underlying response body reader
	reader       io.ReadCloser
	decompressor io.Closer
	rawReader    io.ReadCloser

	// Context cancel function - called when response is closed
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
	if r.rawReader != nil {
		return r.rawReader.Close()
	}
	return nil
}

// ReadAll reads the entire response body into memory
// This defeats the purpose of streaming but is useful for small responses
func (r *StreamResponse) ReadAll() ([]byte, error) {
	defer r.Close()
	return io.ReadAll(r.reader)
}

// ReadChunk reads up to size bytes from the response
func (r *StreamResponse) ReadChunk(size int) ([]byte, error) {
	buf := make([]byte, size)
	n, err := r.reader.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], err
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
// The caller is responsible for closing the response when done
func (t *Transport) DoStream(ctx context.Context, req *Request) (*StreamResponse, error) {
	// Parse URL to determine scheme
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "", err)
	}

	// For HTTP (non-TLS), only HTTP/1.1 is supported
	if parsedURL.Scheme == "http" {
		return t.doStreamHTTP1(ctx, req)
	}

	// When proxy is configured, select protocol based on proxy capabilities
	if t.proxy != nil && (t.proxy.URL != "" || t.proxy.TCPProxy != "" || t.proxy.UDPProxy != "") {
		effectiveProxyURL := t.proxy.URL
		if effectiveProxyURL == "" {
			effectiveProxyURL = t.proxy.TCPProxy
		}
		if effectiveProxyURL == "" {
			effectiveProxyURL = t.proxy.UDPProxy
		}
		if SupportsQUIC(effectiveProxyURL) {
			resp, err := t.doStreamHTTP3(ctx, req)
			if err == nil {
				return resp, nil
			}
			// Fallback to HTTP/2
			return t.doStreamHTTP2(ctx, req)
		}
		// HTTP/HTTPS proxy - use HTTP/2
		return t.doStreamHTTP2(ctx, req)
	}

	// Default HTTPS: Try HTTP/3 first, fallback to HTTP/2
	switch t.protocol {
	case ProtocolHTTP1:
		return t.doStreamHTTP1(ctx, req)
	case ProtocolHTTP2:
		return t.doStreamHTTP2(ctx, req)
	case ProtocolHTTP3:
		return t.doStreamHTTP3(ctx, req)
	default:
		// Auto mode: try H3 -> H2 with fallback
		if t.h3Transport != nil {
			resp, err := t.doStreamHTTP3(ctx, req)
			if err == nil {
				return resp, nil
			}
		}
		return t.doStreamHTTP2(ctx, req)
	}
}

// doStreamHTTP1 executes a streaming request over HTTP/1.1
func (t *Transport) doStreamHTTP1(ctx context.Context, req *Request) (*StreamResponse, error) {
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

	// For streaming, we use a cancellable context without timeout
	// The timeout from the parent context (if any) will still apply
	// But we don't add an additional timeout that would cut off reading
	ctx, cancel := context.WithCancel(ctx)

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
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		cancel()
		return nil, NewRequestError("create_request", host, port, "h1", err)
	}

	// Determine effective TLS-only mode: per-request override takes precedence
	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	// Set preset headers
	applyPresetHeaders(httpReq, t.preset, t.getHeaderOrder(), effectiveTLSOnly, "h1")

	// Override with custom headers (multi-value support)
	// Use Set for first value to replace preset headers, Add for additional values
	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	// Record timing before request
	reqStart := time.Now()

	// Make request - use StreamRoundTrip to avoid connection pooling issues
	resp, err := t.h1Transport.StreamRoundTrip(httpReq)
	if err != nil {
		cancel()
		return nil, WrapError("stream_roundtrip", host, port, "h1", err)
	}

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())
	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	// Setup decompression reader
	reader, decompressor := setupStreamDecompressor(resp.Body, resp.Header.Get("Content-Encoding"))

	return &StreamResponse{
		StatusCode:    resp.StatusCode,
		Headers:       headers,
		FinalURL:      req.URL,
		Timing:        timing,
		Protocol:      "h1",
		ContentLength: resp.ContentLength,
		reader:        reader,
		decompressor:  decompressor,
		rawReader:     resp.Body,
		cancel:        cancel,
	}, nil
}

// doStreamHTTP2 executes a streaming request over HTTP/2
func (t *Transport) doStreamHTTP2(ctx context.Context, req *Request) (*StreamResponse, error) {
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

	// For streaming, use cancellable context without additional timeout
	ctx, cancel := context.WithCancel(ctx)

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
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		cancel()
		return nil, NewRequestError("create_request", host, port, "h2", err)
	}

	// Determine effective TLS-only mode: per-request override takes precedence
	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	// Set preset headers
	applyPresetHeaders(httpReq, t.preset, t.getHeaderOrder(), effectiveTLSOnly, "h2")

	// Override with custom headers (multi-value support)
	// Use Set for first value to replace preset headers, Add for additional values
	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	// Record timing before request
	reqStart := time.Now()

	// Make request
	resp, err := t.h2Transport.RoundTrip(httpReq)
	if err != nil {
		cancel()
		return nil, WrapError("roundtrip", host, port, "h2", err)
	}

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())
	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	// Setup decompression reader
	reader, decompressor := setupStreamDecompressor(resp.Body, resp.Header.Get("Content-Encoding"))

	return &StreamResponse{
		StatusCode:    resp.StatusCode,
		Headers:       headers,
		FinalURL:      req.URL,
		Timing:        timing,
		Protocol:      "h2",
		ContentLength: resp.ContentLength,
		reader:        reader,
		decompressor:  decompressor,
		rawReader:     resp.Body,
		cancel:        cancel,
	}, nil
}

// doStreamHTTP3 executes a streaming request over HTTP/3
func (t *Transport) doStreamHTTP3(ctx context.Context, req *Request) (*StreamResponse, error) {
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

	// For streaming, use cancellable context without additional timeout
	ctx, cancel := context.WithCancel(ctx)

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
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		cancel()
		return nil, NewRequestError("create_request", host, port, "h3", err)
	}

	// Determine effective TLS-only mode: per-request override takes precedence
	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	// Set preset headers
	applyPresetHeaders(httpReq, t.preset, t.getHeaderOrder(), effectiveTLSOnly, "h3")

	// Override with custom headers (multi-value support)
	// Use Set for first value to replace preset headers, Add for additional values
	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	// Record timing before request
	reqStart := time.Now()

	// Make request
	resp, err := t.h3Transport.RoundTrip(httpReq)
	if err != nil {
		cancel()
		return nil, WrapError("roundtrip", host, port, "h3", err)
	}

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())
	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	// Setup decompression reader
	reader, decompressor := setupStreamDecompressor(resp.Body, resp.Header.Get("Content-Encoding"))

	return &StreamResponse{
		StatusCode:    resp.StatusCode,
		Headers:       headers,
		FinalURL:      req.URL,
		Timing:        timing,
		Protocol:      "h3",
		ContentLength: resp.ContentLength,
		reader:        reader,
		decompressor:  decompressor,
		rawReader:     resp.Body,
		cancel:        cancel,
	}, nil
}

// setupStreamDecompressor creates a decompression reader based on Content-Encoding
func setupStreamDecompressor(body io.ReadCloser, encoding string) (io.ReadCloser, io.Closer) {
	switch strings.ToLower(encoding) {
	case "gzip":
		reader, err := gzip.NewReader(body)
		if err != nil {
			return body, nil
		}
		return reader, reader
	case "br":
		return &brotliStreamReader{brotli.NewReader(body)}, nil
	case "deflate":
		return &deflateStreamReader{flate.NewReader(body)}, nil
	case "zstd":
		decoder, err := zstd.NewReader(body)
		if err != nil {
			return body, nil
		}
		return &zstdStreamReader{decoder: decoder, body: body}, nil
	default:
		return body, nil
	}
}

// brotliStreamReader wraps brotli.Reader to implement io.ReadCloser
type brotliStreamReader struct {
	reader *brotli.Reader
}

func (b *brotliStreamReader) Read(p []byte) (n int, err error) {
	return b.reader.Read(p)
}

func (b *brotliStreamReader) Close() error {
	return nil // brotli.Reader doesn't need closing
}

// deflateStreamReader wraps flate.Reader to implement io.ReadCloser
type deflateStreamReader struct {
	reader io.ReadCloser
}

func (d *deflateStreamReader) Read(p []byte) (n int, err error) {
	return d.reader.Read(p)
}

func (d *deflateStreamReader) Close() error {
	return d.reader.Close()
}

// zstdStreamReader wraps zstd.Decoder to implement io.ReadCloser
type zstdStreamReader struct {
	decoder *zstd.Decoder
	body    io.ReadCloser
}

func (z *zstdStreamReader) Read(p []byte) (n int, err error) {
	return z.decoder.Read(p)
}

func (z *zstdStreamReader) Close() error {
	z.decoder.Close()
	return z.body.Close()
}
