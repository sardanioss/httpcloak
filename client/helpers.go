package client

import (
	"bytes"
	"compress/flate"
	"context"
	"fmt"
	"io"
	http "github.com/sardanioss/http"
	"net/url"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/gunzip"
	"github.com/sardanioss/httpcloak/protocol"
)

// extractHost extracts the hostname from a URL string
func extractHost(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// parseURL parses and validates a URL
func parseURL(urlStr string) (*url.URL, error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("only HTTPS is supported")
	}
	return parsed, nil
}

// buildHTTPRequest builds an http.Request with preset headers
func buildHTTPRequest(ctx context.Context, req *Request, preset *fingerprint.Preset, host string) (*http.Request, error) {
	method := req.Method
	if method == "" {
		method = "GET"
	}

	// Read body into bytes if present (for Content-Length calculation)
	var bodyBytes []byte
	var bodyReader io.Reader
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		// POST/PUT/PATCH with empty body must send Content-Length: 0
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Normalize request (Content-Length: 0 for empty POST/PUT/PATCH, Content-Type detection, etc.)
	normalizeRequestWithBody(httpReq, bodyBytes)

	// Set preset headers first
	for key, value := range preset.Headers {
		httpReq.Header.Set(key, value)
	}

	// Set User-Agent
	httpReq.Header.Set("User-Agent", preset.UserAgent)

	// Set Host header
	httpReq.Header.Set("Host", host)

	// Override with custom headers (multi-value support)
	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	return httpReq, nil
}

// processResponse reads and processes an HTTP response
func processResponse(resp *http.Response, originalURL string, startTime time.Time, timing *protocol.Timing) (*Response, error) {
	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	body, err = Decompress(body, contentEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress response: %w", err)
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Build response headers map (multi-value support)
	headers := make(map[string][]string)
	for key, values := range resp.Header {
		lowerKey := strings.ToLower(key)
		headerValues := make([]string, len(values))
		copy(headerValues, values)
		headers[lowerKey] = headerValues
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   originalURL,
		Timing:     timing,
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

// Decompress decompresses response body based on Content-Encoding
func Decompress(data []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "gzip":
		return gunzip.Bytes(data)

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
		// Unknown encoding, return as-is
		return data, nil
	}
}

// normalizeRequest applies standard HTTP behaviors to a request
// This ensures the request conforms to HTTP standards that browsers follow
func normalizeRequest(req *http.Request, bodyLen int) {
	method := strings.ToUpper(req.Method)

	// If there's a body, always set Content-Length explicitly
	// Some servers require this header to be present
	if bodyLen > 0 {
		req.ContentLength = int64(bodyLen)
		req.Header.Set("Content-Length", fmt.Sprintf("%d", bodyLen))
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		// POST/PUT/PATCH with empty body must send Content-Length: 0
		// This is standard HTTP behavior
		req.ContentLength = 0
		req.Header.Set("Content-Length", "0")
	}

	// Ensure Host header is set (Go usually handles this, but be explicit)
	if req.Host == "" && req.URL != nil {
		req.Host = req.URL.Host
	}

	// For methods that typically don't have a body AND body is empty,
	// don't send Content-Length (matches browser behavior)
	if method == "GET" || method == "HEAD" || method == "OPTIONS" || method == "TRACE" {
		if bodyLen == 0 {
			req.Header.Del("Content-Length")
		}
	}
}

// normalizeRequestWithBody applies standard HTTP behaviors including Content-Type detection
// This should be called when we have access to the actual body bytes
func normalizeRequestWithBody(req *http.Request, body []byte) {
	normalizeRequest(req, len(body))

	// Auto-detect Content-Type if not set and body is present
	if len(body) > 0 && req.Header.Get("Content-Type") == "" {
		contentType := detectContentType(body)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
	}
}

// normalizeRequestWithReader applies standard HTTP behaviors for io.Reader body
// Content-Length is only set if the reader size can be determined
func normalizeRequestWithReader(req *http.Request, body io.Reader) {
	if body == nil {
		normalizeRequest(req, 0)
		return
	}

	// Try to get length from common reader types
	var bodyLen int64 = -1
	switch r := body.(type) {
	case *bytes.Reader:
		bodyLen = int64(r.Len())
	case *bytes.Buffer:
		bodyLen = int64(r.Len())
	case *strings.Reader:
		bodyLen = int64(r.Len())
	case io.Seeker:
		// Get current position and seek to end to get length
		if cur, err := r.Seek(0, io.SeekCurrent); err == nil {
			if end, err := r.Seek(0, io.SeekEnd); err == nil {
				bodyLen = end - cur
				r.Seek(cur, io.SeekStart) // Reset position
			}
		}
	}

	if bodyLen >= 0 {
		normalizeRequest(req, int(bodyLen))
	} else {
		// Unknown length - will use chunked transfer encoding
		normalizeRequest(req, 0)
	}
}

// detectContentType attempts to detect the content type from the body
// Returns empty string if unable to detect
func detectContentType(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	// Check for JSON (starts with { or [)
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 {
		first := trimmed[0]
		if first == '{' || first == '[' {
			// Validate it looks like JSON
			if isLikelyJSON(trimmed) {
				return "application/json"
			}
		}
	}

	// Check for XML (starts with < and contains ?>)
	if len(trimmed) > 0 && trimmed[0] == '<' {
		if bytes.HasPrefix(trimmed, []byte("<?xml")) ||
			bytes.HasPrefix(trimmed, []byte("<soap")) ||
			bytes.HasPrefix(trimmed, []byte("<SOAP")) {
			return "application/xml"
		}
		// Could be HTML or other XML
		if bytes.Contains(trimmed[:min(100, len(trimmed))], []byte("html")) {
			return "text/html"
		}
	}

	// Check for form data (key=value&key2=value2)
	if isFormEncoded(trimmed) {
		return "application/x-www-form-urlencoded"
	}

	// Default: don't set, let the user specify
	return ""
}

// isLikelyJSON checks if the body looks like valid JSON structure
func isLikelyJSON(body []byte) bool {
	if len(body) < 2 {
		return false
	}
	first := body[0]
	last := body[len(body)-1]

	// Check for matching brackets
	if first == '{' && last == '}' {
		return true
	}
	if first == '[' && last == ']' {
		return true
	}
	return false
}

// isFormEncoded checks if body looks like URL-encoded form data
func isFormEncoded(body []byte) bool {
	if len(body) == 0 {
		return false
	}

	// Form data typically has key=value pairs with & separators
	// and doesn't contain newlines or special characters outside of encoding
	hasEquals := bytes.Contains(body, []byte("="))
	hasNewline := bytes.Contains(body, []byte("\n"))
	hasSpace := bytes.Contains(body, []byte(" "))

	// Simple heuristic: has = sign, no raw newlines or spaces
	return hasEquals && !hasNewline && !hasSpace
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// hasBody returns true if the HTTP method typically has a request body
func hasBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// resetRequestBody resets the request body for retry attempts
// This handles both non-empty bodies and empty POST/PUT/PATCH bodies
func resetRequestBody(httpReq *http.Request, body []byte) {
	if len(body) > 0 {
		httpReq.Body = io.NopCloser(bytes.NewReader(body))
	} else if hasBody(httpReq.Method) {
		// POST/PUT/PATCH with empty body - still need a valid (empty) reader
		httpReq.Body = io.NopCloser(bytes.NewReader([]byte{}))
	}
}
