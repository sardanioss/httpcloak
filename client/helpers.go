package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/sardanioss/httpcloak/fingerprint"
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

	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		// POST/PUT/PATCH with empty body must send Content-Length: 0
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Normalize request (Content-Length: 0 for empty POST/PUT/PATCH, Content-Type detection, etc.)
	normalizeRequestWithBody(httpReq, req.Body)

	// Set preset headers first
	for key, value := range preset.Headers {
		httpReq.Header.Set(key, value)
	}

	// Set User-Agent
	httpReq.Header.Set("User-Agent", preset.UserAgent)

	// Set Host header
	httpReq.Header.Set("Host", host)

	// Override with custom headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
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

	// Build response headers map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[strings.ToLower(key)] = strings.Join(values, ", ")
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
		FinalURL:   originalURL,
		Timing:     timing,
	}, nil
}

// Decompress decompresses response body based on Content-Encoding
func Decompress(data []byte, encoding string) ([]byte, error) {
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
		// For deflate, just return as-is for now
		return data, nil

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

	// Set Content-Length: 0 for methods that typically have a body but body is empty
	// This is standard behavior for POST, PUT, PATCH with no body
	if (method == "POST" || method == "PUT" || method == "PATCH") && bodyLen == 0 {
		req.ContentLength = 0
		req.Header.Set("Content-Length", "0")
	}

	// Ensure Host header is set (Go usually handles this, but be explicit)
	if req.Host == "" && req.URL != nil {
		req.Host = req.URL.Host
	}

	// For methods that shouldn't have a body, ensure we don't send Content-Length
	// GET, HEAD, DELETE, OPTIONS, TRACE typically don't have bodies
	// (though HTTP/1.1 allows it, browsers don't send Content-Length for these)
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
