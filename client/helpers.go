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
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

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
