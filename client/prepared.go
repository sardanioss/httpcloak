package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	http "github.com/sardanioss/http"
	"net/url"
)

// PreparedRequest is a request that has been prepared for sending
// It allows inspection and modification before actual execution
type PreparedRequest struct {
	// The underlying http.Request
	HTTPRequest *http.Request

	// Original request data (for reference)
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte

	// Configuration
	Timeout       int64    // Timeout in milliseconds
	ForceProtocol Protocol // Forced protocol
	FetchMode     FetchMode
	FetchSite     FetchSite
	Referer       string
	Auth          Auth

	// Redirect settings
	FollowRedirects bool
	MaxRedirects    int

	// The client that will execute this request
	client *Client

	// Whether the request has been prepared
	prepared bool
}

// Prepare creates a PreparedRequest from a Request
// The PreparedRequest can be inspected, modified, and then sent
func (c *Client) Prepare(ctx context.Context, req *Request) (*PreparedRequest, error) {
	// Build URL with params
	reqURL := req.URL
	if len(req.Params) > 0 {
		reqURL = NewURLBuilder(req.URL).Params(req.Params).Build()
	}

	// Parse URL
	parsedURL, err := url.Parse(reqURL)
	if err != nil {
		return nil, err
	}

	// Build method
	method := req.Method
	if method == "" {
		method = "GET"
	}

	// Build body reader
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		// POST/PUT/PATCH with empty body must send Content-Length: 0
		bodyReader = bytes.NewReader([]byte{})
	}

	// Create http.Request
	httpReq, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, err
	}

	// Normalize request (Content-Length: 0 for empty POST/PUT/PATCH, Content-Type detection, etc.)
	normalizeRequestWithBody(httpReq, req.Body)

	// Apply preset headers
	for key, value := range c.preset.Headers {
		httpReq.Header.Set(key, value)
	}

	// Apply User-Agent
	userAgent := c.preset.UserAgent
	if req.UserAgent != "" {
		userAgent = req.UserAgent
	}
	httpReq.Header.Set("User-Agent", userAgent)

	// Apply custom headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Apply Sec-Fetch headers based on mode
	applyModeHeaders(httpReq, c.preset, req, parsedURL)

	// Apply cookies if enabled
	if c.cookies != nil {
		cookieHeader := c.cookies.CookieHeader(parsedURL)
		if cookieHeader != "" {
			httpReq.Header.Set("Cookie", cookieHeader)
		}
	}

	// Determine redirect settings
	followRedirects := c.config.FollowRedirects
	if req.FollowRedirects != nil {
		followRedirects = *req.FollowRedirects
	}
	maxRedirects := c.config.MaxRedirects
	if req.MaxRedirects > 0 {
		maxRedirects = req.MaxRedirects
	}

	return &PreparedRequest{
		HTTPRequest:     httpReq,
		Method:          method,
		URL:             reqURL,
		Headers:         req.Headers,
		Body:            req.Body,
		Timeout:         int64(req.Timeout.Milliseconds()),
		ForceProtocol:   req.ForceProtocol,
		FetchMode:       req.FetchMode,
		FetchSite:       req.FetchSite,
		Referer:         req.Referer,
		Auth:            req.Auth,
		FollowRedirects: followRedirects,
		MaxRedirects:    maxRedirects,
		client:          c,
		prepared:        true,
	}, nil
}

// SetHeader sets a header on the prepared request
func (p *PreparedRequest) SetHeader(key, value string) *PreparedRequest {
	p.HTTPRequest.Header.Set(key, value)
	return p
}

// AddHeader adds a header to the prepared request (allows multiple values)
func (p *PreparedRequest) AddHeader(key, value string) *PreparedRequest {
	p.HTTPRequest.Header.Add(key, value)
	return p
}

// DelHeader removes a header from the prepared request
func (p *PreparedRequest) DelHeader(key string) *PreparedRequest {
	p.HTTPRequest.Header.Del(key)
	return p
}

// GetHeader gets a header value from the prepared request
func (p *PreparedRequest) GetHeader(key string) string {
	return p.HTTPRequest.Header.Get(key)
}

// GetAllHeaders returns all headers
func (p *PreparedRequest) GetAllHeaders() http.Header {
	return p.HTTPRequest.Header
}

// SetBody sets a new body on the prepared request
func (p *PreparedRequest) SetBody(body []byte) *PreparedRequest {
	p.Body = body
	p.HTTPRequest.Body = io.NopCloser(bytes.NewReader(body))
	p.HTTPRequest.ContentLength = int64(len(body))
	p.HTTPRequest.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return p
}

// SetAuth sets authentication on the prepared request
func (p *PreparedRequest) SetAuth(auth Auth) *PreparedRequest {
	p.Auth = auth
	return p
}

// SetTimeout sets the timeout in milliseconds
func (p *PreparedRequest) SetTimeout(ms int64) *PreparedRequest {
	p.Timeout = ms
	return p
}

// SetForceProtocol sets the forced protocol
func (p *PreparedRequest) SetForceProtocol(protocol Protocol) *PreparedRequest {
	p.ForceProtocol = protocol
	return p
}

// Send executes the prepared request
func (p *PreparedRequest) Send(ctx context.Context) (*Response, error) {
	if !p.prepared {
		return nil, &RequestError{Op: "send", Err: "request not prepared"}
	}

	// Apply authentication if set
	auth := p.Auth
	if auth == nil {
		auth = p.client.auth
	}
	if auth != nil {
		if err := auth.Apply(p.HTTPRequest); err != nil {
			return nil, err
		}
	}

	// Rebuild the Request struct for doOnce
	req := &Request{
		Method:          p.Method,
		URL:             p.URL,
		Headers:         p.Headers,
		Body:            p.Body,
		Timeout:         time.Duration(p.Timeout) * time.Millisecond, // Convert ms back to Duration
		ForceProtocol:   p.ForceProtocol,
		FetchMode:       p.FetchMode,
		FetchSite:       p.FetchSite,
		Referer:         p.Referer,
		Auth:            p.Auth,
		FollowRedirects: &p.FollowRedirects,
		MaxRedirects:    p.MaxRedirects,
	}

	// Execute using the client
	return p.client.Do(ctx, req)
}

// RequestError represents a request-level error
type RequestError struct {
	Op  string
	Err string
}

func (e *RequestError) Error() string {
	return e.Op + ": " + e.Err
}

// PrepareGet creates a prepared GET request
func (c *Client) PrepareGet(ctx context.Context, url string, headers map[string]string) (*PreparedRequest, error) {
	return c.Prepare(ctx, &Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// PreparePost creates a prepared POST request
func (c *Client) PreparePost(ctx context.Context, url string, body []byte, headers map[string]string) (*PreparedRequest, error) {
	return c.Prepare(ctx, &Request{
		Method:  "POST",
		URL:     url,
		Body:    body,
		Headers: headers,
	})
}
