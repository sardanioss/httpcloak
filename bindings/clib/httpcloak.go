package main

/*
#include <stdlib.h>
#include <stdint.h>

typedef void (*async_callback)(int64_t callback_id, const char* response_json, const char* error);

// Helper function to invoke callback from Go
static void invoke_callback(async_callback cb, int64_t callback_id, const char* response_json, const char* error) {
    if (cb != NULL) {
        cb(callback_id, response_json, error);
    }
}
*/
import "C"
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/sardanioss/httpcloak"
)

func init() {
	// Initialize library
}

// logDebug writes debug messages to a file
func logDebug(format string, args ...interface{}) {
	msg := fmt.Sprintf("[DEBUG] "+format+"\n", args...)
	f, err := os.OpenFile("/tmp/httpcloak_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	f.WriteString(msg)
	f.Close()
}

// decodeRequestBody decodes the request body based on encoding type
func decodeRequestBody(body, encoding string) ([]byte, error) {
	if body == "" {
		return nil, nil
	}
	if encoding == "base64" {
		return base64.StdEncoding.DecodeString(body)
	}
	return []byte(body), nil
}

// Session handle management
var (
	sessionMu      sync.RWMutex
	sessions       = make(map[int64]*httpcloak.Session)
	sessionCounter int64
)

// Stream handle management for streaming responses
var (
	streamMu      sync.RWMutex
	streams       = make(map[int64]*httpcloak.StreamResponse)
	streamCounter int64
)

// Upload stream handle management for streaming uploads
var (
	uploadMu      sync.RWMutex
	uploads       = make(map[int64]*UploadStream)
	uploadCounter int64
)

// UploadStream represents an in-progress streaming upload
type UploadStream struct {
	session    *httpcloak.Session
	pipeWriter *io.PipeWriter
	pipeReader *io.PipeReader
	url        string
	method     string
	headers    map[string]string
	timeout    int
	responseCh chan *uploadResult
	started    bool
	finished   bool
	mu         sync.Mutex
}

type uploadResult struct {
	response *httpcloak.Response
	err      error
}

// Async callback management
var (
	callbackMu      sync.Mutex
	callbackCounter int64
	asyncCallbacks  = make(map[int64]C.async_callback)
)

// Request configuration for JSON parsing
type RequestConfig struct {
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         string            `json:"body,omitempty"`
	BodyEncoding string            `json:"body_encoding,omitempty"` // "text" (default) or "base64"
	Timeout      int               `json:"timeout,omitempty"`       // seconds
}

// Cookie represents a parsed cookie from Set-Cookie header
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RedirectInfo contains information about a redirect response
type RedirectInfo struct {
	StatusCode int                 `json:"status_code"`
	URL        string              `json:"url"`
	Headers    map[string][]string `json:"headers"`
}

// Response for JSON serialization (legacy - includes body as string)
type ResponseData struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
	FinalURL   string              `json:"final_url"`
	Protocol   string              `json:"protocol"`
	Cookies    []Cookie            `json:"cookies"`
	History    []RedirectInfo      `json:"history"`
}

// ResponseMetadata for optimized responses - body is passed separately as raw bytes
type ResponseMetadata struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	BodyLen    int                 `json:"body_len"`
	FinalURL   string              `json:"final_url"`
	Protocol   string              `json:"protocol"`
	Cookies    []Cookie            `json:"cookies"`
	History    []RedirectInfo      `json:"history"`
}

// RawResponse holds response data with body as raw bytes (not JSON encoded)
type RawResponse struct {
	metadata []byte // JSON encoded metadata
	body     []byte // Raw body bytes
}

var (
	rawResponses   = make(map[int64]*RawResponse)
	rawResponsesMu sync.RWMutex
	rawResponseID  int64
)

// Session configuration
type SessionConfig struct {
	Preset          string            `json:"preset"`
	Proxy           string            `json:"proxy,omitempty"`
	TCPProxy        string            `json:"tcp_proxy,omitempty"`         // Proxy for TCP (HTTP/1.1, HTTP/2)
	UDPProxy        string            `json:"udp_proxy,omitempty"`         // Proxy for UDP (HTTP/3 via MASQUE)
	Timeout         int               `json:"timeout,omitempty"`           // seconds
	HTTPVersion     string            `json:"http_version,omitempty"`      // "auto", "h1", "h2", "h3"
	Verify          *bool             `json:"verify,omitempty"`            // SSL verification (default: true)
	AllowRedirects  *bool             `json:"allow_redirects,omitempty"`   // Follow redirects (default: true)
	MaxRedirects    int               `json:"max_redirects,omitempty"`     // Max redirects (default: 10)
	Retry           int               `json:"retry,omitempty"`             // Retry count (default: 0)
	RetryWaitMin    int               `json:"retry_wait_min,omitempty"`    // Min wait between retries in ms
	RetryWaitMax    int               `json:"retry_wait_max,omitempty"`    // Max wait between retries in ms
	RetryOnStatus   []int             `json:"retry_on_status,omitempty"`   // Status codes to retry on
	PreferIPv4      bool              `json:"prefer_ipv4,omitempty"`       // Prefer IPv4 over IPv6
	ConnectTo       map[string]string `json:"connect_to,omitempty"`        // Domain fronting: request_host -> connect_host
	ECHConfigDomain string            `json:"ech_config_domain,omitempty"` // Domain to fetch ECH config from
}

// Error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

func makeErrorJSON(err error) *C.char {
	resp := ErrorResponse{Error: err.Error()}
	data, _ := json.Marshal(resp)
	return C.CString(string(data))
}

// parseSetCookieHeaders parses Set-Cookie headers into Cookie structs
func parseSetCookieHeaders(headers map[string][]string) []Cookie {
	var cookies []Cookie

	// Try both cases for Set-Cookie header
	setCookieHeaders, exists := headers["set-cookie"]
	if !exists {
		setCookieHeaders, exists = headers["Set-Cookie"]
	}
	if !exists || len(setCookieHeaders) == 0 {
		return cookies
	}

	// Each value in the slice is a separate Set-Cookie header
	for _, line := range setCookieHeaders {
		line = trim(line)
		if line == "" {
			continue
		}

		// Get name=value before any semicolon (attributes like path, expires, etc.)
		semicolonIdx := indexOf(line, ";")
		if semicolonIdx != -1 {
			line = line[:semicolonIdx]
		}

		eqIdx := indexOf(line, "=")
		if eqIdx != -1 {
			name := trim(line[:eqIdx])
			value := trim(line[eqIdx+1:])
			if name != "" {
				cookies = append(cookies, Cookie{Name: name, Value: value})
			}
		}
	}

	return cookies
}

// Helper functions for cookie parsing
func splitByNewline(s string) []string {
	var result []string
	var current string
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			result = append(result, current)
			current = ""
		} else if s[i] != '\r' {
			current += string(s[i])
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func trim(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// convertHeaders converts map[string]string to map[string][]string for the new API
func convertHeaders(headers map[string]string) map[string][]string {
	if headers == nil {
		return nil
	}
	result := make(map[string][]string, len(headers))
	for k, v := range headers {
		result[k] = []string{v}
	}
	return result
}

func makeResponseJSON(resp *httpcloak.Response) *C.char {
	// Read body from io.ReadCloser
	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	// Parse cookies from Set-Cookie header
	cookies := parseSetCookieHeaders(resp.Headers)

	// Convert redirect history
	var history []RedirectInfo
	if len(resp.History) > 0 {
		history = make([]RedirectInfo, len(resp.History))
		for i, h := range resp.History {
			history[i] = RedirectInfo{
				StatusCode: h.StatusCode,
				URL:        h.URL,
				Headers:    h.Headers,
			}
		}
	}

	data := ResponseData{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       string(bodyBytes),
		FinalURL:   resp.FinalURL,
		Protocol:   resp.Protocol,
		Cookies:    cookies,
		History:    history,
	}
	jsonData, _ := json.Marshal(data)
	return C.CString(string(jsonData))
}

// makeRawResponse creates an optimized response with body as raw bytes
func makeRawResponse(resp *httpcloak.Response) int64 {
	// Read body from io.ReadCloser
	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	// Parse cookies from Set-Cookie header
	cookies := parseSetCookieHeaders(resp.Headers)

	// Convert redirect history
	var history []RedirectInfo
	if len(resp.History) > 0 {
		history = make([]RedirectInfo, len(resp.History))
		for i, h := range resp.History {
			history[i] = RedirectInfo{
				StatusCode: h.StatusCode,
				URL:        h.URL,
				Headers:    h.Headers,
			}
		}
	}

	// Create metadata (without body)
	meta := ResponseMetadata{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		BodyLen:    len(bodyBytes),
		FinalURL:   resp.FinalURL,
		Protocol:   resp.Protocol,
		Cookies:    cookies,
		History:    history,
	}
	metaJSON, _ := json.Marshal(meta)

	// Store the raw response
	rawResponsesMu.Lock()
	rawResponseID++
	id := rawResponseID
	rawResponses[id] = &RawResponse{
		metadata: metaJSON,
		body:     bodyBytes,
	}
	rawResponsesMu.Unlock()

	return id
}

//export httpcloak_response_get_metadata
func httpcloak_response_get_metadata(handle C.int64_t) *C.char {
	rawResponsesMu.RLock()
	resp, exists := rawResponses[int64(handle)]
	rawResponsesMu.RUnlock()

	if !exists || resp == nil {
		return makeErrorJSON(errors.New("invalid response handle"))
	}

	return C.CString(string(resp.metadata))
}

//export httpcloak_response_get_body
func httpcloak_response_get_body(handle C.int64_t, outLen *C.int) unsafe.Pointer {
	rawResponsesMu.RLock()
	resp, exists := rawResponses[int64(handle)]
	rawResponsesMu.RUnlock()

	if !exists || resp == nil || len(resp.body) == 0 {
		*outLen = 0
		return nil
	}

	*outLen = C.int(len(resp.body))
	return C.CBytes(resp.body)
}

// httpcloak_response_get_body_ptr returns a DIRECT pointer to the body data (zero-copy)
// WARNING: The pointer is only valid until httpcloak_response_free is called!
// The caller must NOT free this pointer - it's managed by Go.
//
//export httpcloak_response_get_body_ptr
func httpcloak_response_get_body_ptr(handle C.int64_t, outLen *C.int) unsafe.Pointer {
	rawResponsesMu.RLock()
	resp, exists := rawResponses[int64(handle)]
	rawResponsesMu.RUnlock()

	if !exists || resp == nil || len(resp.body) == 0 {
		*outLen = 0
		return nil
	}

	*outLen = C.int(len(resp.body))
	// Return direct pointer to Go memory - caller must not free!
	return unsafe.Pointer(&resp.body[0])
}

//export httpcloak_response_get_body_len
func httpcloak_response_get_body_len(handle C.int64_t) C.int {
	rawResponsesMu.RLock()
	resp, exists := rawResponses[int64(handle)]
	rawResponsesMu.RUnlock()

	if !exists || resp == nil {
		return 0
	}
	return C.int(len(resp.body))
}

//export httpcloak_response_copy_body_to
func httpcloak_response_copy_body_to(handle C.int64_t, dest unsafe.Pointer, destLen C.int) C.int {
	rawResponsesMu.RLock()
	resp, exists := rawResponses[int64(handle)]
	rawResponsesMu.RUnlock()

	if !exists || resp == nil || len(resp.body) == 0 {
		return 0
	}

	// Copy directly to the destination buffer (Python-allocated)
	copyLen := len(resp.body)
	if int(destLen) < copyLen {
		copyLen = int(destLen)
	}

	// Use C.GoBytes in reverse - copy Go bytes to C memory
	destSlice := (*[1 << 30]byte)(dest)[:copyLen:copyLen]
	copy(destSlice, resp.body[:copyLen])

	return C.int(copyLen)
}

//export httpcloak_response_free
func httpcloak_response_free(handle C.int64_t) {
	rawResponsesMu.Lock()
	if _, exists := rawResponses[int64(handle)]; exists {
		delete(rawResponses, int64(handle))
	}
	rawResponsesMu.Unlock()
}

// httpcloak_response_finalize copies body to buffer, returns metadata with body_len, and frees response
// This combines get_metadata + get_body_len + copy_body_to + response_free into one FFI call
//
//export httpcloak_response_finalize
func httpcloak_response_finalize(handle C.int64_t, dest unsafe.Pointer, destLen C.int) *C.char {
	rawResponsesMu.Lock()
	resp, exists := rawResponses[int64(handle)]
	if !exists || resp == nil {
		rawResponsesMu.Unlock()
		return C.CString(`{"error":"invalid response handle"}`)
	}

	// Copy body to destination buffer
	copyLen := len(resp.body)
	if int(destLen) < copyLen {
		copyLen = int(destLen)
	}
	if copyLen > 0 && dest != nil {
		destSlice := (*[1 << 30]byte)(dest)[:copyLen:copyLen]
		copy(destSlice, resp.body[:copyLen])
	}

	// Get metadata (already includes body_len)
	metadata := resp.metadata

	// Clean up
	delete(rawResponses, int64(handle))
	rawResponsesMu.Unlock()

	return C.CString(string(metadata))
}

//export httpcloak_get_raw
func httpcloak_get_raw(handle C.int64_t, url *C.char, optionsJSON *C.char) C.int64_t {
	session := getSession(handle)
	if session == nil {
		return -1
	}

	urlStr := C.GoString(url)

	var options RequestOptions
	if optionsJSON != nil {
		jsonStr := C.GoString(optionsJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &options)
		}
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(options.Timeout)*time.Millisecond)
	} else {
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	}
	defer cancel()

	req := &httpcloak.Request{
		Method:  "GET",
		URL:     urlStr,
		Headers: convertHeaders(options.Headers),
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		return -1
	}

	return C.int64_t(makeRawResponse(resp))
}

//export httpcloak_post_raw
func httpcloak_post_raw(handle C.int64_t, url *C.char, body *C.char, bodyLen C.int, optionsJSON *C.char) C.int64_t {
	session := getSession(handle)
	if session == nil {
		return -1
	}

	urlStr := C.GoString(url)
	var bodyBytes []byte
	if body != nil && bodyLen > 0 {
		bodyBytes = C.GoBytes(unsafe.Pointer(body), bodyLen)
	}

	var options RequestOptions
	if optionsJSON != nil {
		jsonStr := C.GoString(optionsJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &options)
		}
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(options.Timeout)*time.Millisecond)
	} else {
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	}
	defer cancel()

	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req := &httpcloak.Request{
		Method:  "POST",
		URL:     urlStr,
		Headers: convertHeaders(options.Headers),
		Body:    bodyReader,
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		return -1
	}

	return C.int64_t(makeRawResponse(resp))
}

//export httpcloak_request_raw
func httpcloak_request_raw(handle C.int64_t, requestJSON *C.char, body *C.char, bodyLen C.int) C.int64_t {
	session := getSession(handle)
	if session == nil {
		return -1
	}

	var config RequestConfig
	if requestJSON != nil {
		jsonStr := C.GoString(requestJSON)
		json.Unmarshal([]byte(jsonStr), &config)
	}

	var bodyBytes []byte
	if body != nil && bodyLen > 0 {
		bodyBytes = C.GoBytes(unsafe.Pointer(body), bodyLen)
	} else if config.Body != "" {
		var err error
		bodyBytes, err = decodeRequestBody(config.Body, config.BodyEncoding)
		if err != nil {
			return -1 // Invalid base64
		}
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if config.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Millisecond)
	} else {
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	}
	defer cancel()

	method := config.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req := &httpcloak.Request{
		Method:  method,
		URL:     config.URL,
		Headers: convertHeaders(config.Headers),
		Body:    bodyReader,
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		return -1
	}

	return C.int64_t(makeRawResponse(resp))
}

// ============================================================================
// Session Management
// ============================================================================

//export httpcloak_session_new
func httpcloak_session_new(configJSON *C.char) C.int64_t {
	config := SessionConfig{
		Preset:      "chrome-143",
		Timeout:     30,
		HTTPVersion: "auto",
	}

	if configJSON != nil {
		jsonStr := C.GoString(configJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &config)
		}
	}

	var opts []httpcloak.SessionOption
	if config.Proxy != "" {
		opts = append(opts, httpcloak.WithSessionProxy(config.Proxy))
	}
	if config.TCPProxy != "" {
		opts = append(opts, httpcloak.WithSessionTCPProxy(config.TCPProxy))
	}
	if config.UDPProxy != "" {
		opts = append(opts, httpcloak.WithSessionUDPProxy(config.UDPProxy))
	}
	if config.Timeout > 0 {
		opts = append(opts, httpcloak.WithSessionTimeout(time.Duration(config.Timeout)*time.Second))
	}

	// Handle HTTP version preference
	switch config.HTTPVersion {
	case "h1", "http1", "1", "1.1":
		opts = append(opts, httpcloak.WithForceHTTP1())
	case "h2", "http2", "2":
		opts = append(opts, httpcloak.WithForceHTTP2())
	case "h3", "http3", "3":
		logDebug("clib Adding WithForceHTTP3")
		opts = append(opts, httpcloak.WithForceHTTP3())
	// "auto" or empty = default behavior
	}

	// Handle SSL verification
	if config.Verify != nil && !*config.Verify {
		opts = append(opts, httpcloak.WithInsecureSkipVerify())
	}

	// Handle redirects
	if config.AllowRedirects != nil && !*config.AllowRedirects {
		opts = append(opts, httpcloak.WithoutRedirects())
	} else {
		// Always set redirects explicitly - default maxRedirects=0 would block all redirects
		maxRedirects := config.MaxRedirects
		if maxRedirects <= 0 {
			maxRedirects = 10 // default
		}
		opts = append(opts, httpcloak.WithRedirects(true, maxRedirects))
	}

	// Handle IPv4 preference
	if config.PreferIPv4 {
		opts = append(opts, httpcloak.WithSessionPreferIPv4())
	}

	// Handle retry configuration
	// Note: We need to explicitly handle retry=0 to disable retry,
	// since Go's NewSession enables retry by default
	if config.Retry > 0 {
		if config.RetryWaitMin > 0 || config.RetryWaitMax > 0 || len(config.RetryOnStatus) > 0 {
			waitMin := time.Duration(config.RetryWaitMin) * time.Millisecond
			waitMax := time.Duration(config.RetryWaitMax) * time.Millisecond
			if waitMin == 0 {
				waitMin = 500 * time.Millisecond
			}
			if waitMax == 0 {
				waitMax = 10 * time.Second
			}
			opts = append(opts, httpcloak.WithRetryConfig(config.Retry, waitMin, waitMax, config.RetryOnStatus))
		} else {
			opts = append(opts, httpcloak.WithRetry(config.Retry))
		}
	} else if config.Retry == 0 {
		// Explicitly disable retry when retry=0 is passed
		opts = append(opts, httpcloak.WithoutRetry())
	}

	// Handle ConnectTo (domain fronting)
	for requestHost, connectHost := range config.ConnectTo {
		opts = append(opts, httpcloak.WithConnectTo(requestHost, connectHost))
	}

	// Handle ECH config domain
	if config.ECHConfigDomain != "" {
		opts = append(opts, httpcloak.WithECHFrom(config.ECHConfigDomain))
	}

	session := httpcloak.NewSession(config.Preset, opts...)

	sessionMu.Lock()
	sessionCounter++
	handle := sessionCounter
	sessions[handle] = session
	sessionMu.Unlock()

	return C.int64_t(handle)
}

//export httpcloak_session_free
func httpcloak_session_free(handle C.int64_t) {
	sessionMu.Lock()
	session, exists := sessions[int64(handle)]
	if exists {
		delete(sessions, int64(handle))
	}
	sessionMu.Unlock()

	if session != nil {
		session.Close()
	}
}

func getSession(handle C.int64_t) *httpcloak.Session {
	sessionMu.RLock()
	defer sessionMu.RUnlock()
	return sessions[int64(handle)]
}

// ============================================================================
// Synchronous Requests
// ============================================================================

// RequestOptions for httpcloak_get/post JSON parsing
type RequestOptions struct {
	Headers map[string]string `json:"headers,omitempty"`
	Timeout int               `json:"timeout,omitempty"` // milliseconds
}

//export httpcloak_get
func httpcloak_get(handle C.int64_t, url *C.char, optionsJSON *C.char) *C.char {
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	urlStr := C.GoString(url)

	// Parse options (headers + timeout) if provided
	var options RequestOptions
	if optionsJSON != nil {
		jsonStr := C.GoString(optionsJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &options)
		}
	}

	// Create context with timeout if specified, otherwise use default 30s
	ctx := context.Background()
	var cancel context.CancelFunc
	if options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(options.Timeout)*time.Millisecond)
	} else {
		// Default 30s timeout to prevent indefinite hangs (especially for MASQUE)
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	}
	defer cancel()

	req := &httpcloak.Request{
		Method:  "GET",
		URL:     urlStr,
		Headers: convertHeaders(options.Headers),
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		return makeErrorJSON(err)
	}

	return makeResponseJSON(resp)
}

//export httpcloak_post
func httpcloak_post(handle C.int64_t, url *C.char, body *C.char, optionsJSON *C.char) *C.char {
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	urlStr := C.GoString(url)
	bodyStr := ""
	if body != nil {
		bodyStr = C.GoString(body)
	}

	// Parse options (headers + timeout) if provided
	var options RequestOptions
	if optionsJSON != nil {
		jsonStr := C.GoString(optionsJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &options)
		}
	}

	// Create context with timeout if specified, otherwise use default 30s
	ctx := context.Background()
	var cancel context.CancelFunc
	if options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(options.Timeout)*time.Millisecond)
	} else {
		// Default 30s timeout to prevent indefinite hangs (especially for MASQUE)
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	}
	defer cancel()

	var bodyReader io.Reader
	if bodyStr != "" {
		bodyReader = bytes.NewReader([]byte(bodyStr))
	}

	req := &httpcloak.Request{
		Method:  "POST",
		URL:     urlStr,
		Headers: convertHeaders(options.Headers),
		Body:    bodyReader,
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		return makeErrorJSON(err)
	}

	return makeResponseJSON(resp)
}

//export httpcloak_request
func httpcloak_request(handle C.int64_t, requestJSON *C.char) *C.char {
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	var config RequestConfig
	if requestJSON != nil {
		jsonStr := C.GoString(requestJSON)
		if err := json.Unmarshal([]byte(jsonStr), &config); err != nil {
			return makeErrorJSON(err)
		}
	}

	if config.Method == "" {
		config.Method = "GET"
	}

	// Create context with timeout if specified, otherwise use default 30s
	ctx := context.Background()
	var cancel context.CancelFunc
	if config.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	} else {
		// Default 30s timeout to prevent indefinite hangs (especially for MASQUE)
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	}
	defer cancel()

	var bodyReader io.Reader
	if config.Body != "" {
		bodyBytes, err := decodeRequestBody(config.Body, config.BodyEncoding)
		if err != nil {
			return makeErrorJSON(err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req := &httpcloak.Request{
		Method:  config.Method,
		URL:     config.URL,
		Headers: convertHeaders(config.Headers),
		Body:    bodyReader,
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		return makeErrorJSON(err)
	}

	return makeResponseJSON(resp)
}

// ============================================================================
// Asynchronous Requests
// ============================================================================

//export httpcloak_register_callback
func httpcloak_register_callback(callback C.async_callback) C.int64_t {
	callbackMu.Lock()
	callbackCounter++
	id := callbackCounter
	asyncCallbacks[id] = callback
	callbackMu.Unlock()
	return C.int64_t(id)
}

//export httpcloak_unregister_callback
func httpcloak_unregister_callback(callbackID C.int64_t) {
	callbackMu.Lock()
	delete(asyncCallbacks, int64(callbackID))
	callbackMu.Unlock()
}

func invokeCallback(callbackID int64, responseJSON string, errStr string) {
	callbackMu.Lock()
	callback, exists := asyncCallbacks[callbackID]
	// Auto-cleanup: remove callback after retrieval to prevent memory leaks
	if exists {
		delete(asyncCallbacks, callbackID)
	}
	callbackMu.Unlock()

	if !exists {
		return
	}

	var respC *C.char
	var errC *C.char

	if responseJSON != "" {
		respC = C.CString(responseJSON)
	}
	if errStr != "" {
		errC = C.CString(errStr)
	}

	C.invoke_callback(callback, C.int64_t(callbackID), respC, errC)

	if respC != nil {
		C.free(unsafe.Pointer(respC))
	}
	if errC != nil {
		C.free(unsafe.Pointer(errC))
	}
}

//export httpcloak_get_async
func httpcloak_get_async(handle C.int64_t, url *C.char, optionsJSON *C.char, callbackID C.int64_t) {
	session := getSession(handle)
	urlStr := C.GoString(url)

	// Parse options (headers + timeout) if provided - same format as sync version
	var options RequestOptions
	if optionsJSON != nil {
		jsonStr := C.GoString(optionsJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &options)
		}
	}

	go func() {
		if session == nil {
			invokeCallback(int64(callbackID), "", ErrInvalidSession.Error())
			return
		}

		ctx := context.Background()
		req := &httpcloak.Request{
			Method:  "GET",
			URL:     urlStr,
			Headers: convertHeaders(options.Headers),
		}

		resp, err := session.Do(ctx, req)
		if err != nil {
			errResp := ErrorResponse{Error: err.Error()}
			errJSON, _ := json.Marshal(errResp)
			invokeCallback(int64(callbackID), "", string(errJSON))
			return
		}

		// Read body from io.ReadCloser
		var bodyBytes []byte
		if resp.Body != nil {
			bodyBytes, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}

		// Parse cookies from Set-Cookie header
		cookies := parseSetCookieHeaders(resp.Headers)

		// Convert redirect history
		var history []RedirectInfo
		if len(resp.History) > 0 {
			history = make([]RedirectInfo, len(resp.History))
			for i, h := range resp.History {
				history[i] = RedirectInfo{
					StatusCode: h.StatusCode,
					URL:        h.URL,
					Headers:    h.Headers,
				}
			}
		}

		data := ResponseData{
			StatusCode: resp.StatusCode,
			Headers:    resp.Headers,
			Body:       string(bodyBytes),
			FinalURL:   resp.FinalURL,
			Protocol:   resp.Protocol,
			Cookies:    cookies,
			History:    history,
		}
		jsonData, _ := json.Marshal(data)
		invokeCallback(int64(callbackID), string(jsonData), "")
	}()
}

//export httpcloak_post_async
func httpcloak_post_async(handle C.int64_t, url *C.char, body *C.char, optionsJSON *C.char, callbackID C.int64_t) {
	session := getSession(handle)
	urlStr := C.GoString(url)
	bodyStr := ""
	if body != nil {
		bodyStr = C.GoString(body)
	}

	// Parse options (headers + timeout) if provided - same format as sync version
	var options RequestOptions
	if optionsJSON != nil {
		jsonStr := C.GoString(optionsJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &options)
		}
	}

	go func() {
		if session == nil {
			invokeCallback(int64(callbackID), "", ErrInvalidSession.Error())
			return
		}

		var bodyReader io.Reader
		if bodyStr != "" {
			bodyReader = bytes.NewReader([]byte(bodyStr))
		}

		ctx := context.Background()
		req := &httpcloak.Request{
			Method:  "POST",
			URL:     urlStr,
			Headers: convertHeaders(options.Headers),
			Body:    bodyReader,
		}

		resp, err := session.Do(ctx, req)
		if err != nil {
			errResp := ErrorResponse{Error: err.Error()}
			errJSON, _ := json.Marshal(errResp)
			invokeCallback(int64(callbackID), "", string(errJSON))
			return
		}

		// Read body from io.ReadCloser
		var bodyBytes []byte
		if resp.Body != nil {
			bodyBytes, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}

		// Parse cookies from Set-Cookie header
		cookies := parseSetCookieHeaders(resp.Headers)

		// Convert redirect history
		var history []RedirectInfo
		if len(resp.History) > 0 {
			history = make([]RedirectInfo, len(resp.History))
			for i, h := range resp.History {
				history[i] = RedirectInfo{
					StatusCode: h.StatusCode,
					URL:        h.URL,
					Headers:    h.Headers,
				}
			}
		}

		data := ResponseData{
			StatusCode: resp.StatusCode,
			Headers:    resp.Headers,
			Body:       string(bodyBytes),
			FinalURL:   resp.FinalURL,
			Protocol:   resp.Protocol,
			Cookies:    cookies,
			History:    history,
		}
		jsonData, _ := json.Marshal(data)
		invokeCallback(int64(callbackID), string(jsonData), "")
	}()
}

//export httpcloak_request_async
func httpcloak_request_async(handle C.int64_t, requestJSON *C.char, callbackID C.int64_t) {
	session := getSession(handle)

	var config RequestConfig
	if requestJSON != nil {
		jsonStr := C.GoString(requestJSON)
		json.Unmarshal([]byte(jsonStr), &config)
	}

	go func() {
		if session == nil {
			invokeCallback(int64(callbackID), "", ErrInvalidSession.Error())
			return
		}

		if config.Method == "" {
			config.Method = "GET"
		}

		ctx := context.Background()
		if config.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
			defer cancel()
		}

		var bodyReader io.Reader
		if config.Body != "" {
			bodyBytes, err := decodeRequestBody(config.Body, config.BodyEncoding)
			if err != nil {
				errResp := ErrorResponse{Error: err.Error()}
				errJSON, _ := json.Marshal(errResp)
				invokeCallback(int64(callbackID), "", string(errJSON))
				return
			}
			bodyReader = bytes.NewReader(bodyBytes)
		}

		req := &httpcloak.Request{
			Method:  config.Method,
			URL:     config.URL,
			Headers: convertHeaders(config.Headers),
			Body:    bodyReader,
		}

		resp, err := session.Do(ctx, req)
		if err != nil {
			errResp := ErrorResponse{Error: err.Error()}
			errJSON, _ := json.Marshal(errResp)
			invokeCallback(int64(callbackID), "", string(errJSON))
			return
		}

		// Read body from io.ReadCloser
		var bodyBytes []byte
		if resp.Body != nil {
			bodyBytes, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}

		// Parse cookies from Set-Cookie header
		cookies := parseSetCookieHeaders(resp.Headers)

		// Convert redirect history
		var history []RedirectInfo
		if len(resp.History) > 0 {
			history = make([]RedirectInfo, len(resp.History))
			for i, h := range resp.History {
				history[i] = RedirectInfo{
					StatusCode: h.StatusCode,
					URL:        h.URL,
					Headers:    h.Headers,
				}
			}
		}

		data := ResponseData{
			StatusCode: resp.StatusCode,
			Headers:    resp.Headers,
			Body:       string(bodyBytes),
			FinalURL:   resp.FinalURL,
			Protocol:   resp.Protocol,
			Cookies:    cookies,
			History:    history,
		}
		jsonData, _ := json.Marshal(data)
		invokeCallback(int64(callbackID), string(jsonData), "")
	}()
}

// ============================================================================
// Cookie Management
// ============================================================================

//export httpcloak_get_cookies
func httpcloak_get_cookies(handle C.int64_t) *C.char {
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	cookies := session.GetCookies()
	data, _ := json.Marshal(cookies)
	return C.CString(string(data))
}

//export httpcloak_set_cookie
func httpcloak_set_cookie(handle C.int64_t, name *C.char, value *C.char) {
	session := getSession(handle)
	if session == nil {
		return
	}

	session.SetCookie(C.GoString(name), C.GoString(value))
}

// ============================================================================
// Session Persistence
// ============================================================================

//export httpcloak_session_save
func httpcloak_session_save(handle C.int64_t, path *C.char) *C.char {
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	pathStr := C.GoString(path)
	if err := session.Save(pathStr); err != nil {
		return makeErrorJSON(err)
	}

	return C.CString(`{"success":true}`)
}

//export httpcloak_session_load
func httpcloak_session_load(path *C.char) C.int64_t {
	pathStr := C.GoString(path)
	session, err := httpcloak.LoadSession(pathStr)
	if err != nil {
		return -1
	}

	sessionMu.Lock()
	sessionCounter++
	handle := sessionCounter
	sessions[handle] = session
	sessionMu.Unlock()

	return C.int64_t(handle)
}

//export httpcloak_session_marshal
func httpcloak_session_marshal(handle C.int64_t) *C.char {
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	data, err := session.Marshal()
	if err != nil {
		return makeErrorJSON(err)
	}

	return C.CString(string(data))
}

//export httpcloak_session_unmarshal
func httpcloak_session_unmarshal(data *C.char) C.int64_t {
	dataStr := C.GoString(data)
	session, err := httpcloak.UnmarshalSession([]byte(dataStr))
	if err != nil {
		return -1
	}

	sessionMu.Lock()
	sessionCounter++
	handle := sessionCounter
	sessions[handle] = session
	sessionMu.Unlock()

	return C.int64_t(handle)
}

// ============================================================================
// Utility Functions
// ============================================================================

//export httpcloak_free_string
func httpcloak_free_string(str *C.char) {
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

//export httpcloak_version
func httpcloak_version() *C.char {
	return C.CString("1.5.5")
}

//export httpcloak_available_presets
func httpcloak_available_presets() *C.char {
	presets := []string{
		"chrome-143", "chrome-143-windows", "chrome-143-linux", "chrome-143-macos",
		"chrome-131", "chrome-131-windows", "chrome-131-linux", "chrome-131-macos",
		"firefox-133", "safari-18",
	}
	data, _ := json.Marshal(presets)
	return C.CString(string(data))
}

// ============================================================================
// Error Definitions
// ============================================================================

var (
	ErrInvalidSession = errors.New("invalid session handle")
	ErrInvalidStream  = errors.New("invalid stream handle")
)

// ============================================================================
// Streaming API
// ============================================================================

// StreamMetadata contains metadata about a streaming response
type StreamMetadata struct {
	StatusCode    int                 `json:"status_code"`
	Headers       map[string][]string `json:"headers"`
	FinalURL      string              `json:"final_url"`
	Protocol      string              `json:"protocol"`
	ContentLength int64               `json:"content_length"` // -1 if unknown
	Cookies       []Cookie            `json:"cookies"`
}

func getStream(handle int64) *httpcloak.StreamResponse {
	streamMu.RLock()
	defer streamMu.RUnlock()
	return streams[handle]
}

//export httpcloak_stream_get
func httpcloak_stream_get(sessionHandle C.int64_t, url *C.char, optionsJSON *C.char) C.int64_t {
	session := getSession(sessionHandle)
	if session == nil {
		return -1
	}

	urlStr := C.GoString(url)

	// Parse options if provided
	var options RequestOptions
	if optionsJSON != nil {
		jsonStr := C.GoString(optionsJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &options)
		}
	}

	// Create context with timeout for streaming (longer than regular requests)
	ctx := context.Background()
	var cancel context.CancelFunc
	if options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(options.Timeout)*time.Millisecond)
	} else {
		// Use 2-minute timeout for streaming (connection + data transfer)
		ctx, cancel = context.WithTimeout(ctx, 2*time.Minute)
	}
	// Note: We don't defer cancel() here - it will be called when stream is closed

	req := &httpcloak.Request{
		Method:  "GET",
		URL:     urlStr,
		Headers: convertHeaders(options.Headers),
	}

	resp, err := session.DoStream(ctx, req)
	if err != nil {
		cancel()
		return -1
	}

	// Store stream and return handle
	streamMu.Lock()
	streamCounter++
	handle := streamCounter
	streams[handle] = resp
	streamMu.Unlock()

	return C.int64_t(handle)
}

//export httpcloak_stream_post
func httpcloak_stream_post(sessionHandle C.int64_t, url *C.char, body *C.char, optionsJSON *C.char) C.int64_t {
	session := getSession(sessionHandle)
	if session == nil {
		return -1
	}

	urlStr := C.GoString(url)
	bodyStr := ""
	if body != nil {
		bodyStr = C.GoString(body)
	}

	// Parse options if provided
	var options RequestOptions
	if optionsJSON != nil {
		jsonStr := C.GoString(optionsJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &options)
		}
	}

	// Create context with timeout for streaming (longer than regular requests)
	ctx := context.Background()
	var cancel context.CancelFunc
	if options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(options.Timeout)*time.Millisecond)
	} else {
		ctx, cancel = context.WithTimeout(ctx, 2*time.Minute)
	}

	var bodyReader io.Reader
	if bodyStr != "" {
		bodyReader = bytes.NewReader([]byte(bodyStr))
	}

	req := &httpcloak.Request{
		Method:  "POST",
		URL:     urlStr,
		Headers: convertHeaders(options.Headers),
		Body:    bodyReader,
	}

	resp, err := session.DoStream(ctx, req)
	if err != nil {
		cancel()
		return -1
	}

	// Store stream and return handle
	streamMu.Lock()
	streamCounter++
	handle := streamCounter
	streams[handle] = resp
	streamMu.Unlock()

	return C.int64_t(handle)
}

//export httpcloak_stream_request
func httpcloak_stream_request(sessionHandle C.int64_t, requestJSON *C.char) C.int64_t {
	session := getSession(sessionHandle)
	if session == nil {
		return -1
	}

	var config RequestConfig
	if requestJSON != nil {
		jsonStr := C.GoString(requestJSON)
		if err := json.Unmarshal([]byte(jsonStr), &config); err != nil {
			return -1
		}
	}

	if config.Method == "" {
		config.Method = "GET"
	}

	// Create context with timeout for streaming (longer than regular requests)
	ctx := context.Background()
	var cancel context.CancelFunc
	if config.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	} else {
		ctx, cancel = context.WithTimeout(ctx, 2*time.Minute)
	}

	var bodyReader io.Reader
	if config.Body != "" {
		bodyBytes, err := decodeRequestBody(config.Body, config.BodyEncoding)
		if err != nil {
			cancel()
			return -1
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req := &httpcloak.Request{
		Method:  config.Method,
		URL:     config.URL,
		Headers: convertHeaders(config.Headers),
		Body:    bodyReader,
	}

	resp, err := session.DoStream(ctx, req)
	if err != nil {
		cancel()
		return -1
	}

	// Store stream and return handle
	streamMu.Lock()
	streamCounter++
	handle := streamCounter
	streams[handle] = resp
	streamMu.Unlock()

	return C.int64_t(handle)
}

//export httpcloak_stream_get_metadata
func httpcloak_stream_get_metadata(streamHandle C.int64_t) *C.char {
	stream := getStream(int64(streamHandle))
	if stream == nil {
		return makeErrorJSON(ErrInvalidStream)
	}

	cookies := parseSetCookieHeaders(stream.Headers)

	metadata := StreamMetadata{
		StatusCode:    stream.StatusCode,
		Headers:       stream.Headers,
		FinalURL:      stream.FinalURL,
		Protocol:      stream.Protocol,
		ContentLength: stream.ContentLength,
		Cookies:       cookies,
	}

	jsonData, _ := json.Marshal(metadata)
	return C.CString(string(jsonData))
}

//export httpcloak_stream_read
func httpcloak_stream_read(streamHandle C.int64_t, bufferSize C.int) *C.char {
	stream := getStream(int64(streamHandle))
	if stream == nil {
		return nil
	}

	size := int(bufferSize)
	if size <= 0 {
		size = 8192 // Default chunk size
	}

	chunk, err := stream.ReadChunk(size)

	// If we got data, return it (even if there's also an EOF)
	if len(chunk) > 0 {
		return C.CString(encodeBase64(chunk))
	}

	// No data - check for EOF or error
	if err != nil {
		if err.Error() == "EOF" {
			// Return empty string to indicate EOF
			return C.CString("")
		}
		return nil
	}

	// No data and no error - return empty (shouldn't happen normally)
	return C.CString("")
}

//export httpcloak_stream_read_raw
func httpcloak_stream_read_raw(streamHandle C.int64_t, buffer unsafe.Pointer, bufferSize C.int) C.int {
	stream := getStream(int64(streamHandle))
	if stream == nil {
		return -1
	}

	size := int(bufferSize)
	if size <= 0 {
		return 0
	}

	// Create a Go slice backed by the C buffer
	buf := (*[1 << 30]byte)(buffer)[:size:size]

	n, err := stream.Read(buf)
	if err != nil {
		if err.Error() == "EOF" {
			return 0 // EOF
		}
		return -1 // Error
	}

	return C.int(n)
}

//export httpcloak_stream_close
func httpcloak_stream_close(streamHandle C.int64_t) {
	streamMu.Lock()
	stream, exists := streams[int64(streamHandle)]
	if exists {
		delete(streams, int64(streamHandle))
	}
	streamMu.Unlock()

	if stream != nil {
		stream.Close()
	}
}

// ============================================================================
// Streaming Upload Functions
// ============================================================================

// UploadOptions for configuring streaming uploads
type UploadOptions struct {
	Method      string            `json:"method,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Timeout     int               `json:"timeout,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
}

//export httpcloak_upload_start
func httpcloak_upload_start(sessionHandle C.int64_t, url *C.char, optionsJSON *C.char) C.int64_t {
	session := getSession(sessionHandle)
	if session == nil {
		return -1
	}

	urlStr := C.GoString(url)

	// Parse options
	var options UploadOptions
	options.Method = "POST" // Default
	if optionsJSON != nil {
		jsonStr := C.GoString(optionsJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &options)
		}
	}

	if options.Method == "" {
		options.Method = "POST"
	}

	// Create pipe for streaming body
	pr, pw := io.Pipe()

	upload := &UploadStream{
		session:    session,
		pipeWriter: pw,
		pipeReader: pr,
		url:        urlStr,
		method:     options.Method,
		headers:    options.Headers,
		timeout:    options.Timeout,
		responseCh: make(chan *uploadResult, 1),
		started:    false,
		finished:   false,
	}

	// Set Content-Type if specified
	if options.ContentType != "" {
		if upload.headers == nil {
			upload.headers = make(map[string]string)
		}
		upload.headers["Content-Type"] = options.ContentType
	}

	// Store upload and return handle
	uploadMu.Lock()
	uploadCounter++
	handle := uploadCounter
	uploads[handle] = upload
	uploadMu.Unlock()

	// Start the request in a goroutine
	go func() {
		ctx := context.Background()
		var cancel context.CancelFunc
		if upload.timeout > 0 {
			ctx, cancel = context.WithTimeout(ctx, time.Duration(upload.timeout)*time.Millisecond)
		} else {
			// Default 5 minute timeout for uploads
			ctx, cancel = context.WithTimeout(ctx, 5*time.Minute)
		}
		defer cancel()

		req := &httpcloak.Request{
			Method:  upload.method,
			URL:     upload.url,
			Headers: convertHeaders(upload.headers),
			Body:    nil, // Will use pipe reader
		}

		// Use the pipe reader as body
		resp, err := session.DoWithBody(ctx, req, upload.pipeReader)
		upload.responseCh <- &uploadResult{response: resp, err: err}
	}()

	upload.started = true
	return C.int64_t(handle)
}

//export httpcloak_upload_write
func httpcloak_upload_write(uploadHandle C.int64_t, dataBase64 *C.char) C.int {
	uploadMu.RLock()
	upload, exists := uploads[int64(uploadHandle)]
	uploadMu.RUnlock()

	if !exists || upload == nil {
		return -1
	}

	upload.mu.Lock()
	defer upload.mu.Unlock()

	if upload.finished {
		return -1
	}

	// Decode base64 data
	dataStr := C.GoString(dataBase64)
	data, err := decodeBase64(dataStr)
	if err != nil {
		return -1
	}

	// Write to pipe
	n, err := upload.pipeWriter.Write(data)
	if err != nil {
		return -1
	}

	return C.int(n)
}

//export httpcloak_upload_write_raw
func httpcloak_upload_write_raw(uploadHandle C.int64_t, data unsafe.Pointer, dataLen C.int) C.int {
	uploadMu.RLock()
	upload, exists := uploads[int64(uploadHandle)]
	uploadMu.RUnlock()

	if !exists || upload == nil {
		return -1
	}

	upload.mu.Lock()
	defer upload.mu.Unlock()

	if upload.finished {
		return -1
	}

	// Convert to Go slice
	buf := C.GoBytes(data, dataLen)

	// Write to pipe
	n, err := upload.pipeWriter.Write(buf)
	if err != nil {
		return -1
	}

	return C.int(n)
}

//export httpcloak_upload_finish
func httpcloak_upload_finish(uploadHandle C.int64_t) *C.char {
	uploadMu.Lock()
	upload, exists := uploads[int64(uploadHandle)]
	if exists {
		delete(uploads, int64(uploadHandle)) // Clean up the upload from the map
	}
	uploadMu.Unlock()

	if !exists || upload == nil {
		return makeErrorJSON(errors.New("invalid upload handle"))
	}

	upload.mu.Lock()
	if upload.finished {
		upload.mu.Unlock()
		return makeErrorJSON(errors.New("upload already finished"))
	}
	upload.finished = true
	upload.mu.Unlock()

	// Close the pipe writer to signal end of body
	upload.pipeWriter.Close()

	// Wait for response
	result := <-upload.responseCh

	if result.err != nil {
		return makeErrorJSON(result.err)
	}

	// Build response JSON
	resp := result.response

	// Read body from io.ReadCloser
	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	cookies := parseSetCookieHeaders(resp.Headers)

	responseData := ResponseData{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       string(bodyBytes),
		FinalURL:   resp.FinalURL,
		Protocol:   resp.Protocol,
		Cookies:    cookies,
	}

	jsonData, err := json.Marshal(responseData)
	if err != nil {
		return makeErrorJSON(err)
	}

	return C.CString(string(jsonData))
}

//export httpcloak_upload_cancel
func httpcloak_upload_cancel(uploadHandle C.int64_t) {
	uploadMu.Lock()
	upload, exists := uploads[int64(uploadHandle)]
	if exists {
		delete(uploads, int64(uploadHandle))
	}
	uploadMu.Unlock()

	if upload != nil {
		upload.mu.Lock()
		if !upload.finished {
			upload.pipeWriter.CloseWithError(errors.New("upload cancelled"))
		}
		upload.mu.Unlock()
	}
}

// decodeBase64 decodes a base64 string to bytes
func decodeBase64(s string) ([]byte, error) {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	// Remove padding
	s = trimRight(s, "=")

	if len(s) == 0 {
		return []byte{}, nil
	}

	// Build decode table
	decodeTable := make(map[byte]int)
	for i, c := range base64Chars {
		decodeTable[byte(c)] = i
	}

	// Calculate output length
	outLen := len(s) * 3 / 4
	result := make([]byte, outLen)

	j := 0
	for i := 0; i < len(s); i += 4 {
		var n uint32
		count := 0
		for k := 0; k < 4 && i+k < len(s); k++ {
			if val, ok := decodeTable[s[i+k]]; ok {
				n = n<<6 | uint32(val)
				count++
			}
		}

		// Pad with zeros for incomplete groups
		for k := count; k < 4; k++ {
			n = n << 6
		}

		if count >= 2 && j < len(result) {
			result[j] = byte(n >> 16)
			j++
		}
		if count >= 3 && j < len(result) {
			result[j] = byte(n >> 8)
			j++
		}
		if count >= 4 && j < len(result) {
			result[j] = byte(n)
			j++
		}
	}

	return result[:j], nil
}

func trimRight(s, cutset string) string {
	for len(s) > 0 {
		found := false
		for _, c := range cutset {
			if rune(s[len(s)-1]) == c {
				s = s[:len(s)-1]
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return s
}

// encodeBase64 encodes bytes to base64 string
func encodeBase64(data []byte) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, ((len(data)+2)/3)*4)

	for i := 0; i < len(data); i += 3 {
		var b0, b1, b2 byte
		b0 = data[i]
		if i+1 < len(data) {
			b1 = data[i+1]
		}
		if i+2 < len(data) {
			b2 = data[i+2]
		}

		result = append(result, base64Chars[b0>>2])
		result = append(result, base64Chars[((b0&0x03)<<4)|(b1>>4)])

		if i+1 < len(data) {
			result = append(result, base64Chars[((b1&0x0f)<<2)|(b2>>6)])
		} else {
			result = append(result, '=')
		}

		if i+2 < len(data) {
			result = append(result, base64Chars[b2&0x3f])
		} else {
			result = append(result, '=')
		}
	}

	return string(result)
}

func main() {}
