package main

/*
#include <stdlib.h>
#include <stdint.h>

typedef void (*async_callback)(int64_t callback_id, const char* response_json, const char* error);

// Session cache callbacks - called by Go to get/put TLS sessions from external cache
// SYNC mode: returns result immediately
// get: returns JSON string with session data, or NULL if not found
// put: stores session data, returns 0 on success, non-zero on error
// delete: removes session, returns 0 on success
typedef char* (*session_cache_get_callback)(const char* key);
typedef int (*session_cache_put_callback)(const char* key, const char* value_json, int64_t ttl_seconds);
typedef int (*session_cache_delete_callback)(const char* key);
typedef void (*session_cache_error_callback)(const char* operation, const char* key, const char* error);

// ECH config cache callbacks - for HTTP/3 ECH support
typedef char* (*ech_cache_get_callback)(const char* key);
typedef int (*ech_cache_put_callback)(const char* key, const char* value_base64, int64_t ttl_seconds);

// ASYNC mode: callbacks notify JS, JS calls back with result via httpcloak_async_cache_*_result
typedef void (*async_cache_get_callback)(int64_t request_id, const char* key);
typedef void (*async_cache_put_callback)(int64_t request_id, const char* key, const char* value_json, int64_t ttl_seconds);
typedef void (*async_cache_delete_callback)(int64_t request_id, const char* key);
typedef void (*async_ech_get_callback)(int64_t request_id, const char* key);
typedef void (*async_ech_put_callback)(int64_t request_id, const char* key, const char* value_base64, int64_t ttl_seconds);

// Helper function to invoke callback from Go
static void invoke_callback(async_callback cb, int64_t callback_id, const char* response_json, const char* error) {
    if (cb != NULL) {
        cb(callback_id, response_json, error);
    }
}

// Helper functions to invoke SYNC session cache callbacks
static char* invoke_cache_get(session_cache_get_callback cb, const char* key) {
    if (cb != NULL) {
        return cb(key);
    }
    return NULL;
}

static int invoke_cache_put(session_cache_put_callback cb, const char* key, const char* value_json, int64_t ttl_seconds) {
    if (cb != NULL) {
        return cb(key, value_json, ttl_seconds);
    }
    return -1;
}

static void invoke_cache_error(session_cache_error_callback cb, const char* operation, const char* key, const char* error) {
    if (cb != NULL) {
        cb(operation, key, error);
    }
}

static int invoke_cache_delete(session_cache_delete_callback cb, const char* key) {
    if (cb != NULL) {
        return cb(key);
    }
    return -1;
}

static char* invoke_ech_get(ech_cache_get_callback cb, const char* key) {
    if (cb != NULL) {
        return cb(key);
    }
    return NULL;
}

static int invoke_ech_put(ech_cache_put_callback cb, const char* key, const char* value_base64, int64_t ttl_seconds) {
    if (cb != NULL) {
        return cb(key, value_base64, ttl_seconds);
    }
    return -1;
}

// Helper functions to invoke ASYNC session cache callbacks
static void invoke_async_cache_get(async_cache_get_callback cb, int64_t request_id, const char* key) {
    if (cb != NULL) {
        cb(request_id, key);
    }
}

static void invoke_async_cache_put(async_cache_put_callback cb, int64_t request_id, const char* key, const char* value_json, int64_t ttl_seconds) {
    if (cb != NULL) {
        cb(request_id, key, value_json, ttl_seconds);
    }
}

static void invoke_async_cache_delete(async_cache_delete_callback cb, int64_t request_id, const char* key) {
    if (cb != NULL) {
        cb(request_id, key);
    }
}

static void invoke_async_ech_get(async_ech_get_callback cb, int64_t request_id, const char* key) {
    if (cb != NULL) {
        cb(request_id, key);
    }
}

static void invoke_async_ech_put(async_ech_put_callback cb, int64_t request_id, const char* key, const char* value_base64, int64_t ttl_seconds) {
    if (cb != NULL) {
        cb(request_id, key, value_base64, ttl_seconds);
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
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/sardanioss/httpcloak"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/transport"
)

func init() {
	// Initialize library
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

// encodeResponseBody serializes a response body into ResponseData.Body/BodyEncoding.
// Valid UTF-8 passes through as a plain string (back-compat, no size overhead).
// Non-UTF-8 bodies (PDFs, images, compressed streams, etc.) are base64-encoded so
// they survive json.Marshal without U+FFFD replacement corrupting every non-ASCII
// byte. Bindings must check body_encoding and base64-decode when it equals "base64".
func encodeResponseBody(b []byte) (string, string) {
	if utf8.Valid(b) {
		return string(b), ""
	}
	return base64.StdEncoding.EncodeToString(b), "base64"
}

// Session handle management
var (
	sessionMu sync.RWMutex
	sessions  = make(map[int64]*httpcloak.Session)

	// lastErrors carries the most recent failure for a session handle.
	// httpcloak_request_raw returns C.int64_t and signals failure with -1, so
	// it physically cannot carry an error string; every failure class reached
	// the caller as the same generic "Request failed". This is where the real
	// reason goes, retrievable with httpcloak_last_error.
	//
	// Guarded by sessionMu and deleted in httpcloak_session_free, so an entry
	// cannot outlive its session. Nothing is stored for a handle that does not
	// resolve, which stops a caller passing junk handles from growing the map.
	lastErrors     = make(map[int64]string)
	sessionCounter int64
)

// Stream handle management for streaming responses
var (
	streamMu      sync.RWMutex
	streams       = make(map[int64]*streamEntry)
	streamCounter int64
)

// streamEntry pairs an open stream with the cancel func of the context that
// bounds it, so closing the stream also releases the context timer. Storing only
// the StreamResponse (the previous behaviour) leaked the WithTimeout timer until
// it fired, and the cancel func was never called despite the close path claiming
// it would be.
type streamEntry struct {
	resp   *httpcloak.StreamResponse
	cancel context.CancelFunc
}

// Upload stream handle management for streaming uploads
var (
	uploadMu      sync.RWMutex
	uploads       = make(map[int64]*UploadStream)
	uploadCounter int64
)

// Preset pool handle management
var (
	presetPoolMu      sync.RWMutex
	presetPools       = make(map[int64]*fingerprint.PresetPool)
	presetPoolCounter int64
)

func getPresetPool(handle C.int64_t) *fingerprint.PresetPool {
	presetPoolMu.RLock()
	defer presetPoolMu.RUnlock()
	return presetPools[int64(handle)]
}

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
	cancelFuncs     = make(map[int64]context.CancelFunc) // For cancelling in-flight async requests
)

// Request configuration for JSON parsing
type RequestConfig struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	// ExactHeaders replaces the whole header pipeline for this request: the
	// pairs go out in the order and casing given, a name may repeat, and no
	// preset headers, client hints or alphabetical tail are added.
	//
	// It is a list of two-element arrays, [name, value], because the ordinary
	// Headers map cannot carry order, casing or a repeated name, which is
	// exactly what reproducing a captured request needs. Headers is ignored
	// when this is set.
	ExactHeaders [][]string `json:"exact_headers,omitempty"`

	// HeaderOrder sets the order for this one request and overrides whatever
	// the session-wide setter installed. Nothing is stored on the session and
	// no lock is taken, so concurrent requests can each carry their own.
	//
	// It is a prefix rather than a replacement: names listed here go first, in
	// this order, and anything left out keeps the preset's own position. Use it
	// instead of setting a session-wide order around a request, which races
	// with every other request in flight.
	HeaderOrder  []string `json:"header_order,omitempty"`
	Body         string   `json:"body,omitempty"`
	BodyEncoding string   `json:"body_encoding,omitempty"` // "text" (default) or "base64"
	// Timeout's UNIT DEPENDS ON THE ENTRY POINT: httpcloak_request_raw reads it
	// as MILLISECONDS; httpcloak_request and httpcloak_request_async (and
	// httpcloak_stream_request) read it as SECONDS. Bindings must convert to
	// match the export they call. (This split is a known wart — see also
	// RequestOptions.Timeout — kept as-is to avoid a coordinated cross-binding
	// flag day; unify only with per-binding integration tests in place.)
	Timeout int `json:"timeout,omitempty"`
	// FetchMode explicitly forces Sec-Fetch-Mode and bypasses auto-sniffing.
	// Valid values: "cors", "no-cors", "navigate", "websocket". Empty = auto.
	FetchMode string `json:"fetch_mode,omitempty"`
	// FollowRedirects, when non-nil, overrides the session-level redirect
	// policy for this request. nil leaves the session default in effect.
	FollowRedirects *bool `json:"follow_redirects,omitempty"`
	// DisableConditionalCache, when true, skips ETag / If-Modified-Since
	// injection for this request and stops the response from updating the
	// session's per-URL cache. Default false leaves the session-level
	// behaviour intact.
	DisableConditionalCache bool `json:"disable_conditional_cache,omitempty"`
	// DisableClientHints strips ALL UA client hints (sec-ch-ua trio + high-entropy)
	// for this request. DisableHighEntropyClientHints keeps the trio but drops the
	// high-entropy hints. Default false leaves the session behaviour intact.
	DisableClientHints            bool `json:"disable_client_hints,omitempty"`
	DisableHighEntropyClientHints bool `json:"disable_high_entropy_client_hints,omitempty"`

	// DisableRedirectReferer stops a Referer being added on redirect hops. By
	// default one is synthesised per Chrome's strict-origin-when-cross-origin
	// policy, which is what a browser does. When set, no Referer reaches the
	// next hop at all, including one the caller set on the original request.
	DisableRedirectReferer bool `json:"disable_redirect_referer,omitempty"`
}

// Cookie represents a parsed cookie from Set-Cookie header
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Expires  string `json:"expires,omitempty"` // RFC1123 format or empty
	MaxAge   int    `json:"max_age,omitempty"` // seconds, 0 means not set
	Secure   bool   `json:"secure,omitempty"`
	HttpOnly bool   `json:"http_only,omitempty"`
	SameSite string `json:"same_site,omitempty"` // "Strict", "Lax", "None", or empty
}

// RedirectInfo contains information about a redirect response
type RedirectInfo struct {
	StatusCode int                 `json:"status_code"`
	URL        string              `json:"url"`
	Headers    map[string][]string `json:"headers"`
}

// Response for JSON serialization (legacy - includes body as string)
type ResponseData struct {
	StatusCode   int                 `json:"status_code"`
	Headers      map[string][]string `json:"headers"`
	Body         string              `json:"body"`
	BodyEncoding string              `json:"body_encoding,omitempty"` // "" (text) or "base64"
	FinalURL     string              `json:"final_url"`
	Protocol     string              `json:"protocol"`
	Cookies      []Cookie            `json:"cookies"`
	History      []RedirectInfo      `json:"history"`

	// The Go core records all three; they were simply never marshalled, so no
	// binding could reach them however it was written.
	//
	// HeaderOrder is the order the peer sent its headers in and HeaderCasing is
	// how it spelled them. A map carries neither, so anything relaying this
	// response onward, a proxy or a MITM bridge, otherwise emits a different
	// header block than the origin did. Both are nil on HTTP/1.1, which reads
	// through textproto and loses the order and the casing before we see them.
	//
	// Trailer is the block that arrives after the body, which is where gRPC puts
	// its status. Nil when there was none.
	HeaderOrder  []string            `json:"header_order,omitempty"`
	HeaderCasing []string            `json:"header_casing,omitempty"`
	Trailer      map[string][]string `json:"trailer,omitempty"`
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

	// See ResponseData for what these are and when they are nil.
	HeaderOrder  []string            `json:"header_order,omitempty"`
	HeaderCasing []string            `json:"header_casing,omitempty"`
	Trailer      map[string][]string `json:"trailer,omitempty"`
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
	Preset                        string                 `json:"preset"`
	Proxy                         string                 `json:"proxy,omitempty"`
	TCPProxy                      string                 `json:"tcp_proxy,omitempty"`                         // Proxy for TCP (HTTP/1.1, HTTP/2)
	UDPProxy                      string                 `json:"udp_proxy,omitempty"`                         // Proxy for UDP (HTTP/3 via MASQUE)
	Timeout                       int                    `json:"timeout,omitempty"`                           // seconds
	HTTPVersion                   string                 `json:"http_version,omitempty"`                      // "auto", "h1", "h2", "h3"
	Verify                        *bool                  `json:"verify,omitempty"`                            // SSL verification (default: true)
	AllowRedirects                *bool                  `json:"allow_redirects,omitempty"`                   // Follow redirects (default: true)
	MaxRedirects                  int                    `json:"max_redirects,omitempty"`                     // Max redirects (default: 10)
	Retry                         int                    `json:"retry,omitempty"`                             // Retry count (default: 0)
	RetryWaitMin                  int                    `json:"retry_wait_min,omitempty"`                    // Min wait between retries in ms
	RetryWaitMax                  int                    `json:"retry_wait_max,omitempty"`                    // Max wait between retries in ms
	RetryOnStatus                 []int                  `json:"retry_on_status,omitempty"`                   // Status codes to retry on
	PreferIPv4                    bool                   `json:"prefer_ipv4,omitempty"`                       // Prefer IPv4 over IPv6
	ConnectTo                     map[string]string      `json:"connect_to,omitempty"`                        // Domain fronting: request_host -> connect_host
	ECHConfigDomain               string                 `json:"ech_config_domain,omitempty"`                 // Domain to fetch ECH config from
	TLSOnly                       bool                   `json:"tls_only,omitempty"`                          // TLS-only mode: skip preset headers, set all manually
	QuicIdleTimeout               int                    `json:"quic_idle_timeout,omitempty"`                 // QUIC idle timeout in seconds (default: 30)
	LocalAddress                  string                 `json:"local_address,omitempty"`                     // Local IP to bind outgoing connections (IPv6 rotation)
	KeyLogFile                    string                 `json:"key_log_file,omitempty"`                      // Path to write TLS key log for Wireshark decryption
	DisableECH                    bool                   `json:"disable_ech,omitempty"`                       // Disable ECH lookup for faster first request
	DisableHTTP3                  bool                   `json:"disable_http3,omitempty"`                     // Disable HTTP/3 racing while keeping H1/H2 negotiation
	EnableSpeculativeTLS          bool                   `json:"enable_speculative_tls,omitempty"`            // Enable speculative TLS optimization for proxy connections
	SwitchProtocol                string                 `json:"switch_protocol,omitempty"`                   // Protocol to switch to after Refresh()
	WithoutCookieJar              bool                   `json:"without_cookie_jar,omitempty"`                // Disable internal cookie jar (caller manages cookies via headers)
	WithoutConditionalCache       bool                   `json:"without_conditional_cache,omitempty"`         // Disable ETag / If-Modified-Since handling entirely
	WithoutClientHints            bool                   `json:"without_client_hints,omitempty"`              // Disable all UA client hints (trio + high-entropy)
	WithoutHighEntropyClientHints bool                   `json:"without_high_entropy_client_hints,omitempty"` // Disable only the high-entropy UA client hints
	JA3                           string                 `json:"ja3,omitempty"`                               // Custom JA3 fingerprint string
	Akamai                        string                 `json:"akamai,omitempty"`                            // Custom Akamai HTTP/2 fingerprint string
	ExtraFP                       map[string]interface{} `json:"extra_fp,omitempty"`                          // Extra fingerprint options
	TCPTTL                        *int                   `json:"tcp_ttl,omitempty"`                           // Override TCP/IP TTL (128=Windows, 64=Linux/macOS)
	TCPMSS                        *int                   `json:"tcp_mss,omitempty"`                           // Override TCP MSS (1460=Ethernet)
	TCPWindowSize                 *int                   `json:"tcp_window_size,omitempty"`                   // Override TCP window size (64240=Windows, 65535=Linux)
	TCPWindowScale                *int                   `json:"tcp_window_scale,omitempty"`                  // Override TCP window scale (8=Win, 7=Linux, 6=macOS)
	TCPDFBit                      *bool                  `json:"tcp_df,omitempty"`                            // Override IP Don't Fragment flag
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

// --- cgo panic guards (P0) ---
//
// A Go panic that unwinds across the cgo boundary aborts the entire host
// process (SIGABRT) — the C/.NET/Python/Node caller gets no error, no stack,
// just a dead process. Every //export function and every goroutine it spawns
// must therefore convert panics into ordinary error returns. The guard* helpers
// are installed as the first deferred call in each export so a nil deref, an
// out-of-range index, a type assertion, or a bad JSON shape becomes a normal
// failure value instead of a crash. logClibPanic records the panic + stack to
// stderr so the failure is still diagnosable.
func logClibPanic(where string, r interface{}) {
	fmt.Fprintf(os.Stderr, "httpcloak: recovered panic in %s: %v\n%s\n", where, r, debug.Stack())
}

func guardCharP(where string, ret **C.char) {
	if r := recover(); r != nil {
		logClibPanic(where, r)
		*ret = makeErrorJSON(fmt.Errorf("internal panic: %v", r))
	}
}

func guardInt64(where string, ret *C.int64_t) {
	if r := recover(); r != nil {
		logClibPanic(where, r)
		*ret = -1
	}
}

func guardInt(where string, ret *C.int) {
	if r := recover(); r != nil {
		logClibPanic(where, r)
		*ret = 0
	}
}

func guardPtr(where string, ret *unsafe.Pointer) {
	if r := recover(); r != nil {
		logClibPanic(where, r)
		*ret = nil
	}
}

func guardVoid(where string) {
	if r := recover(); r != nil {
		logClibPanic(where, r)
	}
}

// guardAsync recovers a panic inside an async request goroutine and reports it
// back through the registered callback, so the caller's pending future fails
// cleanly instead of hanging forever (or crashing the process).
func guardAsync(where string, callbackID int64) {
	if r := recover(); r != nil {
		logClibPanic(where, r)
		invokeCallback(callbackID, "", fmt.Sprintf("internal panic: %v", r))
	}
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

		cookie := Cookie{}

		// Split by semicolon to get name=value and attributes
		parts := splitBySemicolon(line)
		if len(parts) == 0 {
			continue
		}

		// First part is name=value
		firstPart := trim(parts[0])
		eqIdx := indexOf(firstPart, "=")
		if eqIdx == -1 {
			continue
		}
		cookie.Name = trim(firstPart[:eqIdx])
		cookie.Value = trim(firstPart[eqIdx+1:])
		if cookie.Name == "" {
			continue
		}

		// Parse attributes
		for i := 1; i < len(parts); i++ {
			attr := trim(parts[i])
			if attr == "" {
				continue
			}

			attrLower := toLower(attr)

			// Check for flag attributes (no value)
			if attrLower == "secure" {
				cookie.Secure = true
				continue
			}
			if attrLower == "httponly" {
				cookie.HttpOnly = true
				continue
			}

			// Check for key=value attributes
			attrEqIdx := indexOf(attr, "=")
			if attrEqIdx == -1 {
				continue
			}

			attrName := toLower(trim(attr[:attrEqIdx]))
			attrValue := trim(attr[attrEqIdx+1:])

			switch attrName {
			case "domain":
				cookie.Domain = attrValue
			case "path":
				cookie.Path = attrValue
			case "expires":
				cookie.Expires = attrValue
			case "max-age":
				cookie.MaxAge = parseInt(attrValue)
			case "samesite":
				// Normalize to capitalized form
				sameSiteLower := toLower(attrValue)
				switch sameSiteLower {
				case "strict":
					cookie.SameSite = "Strict"
				case "lax":
					cookie.SameSite = "Lax"
				case "none":
					cookie.SameSite = "None"
				default:
					cookie.SameSite = attrValue
				}
			}
		}

		cookies = append(cookies, cookie)
	}

	return cookies
}

// splitBySemicolon splits a string by semicolon
func splitBySemicolon(s string) []string {
	var result []string
	var current string
	for i := 0; i < len(s); i++ {
		if s[i] == ';' {
			result = append(result, current)
			current = ""
		} else {
			current += string(s[i])
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// toLower converts a string to lowercase (simple ASCII)
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + 32
		}
		result[i] = c
	}
	return string(result)
}

// parseInt parses an integer from a string, returns 0 on error
func parseInt(s string) int {
	result := 0
	negative := false
	i := 0

	if len(s) > 0 && s[0] == '-' {
		negative = true
		i = 1
	}

	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		result = result*10 + int(c-'0')
	}

	if negative {
		return -result
	}
	return result
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

// buildHeaders combines user headers with optional fetch_mode override. When
// fetch_mode is set, it's injected as the Sec-Fetch-Mode header (and a
// coherent Sec-Fetch-Dest when appropriate) so the Go core's mode picker
// treats it as an explicit user intent. User-supplied Sec-Fetch-* headers
// still win.
func buildHeaders(rawHeaders map[string]string, fetchMode string) map[string][]string {
	h := convertHeaders(rawHeaders)
	fetchMode = strings.ToLower(strings.TrimSpace(fetchMode))
	if fetchMode == "" {
		return h
	}
	if h == nil {
		h = make(map[string][]string)
	}
	hasHeader := func(name string) bool {
		for k := range h {
			if strings.EqualFold(k, name) {
				return true
			}
		}
		return false
	}
	switch fetchMode {
	case "cors", "no-cors", "navigate", "websocket":
		if !hasHeader("Sec-Fetch-Mode") {
			h["Sec-Fetch-Mode"] = []string{fetchMode}
		}
		// Pair a coherent default Sec-Fetch-Dest when the user didn't supply
		// one. Keeps the final header set self-consistent.
		if !hasHeader("Sec-Fetch-Dest") {
			switch fetchMode {
			case "cors", "websocket":
				h["Sec-Fetch-Dest"] = []string{"empty"}
			case "navigate":
				h["Sec-Fetch-Dest"] = []string{"document"}
			}
		}
	}
	return h
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

	body, bodyEncoding := encodeResponseBody(bodyBytes)
	data := ResponseData{
		StatusCode:   resp.StatusCode,
		Headers:      resp.Headers,
		HeaderOrder:  resp.HeaderOrder,
		HeaderCasing: resp.HeaderCasing,
		Trailer:      resp.Trailer,
		Body:         body,
		BodyEncoding: bodyEncoding,
		FinalURL:     resp.FinalURL,
		Protocol:     resp.Protocol,
		Cookies:      cookies,
		History:      history,
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
		StatusCode:   resp.StatusCode,
		Headers:      resp.Headers,
		HeaderOrder:  resp.HeaderOrder,
		HeaderCasing: resp.HeaderCasing,
		Trailer:      resp.Trailer,
		BodyLen:      len(bodyBytes),
		FinalURL:     resp.FinalURL,
		Protocol:     resp.Protocol,
		Cookies:      cookies,
		History:      history,
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
func httpcloak_response_get_metadata(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_response_get_metadata", &hcRet)
	rawResponsesMu.RLock()
	resp, exists := rawResponses[int64(handle)]
	rawResponsesMu.RUnlock()

	if !exists || resp == nil {
		return makeErrorJSON(errors.New("invalid response handle"))
	}

	return C.CString(string(resp.metadata))
}

//export httpcloak_response_get_body
func httpcloak_response_get_body(handle C.int64_t, outLen *C.int) (hcRet unsafe.Pointer) {
	defer guardPtr("httpcloak_response_get_body", &hcRet)
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
func httpcloak_response_get_body_ptr(handle C.int64_t, outLen *C.int) (hcRet unsafe.Pointer) {
	defer guardPtr("httpcloak_response_get_body_ptr", &hcRet)
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
func httpcloak_response_get_body_len(handle C.int64_t) (hcRet C.int) {
	defer guardInt("httpcloak_response_get_body_len", &hcRet)
	rawResponsesMu.RLock()
	resp, exists := rawResponses[int64(handle)]
	rawResponsesMu.RUnlock()

	if !exists || resp == nil {
		return 0
	}
	return C.int(len(resp.body))
}

//export httpcloak_response_copy_body_to
func httpcloak_response_copy_body_to(handle C.int64_t, dest unsafe.Pointer, destLen C.int) (hcRet C.int) {
	defer guardInt("httpcloak_response_copy_body_to", &hcRet)
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
	defer guardVoid("httpcloak_response_free")
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
func httpcloak_response_finalize(handle C.int64_t, dest unsafe.Pointer, destLen C.int) (hcRet *C.char) {
	defer guardCharP("httpcloak_response_finalize", &hcRet)
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
func httpcloak_get_raw(handle C.int64_t, url *C.char, optionsJSON *C.char) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_get_raw", &hcRet)
	clearLastError(handle)
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
		Method:                        "GET",
		URL:                           urlStr,
		Headers:                       buildHeaders(options.Headers, options.FetchMode),
		FollowRedirects:               options.FollowRedirects,
		DisableConditionalCache:       options.DisableConditionalCache,
		DisableClientHints:            options.DisableClientHints,
		DisableHighEntropyClientHints: options.DisableHighEntropyClientHints,
		DisableRedirectReferer:        options.DisableRedirectReferer,
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		setLastError(handle, "%v", err)
		return -1
	}

	return C.int64_t(makeRawResponse(resp))
}

// httpcloak_last_error returns why the most recent int64-returning call on
// this session handle failed, or an empty string if it succeeded. The caller
// owns the returned string and must release it with httpcloak_free_string.
//
// It exists because httpcloak_request_raw returns a response handle as an
// int64 and signals failure with -1. That return type cannot carry a message,
// so an invalid request JSON, an undecodable body and a genuine network
// failure were indistinguishable to every binding; they all surfaced as the
// same generic text. The async path never had this problem because it returns
// *C.char and can put the error in the payload.
//
//export httpcloak_last_error
func httpcloak_last_error(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_last_error", &hcRet)
	sessionMu.Lock()
	_, exists := sessions[int64(handle)]
	msg := lastErrors[int64(handle)]
	sessionMu.Unlock()
	if !exists {
		return C.CString("invalid or closed session handle")
	}
	return C.CString(msg)
}

//export httpcloak_post_raw
func httpcloak_post_raw(handle C.int64_t, url *C.char, body *C.char, bodyLen C.int, optionsJSON *C.char) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_post_raw", &hcRet)
	clearLastError(handle)
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
		Method:                        "POST",
		URL:                           urlStr,
		Headers:                       buildHeaders(options.Headers, options.FetchMode),
		Body:                          bodyReader,
		FollowRedirects:               options.FollowRedirects,
		DisableConditionalCache:       options.DisableConditionalCache,
		DisableClientHints:            options.DisableClientHints,
		DisableHighEntropyClientHints: options.DisableHighEntropyClientHints,
		DisableRedirectReferer:        options.DisableRedirectReferer,
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		setLastError(handle, "%v", err)
		return -1
	}

	return C.int64_t(makeRawResponse(resp))
}

//export httpcloak_request_raw
func httpcloak_request_raw(handle C.int64_t, requestJSON *C.char, body *C.char, bodyLen C.int) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_request_raw", &hcRet)
	clearLastError(handle)
	session := getSession(handle)
	if session == nil {
		// Nowhere to store this one: setLastError refuses unresolvable
		// handles, and httpcloak_last_error reports the same thing itself.
		return -1
	}

	var config RequestConfig
	if requestJSON != nil {
		jsonStr := C.GoString(requestJSON)
		// The error used to be discarded, which was worse than returning -1:
		// a malformed request JSON left config at its zero value and went on
		// to issue a GET to an empty URL, so the caller saw a network-shaped
		// failure for what was a serialisation bug on their side.
		if err := json.Unmarshal([]byte(jsonStr), &config); err != nil {
			setLastError(handle, "request JSON is not valid: %v", err)
			return -1
		}
	}

	var bodyBytes []byte
	if body != nil && bodyLen > 0 {
		bodyBytes = C.GoBytes(unsafe.Pointer(body), bodyLen)
	} else if config.Body != "" {
		var err error
		bodyBytes, err = decodeRequestBody(config.Body, config.BodyEncoding)
		if err != nil {
			setLastError(handle, "request body could not be decoded as %s: %v",
				config.BodyEncoding, err)
			return -1
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
		Method:                        method,
		URL:                           config.URL,
		Headers:                       buildHeaders(config.Headers, config.FetchMode),
		ExactHeaders:                  buildExactHeaders(config.ExactHeaders),
		HeaderOrder:                   config.HeaderOrder,
		Body:                          bodyReader,
		FollowRedirects:               config.FollowRedirects,
		DisableConditionalCache:       config.DisableConditionalCache,
		DisableClientHints:            config.DisableClientHints,
		DisableHighEntropyClientHints: config.DisableHighEntropyClientHints,
		DisableRedirectReferer:        config.DisableRedirectReferer,
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		setLastError(handle, "%v", err)
		return -1
	}

	return C.int64_t(makeRawResponse(resp))
}

// ============================================================================
// Session Management
// ============================================================================

//export httpcloak_session_new
func httpcloak_session_new(configJSON *C.char) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_session_new", &hcRet)
	config := SessionConfig{
		Preset:      "chrome-146",
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
		opts = append(opts, httpcloak.WithForceHTTP3())
		// "auto" or empty = default behavior
	}

	// Explicit disable_http3 flag: disables H3 racing while keeping H1/H2
	// auto-negotiation. Reachable indirectly via http_version="h2"/"h1" too
	// (those imply WithDisableHTTP3 per options docs), but the explicit flag
	// is cleaner for callers who just want "no H3" without committing to a
	// specific lower version.
	if config.DisableHTTP3 {
		opts = append(opts, httpcloak.WithDisableHTTP3())
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

	// Handle retry configuration. Retry is opt-in: the Go core defaults to 0
	// retries (changed from 3 per issue #57, to stop silently re-sending
	// non-idempotent POST/PUT/PATCH on 5xx), so retry==0 simply adds no retry
	// option. Bindings also default retry to 0.
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

	// Handle TLS-only mode
	if config.TLSOnly {
		opts = append(opts, httpcloak.WithTLSOnly())
	}

	// Handle QUIC idle timeout
	if config.QuicIdleTimeout > 0 {
		opts = append(opts, httpcloak.WithQuicIdleTimeout(time.Duration(config.QuicIdleTimeout)*time.Second))
	}

	// Handle local address binding (for IPv6 rotation)
	if config.LocalAddress != "" {
		opts = append(opts, httpcloak.WithLocalAddress(config.LocalAddress))
	}

	// Handle key log file (for Wireshark decryption)
	if config.KeyLogFile != "" {
		opts = append(opts, httpcloak.WithKeyLogFile(config.KeyLogFile))
	}

	// Handle ECH disabling for faster first request
	if config.DisableECH {
		opts = append(opts, httpcloak.WithDisableECH())
	}

	// Handle speculative TLS enabling
	if config.EnableSpeculativeTLS {
		opts = append(opts, httpcloak.WithEnableSpeculativeTLS())
	}

	// Handle switch protocol
	if config.SwitchProtocol != "" {
		opts = append(opts, httpcloak.WithSwitchProtocol(config.SwitchProtocol))
	}

	// Handle cookie jar disable (caller manages cookies via headers)
	if config.WithoutCookieJar {
		opts = append(opts, httpcloak.WithoutCookieJar())
	}

	// Handle conditional-cache disable (no ETag / If-Modified-Since traffic)
	if config.WithoutConditionalCache {
		opts = append(opts, httpcloak.WithoutConditionalCache())
	}

	// Handle client-hint disables (full strip / high-entropy only)
	if config.WithoutClientHints {
		opts = append(opts, httpcloak.WithoutClientHints())
	}
	if config.WithoutHighEntropyClientHints {
		opts = append(opts, httpcloak.WithoutHighEntropyClientHints())
	}

	// Handle custom fingerprint (JA3 / Akamai / extra_fp)
	if config.JA3 != "" || config.Akamai != "" || len(config.ExtraFP) > 0 {
		fp := httpcloak.CustomFingerprint{
			JA3:    config.JA3,
			Akamai: config.Akamai,
		}
		// Map extra_fp keys to CustomFingerprint fields
		if config.ExtraFP != nil {
			if v, ok := config.ExtraFP["tls_alpn"]; ok {
				if arr, ok := v.([]interface{}); ok {
					for _, item := range arr {
						if s, ok := item.(string); ok {
							fp.ALPN = append(fp.ALPN, s)
						}
					}
				}
			}
			if v, ok := config.ExtraFP["tls_signature_algorithms"]; ok {
				if arr, ok := v.([]interface{}); ok {
					for _, item := range arr {
						if s, ok := item.(string); ok {
							fp.SignatureAlgorithms = append(fp.SignatureAlgorithms, s)
						}
					}
				}
			}
			if v, ok := config.ExtraFP["tls_cert_compression"]; ok {
				if arr, ok := v.([]interface{}); ok {
					for _, item := range arr {
						if s, ok := item.(string); ok {
							fp.CertCompression = append(fp.CertCompression, s)
						}
					}
				}
			}
			if v, ok := config.ExtraFP["tls_permute_extensions"]; ok {
				if b, ok := v.(bool); ok {
					fp.PermuteExtensions = b
				}
			}
			// JA3Extras carries seven fields; extra_fp mapped four, so three
			// were unreachable from every binding. A Firefox mirror needs
			// record_size_limit, a client offering two key shares needs
			// key_share_curves, and delegated credentials are extension 34.
			if v, ok := config.ExtraFP["tls_delegated_credential_algorithms"]; ok {
				if arr, ok := v.([]interface{}); ok {
					for _, item := range arr {
						if s, ok := item.(string); ok {
							fp.DelegatedCredentialAlgorithms = append(fp.DelegatedCredentialAlgorithms, s)
						}
					}
				}
			}
			if v, ok := config.ExtraFP["tls_record_size_limit"]; ok {
				if n, ok := toUint16(v); ok {
					fp.RecordSizeLimit = n
				}
			}
			if v, ok := config.ExtraFP["tls_key_share_curves"]; ok {
				if f, ok := v.(float64); ok {
					fp.KeyShareCurves = int(f)
				}
			}
		}
		opts = append(opts, httpcloak.WithCustomFingerprint(fp))
	}

	// Handle TCP/IP fingerprint overrides
	if config.TCPTTL != nil || config.TCPMSS != nil || config.TCPWindowSize != nil || config.TCPWindowScale != nil || config.TCPDFBit != nil {
		tcpFP := fingerprint.TCPFingerprint{}
		if config.TCPTTL != nil {
			tcpFP.TTL = *config.TCPTTL
		}
		if config.TCPMSS != nil {
			tcpFP.MSS = *config.TCPMSS
		}
		if config.TCPWindowSize != nil {
			tcpFP.WindowSize = *config.TCPWindowSize
		}
		if config.TCPWindowScale != nil {
			tcpFP.WindowScale = *config.TCPWindowScale
		}
		if config.TCPDFBit != nil {
			tcpFP.DFBit = *config.TCPDFBit
		}
		opts = append(opts, httpcloak.WithTCPFingerprint(tcpFP))
	}

	// Handle session cache if configured globally
	backend, errorCallback := getSessionCacheBackend()
	if backend != nil {
		opts = append(opts, httpcloak.WithSessionCache(backend, errorCallback))
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
	defer guardVoid("httpcloak_session_free")
	sessionMu.Lock()
	session, exists := sessions[int64(handle)]
	if exists {
		delete(sessions, int64(handle))
	}
	delete(lastErrors, int64(handle))
	sessionMu.Unlock()

	if session != nil {
		session.Close()
	}
}

//export httpcloak_session_refresh
func httpcloak_session_refresh(handle C.int64_t) {
	defer guardVoid("httpcloak_session_refresh")
	session := getSession(handle)
	if session != nil {
		session.Refresh()
	}
}

//export httpcloak_session_refresh_protocol
func httpcloak_session_refresh_protocol(handle C.int64_t, protocol *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_refresh_protocol", &hcRet)
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	proto := C.GoString(protocol)
	if err := session.RefreshWithProtocol(proto); err != nil {
		return makeErrorJSON(err)
	}

	return nil
}

//export httpcloak_session_warmup
func httpcloak_session_warmup(handle C.int64_t, url *C.char, timeoutMs C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_warmup", &hcRet)
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	urlStr := C.GoString(url)

	ctx := context.Background()
	var cancel context.CancelFunc
	if timeoutMs > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	} else {
		ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
	}
	defer cancel()

	if err := session.Warmup(ctx, urlStr); err != nil {
		return makeErrorJSON(err)
	}

	return nil
}

// setLastError records why an int64-returning entry point returned -1.
// Storing nothing for an unresolvable handle is deliberate; see lastErrors.
func setLastError(handle C.int64_t, format string, args ...interface{}) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if _, exists := sessions[int64(handle)]; !exists {
		return
	}
	lastErrors[int64(handle)] = fmt.Sprintf(format, args...)
}

// clearLastError drops any stored error for a handle. Called at the top of
// each attempt so a stored message only ever describes the most recent call,
// rather than a stale failure surviving a later success.
func clearLastError(handle C.int64_t) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	delete(lastErrors, int64(handle))
}

func getSession(handle C.int64_t) *httpcloak.Session {
	sessionMu.RLock()
	defer sessionMu.RUnlock()
	return sessions[int64(handle)]
}

//export httpcloak_session_fork
func httpcloak_session_fork(handle C.int64_t) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_session_fork", &hcRet)
	session := getSession(handle)
	if session == nil {
		return -1
	}

	forks := session.Fork(1)
	if len(forks) == 0 {
		return -1
	}

	sessionMu.Lock()
	sessionCounter++
	newHandle := sessionCounter
	sessions[newHandle] = forks[0]
	sessionMu.Unlock()

	return C.int64_t(newHandle)
}

// ============================================================================
// Synchronous Requests
// ============================================================================

// RequestOptions for httpcloak_get/post JSON parsing
type RequestOptions struct {
	Headers map[string]string `json:"headers,omitempty"`
	// Timeout's UNIT DEPENDS ON THE ENTRY POINT: the sync httpcloak_get/
	// httpcloak_post (and the _raw + stream variants) read it as MILLISECONDS,
	// but httpcloak_get_async / httpcloak_post_async read it as SECONDS. Bindings
	// must convert to match the export they call (this mismatch is why the .NET
	// binary path once sent seconds to an ms export — a 1000x-too-short timeout).
	Timeout int `json:"timeout,omitempty"`
	// FetchMode explicitly forces Sec-Fetch-Mode and bypasses auto-sniffing.
	// Valid values: "cors", "no-cors", "navigate", "websocket". Empty = auto.
	FetchMode string `json:"fetch_mode,omitempty"`
	// FollowRedirects, when non-nil, overrides the session-level redirect
	// policy for this request. nil leaves the session default in effect.
	FollowRedirects *bool `json:"follow_redirects,omitempty"`
	// DisableConditionalCache, when true, skips ETag / If-Modified-Since
	// injection for this request and stops the response from updating the
	// session's per-URL cache. Default false leaves the session-level
	// behaviour intact.
	DisableConditionalCache bool `json:"disable_conditional_cache,omitempty"`
	// DisableClientHints strips ALL UA client hints (sec-ch-ua trio + high-entropy)
	// for this request. DisableHighEntropyClientHints keeps the trio but drops the
	// high-entropy hints. Default false leaves the session behaviour intact.
	DisableClientHints            bool `json:"disable_client_hints,omitempty"`
	DisableHighEntropyClientHints bool `json:"disable_high_entropy_client_hints,omitempty"`

	// DisableRedirectReferer stops a Referer being added on redirect hops. By
	// default one is synthesised per Chrome's strict-origin-when-cross-origin
	// policy, which is what a browser does. When set, no Referer reaches the
	// next hop at all, including one the caller set on the original request.
	DisableRedirectReferer bool `json:"disable_redirect_referer,omitempty"`
	// BodyEncoding controls how the request body string is interpreted by
	// post_async / get_async style entry points where the body is passed as
	// a separate C string. "" (default) treats the body as UTF-8 text.
	// "base64" base64-decodes the body before sending. Bindings must set
	// this to "base64" whenever the user-supplied body contains arbitrary
	// bytes (Buffer / bytes / Stream), otherwise NUL bytes terminate the
	// C string early and binary uploads are silently truncated/mangled.
	BodyEncoding string `json:"body_encoding,omitempty"`
}

//export httpcloak_get
func httpcloak_get(handle C.int64_t, url *C.char, optionsJSON *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_get", &hcRet)
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
		Method:                        "GET",
		URL:                           urlStr,
		Headers:                       buildHeaders(options.Headers, options.FetchMode),
		FollowRedirects:               options.FollowRedirects,
		DisableConditionalCache:       options.DisableConditionalCache,
		DisableClientHints:            options.DisableClientHints,
		DisableHighEntropyClientHints: options.DisableHighEntropyClientHints,
		DisableRedirectReferer:        options.DisableRedirectReferer,
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		return makeErrorJSON(err)
	}

	return makeResponseJSON(resp)
}

//export httpcloak_post
func httpcloak_post(handle C.int64_t, url *C.char, body *C.char, optionsJSON *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_post", &hcRet)
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
		// Honor body_encoding (e.g. "base64") so callers can pass bodies with
		// embedded NUL bytes without C.GoString truncating them at the first NUL.
		rawBody, decodeErr := decodeRequestBody(bodyStr, options.BodyEncoding)
		if decodeErr != nil {
			return makeErrorJSON(fmt.Errorf("invalid base64 body: %w", decodeErr))
		}
		if len(rawBody) > 0 {
			bodyReader = bytes.NewReader(rawBody)
		}
	}

	req := &httpcloak.Request{
		Method:                        "POST",
		URL:                           urlStr,
		Headers:                       buildHeaders(options.Headers, options.FetchMode),
		Body:                          bodyReader,
		FollowRedirects:               options.FollowRedirects,
		DisableConditionalCache:       options.DisableConditionalCache,
		DisableClientHints:            options.DisableClientHints,
		DisableHighEntropyClientHints: options.DisableHighEntropyClientHints,
		DisableRedirectReferer:        options.DisableRedirectReferer,
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		return makeErrorJSON(err)
	}

	return makeResponseJSON(resp)
}

//export httpcloak_request
func httpcloak_request(handle C.int64_t, requestJSON *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_request", &hcRet)
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
		Method:                        config.Method,
		URL:                           config.URL,
		Headers:                       buildHeaders(config.Headers, config.FetchMode),
		ExactHeaders:                  buildExactHeaders(config.ExactHeaders),
		HeaderOrder:                   config.HeaderOrder,
		Body:                          bodyReader,
		FollowRedirects:               config.FollowRedirects,
		DisableConditionalCache:       config.DisableConditionalCache,
		DisableClientHints:            config.DisableClientHints,
		DisableHighEntropyClientHints: config.DisableHighEntropyClientHints,
		DisableRedirectReferer:        config.DisableRedirectReferer,
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
func httpcloak_register_callback(callback C.async_callback) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_register_callback", &hcRet)
	callbackMu.Lock()
	callbackCounter++
	id := callbackCounter
	asyncCallbacks[id] = callback
	callbackMu.Unlock()
	return C.int64_t(id)
}

//export httpcloak_unregister_callback
func httpcloak_unregister_callback(callbackID C.int64_t) {
	defer guardVoid("httpcloak_unregister_callback")
	callbackMu.Lock()
	delete(asyncCallbacks, int64(callbackID))
	delete(cancelFuncs, int64(callbackID))
	callbackMu.Unlock()
}

//export httpcloak_cancel_request
func httpcloak_cancel_request(callbackID C.int64_t) {
	defer guardVoid("httpcloak_cancel_request")
	callbackMu.Lock()
	cancel, exists := cancelFuncs[int64(callbackID)]
	callbackMu.Unlock()
	if exists {
		cancel()
	}
}

func invokeCallback(callbackID int64, responseJSON string, errStr string) {
	callbackMu.Lock()
	callback, exists := asyncCallbacks[callbackID]
	// Auto-cleanup: remove callback and cancel func after retrieval to prevent memory leaks
	if exists {
		delete(asyncCallbacks, callbackID)
	}
	delete(cancelFuncs, callbackID)
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
	defer guardVoid("httpcloak_get_async")
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

	// Create cancellable context and store cancel func for this request.
	// Layer the user-supplied timeout on top so per-request timeouts are
	// actually honored — previously options.Timeout was parsed but never
	// applied here, silently dropping the value passed by Node.js callers.
	// Unit matches httpcloak_request_async: seconds.
	ctx, cancel := context.WithCancel(context.Background())
	if options.Timeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, time.Duration(options.Timeout)*time.Second)
		origCancel := cancel
		cancel = func() {
			timeoutCancel()
			origCancel()
		}
	}
	callbackMu.Lock()
	cancelFuncs[int64(callbackID)] = cancel
	callbackMu.Unlock()

	go func() {
		defer cancel()
		defer guardAsync("get_async goroutine", int64(callbackID))
		if session == nil {
			invokeCallback(int64(callbackID), "", ErrInvalidSession.Error())
			return
		}

		req := &httpcloak.Request{
			Method:                        "GET",
			URL:                           urlStr,
			Headers:                       buildHeaders(options.Headers, options.FetchMode),
			FollowRedirects:               options.FollowRedirects,
			DisableConditionalCache:       options.DisableConditionalCache,
			DisableClientHints:            options.DisableClientHints,
			DisableHighEntropyClientHints: options.DisableHighEntropyClientHints,
			DisableRedirectReferer:        options.DisableRedirectReferer,
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

		body, bodyEncoding := encodeResponseBody(bodyBytes)
		data := ResponseData{
			StatusCode:   resp.StatusCode,
			Headers:      resp.Headers,
			HeaderOrder:  resp.HeaderOrder,
			HeaderCasing: resp.HeaderCasing,
			Trailer:      resp.Trailer,
			Body:         body,
			BodyEncoding: bodyEncoding,
			FinalURL:     resp.FinalURL,
			Protocol:     resp.Protocol,
			Cookies:      cookies,
			History:      history,
		}
		jsonData, _ := json.Marshal(data)
		invokeCallback(int64(callbackID), string(jsonData), "")
	}()
}

//export httpcloak_post_async
func httpcloak_post_async(handle C.int64_t, url *C.char, body *C.char, optionsJSON *C.char, callbackID C.int64_t) {
	defer guardVoid("httpcloak_post_async")
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

	// Create cancellable context and store cancel func for this request.
	// Layer the user-supplied timeout on top so per-request timeouts are
	// actually honored — previously options.Timeout was parsed but never
	// applied here. Unit matches httpcloak_request_async: seconds.
	ctx, cancel := context.WithCancel(context.Background())
	if options.Timeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, time.Duration(options.Timeout)*time.Second)
		origCancel := cancel
		cancel = func() {
			timeoutCancel()
			origCancel()
		}
	}
	callbackMu.Lock()
	cancelFuncs[int64(callbackID)] = cancel
	callbackMu.Unlock()

	go func() {
		defer cancel()
		defer guardAsync("post_async goroutine", int64(callbackID))
		if session == nil {
			invokeCallback(int64(callbackID), "", ErrInvalidSession.Error())
			return
		}

		var bodyReader io.Reader
		if bodyStr != "" {
			rawBody, decodeErr := decodeRequestBody(bodyStr, options.BodyEncoding)
			if decodeErr != nil {
				errResp := ErrorResponse{Error: "invalid base64 body: " + decodeErr.Error()}
				errJSON, _ := json.Marshal(errResp)
				invokeCallback(int64(callbackID), "", string(errJSON))
				return
			}
			if len(rawBody) > 0 {
				bodyReader = bytes.NewReader(rawBody)
			}
		}

		req := &httpcloak.Request{
			Method:                        "POST",
			URL:                           urlStr,
			Headers:                       buildHeaders(options.Headers, options.FetchMode),
			Body:                          bodyReader,
			FollowRedirects:               options.FollowRedirects,
			DisableConditionalCache:       options.DisableConditionalCache,
			DisableClientHints:            options.DisableClientHints,
			DisableHighEntropyClientHints: options.DisableHighEntropyClientHints,
			DisableRedirectReferer:        options.DisableRedirectReferer,
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

		body, bodyEncoding := encodeResponseBody(bodyBytes)
		data := ResponseData{
			StatusCode:   resp.StatusCode,
			Headers:      resp.Headers,
			HeaderOrder:  resp.HeaderOrder,
			HeaderCasing: resp.HeaderCasing,
			Trailer:      resp.Trailer,
			Body:         body,
			BodyEncoding: bodyEncoding,
			FinalURL:     resp.FinalURL,
			Protocol:     resp.Protocol,
			Cookies:      cookies,
			History:      history,
		}
		jsonData, _ := json.Marshal(data)
		invokeCallback(int64(callbackID), string(jsonData), "")
	}()
}

//export httpcloak_request_async
func httpcloak_request_async(handle C.int64_t, requestJSON *C.char, callbackID C.int64_t) {
	defer guardVoid("httpcloak_request_async")
	session := getSession(handle)

	var config RequestConfig
	if requestJSON != nil {
		jsonStr := C.GoString(requestJSON)
		json.Unmarshal([]byte(jsonStr), &config)
	}

	// Create cancellable context and store cancel func for this request
	ctx, cancel := context.WithCancel(context.Background())
	callbackMu.Lock()
	cancelFuncs[int64(callbackID)] = cancel
	callbackMu.Unlock()

	go func() {
		defer cancel()
		defer guardAsync("request_async goroutine", int64(callbackID))
		if session == nil {
			invokeCallback(int64(callbackID), "", ErrInvalidSession.Error())
			return
		}

		if config.Method == "" {
			config.Method = "GET"
		}

		// Layer timeout on top of the cancellable context
		if config.Timeout > 0 {
			var timeoutCancel context.CancelFunc
			ctx, timeoutCancel = context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
			defer timeoutCancel()
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
			Method:                        config.Method,
			URL:                           config.URL,
			Headers:                       buildHeaders(config.Headers, config.FetchMode),
			ExactHeaders:                  buildExactHeaders(config.ExactHeaders),
			HeaderOrder:                   config.HeaderOrder,
			Body:                          bodyReader,
			FollowRedirects:               config.FollowRedirects,
			DisableConditionalCache:       config.DisableConditionalCache,
			DisableClientHints:            config.DisableClientHints,
			DisableHighEntropyClientHints: config.DisableHighEntropyClientHints,
			DisableRedirectReferer:        config.DisableRedirectReferer,
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

		body, bodyEncoding := encodeResponseBody(bodyBytes)
		data := ResponseData{
			StatusCode:   resp.StatusCode,
			Headers:      resp.Headers,
			HeaderOrder:  resp.HeaderOrder,
			HeaderCasing: resp.HeaderCasing,
			Trailer:      resp.Trailer,
			Body:         body,
			BodyEncoding: bodyEncoding,
			FinalURL:     resp.FinalURL,
			Protocol:     resp.Protocol,
			Cookies:      cookies,
			History:      history,
		}
		jsonData, _ := json.Marshal(data)
		invokeCallback(int64(callbackID), string(jsonData), "")
	}()
}

// ============================================================================
// Cookie Management
// ============================================================================

//export httpcloak_get_cookies
func httpcloak_get_cookies(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_get_cookies", &hcRet)
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	cookieStates := session.GetCookies()
	// Convert to clib Cookie format with RFC1123 expires string
	var cookies []Cookie
	for _, c := range cookieStates {
		cookie := Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			MaxAge:   c.MaxAge,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
			SameSite: c.SameSite,
		}
		if c.Expires != nil {
			cookie.Expires = c.Expires.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
		}
		cookies = append(cookies, cookie)
	}
	if cookies == nil {
		cookies = []Cookie{}
	}
	data, _ := json.Marshal(cookies)
	return C.CString(string(data))
}

//export httpcloak_set_cookie
func httpcloak_set_cookie(handle C.int64_t, cookieJSON *C.char) {
	defer guardVoid("httpcloak_set_cookie")
	session := getSession(handle)
	if session == nil {
		return
	}

	var cookie Cookie
	if err := json.Unmarshal([]byte(C.GoString(cookieJSON)), &cookie); err != nil {
		return
	}

	var expires *time.Time
	if cookie.Expires != "" {
		if t, err := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", cookie.Expires); err == nil {
			expires = &t
		}
	}

	session.SetCookie(httpcloak.CookieInfo{
		Name:     cookie.Name,
		Value:    cookie.Value,
		Domain:   cookie.Domain,
		Path:     cookie.Path,
		MaxAge:   cookie.MaxAge,
		Secure:   cookie.Secure,
		HttpOnly: cookie.HttpOnly,
		SameSite: cookie.SameSite,
		Expires:  expires,
	})
}

//export httpcloak_delete_cookie
func httpcloak_delete_cookie(handle C.int64_t, name *C.char, domain *C.char) {
	defer guardVoid("httpcloak_delete_cookie")
	session := getSession(handle)
	if session == nil {
		return
	}

	session.DeleteCookie(C.GoString(name), C.GoString(domain))
}

//export httpcloak_clear_cookies
func httpcloak_clear_cookies(handle C.int64_t) {
	defer guardVoid("httpcloak_clear_cookies")
	session := getSession(handle)
	if session == nil {
		return
	}

	session.ClearCookies()
}

// ============================================================================
// Session Persistence
// ============================================================================

//export httpcloak_session_save
func httpcloak_session_save(handle C.int64_t, path *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_save", &hcRet)
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
func httpcloak_session_load(path *C.char) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_session_load", &hcRet)
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
func httpcloak_session_marshal(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_marshal", &hcRet)
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
func httpcloak_session_unmarshal(data *C.char) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_session_unmarshal", &hcRet)
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
// Proxy Management
// ============================================================================

//export httpcloak_session_set_proxy
func httpcloak_session_set_proxy(handle C.int64_t, proxyURL *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_set_proxy", &hcRet)
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	var url string
	if proxyURL != nil {
		url = C.GoString(proxyURL)
	}
	session.SetProxy(url)
	return C.CString(`{"success":true}`)
}

//export httpcloak_session_set_tcp_proxy
func httpcloak_session_set_tcp_proxy(handle C.int64_t, proxyURL *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_set_tcp_proxy", &hcRet)
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	var url string
	if proxyURL != nil {
		url = C.GoString(proxyURL)
	}
	session.SetTCPProxy(url)
	return C.CString(`{"success":true}`)
}

//export httpcloak_session_set_udp_proxy
func httpcloak_session_set_udp_proxy(handle C.int64_t, proxyURL *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_set_udp_proxy", &hcRet)
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	var url string
	if proxyURL != nil {
		url = C.GoString(proxyURL)
	}
	session.SetUDPProxy(url)
	return C.CString(`{"success":true}`)
}

//export httpcloak_session_get_proxy
func httpcloak_session_get_proxy(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_get_proxy", &hcRet)
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}
	return C.CString(session.GetProxy())
}

//export httpcloak_session_get_tcp_proxy
func httpcloak_session_get_tcp_proxy(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_get_tcp_proxy", &hcRet)
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}
	return C.CString(session.GetTCPProxy())
}

//export httpcloak_session_get_udp_proxy
func httpcloak_session_get_udp_proxy(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_get_udp_proxy", &hcRet)
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}
	return C.CString(session.GetUDPProxy())
}

//export httpcloak_session_set_header_order
func httpcloak_session_set_header_order(handle C.int64_t, orderJSON *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_set_header_order", &hcRet)
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	orderStr := C.GoString(orderJSON)
	if orderStr == "" || orderStr == "[]" || orderStr == "null" {
		session.SetHeaderOrder(nil)
		return C.CString(`{"success":true}`)
	}

	var order []string
	if err := json.Unmarshal([]byte(orderStr), &order); err != nil {
		return C.CString(fmt.Sprintf(`{"error":"invalid JSON: %s"}`, err.Error()))
	}

	session.SetHeaderOrder(order)
	return C.CString(`{"success":true}`)
}

//export httpcloak_session_get_header_order
func httpcloak_session_get_header_order(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_get_header_order", &hcRet)
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	order := session.GetHeaderOrder()
	if order == nil {
		return C.CString("[]")
	}

	result, err := json.Marshal(order)
	if err != nil {
		return makeErrorJSON(err)
	}
	return C.CString(string(result))
}

//export httpcloak_session_set_identifier
func httpcloak_session_set_identifier(handle C.int64_t, sessionId *C.char) {
	defer guardVoid("httpcloak_session_set_identifier")
	session := getSession(handle)
	if session == nil {
		return
	}

	id := ""
	if sessionId != nil {
		id = C.GoString(sessionId)
	}
	session.SetSessionIdentifier(id)
}

// ============================================================================
// Conditional Cache + Redirect Runtime Controls
// ============================================================================

//export httpcloak_session_clear_cache
func httpcloak_session_clear_cache(handle C.int64_t) {
	defer guardVoid("httpcloak_session_clear_cache")
	session := getSession(handle)
	if session == nil {
		return
	}
	session.ClearCache()
}

// httpcloak_session_stats returns a JSON snapshot of the session's counters,
// timestamps and transport-level stats. Caller owns the returned string and
// must free it via httpcloak_free_string. Fields:
//
//	id, preset, created_at (unix ns), last_used (unix ns), request_count,
//	active, cookie_count, cache_entry_count, age_ns, idle_time_ns,
//	transport_stats (object).
//
// Returns nil if the session handle is invalid.
//
//export httpcloak_session_stats
func httpcloak_session_stats(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_session_stats", &hcRet)
	session := getSession(handle)
	if session == nil {
		return nil
	}
	stats := session.Stats()
	payload := map[string]interface{}{
		"id":                stats.ID,
		"preset":            stats.Preset,
		"created_at":        stats.CreatedAt.UnixNano(),
		"last_used":         stats.LastUsed.UnixNano(),
		"request_count":     stats.RequestCount,
		"active":            stats.Active,
		"cookie_count":      stats.CookieCount,
		"cache_entry_count": stats.CacheEntryCount,
		"age_ns":            int64(stats.Age),
		"idle_time_ns":      int64(stats.IdleTime),
		"transport_stats":   stats.TransportStats,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return C.CString(string(data))
}

// httpcloak_session_idle_time returns the time since the session last serviced
// a request, in nanoseconds. Returns -1 if the session handle is invalid.
//
//export httpcloak_session_idle_time
func httpcloak_session_idle_time(handle C.int64_t) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_session_idle_time", &hcRet)
	session := getSession(handle)
	if session == nil {
		return -1
	}
	return C.int64_t(session.IdleTime())
}

// httpcloak_session_is_active returns 1 if the session is still usable (Close
// has not run), 0 if closed or the handle is invalid.
//
//export httpcloak_session_is_active
func httpcloak_session_is_active(handle C.int64_t) (hcRet C.int) {
	defer guardInt("httpcloak_session_is_active", &hcRet)
	session := getSession(handle)
	if session == nil {
		return 0
	}
	if session.IsActive() {
		return 1
	}
	return 0
}

// httpcloak_session_touch resets the idle timer to now without issuing a
// request. No-op if the handle is invalid.
//
//export httpcloak_session_touch
func httpcloak_session_touch(handle C.int64_t) {
	defer guardVoid("httpcloak_session_touch")
	session := getSession(handle)
	if session == nil {
		return
	}
	session.Touch()
}

//export httpcloak_session_set_conditional_cache
func httpcloak_session_set_conditional_cache(handle C.int64_t, enabled C.int) {
	defer guardVoid("httpcloak_session_set_conditional_cache")
	session := getSession(handle)
	if session == nil {
		return
	}
	session.SetConditionalCacheEnabled(enabled != 0)
}

//export httpcloak_session_get_conditional_cache
func httpcloak_session_get_conditional_cache(handle C.int64_t) (hcRet C.int) {
	defer guardInt("httpcloak_session_get_conditional_cache", &hcRet)
	session := getSession(handle)
	if session == nil {
		return 0
	}
	if session.ConditionalCacheEnabled() {
		return 1
	}
	return 0
}

//export httpcloak_session_set_client_hints
func httpcloak_session_set_client_hints(handle C.int64_t, enabled C.int) {
	defer guardVoid("httpcloak_session_set_client_hints")
	session := getSession(handle)
	if session == nil {
		return
	}
	session.SetClientHintsEnabled(enabled != 0)
}

//export httpcloak_session_get_client_hints
func httpcloak_session_get_client_hints(handle C.int64_t) (hcRet C.int) {
	defer guardInt("httpcloak_session_get_client_hints", &hcRet)
	session := getSession(handle)
	if session == nil {
		return 0
	}
	if session.ClientHintsEnabled() {
		return 1
	}
	return 0
}

//export httpcloak_session_set_high_entropy_client_hints
func httpcloak_session_set_high_entropy_client_hints(handle C.int64_t, enabled C.int) {
	defer guardVoid("httpcloak_session_set_high_entropy_client_hints")
	session := getSession(handle)
	if session == nil {
		return
	}
	session.SetHighEntropyClientHintsEnabled(enabled != 0)
}

//export httpcloak_session_get_high_entropy_client_hints
func httpcloak_session_get_high_entropy_client_hints(handle C.int64_t) (hcRet C.int) {
	defer guardInt("httpcloak_session_get_high_entropy_client_hints", &hcRet)
	session := getSession(handle)
	if session == nil {
		return 0
	}
	if session.HighEntropyClientHintsEnabled() {
		return 1
	}
	return 0
}

//export httpcloak_session_set_follow_redirects
func httpcloak_session_set_follow_redirects(handle C.int64_t, enabled C.int) {
	defer guardVoid("httpcloak_session_set_follow_redirects")
	session := getSession(handle)
	if session == nil {
		return
	}
	session.SetFollowRedirects(enabled != 0)
}

//export httpcloak_session_get_follow_redirects
func httpcloak_session_get_follow_redirects(handle C.int64_t) (hcRet C.int) {
	defer guardInt("httpcloak_session_get_follow_redirects", &hcRet)
	session := getSession(handle)
	if session == nil {
		return 0
	}
	if session.FollowRedirects() {
		return 1
	}
	return 0
}

//export httpcloak_session_set_max_redirects
func httpcloak_session_set_max_redirects(handle C.int64_t, max C.int) {
	defer guardVoid("httpcloak_session_set_max_redirects")
	session := getSession(handle)
	if session == nil {
		return
	}
	session.SetMaxRedirects(int(max))
}

//export httpcloak_session_get_max_redirects
func httpcloak_session_get_max_redirects(handle C.int64_t) (hcRet C.int) {
	defer guardInt("httpcloak_session_get_max_redirects", &hcRet)
	session := getSession(handle)
	if session == nil {
		return 0
	}
	return C.int(session.MaxRedirects())
}

// ============================================================================
// Utility Functions
// ============================================================================

//export httpcloak_free_string
func httpcloak_free_string(str *C.char) {
	defer guardVoid("httpcloak_free_string")
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

// libVersion is the one place the C ABI reports a version from. It has to be
// bumped with the nine binding version files and the five optionalDependencies
// pins; it was missed for 1.7.2-beta.2, so every binding reported 1.6.11 off a
// 1.7.2b2 wheel.
const libVersion = "1.7.2"

// httpcloak_trim_memory returns freed memory to the operating system and blocks
// until it has.
//
// Freeing a session makes its memory collectable, which is a different thing
// from giving it back: Go's scavenger releases pages lazily, and on Linux with
// MADV_FREE they stay counted against the process until the kernel wants them.
// So RSS stays flat long after the sessions are gone.
//
// Deliberately not called by httpcloak_session_free. It stops the world for a
// full collection, so a caller closing sessions steadily would pay that every
// time. Call it once between batches instead.
//
// Process-wide, not per session.
//
//export httpcloak_trim_memory
func httpcloak_trim_memory() {
	defer guardVoid("httpcloak_trim_memory")
	httpcloak.TrimMemory()
}

//export httpcloak_version
func httpcloak_version() (hcRet *C.char) {
	defer guardCharP("httpcloak_version", &hcRet)
	return C.CString(libVersion)
}

//export httpcloak_available_presets
func httpcloak_available_presets() (hcRet *C.char) {
	defer guardCharP("httpcloak_available_presets", &hcRet)
	// Return preset names with their supported protocols
	presets := fingerprint.AvailableWithInfo()
	data, _ := json.Marshal(presets)
	return C.CString(string(data))
}

//export httpcloak_set_ech_dns_servers
func httpcloak_set_ech_dns_servers(serversJSON *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_set_ech_dns_servers", &hcRet)
	if serversJSON == nil {
		// Reset to defaults
		dns.SetECHDNSServers(nil)
		return nil
	}

	jsonStr := C.GoString(serversJSON)
	if jsonStr == "" || jsonStr == "null" || jsonStr == "[]" {
		// Reset to defaults
		dns.SetECHDNSServers(nil)
		return nil
	}

	var servers []string
	if err := json.Unmarshal([]byte(jsonStr), &servers); err != nil {
		return C.CString(err.Error())
	}

	dns.SetECHDNSServers(servers)
	return nil
}

//export httpcloak_get_ech_dns_servers
func httpcloak_get_ech_dns_servers() (hcRet *C.char) {
	defer guardCharP("httpcloak_get_ech_dns_servers", &hcRet)
	servers := dns.GetECHDNSServers()
	data, _ := json.Marshal(servers)
	return C.CString(string(data))
}

// ============================================================================
// Error Definitions
// ============================================================================

var (
	ErrInvalidSession    = errors.New("invalid session handle")
	ErrInvalidStream     = errors.New("invalid stream handle")
	ErrInvalidLocalProxy = errors.New("invalid local proxy handle")
	ErrInvalidPresetPool = errors.New("invalid preset pool handle")
)

// ============================================================================
// Session Cache Backend (C Callback Wrapper)
// ============================================================================

// CSessionCacheBackend wraps C callbacks to implement transport.SessionCacheBackend
type CSessionCacheBackend struct {
	getCallback    C.session_cache_get_callback
	putCallback    C.session_cache_put_callback
	deleteCallback C.session_cache_delete_callback
	echGetCallback C.ech_cache_get_callback
	echPutCallback C.ech_cache_put_callback
}

// NewCSessionCacheBackend creates a new C callback-backed session cache
func NewCSessionCacheBackend(
	getCallback C.session_cache_get_callback,
	putCallback C.session_cache_put_callback,
	deleteCallback C.session_cache_delete_callback,
	echGetCallback C.ech_cache_get_callback,
	echPutCallback C.ech_cache_put_callback,
) *CSessionCacheBackend {
	return &CSessionCacheBackend{
		getCallback:    getCallback,
		putCallback:    putCallback,
		deleteCallback: deleteCallback,
		echGetCallback: echGetCallback,
		echPutCallback: echPutCallback,
	}
}

// Get retrieves a TLS session from the external cache
func (c *CSessionCacheBackend) Get(ctx context.Context, key string) (*transport.TLSSessionState, error) {
	if c.getCallback == nil {
		return nil, nil
	}

	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC))

	resultC := C.invoke_cache_get(c.getCallback, keyC)
	if resultC == nil {
		return nil, nil // Not found
	}
	// Note: Don't free resultC - it's managed by the callback caller (Python/Node)
	// We only copy the string data with C.GoString

	resultJSON := C.GoString(resultC)
	if resultJSON == "" {
		return nil, nil
	}

	var session transport.TLSSessionState
	if err := json.Unmarshal([]byte(resultJSON), &session); err != nil {
		return nil, fmt.Errorf("decode session: %w", err)
	}

	return &session, nil
}

// Put stores a TLS session in the external cache
func (c *CSessionCacheBackend) Put(ctx context.Context, key string, session *transport.TLSSessionState, ttl time.Duration) error {
	if c.putCallback == nil {
		return nil
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}

	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC))

	valueC := C.CString(string(sessionJSON))
	defer C.free(unsafe.Pointer(valueC))

	ttlSeconds := int64(ttl.Seconds())
	result := C.invoke_cache_put(c.putCallback, keyC, valueC, C.int64_t(ttlSeconds))
	if result != 0 {
		return fmt.Errorf("cache put failed with code %d", result)
	}

	return nil
}

// Delete removes a session from the external cache
func (c *CSessionCacheBackend) Delete(ctx context.Context, key string) error {
	if c.deleteCallback == nil {
		return nil
	}

	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC))

	result := C.invoke_cache_delete(c.deleteCallback, keyC)
	if result != 0 {
		return fmt.Errorf("cache delete failed with code %d", result)
	}

	return nil
}

// GetECHConfig retrieves ECH config from the external cache
func (c *CSessionCacheBackend) GetECHConfig(ctx context.Context, key string) ([]byte, error) {
	if c.echGetCallback == nil {
		return nil, nil
	}

	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC))

	resultC := C.invoke_ech_get(c.echGetCallback, keyC)
	if resultC == nil {
		return nil, nil // Not found
	}
	// Note: Don't free resultC - it's managed by the callback caller (Python/Node)

	resultBase64 := C.GoString(resultC)
	if resultBase64 == "" {
		return nil, nil
	}

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(resultBase64)
	if err != nil {
		return nil, fmt.Errorf("decode ech config: %w", err)
	}

	return data, nil
}

// PutECHConfig stores ECH config in the external cache
func (c *CSessionCacheBackend) PutECHConfig(ctx context.Context, key string, config []byte, ttl time.Duration) error {
	if c.echPutCallback == nil {
		return nil
	}

	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC))

	valueBase64 := base64.StdEncoding.EncodeToString(config)
	valueC := C.CString(valueBase64)
	defer C.free(unsafe.Pointer(valueC))

	ttlSeconds := int64(ttl.Seconds())
	result := C.invoke_ech_put(c.echPutCallback, keyC, valueC, C.int64_t(ttlSeconds))
	if result != 0 {
		return fmt.Errorf("ech cache put failed with code %d", result)
	}

	return nil
}

// CErrorCallback wraps a C error callback
type CErrorCallback struct {
	callback C.session_cache_error_callback
}

// Call invokes the C error callback
func (c *CErrorCallback) Call(operation, key string, err error) {
	if c.callback == nil || err == nil {
		return
	}

	opC := C.CString(operation)
	defer C.free(unsafe.Pointer(opC))

	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC))

	errC := C.CString(err.Error())
	defer C.free(unsafe.Pointer(errC))

	C.invoke_cache_error(c.callback, opC, keyC, errC)
}

// ============================================================================
// Async Session Cache Backend (for async JS callbacks like Redis)
// ============================================================================

// asyncCacheGetResult holds the result of an async cache get operation
type asyncCacheGetResult struct {
	value string
	found bool
}

// asyncCacheOpResult holds the result of an async cache put/delete operation
type asyncCacheOpResult struct {
	success bool
}

// Pending async cache requests
var (
	asyncCacheRequestsMu sync.RWMutex
	asyncCacheRequestID  int64
	asyncCacheGetResults = make(map[int64]chan asyncCacheGetResult)
	asyncCacheOpResults  = make(map[int64]chan asyncCacheOpResult)
	asyncCacheTimeout    = 30 * time.Second // Timeout for async operations
)

// CAsyncSessionCacheBackend wraps async C callbacks to implement transport.SessionCacheBackend
type CAsyncSessionCacheBackend struct {
	getCallback    C.async_cache_get_callback
	putCallback    C.async_cache_put_callback
	deleteCallback C.async_cache_delete_callback
	echGetCallback C.async_ech_get_callback
	echPutCallback C.async_ech_put_callback
}

// NewCAsyncSessionCacheBackend creates a new async C callback-backed session cache
func NewCAsyncSessionCacheBackend(
	getCallback C.async_cache_get_callback,
	putCallback C.async_cache_put_callback,
	deleteCallback C.async_cache_delete_callback,
	echGetCallback C.async_ech_get_callback,
	echPutCallback C.async_ech_put_callback,
) *CAsyncSessionCacheBackend {
	return &CAsyncSessionCacheBackend{
		getCallback:    getCallback,
		putCallback:    putCallback,
		deleteCallback: deleteCallback,
		echGetCallback: echGetCallback,
		echPutCallback: echPutCallback,
	}
}

// registerGetRequest creates a new async get request and returns the request ID and result channel
func registerGetRequest() (int64, chan asyncCacheGetResult) {
	asyncCacheRequestsMu.Lock()
	defer asyncCacheRequestsMu.Unlock()

	asyncCacheRequestID++
	id := asyncCacheRequestID
	ch := make(chan asyncCacheGetResult, 1)
	asyncCacheGetResults[id] = ch
	return id, ch
}

// registerOpRequest creates a new async op request and returns the request ID and result channel
func registerOpRequest() (int64, chan asyncCacheOpResult) {
	asyncCacheRequestsMu.Lock()
	defer asyncCacheRequestsMu.Unlock()

	asyncCacheRequestID++
	id := asyncCacheRequestID
	ch := make(chan asyncCacheOpResult, 1)
	asyncCacheOpResults[id] = ch
	return id, ch
}

// cleanupGetRequest removes a get request from the pending map
func cleanupGetRequest(id int64) {
	asyncCacheRequestsMu.Lock()
	defer asyncCacheRequestsMu.Unlock()
	delete(asyncCacheGetResults, id)
}

// cleanupOpRequest removes an op request from the pending map
func cleanupOpRequest(id int64) {
	asyncCacheRequestsMu.Lock()
	defer asyncCacheRequestsMu.Unlock()
	delete(asyncCacheOpResults, id)
}

// Get retrieves a TLS session from the external async cache
func (c *CAsyncSessionCacheBackend) Get(ctx context.Context, key string) (*transport.TLSSessionState, error) {
	if c.getCallback == nil {
		return nil, nil
	}

	// Register request and get channel
	requestID, resultCh := registerGetRequest()
	defer cleanupGetRequest(requestID)

	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC))

	// Invoke async callback - JS will call httpcloak_async_cache_get_result when done
	C.invoke_async_cache_get(c.getCallback, C.int64_t(requestID), keyC)

	// Wait for result with timeout
	select {
	case result := <-resultCh:
		if !result.found || result.value == "" {
			return nil, nil
		}
		var session transport.TLSSessionState
		if err := json.Unmarshal([]byte(result.value), &session); err != nil {
			return nil, fmt.Errorf("decode session: %w", err)
		}
		return &session, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(asyncCacheTimeout):
		return nil, fmt.Errorf("async cache get timeout")
	}
}

// Put stores a TLS session in the external async cache
func (c *CAsyncSessionCacheBackend) Put(ctx context.Context, key string, session *transport.TLSSessionState, ttl time.Duration) error {
	if c.putCallback == nil {
		return nil
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}

	// Register request and get channel
	requestID, resultCh := registerOpRequest()
	defer cleanupOpRequest(requestID)

	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC))

	valueC := C.CString(string(sessionJSON))
	defer C.free(unsafe.Pointer(valueC))

	ttlSeconds := int64(ttl.Seconds())

	// Invoke async callback
	C.invoke_async_cache_put(c.putCallback, C.int64_t(requestID), keyC, valueC, C.int64_t(ttlSeconds))

	// Wait for result with timeout
	select {
	case result := <-resultCh:
		if !result.success {
			return fmt.Errorf("async cache put failed")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(asyncCacheTimeout):
		return fmt.Errorf("async cache put timeout")
	}
}

// Delete removes a session from the external async cache
func (c *CAsyncSessionCacheBackend) Delete(ctx context.Context, key string) error {
	if c.deleteCallback == nil {
		return nil
	}

	// Register request and get channel
	requestID, resultCh := registerOpRequest()
	defer cleanupOpRequest(requestID)

	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC))

	// Invoke async callback
	C.invoke_async_cache_delete(c.deleteCallback, C.int64_t(requestID), keyC)

	// Wait for result with timeout
	select {
	case result := <-resultCh:
		if !result.success {
			return fmt.Errorf("async cache delete failed")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(asyncCacheTimeout):
		return fmt.Errorf("async cache delete timeout")
	}
}

// GetECHConfig retrieves ECH config from the external async cache
func (c *CAsyncSessionCacheBackend) GetECHConfig(ctx context.Context, key string) ([]byte, error) {
	if c.echGetCallback == nil {
		return nil, nil
	}

	// Register request and get channel
	requestID, resultCh := registerGetRequest()
	defer cleanupGetRequest(requestID)

	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC))

	// Invoke async callback
	C.invoke_async_ech_get(c.echGetCallback, C.int64_t(requestID), keyC)

	// Wait for result with timeout
	select {
	case result := <-resultCh:
		if !result.found || result.value == "" {
			return nil, nil
		}
		// Decode base64
		data, err := base64.StdEncoding.DecodeString(result.value)
		if err != nil {
			return nil, fmt.Errorf("decode ech config: %w", err)
		}
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(asyncCacheTimeout):
		return nil, fmt.Errorf("async ech get timeout")
	}
}

// PutECHConfig stores ECH config in the external async cache
func (c *CAsyncSessionCacheBackend) PutECHConfig(ctx context.Context, key string, config []byte, ttl time.Duration) error {
	if c.echPutCallback == nil {
		return nil
	}

	// Register request and get channel
	requestID, resultCh := registerOpRequest()
	defer cleanupOpRequest(requestID)

	keyC := C.CString(key)
	defer C.free(unsafe.Pointer(keyC))

	valueBase64 := base64.StdEncoding.EncodeToString(config)
	valueC := C.CString(valueBase64)
	defer C.free(unsafe.Pointer(valueC))

	ttlSeconds := int64(ttl.Seconds())

	// Invoke async callback
	C.invoke_async_ech_put(c.echPutCallback, C.int64_t(requestID), keyC, valueC, C.int64_t(ttlSeconds))

	// Wait for result with timeout
	select {
	case result := <-resultCh:
		if !result.success {
			return fmt.Errorf("async ech put failed")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(asyncCacheTimeout):
		return fmt.Errorf("async ech put timeout")
	}
}

//export httpcloak_async_cache_get_result
func httpcloak_async_cache_get_result(requestID C.int64_t, value *C.char) {
	defer guardVoid("httpcloak_async_cache_get_result")
	asyncCacheRequestsMu.RLock()
	ch, ok := asyncCacheGetResults[int64(requestID)]
	asyncCacheRequestsMu.RUnlock()

	if !ok {
		return // Request already cleaned up or invalid
	}

	result := asyncCacheGetResult{found: value != nil}
	if value != nil {
		result.value = C.GoString(value)
	}

	select {
	case ch <- result:
	default:
		// Channel full or closed
	}
}

//export httpcloak_async_cache_op_result
func httpcloak_async_cache_op_result(requestID C.int64_t, success C.int) {
	defer guardVoid("httpcloak_async_cache_op_result")
	asyncCacheRequestsMu.RLock()
	ch, ok := asyncCacheOpResults[int64(requestID)]
	asyncCacheRequestsMu.RUnlock()

	if !ok {
		return // Request already cleaned up or invalid
	}

	result := asyncCacheOpResult{success: success == 0}

	select {
	case ch <- result:
	default:
		// Channel full or closed
	}
}

// Global session cache callbacks (set via httpcloak_set_session_cache_callbacks or httpcloak_set_async_session_cache_callbacks)
var (
	globalSessionCacheMu           sync.RWMutex
	globalSessionCacheBackend      *CSessionCacheBackend      // Sync backend
	globalAsyncSessionCacheBackend *CAsyncSessionCacheBackend // Async backend
	globalSessionCacheError        *CErrorCallback
)

//export httpcloak_set_session_cache_callbacks
func httpcloak_set_session_cache_callbacks(
	getCallback C.session_cache_get_callback,
	putCallback C.session_cache_put_callback,
	deleteCallback C.session_cache_delete_callback,
	echGetCallback C.ech_cache_get_callback,
	echPutCallback C.ech_cache_put_callback,
	errorCallback C.session_cache_error_callback,
) {
	defer guardVoid("httpcloak_set_session_cache_callbacks")
	globalSessionCacheMu.Lock()
	defer globalSessionCacheMu.Unlock()

	// Clear async backend when setting sync callbacks
	globalAsyncSessionCacheBackend = nil

	if getCallback == nil && putCallback == nil {
		// Clear callbacks
		globalSessionCacheBackend = nil
		globalSessionCacheError = nil
		return
	}

	globalSessionCacheBackend = NewCSessionCacheBackend(
		getCallback,
		putCallback,
		deleteCallback,
		echGetCallback,
		echPutCallback,
	)

	if errorCallback != nil {
		globalSessionCacheError = &CErrorCallback{callback: errorCallback}
	} else {
		globalSessionCacheError = nil
	}
}

//export httpcloak_set_async_session_cache_callbacks
func httpcloak_set_async_session_cache_callbacks(
	getCallback C.async_cache_get_callback,
	putCallback C.async_cache_put_callback,
	deleteCallback C.async_cache_delete_callback,
	echGetCallback C.async_ech_get_callback,
	echPutCallback C.async_ech_put_callback,
	errorCallback C.session_cache_error_callback,
) {
	defer guardVoid("httpcloak_set_async_session_cache_callbacks")
	globalSessionCacheMu.Lock()
	defer globalSessionCacheMu.Unlock()

	// Clear sync backend when setting async callbacks
	globalSessionCacheBackend = nil

	if getCallback == nil && putCallback == nil {
		// Clear callbacks
		globalAsyncSessionCacheBackend = nil
		globalSessionCacheError = nil
		return
	}

	globalAsyncSessionCacheBackend = NewCAsyncSessionCacheBackend(
		getCallback,
		putCallback,
		deleteCallback,
		echGetCallback,
		echPutCallback,
	)

	if errorCallback != nil {
		globalSessionCacheError = &CErrorCallback{callback: errorCallback}
	} else {
		globalSessionCacheError = nil
	}
}

//export httpcloak_clear_session_cache_callbacks
func httpcloak_clear_session_cache_callbacks() {
	defer guardVoid("httpcloak_clear_session_cache_callbacks")
	globalSessionCacheMu.Lock()
	defer globalSessionCacheMu.Unlock()
	globalSessionCacheBackend = nil
	globalAsyncSessionCacheBackend = nil
	globalSessionCacheError = nil
}

// getSessionCacheBackend returns the global session cache backend if configured (sync or async)
func getSessionCacheBackend() (transport.SessionCacheBackend, transport.ErrorCallback) {
	globalSessionCacheMu.RLock()
	defer globalSessionCacheMu.RUnlock()

	var errorCallback transport.ErrorCallback
	if globalSessionCacheError != nil {
		ec := globalSessionCacheError // Capture for closure
		errorCallback = func(operation, key string, err error) {
			ec.Call(operation, key, err)
		}
	}

	// Prefer async backend if set
	if globalAsyncSessionCacheBackend != nil {
		return globalAsyncSessionCacheBackend, errorCallback
	}

	if globalSessionCacheBackend != nil {
		return globalSessionCacheBackend, errorCallback
	}

	return nil, nil
}

// ============================================================================
// Local Proxy Management
// ============================================================================

// Local proxy handle management
var (
	localProxyMu      sync.RWMutex
	localProxies      = make(map[int64]*httpcloak.LocalProxy)
	localProxyCounter int64
)

// LocalProxyConfig holds configuration for starting a local proxy
type LocalProxyConfig struct {
	Port           int    `json:"port,omitempty"`            // Port to listen on (0 = auto)
	Preset         string `json:"preset,omitempty"`          // Browser fingerprint preset
	Timeout        int    `json:"timeout,omitempty"`         // Request timeout in seconds
	MaxConnections int    `json:"max_connections,omitempty"` // Max concurrent connections
	TCPProxy       string `json:"tcp_proxy,omitempty"`       // Upstream TCP proxy
	UDPProxy       string `json:"udp_proxy,omitempty"`       // Upstream UDP proxy
	TLSOnly        bool   `json:"tls_only,omitempty"`        // TLS-only mode (skip preset HTTP headers)
}

//export httpcloak_local_proxy_start
func httpcloak_local_proxy_start(configJSON *C.char) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_local_proxy_start", &hcRet)
	config := LocalProxyConfig{
		Port:           0,
		Preset:         "chrome-146",
		Timeout:        30,
		MaxConnections: 1000,
	}

	if configJSON != nil {
		jsonStr := C.GoString(configJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &config)
		}
	}

	var opts []httpcloak.LocalProxyOption
	if config.Preset != "" {
		opts = append(opts, httpcloak.WithProxyPreset(config.Preset))
	}
	if config.Timeout > 0 {
		opts = append(opts, httpcloak.WithProxyTimeout(time.Duration(config.Timeout)*time.Second))
	}
	if config.MaxConnections > 0 {
		opts = append(opts, httpcloak.WithProxyMaxConnections(config.MaxConnections))
	}
	if config.TCPProxy != "" || config.UDPProxy != "" {
		opts = append(opts, httpcloak.WithProxyUpstream(config.TCPProxy, config.UDPProxy))
	}
	if config.TLSOnly {
		opts = append(opts, httpcloak.WithProxyTLSOnly())
	}

	// Handle session cache if configured globally
	backend, errorCallback := getSessionCacheBackend()
	if backend != nil {
		opts = append(opts, httpcloak.WithProxySessionCache(backend, errorCallback))
	}

	proxy, err := httpcloak.StartLocalProxy(config.Port, opts...)
	if err != nil {
		return -1
	}

	localProxyMu.Lock()
	localProxyCounter++
	handle := localProxyCounter
	localProxies[handle] = proxy
	localProxyMu.Unlock()

	return C.int64_t(handle)
}

//export httpcloak_local_proxy_stop
func httpcloak_local_proxy_stop(handle C.int64_t) {
	defer guardVoid("httpcloak_local_proxy_stop")
	localProxyMu.Lock()
	proxy, exists := localProxies[int64(handle)]
	if exists {
		delete(localProxies, int64(handle))
	}
	localProxyMu.Unlock()

	if proxy != nil {
		proxy.Stop()
	}
}

//export httpcloak_local_proxy_get_port
func httpcloak_local_proxy_get_port(handle C.int64_t) (hcRet C.int) {
	defer guardInt("httpcloak_local_proxy_get_port", &hcRet)
	localProxyMu.RLock()
	proxy, exists := localProxies[int64(handle)]
	localProxyMu.RUnlock()

	if !exists || proxy == nil {
		return -1
	}

	return C.int(proxy.Port())
}

//export httpcloak_local_proxy_is_running
func httpcloak_local_proxy_is_running(handle C.int64_t) (hcRet C.int) {
	defer guardInt("httpcloak_local_proxy_is_running", &hcRet)
	localProxyMu.RLock()
	proxy, exists := localProxies[int64(handle)]
	localProxyMu.RUnlock()

	if !exists || proxy == nil {
		return 0
	}

	if proxy.IsRunning() {
		return 1
	}
	return 0
}

//export httpcloak_local_proxy_get_stats
func httpcloak_local_proxy_get_stats(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_local_proxy_get_stats", &hcRet)
	localProxyMu.RLock()
	proxy, exists := localProxies[int64(handle)]
	localProxyMu.RUnlock()

	if !exists || proxy == nil {
		return makeErrorJSON(ErrInvalidLocalProxy)
	}

	stats := proxy.Stats()
	data, _ := json.Marshal(stats)
	return C.CString(string(data))
}

//export httpcloak_local_proxy_register_session
func httpcloak_local_proxy_register_session(proxyHandle C.int64_t, sessionID *C.char, sessionHandle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_local_proxy_register_session", &hcRet)
	localProxyMu.RLock()
	proxy, exists := localProxies[int64(proxyHandle)]
	localProxyMu.RUnlock()

	if !exists || proxy == nil {
		return makeErrorJSON(ErrInvalidLocalProxy)
	}

	session := getSession(sessionHandle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	id := C.GoString(sessionID)
	if err := proxy.RegisterSession(id, session); err != nil {
		return makeErrorJSON(err)
	}

	return nil // Success
}

//export httpcloak_local_proxy_unregister_session
func httpcloak_local_proxy_unregister_session(proxyHandle C.int64_t, sessionID *C.char) (hcRet C.int) {
	defer guardInt("httpcloak_local_proxy_unregister_session", &hcRet)
	localProxyMu.RLock()
	proxy, exists := localProxies[int64(proxyHandle)]
	localProxyMu.RUnlock()

	if !exists || proxy == nil {
		return 0 // Proxy not found
	}

	id := C.GoString(sessionID)
	session := proxy.UnregisterSession(id)
	if session != nil {
		return 1 // Successfully unregistered
	}
	return 0 // Session not found
}

// httpcloak_local_proxy_list_sessions returns a JSON array of the session IDs
// currently registered on the given LocalProxy (the same IDs that the
// X-HTTPCloak-Session header accepts). The caller owns the returned string and
// must free it via httpcloak_free_string. Returns "[]" if no sessions are
// registered, or nil if the proxy handle is invalid.
//
//export httpcloak_local_proxy_list_sessions
func httpcloak_local_proxy_list_sessions(proxyHandle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_local_proxy_list_sessions", &hcRet)
	localProxyMu.RLock()
	proxy, exists := localProxies[int64(proxyHandle)]
	localProxyMu.RUnlock()

	if !exists || proxy == nil {
		return nil
	}

	ids := proxy.ListSessions()
	if ids == nil {
		ids = []string{}
	}
	data, err := json.Marshal(ids)
	if err != nil {
		return nil
	}
	return C.CString(string(data))
}

// httpcloak_local_proxy_has_session returns 1 if a session with the given ID
// is currently registered on the LocalProxy, 0 otherwise. Cheaper than
// list_sessions when callers only need an existence check (no JSON marshal).
//
//export httpcloak_local_proxy_has_session
func httpcloak_local_proxy_has_session(proxyHandle C.int64_t, sessionID *C.char) (hcRet C.int) {
	defer guardInt("httpcloak_local_proxy_has_session", &hcRet)
	localProxyMu.RLock()
	proxy, exists := localProxies[int64(proxyHandle)]
	localProxyMu.RUnlock()

	if !exists || proxy == nil {
		return 0
	}

	id := C.GoString(sessionID)
	if proxy.GetSession(id) != nil {
		return 1
	}
	return 0
}

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

	// The order the peer sent its headers in, nil on HTTP/1.1. Trailers are not
	// here: on a streamed response they have not arrived yet, so they are read
	// after the body through httpcloak_stream_trailer.
	HeaderOrder []string `json:"header_order,omitempty"`

	// StreamHandle is set only by the async entry point, which has to hand the
	// handle back through the callback because there is no return value to put
	// it in. The synchronous path returns the handle directly and leaves this
	// zero, so a caller can tell the two apart.
	StreamHandle int64 `json:"stream_handle,omitempty"`
}

// buildStreamMetadata is what stream_get_metadata returns, factored out so the
// async entry point hands back the same shape rather than a second one that
// drifts from it.
func buildStreamMetadata(resp *httpcloak.StreamResponse) StreamMetadata {
	return StreamMetadata{
		StatusCode:    resp.StatusCode,
		Headers:       resp.Headers,
		HeaderOrder:   resp.HeaderOrder,
		FinalURL:      resp.FinalURL,
		Protocol:      resp.Protocol,
		ContentLength: resp.ContentLength,
		Cookies:       parseSetCookieHeaders(resp.Headers),
	}
}

func getStream(handle int64) *httpcloak.StreamResponse {
	streamMu.RLock()
	defer streamMu.RUnlock()
	if e := streams[handle]; e != nil {
		return e.resp
	}
	return nil
}

//export httpcloak_stream_get
func httpcloak_stream_get(sessionHandle C.int64_t, url *C.char, optionsJSON *C.char) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_stream_get", &hcRet)
	clearLastError(sessionHandle)
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
		Method:                        "GET",
		URL:                           urlStr,
		Headers:                       buildHeaders(options.Headers, options.FetchMode),
		FollowRedirects:               options.FollowRedirects,
		DisableConditionalCache:       options.DisableConditionalCache,
		DisableClientHints:            options.DisableClientHints,
		DisableHighEntropyClientHints: options.DisableHighEntropyClientHints,
		DisableRedirectReferer:        options.DisableRedirectReferer,
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
	streams[handle] = &streamEntry{resp: resp, cancel: cancel}
	streamMu.Unlock()

	return C.int64_t(handle)
}

//export httpcloak_stream_post
func httpcloak_stream_post(sessionHandle C.int64_t, url *C.char, body *C.char, optionsJSON *C.char) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_stream_post", &hcRet)
	clearLastError(sessionHandle)
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
		Method:                        "POST",
		URL:                           urlStr,
		Headers:                       buildHeaders(options.Headers, options.FetchMode),
		Body:                          bodyReader,
		FollowRedirects:               options.FollowRedirects,
		DisableConditionalCache:       options.DisableConditionalCache,
		DisableClientHints:            options.DisableClientHints,
		DisableHighEntropyClientHints: options.DisableHighEntropyClientHints,
		DisableRedirectReferer:        options.DisableRedirectReferer,
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
	streams[handle] = &streamEntry{resp: resp, cancel: cancel}
	streamMu.Unlock()

	return C.int64_t(handle)
}

//export httpcloak_stream_request
func httpcloak_stream_request(sessionHandle C.int64_t, requestJSON *C.char) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_stream_request", &hcRet)
	clearLastError(sessionHandle)
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
		Method:                        config.Method,
		URL:                           config.URL,
		Headers:                       buildHeaders(config.Headers, config.FetchMode),
		ExactHeaders:                  buildExactHeaders(config.ExactHeaders),
		HeaderOrder:                   config.HeaderOrder,
		Body:                          bodyReader,
		FollowRedirects:               config.FollowRedirects,
		DisableConditionalCache:       config.DisableConditionalCache,
		DisableClientHints:            config.DisableClientHints,
		DisableHighEntropyClientHints: config.DisableHighEntropyClientHints,
		DisableRedirectReferer:        config.DisableRedirectReferer,
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
	streams[handle] = &streamEntry{resp: resp, cancel: cancel}
	streamMu.Unlock()

	return C.int64_t(handle)
}

// The async counterpart of httpcloak_stream_request. The synchronous entry
// point blocks the calling thread until the response headers arrive, which for a
// stream can be the whole point of the request: a caller opening several long
// lived streams had to spend a thread on each one while it waited, and a caller
// on a single-threaded runtime could not open one at all without stalling
// everything else.
//
// The callback receives the same JSON the synchronous path returns through
// stream_get_metadata, with the stream handle added, so the caller can go
// straight to stream_read without a second round trip. On failure it receives an
// error object and no handle.
//
// The stream handle it hands back is owned by the caller exactly as the
// synchronous one is: it stays open, and its context stays uncancelled, until
// stream_close. Cancelling before the callback fires is done through the
// callback ID, the same way it is for the other async entry points.
//
//export httpcloak_stream_request_async
func httpcloak_stream_request_async(sessionHandle C.int64_t, requestJSON *C.char, callbackID C.int64_t) {
	defer guardVoid("httpcloak_stream_request_async")
	session := getSession(sessionHandle)

	var config RequestConfig
	if requestJSON != nil {
		if err := json.Unmarshal([]byte(C.GoString(requestJSON)), &config); err != nil {
			go func() {
				errJSON, _ := json.Marshal(ErrorResponse{Error: "invalid request JSON: " + err.Error()})
				invokeCallback(int64(callbackID), "", string(errJSON))
			}()
			return
		}
	}

	// Cancellation before the response arrives goes through the callback ID, as
	// it does for the other async entry points. Once the stream exists its
	// lifetime belongs to the stream handle, so this cancel is handed over to
	// the stream entry rather than deferred away.
	ctx, cancel := context.WithCancel(context.Background())
	callbackMu.Lock()
	cancelFuncs[int64(callbackID)] = cancel
	callbackMu.Unlock()

	go func() {
		handedOver := false
		defer func() {
			if !handedOver {
				cancel()
			}
			callbackMu.Lock()
			delete(cancelFuncs, int64(callbackID))
			callbackMu.Unlock()
		}()
		defer guardAsync("stream_request_async goroutine", int64(callbackID))

		fail := func(msg string) {
			errJSON, _ := json.Marshal(ErrorResponse{Error: msg})
			invokeCallback(int64(callbackID), "", string(errJSON))
		}

		if session == nil {
			fail(ErrInvalidSession.Error())
			return
		}
		if config.Method == "" {
			config.Method = "GET"
		}

		// Same default as the synchronous path: a stream that never sends is a
		// leaked goroutine and a held connection, so it gets an outer bound.
		streamCtx := ctx
		var timeoutCancel context.CancelFunc
		if config.Timeout > 0 {
			streamCtx, timeoutCancel = context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
		} else {
			streamCtx, timeoutCancel = context.WithTimeout(ctx, 2*time.Minute)
		}

		var bodyReader io.Reader
		if config.Body != "" {
			bodyBytes, err := decodeRequestBody(config.Body, config.BodyEncoding)
			if err != nil {
				timeoutCancel()
				fail(err.Error())
				return
			}
			bodyReader = bytes.NewReader(bodyBytes)
		}

		req := &httpcloak.Request{
			Method:                        config.Method,
			URL:                           config.URL,
			Headers:                       buildHeaders(config.Headers, config.FetchMode),
			ExactHeaders:                  buildExactHeaders(config.ExactHeaders),
			HeaderOrder:                   config.HeaderOrder,
			Body:                          bodyReader,
			FollowRedirects:               config.FollowRedirects,
			DisableConditionalCache:       config.DisableConditionalCache,
			DisableClientHints:            config.DisableClientHints,
			DisableHighEntropyClientHints: config.DisableHighEntropyClientHints,
			DisableRedirectReferer:        config.DisableRedirectReferer,
		}

		resp, err := session.DoStream(streamCtx, req)
		if err != nil {
			timeoutCancel()
			fail(err.Error())
			return
		}

		// The stream owns both cancels from here: the caller closes it, not us.
		release := func() {
			timeoutCancel()
			cancel()
		}
		streamMu.Lock()
		streamCounter++
		handle := streamCounter
		streams[handle] = &streamEntry{resp: resp, cancel: release}
		streamMu.Unlock()
		handedOver = true

		meta := buildStreamMetadata(resp)
		meta.StreamHandle = handle
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			fail("encode stream metadata: " + err.Error())
			return
		}
		invokeCallback(int64(callbackID), string(metaJSON), "")
	}()
}

//export httpcloak_stream_get_metadata
func httpcloak_stream_get_metadata(streamHandle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_stream_get_metadata", &hcRet)
	stream := getStream(int64(streamHandle))
	if stream == nil {
		return makeErrorJSON(ErrInvalidStream)
	}

	jsonData, _ := json.Marshal(buildStreamMetadata(stream))
	return C.CString(string(jsonData))
}

//export httpcloak_stream_read
func httpcloak_stream_read(streamHandle C.int64_t, bufferSize C.int) (hcRet *C.char) {
	defer guardCharP("httpcloak_stream_read", &hcRet)
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

// httpcloak_stream_trailer returns the trailing header block as JSON, or "{}"
// when there was none.
//
// Trailers arrive after the body, so unlike a buffered response this cannot be
// part of the metadata handed over when the stream opens. Call it once the body
// has been read to EOF; before then it reports what has arrived, which is
// nothing. gRPC is the case that needs it, since it carries its status there.
//
// The returned C string is malloc'd and must be freed with
// httpcloak_free_string.
//
//export httpcloak_stream_trailer
func httpcloak_stream_trailer(streamHandle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_stream_trailer", &hcRet)
	stream := getStream(int64(streamHandle))
	if stream == nil {
		return C.CString("{}")
	}
	trailer := stream.Trailer()
	if len(trailer) == 0 {
		return C.CString("{}")
	}
	data, err := json.Marshal(trailer)
	if err != nil {
		return C.CString("{}")
	}
	return C.CString(string(data))
}

//export httpcloak_stream_read_raw
func httpcloak_stream_read_raw(streamHandle C.int64_t, buffer unsafe.Pointer, bufferSize C.int) (hcRet C.int) {
	defer guardInt("httpcloak_stream_read_raw", &hcRet)
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
	defer guardVoid("httpcloak_stream_close")
	streamMu.Lock()
	entry, exists := streams[int64(streamHandle)]
	if exists {
		delete(streams, int64(streamHandle))
	}
	streamMu.Unlock()

	if entry != nil {
		if entry.cancel != nil {
			entry.cancel()
		}
		if entry.resp != nil {
			entry.resp.Close()
		}
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
func httpcloak_upload_start(sessionHandle C.int64_t, url *C.char, optionsJSON *C.char) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_upload_start", &hcRet)
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
		defer func() {
			if r := recover(); r != nil {
				logClibPanic("upload_start goroutine", r)
				select {
				case upload.responseCh <- &uploadResult{err: fmt.Errorf("internal panic: %v", r)}:
				default:
				}
			}
		}()
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
func httpcloak_upload_write(uploadHandle C.int64_t, dataBase64 *C.char) (hcRet C.int) {
	defer guardInt("httpcloak_upload_write", &hcRet)
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
func httpcloak_upload_write_raw(uploadHandle C.int64_t, data unsafe.Pointer, dataLen C.int) (hcRet C.int) {
	defer guardInt("httpcloak_upload_write_raw", &hcRet)
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
func httpcloak_upload_finish(uploadHandle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_upload_finish", &hcRet)
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

	body, bodyEncoding := encodeResponseBody(bodyBytes)
	responseData := ResponseData{
		StatusCode:   resp.StatusCode,
		Headers:      resp.Headers,
		HeaderOrder:  resp.HeaderOrder,
		HeaderCasing: resp.HeaderCasing,
		Trailer:      resp.Trailer,
		Body:         body,
		BodyEncoding: bodyEncoding,
		FinalURL:     resp.FinalURL,
		Protocol:     resp.Protocol,
		Cookies:      cookies,
	}

	jsonData, err := json.Marshal(responseData)
	if err != nil {
		return makeErrorJSON(err)
	}

	return C.CString(string(jsonData))
}

//export httpcloak_upload_cancel
func httpcloak_upload_cancel(uploadHandle C.int64_t) {
	defer guardVoid("httpcloak_upload_cancel")
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

// --- Custom Preset Loading ---

//export httpcloak_preset_load_file
func httpcloak_preset_load_file(path *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_preset_load_file", &hcRet)
	p, err := fingerprint.LoadAndBuildPreset(C.GoString(path))
	if err != nil {
		return makeErrorJSON(err)
	}
	if err := fingerprint.RegisterStrict(p.Name, p); err != nil {
		return makeErrorJSON(err)
	}
	data, _ := json.Marshal(map[string]string{"name": p.Name})
	return C.CString(string(data))
}

//export httpcloak_preset_load_json
func httpcloak_preset_load_json(jsonData *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_preset_load_json", &hcRet)
	p, err := fingerprint.LoadAndBuildPresetFromJSON([]byte(C.GoString(jsonData)))
	if err != nil {
		return makeErrorJSON(err)
	}
	if err := fingerprint.RegisterStrict(p.Name, p); err != nil {
		return makeErrorJSON(err)
	}
	data, _ := json.Marshal(map[string]string{"name": p.Name})
	return C.CString(string(data))
}

//export httpcloak_preset_unregister
func httpcloak_preset_unregister(name *C.char) {
	defer guardVoid("httpcloak_preset_unregister")
	fingerprint.Unregister(C.GoString(name))
}

// httpcloak_describe_preset returns a fully-resolved JSON dump of a preset's
// effective state. The returned C string is malloc'd and must be freed by the
// caller via httpcloak_free_string. On error (preset not registered, unknown
// ClientHelloID), the result is a JSON object {"error": "..."} also requiring
// httpcloak_free_string.
//
//export httpcloak_describe_preset
func httpcloak_describe_preset(name *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_describe_preset", &hcRet)
	out, err := fingerprint.Describe(C.GoString(name))
	if err != nil {
		return makeErrorJSON(err)
	}
	return C.CString(out)
}

// --- Preset Pool Lifecycle ---

//export httpcloak_pool_load_file
func httpcloak_pool_load_file(path *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_pool_load_file", &hcRet)
	pool, err := fingerprint.NewPresetPoolFromFile(C.GoString(path))
	if err != nil {
		return makeErrorJSON(err)
	}
	presetPoolMu.Lock()
	presetPoolCounter++
	handle := presetPoolCounter
	presetPools[handle] = pool
	presetPoolMu.Unlock()
	data, _ := json.Marshal(map[string]int64{"handle": handle})
	return C.CString(string(data))
}

//export httpcloak_pool_load_json
func httpcloak_pool_load_json(jsonData *C.char) (hcRet *C.char) {
	defer guardCharP("httpcloak_pool_load_json", &hcRet)
	pool, err := fingerprint.NewPresetPoolFromJSON([]byte(C.GoString(jsonData)))
	if err != nil {
		return makeErrorJSON(err)
	}
	presetPoolMu.Lock()
	presetPoolCounter++
	handle := presetPoolCounter
	presetPools[handle] = pool
	presetPoolMu.Unlock()
	data, _ := json.Marshal(map[string]int64{"handle": handle})
	return C.CString(string(data))
}

// --- Preset Pool Accessors ---

//export httpcloak_pool_pick
func httpcloak_pool_pick(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_pool_pick", &hcRet)
	pool := getPresetPool(handle)
	if pool == nil {
		return makeErrorJSON(ErrInvalidPresetPool)
	}
	return C.CString(pool.Pick().Name)
}

//export httpcloak_pool_random
func httpcloak_pool_random(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_pool_random", &hcRet)
	pool := getPresetPool(handle)
	if pool == nil {
		return makeErrorJSON(ErrInvalidPresetPool)
	}
	return C.CString(pool.Random().Name)
}

//export httpcloak_pool_next
func httpcloak_pool_next(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_pool_next", &hcRet)
	pool := getPresetPool(handle)
	if pool == nil {
		return makeErrorJSON(ErrInvalidPresetPool)
	}
	return C.CString(pool.Next().Name)
}

//export httpcloak_pool_get
func httpcloak_pool_get(handle C.int64_t, index C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_pool_get", &hcRet)
	pool := getPresetPool(handle)
	if pool == nil {
		return makeErrorJSON(ErrInvalidPresetPool)
	}
	idx := int(index)
	if idx < 0 || idx >= pool.Size() {
		return makeErrorJSON(fmt.Errorf("preset pool index %d out of range [0, %d)", idx, pool.Size()))
	}
	return C.CString(pool.Get(idx).Name)
}

//export httpcloak_pool_size
func httpcloak_pool_size(handle C.int64_t) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_pool_size", &hcRet)
	pool := getPresetPool(handle)
	if pool == nil {
		return -1
	}
	return C.int64_t(pool.Size())
}

//export httpcloak_pool_name
func httpcloak_pool_name(handle C.int64_t) (hcRet *C.char) {
	defer guardCharP("httpcloak_pool_name", &hcRet)
	pool := getPresetPool(handle)
	if pool == nil {
		return makeErrorJSON(ErrInvalidPresetPool)
	}
	return C.CString(pool.Name())
}

//export httpcloak_pool_free
func httpcloak_pool_free(handle C.int64_t) {
	defer guardVoid("httpcloak_pool_free")
	presetPoolMu.Lock()
	pool, ok := presetPools[int64(handle)]
	if ok {
		delete(presetPools, int64(handle))
	}
	presetPoolMu.Unlock()
	if pool != nil {
		pool.Close()
	}
}

func main() {}

// toUint16 accepts the shapes JSON can produce for a 16-bit codepoint: a
// number, or a string spelled either "0x4001" or "16385". Anything else is
// rejected rather than coerced, so a malformed value cannot quietly become 0
// and read as "use the default".
func toUint16(v interface{}) (uint16, bool) {
	switch t := v.(type) {
	case float64:
		if t < 0 || t > 65535 {
			return 0, false
		}
		return uint16(t), true
	case string:
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(t), "0x"), 0, 16)
		if err != nil {
			if n2, err2 := strconv.ParseUint(strings.TrimSpace(t), 16, 16); err2 == nil {
				return uint16(n2), true
			}
			return 0, false
		}
		return uint16(n), true
	}
	return 0, false
}

// buildExactHeaders converts the [name, value] pairs from a request config.
// Malformed entries are skipped rather than guessed at: a one-element or
// three-element array has no sensible reading, and inventing one would put a
// header on the wire the caller did not ask for.
func buildExactHeaders(pairs [][]string) []fingerprint.HeaderPair {
	if len(pairs) == 0 {
		return nil
	}
	out := make([]fingerprint.HeaderPair, 0, len(pairs))
	for _, p := range pairs {
		if len(p) != 2 || p[0] == "" {
			continue
		}
		out = append(out, fingerprint.HeaderPair{Key: p[0], Value: p[1]})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
