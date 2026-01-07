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
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/sardanioss/httpcloak"
)

// Session handle management
var (
	sessionMu      sync.RWMutex
	sessions       = make(map[int64]*httpcloak.Session)
	sessionCounter int64
)

// Async callback management
var (
	callbackMu      sync.Mutex
	callbackCounter int64
	asyncCallbacks  = make(map[int64]C.async_callback)
)

// Request configuration for JSON parsing
type RequestConfig struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	Timeout int               `json:"timeout,omitempty"` // seconds
}

// Response for JSON serialization
type ResponseData struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	FinalURL   string            `json:"final_url"`
	Protocol   string            `json:"protocol"`
}

// Session configuration
type SessionConfig struct {
	Preset          string `json:"preset"`
	Proxy           string `json:"proxy,omitempty"`
	Timeout         int    `json:"timeout,omitempty"`           // seconds
	HTTPVersion     string `json:"http_version,omitempty"`      // "auto", "h1", "h2", "h3"
	Verify          *bool  `json:"verify,omitempty"`            // SSL verification (default: true)
	AllowRedirects  *bool  `json:"allow_redirects,omitempty"`   // Follow redirects (default: true)
	MaxRedirects    int    `json:"max_redirects,omitempty"`     // Max redirects (default: 10)
	Retry           int    `json:"retry,omitempty"`             // Retry count (default: 0)
	RetryWaitMin    int    `json:"retry_wait_min,omitempty"`    // Min wait between retries in ms
	RetryWaitMax    int    `json:"retry_wait_max,omitempty"`    // Max wait between retries in ms
	RetryOnStatus   []int  `json:"retry_on_status,omitempty"`   // Status codes to retry on
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

func makeResponseJSON(resp *httpcloak.Response) *C.char {
	data := ResponseData{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       string(resp.Body),
		FinalURL:   resp.FinalURL,
		Protocol:   resp.Protocol,
	}
	jsonData, _ := json.Marshal(data)
	return C.CString(string(jsonData))
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

	// Handle SSL verification
	if config.Verify != nil && !*config.Verify {
		opts = append(opts, httpcloak.WithInsecureSkipVerify())
	}

	// Handle redirects
	if config.AllowRedirects != nil && !*config.AllowRedirects {
		opts = append(opts, httpcloak.WithoutRedirects())
	} else if config.MaxRedirects > 0 {
		opts = append(opts, httpcloak.WithRedirects(true, config.MaxRedirects))
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
	delete(sessions, int64(handle))
	sessionMu.Unlock()
}

func getSession(handle C.int64_t) *httpcloak.Session {
	sessionMu.RLock()
	defer sessionMu.RUnlock()
	return sessions[int64(handle)]
}

// ============================================================================
// Synchronous Requests
// ============================================================================

//export httpcloak_get
func httpcloak_get(handle C.int64_t, url *C.char, headersJSON *C.char) *C.char {
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	ctx := context.Background()
	urlStr := C.GoString(url)

	// Parse custom headers if provided
	var headers map[string]string
	if headersJSON != nil {
		jsonStr := C.GoString(headersJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &headers)
		}
	}

	req := &httpcloak.Request{
		Method:  "GET",
		URL:     urlStr,
		Headers: headers,
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		return makeErrorJSON(err)
	}

	return makeResponseJSON(resp)
}

//export httpcloak_post
func httpcloak_post(handle C.int64_t, url *C.char, body *C.char, headersJSON *C.char) *C.char {
	session := getSession(handle)
	if session == nil {
		return makeErrorJSON(ErrInvalidSession)
	}

	ctx := context.Background()
	urlStr := C.GoString(url)
	bodyStr := ""
	if body != nil {
		bodyStr = C.GoString(body)
	}

	var headers map[string]string
	if headersJSON != nil {
		jsonStr := C.GoString(headersJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &headers)
		}
	}

	req := &httpcloak.Request{
		Method:  "POST",
		URL:     urlStr,
		Headers: headers,
		Body:    []byte(bodyStr),
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

	ctx := context.Background()
	if config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
		defer cancel()
	}

	req := &httpcloak.Request{
		Method:  config.Method,
		URL:     config.URL,
		Headers: config.Headers,
		Body:    []byte(config.Body),
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
func httpcloak_get_async(handle C.int64_t, url *C.char, headersJSON *C.char, callbackID C.int64_t) {
	session := getSession(handle)
	urlStr := C.GoString(url)

	var headers map[string]string
	if headersJSON != nil {
		jsonStr := C.GoString(headersJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &headers)
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
			Headers: headers,
		}

		resp, err := session.Do(ctx, req)
		if err != nil {
			errResp := ErrorResponse{Error: err.Error()}
			errJSON, _ := json.Marshal(errResp)
			invokeCallback(int64(callbackID), "", string(errJSON))
			return
		}

		data := ResponseData{
			StatusCode: resp.StatusCode,
			Headers:    resp.Headers,
			Body:       string(resp.Body),
			FinalURL:   resp.FinalURL,
			Protocol:   resp.Protocol,
		}
		jsonData, _ := json.Marshal(data)
		invokeCallback(int64(callbackID), string(jsonData), "")
	}()
}

//export httpcloak_post_async
func httpcloak_post_async(handle C.int64_t, url *C.char, body *C.char, headersJSON *C.char, callbackID C.int64_t) {
	session := getSession(handle)
	urlStr := C.GoString(url)
	bodyStr := ""
	if body != nil {
		bodyStr = C.GoString(body)
	}

	var headers map[string]string
	if headersJSON != nil {
		jsonStr := C.GoString(headersJSON)
		if jsonStr != "" {
			json.Unmarshal([]byte(jsonStr), &headers)
		}
	}

	go func() {
		if session == nil {
			invokeCallback(int64(callbackID), "", ErrInvalidSession.Error())
			return
		}

		ctx := context.Background()
		req := &httpcloak.Request{
			Method:  "POST",
			URL:     urlStr,
			Headers: headers,
			Body:    []byte(bodyStr),
		}

		resp, err := session.Do(ctx, req)
		if err != nil {
			errResp := ErrorResponse{Error: err.Error()}
			errJSON, _ := json.Marshal(errResp)
			invokeCallback(int64(callbackID), "", string(errJSON))
			return
		}

		data := ResponseData{
			StatusCode: resp.StatusCode,
			Headers:    resp.Headers,
			Body:       string(resp.Body),
			FinalURL:   resp.FinalURL,
			Protocol:   resp.Protocol,
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

		req := &httpcloak.Request{
			Method:  config.Method,
			URL:     config.URL,
			Headers: config.Headers,
			Body:    []byte(config.Body),
		}

		resp, err := session.Do(ctx, req)
		if err != nil {
			errResp := ErrorResponse{Error: err.Error()}
			errJSON, _ := json.Marshal(errResp)
			invokeCallback(int64(callbackID), "", string(errJSON))
			return
		}

		data := ResponseData{
			StatusCode: resp.StatusCode,
			Headers:    resp.Headers,
			Body:       string(resp.Body),
			FinalURL:   resp.FinalURL,
			Protocol:   resp.Protocol,
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
	return C.CString("1.1.1")
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
)

func main() {}
