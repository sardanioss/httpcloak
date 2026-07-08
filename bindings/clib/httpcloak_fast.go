package main

/*
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Pre-allocated response structure to avoid JSON serialization
typedef struct {
    int32_t status_code;
    int32_t body_len;
    int32_t headers_len;
    int32_t protocol;  // 1=h1, 2=h2, 3=h3
    char final_url[2048];
} FastResponseMeta;

*/
import "C"
import (
	"context"
	"crypto/x509"
	"io"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/sardanioss/httpcloak"
)

// init runs automatically when the shared library is loaded.
// Pre-loads x509 system roots to avoid ~20ms delay on first request.
func init() {
	// Force the httpcloak package init to run by creating a dummy session config
	// This ensures x509 roots are loaded before any user request
	_ = &httpcloak.Request{}

	// Also explicitly load roots here in case httpcloak's init changes
	_, _ = x509.SystemCertPool()
}

//export httpcloak_init
func httpcloak_init() {
	defer guardVoid("httpcloak_init")
	// Force Go runtime initialization and warm up the scheduler
	runtime.GC()

	// Pre-load system root CA certificates (normally lazy-loaded on first TLS connection)
	// This takes ~40ms on first call, so we do it at init time
	_, _ = x509.SystemCertPool()

	// Warm up crypto/tls internals by triggering lazy init
	_ = make([]byte, 4096)
	runtime.GC()
}

//export httpcloak_warmup
func httpcloak_warmup(configJSON *C.char) {
	defer guardVoid("httpcloak_warmup")
	// Create and immediately close a session to warm up all internals
	// This triggers DNS resolver init, ECH cache init, etc.
	handle := httpcloak_session_new(configJSON)
	if handle > 0 {
		httpcloak_session_free(handle)
	}
}

//export httpcloak_warmup_full
func httpcloak_warmup_full(configJSON *C.char, warmupURL *C.char, warmupURLLen C.int) {
	defer guardVoid("httpcloak_warmup_full")
	// Full warmup: create session and make a real request to warm all code paths
	// This warms up QUIC handshake, TLS, HTTP/3 framing, etc.
	handle := httpcloak_session_new(configJSON)
	if handle <= 0 {
		return
	}
	defer httpcloak_session_free(handle)

	// Make actual request if URL provided
	if warmupURL != nil && warmupURLLen > 0 {
		rh := httpcloak_get_fast(handle, warmupURL, warmupURLLen)
		if rh > 0 {
			httpcloak_fast_free(rh)
		}
	}
}

// FastResponse holds response data with C-allocated memory
type FastResponse struct {
	meta    *C.FastResponseMeta // C-allocated, safe to return
	body    unsafe.Pointer      // C-allocated body
	bodyLen int
	headers map[string][]string
}

var (
	fastResponses   = make(map[int64]*FastResponse)
	fastResponsesMu sync.RWMutex
	fastResponseID  int64
)

// Protocol constants
const (
	protoH1 = 1
	protoH2 = 2
	protoH3 = 3
)

func protocolToInt(p string) int32 {
	switch p {
	case "h1", "http/1.1", "HTTP/1.1":
		return protoH1
	case "h2", "http/2", "HTTP/2":
		return protoH2
	case "h3", "http/3", "HTTP/3":
		return protoH3
	default:
		return protoH2
	}
}

//export httpcloak_get_fast_timed
func httpcloak_get_fast_timed(handle C.int64_t, url *C.char, urlLen C.int, timings *C.int64_t) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_get_fast_timed", &hcRet)
	t0 := time.Now()

	session := getSession(handle)
	if session == nil {
		return -1
	}

	t1 := time.Now()

	urlStr := C.GoStringN(url, urlLen)

	t2 := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &httpcloak.Request{
		Method: "GET",
		URL:    urlStr,
	}

	t3 := time.Now()

	resp, err := session.Do(ctx, req)

	t4 := time.Now()

	if err != nil {
		return -1
	}

	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	t5 := time.Now()

	// Write timings if provided (array of 5 int64s in microseconds)
	if timings != nil {
		timingsSlice := (*[5]C.int64_t)(unsafe.Pointer(timings))
		timingsSlice[0] = C.int64_t(t1.Sub(t0).Microseconds()) // getSession
		timingsSlice[1] = C.int64_t(t2.Sub(t1).Microseconds()) // string conv
		timingsSlice[2] = C.int64_t(t3.Sub(t2).Microseconds()) // ctx + req setup
		timingsSlice[3] = C.int64_t(t4.Sub(t3).Microseconds()) // session.Do
		timingsSlice[4] = C.int64_t(t5.Sub(t4).Microseconds()) // body read
	}

	// Continue with response handling...
	return httpcloak_get_fast_finish(resp, bodyBytes)
}

func httpcloak_get_fast_finish(resp *httpcloak.Response, bodyBytes []byte) C.int64_t {
	// Allocate C memory for metadata (safe to return to C)
	meta := (*C.FastResponseMeta)(C.malloc(C.size_t(unsafe.Sizeof(C.FastResponseMeta{}))))

	// Fill metadata
	meta.status_code = C.int32_t(resp.StatusCode)
	meta.body_len = C.int32_t(len(bodyBytes))
	meta.protocol = C.int32_t(protocolToInt(resp.Protocol))

	// Copy final URL directly into C struct
	finalURLBytes := []byte(resp.FinalURL)
	if len(finalURLBytes) < 2047 {
		for i := 0; i < len(finalURLBytes); i++ {
			meta.final_url[i] = C.char(finalURLBytes[i])
		}
		meta.final_url[len(finalURLBytes)] = 0
	} else {
		meta.final_url[0] = 0
	}

	// Count headers
	headerCount := 0
	for _, vals := range resp.Headers {
		headerCount += len(vals)
	}
	meta.headers_len = C.int32_t(headerCount)

	// Allocate C memory for body and copy
	var cBody unsafe.Pointer
	if len(bodyBytes) > 0 {
		cBody = C.malloc(C.size_t(len(bodyBytes)))
		C.memcpy(cBody, unsafe.Pointer(&bodyBytes[0]), C.size_t(len(bodyBytes)))
	}

	// Create response
	fr := &FastResponse{
		meta:    meta,
		body:    cBody,
		bodyLen: len(bodyBytes),
		headers: resp.Headers,
	}

	// Store response
	fastResponsesMu.Lock()
	fastResponseID++
	id := fastResponseID
	fastResponses[id] = fr
	fastResponsesMu.Unlock()

	return C.int64_t(id)
}

//export httpcloak_get_fast
func httpcloak_get_fast(handle C.int64_t, url *C.char, urlLen C.int) (hcRet C.int64_t) {
	defer guardInt64("httpcloak_get_fast", &hcRet)
	session := getSession(handle)
	if session == nil {
		return -1
	}

	// Use C.GoStringN which is optimized for known-length strings
	urlStr := C.GoStringN(url, urlLen)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &httpcloak.Request{
		Method: "GET",
		URL:    urlStr,
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		return -1
	}

	// Read body
	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	// Allocate C memory for metadata (safe to return to C)
	meta := (*C.FastResponseMeta)(C.malloc(C.size_t(unsafe.Sizeof(C.FastResponseMeta{}))))

	// Fill metadata
	meta.status_code = C.int32_t(resp.StatusCode)
	meta.body_len = C.int32_t(len(bodyBytes))
	meta.protocol = C.int32_t(protocolToInt(resp.Protocol))

	// Copy final URL directly into C struct
	finalURLBytes := []byte(resp.FinalURL)
	if len(finalURLBytes) < 2047 {
		for i := 0; i < len(finalURLBytes); i++ {
			meta.final_url[i] = C.char(finalURLBytes[i])
		}
		meta.final_url[len(finalURLBytes)] = 0
	} else {
		meta.final_url[0] = 0
	}

	// Count headers
	headerCount := 0
	for _, vals := range resp.Headers {
		headerCount += len(vals)
	}
	meta.headers_len = C.int32_t(headerCount)

	// Allocate C memory for body and copy
	var cBody unsafe.Pointer
	if len(bodyBytes) > 0 {
		cBody = C.malloc(C.size_t(len(bodyBytes)))
		C.memcpy(cBody, unsafe.Pointer(&bodyBytes[0]), C.size_t(len(bodyBytes)))
	}

	// Create response
	fr := &FastResponse{
		meta:    meta,
		body:    cBody,
		bodyLen: len(bodyBytes),
		headers: resp.Headers,
	}

	// Store response
	fastResponsesMu.Lock()
	fastResponseID++
	id := fastResponseID
	fastResponses[id] = fr
	fastResponsesMu.Unlock()

	return C.int64_t(id)
}

//export httpcloak_fast_get_meta
func httpcloak_fast_get_meta(handle C.int64_t) (hcRet *C.FastResponseMeta) {
	defer guardVoid("httpcloak_fast_get_meta")
	fastResponsesMu.RLock()
	resp, exists := fastResponses[int64(handle)]
	fastResponsesMu.RUnlock()

	if !exists || resp == nil {
		return nil
	}

	return resp.meta
}

//export httpcloak_fast_get_body_ptr
func httpcloak_fast_get_body_ptr(handle C.int64_t) (hcRet unsafe.Pointer) {
	defer guardPtr("httpcloak_fast_get_body_ptr", &hcRet)
	fastResponsesMu.RLock()
	resp, exists := fastResponses[int64(handle)]
	fastResponsesMu.RUnlock()

	if !exists || resp == nil || resp.bodyLen == 0 {
		return nil
	}

	return resp.body
}

//export httpcloak_fast_get_body_len
func httpcloak_fast_get_body_len(handle C.int64_t) (hcRet C.int) {
	defer guardInt("httpcloak_fast_get_body_len", &hcRet)
	fastResponsesMu.RLock()
	resp, exists := fastResponses[int64(handle)]
	fastResponsesMu.RUnlock()

	if !exists || resp == nil {
		return 0
	}

	return C.int(resp.bodyLen)
}

//export httpcloak_fast_free
func httpcloak_fast_free(handle C.int64_t) {
	defer guardVoid("httpcloak_fast_free")
	fastResponsesMu.Lock()
	resp, exists := fastResponses[int64(handle)]
	if exists && resp != nil {
		// Free C-allocated memory
		if resp.meta != nil {
			C.free(unsafe.Pointer(resp.meta))
		}
		if resp.body != nil {
			C.free(resp.body)
		}
		delete(fastResponses, int64(handle))
	}
	fastResponsesMu.Unlock()
}
