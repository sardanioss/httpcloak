//go:build hctest

package main

// Test-only cgo helpers for callback_thread_test.go. Test files cannot use cgo
// themselves, so the C callbacks the tests register live here, behind the
// hctest build tag so they never reach a shipped library.

/*
#cgo CFLAGS: -DHC_TEST -DHC_FORCE_EXPORT_HOP
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "httpcloak_api.h"

static volatile int t_async_calls = 0;
static volatile int t_async_on_worker = 0;
static volatile int t_get_calls = 0;
static volatile int t_get_on_worker = 0;

static void t_async_cb(int64_t id, const char* resp, const char* err) {
    (void)id; (void)resp; (void)err;
    __sync_fetch_and_add(&t_async_calls, 1);
    if (hc_on_worker_thread()) __sync_fetch_and_add(&t_async_on_worker, 1);
}

static char t_get_value[] = "";
static char* t_get_cb(const char* key) {
    (void)key;
    __sync_fetch_and_add(&t_get_calls, 1);
    if (hc_on_worker_thread()) __sync_fetch_and_add(&t_get_on_worker, 1);
    return t_get_value;
}

// A get callback that calls back into Go while it runs, and from there into
// another host callback, the shape a binding produces when its callback ends
// up making a synchronous library call. On a single worker thread this would
// wait on itself forever.
extern void hcTestReenter(void);
static char* t_reentrant_get_cb(const char* key) {
    (void)key;
    hcTestReenter();
    return t_get_value;
}

// A get callback that calls a public export while it runs: a host whose
// cache lookup makes a library call. The call hops to an export thread from a
// callback thread, while the Go code that invoked the callback still waits.
static volatile int t_export_in_cb_ok = 0;
static char* t_export_get_cb(const char* key) {
    (void)key;
    char* v = httpcloak_version();
    if (v != NULL) {
        if (v[0] != 0) __sync_fetch_and_add(&t_export_in_cb_ok, 1);
        httpcloak_free_string(v);
    }
    return t_get_value;
}
static session_cache_get_callback t_export_get_ptr(void) { return t_export_get_cb; }
static int t_export_in_cb(void) { return t_export_in_cb_ok; }

// Calls into the library from threads Go has never seen, as a host's own
// threads do. Each thread makes one blocking GET through the public API.
typedef struct { const char* cfg; const char* url; int status; } t_get_job;
static void* t_get_thread(void* p) {
    t_get_job* j = (t_get_job*)p;
    int64_t h = httpcloak_session_new((char*)j->cfg);
    if (h <= 0) { j->status = -1; return NULL; }
    char* resp = httpcloak_get(h, (char*)j->url, NULL);
    if (resp != NULL) {
        j->status = strstr(resp, "\"status_code\":200") != NULL ? 200 : -2;
        httpcloak_free_string(resp);
    } else {
        j->status = -3;
    }
    httpcloak_session_free(h);
    return NULL;
}
static int t_get_from_threads(const char* cfg, const char* url, int n) {
    pthread_t ts[64];
    t_get_job jobs[64];
    if (n > 64) n = 64;
    for (int i = 0; i < n; i++) {
        jobs[i].cfg = cfg; jobs[i].url = url; jobs[i].status = 0;
        if (pthread_create(&ts[i], NULL, t_get_thread, &jobs[i]) != 0) return -1;
    }
    int ok = 0;
    for (int i = 0; i < n; i++) {
        pthread_join(ts[i], NULL);
        if (jobs[i].status == 200) ok++;
    }
    return ok;
}

static async_callback t_async_ptr(void) { return t_async_cb; }
static session_cache_get_callback t_get_ptr(void) { return t_get_cb; }
static session_cache_get_callback t_reentrant_get_ptr(void) { return t_reentrant_get_cb; }
static int t_counts(int which) {
    switch (which) {
    case 0: return t_async_calls;
    case 1: return t_async_on_worker;
    case 2: return t_get_calls;
    default: return t_get_on_worker;
    }
}
*/
import "C"

import (
	"context"
	"unsafe"
)

func hcTestRegisterAsync() int64 {
	return int64(hcgo_httpcloak_register_callback(C.async_callback(C.t_async_ptr())))
}

func hcTestCounts() (asyncCalls, asyncOnWorker, getCalls, getOnWorker int) {
	return int(C.t_counts(0)), int(C.t_counts(1)), int(C.t_counts(2)), int(C.t_counts(3))
}

func hcTestSessionNew(cfg string) int64 {
	c := C.CString(cfg)
	defer C.free(unsafe.Pointer(c))
	return int64(hcgo_httpcloak_session_new(c))
}

func hcTestRequestAsync(handle int64, reqJSON string, id int64) {
	c := C.CString(reqJSON)
	defer C.free(unsafe.Pointer(c))
	hcgo_httpcloak_request_async(C.int64_t(handle), c, C.int64_t(id))
}

// hcTestCacheGet drives the synchronous session-cache get path directly.
func hcTestCacheGet(reentrant bool) {
	cb := C.session_cache_get_callback(C.t_get_ptr())
	if reentrant {
		cb = C.session_cache_get_callback(C.t_reentrant_get_ptr())
	}
	b := NewCSessionCacheBackend(cb, nil, nil, nil, nil)
	b.Get(context.Background(), "host:443")
}

//export hcTestReenter
func hcTestReenter() {
	hcTestCacheGet(false)
}

func hcTestSessionFree(h int64) { hcgo_httpcloak_session_free(C.int64_t(h)) }

// hcTestExportFromCallback runs a cache get whose callback calls a public
// export, and reports how many such calls succeeded so far.
func hcTestExportFromCallback() int {
	b := NewCSessionCacheBackend(C.session_cache_get_callback(C.t_export_get_ptr()), nil, nil, nil, nil)
	b.Get(context.Background(), "host:443")
	return int(C.t_export_in_cb())
}

// hcTestExportFromCallbackCount reports the same count without a call.
func hcTestExportFromCallbackCount() int { return int(C.t_export_in_cb()) }

// hcTestGetFromThreads makes n concurrent GETs through the public C API, each
// from its own new C thread, and returns how many got a 200.
func hcTestGetFromThreads(cfg, url string, n int) int {
	c := C.CString(cfg)
	defer C.free(unsafe.Pointer(c))
	u := C.CString(url)
	defer C.free(unsafe.Pointer(u))
	return int(C.t_get_from_threads(c, u, C.int(n)))
}

// hcTestPublicVersion calls the public httpcloak_version wrapper.
func hcTestPublicVersion() string {
	v := C.httpcloak_version()
	defer C.httpcloak_free_string(v)
	return C.GoString(v)
}

func hcTestExportHops() int { return int(C.hc_test_export_hops()) }

// hcTestDirectVersion calls the Go function without the wrapper.
func hcTestDirectVersion() string {
	v := hcgo_httpcloak_version()
	defer C.httpcloak_free_string(v)
	return C.GoString(v)
}
