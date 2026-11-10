//go:build hctest

package main

// Test-only cgo helpers for callback_thread_test.go. Test files cannot use cgo
// themselves, so the C callbacks the tests register live here, behind the
// hctest build tag so they never reach a shipped library.

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "callback_pool.h"

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

// t_record_cb keeps a copy of the error each call is given, for a test to
// read back; the copies are never freed, which a test can afford.
static char* volatile t_recorded_err = 0;
static volatile int t_recorded_calls = 0;
static void t_record_cb(int64_t id, const char* resp, const char* err) {
    (void)id; (void)resp;
    t_recorded_err = err ? strdup(err) : 0;
    __sync_fetch_and_add(&t_recorded_calls, 1);
}

static async_callback t_async_ptr(void) { return t_async_cb; }
static async_callback t_record_ptr(void) { return t_record_cb; }
static int t_recorded(void) { return t_recorded_calls; }
static char* t_recorded_error(void) { return t_recorded_err; }
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
	"time"
	"unsafe"
)

func hcTestRegisterAsync() int64 {
	return int64(httpcloak_register_callback(C.async_callback(C.t_async_ptr())))
}

func hcTestRegisterRecording() int64 {
	return int64(httpcloak_register_callback(C.async_callback(C.t_record_ptr())))
}

// hcTestRecorded waits for the recording callback to have been called n times
// in all, and returns the error the last call was given.
func hcTestRecorded(n int) (string, bool) {
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if int(C.t_recorded()) >= n {
			return C.GoString(C.t_recorded_error()), true
		}
	}
	return "", false
}

func hcTestCounts() (asyncCalls, asyncOnWorker, getCalls, getOnWorker int) {
	return int(C.t_counts(0)), int(C.t_counts(1)), int(C.t_counts(2)), int(C.t_counts(3))
}

func hcTestSessionNew(cfg string) int64 {
	c := C.CString(cfg)
	defer C.free(unsafe.Pointer(c))
	return int64(httpcloak_session_new(c))
}

func hcTestRequestAsync(handle int64, reqJSON string, id int64) {
	c := C.CString(reqJSON)
	defer C.free(unsafe.Pointer(c))
	httpcloak_request_async(C.int64_t(handle), c, C.int64_t(id))
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

func hcTestSessionFree(h int64) { httpcloak_session_free(C.int64_t(h)) }
