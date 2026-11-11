// Host-callback dispatch for the C shim. See callback_pool.c.
#ifndef HTTPCLOAK_CALLBACK_POOL_H
#define HTTPCLOAK_CALLBACK_POOL_H

// These are internal to the library. Hidden, so the shared object does not
// export them for another library in the host process to interpose; a DLL
// exports nothing that is not marked for export, so Windows needs nothing.
#if defined(__GNUC__) && !defined(_WIN32)
#define HC_INTERNAL __attribute__((visibility("hidden")))
#else
#define HC_INTERNAL
#endif

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

HC_INTERNAL void invoke_callback(async_callback cb, int64_t callback_id, const char* response_json, const char* error);
HC_INTERNAL char* invoke_cache_get(session_cache_get_callback cb, const char* key);
HC_INTERNAL int invoke_cache_put(session_cache_put_callback cb, const char* key, const char* value_json, int64_t ttl_seconds);
HC_INTERNAL void invoke_cache_error(session_cache_error_callback cb, const char* operation, const char* key, const char* error);
HC_INTERNAL int invoke_cache_delete(session_cache_delete_callback cb, const char* key);
HC_INTERNAL char* invoke_ech_get(ech_cache_get_callback cb, const char* key);
HC_INTERNAL int invoke_ech_put(ech_cache_put_callback cb, const char* key, const char* value_base64, int64_t ttl_seconds);
HC_INTERNAL void invoke_async_cache_get(async_cache_get_callback cb, int64_t request_id, const char* key);
HC_INTERNAL void invoke_async_cache_put(async_cache_put_callback cb, int64_t request_id, const char* key, const char* value_json, int64_t ttl_seconds);
HC_INTERNAL void invoke_async_cache_delete(async_cache_delete_callback cb, int64_t request_id, const char* key);
HC_INTERNAL void invoke_async_ech_get(async_ech_get_callback cb, int64_t request_id, const char* key);
HC_INTERNAL void invoke_async_ech_put(async_ech_put_callback cb, int64_t request_id, const char* key, const char* value_base64, int64_t ttl_seconds);

// hc_export_hop runs thunk(args) on a library-owned thread and waits for it.
// The generated public wrappers use it on Windows (#147).
HC_INTERNAL void hc_export_hop(void (*thunk)(void*), void* args);

#ifdef HC_TEST
// hc_on_worker_thread reports whether the calling thread runs host callbacks,
// hc_on_export_thread whether it runs the library's exports.
HC_INTERNAL int hc_on_worker_thread(void);
HC_INTERNAL int hc_on_export_thread(void);
// hc_test_export_hops counts exports that ran on an export thread.
HC_INTERNAL int hc_test_export_hops(void);
#endif

#endif
