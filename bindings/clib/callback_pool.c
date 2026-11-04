// Host-callback dispatch for the C shim. It lives in its own file rather than
// in the cgo preamble of httpcloak.go: that file has //export functions, so
// cgo copies its preamble into _cgo_export.c too, and anything defined there
// would exist twice.

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "callback_pool.h"

// ---------------------------------------------------------------------------
// Host callbacks run on threads this shim owns, never on Go's (issue #114).
//
// A host runtime can treat any thread that has ever run its code as one of its
// own. .NET does: it suspends its threads for GC with special user APCs, and
// a Go thread that once ran a managed callback becomes a target. When such an
// APC lands while that thread is running Go code on a goroutine stack,
// KiUserApcDispatcher cannot deliver it and raises STATUS_INVALID_PARAMETER
// (0xC000000D), which ends the process with no dump and no managed exception.
// Seen on the async completion path; the cache callbacks are the same hazard.
//
// So every invoke_* below hands the call to a worker thread created here and
// waits for it. The caller still blocks until the callback returns, exactly
// as when it ran the callback itself, so string lifetimes, return values and
// ordering are unchanged; only the thread the host code runs on is different.
//
// The pool keeps one worker free for every queued job, creating threads as
// needed, so a callback that re-enters the library and triggers another
// callback never waits behind itself. Idle workers exit after 30 seconds.
// ---------------------------------------------------------------------------

typedef struct hc_job hc_job;
typedef void (*hc_run_fn)(hc_job*);

struct hc_job {
    hc_run_fn run;
    void* fn;
    int64_t id;
    const char* a;
    const char* b;
    const char* c;
    int64_t n;
    char* ret_str;
    int ret_int;
    int done;
    hc_job* next;
#ifdef _WIN32
    void* cv_storage[1]; // CONDITION_VARIABLE is pointer-sized
#else
    char cv_storage[64]; // pthread_cond_t
#endif
};

#ifdef _WIN32
#include <windows.h>
#include <process.h>
static CRITICAL_SECTION hc_lock;
static CONDITION_VARIABLE hc_queue_cv;
static INIT_ONCE hc_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK hc_init_win(PINIT_ONCE o, PVOID p, PVOID* c) {
    (void)o; (void)p; (void)c;
    InitializeCriticalSection(&hc_lock);
    InitializeConditionVariable(&hc_queue_cv);
    return TRUE;
}
static void hc_init(void) { InitOnceExecuteOnce(&hc_once, hc_init_win, NULL, NULL); }
#define HC_LOCK()   EnterCriticalSection(&hc_lock)
#define HC_UNLOCK() LeaveCriticalSection(&hc_lock)
#define HC_JOB_CV(j) ((PCONDITION_VARIABLE)(j)->cv_storage)
static void hc_job_cv_init(hc_job* j) { InitializeConditionVariable(HC_JOB_CV(j)); }
static void hc_job_cv_destroy(hc_job* j) { (void)j; }
static void hc_job_wait(hc_job* j) { SleepConditionVariableCS(HC_JOB_CV(j), &hc_lock, INFINITE); }
static void hc_job_signal(hc_job* j) { WakeConditionVariable(HC_JOB_CV(j)); }
static void hc_queue_signal(void) { WakeConditionVariable(&hc_queue_cv); }
// Returns nonzero when the wait timed out.
static int hc_queue_wait(unsigned ms) {
    return !SleepConditionVariableCS(&hc_queue_cv, &hc_lock, ms) && GetLastError() == ERROR_TIMEOUT;
}
static unsigned __stdcall hc_worker_main(void* arg);
static int hc_spawn(void) {
    uintptr_t h = _beginthreadex(NULL, 0, hc_worker_main, NULL, 0, NULL);
    if (h == 0) return -1;
    CloseHandle((HANDLE)h);
    return 0;
}
#else
#include <pthread.h>
#include <time.h>
#include <errno.h>
static pthread_mutex_t hc_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t hc_queue_cv = PTHREAD_COND_INITIALIZER;
static void hc_init(void) {}
#define HC_LOCK()   pthread_mutex_lock(&hc_lock)
#define HC_UNLOCK() pthread_mutex_unlock(&hc_lock)
#define HC_JOB_CV(j) ((pthread_cond_t*)(void*)(j)->cv_storage)
static void hc_job_cv_init(hc_job* j) { pthread_cond_init(HC_JOB_CV(j), NULL); }
static void hc_job_cv_destroy(hc_job* j) { pthread_cond_destroy(HC_JOB_CV(j)); }
static void hc_job_wait(hc_job* j) { pthread_cond_wait(HC_JOB_CV(j), &hc_lock); }
static void hc_job_signal(hc_job* j) { pthread_cond_signal(HC_JOB_CV(j)); }
static void hc_queue_signal(void) { pthread_cond_signal(&hc_queue_cv); }
static int hc_queue_wait(unsigned ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    return pthread_cond_timedwait(&hc_queue_cv, &hc_lock, &ts) == ETIMEDOUT;
}
static void* hc_worker_main(void* arg);
static int hc_spawn(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, hc_worker_main, NULL) != 0) return -1;
    pthread_detach(t);
    return 0;
}
#endif

_Static_assert(sizeof(((hc_job*)0)->cv_storage) >=
#ifdef _WIN32
    sizeof(CONDITION_VARIABLE),
#else
    sizeof(pthread_cond_t),
#endif
    "hc_job condition variable storage too small");

static hc_job* hc_head = NULL;
static hc_job* hc_tail = NULL;
static int hc_queued = 0; // jobs waiting for a worker
static int hc_idle = 0;   // workers waiting for a job

// Test builds record which threads are the pool's so the tests can check that
// callbacks never run on a Go thread. Release builds carry no thread-local
// state at all: MinGW implements _Thread_local through libgcc_s_seh-1.dll, a
// DLL stock Windows does not have, and 1.7.3 failed to load because of it (#131).
#ifdef HC_TEST
static _Thread_local int hc_on_worker;
int hc_on_worker_thread(void) { return hc_on_worker; }
#define HC_MARK_WORKER() (hc_on_worker = 1)
#else
#define HC_MARK_WORKER() ((void)0)
#endif

static void hc_worker_loop(void) {
    HC_MARK_WORKER();
    HC_LOCK();
    for (;;) {
        while (hc_head == NULL) {
            hc_idle++;
            int timed_out = hc_queue_wait(30000);
            hc_idle--;
            if (timed_out && hc_head == NULL) {
                HC_UNLOCK();
                return;
            }
        }
        hc_job* j = hc_head;
        hc_head = j->next;
        if (hc_head == NULL) hc_tail = NULL;
        hc_queued--;
        HC_UNLOCK();

        j->run(j);

        HC_LOCK();
        j->done = 1;
        hc_job_signal(j);
    }
}

#ifdef _WIN32
static unsigned __stdcall hc_worker_main(void* arg) { (void)arg; hc_worker_loop(); return 0; }
#else
static void* hc_worker_main(void* arg) { (void)arg; hc_worker_loop(); return NULL; }
#endif

// hc_dispatch runs j on a worker and returns once it has. If no thread can be
// created at all, it runs j here rather than fail the call.
static void hc_dispatch(hc_job* j) {
    hc_init();
    j->done = 0;
    j->next = NULL;
    hc_job_cv_init(j);
    HC_LOCK();
    if (hc_tail == NULL) hc_head = j; else hc_tail->next = j;
    hc_tail = j;
    hc_queued++;
    if (hc_queued > hc_idle && hc_spawn() != 0 && hc_idle == 0) {
        // No worker and none can be made: take the job back and run it here.
        hc_job** pp = &hc_head;
        hc_job* prev = NULL;
        while (*pp != j) { prev = *pp; pp = &(*pp)->next; }
        *pp = j->next;
        if (hc_tail == j) hc_tail = prev;
        hc_queued--;
        HC_UNLOCK();
        j->run(j);
        hc_job_cv_destroy(j);
        return;
    }
    hc_queue_signal();
    while (!j->done) hc_job_wait(j);
    HC_UNLOCK();
    hc_job_cv_destroy(j);
}

static void run_callback(hc_job* j) { ((async_callback)j->fn)(j->id, j->a, j->b); }
// A getter's result stays owned by the callback, which may reuse or free it on
// its next call: Python hands back a slot in a small ring, .NET a buffer it
// frees on the following lookup, Android a thread-local. Go only reads it
// after the cgo call returns, by which time another lookup may have run, so
// the result is copied here, on the worker, before it can take another job.
// The copy is Go's to free.
static char* copy_cache_result(const char* result) {
    return result != NULL ? strdup(result) : NULL;
}

static void run_cache_get(hc_job* j) { j->ret_str = copy_cache_result(((session_cache_get_callback)j->fn)(j->a)); }
static void run_cache_put(hc_job* j) { j->ret_int = ((session_cache_put_callback)j->fn)(j->a, j->b, j->n); }
static void run_cache_error(hc_job* j) { ((session_cache_error_callback)j->fn)(j->a, j->b, j->c); }
static void run_cache_delete(hc_job* j) { j->ret_int = ((session_cache_delete_callback)j->fn)(j->a); }
static void run_ech_get(hc_job* j) { j->ret_str = copy_cache_result(((ech_cache_get_callback)j->fn)(j->a)); }
static void run_ech_put(hc_job* j) { j->ret_int = ((ech_cache_put_callback)j->fn)(j->a, j->b, j->n); }
static void run_async_cache_get(hc_job* j) { ((async_cache_get_callback)j->fn)(j->id, j->a); }
static void run_async_cache_put(hc_job* j) { ((async_cache_put_callback)j->fn)(j->id, j->a, j->b, j->n); }
static void run_async_cache_delete(hc_job* j) { ((async_cache_delete_callback)j->fn)(j->id, j->a); }
static void run_async_ech_get(hc_job* j) { ((async_ech_get_callback)j->fn)(j->id, j->a); }
static void run_async_ech_put(hc_job* j) { ((async_ech_put_callback)j->fn)(j->id, j->a, j->b, j->n); }

#define HC_JOB(runner, f) hc_job j; j.run = runner; j.fn = (void*)(f); j.id = 0; \
    j.a = NULL; j.b = NULL; j.c = NULL; j.n = 0; j.ret_str = NULL; j.ret_int = -1

void invoke_callback(async_callback cb, int64_t callback_id, const char* response_json, const char* error) {
    if (cb == NULL) return;
    HC_JOB(run_callback, cb);
    j.id = callback_id; j.a = response_json; j.b = error;
    hc_dispatch(&j);
}

char* invoke_cache_get(session_cache_get_callback cb, const char* key) {
    if (cb == NULL) return NULL;
    HC_JOB(run_cache_get, cb);
    j.a = key;
    hc_dispatch(&j);
    return j.ret_str;
}

int invoke_cache_put(session_cache_put_callback cb, const char* key, const char* value_json, int64_t ttl_seconds) {
    if (cb == NULL) return -1;
    HC_JOB(run_cache_put, cb);
    j.a = key; j.b = value_json; j.n = ttl_seconds;
    hc_dispatch(&j);
    return j.ret_int;
}

void invoke_cache_error(session_cache_error_callback cb, const char* operation, const char* key, const char* error) {
    if (cb == NULL) return;
    HC_JOB(run_cache_error, cb);
    j.a = operation; j.b = key; j.c = error;
    hc_dispatch(&j);
}

int invoke_cache_delete(session_cache_delete_callback cb, const char* key) {
    if (cb == NULL) return -1;
    HC_JOB(run_cache_delete, cb);
    j.a = key;
    hc_dispatch(&j);
    return j.ret_int;
}

char* invoke_ech_get(ech_cache_get_callback cb, const char* key) {
    if (cb == NULL) return NULL;
    HC_JOB(run_ech_get, cb);
    j.a = key;
    hc_dispatch(&j);
    return j.ret_str;
}

int invoke_ech_put(ech_cache_put_callback cb, const char* key, const char* value_base64, int64_t ttl_seconds) {
    if (cb == NULL) return -1;
    HC_JOB(run_ech_put, cb);
    j.a = key; j.b = value_base64; j.n = ttl_seconds;
    hc_dispatch(&j);
    return j.ret_int;
}

void invoke_async_cache_get(async_cache_get_callback cb, int64_t request_id, const char* key) {
    if (cb == NULL) return;
    HC_JOB(run_async_cache_get, cb);
    j.id = request_id; j.a = key;
    hc_dispatch(&j);
}

void invoke_async_cache_put(async_cache_put_callback cb, int64_t request_id, const char* key, const char* value_json, int64_t ttl_seconds) {
    if (cb == NULL) return;
    HC_JOB(run_async_cache_put, cb);
    j.id = request_id; j.a = key; j.b = value_json; j.n = ttl_seconds;
    hc_dispatch(&j);
}

void invoke_async_cache_delete(async_cache_delete_callback cb, int64_t request_id, const char* key) {
    if (cb == NULL) return;
    HC_JOB(run_async_cache_delete, cb);
    j.id = request_id; j.a = key;
    hc_dispatch(&j);
}

void invoke_async_ech_get(async_ech_get_callback cb, int64_t request_id, const char* key) {
    if (cb == NULL) return;
    HC_JOB(run_async_ech_get, cb);
    j.id = request_id; j.a = key;
    hc_dispatch(&j);
}

void invoke_async_ech_put(async_ech_put_callback cb, int64_t request_id, const char* key, const char* value_base64, int64_t ttl_seconds) {
    if (cb == NULL) return;
    HC_JOB(run_async_ech_put, cb);
    j.id = request_id; j.a = key; j.b = value_base64; j.n = ttl_seconds;
    hc_dispatch(&j);
}
