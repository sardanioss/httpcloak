// Host-callback dispatch for the C shim. It lives in its own file rather than
// in the cgo preamble of httpcloak.go: that file has //export functions, so
// cgo copies its preamble into _cgo_export.c too, and anything defined there
// would exist twice.

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "callback_pool.h"

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <pthread.h>
#include <time.h>
#include <errno.h>
#endif

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
    void* arg;
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

// A pool of threads this shim owns. There are two: one runs host callbacks for
// Go (#114), the other runs Go for the host's calls into the library (#147).
// They are kept apart so neither kind of work ever queues behind the other.
typedef struct hc_pool {
#ifdef _WIN32
    CRITICAL_SECTION lock;
    CONDITION_VARIABLE queue_cv;
    INIT_ONCE once;
#else
    pthread_mutex_t lock;
    pthread_cond_t queue_cv;
#endif
    hc_job* head;
    hc_job* tail;
    int queued; // jobs waiting for a worker
    int idle;   // workers waiting for a job
    int kind;   // HC_POOL_*, for the test builds' thread marks
} hc_pool;

#define HC_POOL_CALLBACK 1
#define HC_POOL_EXPORT 2

#ifdef _WIN32
#define HC_POOL_INIT(k) { .once = INIT_ONCE_STATIC_INIT, .kind = (k) }
static BOOL CALLBACK hc_init_win(PINIT_ONCE o, PVOID p, PVOID* c) {
    (void)o; (void)c;
    hc_pool* pool = (hc_pool*)p;
    InitializeCriticalSection(&pool->lock);
    InitializeConditionVariable(&pool->queue_cv);
    return TRUE;
}
static void hc_init(hc_pool* p) { InitOnceExecuteOnce(&p->once, hc_init_win, p, NULL); }
#define HC_LOCK(p)   EnterCriticalSection(&(p)->lock)
#define HC_UNLOCK(p) LeaveCriticalSection(&(p)->lock)
#define HC_JOB_CV(j) ((PCONDITION_VARIABLE)(j)->cv_storage)
static void hc_job_cv_init(hc_job* j) { InitializeConditionVariable(HC_JOB_CV(j)); }
static void hc_job_cv_destroy(hc_job* j) { (void)j; }
static void hc_job_wait(hc_pool* p, hc_job* j) { SleepConditionVariableCS(HC_JOB_CV(j), &p->lock, INFINITE); }
static void hc_job_signal(hc_job* j) { WakeConditionVariable(HC_JOB_CV(j)); }
static void hc_queue_signal(hc_pool* p) { WakeConditionVariable(&p->queue_cv); }
// Returns nonzero when the wait timed out.
static int hc_queue_wait(hc_pool* p, unsigned ms) {
    return !SleepConditionVariableCS(&p->queue_cv, &p->lock, ms) && GetLastError() == ERROR_TIMEOUT;
}
static unsigned __stdcall hc_worker_main(void* arg);
static int hc_spawn(hc_pool* p) {
    uintptr_t h = _beginthreadex(NULL, 0, hc_worker_main, p, 0, NULL);
    if (h == 0) return -1;
    CloseHandle((HANDLE)h);
    return 0;
}
#else
#define HC_POOL_INIT(k) { .lock = PTHREAD_MUTEX_INITIALIZER, .queue_cv = PTHREAD_COND_INITIALIZER, .kind = (k) }
static void hc_init(hc_pool* p) { (void)p; }
#define HC_LOCK(p)   pthread_mutex_lock(&(p)->lock)
#define HC_UNLOCK(p) pthread_mutex_unlock(&(p)->lock)
#define HC_JOB_CV(j) ((pthread_cond_t*)(void*)(j)->cv_storage)
static void hc_job_cv_init(hc_job* j) { pthread_cond_init(HC_JOB_CV(j), NULL); }
static void hc_job_cv_destroy(hc_job* j) { pthread_cond_destroy(HC_JOB_CV(j)); }
static void hc_job_wait(hc_pool* p, hc_job* j) { pthread_cond_wait(HC_JOB_CV(j), &p->lock); }
static void hc_job_signal(hc_job* j) { pthread_cond_signal(HC_JOB_CV(j)); }
static void hc_queue_signal(hc_pool* p) { pthread_cond_signal(&p->queue_cv); }
static int hc_queue_wait(hc_pool* p, unsigned ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    return pthread_cond_timedwait(&p->queue_cv, &p->lock, &ts) == ETIMEDOUT;
}
static void* hc_worker_main(void* arg);
static int hc_spawn(hc_pool* p) {
    pthread_t t;
    if (pthread_create(&t, NULL, hc_worker_main, p) != 0) return -1;
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

static hc_pool hc_callback_pool = HC_POOL_INIT(HC_POOL_CALLBACK);
static hc_pool hc_export_pool = HC_POOL_INIT(HC_POOL_EXPORT);

// Test builds record which pool, if any, a thread belongs to so the tests can
// check where callbacks and exports run. Release builds carry no thread-local
// state at all: MinGW implements _Thread_local through libgcc_s_seh-1.dll, a
// DLL stock Windows does not have, and 1.7.3 failed to load because of it (#131).
#ifdef HC_TEST
static _Thread_local int hc_thread_kind;
int hc_on_worker_thread(void) { return hc_thread_kind == HC_POOL_CALLBACK; }
int hc_on_export_thread(void) { return hc_thread_kind == HC_POOL_EXPORT; }
#define HC_MARK_WORKER(p) (hc_thread_kind = (p)->kind)
#else
#define HC_MARK_WORKER(p) ((void)(p))
#endif

static void hc_worker_loop(hc_pool* p) {
    HC_MARK_WORKER(p);
    HC_LOCK(p);
    for (;;) {
        while (p->head == NULL) {
            p->idle++;
            int timed_out = hc_queue_wait(p, 30000);
            p->idle--;
            if (timed_out && p->head == NULL) {
                HC_UNLOCK(p);
                return;
            }
        }
        hc_job* j = p->head;
        p->head = j->next;
        if (p->head == NULL) p->tail = NULL;
        p->queued--;
        HC_UNLOCK(p);

        j->run(j);

        HC_LOCK(p);
        j->done = 1;
        hc_job_signal(j);
    }
}

#ifdef _WIN32
static unsigned __stdcall hc_worker_main(void* arg) { hc_worker_loop((hc_pool*)arg); return 0; }
#else
static void* hc_worker_main(void* arg) { hc_worker_loop((hc_pool*)arg); return NULL; }
#endif

// hc_dispatch runs j on one of p's workers and returns once it has. If no
// thread can be created at all, it runs j here rather than fail the call.
static void hc_dispatch(hc_pool* p, hc_job* j) {
    hc_init(p);
    j->done = 0;
    j->next = NULL;
    hc_job_cv_init(j);
    HC_LOCK(p);
    if (p->tail == NULL) p->head = j; else p->tail->next = j;
    p->tail = j;
    p->queued++;
    if (p->queued > p->idle && hc_spawn(p) != 0 && p->idle == 0) {
        // No worker and none can be made: take the job back and run it here.
        hc_job** pp = &p->head;
        hc_job* prev = NULL;
        while (*pp != j) { prev = *pp; pp = &(*pp)->next; }
        *pp = j->next;
        if (p->tail == j) p->tail = prev;
        p->queued--;
        HC_UNLOCK(p);
        j->run(j);
        hc_job_cv_destroy(j);
        return;
    }
    hc_queue_signal(p);
    while (!j->done) hc_job_wait(p, j);
    HC_UNLOCK(p);
    hc_job_cv_destroy(j);
}

// ---------------------------------------------------------------------------
// Calls into the library run on threads this shim owns too (#147).
//
// The same APC hazard runs the other way: a .NET thread that calls an export
// runs Go on a goroutine stack, and a GC suspension APC aimed at it then kills
// the process with 0xC000000D. So on Windows every public function is a C
// wrapper (exports_gen.c) that hands the Go call to hc_export_pool and waits.
// Arguments and results pass through the wrapper's own stack frame, which
// outlives the job, and the caller blocks exactly as long as before.
// ---------------------------------------------------------------------------

#ifdef HC_TEST
static volatile int hc_test_hops;
int hc_test_export_hops(void) { return __sync_fetch_and_add(&hc_test_hops, 0); }
#define HC_COUNT_HOP() do { if (hc_on_export_thread()) __sync_fetch_and_add(&hc_test_hops, 1); } while (0)
#else
#define HC_COUNT_HOP() ((void)0)
#endif

static void run_export(hc_job* j) {
    HC_COUNT_HOP();
    ((void (*)(void*))j->fn)(j->arg);
}

void hc_export_hop(void (*thunk)(void*), void* args) {
    hc_job j;
    j.run = run_export;
    j.fn = (void*)thunk;
    j.arg = args;
    hc_dispatch(&hc_export_pool, &j);
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

#define HC_JOB(runner, f) hc_job j; j.run = runner; j.fn = (void*)(f); j.arg = NULL; j.id = 0; \
    j.a = NULL; j.b = NULL; j.c = NULL; j.n = 0; j.ret_str = NULL; j.ret_int = -1

void invoke_callback(async_callback cb, int64_t callback_id, const char* response_json, const char* error) {
    if (cb == NULL) return;
    HC_JOB(run_callback, cb);
    j.id = callback_id; j.a = response_json; j.b = error;
    hc_dispatch(&hc_callback_pool, &j);
}

char* invoke_cache_get(session_cache_get_callback cb, const char* key) {
    if (cb == NULL) return NULL;
    HC_JOB(run_cache_get, cb);
    j.a = key;
    hc_dispatch(&hc_callback_pool, &j);
    return j.ret_str;
}

int invoke_cache_put(session_cache_put_callback cb, const char* key, const char* value_json, int64_t ttl_seconds) {
    if (cb == NULL) return -1;
    HC_JOB(run_cache_put, cb);
    j.a = key; j.b = value_json; j.n = ttl_seconds;
    hc_dispatch(&hc_callback_pool, &j);
    return j.ret_int;
}

void invoke_cache_error(session_cache_error_callback cb, const char* operation, const char* key, const char* error) {
    if (cb == NULL) return;
    HC_JOB(run_cache_error, cb);
    j.a = operation; j.b = key; j.c = error;
    hc_dispatch(&hc_callback_pool, &j);
}

int invoke_cache_delete(session_cache_delete_callback cb, const char* key) {
    if (cb == NULL) return -1;
    HC_JOB(run_cache_delete, cb);
    j.a = key;
    hc_dispatch(&hc_callback_pool, &j);
    return j.ret_int;
}

char* invoke_ech_get(ech_cache_get_callback cb, const char* key) {
    if (cb == NULL) return NULL;
    HC_JOB(run_ech_get, cb);
    j.a = key;
    hc_dispatch(&hc_callback_pool, &j);
    return j.ret_str;
}

int invoke_ech_put(ech_cache_put_callback cb, const char* key, const char* value_base64, int64_t ttl_seconds) {
    if (cb == NULL) return -1;
    HC_JOB(run_ech_put, cb);
    j.a = key; j.b = value_base64; j.n = ttl_seconds;
    hc_dispatch(&hc_callback_pool, &j);
    return j.ret_int;
}

void invoke_async_cache_get(async_cache_get_callback cb, int64_t request_id, const char* key) {
    if (cb == NULL) return;
    HC_JOB(run_async_cache_get, cb);
    j.id = request_id; j.a = key;
    hc_dispatch(&hc_callback_pool, &j);
}

void invoke_async_cache_put(async_cache_put_callback cb, int64_t request_id, const char* key, const char* value_json, int64_t ttl_seconds) {
    if (cb == NULL) return;
    HC_JOB(run_async_cache_put, cb);
    j.id = request_id; j.a = key; j.b = value_json; j.n = ttl_seconds;
    hc_dispatch(&hc_callback_pool, &j);
}

void invoke_async_cache_delete(async_cache_delete_callback cb, int64_t request_id, const char* key) {
    if (cb == NULL) return;
    HC_JOB(run_async_cache_delete, cb);
    j.id = request_id; j.a = key;
    hc_dispatch(&hc_callback_pool, &j);
}

void invoke_async_ech_get(async_ech_get_callback cb, int64_t request_id, const char* key) {
    if (cb == NULL) return;
    HC_JOB(run_async_ech_get, cb);
    j.id = request_id; j.a = key;
    hc_dispatch(&hc_callback_pool, &j);
}

void invoke_async_ech_put(async_ech_put_callback cb, int64_t request_id, const char* key, const char* value_base64, int64_t ttl_seconds) {
    if (cb == NULL) return;
    HC_JOB(run_async_ech_put, cb);
    j.id = request_id; j.a = key; j.b = value_base64; j.n = ttl_seconds;
    hc_dispatch(&hc_callback_pool, &j);
}
