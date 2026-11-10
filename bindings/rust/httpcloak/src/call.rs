//! Requests in flight.
//!
//! Every request goes through the library's asynchronous exports, blocking or
//! not: those report their result, or the reason they failed, to a callback,
//! where the synchronous `_raw` exports leave the reason in a slot per session
//! that a concurrent call on the same session overwrites. They can also be
//! cancelled, which is how timeouts are made exact and how dropping a future
//! stops its request.
//!
//! A [`Call`] is one registered callback ID. The library completes it on one of
//! its callback threads; a thread blocked in [`Call::wait`] or a task polling
//! [`CallFuture`] picks the result up. Whoever gives up on a call first, the
//! caller by dropping it or the deadline by expiring, cancels it in the
//! library, and a result that still arrives afterwards is handed to the call's
//! [`Leftover`] handler so a stream it opened is closed rather than leaked.

use std::collections::{BTreeMap, HashMap};
use std::ffi::c_char;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use httpcloak_sys as sys;
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::ffi;

/// A finished call's result: the JSON the library reported, and when.
pub(crate) struct Completed {
    pub(crate) json: String,
    pub(crate) elapsed: Duration,
}

/// What to do with a successful result that arrives after the call was given
/// up on.
#[derive(Clone, Copy)]
pub(crate) enum Leftover {
    /// Nothing: a buffered response owns nothing in the library.
    Discard,
    /// The result is stream metadata; close the stream it names.
    CloseStream,
}

pub(crate) struct Shared {
    id: i64,
    started: Instant,
    leftover: Leftover,
    state: Mutex<State>,
    done: Condvar,
}

#[derive(Default)]
struct State {
    outcome: Option<Result<Completed>>,
    waker: Option<Waker>,
    /// The outcome has been taken by the caller.
    taken: bool,
    /// Nobody will take the outcome any more; the library has been told to
    /// cancel, and a late result is disposed of.
    abandoned: bool,
}

/// The calls the library has yet to report on, by callback ID.
static PENDING: LazyLock<Mutex<HashMap<i64, Arc<Shared>>>> = LazyLock::new(Default::default);

/// Locks a mutex, carrying on through poisoning: nothing here leaves its data
/// half-updated across a panic, and the callback must never panic.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// An asynchronous library call, from registering its callback until its
/// result is taken or it is given up on.
pub(crate) struct Call {
    shared: Arc<Shared>,
    finished: bool,
}

impl Call {
    /// Registers a callback and runs `start` with its ID, which must hand the
    /// ID to exactly one asynchronous export.
    pub(crate) fn start(leftover: Leftover, start: impl FnOnce(i64)) -> Result<Call> {
        // SAFETY: on_complete has the signature the library expects, never
        // unwinds, and lives for the whole program.
        let id = unsafe { sys::httpcloak_register_callback(Some(on_complete)) };
        if id <= 0 {
            return Err(Error::new_other("the library could not register a completion callback"));
        }
        let shared = Arc::new(Shared {
            id,
            started: Instant::now(),
            leftover,
            state: Mutex::new(State::default()),
            done: Condvar::new(),
        });
        // Registered before the export runs: its result can arrive on another
        // thread before the export has even returned.
        lock(&PENDING).insert(id, shared.clone());
        start(id);
        Ok(Call { shared, finished: false })
    }

    /// Blocks until the result arrives or `deadline` passes.
    pub(crate) fn wait(mut self, deadline: Option<Deadline>) -> Result<Completed> {
        let mut state = lock(&self.shared.state);
        loop {
            if let Some(outcome) = state.outcome.take() {
                state.taken = true;
                self.finished = true;
                return outcome;
            }
            match deadline {
                None => state = self.shared.done.wait(state).unwrap_or_else(|e| e.into_inner()),
                Some(d) => {
                    let now = Instant::now();
                    if now >= d.at {
                        drop(state);
                        self.shared.expire(d.timeout);
                        state = lock(&self.shared.state);
                        continue;
                    }
                    state = self.shared.done.wait_timeout(state, d.at - now).unwrap_or_else(|e| e.into_inner()).0;
                }
            }
        }
    }

    /// Waits for the result without blocking.
    pub(crate) fn into_future(self, deadline: Option<Deadline>) -> CallFuture {
        CallFuture { call: self, deadline, timer: None, timer_armed: false }
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        if !self.finished {
            self.shared.abandon();
        }
    }
}

/// When a call times out, and the timeout to report.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Deadline {
    pub(crate) at: Instant,
    pub(crate) timeout: Duration,
}

impl Deadline {
    /// The deadline `timeout` from now, or `None` when that is too far away to
    /// represent, which is as good as no deadline.
    pub(crate) fn after(timeout: Duration) -> Option<Deadline> {
        Instant::now().checked_add(timeout).map(|at| Deadline { at, timeout })
    }
}

impl Shared {
    /// Records the library's result, or disposes of it when nobody wants it.
    fn complete(&self, outcome: Result<Completed>) {
        let mut state = lock(&self.state);
        if state.abandoned {
            drop(state);
            if let Ok(completed) = outcome {
                self.leftover.dispose(&completed.json);
            }
            return;
        }
        state.outcome = Some(outcome);
        let waker = state.waker.take();
        drop(state);
        self.done.notify_all();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Gives up on the call: disposes of a result that has arrived but not
    /// been taken, or tells the library to cancel.
    fn abandon(&self) {
        let mut state = lock(&self.state);
        if state.abandoned {
            return;
        }
        state.abandoned = true;
        state.waker = None;
        let outcome = state.outcome.take();
        drop(state);
        match outcome {
            Some(Ok(completed)) => self.leftover.dispose(&completed.json),
            Some(Err(_)) => {}
            // SAFETY: plain call; an ID the library no longer knows is a no-op.
            None => unsafe { sys::httpcloak_cancel_request(self.id) },
        }
    }

    /// Fails the call with a timeout, unless it has finished already.
    fn expire(&self, timeout: Duration) {
        let mut state = lock(&self.state);
        if state.outcome.is_some() || state.taken || state.abandoned {
            return;
        }
        state.outcome = Some(Err(Error::timeout(format!("the request timed out after {timeout:?}"))));
        state.abandoned = true;
        let waker = state.waker.take();
        drop(state);
        // SAFETY: plain call; an ID the library no longer knows is a no-op.
        unsafe { sys::httpcloak_cancel_request(self.id) };
        self.done.notify_all();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Leftover {
    /// Releases what a result nobody will take owns.
    pub(crate) fn dispose(self, json: &str) {
        match self {
            Leftover::Discard => {}
            Leftover::CloseStream => {
                #[derive(Deserialize)]
                struct Handle {
                    #[serde(default)]
                    stream_handle: i64,
                }
                if let Ok(Handle { stream_handle }) = serde_json::from_str::<Handle>(json) {
                    if stream_handle > 0 {
                        // SAFETY: plain call; the stream is ours and nobody
                        // else has seen its handle.
                        unsafe { sys::httpcloak_stream_close(stream_handle) };
                    }
                }
            }
        }
    }
}

/// The library's completion callback, for every call.
///
/// It runs on one of the library's callback threads, which waits for it, so
/// it only copies the strings (they are freed when it returns) and hands them
/// over. It must not unwind into the library.
unsafe extern "C" fn on_complete(id: i64, response: *const c_char, error: *const c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the library passes null or strings valid for this call.
        let (response, error) = unsafe { (ffi::borrow_string(response), ffi::borrow_string(error)) };
        let Some(shared) = lock(&PENDING).remove(&id) else { return };
        let elapsed = shared.started.elapsed();
        let outcome = match (response, error) {
            (Some(json), _) if !json.is_empty() => Ok(Completed { json, elapsed }),
            (_, Some(error)) => Err(Error::from_library(ffi::async_error_message(&error))),
            _ => Err(Error::new_other("the library reported neither a response nor an error")),
        };
        shared.complete(outcome);
    }));
}

/// [`Call`] as a future.
pub(crate) struct CallFuture {
    call: Call,
    deadline: Option<Deadline>,
    /// The deadline's place in the timer, once armed, so that it is removed
    /// the moment the call is done rather than when the deadline passes.
    timer: Option<TimerKey>,
    timer_armed: bool,
}

impl Future for CallFuture {
    type Output = Result<Completed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let shared = &this.call.shared;
        let mut state = lock(&shared.state);
        if let Some(outcome) = state.outcome.take() {
            state.taken = true;
            drop(state);
            this.call.finished = true;
            if let Some(key) = this.timer.take() {
                TIMER.disarm(key);
            }
            return Poll::Ready(outcome);
        }
        match &state.waker {
            Some(w) if w.will_wake(cx.waker()) => {}
            _ => state.waker = Some(cx.waker().clone()),
        }
        drop(state);
        if let (Some(deadline), false) = (this.deadline, this.timer_armed) {
            this.timer_armed = true;
            // Without a timer thread, the library's own timeout, the same
            // one rounded up to a whole second, still ends the call.
            this.timer = TIMER.arm(deadline.at, Expiry::Call(Arc::downgrade(shared), deadline.timeout));
        }
        Poll::Pending
    }
}

impl Drop for CallFuture {
    fn drop(&mut self) {
        if let Some(key) = self.timer.take() {
            TIMER.disarm(key);
        }
    }
}

/// What the timer does when a deadline passes.
pub(crate) enum Expiry {
    /// Fail a call with a timeout and cancel it.
    Call(Weak<Shared>, Duration),
    /// Cancel a stream's context, so a read blocked on it returns.
    Stream(Weak<StreamDeadline>),
}

/// A streamed body's deadline: the request's timeout, counted from when it
/// was sent, carried past the headers into the reads of the body.
pub(crate) struct StreamDeadline {
    pub(crate) handle: i64,
    pub(crate) deadline: Deadline,
    expired: AtomicBool,
}

impl StreamDeadline {
    pub(crate) fn new(handle: i64, deadline: Deadline) -> StreamDeadline {
        StreamDeadline { handle, deadline, expired: AtomicBool::new(false) }
    }

    /// Whether the deadline has passed, cancelling the stream the first time
    /// that is noticed, by whoever notices.
    pub(crate) fn passed(&self) -> bool {
        if self.expired.load(AtomicOrdering::Acquire) {
            return true;
        }
        if Instant::now() >= self.deadline.at {
            self.expire();
            return true;
        }
        false
    }

    fn expire(&self) {
        if !self.expired.swap(true, AtomicOrdering::AcqRel) {
            // SAFETY: plain call. Cancelling may race a read on another
            // thread, which is what it is for, and a stream already closed is
            // a no-op: handles are never reused.
            unsafe { sys::httpcloak_stream_cancel(self.handle) };
        }
    }
}

/// An armed deadline's place in the timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TimerKey(Instant, u64);

/// Deadlines that need something other than the waiting thread to act on
/// them: a future has no thread to wait with, and a stream read is blocked in
/// the library. One thread serves them all, started the first time one is
/// armed. Entries are removed as soon as their owner is done with them, so
/// the timer holds as many as there are live deadlines.
struct Timer {
    queue: Mutex<BTreeMap<TimerKey, Expiry>>,
    wake: Condvar,
    running: AtomicBool,
    next: AtomicU64,
}

static TIMER: LazyLock<Arc<Timer>> = LazyLock::new(|| {
    let timer = Arc::new(Timer {
        queue: Mutex::new(BTreeMap::new()),
        wake: Condvar::new(),
        running: AtomicBool::new(false),
        next: AtomicU64::new(0),
    });
    // The thread keeps the timer for the life of the process, as the static
    // does.
    let for_thread = timer.clone();
    if std::thread::Builder::new().name("httpcloak-timer".into()).spawn(move || for_thread.run()).is_ok() {
        timer.running.store(true, AtomicOrdering::Release);
    }
    timer
});

/// Arms a stream's deadline; `None` when there is no timer thread, in which
/// case reads still check the deadline themselves before blocking.
pub(crate) fn arm_stream(deadline: &Arc<StreamDeadline>) -> Option<TimerKey> {
    TIMER.arm(deadline.deadline.at, Expiry::Stream(Arc::downgrade(deadline)))
}

pub(crate) fn disarm(key: TimerKey) {
    TIMER.disarm(key)
}

impl Timer {
    /// Queues `expiry` for `at`. `None` when there is no timer thread.
    fn arm(&self, at: Instant, expiry: Expiry) -> Option<TimerKey> {
        if !self.running.load(AtomicOrdering::Acquire) {
            return None;
        }
        let key = TimerKey(at, self.next.fetch_add(1, AtomicOrdering::Relaxed));
        let mut queue = lock(&self.queue);
        let earliest = queue.keys().next().map_or(true, |first| key < *first);
        queue.insert(key, expiry);
        drop(queue);
        if earliest {
            self.wake.notify_one();
        }
        Some(key)
    }

    /// Removes a deadline whose owner is done. A no-op once it has fired.
    fn disarm(&self, key: TimerKey) {
        lock(&self.queue).remove(&key);
    }

    fn run(&self) {
        let mut queue = lock(&self.queue);
        loop {
            let now = Instant::now();
            let mut due = Vec::new();
            while let Some(entry) = queue.first_entry().filter(|e| e.key().0 <= now) {
                due.push(entry.remove());
            }
            if !due.is_empty() {
                // Expiring calls into the library; not with the queue locked.
                drop(queue);
                for expiry in due {
                    match expiry {
                        Expiry::Call(call, timeout) => {
                            if let Some(call) = call.upgrade() {
                                call.expire(timeout);
                            }
                        }
                        Expiry::Stream(stream) => {
                            if let Some(stream) = stream.upgrade() {
                                stream.expire();
                            }
                        }
                    }
                }
                queue = lock(&self.queue);
                continue;
            }
            queue = match queue.keys().next().map(|k| k.0) {
                Some(at) => self.wake.wait_timeout(queue, at - now).unwrap_or_else(|e| e.into_inner()).0,
                None => self.wake.wait(queue).unwrap_or_else(|e| e.into_inner()),
            };
        }
    }
}

/// How many deadlines the timer holds. For tests that check nothing is left
/// behind.
#[doc(hidden)]
pub fn armed_deadlines() -> usize {
    if TIMER.running.load(AtomicOrdering::Acquire) {
        lock(&TIMER.queue).len()
    } else {
        0
    }
}

/// How many calls the library has yet to report on. For tests that check
/// nothing is left behind.
#[doc(hidden)]
pub fn pending_calls() -> usize {
    lock(&PENDING).len()
}
