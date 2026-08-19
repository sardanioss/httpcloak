package main

import "testing"

// httpcloak_request_raw and its siblings return C.int64_t and signal failure
// with -1, so the return type cannot carry a message. Before the last-error
// slot existed, an invalid request JSON, an undecodable body and a genuine
// network failure were indistinguishable to every binding: all three reached
// the caller as the same generic "Request failed" string.
//
// The slot is keyed by session handle, guarded by sessionMu and deleted in
// httpcloak_session_free, so these lock the three properties that keep it
// from leaking or lying.
func TestLastErrorIsScopedToItsHandle(t *testing.T) {
	sessionMu.Lock()
	sessions[901] = nil // presence is what setLastError checks, not the value
	sessions[902] = nil
	sessionMu.Unlock()
	defer func() {
		sessionMu.Lock()
		delete(sessions, 901)
		delete(sessions, 902)
		delete(lastErrors, 901)
		delete(lastErrors, 902)
		sessionMu.Unlock()
	}()

	setLastError(901, "boom on %d", 901)
	if got := lastErrors[901]; got != "boom on 901" {
		t.Errorf("handle 901 stored %q, want %q", got, "boom on 901")
	}
	// One session's failure must not surface on another's next call.
	if got, ok := lastErrors[902]; ok {
		t.Errorf("handle 902 picked up %q from a different session", got)
	}
}

// A stored error must not survive a later success, or callers reading it
// after an unrelated failure get a stale message from a previous request.
func TestLastErrorIsClearedPerAttempt(t *testing.T) {
	sessionMu.Lock()
	sessions[903] = nil
	sessionMu.Unlock()
	defer func() {
		sessionMu.Lock()
		delete(sessions, 903)
		delete(lastErrors, 903)
		sessionMu.Unlock()
	}()

	setLastError(903, "first failure")
	clearLastError(903)
	if got, ok := lastErrors[903]; ok {
		t.Errorf("error %q survived clearLastError", got)
	}
}

// An unresolvable handle must store nothing, otherwise a caller passing junk
// handles grows the map without bound and nothing ever frees the entries.
func TestLastErrorIgnoresUnknownHandles(t *testing.T) {
	setLastError(999999, "should not be stored")
	sessionMu.Lock()
	_, ok := lastErrors[999999]
	sessionMu.Unlock()
	if ok {
		t.Error("stored an error for a handle with no session; the map can now grow without bound")
	}
}
