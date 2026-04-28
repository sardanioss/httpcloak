package httpcloak

import (
	"testing"
)

// Issue #57: silent retry on 5xx for callers that didn't ask for retries.
//
// The bug had three layers of damage:
//   1. Python binding's Session(retry: int = 3) → always sent retry=3 to clib
//   2. Node.js binding's `retry = 3` destructuring default → same
//   3. clib decoder + Go option chain happily honored that 3
//
// Fix: bindings default `retry` to 0 — matches the .NET binding that has
// always defaulted to 0. This test pins the GO-side option chain so any
// future refactor that re-introduces an implicit default is caught here
// even if the binding-level static tests are skipped.
//
// Two assertions:
//   1. NewSession with no options leaves retryCount at 0 (the fixed bug)
//   2. WithRetry / WithoutRetry / WithRetryConfig all wire through correctly

func TestRetryDefault_NoOptionsMeansNoRetry(t *testing.T) {
	cfg := &sessionConfig{}
	if cfg.retryCount != 0 {
		t.Fatalf("zero-value sessionConfig retryCount = %d, want 0 (issue #57)", cfg.retryCount)
	}
}

func TestRetryDefault_WithRetryEnables(t *testing.T) {
	cfg := &sessionConfig{}
	WithRetry(3)(cfg)
	if cfg.retryCount != 3 {
		t.Errorf("WithRetry(3) → retryCount = %d, want 3", cfg.retryCount)
	}
}

func TestRetryDefault_WithoutRetryExplicitlyDisables(t *testing.T) {
	cfg := &sessionConfig{retryCount: 5}
	WithoutRetry()(cfg)
	if cfg.retryCount != 0 {
		t.Errorf("WithoutRetry() left retryCount at %d, want 0", cfg.retryCount)
	}
}

func TestRetryDefault_WithRetryConfigPropagates(t *testing.T) {
	cfg := &sessionConfig{}
	WithRetryConfig(2, 0, 0, []int{500, 502})(cfg)
	if cfg.retryCount != 2 {
		t.Errorf("retryCount = %d, want 2", cfg.retryCount)
	}
	if len(cfg.retryOnStatus) != 2 || cfg.retryOnStatus[0] != 500 || cfg.retryOnStatus[1] != 502 {
		t.Errorf("retryOnStatus = %v, want [500, 502]", cfg.retryOnStatus)
	}
}

// TestRetryDefault_NewSessionNoRetryOptions builds an actual Session with
// no retry options and inspects the protocol.SessionConfig flowing into the
// inner session. RetryEnabled must be false; any future change that flips
// this default is the same bug returning. (Avoids any network setup —
// NewSession populates the inner config eagerly even on transport errors.)
func TestRetryDefault_NewSessionNoRetryOptions(t *testing.T) {
	// Non-existent preset is fine; we only inspect retry wiring, not transport.
	s := NewSession("chrome-146")
	defer s.Close()

	if s.inner == nil {
		t.Fatal("session.inner not built — NewSession contract changed?")
	}
	cfg := s.inner.Config
	if cfg == nil {
		t.Fatal("inner.Config is nil")
	}
	if cfg.RetryEnabled {
		t.Errorf("RetryEnabled = true with no options, want false (issue #57)")
	}
	if cfg.MaxRetries != 0 {
		t.Errorf("MaxRetries = %d with no options, want 0 (issue #57)", cfg.MaxRetries)
	}
}
