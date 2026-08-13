package transport

import (
	stdtls "crypto/tls"
	"crypto/x509"
	"os"
	"regexp"
	"testing"
)

// Regression locks for two defects found in the 1.6.9 work itself.

// SetProxy and SetPreset throw away the protocol transports and build fresh
// ones. They must carry the caller's certificate verification hooks across.
//
// They did not. tlsVerify was a write-only field: set by SetTLSVerify and never
// read again, while insecureSkipVerify sitting right beside it WAS re-applied on
// both rebuild paths. The effect was that a caller who installed certificate
// pinning and then rotated proxy or preset - the core use case for a
// fingerprinting client - silently dropped back to default verification. No
// error, no way to notice from the outside. That is the same silent-failure
// shape as issue #85 itself.
func TestTLSVerifySurvivesTransportRebuild(t *testing.T) {
	verify := &TLSVerify{
		VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error { return nil },
		VerifyConnection:      func(_ stdtls.ConnectionState) error { return nil },
	}

	installed := func(tr *Transport) (h1, h2, h3 bool) {
		h1 = tr.h1Transport != nil && tr.h1Transport.tlsVerify != nil
		h2 = tr.h2Transport != nil && tr.h2Transport.tlsVerify != nil
		h3 = tr.h3Transport == nil || tr.h3Transport.tlsVerify != nil
		return
	}

	t.Run("SetProxy", func(t *testing.T) {
		tr := NewTransport("chrome-146")
		defer tr.Close()

		tr.SetTLSVerify(verify)
		if h1, h2, h3 := installed(tr); !h1 || !h2 || !h3 {
			t.Fatalf("hooks not installed before rebuild: h1=%v h2=%v h3=%v", h1, h2, h3)
		}

		tr.SetProxy(nil)

		if h1, h2, h3 := installed(tr); !h1 || !h2 || !h3 {
			t.Errorf("SetProxy dropped the verification hooks: h1=%v h2=%v h3=%v", h1, h2, h3)
			t.Error("a caller that installed certificate pinning and then rotated proxy " +
				"would silently fall back to default verification")
		}
	})

	t.Run("SetPreset", func(t *testing.T) {
		tr := NewTransport("chrome-146")
		defer tr.Close()

		tr.SetTLSVerify(verify)
		tr.SetPreset("chrome-148")

		if h1, h2, h3 := installed(tr); !h1 || !h2 || !h3 {
			t.Errorf("SetPreset dropped the verification hooks: h1=%v h2=%v h3=%v", h1, h2, h3)
		}
	})
}

// The RoundTrip error paths must go through conn.release(), never a bare
// decrement of inFlight.
//
// release() does the decrement AND evaluates `closeRequested && inFlight <= 0`,
// which is what actually closes a connection whose close was deferred because it
// was evicted while a request was still in flight. A bare `conn.inFlight--`
// skips that check, so such a connection is never closed: its TLS conn, its h2
// ClientConn and that connection's reader goroutine leak for the process
// lifetime. Worse, the removeConn(key) that follows may then close a healthy
// replacement already published under the same key.
//
// This is a source scan rather than a behavioural test on purpose. Reproducing
// it needs a connection evicted at the exact moment its in-flight RoundTrip
// fails, which is a narrow race; the invariant "nothing outside release()
// decrements inFlight" is the thing worth pinning, and it cannot drift silently.
func TestNoBareInFlightDecrement(t *testing.T) {
	src, err := os.ReadFile("http2_transport.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}

	// Any decrement of an inFlight counter, on any receiver.
	dec := regexp.MustCompile(`(?m)^\s*\w+\.inFlight--`)
	matches := dec.FindAllIndex(src, -1)

	// Exactly one is legitimate: the one inside release() itself.
	if len(matches) != 1 {
		for _, m := range matches {
			line := 1
			for _, b := range src[:m[0]] {
				if b == '\n' {
					line++
				}
			}
			t.Errorf("http2_transport.go:%d decrements inFlight directly", line)
		}
		t.Fatalf("found %d direct inFlight decrements, want exactly 1 (the one inside release()); "+
			"every other path must call conn.release() so a deferred close actually fires", len(matches))
	}

	// And confirm the one that exists is the one in release().
	relIdx := regexp.MustCompile(`func \(c \*persistentConn\) release\(\)`).FindIndex(src)
	if relIdx == nil {
		t.Fatal("persistentConn.release() not found")
	}
	if matches[0][0] < relIdx[0] || matches[0][0] > relIdx[0]+400 {
		t.Error("the single inFlight decrement is not the one inside release()")
	}
}
