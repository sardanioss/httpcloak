package transport

import (
	"bytes"
	"testing"
)

// TestBuildChromeTransportParams_GoogleConnectionOptions locks the wire value
// of QUIC transport parameter 0x3128 (google_connection_options).
//
// Stable Chrome's default for kQuicOptions is "ORIG" (Chromium
// net/base/features.cc → kTryQuicByDefault / kQuicOptions). Sending "B2ON"
// (Enable BBRv2 — only present with --enable-features=QuicConnectionOptions=B2ON
// or a Finch override) causes some QUIC-aware bot detectors to silently drop
// follow-up frames after the handshake, producing a 30s MaxIdleTimeout error.
//
// If a future Chrome capture shows a different value, update both this test
// and the value in BuildChromeTransportParams together.
func TestBuildChromeTransportParams_GoogleConnectionOptions(t *testing.T) {
	params := BuildChromeTransportParams()

	got, ok := params[tpGoogleConnectionOptions]
	if !ok {
		t.Fatalf("BuildChromeTransportParams() missing tpGoogleConnectionOptions (0x3128)")
	}
	want := []byte("ORIG")
	if !bytes.Equal(got, want) {
		t.Errorf("google_connection_options value = %q (% x), want %q (% x)",
			got, got, want, want)
	}
	if len(got) != 4 {
		t.Errorf("google_connection_options length = %d, want 4 (single QUIC tag)", len(got))
	}
}
