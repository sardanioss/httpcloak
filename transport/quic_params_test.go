package transport

import (
	"bytes"
	"encoding/binary"
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

// TestBuildChromeTransportParams_ExactSet locks the full set of Chrome-specific
// QUIC transport parameters we add.
//
// A real Chrome 151 QUIC ClientHello carries exactly these transport
// parameters: 1 (max_idle_timeout), 3 (max_udp_payload_size), 4
// (initial_max_data), 5/6/7 (initial_max_stream_data_*), 8/9
// (initial_max_streams_*), 15 (initial_source_connection_id), 17
// (version_information), 32 (max_datagram_frame_size), 12584
// (google_connection_options) and one GREASE parameter.
//
// Everything except 17 and 12584 comes from quic-go's own config, and the
// GREASE parameter is inserted by the fork's Chrome-mode marshaling. So this
// map must contain those two and nothing else.
//
// Two parameters were previously sent that Chrome does not send at all:
//
//	google_version (0x4752 / 18258)
//	initial_rtt    (0x3127 / 12583)
//
// Both were removed. initial_rtt additionally required timing a throwaway TCP
// connection to the target before an HTTP/3 request, which was its own tell.
func TestBuildChromeTransportParams_ExactSet(t *testing.T) {
	params := BuildChromeTransportParams()

	want := map[uint64]bool{
		0x11:   true, // version_information
		0x3128: true, // google_connection_options (12584)
	}

	for id := range params {
		if !want[id] {
			t.Errorf("BuildChromeTransportParams() sends unexpected transport parameter "+
				"0x%x (%d); real Chrome does not send it", id, id)
		}
	}
	for id := range want {
		if _, ok := params[id]; !ok {
			t.Errorf("BuildChromeTransportParams() missing expected transport parameter 0x%x (%d)", id, id)
		}
	}

	// Named explicitly so a regression reads clearly rather than as a count mismatch.
	for _, banned := range []struct {
		id   uint64
		name string
	}{
		{0x4752, "google_version"},
		{0x3127, "initial_rtt"},
	} {
		if _, ok := params[banned.id]; ok {
			t.Errorf("%s (0x%x) is sent again; a real Chrome 151 capture shows Chrome does not send it",
				banned.name, banned.id)
		}
	}
}

// version_information (0x11) is chosen_version followed by the available list,
// and Chrome puts a GREASE version ahead of QUICv1 in that list.
func TestBuildChromeTransportParams_VersionInformation(t *testing.T) {
	params := BuildChromeTransportParams()

	got, ok := params[tpVersionInformation]
	if !ok {
		t.Fatal("BuildChromeTransportParams() missing version_information (0x11)")
	}
	if len(got) != 12 {
		t.Fatalf("version_information length = %d, want 12 (chosen + 2 available)", len(got))
	}
	if chosen := binary.BigEndian.Uint32(got[0:4]); chosen != 1 {
		t.Errorf("chosen_version = %d, want 1 (QUICv1)", chosen)
	}
	// GREASE versions are of the form 0x?a?a?a?a.
	if grease := binary.BigEndian.Uint32(got[4:8]); grease&0x0f0f0f0f != 0x0a0a0a0a {
		t.Errorf("first available version = 0x%08x, want a GREASE version (0x?a?a?a?a)", grease)
	}
	if v1 := binary.BigEndian.Uint32(got[8:12]); v1 != 1 {
		t.Errorf("second available version = %d, want 1 (QUICv1)", v1)
	}
}
