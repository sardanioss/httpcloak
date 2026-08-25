package transport

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
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
// which carries QUICv1 and one GREASE version.
//
// The ORDER of those two is not asserted here, and that is the point: upstream
// inserts the GREASE label at a uniformly random index, so half of real
// connections lead with it. TestGREASEVersionPositionVaries next door is what
// holds that property; this one holds the shape.
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

	first := binary.BigEndian.Uint32(got[4:8])
	second := binary.BigEndian.Uint32(got[8:12])
	// GREASE versions are of the form 0x?a?a?a?a.
	isGrease := func(v uint32) bool { return v&0x0f0f0f0f == 0x0a0a0a0a }
	switch {
	case isGrease(first) && second == 1:
	case first == 1 && isGrease(second):
	default:
		t.Errorf("available_versions = 0x%08x, 0x%08x; want QUICv1 and one "+
			"GREASE version in some order", first, second)
	}
}

// Only Chromium-based presets may carry Chrome's browser-specific QUIC
// transport parameters.
//
// The gate used to key off H3QUICTransportParamOrder(), which selects parameter
// ORDERING and defaults to "chrome" for any preset that does not set it. Every
// non-Chrome preset therefore advertised google_connection_options (0x3128) and
// version_information (0x11) on HTTP/3. Measured on the wire: a forced-H3
// firefox-148 connection sent a Firefox-shaped ClientHello - 12 Firefox
// signature algorithms, not Chrome's 10 - alongside a Google-only transport
// parameter. That combination is a flat contradiction for anyone inspecting the
// handshake, and it is exactly the kind of tell this library exists to remove.
func TestChromeQUICParamsOnlyForChromePresets(t *testing.T) {
	shouldSend := map[string]bool{
		"chrome-151":         true,
		"chrome-151-windows": true,
		"chrome-151-android": true,
		"chrome-150":         true,
		"chrome-146":         true,
		// WebKit underneath, so no Google parameters.
		"chrome-151-ios": false,
		"safari-18":      false,
		"firefox-148":    false,
		"firefox-133":    false,
	}

	for name, want := range shouldSend {
		p := fingerprint.Get(name)
		if p == nil {
			continue
		}
		params := AdditionalTransportParamsForPreset(p, nil, "", 0)
		got := len(params) > 0
		if got != want {
			verb := "must not"
			if want {
				verb = "must"
			}
			t.Errorf("%s: %s carry Chrome QUIC transport parameters, got %d of them", name, verb, len(params))
		}
		if !want {
			for _, id := range []uint64{0x11, 0x3128} {
				if _, ok := params[id]; ok {
					t.Errorf("%s advertises Chrome-only transport parameter 0x%x on a non-Chromium identity", name, id)
				}
			}
		}
	}
}

// google_connection_options is preset-driven, and the preset key has to reach
// the wire rather than only the getter.
//
// The value is not fixed by Chrome version. Chromium parses it from
// features::kQuicOptions under kTryQuicByDefault, net/base/features.cc:
//
//	BASE_FEATURE_PARAM(std::string, kQuicOptions, &kTryQuicByDefault,
//	                   "quic_options", "ORIG");
//
// so "ORIG" is the shipped default and a browser holding a different Finch seed
// sends something else. Captures of one Chrome 152 install show both: a resumed
// connection carried "ORIG" and two fresh ones carried "IW50ORIG". IW50 is not
// a Chromium default anywhere, so the default here stays at the unmodified
// value and anything else comes from the preset.
//
// This drives the whole path: JSON in, describe out, JSON back in, then the
// bytes the connection would actually send. A getter assertion would pass even
// if the JSON key were dropped on the way in, which is exactly the failure the
// data_frame_max_size key had.
func TestConnectionOptionsReachTheWire(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want string // "" means the parameter must be absent
	}{
		{"default", "", "ORIG"},
		{"two tags", `,"http3":{"quic_connection_options":["IW50","ORIG"]}`, "IW50ORIG"},
		{"one other tag", `,"http3":{"quic_connection_options":["B2ON"]}`, "B2ON"},
		{"empty omits", `,"http3":{"quic_connection_options":[]}`, ""},
		{"bad width dropped", `,"http3":{"quic_connection_options":["TOOLONG","ORIG"]}`, "ORIG"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "connopt-" + strings.ReplaceAll(tc.name, " ", "-")
			if tc.json == "" {
				name = "chrome-151-windows"
			} else {
				registerPreset(t, name, tc.json)
			}

			p := fingerprint.Get(name)
			if p == nil {
				t.Fatalf("preset %q is not registered", name)
			}

			// Round-trip through describe so the emit and the parse are both
			// on the path, not just the struct field.
			described, err := fingerprint.Describe(name)
			if err != nil {
				t.Fatalf("describe: %v", err)
			}
			rt, err := fingerprint.LoadAndBuildPresetFromJSON([]byte(described))
			if err != nil {
				t.Fatalf("reload described JSON: %v", err)
			}

			// describe emits the key only when the preset sets it. Emitting
			// the resolved default would put ["ORIG"] into a Firefox preset's
			// output, where the parameter is never sent at all, and a user who
			// edited that and reloaded would watch the key vanish silently.
			hasKey := strings.Contains(described, `"quic_connection_options"`)
			if want := tc.json != ""; hasKey != want {
				t.Errorf("describe emitted the key = %v, want %v", hasKey, want)
			}

			for label, preset := range map[string]*fingerprint.Preset{"direct": p, "round-tripped": rt} {
				params := AdditionalTransportParamsForPreset(preset, nil, "", 0)
				got, ok := params[tpGoogleConnectionOptions]
				if tc.want == "" {
					if ok {
						t.Errorf("%s: google_connection_options present as %q for an empty tag list", label, got)
					}
					continue
				}
				if !ok {
					t.Fatalf("%s: google_connection_options (0x3128) absent, want %q", label, tc.want)
				}
				if string(got) != tc.want {
					t.Errorf("%s: google_connection_options = %q (% x), want %q", label, got, got, tc.want)
				}
				if len(got)%4 != 0 {
					t.Errorf("%s: google_connection_options is %d bytes, which is not a whole number of 4-byte QUIC tags",
						label, len(got))
				}
			}
		})
	}
}

// A non-Chromium preset neither sends google_connection_options nor advertises
// the key that would set it, so its describe output cannot teach a user to
// configure something that is gated off one layer down.
func TestConnectionOptionsAbsentFromNonChromePresets(t *testing.T) {
	for _, name := range []string{"firefox-148", "safari-18", "chrome-151-ios"} {
		p := fingerprint.Get(name)
		if p == nil {
			continue
		}
		if params := AdditionalTransportParamsForPreset(p, nil, "", 0); len(params) != 0 {
			t.Errorf("%s carries %d Chrome QUIC transport parameters", name, len(params))
		}
		described, err := fingerprint.Describe(name)
		if err != nil {
			t.Fatalf("%s: describe: %v", name, err)
		}
		if strings.Contains(described, `"quic_connection_options"`) {
			t.Errorf("%s advertises quic_connection_options in its describe output, "+
				"but presetIsChromeQUIC gates the parameter off entirely for it", name)
		}
	}
}
