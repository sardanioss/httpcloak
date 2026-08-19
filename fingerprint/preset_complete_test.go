package fingerprint

import (
	"strings"
	"testing"
)

// A spec with no based_on starts BuildPreset from an empty Preset, so one
// describing only TLS produces a profile with no user agent, no headers and no
// HTTP/2 settings. That used to load and register without complaint; the
// failure landed on the first request instead, and it landed as a 20 second
// hang ending in "roundtrip example.com [h1]: context deadline exceeded",
// which says nothing about the preset being the cause.
//
// The gate lives in the loaders rather than in BuildPreset, because a partial
// preset is a legitimate intermediate for the builder. So this asserts through
// LoadAndBuildPresetFromJSON, which is the path every binding and the C ABI
// take.
func TestLoaderRejectsUnusablePreset(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want string
	}{
		{
			name: "tls only, nothing else",
			json: `{"version":1,"preset":{"name":"t1","tls":{"client_hello":"chrome-133"}}}`,
			want: "no user agent",
		},
		{
			name: "no tls source at all",
			json: `{"version":1,"preset":{"name":"t2","headers":{"user_agent":"UA","order":[{"key":"accept","value":"*/*"}]}}}`,
			want: "no TLS fingerprint source",
		},
		{
			name: "user agent but no header set",
			json: `{"version":1,"preset":{"name":"t3","tls":{"client_hello":"chrome-133"},"headers":{"user_agent":"UA"}}}`,
			want: "no headers",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadAndBuildPresetFromJSON([]byte(tc.json))
			if err == nil {
				t.Fatalf("loaded without error; want a build-time failure mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error was %q, want it to mention %q", err, tc.want)
			}
			// The message has to name the escape hatch, otherwise the reader
			// has no way to know based_on would fix it.
			if !strings.Contains(err.Error(), "based_on") {
				t.Errorf("error %q does not mention based_on", err)
			}
		})
	}
}

// The gate must not fire on a preset that inherits its non-TLS layers, which
// is the shape the mirror addon produces: a captured TLS block on top of a
// browser base.
func TestLoaderAcceptsTLSOverABase(t *testing.T) {
	const j = `{"version":1,"preset":{"name":"mirror-probe","based_on":"chrome-latest","tls":{"client_hello":"chrome-133"}}}`
	p, err := LoadAndBuildPresetFromJSON([]byte(j))
	if err != nil {
		t.Fatalf("a TLS block over based_on must load: %v", err)
	}
	if p.UserAgent == "" || len(p.HeaderOrder) == 0 {
		t.Errorf("inherited profile is empty: ua=%q headers=%d", p.UserAgent, len(p.HeaderOrder))
	}
}

// BuildPreset stays permissive on purpose. Tightening it breaks every caller
// that composes a preset in stages, and the fingerprint suite has a lot of
// them.
func TestBuildPresetStaysPermissive(t *testing.T) {
	p, err := BuildPreset(&PresetSpec{Name: "partial", TLS: &TLSSpec{ClientHello: "chrome-133"}})
	if err != nil {
		t.Fatalf("BuildPreset must still accept a partial spec: %v", err)
	}
	if p.ClientHelloID.Client == "" {
		t.Error("partial build lost the TLS source")
	}
}
