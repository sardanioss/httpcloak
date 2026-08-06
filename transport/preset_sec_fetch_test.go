package transport

import (
	"testing"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// TestPresetSendsSecFetch checks the gate that keeps the Sec-Fetch-* coercion
// off presets describing clients that send no Sec-Fetch-* at all. Every built-in
// must pass the gate, or applyPresetHeaders stops correcting browser headers on
// API calls and the behavior issue #53 asked for regresses.
func TestPresetSendsSecFetch(t *testing.T) {
	var checked int
	for _, name := range fingerprint.Available() {
		p := fingerprint.GetStrict(name)
		if p == nil {
			continue
		}
		checked++
		if !presetSendsSecFetch(p) {
			t.Errorf("presetSendsSecFetch(%s) = false, want true for a built-in browser preset", name)
		}
	}
	if checked == 0 {
		t.Fatal("no built-in presets were checked, so this proves nothing")
	}
	t.Logf("checked %d built-in presets", checked)
}

// A preset whose HPACK position table declares no sec-fetch headers describes a
// non-browser client (okhttp, curl, a native SDK). Coercing Sec-Fetch-* onto one
// does not fix an incoherence, it invents headers the client never sends.
func TestPresetSendsSecFetchNonBrowser(t *testing.T) {
	tests := []struct {
		name  string
		order []string
		want  bool
	}{
		{"okhttp-style table", []string{"authorization", "accept-language", "user-agent", "content-type", "accept-encoding"}, false},
		{"empty table falls back to Chrome's", nil, true},
		{"table with sec-fetch", []string{"user-agent", "sec-fetch-mode", "accept-encoding"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &fingerprint.Preset{}
			if tt.order != nil {
				p.H2Config = &fingerprint.H2FingerprintConfig{HPACKHeaderOrder: tt.order}
			}
			if got := presetSendsSecFetch(p); got != tt.want {
				t.Errorf("presetSendsSecFetch() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The gate has to hold where it is actually used: applyPresetHeaders must leave
// a non-browser preset's headers alone on an API-shaped request, while still
// coercing a browser preset's.
func TestApplyPresetHeadersSkipsSecFetchForNonBrowserPreset(t *testing.T) {
	injected := []string{"Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-Site", "Accept"}

	tests := []struct {
		name       string
		preset     *fingerprint.Preset
		wantAbsent bool
	}{
		{
			name: "non-browser preset",
			preset: &fingerprint.Preset{
				UserAgent: "okhttp/5.1.0",
				H2Config: &fingerprint.H2FingerprintConfig{
					HPACKHeaderOrder: []string{"user-agent", "content-type", "accept-encoding"},
				},
			},
			wantAbsent: true,
		},
		{
			name:       "browser preset",
			preset:     fingerprint.GetStrict("chrome-146-windows"),
			wantAbsent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.preset == nil {
				t.Skip("preset not registered")
			}
			req, err := http.NewRequest("POST", "https://example.com/api", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			// An API-shaped POST, which is what sniffXHRMode classifies as XHR.
			userHeaders := map[string][]string{"Content-Type": {"application/json"}}

			applyPresetHeaders(req, tt.preset, nil, nil, false, "h2", userHeaders, false)

			for _, key := range injected {
				_, present := req.Header[key]
				if tt.wantAbsent && present {
					t.Errorf("%s = %q was set, want it absent for a preset that does not declare it", key, req.Header.Get(key))
				}
				if !tt.wantAbsent && !present {
					t.Errorf("%s is absent, want the XHR coercion to still apply to a browser preset", key)
				}
			}
		})
	}
}
