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
	secFetchPair := []fingerprint.HeaderPair{
		{Key: "user-agent", Value: "x"},
		{Key: "sec-fetch-mode", Value: "navigate"},
		{Key: "accept-encoding", Value: "gzip"},
	}
	plainPair := []fingerprint.HeaderPair{
		{Key: "authorization", Value: "x"},
		{Key: "user-agent", Value: "okhttp/5.1.0"},
		{Key: "accept-encoding", Value: "gzip"},
	}

	tests := []struct {
		name   string
		emit   []fingerprint.HeaderPair
		hdrMap map[string]string
		table  []string
		want   bool
	}{
		{
			name:  "emit set carries sec-fetch",
			emit:  secFetchPair,
			table: []string{"user-agent", "sec-fetch-mode"},
			want:  true,
		},
		{
			name:  "non-browser emit set",
			emit:  plainPair,
			table: []string{"authorization", "user-agent", "accept-encoding"},
			want:  false,
		},
		{
			// The hole the original gate left open. A custom preset that drops
			// Sec-Fetch-* from what it SENDS while inheriting a browser's HPACK
			// position table used to be coerced anyway, so the opt-out silently
			// failed for exactly the preset that asked for it.
			name:  "emit set opts out while inheriting a browser table",
			emit:  plainPair,
			table: []string{"user-agent", "sec-fetch-mode", "sec-fetch-dest"},
			want:  false,
		},
		{
			// Casing is the preset author's choice; the wire is lowercase but a
			// hand-written preset need not be.
			name: "canonical casing still matches",
			emit: []fingerprint.HeaderPair{
				{Key: "User-Agent", Value: "x"},
				{Key: "Sec-Fetch-Site", Value: "none"},
			},
			want: true,
		},
		{
			// The based_on case: a custom preset drops Sec-Fetch-* from its own
			// emit set but inherits the base preset's Headers map. The emit set
			// must win, or the opt-out silently fails for exactly the preset
			// that asked for it.
			name:   "based_on preset opts out while inheriting a base Headers map",
			emit:   plainPair,
			hdrMap: map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none"},
			want:   false,
		},
		{
			name:   "map-only preset with sec-fetch",
			hdrMap: map[string]string{"Sec-Fetch-Mode": "navigate"},
			want:   true,
		},
		{
			name:   "map-only preset without",
			hdrMap: map[string]string{"User-Agent": "curl/8.5.0"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &fingerprint.Preset{HeaderOrder: tt.emit, Headers: tt.hdrMap}
			if tt.table != nil {
				p.H2Config = &fingerprint.H2FingerprintConfig{HPACKHeaderOrder: tt.table}
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
