package transport

import (
	"reflect"
	"testing"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// The cache is only sound if replaying it writes exactly what deriving the
// preset afresh writes, for every built-in preset and every switch that
// changes which preset headers are applied.
func TestPresetWireHeadersMatchFreshDerivation(t *testing.T) {
	userHeaders := map[string][]string{
		"content-type": {"application/json"},
		"referer":      {"https://app.example.com/"},
	}
	for _, name := range fingerprint.Available() {
		preset := fingerprint.Get(name)
		if preset == nil {
			continue
		}
		cached := newPresetWireHeaders(preset)
		for _, protocol := range []string{"h1", "h2", "h3"} {
			for _, strip := range []bool{false, true} {
				for _, tlsOnly := range []bool{false, true} {
					gotReq, _ := http.NewRequest("GET", "https://api.example.com/v1/items/42", nil)
					wantReq, _ := http.NewRequest("GET", "https://api.example.com/v1/items/42", nil)

					// The same cache entry, reused the way a transport reuses it.
					applyPresetHeaders(gotReq, cached, nil, nil, tlsOnly, protocol, userHeaders, strip, nil)
					// A derivation of its own, as the very first request does.
					applyPresetHeaders(wantReq, newPresetWireHeaders(preset), nil, nil, tlsOnly, protocol, userHeaders, strip, nil)

					if !reflect.DeepEqual(gotReq.Header, wantReq.Header) {
						t.Fatalf("preset %s protocol=%s strip=%v tlsOnly=%v: reused cache wrote\n%v\nfresh derivation wrote\n%v",
							name, protocol, strip, tlsOnly, gotReq.Header, wantReq.Header)
					}
				}
			}
		}
	}
}

// The cached keys must be exactly what Header.Set would have canonicalised
// them to, or direct assignment writes a second entry under a different
// spelling and the preset header silently goes missing from the wire.
func TestPresetWireHeadersUseCanonicalKeys(t *testing.T) {
	for _, name := range fingerprint.Available() {
		preset := fingerprint.Get(name)
		if preset == nil {
			continue
		}
		for _, p := range newPresetWireHeaders(preset).pairs {
			if want := http.CanonicalHeaderKey(p.key); p.key != want {
				t.Errorf("preset %s: cached key %q, want %q", name, p.key, want)
			}
		}
	}
}

// A transport whose preset is swapped must not keep serving the old one's
// headers.
func TestTransportWireHeadersFollowPresetSwap(t *testing.T) {
	tr := &Transport{}
	first := fingerprint.Get("chrome-latest")
	second := fingerprint.Get("firefox-latest")
	if first == nil || second == nil {
		t.Skip("presets unavailable")
	}

	if got := tr.wireHeaders(first); got.preset != first {
		t.Fatalf("wireHeaders returned an entry for %p, want %p", got.preset, first)
	}
	// Same preset: the same entry comes back rather than a rebuild.
	if a, b := tr.wireHeaders(first), tr.wireHeaders(first); a != b {
		t.Error("wireHeaders rebuilt the entry for an unchanged preset")
	}
	if got := tr.wireHeaders(second); got.preset != second {
		t.Errorf("after the swap wireHeaders returned an entry for %p, want %p", got.preset, second)
	}
}

// User-Agent is written unconditionally and last, so a preset that also lists
// it in its header table must still end up with the preset's UserAgent field.
func TestPresetWireHeadersUserAgentWins(t *testing.T) {
	preset := fingerprint.Get("chrome-latest")
	if preset == nil {
		t.Skip("preset unavailable")
	}
	req, _ := http.NewRequest("GET", "https://api.example.com/v1/items/42", nil)
	applyPresetHeaders(req, newPresetWireHeaders(preset), nil, nil, false, "h2", nil, false, nil)
	if got := req.Header.Get("User-Agent"); got != preset.UserAgent {
		t.Errorf("User-Agent = %q, want %q", got, preset.UserAgent)
	}
}

// The preset's single element value slices come out of one backing array.
// Header.Set used to give each its own, so each must still behave as if it
// had one: appending through an entry must not overwrite the next header's
// value.
func TestPresetWireHeadersValuesAreIsolated(t *testing.T) {
	preset := fingerprint.Get("chrome-latest")
	if preset == nil {
		t.Skip("preset unavailable")
	}
	req, _ := http.NewRequest("GET", "https://api.example.com/v1/items/42", nil)
	applyPresetHeaders(req, newPresetWireHeaders(preset), nil, nil, false, "h2", nil, false, nil)

	before := map[string][]string{}
	for k, v := range req.Header {
		// The ordering keys are bookkeeping, not preset values, and the order
		// list is returned with spare capacity by design.
		if k != http.HeaderOrderKey && k != http.PHeaderOrderKey && cap(v) != len(v) {
			t.Errorf("header %q has cap %d for len %d; appending would reach into a neighbor",
				k, cap(v), len(v))
		}
		before[k] = append([]string(nil), v...)
	}
	if len(before) < 2 {
		t.Fatal("the preset wrote fewer than two headers; this test is not covering anything")
	}

	// Append through every entry, then check nothing else moved.
	for k := range before {
		if k == http.HeaderOrderKey || k == http.PHeaderOrderKey {
			continue
		}
		_ = append(req.Header[k], "appended")
	}
	for k, want := range before {
		if got := req.Header[k]; !reflect.DeepEqual(got, want) {
			t.Errorf("after appending through the neighbors, header %q = %v, want %v", k, got, want)
		}
	}
}
