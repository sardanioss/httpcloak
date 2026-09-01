package fingerprint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The exact failure this exists for: a preset written to mirror one client, with
// one key misspelled, loads without complaint and goes on the wire as a different
// client. Nothing else in the loader fails this quietly.
func TestUnknownPresetFieldsFindsATypo(t *testing.T) {
	const spec = `{
	  "preset": {
	    "name": "typo",
	    "based_on": "chrome-latest",
	    "tls": {
	      "cipher_suits": [4865],
	      "signature_algorithms": [1027]
	    },
	    "htp2": {"hpack_header_order": ["accept"]}
	  }
	}`
	got, err := UnknownPresetFields([]byte(spec))
	if err != nil {
		t.Fatalf("UnknownPresetFields: %v", err)
	}
	want := []string{"preset.htp2", "preset.tls.cipher_suits"}
	if len(got) != len(want) {
		t.Fatalf("found %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("found %v, want %v", got, want)
			break
		}
	}

	// And the strict loader refuses it, naming both.
	if _, err := LoadPresetFromJSONStrict([]byte(spec)); err == nil {
		t.Error("strict load accepted a preset with two unknown fields")
	} else {
		for _, name := range want {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error does not name %q: %v", name, err)
			}
		}
	}
}

// The lenient loader must keep accepting it, so a preset written for a newer
// version still loads on an older one.
func TestLenientLoaderStillAcceptsUnknownFields(t *testing.T) {
	const spec = `{"preset": {"name": "fwd", "based_on": "chrome-latest", "some_future_key": 1}}`
	if _, err := LoadPresetFromJSON([]byte(spec)); err != nil {
		t.Errorf("lenient load rejected a forward-compatible preset: %v", err)
	}
	if _, err := LoadPresetFromJSONStrict([]byte(spec)); err == nil {
		t.Error("strict load accepted it; the two modes are meant to differ")
	}
}

// A map-typed field holds caller data, not schema, so its keys are not unknown
// fields. Without this the walk would flag every header name in a preset.
func TestFreeFormMapKeysAreNotUnknownFields(t *testing.T) {
	const spec = `{
	  "preset": {
	    "name": "hdrs",
	    "based_on": "chrome-latest",
	    "headers": {"values": {"x-anything-at-all": "1", "x-another": "2"}}
	  }
	}`
	got, err := UnknownPresetFields([]byte(spec))
	if err != nil {
		t.Fatalf("UnknownPresetFields: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("flagged caller-supplied header names as unknown fields: %v", got)
	}
}

// Every preset we ship must pass the strict loader, otherwise the strict mode is
// advertising a standard our own files do not meet.
func TestEmbeddedPresetsPassStrictLoading(t *testing.T) {
	files, err := filepath.Glob("embedded/*.json")
	if err != nil || len(files) == 0 {
		t.Skip("no embedded presets found")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if _, err := LoadPresetFromJSONStrict(b); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
	}
}
