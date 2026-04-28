package fingerprint

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	tls "github.com/sardanioss/utls"
)

// TestDescribe_NotRegistered ensures Describe surfaces a clear error when
// the name is unknown rather than returning the Chrome146 fallback.
func TestDescribe_NotRegistered(t *testing.T) {
	_, err := Describe("does-not-exist")
	if err == nil {
		t.Fatalf("expected error for unknown preset, got nil")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error should mention not-registered, got %v", err)
	}
}

// TestDescribe_Idempotent verifies two consecutive Describe calls on the
// same preset produce byte-identical output. This catches:
//   - Map-iteration order leaking into output
//   - Pointer-vs-value differences across calls
//   - Time-dependent state
func TestDescribe_Idempotent(t *testing.T) {
	for _, name := range Available() {
		t.Run(name, func(t *testing.T) {
			a, err := Describe(name)
			if err != nil {
				t.Fatalf("first Describe: %v", err)
			}
			b, err := Describe(name)
			if err != nil {
				t.Fatalf("second Describe: %v", err)
			}
			if a != b {
				t.Errorf("Describe is not idempotent\n--- first ---\n%s\n--- second ---\n%s", a, b)
			}
		})
	}
}

// TestDescribe_OutputIsValidJSON parses each preset's describe output to
// ensure it's well-formed JSON. The "name" field reflects the preset's
// internal Name, which can differ from the lookup alias (e.g.
// chrome-latest → preset.Name=chrome-146).
func TestDescribe_OutputIsValidJSON(t *testing.T) {
	for _, name := range Available() {
		t.Run(name, func(t *testing.T) {
			p := GetStrict(name)
			if p == nil {
				t.Fatalf("preset %q not registered", name)
			}
			out, err := Describe(name)
			if err != nil {
				t.Fatalf("describe: %v", err)
			}
			pf, err := LoadPresetFromJSON([]byte(out))
			if err != nil {
				t.Fatalf("output is not valid PresetFile JSON: %v\n%s", err, out)
			}
			if pf.Version != 1 {
				t.Errorf("Version = %d, want 1", pf.Version)
			}
			if pf.Preset == nil {
				t.Fatalf("Preset is nil")
			}
			if pf.Preset.Name != p.Name {
				t.Errorf("Name = %q, want %q (internal preset name)", pf.Preset.Name, p.Name)
			}
			if pf.Preset.BasedOn != "" {
				t.Errorf("BasedOn = %q, want empty (Describe must always emit fully-flattened output)", pf.Preset.BasedOn)
			}
		})
	}
}

// TestDescribe_StrictRoundTripAllBuiltins is the primary acceptance bar from
// the plan. For every name in Available():
//
//  1. JSON1 = Describe(name)
//  2. preset' = BuildPreset(parse(JSON1))
//  3. register preset' under preset.Name+"-rt"  (NOT alias+"-rt"; the
//     preset's own internal Name may differ from the lookup alias —
//     e.g. "chrome-latest" resolves to a Preset whose Name is "chrome-146")
//  4. JSON2 = Describe(internalName+"-rt") with -rt stripped
//  5. assert JSON1 == JSON2 byte-for-byte
//
// Any failure here means describe + load are not strict inverses.
func TestDescribe_StrictRoundTripAllBuiltins(t *testing.T) {
	for _, name := range Available() {
		t.Run(name, func(t *testing.T) {
			p := GetStrict(name)
			if p == nil {
				t.Fatalf("preset %q not registered", name)
			}
			internalName := p.Name

			json1, err := Describe(name)
			if err != nil {
				t.Fatalf("describe: %v", err)
			}

			pf, err := LoadPresetFromJSON([]byte(json1))
			if err != nil {
				t.Fatalf("parse: %v\n%s", err, json1)
			}
			if pf.Preset == nil {
				t.Fatalf("preset section missing")
			}

			rt, err := BuildPreset(pf.Preset)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			rtName := internalName + "-httpcloak-rt"
			rt.Name = rtName
			Register(rtName, rt)
			defer Unregister(rtName)

			json2, err := Describe(rtName)
			if err != nil {
				t.Fatalf("re-describe: %v", err)
			}

			// Strip the -httpcloak-rt suffix so substantive comparison is
			// against the original internal name. Suffix is unique enough to
			// guarantee we don't clobber other content.
			json2 = strings.Replace(json2, rtName, internalName, 1)

			if json1 != json2 {
				t.Errorf("strict round-trip failed for %s (internal=%s)\n--- JSON1 ---\n%s\n--- JSON2 ---\n%s",
					name, internalName, json1, json2)
			}
		})
	}
}

// TestDescribe_HeadersValuesAreSorted ensures the JSON output emits header
// keys in alphabetical order regardless of map iteration order at write time.
// Determinism is required for byte-equal round trips.
func TestDescribe_HeadersValuesAreSorted(t *testing.T) {
	out, err := Describe("chrome-146-windows")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}

	var pf PresetFile
	if err := json.Unmarshal([]byte(out), &pf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pf.Preset == nil || pf.Preset.Headers == nil {
		t.Fatalf("preset has no headers")
	}

	// The serialized values map must be sorted alphabetically. Easiest way:
	// scan the raw output and check the order of header keys appearing in
	// the "values" object literal.
	const valuesMarker = "\"values\": {"
	idx := strings.Index(out, valuesMarker)
	if idx == -1 {
		t.Fatalf("no values key in output:\n%s", out)
	}
	tail := out[idx+len(valuesMarker):]
	end := strings.Index(tail, "}")
	if end == -1 {
		t.Fatalf("unterminated values object")
	}
	body := tail[:end]

	var keysFound []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "\"") {
			continue
		}
		// Extract key (between first and second quote)
		closeQuote := strings.Index(line[1:], "\"")
		if closeQuote == -1 {
			continue
		}
		keysFound = append(keysFound, line[1:1+closeQuote])
	}

	sorted := make([]string, len(keysFound))
	copy(sorted, keysFound)
	sort.Strings(sorted)

	if !reflect.DeepEqual(keysFound, sorted) {
		t.Errorf("header values not sorted alphabetically\nfound: %v\nwant:  %v", keysFound, sorted)
	}
}

// TestDescribe_HeaderOrderPreserved verifies the ordered HeaderOrder slice
// is emitted in slice order (not alphabetical). Wire ordering matters and
// must round-trip exactly.
func TestDescribe_HeaderOrderPreserved(t *testing.T) {
	p := GetStrict("chrome-146-windows")
	if p == nil {
		t.Fatalf("chrome-146-windows not registered")
	}
	out, err := Describe("chrome-146-windows")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	var pf PresetFile
	if err := json.Unmarshal([]byte(out), &pf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pf.Preset.Headers == nil || len(pf.Preset.Headers.Order) != len(p.HeaderOrder) {
		t.Fatalf("Order length mismatch: got %d, want %d", len(pf.Preset.Headers.Order), len(p.HeaderOrder))
	}
	for i, hp := range p.HeaderOrder {
		if pf.Preset.Headers.Order[i].Key != hp.Key || pf.Preset.Headers.Order[i].Value != hp.Value {
			t.Errorf("HeaderOrder[%d] = %+v, want %+v", i, pf.Preset.Headers.Order[i], hp)
		}
	}
}

// TestDescribe_NoBasedOnInOutput proves we never emit based_on anywhere
// in the output, even for presets that reference inheritance internally.
func TestDescribe_NoBasedOnInOutput(t *testing.T) {
	for _, name := range Available() {
		out, err := Describe(name)
		if err != nil {
			t.Fatalf("%s: describe: %v", name, err)
		}
		if strings.Contains(out, "\"based_on\"") {
			t.Errorf("%s: output contains based_on (must be flattened)", name)
		}
	}
}

// TestDescribe_HTTP3OnlyWhenSupported ensures HTTP3 section is omitted for
// presets that don't support it, and present for those that do. The plan's
// SupportHTTP3 round-trip contract depends on this.
func TestDescribe_HTTP3OnlyWhenSupported(t *testing.T) {
	for _, name := range Available() {
		p := GetStrict(name)
		out, err := Describe(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var pf PresetFile
		if err := json.Unmarshal([]byte(out), &pf); err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		if p.SupportHTTP3 && pf.Preset.HTTP3 == nil {
			t.Errorf("%s: SupportHTTP3=true but http3 section missing", name)
		}
		if !p.SupportHTTP3 && pf.Preset.HTTP3 != nil {
			t.Errorf("%s: SupportHTTP3=false but http3 section present", name)
		}
	}
}

// TestDescribe_TCPSectionOmittedWhenZero verifies the TCP section is dropped
// when the preset has no TCP fingerprint configured. Round-trip must NOT
// resurrect zero values via the platform shorthand.
func TestDescribe_TCPSectionOmittedWhenZero(t *testing.T) {
	// Chrome133 (legacy) has TCPFingerprint{} — all zeros.
	out, err := Describe("chrome-133")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if strings.Contains(out, "\"tcp\":") {
		t.Errorf("chrome-133 has zero TCPFingerprint but tcp section was emitted:\n%s", out)
	}
}

// TestDescribe_TCPSectionPresentWhenSet checks chrome-145-windows has a
// non-zero TCPFingerprint and that it shows up in the JSON output.
func TestDescribe_TCPSectionPresentWhenSet(t *testing.T) {
	p := GetStrict("chrome-145-windows")
	if p == nil {
		t.Fatalf("chrome-145-windows not registered")
	}
	if p.TCPFingerprint == (TCPFingerprint{}) {
		t.Skip("chrome-145-windows has zero TCP fingerprint; nothing to test here")
	}

	out, err := Describe("chrome-145-windows")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if !strings.Contains(out, "\"tcp\":") {
		t.Errorf("chrome-145-windows has TCPFingerprint set but no tcp section\n%s", out)
	}
}

// TestDescribe_JA3PresetEmitsJA3 covers the JA3-defined preset path. If a
// preset uses a JA3 string instead of a ClientHelloID, the output must use
// the ja3 field (not client_hello) and must round-trip.
func TestDescribe_JA3PresetEmitsJA3(t *testing.T) {
	// Construct a synthetic JA3-mode preset. Real built-ins all use
	// ClientHelloID, so we register one ad-hoc.
	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
	p := &Preset{
		Name:      "synthetic-ja3",
		JA3:       ja3,
		UserAgent: "Mozilla/5.0",
		Headers:   map[string]string{"accept": "*/*"},
		HeaderOrder: []HeaderPair{
			{Key: "user-agent", Value: ""},
			{Key: "accept", Value: "*/*"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:   65536,
			InitialWindowSize: 6291456,
		},
	}
	Register(p.Name, p)
	defer Unregister(p.Name)

	out, err := Describe(p.Name)
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if !strings.Contains(out, "\"ja3\":") {
		t.Errorf("synthetic-ja3 has JA3 string but ja3 field missing\n%s", out)
	}
	if strings.Contains(out, "\"client_hello\":") {
		t.Errorf("synthetic-ja3 has JA3 string but client_hello was also emitted\n%s", out)
	}

	// Round-trip
	pf, err := LoadPresetFromJSON([]byte(out))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rt, err := BuildPreset(pf.Preset)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if rt.JA3 != ja3 {
		t.Errorf("round-trip lost JA3 string: got %q, want %q", rt.JA3, ja3)
	}
}

// TestDescribe_UnregisteredClientHelloID covers a preset that holds a utls
// ClientHelloID not present in clientHelloIDs. Describe must error rather
// than emit empty/malformed JSON.
func TestDescribe_UnregisteredClientHelloID(t *testing.T) {
	p := &Preset{
		Name:          "synthetic-bad-id",
		ClientHelloID: tls.ClientHelloID{Client: "Synthetic", Version: "0.0"},
	}
	Register(p.Name, p)
	defer Unregister(p.Name)

	_, err := Describe(p.Name)
	if err == nil {
		t.Fatalf("expected error for unregistered ClientHelloID, got nil")
	}
	if !strings.Contains(err.Error(), "unregistered") {
		t.Errorf("error should mention unregistered, got %v", err)
	}
}

// TestDescribe_CustomRegistryRoundTrip is the symmetric case: register an
// arbitrary user-built preset, describe it, parse the result, and verify
// the rebuilt preset equals the original on observable fields.
func TestDescribe_CustomRegistryRoundTrip(t *testing.T) {
	// Build a slightly-tweaked Chrome146Linux variant.
	base := Chrome146Linux()
	base.Name = "custom-tweaked"
	base.Headers["x-custom"] = "yes"
	base.HeaderOrder = append(base.HeaderOrder, HeaderPair{Key: "x-custom", Value: "yes"})
	Register(base.Name, base)
	defer Unregister(base.Name)

	out, err := Describe(base.Name)
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	pf, err := LoadPresetFromJSON([]byte(out))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rt, err := BuildPreset(pf.Preset)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if rt.Headers["x-custom"] != "yes" {
		t.Errorf("custom header lost: %v", rt.Headers)
	}
	if rt.UserAgent != base.UserAgent {
		t.Errorf("UA mismatch: got %q, want %q", rt.UserAgent, base.UserAgent)
	}
	if rt.SupportHTTP3 != base.SupportHTTP3 {
		t.Errorf("SupportHTTP3: got %v, want %v", rt.SupportHTTP3, base.SupportHTTP3)
	}
}
