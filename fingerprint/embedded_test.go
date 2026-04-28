package fingerprint

import (
	"io/fs"
	"strings"
	"testing"
)

// TestEmbedded_AllJSONsParseAndBuild walks the embedded/ directory and
// confirms every .json file:
//   1. parses cleanly,
//   2. builds via BuildPreset (so based_on chains resolve at init time),
//   3. is registered after init (the Register call from embedded.go ran).
func TestEmbedded_AllJSONsParseAndBuild(t *testing.T) {
	entries, err := fs.ReadDir(embeddedPresets, "embedded")
	if err != nil {
		t.Fatalf("read embedded dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no embedded presets — go:embed pattern must match at least one file at compile time")
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			data, err := embeddedPresets.ReadFile("embedded/" + e.Name())
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			pf, err := LoadPresetFromJSON(data)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if pf.Preset == nil {
				t.Fatal("preset section missing")
			}

			// Re-build to confirm the spec is internally consistent. (init
			// already did this once; we redo it as a self-check.)
			built, err := BuildPreset(pf.Preset)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			// And confirm the init-time registration is observable via Get.
			fromRegistry := GetStrict(built.Name)
			if fromRegistry == nil {
				t.Fatalf("preset %q not registered after init — embedded.go init() may have skipped it", built.Name)
			}
			if fromRegistry.Name != built.Name {
				t.Errorf("registry returned name=%q for lookup %q", fromRegistry.Name, built.Name)
			}
		})
	}
}

// TestEmbedded_RoundTripDescribe verifies every embedded preset passes the
// strict byte-equal Describe contract — same bar as built-in factories.
func TestEmbedded_RoundTripDescribe(t *testing.T) {
	entries, err := fs.ReadDir(embeddedPresets, "embedded")
	if err != nil {
		t.Fatalf("read embedded dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, _ := embeddedPresets.ReadFile("embedded/" + e.Name())
		pf, _ := LoadPresetFromJSON(data)
		if pf == nil || pf.Preset == nil {
			continue
		}
		name := pf.Preset.Name

		t.Run(name, func(t *testing.T) {
			json1, err := Describe(name)
			if err != nil {
				t.Fatalf("describe: %v", err)
			}
			parsed, err := LoadPresetFromJSON([]byte(json1))
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			rt, err := BuildPreset(parsed.Preset)
			if err != nil {
				t.Fatalf("re-build: %v", err)
			}

			rtName := name + "-embeddedrt"
			rt.Name = rtName
			Register(rtName, rt)
			defer Unregister(rtName)

			json2, err := Describe(rtName)
			if err != nil {
				t.Fatalf("re-describe: %v", err)
			}
			json2 = strings.Replace(json2, rtName, name, 1)

			if json1 != json2 {
				t.Errorf("strict round-trip failed for embedded %s\n--- JSON1 ---\n%s\n--- JSON2 ---\n%s",
					name, json1, json2)
			}
		})
	}
}

// TestEmbedded_FactoryDelegationIsConsistent verifies that when an embedded
// JSON shares a name with a built-in factory, the factory is the LookupCustom
// bridge pattern (Chrome147Windows etc.) — i.e., calling the factory returns
// the embedded preset, not a divergent in-memory definition.
//
// This catches the failure mode where a contributor adds an embedded JSON
// AND independently writes a competing factory function for the same name —
// Get(name) would silently prefer one over the other depending on
// LookupCustom precedence.
func TestEmbedded_FactoryDelegationIsConsistent(t *testing.T) {
	entries, _ := fs.ReadDir(embeddedPresets, "embedded")

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, _ := embeddedPresets.ReadFile("embedded/" + e.Name())
		pf, _ := LoadPresetFromJSON(data)
		if pf == nil || pf.Preset == nil {
			continue
		}
		name := pf.Preset.Name

		factory, hasFactory := presets[name]
		if !hasFactory {
			continue // No factory shadow; embedded JSON is the sole producer.
		}

		// Factory exists; it MUST delegate to LookupCustom for the embedded
		// preset to be observable. Verify by calling the factory and
		// comparing observable state to a direct LookupCustom result.
		viaFactory := factory()
		viaCustom := LookupCustom(name)
		if viaCustom == nil {
			t.Errorf("embedded preset %s registered but LookupCustom returned nil", name)
			continue
		}
		// Compare a representative subset of observable fields.
		if viaFactory.Name != viaCustom.Name ||
			viaFactory.UserAgent != viaCustom.UserAgent ||
			viaFactory.Headers["sec-ch-ua"] != viaCustom.Headers["sec-ch-ua"] {
			t.Errorf("factory %s does not delegate to embedded preset:\n  factory.UA = %q\n  custom.UA  = %q",
				name, viaFactory.UserAgent, viaCustom.UserAgent)
		}
	}
}
