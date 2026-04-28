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

// TestEmbedded_NoNameCollisionWithBuiltins guards against an embedded JSON
// silently overwriting a built-in factory preset. Both register through the
// custom registry, but built-ins are also reachable directly via the
// presets[] map — a name collision means Get() inconsistency depending on
// init order. Embedded names should be net-new.
func TestEmbedded_NoNameCollisionWithBuiltins(t *testing.T) {
	entries, _ := fs.ReadDir(embeddedPresets, "embedded")

	// Snapshot the names emitted by built-in factories alone.
	builtins := make(map[string]bool)
	for name := range presets {
		// Resolve the factory to extract its internal name (which may
		// differ from the alias key, e.g. "chrome-latest" → preset.Name="chrome-146").
		p := presets[name]()
		builtins[p.Name] = true
		builtins[name] = true
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
		if builtins[pf.Preset.Name] {
			t.Errorf("embedded preset %s name %q collides with a built-in factory — embedded JSON should add net-new presets",
				e.Name(), pf.Preset.Name)
		}
	}
}
