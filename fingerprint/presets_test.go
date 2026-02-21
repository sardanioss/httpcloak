package fingerprint

import (
	"testing"
)

func TestAvailableWithInfo(t *testing.T) {
	info := AvailableWithInfo()

	// Must have all presets
	allPresets := Available()
	if len(info) != len(allPresets) {
		t.Fatalf("AvailableWithInfo returned %d presets, Available() returned %d", len(info), len(allPresets))
	}

	// Every preset from Available() must be in AvailableWithInfo()
	for _, name := range allPresets {
		if _, ok := info[name]; !ok {
			t.Errorf("preset %q missing from AvailableWithInfo()", name)
		}
	}

	// Every preset must have at least h1 and h2
	for name, pi := range info {
		if len(pi.Protocols) < 2 {
			t.Errorf("preset %q has %d protocols, expected at least 2", name, len(pi.Protocols))
		}
		hasH1 := false
		hasH2 := false
		for _, p := range pi.Protocols {
			if p == "h1" {
				hasH1 = true
			}
			if p == "h2" {
				hasH2 = true
			}
		}
		if !hasH1 {
			t.Errorf("preset %q missing h1", name)
		}
		if !hasH2 {
			t.Errorf("preset %q missing h2", name)
		}
	}

	// Known H3-supported presets must have h3
	h3Presets := []string{
		"chrome-143", "chrome-143-windows", "chrome-143-linux", "chrome-143-macos",
		"chrome-144", "chrome-144-windows", "chrome-144-linux", "chrome-144-macos",
		"chrome-145", "chrome-145-windows", "chrome-145-linux", "chrome-145-macos",
		"safari-18", "chrome-143-ios", "chrome-144-ios", "chrome-145-ios",
		"safari-18-ios", "chrome-143-android", "chrome-144-android", "chrome-145-android",
	}
	for _, name := range h3Presets {
		pi, ok := info[name]
		if !ok {
			t.Errorf("expected H3 preset %q not found", name)
			continue
		}
		hasH3 := false
		for _, p := range pi.Protocols {
			if p == "h3" {
				hasH3 = true
			}
		}
		if !hasH3 {
			t.Errorf("preset %q should support h3 but doesn't", name)
		}
	}

	// Known non-H3 presets must NOT have h3
	noH3Presets := []string{"chrome-133", "chrome-141", "firefox-133", "safari-17-ios"}
	for _, name := range noH3Presets {
		pi, ok := info[name]
		if !ok {
			t.Errorf("expected non-H3 preset %q not found", name)
			continue
		}
		for _, p := range pi.Protocols {
			if p == "h3" {
				t.Errorf("preset %q should NOT support h3 but does", name)
			}
		}
	}
}
