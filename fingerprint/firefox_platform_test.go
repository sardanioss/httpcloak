package fingerprint

import (
	"encoding/json"
	"testing"
)

// Locks the Firefox per-platform preset wiring. Firefox advertises no UA Client
// Hints and NSS emits the same ClientHello regardless of OS, so a platform
// variant is its auto-detected base with exactly one field changed: the OS
// token of the User-Agent. This guards that the embedded JSON loaded (a base
// fallback would leave the host OS token in place), that the rv: token matches
// the Firefox version, and that nothing but name and User-Agent differs from
// the base fingerprint.
func TestFirefoxPlatformPresets(t *testing.T) {
	tests := []struct {
		name   string
		base   string
		wantUA string
	}{
		{"firefox-133-windows", "firefox-133", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"},
		{"firefox-133-linux", "firefox-133", "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"},
		{"firefox-133-macos", "firefox-133", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0"},
		{"firefox-148-windows", "firefox-148", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0"},
		{"firefox-148-linux", "firefox-148", "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"},
		{"firefox-148-macos", "firefox-148", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Get(tt.name)
			if p == nil {
				t.Fatalf("%s: not registered", tt.name)
			}
			if p.UserAgent != tt.wantUA {
				t.Errorf("%s: UA = %q, want %q (embedded JSON may not have loaded)", tt.name, p.UserAgent, tt.wantUA)
			}

			// Only name and User-Agent may differ from the base. Describe
			// flattens both to fully-resolved JSON, so blanking those two
			// fields makes the specs compare equal iff nothing else differs -
			// the TLS ClientHello, HTTP/2 settings and header order in
			// particular.
			if got, want := normalizedFirefoxSpec(t, tt.name), normalizedFirefoxSpec(t, tt.base); got != want {
				t.Errorf("%s differs from base %s beyond name and user-agent", tt.name, tt.base)
			}
		})
	}
}

// Firefox family names must resolve to real presets so a preset pool built from
// them does not silently fall back to Chrome via Get.
func TestFirefoxPlatformPresetsRegistered(t *testing.T) {
	for _, name := range []string{
		"firefox-133-windows", "firefox-133-linux", "firefox-133-macos",
		"firefox-148-windows", "firefox-148-linux", "firefox-148-macos",
		"firefox-latest-windows", "firefox-latest-linux", "firefox-latest-macos",
	} {
		if GetStrict(name) == nil {
			t.Errorf("%s: not registered (GetStrict returned nil)", name)
		}
	}
}

// normalizedFirefoxSpec describes a preset and deletes the two fields a
// platform variant is allowed to change - the preset name and the User-Agent -
// so two specs compare equal iff nothing else differs.
func normalizedFirefoxSpec(t *testing.T, name string) string {
	t.Helper()
	described, err := Describe(name)
	if err != nil {
		t.Fatalf("describe %q: %v", name, err)
	}
	var file map[string]any
	if err := json.Unmarshal([]byte(described), &file); err != nil {
		t.Fatalf("parse described %q: %v", name, err)
	}
	preset, ok := file["preset"].(map[string]any)
	if !ok {
		t.Fatalf("described %q has no preset object", name)
	}
	delete(preset, "name")
	if h, ok := preset["headers"].(map[string]any); ok {
		delete(h, "user_agent")
	}
	out, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("re-encode %q: %v", name, err)
	}
	return string(out)
}
