package fingerprint

import (
	"strings"
	"testing"
)

// A mistyped preset name used to resolve to a real preset several Chrome
// versions old, so the request went out with a fingerprint nobody chose and
// nothing said so. These are the mistakes people actually make.
func TestSuggestNamesTheNearestPreset(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"chrome-152-window", "chrome-152-windows"},   // dropped character
		{"chrmoe-152-windows", "chrome-152-windows"},  // transposition
		{"chrome-152-windowss", "chrome-152-windows"}, // doubled character
		{"chrome152-windows", "chrome-152-windows"},   // missing separator
		{"firefox-latst", "firefox-latest"},
	} {
		if got := Suggest(tc.in); got != tc.want {
			t.Errorf("Suggest(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A name sharing nothing with any preset gets no suggestion, so the error says
// "try chrome-latest" rather than proposing something arbitrary.
func TestSuggestDeclinesWhenNothingIsClose(t *testing.T) {
	for _, in := range []string{"totally-made-up", "curl", "", "xxxxxxxxxxxxxxxxxxxx"} {
		if got := Suggest(in); got != "" {
			t.Errorf("Suggest(%q) = %q, want no suggestion", in, got)
		}
	}
}

// The error names the closest match when there is one, and the current default
// resolved to its real version when there is not.
func TestUnknownPresetErrorText(t *testing.T) {
	err := UnknownPresetError("chrome-152-window")
	if !strings.Contains(err.Error(), `did you mean "chrome-152-windows"`) {
		t.Errorf("error does not name the near match: %v", err)
	}

	err = UnknownPresetError("totally-made-up")
	if !strings.Contains(err.Error(), "chrome-latest") {
		t.Errorf("error does not point at the default: %v", err)
	}
	if !strings.Contains(err.Error(), "currently chrome-15") {
		t.Errorf("error does not resolve what chrome-latest currently is: %v", err)
	}
}

// Every shipped preset has to be reachable through the list the error points at,
// or the advice is wrong.
func TestKnownPresetsCoversTheShippedOnes(t *testing.T) {
	known := map[string]bool{}
	for _, n := range KnownPresets() {
		known[n] = true
	}
	for _, n := range []string{
		"chrome-152-windows", "chrome-152-ios", "chrome-latest",
		"firefox-148", "safari-18", "chrome-133",
	} {
		if !known[n] {
			t.Errorf("KnownPresets() omits %q", n)
		}
	}
	if len(known) < 40 {
		t.Errorf("KnownPresets() returned only %d names, expected the full registry", len(known))
	}
}
