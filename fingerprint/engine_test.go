package fingerprint

import (
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/internal/engine"
)

// TestEveryPresetHasItsBrowsersEngine checks the engine read from each
// built-in preset's User-Agent against the browser the preset is named after:
// the Chrome presets on iOS are WebKit, every other Chrome preset Chromium,
// Firefox Gecko and Safari WebKit.
func TestEveryPresetHasItsBrowsersEngine(t *testing.T) {
	for _, name := range Available() {
		p := Get(name)
		if p == nil {
			t.Errorf("%s: Get returned nil", name)
			continue
		}
		var want engine.Kind
		switch {
		case strings.Contains(name, "ios"), strings.Contains(name, "safari"):
			want = engine.WebKit
		case strings.Contains(name, "chrome"):
			want = engine.Chromium
		case strings.Contains(name, "firefox"):
			want = engine.Gecko
		default:
			t.Errorf("%s: no browser in the name; add it to this test", name)
			continue
		}
		if got := engine.Of(p.UserAgent); got != want {
			t.Errorf("%s: engine %v, want %v (User-Agent %q)", name, got, want, p.UserAgent)
		}
	}
}
