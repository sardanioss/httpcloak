package fingerprint

import (
	"strings"
	"testing"
)

// A browser sends fetch() and XHR the Accept-Encoding and Accept-Language it
// sends on every other request: Chrome 156, Firefox 159 and Safari 26.3 each
// sent one pair on navigations, iframes, fetch(), XHR and subresource loads.
// GenerateXHRHeaders hardcoded Chrome's pair, so safari-18 and the iOS Chrome
// 143 to 147 presets gained zstd, firefox-133 sent q=0.9 instead of its q=0.5,
// and chrome-144-macos lost its en-GB list. The pair to match is the one the
// session transport sends, from the preset's order list.
func TestGenerateXHRHeadersUsesPresetEncodingAndLanguage(t *testing.T) {
	for _, name := range Available() {
		p := Get(name)
		var enc, lang string
		for _, hp := range p.HeaderOrder {
			switch strings.ToLower(hp.Key) {
			case "accept-encoding":
				enc = hp.Value
			case "accept-language":
				lang = hp.Value
			}
		}
		if enc == "" || lang == "" {
			t.Fatalf("%s sends no Accept-Encoding or Accept-Language", name)
		}
		h := NewHeaderCoherence(p).GenerateXHRHeaders("https://example.com/page", "https://example.com/api")
		if h["Accept-Encoding"] != enc || h["Accept-Language"] != lang {
			t.Errorf("%s: Accept-Encoding %q, Accept-Language %q; want %q, %q",
				name, h["Accept-Encoding"], h["Accept-Language"], enc, lang)
		}
	}

	// A preset without either header gets Chrome's.
	h := NewHeaderCoherence(&Preset{Name: "custom"}).GenerateXHRHeaders("", "https://example.com/api")
	if h["Accept-Encoding"] != "gzip, deflate, br, zstd" || h["Accept-Language"] != "en-US,en;q=0.9" {
		t.Errorf("custom preset: Accept-Encoding %q, Accept-Language %q; want Chrome's",
			h["Accept-Encoding"], h["Accept-Language"])
	}
}
