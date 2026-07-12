package fingerprint

import (
	"strings"
	"testing"
)

// Locks the Chrome 149 preset wiring (issue: 2026-06 Chrome 149 release). The
// wire fingerprint is inherited from chrome-148 (verified identical on the wire:
// JA4 t13d1516h2_8daaf6152771_d8a2da3f94cd); this guards the header overrides
// and the based_on chain so a future edit can't silently drop them back to 148.
func TestChrome149Presets(t *testing.T) {
	const wantSecCHUA = `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"`

	secCHUA := func(p *Preset) string {
		for _, h := range p.HeaderOrder {
			if h.Key == "sec-ch-ua" {
				return h.Value
			}
		}
		return p.Headers["sec-ch-ua"]
	}

	for _, name := range []string{"chrome-149", "chrome-149-windows", "chrome-149-linux", "chrome-149-macos"} {
		p := Get(name)
		if p == nil {
			t.Fatalf("%s: not registered", name)
		}
		if !strings.Contains(p.UserAgent, "Chrome/149.0.0.0") {
			t.Errorf("%s: UA = %q, want Chrome/149.0.0.0 (based_on chain may have fallen back to 148)", name, p.UserAgent)
		}
		if got := secCHUA(p); got != wantSecCHUA {
			t.Errorf("%s: sec-ch-ua = %q, want %q", name, got, wantSecCHUA)
		}
	}

	// chrome-latest now resolves to Chrome 150 (the newest desktop preset).
	if ua := Get("chrome-latest").UserAgent; !strings.Contains(ua, "Chrome/150.0.0.0") {
		t.Errorf("chrome-latest UA = %q, want Chrome/150.0.0.0", ua)
	}
}
