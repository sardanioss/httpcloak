package fingerprint

import (
	"fmt"
	"strings"
	"testing"
)

// Chrome 156 is headers-only over 155, as 153 and 154 were over theirs: the
// User-Agent and sec-ch-ua move. Checked on the wire against Chrome
// 156.0.8078.73 on Linux through tls.peet.ws: the same JA4 and peetprint as
// chrome-155-linux, the same HTTP/2 SETTINGS and header order, and the
// document, image, script and fetch() Accept unchanged. This sec-ch-ua is what
// that Chrome sent, and what Chromium's brand derivation gives for 156.
const chrome156SecCHUA = `"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"`

func TestChrome156Presets(t *testing.T) {
	for _, suffix := range []string{"", "-windows", "-linux", "-macos", "-android"} {
		name := "chrome-156" + suffix
		p := GetStrict(name)
		if p == nil {
			t.Errorf("%s not registered", name)
			continue
		}
		if !strings.Contains(p.UserAgent, "Chrome/156.0.0.0") {
			t.Errorf("%s: UA = %q, want Chrome/156.0.0.0; the based_on chain may have dropped the override", name, p.UserAgent)
		}
		if got := chrome152SecCHUA(p); got != chrome156SecCHUA {
			t.Errorf("%s: sec-ch-ua = %q, want %q", name, got, chrome156SecCHUA)
		}
	}
	if got := greasedBrandList(156); got != chrome156SecCHUA {
		t.Errorf("chrome-156: derivation gives %q, Chrome sent %q", got, chrome156SecCHUA)
	}
}

// Everything but those two headers reaches 156 from 155 through based_on.
func TestChrome156InheritsTheClientHello(t *testing.T) {
	for _, plat := range []string{"windows", "linux", "macos", "android"} {
		old, new := Get("chrome-155-"+plat), Get("chrome-156-"+plat)
		label := "chrome-156-" + plat
		if new.ClientHelloID != old.ClientHelloID || new.QUICClientHelloID != old.QUICClientHelloID {
			t.Errorf("%s: ClientHello ids differ from 155", label)
		}
		if fmt.Sprint(new.SignatureAlgorithms) != fmt.Sprint(old.SignatureAlgorithms) {
			t.Errorf("%s: signature algorithms differ from 155", label)
		}
		if fmt.Sprint(anchorHex(new)) != fmt.Sprint(anchorHex(old)) {
			t.Errorf("%s: trust anchors differ from 155", label)
		}
		if new.ResolveNavigationAccept() != old.ResolveNavigationAccept() || new.ResolveImageAccept() != old.ResolveImageAccept() {
			t.Errorf("%s: Accept moved, but 156 kept 155's", label)
		}
		if diff := headerValueDiff(old, new); len(diff) != 2 {
			t.Errorf("%s: %d header values differ from 155, want 2 (user-agent, sec-ch-ua): %v", label, len(diff), diff)
		}
	}
}

// No iOS preset for 156, for the reason given under
// TestChrome153HasNoIOSPresetYet.
func TestChrome156HasNoIOSPresetYet(t *testing.T) {
	if p := GetStrict("chrome-156-ios"); p != nil {
		t.Errorf("chrome-156-ios is registered with UA %q; only add it from a capture", p.UserAgent)
	}
}

// The -latest aliases move as a set. This is the single home
// for the assertion; move it to the next version's file rather than copying it.
// iOS stays on its last capture.
func TestChrome156LatestAliases(t *testing.T) {
	for _, tc := range []struct{ alias, wantUA string }{
		{"chrome-latest", "Chrome/156.0.0.0"},
		{"chrome-latest-windows", "Chrome/156.0.0.0"},
		{"chrome-latest-linux", "Chrome/156.0.0.0"},
		{"chrome-latest-macos", "Chrome/156.0.0.0"},
		{"chrome-latest-android", "Chrome/156.0.0.0"},
		{"android-chrome-latest", "Chrome/156.0.0.0"},
		{"chrome-latest-ios", "CriOS/155.0.8059.37"},
		{"ios-chrome-latest", "CriOS/155.0.8059.37"},
	} {
		p := GetStrict(tc.alias)
		if p == nil {
			t.Errorf("%s not registered", tc.alias)
			continue
		}
		if !strings.Contains(p.UserAgent, tc.wantUA) {
			t.Errorf("%s: UA = %q, want it to contain %q", tc.alias, p.UserAgent, tc.wantUA)
		}
	}
}
