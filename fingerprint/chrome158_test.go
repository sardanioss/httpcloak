package fingerprint

import (
	"fmt"
	"strings"
	"testing"
)

// Chrome 156, 157 and 158 are headers-only bumps over 155: the User-Agent and
// sec-ch-ua move, nothing else. Measured on 155.0.8059.84, 156.0.8078.80,
// 157.0.8103.50 and 158.0.8127.18 through one local recorder: the ClientHello, the HTTP/2
// SETTINGS, WINDOW_UPDATE and HEADERS frames, the header order and the Accept
// values were identical across all four, and chrome-155-linux matched 155 on
// every one of them. Both sec-ch-ua values were derived first and then matched
// the greased brand of the real binaries.
//
// Those builds were run with --disable-field-trial-config. Without it, the
// testing field trial config adds a TLS extension (0x12e0) and trims
// Accept-Language; neither is what a stable Chrome sends.
const (
	chrome156SecCHUA = `"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"`
	chrome157SecCHUA = `"Not-A.Brand";v="99", "Google Chrome";v="157", "Chromium";v="157"`
	chrome158SecCHUA = `"Chromium";v="158", "Not.A/Brand";v="24", "Google Chrome";v="158"`
)

func TestChrome156To158Presets(t *testing.T) {
	for _, tc := range []struct {
		major   int
		secCHUA string
	}{{156, chrome156SecCHUA}, {157, chrome157SecCHUA}, {158, chrome158SecCHUA}} {
		if got := greasedBrandList(tc.major); got != tc.secCHUA {
			t.Errorf("chrome-%d: derivation gives %q, want %q", tc.major, got, tc.secCHUA)
		}
		for _, suffix := range []string{"", "-windows", "-linux", "-macos", "-android"} {
			name := fmt.Sprintf("chrome-%d%s", tc.major, suffix)
			p := GetStrict(name)
			if p == nil {
				t.Errorf("%s not registered", name)
				continue
			}
			if want := fmt.Sprintf("Chrome/%d.0.0.0", tc.major); !strings.Contains(p.UserAgent, want) {
				t.Errorf("%s: UA = %q, want %s; the based_on chain may have dropped the override",
					name, p.UserAgent, want)
			}
			if got := chrome152SecCHUA(p); got != tc.secCHUA {
				t.Errorf("%s: sec-ch-ua = %q, want %q", name, got, tc.secCHUA)
			}
		}
	}
}

// Everything but the two headers reaches 156, 157 and 158 through based_on: same
// ClientHello, signature algorithms, trust anchors in the same order, and the
// same Accept values.
func TestChrome156To158InheritEverythingElse(t *testing.T) {
	for _, plat := range []string{"windows", "linux", "macos", "android"} {
		for _, step := range [][2]int{{155, 156}, {156, 157}, {157, 158}} {
			old := Get(fmt.Sprintf("chrome-%d-%s", step[0], plat))
			new := Get(fmt.Sprintf("chrome-%d-%s", step[1], plat))
			label := fmt.Sprintf("chrome-%d-%s", step[1], plat)
			if new.ClientHelloID != old.ClientHelloID || new.QUICClientHelloID != old.QUICClientHelloID {
				t.Errorf("%s: ClientHello ids differ from %d", label, step[0])
			}
			if fmt.Sprint(new.SignatureAlgorithms) != fmt.Sprint(old.SignatureAlgorithms) {
				t.Errorf("%s: signature algorithms differ from %d", label, step[0])
			}
			if fmt.Sprint(anchorHex(new)) != fmt.Sprint(anchorHex(old)) {
				t.Errorf("%s: trust anchors differ from %d", label, step[0])
			}
			if new.ResolveNavigationAccept() != old.ResolveNavigationAccept() ||
				new.ResolveImageAccept() != old.ResolveImageAccept() {
				t.Errorf("%s: Accept differs from %d", label, step[0])
			}
			if diff := headerValueDiff(old, new); len(diff) != 2 {
				t.Errorf("%s: %d header values differ from %d, want 2 (User-Agent, sec-ch-ua): %v",
					label, len(diff), step[0], diff)
			}
		}
	}
}

func TestChromeBrandListFollowsChromiumThrough158(t *testing.T) {
	for major := 146; major <= 158; major++ {
		p := GetStrict(fmt.Sprintf("chrome-%d-windows", major))
		if p == nil {
			continue
		}
		if got, want := greasedBrandList(major), chrome152SecCHUA(p); got != want {
			t.Errorf("chrome-%d: derivation gives %q, tree has %q", major, got, want)
		}
	}
}

// No iOS preset for 156, 157 or 158 until a capture gives the CriOS build number;
// see TestChrome153HasNoIOSPresetYet.
func TestChrome156To158HaveNoIOSPresetYet(t *testing.T) {
	for _, name := range []string{"chrome-156-ios", "chrome-157-ios", "chrome-158-ios"} {
		if p := GetStrict(name); p != nil {
			t.Errorf("%s is registered with UA %q; only add it from a capture", name, p.UserAgent)
		}
	}
}

// The -latest aliases move as a set. This is the single home
// for the assertion; move it to the next version's file rather than copying it.
// iOS stays on the newest captured build.
func TestChrome158LatestAliases(t *testing.T) {
	for _, tc := range []struct{ alias, wantUA string }{
		{"chrome-latest", "Chrome/158.0.0.0"},
		{"chrome-latest-windows", "Chrome/158.0.0.0"},
		{"chrome-latest-linux", "Chrome/158.0.0.0"},
		{"chrome-latest-macos", "Chrome/158.0.0.0"},
		{"chrome-latest-android", "Chrome/158.0.0.0"},
		{"android-chrome-latest", "Chrome/158.0.0.0"},
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
