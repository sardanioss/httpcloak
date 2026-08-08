package fingerprint

import (
	"strings"
	"testing"

	tls "github.com/sardanioss/utls"
)

// Chrome 151 is a pure header diff over the chrome-150 chain. Everything below
// the header layer must be inherited untouched.
//
// The sec-ch-ua value below is transcribed from real Chrome 151 captures (both
// a TCP/H2 capture and an independent QUIC/H3 one). It is asserted literally
// because a version bump alone does not produce it: Chrome reseeds its greased
// brand list off the major version, so the separator characters, the GREASE
// version and the brand ORDER all changed between 150 and 151.
//
//	150: "Not;A=Brand";v="8",  "Chromium";v="150", "Google Chrome";v="150"
//	151: "Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"
const chrome151SecCHUA = `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`

// ML-DSA post-quantum codepoints (0x0904-0x0906) followed by the classical set,
// inherited from chrome-150. Yields JA4 t13d1516h2_8daaf6152771_806a8c22fdea.
var chrome151SigAlgs = []tls.SignatureScheme{
	0x0904, 0x0905, 0x0906,
	tls.ECDSAWithP256AndSHA256,
	tls.PSSWithSHA256,
	tls.PKCS1WithSHA256,
	tls.ECDSAWithP384AndSHA384,
	tls.PSSWithSHA384,
	tls.PKCS1WithSHA384,
	tls.PSSWithSHA512,
	tls.PKCS1WithSHA512,
}

func TestChrome151DesktopPresets(t *testing.T) {
	cases := []struct {
		preset   string
		ua       string
		platform string
	}{
		{"chrome-151-windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36", `"Windows"`},
		{"chrome-151-linux", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36", `"Linux"`},
		{"chrome-151-macos", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36", `"macOS"`},
	}

	for _, tc := range cases {
		t.Run(tc.preset, func(t *testing.T) {
			p := Get(tc.preset)
			if p == nil {
				t.Fatalf("%s not registered", tc.preset)
			}
			// A failure here usually means the based_on chain fell back to an
			// older preset rather than loading the 151 JSON.
			if p.Name != tc.preset {
				t.Errorf("Name = %q, want %q (based_on chain may have fallen back)", p.Name, tc.preset)
			}
			if p.UserAgent != tc.ua {
				t.Errorf("UserAgent =\n  %q\nwant\n  %q", p.UserAgent, tc.ua)
			}
			assertHeader(t, p, "sec-ch-ua", chrome151SecCHUA)
			assertHeader(t, p, "sec-ch-ua-platform", tc.platform)
			assertHeader(t, p, "sec-ch-ua-mobile", "?0")

			// Inherited from 150 and must not drift.
			assertSigAlgs(t, tc.preset, p.SignatureAlgorithms, chrome151SigAlgs)
			if len(p.QUICSignatureAlgorithms) != 0 {
				t.Errorf("%s: QUICSignatureAlgorithms must stay empty (Chrome does not "+
					"advertise ML-DSA over QUIC), got %v", tc.preset, p.QUICSignatureAlgorithms)
			}
		})
	}
}

func TestChrome151AndroidPreset(t *testing.T) {
	p := Get("chrome-151-android")
	if p == nil {
		t.Fatal("chrome-151-android not registered")
	}
	if p.Name != "chrome-151-android" {
		t.Errorf("Name = %q, want chrome-151-android (based_on chain may have fallen back)", p.Name)
	}
	const wantUA = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36"
	if p.UserAgent != wantUA {
		t.Errorf("UserAgent =\n  %q\nwant\n  %q", p.UserAgent, wantUA)
	}
	assertHeader(t, p, "sec-ch-ua", chrome151SecCHUA)
	assertHeader(t, p, "sec-ch-ua-mobile", "?1")
	assertHeader(t, p, "sec-ch-ua-platform", `"Android"`)

	assertSigAlgs(t, "chrome-151-android", p.SignatureAlgorithms, chrome151SigAlgs)
	if len(p.QUICSignatureAlgorithms) != 0 {
		t.Errorf("chrome-151-android: QUICSignatureAlgorithms must be empty, got %v", p.QUICSignatureAlgorithms)
	}
}

// iOS Chrome is WebKit underneath, so it sends no client hints and must not
// pick up the desktop ML-DSA signature algorithms.
func TestChrome151IOSPreset(t *testing.T) {
	p := Get("chrome-151-ios")
	if p == nil {
		t.Fatal("chrome-151-ios not registered")
	}
	if p.Name != "chrome-151-ios" {
		t.Errorf("Name = %q, want chrome-151-ios (based_on chain may have fallen back)", p.Name)
	}
	if !strings.Contains(p.UserAgent, "CriOS/151.") {
		t.Errorf("UserAgent = %q, want a CriOS/151.x build", p.UserAgent)
	}
	if len(p.SignatureAlgorithms) != 0 {
		t.Errorf("chrome-151-ios must not carry desktop ML-DSA sig-algs, got %v", p.SignatureAlgorithms)
	}
}

// The -latest aliases must track the newest verified preset. iOS deliberately
// stays on 150: the iOS User-Agent carries a full build number that cannot be
// derived from the major version, so chrome-151-ios is provisional until a real
// capture confirms it. When that lands, update the UA in
// embedded/chrome-151-ios.json, point chrome-latest-ios at IOSChrome151, and
// flip this assertion.
func TestChrome151LatestAliases(t *testing.T) {
	for alias, want := range map[string]string{
		"chrome-latest":         "Chrome/151.0.0.0",
		"chrome-latest-windows": "Chrome/151.0.0.0",
		"chrome-latest-linux":   "Chrome/151.0.0.0",
		"chrome-latest-macos":   "Chrome/151.0.0.0",
		"chrome-latest-android": "Chrome/151.0.0.0",
		"chrome-latest-ios":     "CriOS/150.",
	} {
		p := Get(alias)
		if p == nil {
			t.Errorf("%s not registered", alias)
			continue
		}
		if !strings.Contains(p.UserAgent, want) {
			t.Errorf("%s UA = %q, want it to contain %q", alias, p.UserAgent, want)
		}
	}
}

func assertHeader(t *testing.T, p *Preset, key, want string) {
	t.Helper()
	for _, h := range p.HeaderOrder {
		if strings.EqualFold(h.Key, key) {
			if h.Value != want {
				t.Errorf("header %s =\n  %q\nwant\n  %q", key, h.Value, want)
			}
			return
		}
	}
	t.Errorf("header %s missing from HeaderOrder", key)
}

func assertSigAlgs(t *testing.T, preset string, got, want []tls.SignatureScheme) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: SignatureAlgorithms = %v (len %d), want len %d", preset, got, len(got), len(want))
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s: SignatureAlgorithms[%d] = 0x%04x, want 0x%04x", preset, i, got[i], want[i])
		}
	}
}
