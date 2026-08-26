package fingerprint

import (
	"strings"
	"testing"
)

// Locks the iOS Chrome header shape against a real CriOS/151 capture.
//
// iOS Chrome is WebKit underneath and inherits Safari's TLS, which is why the
// preset was built on the Safari base. It does NOT inherit Safari's HTTP/2
// header order, and that went unnoticed because the JA4, peetprint and Akamai
// fingerprints all matched: none of them covers the regular header order. The
// preset carried Safari's, and put eight headers on the wire in the wrong
// sequence on every request.
//
// Captured order, which is also what the preset's own headers.order declared
// all along:
//
//	sec-fetch-dest, user-agent, accept, sec-fetch-site, sec-fetch-mode,
//	accept-language, priority, accept-encoding
func TestIOSChromeHeaderOrder(t *testing.T) {
	want := []string{
		"sec-fetch-dest", "user-agent", "accept", "sec-fetch-site",
		"sec-fetch-mode", "accept-language", "priority", "accept-encoding",
	}

	for _, name := range []string{"chrome-148-ios", "chrome-150-ios", "chrome-151-ios", "chrome-152-ios"} {
		p := Get(name)
		if p == nil {
			t.Errorf("%s not registered", name)
			continue
		}
		got := p.H2HeaderOrder()
		if len(got) < len(want) {
			t.Errorf("%s: H2 header order has %d entries, want at least %d",
				name, len(got), len(want))
			continue
		}
		for i, w := range want {
			if got[i] != w {
				t.Errorf("%s: H2 header order position %d is %q, want %q; the "+
					"whole prefix is %v", name, i, got[i], w, got[:len(want)])
				break
			}
		}

		// Safari's order leads with accept and carries sec-fetch-user early.
		// Landing back on it means the based_on chain fell through again.
		if got[0] == "accept" {
			t.Errorf("%s: H2 header order leads with accept, which is Safari's "+
				"shape, not iOS Chrome's", name)
		}
	}
}

// The iOS User-Agent is measured, not invented.
//
// chrome-151-ios shipped a placeholder, CriOS/151.0.7990.44 on iOS 26_5_0, and
// a real capture turned out to be CriOS/151.0.7922.112 on 26_6_0: wrong in both
// the build number and the iOS version. No scheme would have guessed it, which
// is why the line does not invent them any more.
func TestIOSChromeUserAgentIsCaptured(t *testing.T) {
	p := Get("chrome-151-ios")
	if p == nil {
		t.Fatal("chrome-151-ios not registered")
	}
	const want = "CriOS/151.0.7922.112"
	if !strings.Contains(p.UserAgent, want) {
		t.Errorf("chrome-151-ios UA = %q, want it to contain the captured %q",
			p.UserAgent, want)
	}
	if strings.Contains(p.UserAgent, "7990.44") {
		t.Error("chrome-151-ios still carries the invented build number 7990.44")
	}

	// 152 is captured too, and its build number is not derivable from 151's:
	// 7922.112 -> 7977.64, with the patch component going DOWN.
	q := Get("chrome-152-ios")
	if q == nil {
		t.Fatal("chrome-152-ios not registered")
	}
	if !strings.Contains(q.UserAgent, "CriOS/152.0.7977.64") {
		t.Errorf("chrome-152-ios UA = %q, want the captured CriOS/152.0.7977.64", q.UserAgent)
	}
	for _, guess := range []string{"8080.60", "7990.44"} {
		if strings.Contains(q.UserAgent, guess) || strings.Contains(p.UserAgent, guess) {
			t.Errorf("an iOS preset still carries the invented build number %s", guess)
		}
	}
}

// iOS Chrome sends no client hints at all, so neither Chrome 152 wire change
// reaches it either.
func TestIOSChromeSendsNoChromeOnlyMachinery(t *testing.T) {
	for _, name := range []string{"chrome-150-ios", "chrome-151-ios", "chrome-152-ios"} {
		p := Get(name)
		if p == nil {
			continue
		}
		for _, h := range p.HeaderOrder {
			if strings.HasPrefix(strings.ToLower(h.Key), "sec-ch-ua") {
				t.Errorf("%s sends the client hint %q; WebKit has none", name, h.Key)
			}
		}
		if len(p.TrustAnchors) != 0 {
			t.Errorf("%s carries %d trust anchors; that is a BoringSSL extension",
				name, len(p.TrustAnchors))
		}
	}
}
