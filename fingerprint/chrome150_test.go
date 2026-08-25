package fingerprint

import (
	"strings"
	"testing"
)

// Locks the Chrome 150 preset wiring. Chrome 150 inherits the byte-exact TLS/H2/
// QUIC base from the chrome-149 chain and adds, over 149 (all from a real Chrome
// 150 capture):
//   - TCP signature_algorithms prepend the three ML-DSA codepoints
//     (0x0904/0905/0906 = ML-DSA-44/65/87, draft-ietf-tls-mldsa) -> H1/H2 JA4
//     tail 806a8c22fdea. QUIC does NOT advertise ML-DSA (anti-amplification), so
//     its sig-algs override stays empty and the H3 JA4 tail stays 653d80c3fe9d.
//   - UA -> Chrome/150 and a sec-ch-ua brand rotation (GREASE "Not;A=Brand" v="8",
//     moved to first position).
//
// This guards the header overrides, the based_on chain, AND the per-protocol
// sig-algs split so a future edit can't silently drop ML-DSA off TCP or leak it
// onto QUIC.
func TestChrome150Presets(t *testing.T) {
	const wantSecCHUA = `"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"`

	// ML-DSA-44/65/87 codepoints (draft-ietf-tls-mldsa).
	const mldsa44, mldsa65, mldsa87 = 0x0904, 0x0905, 0x0906

	secCHUA := func(p *Preset) string {
		for _, h := range p.HeaderOrder {
			if h.Key == "sec-ch-ua" {
				return h.Value
			}
		}
		return p.Headers["sec-ch-ua"]
	}
	hasScheme := func(algs []uint16sig, v uint16sig) bool {
		for _, a := range algs {
			if a == v {
				return true
			}
		}
		return false
	}

	for _, name := range []string{"chrome-150", "chrome-150-windows", "chrome-150-linux", "chrome-150-macos"} {
		p := Get(name)
		if p == nil {
			t.Fatalf("%s: not registered", name)
		}
		if !strings.Contains(p.UserAgent, "Chrome/150.0.0.0") {
			t.Errorf("%s: UA = %q, want Chrome/150.0.0.0 (based_on chain may have fallen back)", name, p.UserAgent)
		}
		if got := secCHUA(p); got != wantSecCHUA {
			t.Errorf("%s: sec-ch-ua = %q, want %q", name, got, wantSecCHUA)
		}

		// TCP sig-algs MUST carry ML-DSA.
		tcp := toUint16sig(p.SignatureAlgorithms)
		for _, want := range []uint16sig{mldsa44, mldsa65, mldsa87} {
			if !hasScheme(tcp, want) {
				t.Errorf("%s: TCP SignatureAlgorithms missing ML-DSA 0x%04x: %v", name, want, tcp)
			}
		}
		// QUIC sig-algs MUST NOT carry ML-DSA (empty override = inherit the
		// byte-exact QUIC base).
		if len(p.QUICSignatureAlgorithms) != 0 {
			t.Errorf("%s: QUICSignatureAlgorithms must be empty (Chrome 150 does not send ML-DSA on QUIC), got %v", name, p.QUICSignatureAlgorithms)
		}
	}

	// chrome-latest tracks the newest desktop preset, now 152.
	if ua := Get("chrome-latest").UserAgent; !strings.Contains(ua, "Chrome/152.0.0.0") {
		t.Errorf("chrome-latest UA = %q, want Chrome/152.0.0.0", ua)
	}
}

// Locks the Chrome 150 iOS preset. iOS Chrome is forced onto Safari/WebKit's TLS
// stack (HelloIOS_18), so unlike the desktop chrome-150 line it must NOT carry the
// ML-DSA signature_algorithms override — WebKit does not advertise ML-DSA. The
// wire fingerprint is inherited byte-exact from the chrome-148 iOS base (verified
// JA4 t13d2013h2_a09f3c656075_7f0f34a4126d against a real iOS 26.5 capture); this
// guards the UA/header bump, the Safari TLS base, and the no-ML-DSA invariant.
func TestChrome150IOSPreset(t *testing.T) {
	p := Get("chrome-150-ios")
	if p == nil {
		t.Fatal("chrome-150-ios: not registered")
	}
	if !strings.Contains(p.UserAgent, "CriOS/150.0.7871.51") || !strings.Contains(p.UserAgent, "iPhone OS 26_5") {
		t.Errorf("chrome-150-ios: UA = %q, want CriOS/150.0.7871.51 on iPhone OS 26_5 (based_on chain may have fallen back)", p.UserAgent)
	}
	// Safari/WebKit TLS, not desktop Chrome's ClientHello.
	if p.ClientHelloID.Client != "iOS" {
		t.Errorf("chrome-150-ios: ClientHelloID.Client = %q, want iOS (WebKit/Safari TLS)", p.ClientHelloID.Client)
	}
	// WebKit does not advertise ML-DSA — no signature_algorithms override.
	if len(p.SignatureAlgorithms) != 0 {
		t.Errorf("chrome-150-ios: SignatureAlgorithms must be empty (iOS/WebKit has no ML-DSA), got %v", p.SignatureAlgorithms)
	}
	if len(p.QUICSignatureAlgorithms) != 0 {
		t.Errorf("chrome-150-ios: QUICSignatureAlgorithms must be empty, got %v", p.QUICSignatureAlgorithms)
	}
	// The iOS header block leads with sec-fetch-dest (Safari order), inherited from
	// the 148 base; a based_on regression would drop it to desktop Chrome's order.
	if len(p.HeaderOrder) == 0 || p.HeaderOrder[0].Key != "sec-fetch-dest" {
		t.Errorf("chrome-150-ios: header order should lead with sec-fetch-dest, got %+v", p.HeaderOrder)
	}
	// chrome-latest-ios moved to 151 once a real CriOS/151 capture landed.
	// It sat on 150 while the 151 User-Agent was invented.
	if ua := Get("chrome-latest-ios").UserAgent; !strings.Contains(ua, "CriOS/151.0.7922.112") {
		t.Errorf("chrome-latest-ios UA = %q, want the captured CriOS/151.0.7922.112", ua)
	}
}

// Locks the Chrome 150 Android preset. Android Chrome runs the same
// Chromium/BoringSSL stack as desktop (only iOS is the WebKit exception), so
// unlike chrome-150-ios it MUST carry the ML-DSA signature_algorithms override on
// TCP (never on QUIC), while wearing the reduced-UA mobile identity
// (sec-ch-ua-mobile ?1, sec-ch-ua-platform "Android"). Guards the ML-DSA
// inheritance and the mobile header identity against a based_on regression.
func TestChrome150AndroidPreset(t *testing.T) {
	const mldsa44, mldsa65, mldsa87 = 0x0904, 0x0905, 0x0906
	p := Get("chrome-150-android")
	if p == nil {
		t.Fatal("chrome-150-android: not registered")
	}
	if !strings.Contains(p.UserAgent, "Chrome/150.0.0.0") || !strings.Contains(p.UserAgent, "Android 10; K") || !strings.Contains(p.UserAgent, "Mobile") {
		t.Errorf("chrome-150-android: UA = %q, want reduced Android Chrome/150 Mobile UA", p.UserAgent)
	}
	hdr := func(k string) string {
		for _, h := range p.HeaderOrder {
			if h.Key == k {
				return h.Value
			}
		}
		return p.Headers[k]
	}
	if got := hdr("sec-ch-ua-mobile"); got != "?1" {
		t.Errorf("chrome-150-android: sec-ch-ua-mobile = %q, want ?1", got)
	}
	if got := hdr("sec-ch-ua-platform"); got != `"Android"` {
		t.Errorf("chrome-150-android: sec-ch-ua-platform = %q, want \"Android\"", got)
	}
	// Android mirrors desktop: ML-DSA on TCP.
	tcp := toUint16sig(p.SignatureAlgorithms)
	has := func(v uint16sig) bool {
		for _, a := range tcp {
			if a == v {
				return true
			}
		}
		return false
	}
	for _, want := range []uint16sig{mldsa44, mldsa65, mldsa87} {
		if !has(want) {
			t.Errorf("chrome-150-android: TCP SignatureAlgorithms missing ML-DSA 0x%04x: %v", want, tcp)
		}
	}
	// ...but not on QUIC.
	if len(p.QUICSignatureAlgorithms) != 0 {
		t.Errorf("chrome-150-android: QUICSignatureAlgorithms must be empty, got %v", p.QUICSignatureAlgorithms)
	}
	if ua := Get("chrome-latest-android").UserAgent; !strings.Contains(ua, "Chrome/152.0.0.0") {
		t.Errorf("chrome-latest-android UA = %q, want Chrome/152.0.0.0", ua)
	}
}

// uint16sig mirrors utls.SignatureScheme (uint16) so the test can compare
// codepoints without importing the alias under a second name.
type uint16sig = uint16

func toUint16sig[T ~uint16](in []T) []uint16sig {
	out := make([]uint16sig, len(in))
	for i, v := range in {
		out[i] = uint16sig(v)
	}
	return out
}
