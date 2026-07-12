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

	// chrome-latest tracks the newest desktop preset (150).
	if ua := Get("chrome-latest").UserAgent; !strings.Contains(ua, "Chrome/150.0.0.0") {
		t.Errorf("chrome-latest UA = %q, want Chrome/150.0.0.0", ua)
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
