package fingerprint

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Chrome 152 is the first release since 146 to change the ClientHello rather
// than only the headers. Two wire changes, both confirmed against BoringSSL
// source and four captures across two hosts and both transports.

// chrome152SecCHUA reads the brand list from wherever a preset keeps it. The
// older files declare this as a closure inside each test; it is a package
// helper here so the 152 tests can share one.
func chrome152SecCHUA(p *Preset) string {
	for _, h := range p.HeaderOrder {
		if h.Key == "sec-ch-ua" {
			return h.Value
		}
	}
	return p.Headers["sec-ch-ua"]
}

// The desktop and Android presets carry both wire changes and the reseeded
// brand list.
func TestChrome152Desktop(t *testing.T) {
	const wantSecCHUA = `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`

	for _, name := range []string{
		"chrome-152", "chrome-152-windows", "chrome-152-linux",
		"chrome-152-macos", "chrome-152-android",
	} {
		p := Get(name)
		if p == nil {
			t.Errorf("%s not registered", name)
			continue
		}
		if !strings.Contains(p.UserAgent, "Chrome/152.0.0.0") {
			t.Errorf("%s: UA = %q, want Chrome/152.0.0.0; the based_on chain may "+
				"have fallen back to 151", name, p.UserAgent)
		}
		if got := chrome152SecCHUA(p); got != wantSecCHUA {
			t.Errorf("%s: sec-ch-ua = %q, want %q", name, got, wantSecCHUA)
		}

		// signature_algorithms carries NO GREASE by default, and the eleven
		// entries are Chrome 151's, unchanged.
		//
		// Chrome 152 can go either way here. BoringSSL prepends a GREASE
		// sigalg from ext_sigalgs_add_clienthello, but only when
		// grease_sigalgs_enabled is set, and Chromium sets it behind a Finch
		// flag:
		//
		//	SSL_CTX_set_grease_enabled(ssl_ctx_.get(), 1);
		//	if (base::FeatureList::IsEnabled(features::kTlsGreaseSigalgs)) {
		//	  SSL_CTX_set_grease_sigalgs_enabled(ssl_ctx_.get(), 1);
		//	}
		//
		// BoringSSL's own header calls it staged ("fold this into
		// SSL_CTX_set_grease_enabled once deployed safely"), so both cohorts
		// are genuine Chrome 152 and flag-off is the larger one for now.
		//
		// We default to flag-off because the exposure is asymmetric. JA4 says
		// to ignore GREASE "anywhere it sees them", so a compliant scorer
		// hashes both cohorts to one stable value and the choice is free. A
		// non-compliant scorer folds the GREASE into JA4_c, and then flag-on
		// yields sixteen identities from one profile while flag-off yields
		// one. Measured against tls.peet.ws, which is non-compliant here:
		// twenty connections gave twelve distinct JA4_c, a clean 1:1 map from
		// GREASE value to hash.
		//
		// Flag-on stays reachable: put 2570 back at the head of
		// signature_algorithms in the preset JSON. TestChrome152SigalgGrease
		// below locks that it still works.
		if len(p.SignatureAlgorithms) != 11 {
			t.Errorf("%s: %d TCP signature algorithms, want 11 (Chrome 151's list, no GREASE)",
				name, len(p.SignatureAlgorithms))
			continue
		}
		for i, sa := range p.SignatureAlgorithms {
			if uint16(sa)&0x0f0f == 0x0a0a {
				t.Errorf("%s: algorithm %d is a GREASE value %#04x; the default "+
					"cohort is flag-off, so nothing here may be GREASE", name, i, sa)
			}
		}

		// QUIC needs no override: the nine algorithms the base advertises
		// already match the capture, and Chrome sends no GREASE there.
		if len(p.QUICSignatureAlgorithms) != 0 {
			t.Errorf("%s: QUICSignatureAlgorithms must stay empty; Chrome 152 "+
				"greases signature_algorithms on TCP only, and the QUIC list is "+
				"already correct in the base. Got %v", name, p.QUICSignatureAlgorithms)
		}

		// 28 trust anchors across three issuer arcs, 11 / 9 / 8. It was 32
		// when 152 shipped; the Chrome Root Store is component-updated, so the
		// set moves without a browser version bump.
		if len(p.TrustAnchors) != 28 {
			t.Errorf("%s: %d trust anchors, want 28", name, len(p.TrustAnchors))
			continue
		}
		arcs := map[string]int{}
		seen := map[string]bool{}
		for _, ta := range p.TrustAnchors {
			h := hex.EncodeToString(ta)
			if seen[h] {
				t.Errorf("%s: trust anchor %s appears twice", name, h)
			}
			seen[h] = true
			switch {
			case strings.HasPrefix(h, "d67909"):
				arcs["d67909"]++
			case strings.HasPrefix(h, "839a648c9b2d01"):
				arcs["839a648c9b2d01"]++
			case strings.HasPrefix(h, "82df1302"):
				arcs["82df1302"]++
			default:
				t.Errorf("%s: trust anchor %s is under no known issuer arc", name, h)
			}
		}
		for arc, want := range map[string]int{"d67909": 11, "839a648c9b2d01": 9, "82df1302": 8} {
			if arcs[arc] != want {
				t.Errorf("%s: arc %s has %d identifiers, want %d", name, arc, arcs[arc], want)
			}
		}
	}
}

// iOS Chrome is WebKit underneath, so NEITHER wire change applies.
//
// Two CriOS/152 captures agree with the two CriOS/151 ones on every
// fingerprint, which is what WebKit underneath predicts: only the User-Agent
// moves between versions.
//
// The build number is measured, never derived. 151 was 151.0.7922.112 and 152
// is 152.0.7977.64, so even the patch component fell rather than rose. An
// earlier placeholder had guessed 152.0.8080.60 and a still earlier one had
// guessed 151.0.7990.44; both were wrong, which is why this asserts on a
// captured string.
func TestChrome152iOSCarriesNeitherWireChange(t *testing.T) {
	p := Get("chrome-152-ios")
	if p == nil {
		t.Fatal("chrome-152-ios not registered")
	}
	if !strings.Contains(p.UserAgent, "CriOS/152.0.7977.64") {
		t.Errorf("UA = %q, want the captured CriOS/152.0.7977.64", p.UserAgent)
	}
	if len(p.TrustAnchors) != 0 {
		t.Errorf("chrome-152-ios carries %d trust anchors; WebKit does not send "+
			"the extension at all", len(p.TrustAnchors))
	}
	for i, sa := range p.SignatureAlgorithms {
		if uint16(sa)&0x0f0f == 0x0a0a {
			t.Errorf("chrome-152-ios signature algorithm %d is the GREASE value "+
				"%#04x; that is BoringSSL behaviour and WebKit has none of it", i, sa)
		}
	}
	if chrome152SecCHUA(p) != "" {
		t.Errorf("chrome-152-ios sends sec-ch-ua = %q; WebKit sends no client hints",
			chrome152SecCHUA(p))
	}
}

// Chrome 151 must not have acquired either change, or the diff is being
// applied to the wrong preset.
func TestChrome151StillCarriesNeitherWireChange(t *testing.T) {
	for _, name := range []string{"chrome-151-windows", "chrome-151-linux", "chrome-151-android"} {
		p := Get(name)
		if p == nil {
			continue
		}
		if len(p.TrustAnchors) != 0 {
			t.Errorf("%s carries %d trust anchors; the extension arrived in 152",
				name, len(p.TrustAnchors))
		}
		if len(p.SignatureAlgorithms) != 11 {
			t.Errorf("%s has %d signature algorithms, want 11 with no GREASE",
				name, len(p.SignatureAlgorithms))
		}
	}
}

// The flag-on cohort has to stay reachable. Chrome 152 with
// features::kTlsGreaseSigalgs enabled prepends a GREASE signature algorithm,
// and a caller who wants to sit in that cohort puts 2570 (0x0a0a) back at the
// head of signature_algorithms in the preset JSON.
//
// Without this, "switchable" is a claim in a comment rather than a property of
// the code, and the next edit to the sigalg path could quietly remove the
// ability to express the other cohort at all.
func TestChrome152SigalgGreaseStaysReachable(t *testing.T) {
	const spec = `{
	  "preset": {
	    "name": "chrome-152-greased-sigalgs",
	    "based_on": "chrome-152-windows",
	    "tls": {
	      "signature_algorithms": [2570, 2308, 2309, 2310, 1027, 2052,
	                               1025, 1283, 2053, 1281, 2054, 1537]
	    }
	  }
	}`

	pf, err := LoadPresetFromJSON([]byte(spec))
	if err != nil {
		t.Fatalf("loading the flag-on variant failed: %v", err)
	}
	p, err := BuildPreset(pf.Preset)
	if err != nil {
		t.Fatalf("building the flag-on variant failed: %v", err)
	}

	if len(p.SignatureAlgorithms) != 12 {
		t.Fatalf("%d signature algorithms, want 12 (one GREASE plus eleven)",
			len(p.SignatureAlgorithms))
	}
	if got := uint16(p.SignatureAlgorithms[0]); got != 0x0a0a {
		t.Errorf("first signature algorithm is %#04x, want the 0x0a0a placeholder "+
			"that uTLS substitutes a real GREASE value for per connection", got)
	}
	for i, sa := range p.SignatureAlgorithms[1:] {
		if uint16(sa)&0x0f0f == 0x0a0a {
			t.Errorf("algorithm %d is a second GREASE value %#04x; "+
				"ext_sigalgs_add_clienthello adds exactly one", i+1, sa)
		}
	}

	// And the default really is the other cohort, so the two are distinguishable.
	base := Get("chrome-152-windows")
	if base == nil {
		t.Fatal("chrome-152-windows not registered")
	}
	if len(base.SignatureAlgorithms) == len(p.SignatureAlgorithms) {
		t.Errorf("the default and the flag-on variant both have %d signature "+
			"algorithms; the override did nothing", len(p.SignatureAlgorithms))
	}
}
