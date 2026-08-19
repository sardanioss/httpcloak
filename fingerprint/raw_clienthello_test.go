package fingerprint

import (
	"encoding/base64"
	"strings"
	"testing"

	utls "github.com/sardanioss/utls"
)

// Real captured ClientHello records, kept here rather than as fixture files so
// the lock cannot silently pass because a fixture went missing.
//
// chrome carries GREASE: one cipher and two extensions, the extensions first
// and last in the list. That is the whole reason raw hellos exist. JA3 cannot
// express GREASE, so a hello mirrored through tls.ja3 emits none, and because
// JA4 and JA3N both ignore GREASE every reflector reports an exact match while
// the wire disagrees.
//
// curl is the blunt-mimicry case: uTLS rejects it with "unsupported extension
// 22" unless allow_blunt_mimicry is set.
const rawChromeHello = "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"

const rawCurlHello = "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"

func mustDecode(t *testing.T, b64 string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("fixture is not valid base64: %v", err)
	}
	return raw
}

func greaseCounts(spec *utls.ClientHelloSpec) (ciphers, exts int, first, last bool) {
	for _, c := range spec.CipherSuites {
		if c&0x0f0f == 0x0a0a && byte(c>>8) == byte(c) {
			ciphers++
		}
	}
	for i, x := range spec.Extensions {
		if _, is := x.(*utls.UtlsGREASEExtension); is {
			exts++
			if i == 0 {
				first = true
			}
			if i == len(spec.Extensions)-1 {
				last = true
			}
		}
	}
	return
}

// The assertion that catches a regression: position, not just count.
func TestRawClientHelloPreservesGREASEInPosition(t *testing.T) {
	spec, err := SpecFromRawClientHello(mustDecode(t, rawChromeHello), false)
	if err != nil {
		t.Fatalf("chrome hello did not round-trip: %v", err)
	}
	ciphers, exts, first, last := greaseCounts(spec)
	if ciphers != 1 {
		t.Errorf("GREASE ciphers = %d, want 1", ciphers)
	}
	if exts != 2 {
		t.Errorf("GREASE extensions = %d, want 2", exts)
	}
	if !first || !last {
		t.Errorf("GREASE extensions must sit first and last, got first=%v last=%v", first, last)
	}
	if len(spec.CipherSuites) != 16 || len(spec.Extensions) != 18 {
		t.Errorf("shape drifted: %d ciphers, %d extensions, want 16 and 18",
			len(spec.CipherSuites), len(spec.Extensions))
	}
}

// C3: an unusable capture must be named at load time, not surface later as a
// handshake failure with no mention of the preset.
func TestRawClientHelloValidationIsNamedAtLoadTime(t *testing.T) {
	if _, err := DecodeRawClientHello("tls.raw_client_hello", rawCurlHello, false); err == nil {
		t.Fatal("curl hello loaded without blunt mimicry; uTLS rejects extension 22")
	} else {
		if !strings.Contains(err.Error(), "allow_blunt_mimicry") {
			t.Errorf("error %q does not name the option that fixes it", err)
		}
	}
	if _, err := DecodeRawClientHello("tls.raw_client_hello", rawCurlHello, true); err != nil {
		t.Errorf("curl hello must load with blunt mimicry: %v", err)
	}
	for _, tc := range []struct{ name, in, want string }{
		{"not base64", "!!!!", "not valid base64"},
		{"not a TLS record", base64.StdEncoding.EncodeToString([]byte("hello there")), "does not look like a TLS record"},
	} {
		if _, err := DecodeRawClientHello("tls.raw_client_hello", tc.in, false); err == nil {
			t.Errorf("%s: loaded without error", tc.name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q, want it to mention %q", tc.name, err, tc.want)
		}
	}
}

// C12. The old inline chain in each transport opened with
// `if ja3String != ""`, taken unconditionally, so the PSK arm below it could
// never run for a JA3 preset no matter what the preset asked for. The resolver
// has to honour the PSK variant of whichever source wins, for every source.
func TestResolverHonoursThePSKVariantOfEverySource(t *testing.T) {
	chrome := mustDecode(t, rawChromeHello)
	curl := mustDecode(t, rawCurlHello)

	// Distinguishable by shape: chrome is 16 ciphers, curl is 30.
	p := &Preset{RawClientHello: chrome, RawPSKClientHello: curl, RawBluntMimicry: true}
	spec, src, err := ResolveClientHelloSpec(p, "", nil, true, 0)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if src != SourceRaw {
		t.Fatalf("source = %v, want raw", src)
	}
	if len(spec.CipherSuites) != 30 {
		t.Errorf("wantPSK did not select raw_psk_client_hello: got %d ciphers, want 30",
			len(spec.CipherSuites))
	}
	// And without wantPSK it must go back to the primary capture.
	spec, _, err = ResolveClientHelloSpec(p, "", nil, false, 0)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(spec.CipherSuites) != 16 {
		t.Errorf("non-PSK resolve returned %d ciphers, want the primary capture's 16",
			len(spec.CipherSuites))
	}
}

// C11. hasPSKSpec used to be derived by asking whether the JA3 string carried
// extension 41. Only a JA3 captured mid-resumption ever does, and a first
// capture never is, so a JA3 preset reported "no PSK" forever.
func TestHasPSKVariantAsksThePresetNotTheString(t *testing.T) {
	chrome := mustDecode(t, rawChromeHello)
	for _, tc := range []struct {
		name string
		p    *Preset
		want bool
	}{
		{"raw with a resumption capture", &Preset{RawClientHello: chrome, RawPSKClientHello: chrome}, true},
		{"raw without one", &Preset{RawClientHello: chrome}, false},
		{"ja3 with psk_ja3", &Preset{JA3: "771,4865,0-23,29,0", PSKJA3: "771,4865,0-23-41,29,0"}, true},
		{"ja3 without psk_ja3", &Preset{JA3: "771,4865,0-23,29,0"}, false},
	} {
		if got := HasPSKVariant(tc.p, ""); got != tc.want {
			t.Errorf("%s: HasPSKVariant = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Precedence has to be explicit, because "which source wins" was previously
// spelled out twice in two transports and drifted between them.
func TestClientHelloSourcePrecedence(t *testing.T) {
	chrome := mustDecode(t, rawChromeHello)
	both := &Preset{RawClientHello: chrome, JA3: "771,4865,0,29,0"}
	if got := ClientHelloSourceOf(both, ""); got != SourceRaw {
		t.Errorf("raw must outrank a preset ja3, got %v", got)
	}
	if got := ClientHelloSourceOf(both, "771,4865,0,29,0"); got != SourceJA3 {
		t.Errorf("a caller-supplied ja3 must outrank everything, got %v", got)
	}
}
