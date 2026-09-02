package fingerprint

import (
	"encoding/base64"
	"testing"

	utls "github.com/sardanioss/utls"
)

// buildRawHelloBytes produces a real ClientHello record to stand in for a
// capture. What matters is only that it arrives as bytes with no ClientHelloID
// attached, which is exactly the situation a captured hello is in.
func buildRawHelloBytes(t *testing.T) []byte {
	t.Helper()
	spec, err := utls.UTLSIdToSpecWithSeed(utls.HelloChrome_133, 1)
	if err != nil {
		t.Skipf("cannot build a reference hello: %v", err)
	}
	conn := utls.UClient(nil, &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		OmitEmptyPsk:       true,
	}, utls.HelloCustom)
	if err := conn.ApplyPreset(&spec); err != nil {
		t.Skipf("cannot apply the reference spec: %v", err)
	}
	if err := conn.BuildHandshakeState(); err != nil {
		t.Skipf("cannot build the handshake state: %v", err)
	}
	hello := conn.HandshakeState.Hello.Raw
	if len(hello) == 0 {
		t.Skip("reference hello has no marshalled bytes")
	}
	// Wrap the handshake message in a TLS record, which is what a capture is.
	rec := []byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}
	return append(rec, hello...)
}

func extIDs(t *testing.T, spec *utls.ClientHelloSpec) []uint16 {
	t.Helper()
	var out []uint16
	for _, e := range spec.Extensions {
		var id uint16
		switch v := e.(type) {
		case *utls.SNIExtension:
			id = 0
		case *utls.SupportedCurvesExtension:
			id = 10
		case *utls.SignatureAlgorithmsExtension:
			id = 13
		case *utls.ALPNExtension:
			id = 16
		case *utls.StatusRequestExtension:
			id = 5
		case *utls.SessionTicketExtension:
			id = 35
		case *utls.SupportedVersionsExtension:
			id = 43
		case *utls.KeyShareExtension:
			id = 51
		default:
			_ = v
			id = 65535
		}
		out = append(out, id)
	}
	return out
}

// A captured hello is one connection's worth of evidence, so its extension order
// must stay put unless the preset declares the client varies it. Mirroring a
// captured Chrome without this freezes an order the real client reshuffles on
// every handshake, which is a stable value where the original has none.
func TestRawHelloOrderIsFrozenByDefault(t *testing.T) {
	raw := buildRawHelloBytes(t)
	p := &Preset{RawClientHello: raw}

	first, _, err := ResolveClientHelloSpec(p, "", nil, false, 1)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, seed := range []int64{2, 3, 99, 12345} {
		got, _, err := ResolveClientHelloSpec(p, "", nil, false, seed)
		if err != nil {
			t.Fatalf("resolve seed %d: %v", seed, err)
		}
		if !sameOrder(extIDs(t, first), extIDs(t, got)) {
			t.Fatalf("seed %d changed a captured hello's extension order with "+
				"permute_raw_hello unset", seed)
		}
	}
}

// And with it declared, the order varies per connection the way Chromium's does.
func TestRawHelloPermutesWhenDeclared(t *testing.T) {
	raw := buildRawHelloBytes(t)
	p := &Preset{RawClientHello: raw, RawPermuteExtensions: true}

	seen := map[string]bool{}
	for _, seed := range []int64{1, 2, 3, 7, 99, 12345} {
		spec, _, err := ResolveClientHelloSpec(p, "", nil, false, seed)
		if err != nil {
			t.Fatalf("resolve seed %d: %v", seed, err)
		}
		seen[orderKey(extIDs(t, spec))] = true
	}
	if len(seen) < 3 {
		t.Errorf("6 seeds produced %d distinct extension orders; a declared "+
			"permuting client should vary on nearly every one", len(seen))
	}
}

// Blunt mimicry passes through extensions with no model behind them, and those
// cannot be moved safely, so it wins over the permute flag rather than the two
// combining.
func TestBluntMimicryDisablesRawPermutation(t *testing.T) {
	raw := buildRawHelloBytes(t)
	p := &Preset{RawClientHello: raw, RawPermuteExtensions: true, RawBluntMimicry: true}

	first, _, err := ResolveClientHelloSpec(p, "", nil, false, 1)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, seed := range []int64{2, 3, 99} {
		got, _, err := ResolveClientHelloSpec(p, "", nil, false, seed)
		if err != nil {
			t.Fatalf("resolve seed %d: %v", seed, err)
		}
		if !sameOrder(extIDs(t, first), extIDs(t, got)) {
			t.Fatalf("seed %d reordered a blunt-mimicry hello; extensions with no "+
				"model behind them must not be moved", seed)
		}
	}
}

func sameOrder(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func orderKey(ids []uint16) string {
	b := make([]byte, 0, len(ids)*2)
	for _, id := range ids {
		b = append(b, byte(id>>8), byte(id))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// permute_extensions is what the other two TLS modes call this, so it is the
// name someone reaches for first with a captured hello. It fed JA3Extras, which
// the raw path never consults, so it was accepted and did nothing: a preset that
// looks configured and goes on the wire unchanged, which is the exact failure
// the key exists to avoid.
func TestPermuteExtensionsWorksOnTheRawPath(t *testing.T) {
	raw := buildRawHelloBytes(t)
	b64 := base64.StdEncoding.EncodeToString(raw)

	for _, tc := range []struct {
		name  string
		extra string
		want  bool // true = order should vary
	}{
		{"neither key", "", false},
		{"permute_extensions", `,"permute_extensions":true`, true},
		{"permute_raw_hello", `,"permute_raw_hello":true`, true},
		{"both", `,"permute_extensions":true,"permute_raw_hello":true`, true},
		{"permute_raw_hello wins when they disagree", `,"permute_extensions":true,"permute_raw_hello":false`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := `{"preset":{"name":"rp-` + tc.name + `","based_on":"chrome-latest",` +
				`"tls":{"raw_client_hello":"` + b64 + `"` + tc.extra + `}}}`
			pf, err := LoadPresetFromJSON([]byte(spec))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			p, err := BuildPreset(pf.Preset)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			seen := map[string]bool{}
			for _, seed := range []int64{1, 2, 3, 7, 99} {
				s, _, err := ResolveClientHelloSpec(p, "", nil, false, seed)
				if err != nil {
					t.Fatalf("resolve: %v", err)
				}
				seen[orderKey(extIDs(t, s))] = true
			}
			varied := len(seen) > 1
			if varied != tc.want {
				t.Errorf("%d distinct orders across 5 seeds (varied=%v), want varied=%v",
					len(seen), varied, tc.want)
			}
		})
	}
}
