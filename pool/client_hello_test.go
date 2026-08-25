package pool

import (
	"slices"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	utls "github.com/sardanioss/utls"
)

func TestTCPClientHelloSpecAppliesPresetSignatureAlgorithms(t *testing.T) {
	preset := fingerprint.GetStrict("chrome-150-windows")
	if preset == nil {
		t.Fatal("chrome-150-windows preset is unavailable")
	}

	spec, err := tcpClientHelloSpec(preset, preset.ClientHelloID, 42)
	if err != nil {
		t.Fatalf("tcpClientHelloSpec() error = %v", err)
	}
	if got := signatureAlgorithms(spec); !slices.Equal(got, preset.SignatureAlgorithms) {
		t.Fatalf("signature algorithms = %v, want %v", got, preset.SignatureAlgorithms)
	}

	manager := NewManager(preset)
	t.Cleanup(manager.Close)
	if got := signatureAlgorithms(manager.cachedSpec); !slices.Equal(got, preset.SignatureAlgorithms) {
		t.Fatalf("manager cached signature algorithms = %v, want %v", got, preset.SignatureAlgorithms)
	}
	if manager.cachedPSKSpec != nil {
		if got := signatureAlgorithms(manager.cachedPSKSpec); !slices.Equal(got, preset.SignatureAlgorithms) {
			t.Fatalf("manager cached PSK signature algorithms = %v, want %v", got, preset.SignatureAlgorithms)
		}
	}
}

func TestQUICClientHelloSpecUsesIndependentOverride(t *testing.T) {
	preset := fingerprint.GetStrict("chrome-150-windows")
	if preset == nil {
		t.Fatal("chrome-150-windows preset is unavailable")
	}
	preset.QUICSignatureAlgorithms = []utls.SignatureScheme{0x1234, 0x5678}

	spec, err := quicClientHelloSpec(preset, preset.QUICClientHelloID, 42)
	if err != nil {
		t.Fatalf("quicClientHelloSpec() error = %v", err)
	}
	if got := signatureAlgorithms(spec); !slices.Equal(got, preset.QUICSignatureAlgorithms) {
		t.Fatalf("QUIC signature algorithms = %v, want %v", got, preset.QUICSignatureAlgorithms)
	}

	manager := NewQUICManager(preset, nil)
	t.Cleanup(manager.Close)
	if got := signatureAlgorithms(manager.cachedSpec); !slices.Equal(got, preset.QUICSignatureAlgorithms) {
		t.Fatalf("QUIC manager cached signature algorithms = %v, want %v", got, preset.QUICSignatureAlgorithms)
	}
}

func signatureAlgorithms(spec *utls.ClientHelloSpec) []utls.SignatureScheme {
	if spec == nil {
		return nil
	}
	for _, extension := range spec.Extensions {
		if algorithms, ok := extension.(*utls.SignatureAlgorithmsExtension); ok {
			return algorithms.SupportedSignatureAlgorithms
		}
	}
	return nil
}

// A pooled connection carries the same trust_anchors extension as a
// transport-built one.
//
// It did not. Both helpers went through fingerprint.SpecFor, which passes no
// anchors, so a Chrome 152 profile advertised the extension through the
// transport and omitted it through the pool: one profile, two different
// ClientHellos, decided by whether the caller happened to use a pool. That is
// the drift that moved the quic.Config and the HTTP/3 SETTINGS into
// internal/h3build, in the same package pair.
func TestClientHelloSpecsCarryTrustAnchors(t *testing.T) {
	preset := fingerprint.GetStrict("chrome-152-windows")
	if preset == nil {
		t.Fatal("chrome-152-windows preset is unavailable")
	}
	if len(preset.TrustAnchors) == 0 {
		t.Fatal("chrome-152-windows carries no trust anchors, so this proves nothing")
	}
	want := len(preset.TrustAnchors)

	for _, tc := range []struct {
		name string
		spec func() (*utls.ClientHelloSpec, error)
	}{
		{"tcp", func() (*utls.ClientHelloSpec, error) {
			return tcpClientHelloSpec(preset, preset.ClientHelloID, 42)
		}},
		{"quic", func() (*utls.ClientHelloSpec, error) {
			return quicClientHelloSpec(preset, preset.QUICClientHelloID, 42)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := tc.spec()
			if err != nil {
				t.Fatalf("building the spec: %v", err)
			}
			got := trustAnchorCount(spec)
			if got != want {
				t.Fatalf("the pooled %s spec carries %d trust anchors, want %d; "+
					"a pooled connection would advertise a different ClientHello "+
					"than a transport-built one for the same profile",
					tc.name, got, want)
			}
		})
	}

	// And the cached specs the managers hold, which is what a pooled
	// connection actually hands to uTLS.
	m := NewManager(preset)
	t.Cleanup(m.Close)
	if got := trustAnchorCount(m.cachedSpec); got != want {
		t.Errorf("the TCP manager's cached spec carries %d trust anchors, want %d", got, want)
	}
	q := NewQUICManager(preset, nil)
	t.Cleanup(q.Close)
	if got := trustAnchorCount(q.cachedSpec); got != want {
		t.Errorf("the QUIC manager's cached spec carries %d trust anchors, want %d", got, want)
	}
}

// A profile that sets none does not acquire the extension from the pool.
func TestPoolLeavesTrustAnchorsAloneWhenUnset(t *testing.T) {
	preset := fingerprint.GetStrict("chrome-151-windows")
	if preset == nil {
		t.Fatal("chrome-151-windows preset is unavailable")
	}
	spec, err := quicClientHelloSpec(preset, preset.QUICClientHelloID, 42)
	if err != nil {
		t.Fatalf("building the spec: %v", err)
	}
	if n := trustAnchorCount(spec); n != 0 {
		t.Fatalf("chrome-151 acquired %d trust anchors; the extension arrived in 152", n)
	}
}

func trustAnchorCount(spec *utls.ClientHelloSpec) int {
	if spec == nil {
		return -1
	}
	for _, extension := range spec.Extensions {
		if ta, ok := extension.(*utls.TrustAnchorsExtension); ok {
			return len(ta.TrustAnchors)
		}
	}
	return 0
}
