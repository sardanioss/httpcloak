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
