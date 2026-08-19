package httpcloak

import (
	"strings"
	"testing"

	tls "github.com/sardanioss/utls"
)

// The name table cannot keep up with TLS codepoints, and a mirroring library
// has to reproduce whatever a real client sent. A caller asking for ML-DSA
// used to get an empty list and a Chrome 146 signature_algorithms extension,
// because unknown names were silently dropped.
func TestSignatureAlgorithmsAcceptNamesAndCodepoints(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want []tls.SignatureScheme
	}{
		{[]string{"ecdsa_secp256r1_sha256"}, []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}},
		// Chrome 150+ post-quantum, previously unspellable through this API.
		{[]string{"mldsa44", "mldsa65", "mldsa87"}, []tls.SignatureScheme{0x0904, 0x0905, 0x0906}},
		// Present in real captures, previously missing from the table.
		{[]string{"rsa_pkcs1_sha1", "ed25519"}, []tls.SignatureScheme{0x0201, 0x0807}},
		// Raw codepoints, either spelling, so a new algorithm never needs a
		// code change here.
		{[]string{"0x0904", "2308"}, []tls.SignatureScheme{0x0904, 0x0904}},
	} {
		got, err := parseSignatureAlgorithmsStrict(tc.in)
		if err != nil {
			t.Errorf("%v: %v", tc.in, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("%v: got %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%v: got %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}

// Silently dropping is the worst failure mode here: the request succeeds, the
// extension is short, and nothing says why.
func TestUnknownSignatureAlgorithmIsAnError(t *testing.T) {
	_, err := parseSignatureAlgorithmsStrict([]string{"ecdsa_secp256r1_sha256", "not_a_real_alg"})
	if err == nil {
		t.Fatal("unknown algorithm accepted silently")
	}
	if !strings.Contains(err.Error(), "not_a_real_alg") {
		t.Errorf("error %q does not name the offending value", err)
	}
	if !strings.Contains(err.Error(), "codepoint") {
		t.Errorf("error %q does not mention the codepoint escape hatch", err)
	}
}

// JA3Extras carries seven fields. Three of them had no route in from this API,
// so a Firefox mirror could not set record_size_limit and a client offering
// two key shares could not say so.
func TestCustomFingerprintReachesAllJA3Extras(t *testing.T) {
	cfg := &sessionConfig{}
	WithCustomFingerprint(CustomFingerprint{
		JA3:                           "771,4865,0-23,29,0",
		SignatureAlgorithms:           []string{"mldsa44"},
		DelegatedCredentialAlgorithms: []string{"ecdsa_secp256r1_sha256"},
		RecordSizeLimit:               0x1234,
		KeyShareCurves:                2,
	})(cfg)

	if cfg.configErr != nil {
		t.Fatalf("unexpected config error: %v", cfg.configErr)
	}
	e := cfg.customJA3Extras
	if e == nil {
		t.Fatal("no JA3Extras built")
	}
	if len(e.SignatureAlgorithms) != 1 || e.SignatureAlgorithms[0] != 0x0904 {
		t.Errorf("SignatureAlgorithms = %v, want [0x0904]", e.SignatureAlgorithms)
	}
	if len(e.DelegatedCredentialAlgorithms) != 1 {
		t.Errorf("DelegatedCredentialAlgorithms = %v, want one entry", e.DelegatedCredentialAlgorithms)
	}
	if e.RecordSizeLimit != 0x1234 {
		t.Errorf("RecordSizeLimit = %#x, want 0x1234", e.RecordSizeLimit)
	}
	if e.KeyShareCurves != 2 {
		t.Errorf("KeyShareCurves = %d, want 2", e.KeyShareCurves)
	}
}

// An unset RecordSizeLimit must keep the Chrome default rather than becoming
// zero, which would drop the extension entirely.
func TestRecordSizeLimitDefaultsWhenUnset(t *testing.T) {
	cfg := &sessionConfig{}
	WithCustomFingerprint(CustomFingerprint{JA3: "771,4865,0-23,29,0"})(cfg)
	if cfg.customJA3Extras.RecordSizeLimit != 0x4001 {
		t.Errorf("RecordSizeLimit = %#x, want the Chrome default 0x4001",
			cfg.customJA3Extras.RecordSizeLimit)
	}
}
