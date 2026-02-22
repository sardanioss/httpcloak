package fingerprint

import (
	"testing"

	tls "github.com/sardanioss/utls"
)

func TestParseJA3_ChromeLike(t *testing.T) {
	// A Chrome-like JA3 string (simplified)
	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"

	spec, err := ParseJA3(ja3, nil)
	if err != nil {
		t.Fatalf("ParseJA3 failed: %v", err)
	}

	// Verify TLS version
	if spec.TLSVersMax != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 (0x0304), got 0x%04x", spec.TLSVersMax)
	}

	// Verify cipher suites
	expectedCiphers := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}
	if len(spec.CipherSuites) != len(expectedCiphers) {
		t.Errorf("expected %d cipher suites, got %d", len(expectedCiphers), len(spec.CipherSuites))
	} else {
		for i, cs := range spec.CipherSuites {
			if cs != expectedCiphers[i] {
				t.Errorf("cipher suite %d: expected 0x%04x, got 0x%04x", i, expectedCiphers[i], cs)
			}
		}
	}

	// Verify extensions were created
	if len(spec.Extensions) == 0 {
		t.Error("expected extensions, got none")
	}

	// Verify extension count matches input
	// Input: 0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21 = 16 extensions
	if len(spec.Extensions) != 16 {
		t.Errorf("expected 16 extensions, got %d", len(spec.Extensions))
	}
}

func TestParseJA3_WithGREASE(t *testing.T) {
	// JA3 with GREASE values that should be filtered
	ja3 := "771,2570-4865-4866-4867,0-23-10-11-13-16-51-45-43,2570-29-23-24,0"

	spec, err := ParseJA3(ja3, nil)
	if err != nil {
		t.Fatalf("ParseJA3 failed: %v", err)
	}

	// GREASE cipher (2570 = 0x0A0A) should be filtered
	for _, cs := range spec.CipherSuites {
		if isGREASE(cs) {
			t.Errorf("GREASE cipher suite 0x%04x should have been filtered", cs)
		}
	}

	// Verify only 3 non-GREASE ciphers remain
	if len(spec.CipherSuites) != 3 {
		t.Errorf("expected 3 cipher suites after GREASE filtering, got %d", len(spec.CipherSuites))
	}
}

func TestParseJA3_CustomExtras(t *testing.T) {
	ja3 := "771,4865-4866,0-16-13-51-45-43,29-23,0"

	extras := &JA3Extras{
		SignatureAlgorithms: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
		},
		ALPN:            []string{"h2"},
		CertCompAlgs:    []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
		RecordSizeLimit: 0x4001,
	}

	spec, err := ParseJA3(ja3, extras)
	if err != nil {
		t.Fatalf("ParseJA3 failed: %v", err)
	}

	// Verify ALPN extension uses custom value
	found := false
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*tls.ALPNExtension); ok {
			found = true
			if len(alpn.AlpnProtocols) != 1 || alpn.AlpnProtocols[0] != "h2" {
				t.Errorf("expected ALPN [h2], got %v", alpn.AlpnProtocols)
			}
		}
	}
	if !found {
		t.Error("ALPN extension not found")
	}
}

func TestParseJA3_MalformedInput(t *testing.T) {
	tests := []struct {
		name string
		ja3  string
	}{
		{"empty", ""},
		{"too few fields", "771,4865"},
		{"too many fields", "771,4865,0,29,0,extra"},
		{"invalid version", "abc,4865,0,29,0"},
		{"invalid cipher", "771,abc,0,29,0"},
		{"invalid extension", "771,4865,abc,29,0"},
		{"invalid curve", "771,4865,0,abc,0"},
		{"invalid point format", "771,4865,0,29,abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseJA3(tt.ja3, nil)
			if err == nil {
				t.Errorf("expected error for %q, got nil", tt.ja3)
			}
		})
	}
}

func TestParseJA3_EmptyFields(t *testing.T) {
	// All fields present but some empty (valid — empty extensions, curves, etc.)
	ja3 := "771,4865,,,"

	spec, err := ParseJA3(ja3, nil)
	if err != nil {
		t.Fatalf("ParseJA3 failed: %v", err)
	}

	if len(spec.CipherSuites) != 1 {
		t.Errorf("expected 1 cipher suite, got %d", len(spec.CipherSuites))
	}
	if len(spec.Extensions) != 0 {
		t.Errorf("expected 0 extensions, got %d", len(spec.Extensions))
	}
}

func TestParseJA3_ExtensionTypes(t *testing.T) {
	// Verify specific extensions are created with correct types
	// Extensions: SNI(0), supported_groups(10), ALPN(16), supported_versions(43), key_share(51)
	ja3 := "771,4865,0-10-16-43-51,29-23,0"

	spec, err := ParseJA3(ja3, nil)
	if err != nil {
		t.Fatalf("ParseJA3 failed: %v", err)
	}

	if len(spec.Extensions) != 5 {
		t.Fatalf("expected 5 extensions, got %d", len(spec.Extensions))
	}

	// Verify each extension type
	if _, ok := spec.Extensions[0].(*tls.SNIExtension); !ok {
		t.Errorf("extension 0: expected SNIExtension, got %T", spec.Extensions[0])
	}
	if sc, ok := spec.Extensions[1].(*tls.SupportedCurvesExtension); !ok {
		t.Errorf("extension 1: expected SupportedCurvesExtension, got %T", spec.Extensions[1])
	} else {
		// Curves from JA3: 29 (X25519), 23 (P-256)
		if len(sc.Curves) != 2 {
			t.Errorf("expected 2 curves, got %d", len(sc.Curves))
		} else {
			if sc.Curves[0] != tls.X25519 {
				t.Errorf("curve 0: expected X25519 (%d), got %d", tls.X25519, sc.Curves[0])
			}
			if sc.Curves[1] != tls.CurveP256 {
				t.Errorf("curve 1: expected P256 (%d), got %d", tls.CurveP256, sc.Curves[1])
			}
		}
	}
	if alpn, ok := spec.Extensions[2].(*tls.ALPNExtension); !ok {
		t.Errorf("extension 2: expected ALPNExtension, got %T", spec.Extensions[2])
	} else {
		// Default ALPN: ["h2", "http/1.1"]
		if len(alpn.AlpnProtocols) != 2 || alpn.AlpnProtocols[0] != "h2" || alpn.AlpnProtocols[1] != "http/1.1" {
			t.Errorf("expected ALPN [h2, http/1.1], got %v", alpn.AlpnProtocols)
		}
	}
	if sv, ok := spec.Extensions[3].(*tls.SupportedVersionsExtension); !ok {
		t.Errorf("extension 3: expected SupportedVersionsExtension, got %T", spec.Extensions[3])
	} else {
		if len(sv.Versions) != 2 || sv.Versions[0] != tls.VersionTLS13 || sv.Versions[1] != tls.VersionTLS12 {
			t.Errorf("expected versions [TLS1.3, TLS1.2], got %v", sv.Versions)
		}
	}
	if ks, ok := spec.Extensions[4].(*tls.KeyShareExtension); !ok {
		t.Errorf("extension 4: expected KeyShareExtension, got %T", spec.Extensions[4])
	} else {
		// Key share only for first (preferred) non-GREASE curve, matching real browser behavior
		if len(ks.KeyShares) != 1 {
			t.Errorf("expected 1 key share (first preferred curve only), got %d", len(ks.KeyShares))
		} else if ks.KeyShares[0].Group != tls.X25519 {
			t.Errorf("key share 0: expected X25519, got %v", ks.KeyShares[0].Group)
		}
	}
}

func TestParseJA3_TLS12Only(t *testing.T) {
	// JA3 with no supported_versions extension → TLS 1.2 max
	ja3 := "771,4865-49195,0-10-11-13-16,29-23,0"

	spec, err := ParseJA3(ja3, nil)
	if err != nil {
		t.Fatalf("ParseJA3 failed: %v", err)
	}

	if spec.TLSVersMax != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 max (0x0303), got 0x%04x", spec.TLSVersMax)
	}
	if spec.TLSVersMin != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 min (0x0303), got 0x%04x", spec.TLSVersMin)
	}
}

func TestParseJA3_AllKnownExtensions(t *testing.T) {
	// Test all known extension IDs that have specific handlers
	// IDs: 0,5,10,11,13,16,17,18,21,22,23,27,28,34,35,41,43,44,45,49,50,51,57,65037,65281
	ja3 := "771,4865,0-5-10-11-13-16-17-18-21-22-23-27-28-34-35-41-43-44-45-49-50-51-57-65037-65281,29,0"

	spec, err := ParseJA3(ja3, nil)
	if err != nil {
		t.Fatalf("ParseJA3 failed: %v", err)
	}

	if len(spec.Extensions) != 25 {
		t.Errorf("expected 25 extensions, got %d", len(spec.Extensions))
	}

	// Spot-check a few specific extension types
	for _, ext := range spec.Extensions {
		switch ext.(type) {
		case *tls.SNIExtension,
			*tls.StatusRequestExtension,
			*tls.SupportedCurvesExtension,
			*tls.SupportedPointsExtension,
			*tls.SignatureAlgorithmsExtension,
			*tls.ALPNExtension,
			*tls.StatusRequestV2Extension,
			*tls.SCTExtension,
			*tls.UtlsPaddingExtension,
			*tls.UtlsExtendedMasterSecretExtension,
			*tls.UtlsCompressCertExtension,
			*tls.FakeRecordSizeLimitExtension,
			*tls.DelegatedCredentialsExtension,
			*tls.SessionTicketExtension,
			*tls.UtlsPreSharedKeyExtension,
			*tls.SupportedVersionsExtension,
			*tls.CookieExtension,
			*tls.PSKKeyExchangeModesExtension,
			*tls.SignatureAlgorithmsCertExtension,
			*tls.KeyShareExtension,
			*tls.GREASEEncryptedClientHelloExtension,
			*tls.RenegotiationInfoExtension,
			*tls.GenericExtension:
			// OK
		default:
			t.Errorf("unexpected extension type: %T", ext)
		}
	}
}

func TestParseJA3_RecordSizeLimit(t *testing.T) {
	// Test record_size_limit extension (28) with custom value
	ja3 := "771,4865,28,29,0"

	extras := &JA3Extras{
		RecordSizeLimit: 0x2000,
	}
	spec, err := ParseJA3(ja3, extras)
	if err != nil {
		t.Fatalf("ParseJA3 failed: %v", err)
	}

	if len(spec.Extensions) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(spec.Extensions))
	}
	rsl, ok := spec.Extensions[0].(*tls.FakeRecordSizeLimitExtension)
	if !ok {
		t.Fatalf("expected FakeRecordSizeLimitExtension, got %T", spec.Extensions[0])
	}
	if rsl.Limit != 0x2000 {
		t.Errorf("expected RecordSizeLimit 0x2000, got 0x%04x", rsl.Limit)
	}
}

func TestParseJA3_RecordSizeLimitDefault(t *testing.T) {
	// Test record_size_limit extension with zero → falls back to 0x4001
	ja3 := "771,4865,28,29,0"

	extras := &JA3Extras{
		RecordSizeLimit: 0, // zero = use default
	}
	spec, err := ParseJA3(ja3, extras)
	if err != nil {
		t.Fatalf("ParseJA3 failed: %v", err)
	}

	rsl, ok := spec.Extensions[0].(*tls.FakeRecordSizeLimitExtension)
	if !ok {
		t.Fatalf("expected FakeRecordSizeLimitExtension, got %T", spec.Extensions[0])
	}
	if rsl.Limit != 0x4001 {
		t.Errorf("expected default RecordSizeLimit 0x4001, got 0x%04x", rsl.Limit)
	}
}

func TestParseJA3_GREASEExtensions(t *testing.T) {
	// GREASE extension IDs should become UtlsGREASEExtension
	ja3 := "771,4865,2570-0-6682,29,0"

	spec, err := ParseJA3(ja3, nil)
	if err != nil {
		t.Fatalf("ParseJA3 failed: %v", err)
	}

	if len(spec.Extensions) != 3 {
		t.Fatalf("expected 3 extensions, got %d", len(spec.Extensions))
	}

	// 2570 (0x0A0A) and 6682 (0x1A1A) are GREASE
	if _, ok := spec.Extensions[0].(*tls.UtlsGREASEExtension); !ok {
		t.Errorf("extension 0: expected UtlsGREASEExtension for GREASE value, got %T", spec.Extensions[0])
	}
	if _, ok := spec.Extensions[1].(*tls.SNIExtension); !ok {
		t.Errorf("extension 1: expected SNIExtension, got %T", spec.Extensions[1])
	}
	if _, ok := spec.Extensions[2].(*tls.UtlsGREASEExtension); !ok {
		t.Errorf("extension 2: expected UtlsGREASEExtension for GREASE value, got %T", spec.Extensions[2])
	}
}

func TestParseJA3_PointFormats(t *testing.T) {
	// Verify point formats are passed through
	ja3 := "771,4865,11,29,0-1-2"

	spec, err := ParseJA3(ja3, nil)
	if err != nil {
		t.Fatalf("ParseJA3 failed: %v", err)
	}

	if len(spec.Extensions) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(spec.Extensions))
	}

	pf, ok := spec.Extensions[0].(*tls.SupportedPointsExtension)
	if !ok {
		t.Fatalf("expected SupportedPointsExtension, got %T", spec.Extensions[0])
	}
	if len(pf.SupportedPoints) != 3 {
		t.Errorf("expected 3 point formats, got %d", len(pf.SupportedPoints))
	} else {
		if pf.SupportedPoints[0] != 0 || pf.SupportedPoints[1] != 1 || pf.SupportedPoints[2] != 2 {
			t.Errorf("expected point formats [0,1,2], got %v", pf.SupportedPoints)
		}
	}
}

func TestParseJA3_CompressionMethods(t *testing.T) {
	// Verify compression methods always set to null compression
	ja3 := "771,4865,,,"

	spec, err := ParseJA3(ja3, nil)
	if err != nil {
		t.Fatalf("ParseJA3 failed: %v", err)
	}

	if len(spec.CompressionMethods) != 1 || spec.CompressionMethods[0] != 0 {
		t.Errorf("expected compression methods [0], got %v", spec.CompressionMethods)
	}
}

func TestIsGREASE(t *testing.T) {
	greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
		0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

	for _, v := range greaseValues {
		if !isGREASE(v) {
			t.Errorf("expected 0x%04x to be GREASE", v)
		}
	}

	nonGREASE := []uint16{0x0001, 0x1301, 0xc02b, 0x0a0b, 0x1234}
	for _, v := range nonGREASE {
		if isGREASE(v) {
			t.Errorf("expected 0x%04x to NOT be GREASE", v)
		}
	}
}

func TestParseJA3_PartialExtrasDefaultsMerging(t *testing.T) {
	ja3 := "771,4865-4866-4867,0-10-11-13-16-43-51-23-65281-35-45,29-23-24,0"

	// Create extras with only PermuteExtensions set — all other fields are zero/nil.
	// ParseJA3 should fill in defaults for the nil fields without failing.
	extras := &JA3Extras{
		PermuteExtensions: true,
	}

	spec, err := ParseJA3(ja3, extras)
	if err != nil {
		t.Fatalf("ParseJA3 with partial extras failed: %v", err)
	}

	// Verify spec was produced
	if spec == nil {
		t.Fatal("expected non-nil spec")
	}
	if len(spec.CipherSuites) != 3 {
		t.Errorf("expected 3 cipher suites, got %d", len(spec.CipherSuites))
	}

	// Verify caller's struct was NOT mutated
	if len(extras.SignatureAlgorithms) != 0 {
		t.Errorf("caller's SignatureAlgorithms was mutated: got %d entries", len(extras.SignatureAlgorithms))
	}
	if len(extras.ALPN) != 0 {
		t.Errorf("caller's ALPN was mutated: got %v", extras.ALPN)
	}
	if len(extras.CertCompAlgs) != 0 {
		t.Errorf("caller's CertCompAlgs was mutated: got %v", extras.CertCompAlgs)
	}
	if extras.RecordSizeLimit != 0 {
		t.Errorf("caller's RecordSizeLimit was mutated: got %d", extras.RecordSizeLimit)
	}

	// Verify the spec's extensions contain proper data from defaults
	// Check that ALPN extension has default protocols
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*tls.ALPNExtension); ok {
			if len(alpn.AlpnProtocols) == 0 {
				t.Error("ALPN extension has no protocols (defaults not applied)")
			}
			break
		}
	}
	// Check that signature_algorithms extension has algorithms
	for _, ext := range spec.Extensions {
		if sigAlg, ok := ext.(*tls.SignatureAlgorithmsExtension); ok {
			if len(sigAlg.SupportedSignatureAlgorithms) == 0 {
				t.Error("signature_algorithms extension is empty (defaults not applied)")
			}
			break
		}
	}
}
