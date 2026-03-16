package fingerprint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	tls "github.com/sardanioss/utls"
)

// --- Registry Tests ---

func TestRegistryRegisterAndLookup(t *testing.T) {
	p := &Preset{Name: "test-custom"}
	Register("test-custom", p)
	defer Unregister("test-custom")

	got := LookupCustom("test-custom")
	if got == nil {
		t.Fatal("expected preset, got nil")
	}
	if got.Name != "test-custom" {
		t.Fatalf("expected name test-custom, got %s", got.Name)
	}
}

func TestRegistryUnregister(t *testing.T) {
	Register("test-unreg", &Preset{Name: "test-unreg"})
	Unregister("test-unreg")

	if got := LookupCustom("test-unreg"); got != nil {
		t.Fatal("expected nil after unregister")
	}
}

func TestRegistryLookupNotFound(t *testing.T) {
	if got := LookupCustom("nonexistent-xyz-123"); got != nil {
		t.Fatal("expected nil for nonexistent key")
	}
}

func TestGetChecksRegistryFirst(t *testing.T) {
	p := &Preset{Name: "custom-override", UserAgent: "CustomUA/1.0"}
	Register("custom-override", p)
	defer Unregister("custom-override")

	got := Get("custom-override")
	if got.UserAgent != "CustomUA/1.0" {
		t.Fatalf("expected custom UA, got %s", got.UserAgent)
	}
}

func TestGetFallsBackToBuiltin(t *testing.T) {
	got := Get("chrome-146-windows")
	if got == nil {
		t.Fatal("expected chrome-146-windows preset")
	}
	if got.Name != "chrome-146-windows" {
		t.Fatalf("expected chrome-146-windows, got %s", got.Name)
	}
}

// --- ClientHelloID Resolution Tests ---

func TestResolveClientHelloID(t *testing.T) {
	tests := []string{
		"chrome-146-windows",
		"chrome-146-linux",
		"chrome-146-macos",
		"chrome-146-quic",
		"chrome-146-windows-psk",
		"firefox-120",
		"safari-18",
		"ios-18",
		"ios-18-quic",
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			id, err := ResolveClientHelloID(name)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id.Client == "" {
				t.Fatal("resolved ID has empty Client")
			}
		})
	}
}

func TestResolveClientHelloIDUnknown(t *testing.T) {
	_, err := ResolveClientHelloID("nonexistent-browser-999")
	if err == nil {
		t.Fatal("expected error for unknown ID")
	}
}

// --- BuildPreset Tests ---

func TestBuildPresetBasedOn(t *testing.T) {
	spec := &PresetSpec{
		Name:    "my-chrome",
		BasedOn: "chrome-146-windows",
		Headers: &HeaderSpec{
			UserAgent: "MyCustomUA/1.0",
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "my-chrome" {
		t.Fatalf("expected name my-chrome, got %s", p.Name)
	}
	if p.UserAgent != "MyCustomUA/1.0" {
		t.Fatalf("expected custom UA, got %s", p.UserAgent)
	}
	// Should inherit ClientHelloID from base
	base := Get("chrome-146-windows")
	if p.ClientHelloID != base.ClientHelloID {
		t.Fatal("expected inherited ClientHelloID from base")
	}
}

func TestBuildPresetUnknownBasedOnError(t *testing.T) {
	spec := &PresetSpec{
		Name:    "bad",
		BasedOn: "nonexistent-browser-999",
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for unknown based_on")
	}
}

func TestBuildPresetNilSpec(t *testing.T) {
	_, err := BuildPreset(nil)
	if err == nil {
		t.Fatal("expected error for nil spec")
	}
}

func TestGetStrictReturnsNil(t *testing.T) {
	if got := GetStrict("nonexistent-xyz-999"); got != nil {
		t.Fatal("expected nil for unknown name")
	}
}

func TestGetStrictFindsBuiltin(t *testing.T) {
	got := GetStrict("chrome-146-windows")
	if got == nil {
		t.Fatal("expected preset")
	}
	if got.Name != "chrome-146-windows" {
		t.Fatalf("expected chrome-146-windows, got %s", got.Name)
	}
}

func TestGetStrictFindsCustom(t *testing.T) {
	Register("strict-test", &Preset{Name: "strict-test"})
	defer Unregister("strict-test")

	got := GetStrict("strict-test")
	if got == nil {
		t.Fatal("expected custom preset")
	}
	if got.Name != "strict-test" {
		t.Fatalf("expected strict-test, got %s", got.Name)
	}
}

func TestRegisterNilIgnored(t *testing.T) {
	Register("nil-test", nil)
	if got := LookupCustom("nil-test"); got != nil {
		t.Fatal("expected nil preset to not be stored")
	}
}

func TestBuildPresetWithJA3(t *testing.T) {
	spec := &PresetSpec{
		Name: "ja3-test",
		TLS: &TLSSpec{
			JA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.JA3 != spec.TLS.JA3 {
		t.Fatal("JA3 string not stored on preset")
	}
}

func TestBuildPresetJA3AndClientHelloMutuallyExclusive(t *testing.T) {
	spec := &PresetSpec{
		Name: "conflict",
		TLS: &TLSSpec{
			JA3:         "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0",
			ClientHello: "chrome-146-windows",
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for ja3+client_hello conflict")
	}
}

func TestBuildPresetWithClientHello(t *testing.T) {
	spec := &PresetSpec{
		Name: "ch-test",
		TLS: &TLSSpec{
			ClientHello:     "chrome-146-windows",
			PSKClientHello:  "chrome-146-windows-psk",
			QUICClientHello: "chrome-146-quic",
			QUICPSKClientHello: "chrome-146-quic-psk",
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ClientHelloID.Client == "" {
		t.Fatal("ClientHelloID not set")
	}
	if p.PSKClientHelloID.Client == "" {
		t.Fatal("PSKClientHelloID not set")
	}
	if p.QUICClientHelloID.Client == "" {
		t.Fatal("QUICClientHelloID not set")
	}
	if p.QUICPSKClientHelloID.Client == "" {
		t.Fatal("QUICPSKClientHelloID not set")
	}
}

func TestBuildPresetWithAkamai(t *testing.T) {
	spec := &PresetSpec{
		Name: "akamai-test",
		HTTP2: &HTTP2Spec{
			Akamai: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.HTTP2Settings.HeaderTableSize != 65536 {
		t.Fatalf("expected HeaderTableSize 65536, got %d", p.HTTP2Settings.HeaderTableSize)
	}
	if p.HTTP2Settings.InitialWindowSize != 6291456 {
		t.Fatalf("expected InitialWindowSize 6291456, got %d", p.HTTP2Settings.InitialWindowSize)
	}
	if p.HTTP2Settings.ConnectionWindowUpdate != 15663105 {
		t.Fatalf("expected ConnectionWindowUpdate 15663105, got %d", p.HTTP2Settings.ConnectionWindowUpdate)
	}
}

func TestBuildPresetAkamaiWithOverlay(t *testing.T) {
	maxFrame := uint32(32768)
	spec := &PresetSpec{
		Name: "akamai-overlay",
		HTTP2: &HTTP2Spec{
			Akamai:       "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
			MaxFrameSize: &maxFrame,
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Akamai sets HeaderTableSize=65536
	if p.HTTP2Settings.HeaderTableSize != 65536 {
		t.Fatalf("expected HeaderTableSize 65536, got %d", p.HTTP2Settings.HeaderTableSize)
	}
	// Individual field overlays
	if p.HTTP2Settings.MaxFrameSize != 32768 {
		t.Fatalf("expected MaxFrameSize 32768, got %d", p.HTTP2Settings.MaxFrameSize)
	}
}

func TestBuildPresetWithTCPPlatform(t *testing.T) {
	spec := &PresetSpec{
		Name: "tcp-test",
		TCP: &TCPSpec{
			Platform: "Windows",
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.TCPFingerprint.TTL != 128 {
		t.Fatalf("expected TTL 128 for Windows, got %d", p.TCPFingerprint.TTL)
	}
	if p.TCPFingerprint.WindowSize != 64240 {
		t.Fatalf("expected WindowSize 64240, got %d", p.TCPFingerprint.WindowSize)
	}
}

func TestBuildPresetTCPPlatformWithOverride(t *testing.T) {
	ttl := 100
	spec := &PresetSpec{
		Name: "tcp-override",
		TCP: &TCPSpec{
			Platform: "Windows",
			TTL:      &ttl,
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Platform sets base values
	if p.TCPFingerprint.WindowSize != 64240 {
		t.Fatalf("expected WindowSize 64240, got %d", p.TCPFingerprint.WindowSize)
	}
	// Individual field overrides
	if p.TCPFingerprint.TTL != 100 {
		t.Fatalf("expected TTL 100 (override), got %d", p.TCPFingerprint.TTL)
	}
}

func TestBuildPresetBasedOnInheritance(t *testing.T) {
	// Only override user-agent, inherit everything else
	spec := &PresetSpec{
		Name:    "override-ua-only",
		BasedOn: "chrome-146-windows",
		Headers: &HeaderSpec{
			UserAgent: "OverriddenUA/2.0",
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	base := Get("chrome-146-windows")

	// UA should be overridden
	if p.UserAgent != "OverriddenUA/2.0" {
		t.Fatalf("expected overridden UA, got %s", p.UserAgent)
	}
	// HTTP2Settings should be inherited
	if p.HTTP2Settings.HeaderTableSize != base.HTTP2Settings.HeaderTableSize {
		t.Fatal("HTTP2Settings.HeaderTableSize not inherited")
	}
	if p.SupportHTTP3 != base.SupportHTTP3 {
		t.Fatal("SupportHTTP3 not inherited")
	}
}

func TestBuildPresetValidationHPACKPolicy(t *testing.T) {
	bad := "invalid-policy"
	spec := &PresetSpec{
		Name: "bad-hpack",
		HTTP2: &HTTP2Spec{
			HPACKIndexingPolicy: &bad,
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for invalid HPACK policy")
	}
}

func TestBuildPresetValidationStreamPriorityMode(t *testing.T) {
	bad := "invalid-mode"
	spec := &PresetSpec{
		Name: "bad-priority",
		HTTP2: &HTTP2Spec{
			StreamPriorityMode: &bad,
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for invalid stream priority mode")
	}
}

func TestBuildPresetValidationQUICTransportOrder(t *testing.T) {
	bad := "invalid-order"
	spec := &PresetSpec{
		Name: "bad-quic-order",
		HTTP3: &HTTP3Spec{
			QUICTransportParamOrder: &bad,
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for invalid QUIC transport param order")
	}
}

func TestBuildPresetHTTP3Config(t *testing.T) {
	cap := uint64(32768)
	blocked := uint64(50)
	spec := &PresetSpec{
		Name: "h3-test",
		HTTP3: &HTTP3Spec{
			QPACKMaxTableCapacity: &cap,
			QPACKBlockedStreams:   &blocked,
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.H3Config == nil {
		t.Fatal("expected H3Config to be set")
	}
	if *p.H3Config.QPACKMaxTableCapacity != 32768 {
		t.Fatalf("expected QPACKMaxTableCapacity 32768, got %d", *p.H3Config.QPACKMaxTableCapacity)
	}
	if *p.H3Config.QPACKBlockedStreams != 50 {
		t.Fatalf("expected QPACKBlockedStreams 50, got %d", *p.H3Config.QPACKBlockedStreams)
	}
}

func TestBuildPresetProtocol(t *testing.T) {
	h3 := true
	spec := &PresetSpec{
		Name: "proto-test",
		Protocol: &ProtocolSpec{
			HTTP3: &h3,
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !p.SupportHTTP3 {
		t.Fatal("expected SupportHTTP3 true")
	}
}

func TestBuildPresetJA3WithExtras(t *testing.T) {
	permute := true
	rsl := uint16(0x4001)
	spec := &PresetSpec{
		Name: "ja3-extras",
		TLS: &TLSSpec{
			JA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
			JA3ExtrasSpec: &JA3ExtrasSpec{
				ALPN:              []string{"h2", "http/1.1"},
				CertCompression:   []string{"brotli"},
				PermuteExtensions: &permute,
				RecordSizeLimit:   &rsl,
			},
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.JA3Extras == nil {
		t.Fatal("expected JA3Extras to be set")
	}
	if !p.JA3Extras.PermuteExtensions {
		t.Fatal("expected PermuteExtensions true")
	}
	if p.JA3Extras.RecordSizeLimit != 0x4001 {
		t.Fatalf("expected RSL 0x4001, got 0x%x", p.JA3Extras.RecordSizeLimit)
	}
}

func TestBuildPresetHeaders(t *testing.T) {
	spec := &PresetSpec{
		Name: "headers-test",
		Headers: &HeaderSpec{
			UserAgent: "TestUA/1.0",
			Values: map[string]string{
				"sec-ch-ua":          `"Chromium";v="146"`,
				"sec-ch-ua-platform": `"Windows"`,
			},
			Order: []HeaderPairSpec{
				{Key: ":method", Value: "GET"},
				{Key: ":authority", Value: ""},
				{Key: ":scheme", Value: "https"},
				{Key: ":path", Value: "/"},
			},
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.UserAgent != "TestUA/1.0" {
		t.Fatalf("expected TestUA/1.0, got %s", p.UserAgent)
	}
	if p.Headers["sec-ch-ua"] != `"Chromium";v="146"` {
		t.Fatal("header value not set correctly")
	}
	if len(p.HeaderOrder) != 4 {
		t.Fatalf("expected 4 header pairs, got %d", len(p.HeaderOrder))
	}
}

func TestBuildPresetHTTP2StructuredSettings(t *testing.T) {
	spec := &PresetSpec{
		Name: "settings-list",
		HTTP2: &HTTP2Spec{
			Settings: []HTTP2SettingSpec{
				{ID: 1, Value: 65536},
				{ID: 4, Value: 6291456},
				{ID: 8, Value: 1},
			},
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.HTTP2Settings.HeaderTableSize != 65536 {
		t.Fatalf("expected 65536, got %d", p.HTTP2Settings.HeaderTableSize)
	}
	if p.HTTP2Settings.InitialWindowSize != 6291456 {
		t.Fatalf("expected 6291456, got %d", p.HTTP2Settings.InitialWindowSize)
	}
	if !p.HTTP2Settings.NoRFC7540Priorities {
		t.Fatal("expected NoRFC7540Priorities true")
	}
}

// --- Clone Tests ---

func TestClonePresetDeepCopy(t *testing.T) {
	src := Get("chrome-146-windows")
	dst := clonePreset(src)

	// Modify dst, verify src unchanged
	dst.Name = "modified"
	dst.UserAgent = "Modified/1.0"
	if src.Name == "modified" {
		t.Fatal("clone modified source Name")
	}
	if src.UserAgent == "Modified/1.0" {
		t.Fatal("clone modified source UserAgent")
	}
}

func TestClonePresetDeepCopyHeaders(t *testing.T) {
	src := &Preset{
		Name:      "src",
		Headers:   map[string]string{"a": "1", "b": "2"},
		HeaderOrder: []HeaderPair{{Key: "x", Value: "y"}},
	}
	dst := clonePreset(src)

	dst.Headers["a"] = "modified"
	if src.Headers["a"] == "modified" {
		t.Fatal("clone modified source Headers map")
	}

	dst.HeaderOrder[0].Key = "modified"
	if src.HeaderOrder[0].Key == "modified" {
		t.Fatal("clone modified source HeaderOrder slice")
	}
}

func TestClonePresetDeepCopyH2Config(t *testing.T) {
	disableSplit := true
	src := &Preset{
		Name: "src",
		H2Config: &H2FingerprintConfig{
			HPACKHeaderOrder:    []string{"a", "b"},
			HPACKIndexingPolicy: "chrome",
			DisableCookieSplit:  &disableSplit,
		},
	}
	dst := clonePreset(src)

	dst.H2Config.HPACKHeaderOrder[0] = "modified"
	if src.H2Config.HPACKHeaderOrder[0] == "modified" {
		t.Fatal("clone modified source H2Config.HPACKHeaderOrder")
	}

	*dst.H2Config.DisableCookieSplit = false
	if !*src.H2Config.DisableCookieSplit {
		t.Fatal("clone modified source H2Config.DisableCookieSplit")
	}
}

// --- Mutual Exclusion Tests ---

func TestApplyTLSJA3ClearsClientHelloID(t *testing.T) {
	// Start from a Chrome preset with ClientHelloID set, then overlay JA3
	spec := &PresetSpec{
		Name:    "ja3-override",
		BasedOn: "chrome-146-windows",
		TLS: &TLSSpec{
			JA3: "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0",
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.JA3 == "" {
		t.Fatal("expected JA3 to be set")
	}
	// All ClientHelloID fields should be cleared
	if p.ClientHelloID.Client != "" {
		t.Fatal("expected ClientHelloID to be cleared")
	}
	if p.PSKClientHelloID.Client != "" {
		t.Fatal("expected PSKClientHelloID to be cleared")
	}
	if p.QUICClientHelloID.Client != "" {
		t.Fatal("expected QUICClientHelloID to be cleared")
	}
	if p.QUICPSKClientHelloID.Client != "" {
		t.Fatal("expected QUICPSKClientHelloID to be cleared")
	}
}

func TestApplyTLSClientHelloClearsJA3(t *testing.T) {
	// Create a preset with JA3, register it, then build another based on it with ClientHello
	ja3Preset := &Preset{
		Name:      "ja3-base",
		JA3:       "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0",
		JA3Extras: &JA3Extras{ALPN: []string{"h2"}},
	}
	Register("ja3-base", ja3Preset)
	defer Unregister("ja3-base")

	spec := &PresetSpec{
		Name:    "ch-override",
		BasedOn: "ja3-base",
		TLS: &TLSSpec{
			ClientHello: "chrome-146-windows",
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.JA3 != "" {
		t.Fatalf("expected JA3 to be cleared, got %s", p.JA3)
	}
	if p.JA3Extras != nil {
		t.Fatal("expected JA3Extras to be cleared")
	}
	if p.ClientHelloID.Client == "" {
		t.Fatal("expected ClientHelloID to be set")
	}
}

// --- Validation Hardening Tests ---

func TestParseCertCompAlgsAll3(t *testing.T) {
	spec := &PresetSpec{
		Name: "certcomp-all",
		TLS: &TLSSpec{
			JA3: "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0",
			JA3ExtrasSpec: &JA3ExtrasSpec{
				CertCompression: []string{"brotli", "zlib", "zstd"},
			},
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.JA3Extras.CertCompAlgs) != 3 {
		t.Fatalf("expected 3 cert comp algs, got %d", len(p.JA3Extras.CertCompAlgs))
	}
}

func TestParseCertCompAlgsUnknownError(t *testing.T) {
	spec := &PresetSpec{
		Name: "certcomp-bad",
		TLS: &TLSSpec{
			JA3: "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0",
			JA3ExtrasSpec: &JA3ExtrasSpec{
				CertCompression: []string{"brotli", "lz4"},
			},
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for unknown cert compression 'lz4'")
	}
}

func TestApplyTCPUnknownPlatformError(t *testing.T) {
	spec := &PresetSpec{
		Name: "tcp-bad",
		TCP: &TCPSpec{
			Platform: "FreeBSD",
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for unknown platform 'FreeBSD'")
	}
}

func TestApplyTCPAllValidPlatforms(t *testing.T) {
	for _, platform := range []string{"Windows", "macOS", "Linux"} {
		t.Run(platform, func(t *testing.T) {
			spec := &PresetSpec{
				Name: "tcp-" + platform,
				TCP:  &TCPSpec{Platform: platform},
			}
			p, err := BuildPreset(spec)
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", platform, err)
			}
			if p.TCPFingerprint.TTL == 0 {
				t.Fatalf("expected non-zero TTL for %s", platform)
			}
		})
	}
}

func TestBuildPresetPSKWithoutClientHelloError(t *testing.T) {
	spec := &PresetSpec{
		Name: "psk-no-ch",
		TLS: &TLSSpec{
			PSKClientHello: "chrome-146-windows-psk",
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for PSK without client_hello")
	}
}

func TestBuildPresetQUICWithoutClientHelloError(t *testing.T) {
	spec := &PresetSpec{
		Name: "quic-no-ch",
		TLS: &TLSSpec{
			QUICClientHello: "chrome-146-quic",
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for QUIC without client_hello")
	}
}

func TestBuildPresetCertCompFromTopLevelTLS(t *testing.T) {
	spec := &PresetSpec{
		Name: "top-level-extras",
		TLS: &TLSSpec{
			JA3:             "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0",
			SignatureAlgorithms: []uint16{1027, 2052},
			ALPN:            []string{"h2", "http/1.1"},
			CertCompression: []string{"brotli"},
			RecordSizeLimit: ptrUint16(0x4001),
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.JA3Extras == nil {
		t.Fatal("expected JA3Extras from top-level TLS fields")
	}
	if len(p.JA3Extras.SignatureAlgorithms) != 2 {
		t.Fatalf("expected 2 sig algs, got %d", len(p.JA3Extras.SignatureAlgorithms))
	}
	if len(p.JA3Extras.ALPN) != 2 {
		t.Fatalf("expected 2 ALPN, got %d", len(p.JA3Extras.ALPN))
	}
	if len(p.JA3Extras.CertCompAlgs) != 1 {
		t.Fatalf("expected 1 cert comp alg, got %d", len(p.JA3Extras.CertCompAlgs))
	}
	if p.JA3Extras.RecordSizeLimit != 0x4001 {
		t.Fatalf("expected RSL 0x4001, got 0x%x", p.JA3Extras.RecordSizeLimit)
	}
}

func TestBuildPresetCertCompTopLevelUnknownError(t *testing.T) {
	spec := &PresetSpec{
		Name: "top-level-bad",
		TLS: &TLSSpec{
			JA3:             "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0",
			CertCompression: []string{"invalid"},
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for unknown cert compression in top-level TLS")
	}
}

func ptrUint16(v uint16) *uint16 { return &v }

// --- JSON Load Tests ---

func TestLoadPresetFromJSON(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"preset": {
			"name": "json-test",
			"based_on": "chrome-146-windows",
			"headers": {
				"user_agent": "JsonUA/1.0"
			}
		}
	}`)

	pf, err := LoadPresetFromJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pf.Preset == nil {
		t.Fatal("expected preset in file")
	}
	if pf.Preset.Name != "json-test" {
		t.Fatalf("expected name json-test, got %s", pf.Preset.Name)
	}
}

func TestLoadAndBuildPresetFromJSON(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"preset": {
			"name": "load-build-test",
			"based_on": "chrome-146-windows",
			"headers": {
				"user_agent": "LoadBuild/1.0"
			}
		}
	}`)

	p, err := LoadAndBuildPresetFromJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "load-build-test" {
		t.Fatalf("expected name load-build-test, got %s", p.Name)
	}
	if p.UserAgent != "LoadBuild/1.0" {
		t.Fatalf("expected LoadBuild/1.0, got %s", p.UserAgent)
	}
}

func TestLoadPresetFromFile(t *testing.T) {
	data := `{
		"version": 1,
		"preset": {
			"name": "file-test",
			"based_on": "chrome-146-windows",
			"headers": { "user_agent": "FileTest/1.0" }
		}
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	p, err := LoadAndBuildPreset(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "file-test" {
		t.Fatalf("expected file-test, got %s", p.Name)
	}
}

func TestLoadPresetFromFileNotFound(t *testing.T) {
	_, err := LoadPresetFromFile("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadPresetFromJSONInvalid(t *testing.T) {
	_, err := LoadPresetFromJSON([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- PresetPool Tests ---

func TestPresetPoolRandom(t *testing.T) {
	presets := []*Preset{
		{Name: "p1"},
		{Name: "p2"},
		{Name: "p3"},
	}
	pool := NewPresetPool("test-pool", PoolRandom, presets)

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		p := pool.Random()
		seen[p.Name] = true
	}
	// With 100 tries, we should have seen all 3
	if len(seen) != 3 {
		t.Fatalf("expected 3 distinct presets, saw %d", len(seen))
	}
}

func TestPresetPoolRoundRobin(t *testing.T) {
	presets := []*Preset{
		{Name: "rr1"},
		{Name: "rr2"},
		{Name: "rr3"},
	}
	pool := NewPresetPool("test-rr", PoolRoundRobin, presets)

	expected := []string{"rr1", "rr2", "rr3", "rr1", "rr2", "rr3"}
	for i, exp := range expected {
		got := pool.Next()
		if got.Name != exp {
			t.Fatalf("iteration %d: expected %s, got %s", i, exp, got.Name)
		}
	}
}

func TestPresetPoolGet(t *testing.T) {
	presets := []*Preset{
		{Name: "g0"},
		{Name: "g1"},
	}
	pool := NewPresetPool("test-get", PoolRandom, presets)

	if pool.Get(0).Name != "g0" {
		t.Fatal("Get(0) wrong")
	}
	if pool.Get(1).Name != "g1" {
		t.Fatal("Get(1) wrong")
	}
}

func TestPresetPoolSize(t *testing.T) {
	pool := NewPresetPool("test-size", PoolRandom, []*Preset{{}, {}, {}})
	if pool.Size() != 3 {
		t.Fatalf("expected size 3, got %d", pool.Size())
	}
}

func TestPresetPoolName(t *testing.T) {
	pool := NewPresetPool("my-pool", PoolRandom, []*Preset{{}})
	if pool.Name() != "my-pool" {
		t.Fatalf("expected my-pool, got %s", pool.Name())
	}
}

func TestPresetPoolClose(t *testing.T) {
	p := &Preset{Name: "close-test-preset"}
	Register("close-test-preset", p)
	pool := NewPresetPool("close-pool", PoolRandom, []*Preset{p})

	pool.Close()

	if got := LookupCustom("close-test-preset"); got != nil {
		t.Fatal("expected preset to be unregistered after Close")
	}
}

func TestPresetPoolFromJSON(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"pool": {
			"name": "json-pool",
			"strategy": "round-robin",
			"presets": [
				{
					"name": "pool-p1",
					"based_on": "chrome-146-windows",
					"headers": { "user_agent": "Pool1/1.0" }
				},
				{
					"name": "pool-p2",
					"based_on": "chrome-146-linux",
					"headers": { "user_agent": "Pool2/1.0" }
				}
			]
		}
	}`)

	pool, err := NewPresetPoolFromJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer pool.Close()

	if pool.Size() != 2 {
		t.Fatalf("expected 2 presets, got %d", pool.Size())
	}
	if pool.Name() != "json-pool" {
		t.Fatalf("expected json-pool, got %s", pool.Name())
	}

	// Check auto-registration
	if got := LookupCustom("pool-p1"); got == nil {
		t.Fatal("pool-p1 not auto-registered")
	}
	if got := LookupCustom("pool-p2"); got == nil {
		t.Fatal("pool-p2 not auto-registered")
	}

	// Round-robin
	first := pool.Next()
	second := pool.Next()
	if first.Name == second.Name {
		t.Fatal("round-robin returned same preset twice")
	}
}

func TestPresetPoolFromJSONSinglePreset(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"preset": {
			"name": "single-pool-test",
			"based_on": "chrome-146-windows"
		}
	}`)

	pool, err := NewPresetPoolFromJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer pool.Close()

	if pool.Size() != 1 {
		t.Fatalf("expected 1 preset, got %d", pool.Size())
	}
}

func TestPresetPoolEmptyError(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"pool": {
			"name": "empty-pool",
			"strategy": "random",
			"presets": []
		}
	}`)

	_, err := NewPresetPoolFromJSON(data)
	if err == nil {
		t.Fatal("expected error for empty pool")
	}
}

func TestPresetPoolFromFile(t *testing.T) {
	data := `{
		"version": 1,
		"pool": {
			"name": "file-pool",
			"strategy": "random",
			"presets": [
				{ "name": "fp1", "based_on": "chrome-146-windows" },
				{ "name": "fp2", "based_on": "chrome-146-linux" }
			]
		}
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "pool.json")
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	pool, err := NewPresetPoolFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer pool.Close()

	if pool.Size() != 2 {
		t.Fatalf("expected 2, got %d", pool.Size())
	}
}

// --- Pool Hardening Tests ---

func TestNewPresetPoolEmptyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty presets")
		}
	}()
	NewPresetPool("empty", PoolRandom, []*Preset{})
}

func TestPresetPoolNextOverflow(t *testing.T) {
	presets := []*Preset{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	pool := NewPresetPool("overflow", PoolRoundRobin, presets)

	// Set counter near int64 max to test overflow
	pool.index.Store(9223372036854775805) // MaxInt64 - 2

	// These 5 calls cross the int64 overflow boundary
	for i := 0; i < 5; i++ {
		p := pool.Next()
		if p == nil {
			t.Fatalf("got nil on call %d after overflow", i)
		}
	}
}

func TestPresetPoolPick(t *testing.T) {
	presets := []*Preset{{Name: "p1"}, {Name: "p2"}, {Name: "p3"}}

	// Round-robin Pick
	rrPool := NewPresetPool("rr", PoolRoundRobin, presets)
	first := rrPool.Pick()
	second := rrPool.Pick()
	if first.Name == second.Name {
		t.Fatal("round-robin Pick returned same preset twice")
	}

	// Random Pick (just verify it doesn't panic)
	randPool := NewPresetPool("rand", PoolRandom, presets)
	for i := 0; i < 50; i++ {
		if randPool.Pick() == nil {
			t.Fatal("Pick returned nil")
		}
	}
}

func TestBuildPoolSinglePresetEmptyName(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"preset": {
			"name": ""
		}
	}`)
	pool, err := NewPresetPoolFromJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer pool.Close()

	// Empty name should not be registered
	if got := LookupCustom(""); got != nil {
		t.Fatal("empty name should not be registered")
	}
}

func TestBuildPoolPartialFailureNoRegistration(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"pool": {
			"name": "partial-fail",
			"strategy": "random",
			"presets": [
				{ "name": "partial-ok", "based_on": "chrome-146-windows" },
				{ "name": "partial-bad", "based_on": "nonexistent-999" }
			]
		}
	}`)
	_, err := NewPresetPoolFromJSON(data)
	if err == nil {
		t.Fatal("expected error for bad based_on")
	}
	// Preset 0 should NOT be registered since preset 1 failed
	if got := LookupCustom("partial-ok"); got != nil {
		t.Fatal("preset should not be registered after partial failure")
	}
}

func TestPresetPoolFromJSONUnknownStrategy(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"pool": {
			"name": "bad-strategy",
			"strategy": "shuffle",
			"presets": [
				{ "name": "s1", "based_on": "chrome-146-windows" }
			]
		}
	}`)
	_, err := NewPresetPoolFromJSON(data)
	if err == nil {
		t.Fatal("expected error for unknown strategy")
	}
}

func TestPresetPoolFromJSONNoField(t *testing.T) {
	data := []byte(`{"version": 1}`)
	_, err := NewPresetPoolFromJSON(data)
	if err == nil {
		t.Fatal("expected error when neither preset nor pool set")
	}
}

// --- Thread Safety Tests ---

func TestPresetPoolConcurrentRandom(t *testing.T) {
	presets := make([]*Preset, 10)
	for i := range presets {
		presets[i] = &Preset{Name: "concurrent-" + string(rune('a'+i))}
	}
	pool := NewPresetPool("concurrent-pool", PoolRandom, presets)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				p := pool.Random()
				if p == nil {
					t.Error("got nil preset")
				}
			}
		}()
	}
	wg.Wait()
}

func TestPresetPoolConcurrentNext(t *testing.T) {
	presets := make([]*Preset, 5)
	for i := range presets {
		presets[i] = &Preset{Name: "rr-concurrent"}
	}
	pool := NewPresetPool("concurrent-rr", PoolRoundRobin, presets)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				p := pool.Next()
				if p == nil {
					t.Error("got nil preset")
				}
			}
		}()
	}
	wg.Wait()
}

func TestRegistryConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		name := "concurrent-reg-" + string(rune('a'+i%26))
		go func() {
			defer wg.Done()
			Register(name, &Preset{Name: name})
		}()
		go func() {
			defer wg.Done()
			LookupCustom(name)
		}()
	}
	wg.Wait()
	// Cleanup
	for i := 0; i < 26; i++ {
		Unregister("concurrent-reg-" + string(rune('a'+i)))
	}
}

// --- JSON Round-Trip Test ---

func TestPresetSpecJSONRoundTrip(t *testing.T) {
	hpackPolicy := "chrome"
	streamPrio := "default"
	h3 := true
	permute := true
	rsl := uint16(0x4001)
	cap := uint64(32768)

	original := PresetFile{
		Version: 1,
		Preset: &PresetSpec{
			Name:    "roundtrip-test",
			BasedOn: "chrome-146-windows",
			TLS: &TLSSpec{
				JA3: "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0",
				JA3ExtrasSpec: &JA3ExtrasSpec{
					ALPN:              []string{"h2", "http/1.1"},
					CertCompression:   []string{"brotli"},
					PermuteExtensions: &permute,
					RecordSizeLimit:   &rsl,
				},
			},
			HTTP2: &HTTP2Spec{
				Akamai:              "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
				HPACKIndexingPolicy: &hpackPolicy,
				StreamPriorityMode:  &streamPrio,
			},
			HTTP3: &HTTP3Spec{
				QPACKMaxTableCapacity: &cap,
			},
			Headers: &HeaderSpec{
				UserAgent: "RoundTrip/1.0",
			},
			TCP: &TCPSpec{
				Platform: "Windows",
			},
			Protocol: &ProtocolSpec{
				HTTP3: &h3,
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded PresetFile
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Preset.Name != "roundtrip-test" {
		t.Fatalf("name mismatch: %s", decoded.Preset.Name)
	}
	if decoded.Preset.TLS.JA3 != original.Preset.TLS.JA3 {
		t.Fatal("JA3 mismatch")
	}
	if decoded.Preset.Headers.UserAgent != "RoundTrip/1.0" {
		t.Fatal("UserAgent mismatch")
	}
}

// --- Coverage Gap Tests ---

func ptrUint64(v uint64) *uint64 { return &v }
func ptrInt64(v int64) *int64    { return &v }
func ptrBool(v bool) *bool       { return &v }
func ptrString(v string) *string { return &v }

func TestClonePresetH3ConfigDeepCopy(t *testing.T) {
	src := &Preset{
		Name: "h3-clone-src",
		H3Config: &H3FingerprintConfig{
			QPACKMaxTableCapacity:    ptrUint64(32768),
			QPACKBlockedStreams:      ptrUint64(50),
			MaxFieldSectionSize:      ptrUint64(262144),
			EnableDatagrams:          ptrBool(true),
			QUICInitialPacketSize:    ptrUint16(1250),
			QUICMaxIncomingStreams:    ptrInt64(100),
			QUICMaxIncomingUniStreams: ptrInt64(103),
			QUICAllow0RTT:            ptrBool(true),
			QUICChromeStyleInitial:   ptrBool(true),
			QUICDisableHelloScramble: ptrBool(false),
			QUICTransportParamOrder:  "chrome",
			MaxResponseHeaderBytes:   ptrUint64(262144),
			SendGreaseFrames:         ptrBool(true),
		},
	}
	dst := clonePreset(src)

	// Mutate every pointer field in dst
	*dst.H3Config.QPACKMaxTableCapacity = 99999
	*dst.H3Config.QPACKBlockedStreams = 99999
	*dst.H3Config.MaxFieldSectionSize = 99999
	*dst.H3Config.EnableDatagrams = false
	*dst.H3Config.QUICInitialPacketSize = 9999
	*dst.H3Config.QUICMaxIncomingStreams = 99999
	*dst.H3Config.QUICMaxIncomingUniStreams = 99999
	*dst.H3Config.QUICAllow0RTT = false
	*dst.H3Config.QUICChromeStyleInitial = false
	*dst.H3Config.QUICDisableHelloScramble = true
	*dst.H3Config.MaxResponseHeaderBytes = 99999
	*dst.H3Config.SendGreaseFrames = false

	// Verify src is unchanged
	if *src.H3Config.QPACKMaxTableCapacity != 32768 {
		t.Fatal("src QPACKMaxTableCapacity mutated by clone")
	}
	if *src.H3Config.EnableDatagrams != true {
		t.Fatal("src EnableDatagrams mutated by clone")
	}
	if *src.H3Config.QUICAllow0RTT != true {
		t.Fatal("src QUICAllow0RTT mutated by clone")
	}
	if *src.H3Config.SendGreaseFrames != true {
		t.Fatal("src SendGreaseFrames mutated by clone")
	}
}

func TestClonePresetJA3ExtrasDeepCopy(t *testing.T) {
	src := &Preset{
		Name: "ja3-clone-src",
		JA3:  "771,4865,0-23,29,0",
		JA3Extras: &JA3Extras{
			SignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
			ALPN:                []string{"h2", "http/1.1"},
			CertCompAlgs:        []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
			PermuteExtensions:   true,
			RecordSizeLimit:     0x4001,
		},
	}
	dst := clonePreset(src)

	// Mutate dst
	dst.JA3Extras.SignatureAlgorithms[0] = 0
	dst.JA3Extras.ALPN[0] = "modified"
	dst.JA3Extras.CertCompAlgs[0] = 0

	// Verify src unchanged
	if src.JA3Extras.SignatureAlgorithms[0] != tls.ECDSAWithP256AndSHA256 {
		t.Fatal("src SignatureAlgorithms mutated by clone")
	}
	if src.JA3Extras.ALPN[0] != "h2" {
		t.Fatal("src ALPN mutated by clone")
	}
	if src.JA3Extras.CertCompAlgs[0] != tls.CertCompressionBrotli {
		t.Fatal("src CertCompAlgs mutated by clone")
	}
}

func TestClonePresetNilFields(t *testing.T) {
	src := &Preset{Name: "nil-clone"}
	dst := clonePreset(src)
	if dst.H2Config != nil || dst.H3Config != nil || dst.JA3Extras != nil || dst.Headers != nil {
		t.Fatal("expected nil fields to remain nil after clone")
	}
}

func TestApplyHTTP3AllFields(t *testing.T) {
	order := "random"
	spec := &PresetSpec{
		Name: "h3-all",
		HTTP3: &HTTP3Spec{
			QPACKMaxTableCapacity:    ptrUint64(32768),
			QPACKBlockedStreams:      ptrUint64(50),
			MaxFieldSectionSize:      ptrUint64(262144),
			EnableDatagrams:          ptrBool(true),
			QUICInitialPacketSize:    ptrUint16(1350),
			QUICMaxIncomingStreams:    ptrInt64(200),
			QUICMaxIncomingUniStreams: ptrInt64(103),
			QUICAllow0RTT:            ptrBool(false),
			QUICChromeStyleInitial:   ptrBool(false),
			QUICDisableHelloScramble: ptrBool(true),
			QUICTransportParamOrder:  &order,
			MaxResponseHeaderBytes:   ptrUint64(131072),
			SendGreaseFrames:         ptrBool(false),
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h3 := p.H3Config
	if h3 == nil {
		t.Fatal("expected H3Config")
	}
	if *h3.QPACKMaxTableCapacity != 32768 {
		t.Fatalf("QPACKMaxTableCapacity: got %d", *h3.QPACKMaxTableCapacity)
	}
	if *h3.QPACKBlockedStreams != 50 {
		t.Fatalf("QPACKBlockedStreams: got %d", *h3.QPACKBlockedStreams)
	}
	if *h3.MaxFieldSectionSize != 262144 {
		t.Fatalf("MaxFieldSectionSize: got %d", *h3.MaxFieldSectionSize)
	}
	if !*h3.EnableDatagrams {
		t.Fatal("EnableDatagrams: expected true")
	}
	if *h3.QUICInitialPacketSize != 1350 {
		t.Fatalf("QUICInitialPacketSize: got %d", *h3.QUICInitialPacketSize)
	}
	if *h3.QUICMaxIncomingStreams != 200 {
		t.Fatalf("QUICMaxIncomingStreams: got %d", *h3.QUICMaxIncomingStreams)
	}
	if *h3.QUICMaxIncomingUniStreams != 103 {
		t.Fatalf("QUICMaxIncomingUniStreams: got %d", *h3.QUICMaxIncomingUniStreams)
	}
	if *h3.QUICAllow0RTT {
		t.Fatal("QUICAllow0RTT: expected false")
	}
	if *h3.QUICChromeStyleInitial {
		t.Fatal("QUICChromeStyleInitial: expected false")
	}
	if !*h3.QUICDisableHelloScramble {
		t.Fatal("QUICDisableHelloScramble: expected true")
	}
	if h3.QUICTransportParamOrder != "random" {
		t.Fatalf("QUICTransportParamOrder: got %s", h3.QUICTransportParamOrder)
	}
	if *h3.MaxResponseHeaderBytes != 131072 {
		t.Fatalf("MaxResponseHeaderBytes: got %d", *h3.MaxResponseHeaderBytes)
	}
	if *h3.SendGreaseFrames {
		t.Fatal("SendGreaseFrames: expected false")
	}
}

func TestApplyHTTP3PointerIsolation(t *testing.T) {
	cap := uint64(32768)
	spec := &PresetSpec{
		Name:  "h3-isolation",
		HTTP3: &HTTP3Spec{QPACKMaxTableCapacity: &cap},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Mutate the spec's pointer — preset should be unaffected
	cap = 99999
	if *p.H3Config.QPACKMaxTableCapacity != 32768 {
		t.Fatal("preset H3Config mutated via spec pointer")
	}
}

func TestApplyHTTP2H2ConfigFields(t *testing.T) {
	policy := "never"
	mode := "default"
	split := false
	spec := &PresetSpec{
		Name: "h2-config-all",
		HTTP2: &HTTP2Spec{
			SettingsOrder:       []uint16{1, 4, 6},
			PseudoOrder:         []string{":method", ":path", ":authority", ":scheme"},
			HPACKHeaderOrder:    []string{"content-type", "accept"},
			HPACKIndexingPolicy: &policy,
			HPACKNeverIndex:     []string{"cookie", "authorization"},
			StreamPriorityMode:  &mode,
			DisableCookieSplit:  &split,
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2 := p.H2Config
	if h2 == nil {
		t.Fatal("expected H2Config")
	}
	if len(h2.SettingsOrder) != 3 {
		t.Fatalf("SettingsOrder: got %d", len(h2.SettingsOrder))
	}
	if len(h2.PseudoHeaderOrder) != 4 {
		t.Fatalf("PseudoHeaderOrder: got %d", len(h2.PseudoHeaderOrder))
	}
	if len(h2.HPACKHeaderOrder) != 2 {
		t.Fatalf("HPACKHeaderOrder: got %d", len(h2.HPACKHeaderOrder))
	}
	if h2.HPACKIndexingPolicy != "never" {
		t.Fatalf("HPACKIndexingPolicy: got %s", h2.HPACKIndexingPolicy)
	}
	if len(h2.HPACKNeverIndex) != 2 {
		t.Fatalf("HPACKNeverIndex: got %d", len(h2.HPACKNeverIndex))
	}
	if h2.StreamPriorityMode != "default" {
		t.Fatalf("StreamPriorityMode: got %s", h2.StreamPriorityMode)
	}
	if *h2.DisableCookieSplit != false {
		t.Fatal("DisableCookieSplit: expected false")
	}
}

func TestApplyHTTP2SliceIsolation(t *testing.T) {
	order := []string{":method", ":path"}
	spec := &PresetSpec{
		Name:  "h2-isolation",
		HTTP2: &HTTP2Spec{PseudoOrder: order},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Mutate the spec slice — preset should be unaffected
	order[0] = "modified"
	if p.H2Config.PseudoHeaderOrder[0] != ":method" {
		t.Fatal("preset H2Config mutated via spec slice")
	}
}

func TestApplyTCPIndividualFields(t *testing.T) {
	mss := 1400
	ws := 32768
	wscale := 10
	df := false
	spec := &PresetSpec{
		Name: "tcp-fields",
		TCP: &TCPSpec{
			MSS:         &mss,
			WindowSize:  &ws,
			WindowScale: &wscale,
			DFBit:       &df,
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.TCPFingerprint.MSS != 1400 {
		t.Fatalf("MSS: got %d", p.TCPFingerprint.MSS)
	}
	if p.TCPFingerprint.WindowSize != 32768 {
		t.Fatalf("WindowSize: got %d", p.TCPFingerprint.WindowSize)
	}
	if p.TCPFingerprint.WindowScale != 10 {
		t.Fatalf("WindowScale: got %d", p.TCPFingerprint.WindowScale)
	}
	if p.TCPFingerprint.DFBit != false {
		t.Fatal("DFBit: expected false")
	}
}

func TestLoadAndBuildPresetNoPresetField(t *testing.T) {
	data := []byte(`{"version": 1, "pool": {"name":"x","presets":[{"name":"y","based_on":"chrome-146-windows"}]}}`)
	_, err := LoadAndBuildPresetFromJSON(data)
	if err == nil {
		t.Fatal("expected error when preset field is missing")
	}
}

func TestLoadAndBuildPresetFromFileNoPresetField(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/no_preset.json"
	os.WriteFile(path, []byte(`{"version": 1}`), 0644)
	_, err := LoadAndBuildPreset(path)
	if err == nil {
		t.Fatal("expected error when preset field is missing")
	}
}

func TestBuildPresetEmptySpec(t *testing.T) {
	p, err := BuildPreset(&PresetSpec{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil preset")
	}
}

func TestBuildPresetHTTP2SettingsAllIDs(t *testing.T) {
	spec := &PresetSpec{
		Name: "settings-all-ids",
		HTTP2: &HTTP2Spec{
			Settings: []HTTP2SettingSpec{
				{ID: 1, Value: 4096},
				{ID: 2, Value: 1},
				{ID: 3, Value: 100},
				{ID: 4, Value: 65535},
				{ID: 5, Value: 16384},
				{ID: 6, Value: 8192},
				{ID: 8, Value: 1},
			},
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.HTTP2Settings.HeaderTableSize != 4096 {
		t.Fatalf("ID 1: got %d", p.HTTP2Settings.HeaderTableSize)
	}
	if !p.HTTP2Settings.EnablePush {
		t.Fatal("ID 2: expected true")
	}
	if p.HTTP2Settings.MaxConcurrentStreams != 100 {
		t.Fatalf("ID 3: got %d", p.HTTP2Settings.MaxConcurrentStreams)
	}
	if p.HTTP2Settings.InitialWindowSize != 65535 {
		t.Fatalf("ID 4: got %d", p.HTTP2Settings.InitialWindowSize)
	}
	if p.HTTP2Settings.MaxFrameSize != 16384 {
		t.Fatalf("ID 5: got %d", p.HTTP2Settings.MaxFrameSize)
	}
	if p.HTTP2Settings.MaxHeaderListSize != 8192 {
		t.Fatalf("ID 6: got %d", p.HTTP2Settings.MaxHeaderListSize)
	}
	if !p.HTTP2Settings.NoRFC7540Priorities {
		t.Fatal("ID 8: expected true")
	}
}

func TestBuildPresetHTTP2EnablePushIndividual(t *testing.T) {
	push := true
	spec := &PresetSpec{
		Name:  "push-test",
		HTTP2: &HTTP2Spec{EnablePush: &push},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !p.HTTP2Settings.EnablePush {
		t.Fatal("expected EnablePush true")
	}
}

// --- 100% Coverage Gap Tests ---

func TestLoadAndBuildPresetFileReadError(t *testing.T) {
	_, err := LoadAndBuildPreset("/nonexistent/path/preset.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadAndBuildPresetFromJSONParseError(t *testing.T) {
	_, err := LoadAndBuildPresetFromJSON([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestBuildPresetHTTP2AkamaiParseError(t *testing.T) {
	spec := &PresetSpec{
		Name:  "bad-akamai",
		HTTP2: &HTTP2Spec{Akamai: "invalid|bad"},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for invalid akamai string")
	}
}

func TestClonePresetH2ConfigAllSlices(t *testing.T) {
	disableSplit := true
	src := &Preset{
		Name: "h2-full-clone",
		H2Config: &H2FingerprintConfig{
			HPACKHeaderOrder:    []string{"a", "b"},
			HPACKIndexingPolicy: "chrome",
			HPACKNeverIndex:     []string{"cookie", "auth"},
			StreamPriorityMode:  "default",
			DisableCookieSplit:  &disableSplit,
			SettingsOrder:       []uint16{1, 4, 6},
			PseudoHeaderOrder:   []string{":method", ":path"},
		},
	}
	dst := clonePreset(src)

	// Mutate every slice/pointer in dst
	dst.H2Config.HPACKNeverIndex[0] = "modified"
	dst.H2Config.SettingsOrder[0] = 999
	dst.H2Config.PseudoHeaderOrder[0] = "modified"

	// Verify src unchanged
	if src.H2Config.HPACKNeverIndex[0] != "cookie" {
		t.Fatal("src HPACKNeverIndex mutated")
	}
	if src.H2Config.SettingsOrder[0] != 1 {
		t.Fatal("src SettingsOrder mutated")
	}
	if src.H2Config.PseudoHeaderOrder[0] != ":method" {
		t.Fatal("src PseudoHeaderOrder mutated")
	}
}

func TestApplyTLSInvalidPSKClientHello(t *testing.T) {
	spec := &PresetSpec{
		Name: "bad-psk",
		TLS: &TLSSpec{
			ClientHello:    "chrome-146-windows",
			PSKClientHello: "nonexistent-psk-999",
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for invalid PSK client hello")
	}
}

func TestApplyTLSInvalidQUICClientHello(t *testing.T) {
	spec := &PresetSpec{
		Name: "bad-quic",
		TLS: &TLSSpec{
			ClientHello:     "chrome-146-windows",
			QUICClientHello: "nonexistent-quic-999",
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for invalid QUIC client hello")
	}
}

func TestApplyTLSInvalidQUICPSKClientHello(t *testing.T) {
	spec := &PresetSpec{
		Name: "bad-quic-psk",
		TLS: &TLSSpec{
			ClientHello:        "chrome-146-windows",
			QUICPSKClientHello: "nonexistent-quic-psk-999",
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for invalid QUIC PSK client hello")
	}
}

func TestApplyTLSInvalidClientHello(t *testing.T) {
	spec := &PresetSpec{
		Name: "bad-ch",
		TLS: &TLSSpec{
			ClientHello: "nonexistent-browser-999",
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for invalid client hello")
	}
}

func TestBuildJA3ExtrasFromTLSPermuteAndRSL(t *testing.T) {
	permute := true
	rsl := uint16(0x4001)
	spec := &PresetSpec{
		Name: "permute-rsl",
		TLS: &TLSSpec{
			JA3:               "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0",
			PermuteExtensions: &permute,
			RecordSizeLimit:   &rsl,
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.JA3Extras == nil {
		t.Fatal("expected JA3Extras")
	}
	if !p.JA3Extras.PermuteExtensions {
		t.Fatal("expected PermuteExtensions true")
	}
	if p.JA3Extras.RecordSizeLimit != 0x4001 {
		t.Fatalf("expected RSL 0x4001, got 0x%x", p.JA3Extras.RecordSizeLimit)
	}
}

func TestApplyHTTP2IndividualFieldsFull(t *testing.T) {
	maxConc := uint32(200)
	maxHL := uint32(16384)
	noRFC := true
	connWU := uint32(12345678)
	sw := uint16(128)
	se := true
	spec := &PresetSpec{
		Name: "h2-all-individual",
		HTTP2: &HTTP2Spec{
			MaxConcurrentStreams:  &maxConc,
			MaxHeaderListSize:    &maxHL,
			NoRFC7540Priorities:  &noRFC,
			ConnectionWindowUpdate: &connWU,
			StreamWeight:         &sw,
			StreamExclusive:      &se,
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.HTTP2Settings.MaxConcurrentStreams != 200 {
		t.Fatalf("MaxConcurrentStreams: got %d", p.HTTP2Settings.MaxConcurrentStreams)
	}
	if p.HTTP2Settings.MaxHeaderListSize != 16384 {
		t.Fatalf("MaxHeaderListSize: got %d", p.HTTP2Settings.MaxHeaderListSize)
	}
	if !p.HTTP2Settings.NoRFC7540Priorities {
		t.Fatal("NoRFC7540Priorities: expected true")
	}
	if p.HTTP2Settings.ConnectionWindowUpdate != 12345678 {
		t.Fatalf("ConnectionWindowUpdate: got %d", p.HTTP2Settings.ConnectionWindowUpdate)
	}
	if p.HTTP2Settings.StreamWeight != 128 {
		t.Fatalf("StreamWeight: got %d", p.HTTP2Settings.StreamWeight)
	}
	if !p.HTTP2Settings.StreamExclusive {
		t.Fatal("StreamExclusive: expected true")
	}
}

func TestValidatePresetQUICPSKWithoutClientHello(t *testing.T) {
	spec := &PresetSpec{
		Name: "quic-psk-no-ch",
		TLS: &TLSSpec{
			QUICPSKClientHello: "chrome-146-quic-psk",
		},
	}
	_, err := BuildPreset(spec)
	if err == nil {
		t.Fatal("expected error for QUIC PSK without client_hello")
	}
}

func TestPresetPoolFromFileError(t *testing.T) {
	_, err := NewPresetPoolFromFile("/nonexistent/pool.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestPresetPoolFromJSONError(t *testing.T) {
	_, err := NewPresetPoolFromJSON([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestBuildPoolPoolBuildError(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"pool": {
			"name": "build-fail",
			"presets": [
				{ "name": "fail-preset", "based_on": "nonexistent-xyz" }
			]
		}
	}`)
	_, err := NewPresetPoolFromJSON(data)
	if err == nil {
		t.Fatal("expected error for pool with bad preset")
	}
}

func TestPresetPoolSinglePresetRandom(t *testing.T) {
	pool := NewPresetPool("single", PoolRandom, []*Preset{{Name: "only"}})
	for i := 0; i < 10; i++ {
		if pool.Random().Name != "only" {
			t.Fatal("single-preset Random returned wrong preset")
		}
	}
}

func TestBuildPoolSinglePresetBuildError(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"preset": {
			"name": "single-fail",
			"based_on": "nonexistent-xyz-999"
		}
	}`)
	_, err := NewPresetPoolFromJSON(data)
	if err == nil {
		t.Fatal("expected error for single preset with bad based_on")
	}
}

func TestPresetPoolSinglePresetNext(t *testing.T) {
	pool := NewPresetPool("single", PoolRoundRobin, []*Preset{{Name: "only"}})
	for i := 0; i < 10; i++ {
		if pool.Next().Name != "only" {
			t.Fatal("single-preset Next returned wrong preset")
		}
	}
}
