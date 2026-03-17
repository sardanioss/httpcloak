package fingerprint

import (
	"reflect"
	"testing"
)

func TestAvailableWithInfo(t *testing.T) {
	info := AvailableWithInfo()

	// Must have all presets
	allPresets := Available()
	if len(info) != len(allPresets) {
		t.Fatalf("AvailableWithInfo returned %d presets, Available() returned %d", len(info), len(allPresets))
	}

	// Every preset from Available() must be in AvailableWithInfo()
	for _, name := range allPresets {
		if _, ok := info[name]; !ok {
			t.Errorf("preset %q missing from AvailableWithInfo()", name)
		}
	}

	// Every preset must have at least h1 and h2
	for name, pi := range info {
		if len(pi.Protocols) < 2 {
			t.Errorf("preset %q has %d protocols, expected at least 2", name, len(pi.Protocols))
		}
		hasH1 := false
		hasH2 := false
		for _, p := range pi.Protocols {
			if p == "h1" {
				hasH1 = true
			}
			if p == "h2" {
				hasH2 = true
			}
		}
		if !hasH1 {
			t.Errorf("preset %q missing h1", name)
		}
		if !hasH2 {
			t.Errorf("preset %q missing h2", name)
		}
	}

	// Known H3-supported presets must have h3
	h3Presets := []string{
		"chrome-143", "chrome-143-windows", "chrome-143-linux", "chrome-143-macos",
		"chrome-144", "chrome-144-windows", "chrome-144-linux", "chrome-144-macos",
		"chrome-145", "chrome-145-windows", "chrome-145-linux", "chrome-145-macos",
		"chrome-146", "chrome-146-windows", "chrome-146-linux", "chrome-146-macos",
		"safari-18", "chrome-143-ios", "chrome-144-ios", "chrome-145-ios", "chrome-146-ios",
		"safari-18-ios", "chrome-143-android", "chrome-144-android", "chrome-145-android", "chrome-146-android",
	}
	for _, name := range h3Presets {
		pi, ok := info[name]
		if !ok {
			t.Errorf("expected H3 preset %q not found", name)
			continue
		}
		hasH3 := false
		for _, p := range pi.Protocols {
			if p == "h3" {
				hasH3 = true
			}
		}
		if !hasH3 {
			t.Errorf("preset %q should support h3 but doesn't", name)
		}
	}

	// Known non-H3 presets must NOT have h3
	noH3Presets := []string{"chrome-133", "chrome-141", "firefox-133", "safari-17-ios"}
	for _, name := range noH3Presets {
		pi, ok := info[name]
		if !ok {
			t.Errorf("expected non-H3 preset %q not found", name)
			continue
		}
		for _, p := range pi.Protocols {
			if p == "h3" {
				t.Errorf("preset %q should NOT support h3 but does", name)
			}
		}
	}
}

// --- H2 Getter Tests ---

func boolPtr(v bool) *bool       { return &v }
func uint64Ptr(v uint64) *uint64  { return &v }
func uint16Ptr(v uint16) *uint16  { return &v }
func int64Ptr(v int64) *int64     { return &v }

func TestH2HeaderOrderDefault(t *testing.T) {
	p := Chrome146()
	order := p.H2HeaderOrder()
	if len(order) != 19 {
		t.Fatalf("expected 19 headers in Chrome default order, got %d", len(order))
	}
	if order[0] != "cache-control" {
		t.Fatalf("expected first header 'cache-control', got %q", order[0])
	}
}

func TestH2HeaderOrderCustom(t *testing.T) {
	p := Chrome146()
	p.H2Config = &H2FingerprintConfig{
		HPACKHeaderOrder: []string{"accept", "user-agent"},
	}
	order := p.H2HeaderOrder()
	if !reflect.DeepEqual(order, []string{"accept", "user-agent"}) {
		t.Fatalf("expected custom order, got %v", order)
	}
}

func TestH2HPACKIndexingPolicyDefault(t *testing.T) {
	p := Chrome146()
	if p.H2HPACKIndexingPolicy() != "chrome" {
		t.Fatalf("expected 'chrome', got %q", p.H2HPACKIndexingPolicy())
	}
}

func TestH2HPACKIndexingPolicyCustom(t *testing.T) {
	p := Chrome146()
	p.H2Config = &H2FingerprintConfig{HPACKIndexingPolicy: "never"}
	if p.H2HPACKIndexingPolicy() != "never" {
		t.Fatalf("expected 'never', got %q", p.H2HPACKIndexingPolicy())
	}
}

func TestH2HPACKNeverIndexDefault(t *testing.T) {
	p := Chrome146()
	ni := p.H2HPACKNeverIndex()
	expected := []string{"cookie", "authorization", "proxy-authorization"}
	if !reflect.DeepEqual(ni, expected) {
		t.Fatalf("expected %v, got %v", expected, ni)
	}
}

func TestH2HPACKNeverIndexCustom(t *testing.T) {
	p := Chrome146()
	p.H2Config = &H2FingerprintConfig{HPACKNeverIndex: []string{"set-cookie"}}
	ni := p.H2HPACKNeverIndex()
	if !reflect.DeepEqual(ni, []string{"set-cookie"}) {
		t.Fatalf("expected [set-cookie], got %v", ni)
	}
}

func TestH2StreamPriorityModeDefault(t *testing.T) {
	p := Chrome146()
	if p.H2StreamPriorityMode() != "chrome" {
		t.Fatalf("expected 'chrome', got %q", p.H2StreamPriorityMode())
	}
}

func TestH2StreamPriorityModeCustom(t *testing.T) {
	p := Chrome146()
	p.H2Config = &H2FingerprintConfig{StreamPriorityMode: "default"}
	if p.H2StreamPriorityMode() != "default" {
		t.Fatalf("expected 'default', got %q", p.H2StreamPriorityMode())
	}
}

func TestH2DisableCookieSplitDefault(t *testing.T) {
	p := Chrome146()
	if !p.H2DisableCookieSplit() {
		t.Fatal("expected true (Chrome default)")
	}
}

func TestH2DisableCookieSplitCustom(t *testing.T) {
	p := Chrome146()
	p.H2Config = &H2FingerprintConfig{DisableCookieSplit: boolPtr(false)}
	if p.H2DisableCookieSplit() {
		t.Fatal("expected false (Firefox behavior)")
	}
}

func TestH2SettingsOrderDefault(t *testing.T) {
	p := Chrome146()
	order := p.H2SettingsOrder()
	expected := []uint16{1, 2, 4, 6}
	if !reflect.DeepEqual(order, expected) {
		t.Fatalf("expected %v, got %v", expected, order)
	}
}

func TestH2SettingsOrderCustom(t *testing.T) {
	p := Chrome146()
	p.H2Config = &H2FingerprintConfig{SettingsOrder: []uint16{2, 4, 3, 9}}
	order := p.H2SettingsOrder()
	expected := []uint16{2, 4, 3, 9}
	if !reflect.DeepEqual(order, expected) {
		t.Fatalf("expected %v, got %v", expected, order)
	}
}

func TestH2PseudoHeaderOrderDefault(t *testing.T) {
	p := Chrome146()
	order := p.H2PseudoHeaderOrder()
	expected := []string{":method", ":authority", ":scheme", ":path"}
	if !reflect.DeepEqual(order, expected) {
		t.Fatalf("expected %v, got %v", expected, order)
	}
}

func TestH2PseudoHeaderOrderCustom(t *testing.T) {
	p := Chrome146()
	p.H2Config = &H2FingerprintConfig{
		PseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
	}
	order := p.H2PseudoHeaderOrder()
	expected := []string{":method", ":scheme", ":path", ":authority"}
	if !reflect.DeepEqual(order, expected) {
		t.Fatalf("expected %v, got %v", expected, order)
	}
}

// --- H3 Getter Tests ---

func TestH3QPACKMaxTableCapacityDefault(t *testing.T) {
	p := Chrome146()
	if p.H3QPACKMaxTableCapacity() != 65536 {
		t.Fatalf("expected 65536, got %d", p.H3QPACKMaxTableCapacity())
	}
}

func TestH3QPACKMaxTableCapacitySafariHeuristic(t *testing.T) {
	// Both Safari18 and IOSSafari18 have NoRFC7540Priorities=true
	p := Safari18()
	if p.H3QPACKMaxTableCapacity() != 16383 {
		t.Fatalf("Safari18: expected 16383 (Safari heuristic), got %d", p.H3QPACKMaxTableCapacity())
	}
	p2 := IOSSafari18()
	if p2.H3QPACKMaxTableCapacity() != 16383 {
		t.Fatalf("IOSSafari18: expected 16383 (Safari heuristic), got %d", p2.H3QPACKMaxTableCapacity())
	}
}

func TestH3QPACKMaxTableCapacityCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{QPACKMaxTableCapacity: uint64Ptr(4096)}
	if p.H3QPACKMaxTableCapacity() != 4096 {
		t.Fatalf("expected 4096, got %d", p.H3QPACKMaxTableCapacity())
	}
}

func TestH3QPACKBlockedStreamsDefault(t *testing.T) {
	p := Chrome146()
	if p.H3QPACKBlockedStreams() != 100 {
		t.Fatalf("expected 100, got %d", p.H3QPACKBlockedStreams())
	}
}

func TestH3QPACKBlockedStreamsCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{QPACKBlockedStreams: uint64Ptr(50)}
	if p.H3QPACKBlockedStreams() != 50 {
		t.Fatalf("expected 50, got %d", p.H3QPACKBlockedStreams())
	}
}

func TestH3MaxFieldSectionSizeDefault(t *testing.T) {
	p := Chrome146()
	if p.H3MaxFieldSectionSize() != 262144 {
		t.Fatalf("expected 262144, got %d", p.H3MaxFieldSectionSize())
	}
}

func TestH3MaxFieldSectionSizeSafariHeuristic(t *testing.T) {
	p := IOSSafari18()
	if p.H3MaxFieldSectionSize() != 0 {
		t.Fatalf("expected 0 (Safari omit), got %d", p.H3MaxFieldSectionSize())
	}
}

func TestH3MaxFieldSectionSizeCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{MaxFieldSectionSize: uint64Ptr(131072)}
	if p.H3MaxFieldSectionSize() != 131072 {
		t.Fatalf("expected 131072, got %d", p.H3MaxFieldSectionSize())
	}
}

func TestH3EnableDatagramsDefault(t *testing.T) {
	p := Chrome146()
	if !p.H3EnableDatagrams() {
		t.Fatal("expected true (Chrome default)")
	}
}

func TestH3EnableDatagramsSafariHeuristic(t *testing.T) {
	p := IOSSafari18()
	if p.H3EnableDatagrams() {
		t.Fatal("expected false (Safari heuristic)")
	}
}

func TestH3EnableDatagramsCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{EnableDatagrams: boolPtr(false)}
	if p.H3EnableDatagrams() {
		t.Fatal("expected false (custom)")
	}
}

func TestH3QUICInitialPacketSizeDefault(t *testing.T) {
	p := Chrome146()
	if p.H3QUICInitialPacketSize() != 1250 {
		t.Fatalf("expected 1250, got %d", p.H3QUICInitialPacketSize())
	}
}

func TestH3QUICInitialPacketSizeCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{QUICInitialPacketSize: uint16Ptr(1350)}
	if p.H3QUICInitialPacketSize() != 1350 {
		t.Fatalf("expected 1350, got %d", p.H3QUICInitialPacketSize())
	}
}

func TestH3QUICMaxIncomingStreamsDefault(t *testing.T) {
	p := Chrome146()
	if p.H3QUICMaxIncomingStreams() != 100 {
		t.Fatalf("expected 100, got %d", p.H3QUICMaxIncomingStreams())
	}
}

func TestH3QUICMaxIncomingStreamsCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{QUICMaxIncomingStreams: int64Ptr(200)}
	if p.H3QUICMaxIncomingStreams() != 200 {
		t.Fatalf("expected 200, got %d", p.H3QUICMaxIncomingStreams())
	}
}

func TestH3QUICMaxIncomingUniStreamsDefault(t *testing.T) {
	p := Chrome146()
	if p.H3QUICMaxIncomingUniStreams() != 103 {
		t.Fatalf("expected 103, got %d", p.H3QUICMaxIncomingUniStreams())
	}
}

func TestH3QUICMaxIncomingUniStreamsCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{QUICMaxIncomingUniStreams: int64Ptr(50)}
	if p.H3QUICMaxIncomingUniStreams() != 50 {
		t.Fatalf("expected 50, got %d", p.H3QUICMaxIncomingUniStreams())
	}
}

func TestH3QUICAllow0RTTDefault(t *testing.T) {
	p := Chrome146()
	if !p.H3QUICAllow0RTT() {
		t.Fatal("expected true")
	}
}

func TestH3QUICAllow0RTTCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{QUICAllow0RTT: boolPtr(false)}
	if p.H3QUICAllow0RTT() {
		t.Fatal("expected false")
	}
}

func TestH3QUICChromeStyleInitialDefault(t *testing.T) {
	p := Chrome146()
	if !p.H3QUICChromeStyleInitial() {
		t.Fatal("expected true")
	}
}

func TestH3QUICChromeStyleInitialCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{QUICChromeStyleInitial: boolPtr(false)}
	if p.H3QUICChromeStyleInitial() {
		t.Fatal("expected false")
	}
}

func TestH3QUICDisableHelloScrambleDefault(t *testing.T) {
	p := Chrome146()
	if !p.H3QUICDisableHelloScramble() {
		t.Fatal("expected true")
	}
}

func TestH3QUICDisableHelloScrambleCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{QUICDisableHelloScramble: boolPtr(false)}
	if p.H3QUICDisableHelloScramble() {
		t.Fatal("expected false")
	}
}

func TestH3QUICTransportParamOrderDefault(t *testing.T) {
	p := Chrome146()
	if p.H3QUICTransportParamOrder() != "chrome" {
		t.Fatalf("expected 'chrome', got %q", p.H3QUICTransportParamOrder())
	}
}

func TestH3QUICTransportParamOrderCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{QUICTransportParamOrder: "random"}
	if p.H3QUICTransportParamOrder() != "random" {
		t.Fatalf("expected 'random', got %q", p.H3QUICTransportParamOrder())
	}
}

func TestH3MaxResponseHeaderBytesDefault(t *testing.T) {
	p := Chrome146()
	if p.H3MaxResponseHeaderBytes() != 262144 {
		t.Fatalf("expected 262144, got %d", p.H3MaxResponseHeaderBytes())
	}
}

func TestH3MaxResponseHeaderBytesCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{MaxResponseHeaderBytes: uint64Ptr(131072)}
	if p.H3MaxResponseHeaderBytes() != 131072 {
		t.Fatalf("expected 131072, got %d", p.H3MaxResponseHeaderBytes())
	}
}

func TestH3SendGreaseFramesDefault(t *testing.T) {
	p := Chrome146()
	if !p.H3SendGreaseFrames() {
		t.Fatal("expected true")
	}
}

func TestH3SendGreaseFramesCustom(t *testing.T) {
	p := Chrome146()
	p.H3Config = &H3FingerprintConfig{SendGreaseFrames: boolPtr(false)}
	if p.H3SendGreaseFrames() {
		t.Fatal("expected false")
	}
}

// --- Phase 4: Explicit H2Config Tests ---

func TestFirefoxH2Config(t *testing.T) {
	p := Firefox133()
	if p.H2Config == nil {
		t.Fatal("Firefox133 H2Config should not be nil")
	}
	if p.H2DisableCookieSplit() {
		t.Fatal("Firefox should NOT disable cookie split")
	}
	settings := p.H2SettingsOrder()
	expectedSettings := []uint16{1, 2, 4, 5}
	if !reflect.DeepEqual(settings, expectedSettings) {
		t.Fatalf("Firefox settings order: expected %v, got %v", expectedSettings, settings)
	}
	order := p.H2HeaderOrder()
	if len(order) == 0 || order[0] != "user-agent" {
		t.Fatalf("Firefox HPACK should start with user-agent, got %v", order)
	}
	for _, h := range order {
		if h == "sec-ch-ua" {
			t.Fatal("Firefox HPACK should not contain sec-ch-ua")
		}
	}
	if p.H2StreamPriorityMode() != "default" {
		t.Fatalf("Firefox priority mode: expected 'default', got %q", p.H2StreamPriorityMode())
	}
	// Firefox pseudo-header order: m,p,a,s (verified via tls.peet.ws)
	pseudo := p.H2PseudoHeaderOrder()
	expectedPseudo := []string{":method", ":path", ":authority", ":scheme"}
	if !reflect.DeepEqual(pseudo, expectedPseudo) {
		t.Fatalf("Firefox pseudo order: expected %v, got %v", expectedPseudo, pseudo)
	}
}

func TestFirefox148Preset(t *testing.T) {
	p := Firefox148()
	if p.JA3 == "" {
		t.Fatal("Firefox148 should use JA3 string")
	}
	if p.JA3Extras == nil {
		t.Fatal("Firefox148 should have JA3Extras")
	}
	if len(p.JA3Extras.SignatureAlgorithms) != 11 {
		t.Fatalf("Firefox148 should have 11 sig algs, got %d", len(p.JA3Extras.SignatureAlgorithms))
	}
	if len(p.JA3Extras.CertCompAlgs) != 3 {
		t.Fatalf("Firefox148 should have 3 cert comp algs (zlib, brotli, zstd), got %d", len(p.JA3Extras.CertCompAlgs))
	}
	if p.JA3Extras.KeyShareCurves != 3 {
		t.Fatalf("Firefox148 should send 3 key shares, got %d", p.JA3Extras.KeyShareCurves)
	}
	if p.HTTP2Settings.EnablePush {
		t.Fatal("Firefox148 should have ENABLE_PUSH=0")
	}
	if p.H2Config == nil {
		t.Fatal("Firefox148 should have H2Config")
	}
	pseudo := p.H2PseudoHeaderOrder()
	if !reflect.DeepEqual(pseudo, []string{":method", ":path", ":authority", ":scheme"}) {
		t.Fatalf("Firefox148 pseudo order wrong: %v", pseudo)
	}
}

func TestSafariH2Config(t *testing.T) {
	p := Safari18()
	if p.H2Config == nil {
		t.Fatal("Safari18 H2Config should not be nil")
	}
	pseudo := p.H2PseudoHeaderOrder()
	expectedPseudo := []string{":method", ":scheme", ":path", ":authority"}
	if !reflect.DeepEqual(pseudo, expectedPseudo) {
		t.Fatalf("Safari pseudo order: expected %v, got %v", expectedPseudo, pseudo)
	}
	settings := p.H2SettingsOrder()
	expectedSettings := []uint16{2, 4, 3, 5, 9}
	if !reflect.DeepEqual(settings, expectedSettings) {
		t.Fatalf("Safari settings order: expected %v, got %v", expectedSettings, settings)
	}
	order := p.H2HeaderOrder()
	if len(order) == 0 || order[0] != "accept" {
		t.Fatalf("Safari HPACK should start with accept, got %v", order)
	}
	for _, h := range order {
		if h == "sec-ch-ua" {
			t.Fatal("Safari HPACK should not contain sec-ch-ua")
		}
	}
	// H3Config should be explicitly set (not relying on heuristic)
	if p.H3Config == nil {
		t.Fatal("Safari18 H3Config should not be nil")
	}
	if p.H3QPACKMaxTableCapacity() != 16383 {
		t.Fatalf("Safari H3 QPACK capacity: expected 16383, got %d", p.H3QPACKMaxTableCapacity())
	}
	if p.H3MaxFieldSectionSize() != 0 {
		t.Fatalf("Safari H3 max field section: expected 0, got %d", p.H3MaxFieldSectionSize())
	}
	if p.H3EnableDatagrams() {
		t.Fatal("Safari H3 should not enable datagrams")
	}
	if p.H3QUICChromeStyleInitial() {
		t.Fatal("Safari should not use Chrome-style initial packets")
	}
	if p.H3SendGreaseFrames() {
		t.Fatal("Safari should not send GREASE frames")
	}
}

func TestIOSChromeH2Config(t *testing.T) {
	p := IOSChrome146()
	if p.H2Config == nil {
		t.Fatal("IOSChrome146 H2Config should not be nil")
	}
	pseudo := p.H2PseudoHeaderOrder()
	expectedPseudo := []string{":method", ":scheme", ":path", ":authority"}
	if !reflect.DeepEqual(pseudo, expectedPseudo) {
		t.Fatalf("iOS Chrome pseudo order: expected %v, got %v", expectedPseudo, pseudo)
	}
	settings := p.H2SettingsOrder()
	expectedSettings := []uint16{2, 4, 3, 5, 9}
	if !reflect.DeepEqual(settings, expectedSettings) {
		t.Fatalf("iOS Chrome settings order: expected %v, got %v", expectedSettings, settings)
	}
}

func TestAndroidChromeH2Config(t *testing.T) {
	p := AndroidChrome146()
	if p.H2Config == nil {
		t.Fatal("AndroidChrome146 H2Config should not be nil")
	}
	settings := p.H2SettingsOrder()
	expectedSettings := []uint16{1, 2, 4, 6}
	if !reflect.DeepEqual(settings, expectedSettings) {
		t.Fatalf("Android Chrome settings order: expected %v, got %v", expectedSettings, settings)
	}
	pseudo := p.H2PseudoHeaderOrder()
	expectedPseudo := []string{":method", ":authority", ":scheme", ":path"}
	if !reflect.DeepEqual(pseudo, expectedPseudo) {
		t.Fatalf("Android Chrome pseudo order: expected %v, got %v", expectedPseudo, pseudo)
	}
	if !p.H2DisableCookieSplit() {
		t.Fatal("Android Chrome should disable cookie split (same as desktop)")
	}
}

func TestChromeH2ConfigNoRegression(t *testing.T) {
	p := Chrome146()
	order := p.H2HeaderOrder()
	if len(order) != 19 || order[0] != "cache-control" {
		t.Fatalf("Chrome HPACK order regression: got %d headers, first=%q", len(order), order[0])
	}
	if p.H2HPACKIndexingPolicy() != "chrome" {
		t.Fatalf("Chrome indexing policy regression: got %q", p.H2HPACKIndexingPolicy())
	}
	ni := p.H2HPACKNeverIndex()
	if len(ni) != 3 {
		t.Fatalf("Chrome never-index regression: expected 3, got %d", len(ni))
	}
	if p.H2StreamPriorityMode() != "chrome" {
		t.Fatalf("Chrome priority mode regression: got %q", p.H2StreamPriorityMode())
	}
	if !p.H2DisableCookieSplit() {
		t.Fatal("Chrome cookie split regression: expected true")
	}
	settings := p.H2SettingsOrder()
	if !reflect.DeepEqual(settings, []uint16{1, 2, 4, 6}) {
		t.Fatalf("Chrome settings order regression: got %v", settings)
	}
	pseudo := p.H2PseudoHeaderOrder()
	if !reflect.DeepEqual(pseudo, []string{":method", ":authority", ":scheme", ":path"}) {
		t.Fatalf("Chrome pseudo order regression: got %v", pseudo)
	}
}

func TestAllPresetsHaveH2Config(t *testing.T) {
	allPresets := Available()
	for _, name := range allPresets {
		p := Get(name)
		if p.H2Config == nil {
			t.Errorf("preset %q has nil H2Config", name)
		}
	}
}

// --- H2/H3 Getters with nil H2Config/H3Config ---

func TestH2GettersWithNilConfig(t *testing.T) {
	p := &Preset{Name: "bare"}
	// All should return Chrome defaults without panicking
	if len(p.H2HeaderOrder()) != 19 {
		t.Fatal("expected 19 element Chrome header order")
	}
	if p.H2HPACKIndexingPolicy() != "chrome" {
		t.Fatal("expected 'chrome'")
	}
	if len(p.H2HPACKNeverIndex()) != 3 {
		t.Fatal("expected 3 never-index headers")
	}
	if p.H2StreamPriorityMode() != "chrome" {
		t.Fatal("expected 'chrome'")
	}
	if !p.H2DisableCookieSplit() {
		t.Fatal("expected true")
	}
	if p.H2SettingsOrder() != nil {
		t.Fatal("expected nil")
	}
	if p.H2PseudoHeaderOrder() != nil {
		t.Fatal("expected nil")
	}
}

func TestH3GettersWithNilConfig(t *testing.T) {
	p := &Preset{Name: "bare"}
	// All should return Chrome defaults without panicking
	if p.H3QPACKMaxTableCapacity() != 65536 {
		t.Fatalf("expected 65536, got %d", p.H3QPACKMaxTableCapacity())
	}
	if p.H3QPACKBlockedStreams() != 100 {
		t.Fatalf("expected 100, got %d", p.H3QPACKBlockedStreams())
	}
	if p.H3MaxFieldSectionSize() != 262144 {
		t.Fatalf("expected 262144, got %d", p.H3MaxFieldSectionSize())
	}
	if !p.H3EnableDatagrams() {
		t.Fatal("expected true")
	}
	if p.H3QUICInitialPacketSize() != 1250 {
		t.Fatalf("expected 1250, got %d", p.H3QUICInitialPacketSize())
	}
	if p.H3QUICMaxIncomingStreams() != 100 {
		t.Fatalf("expected 100, got %d", p.H3QUICMaxIncomingStreams())
	}
	if p.H3QUICMaxIncomingUniStreams() != 103 {
		t.Fatalf("expected 103, got %d", p.H3QUICMaxIncomingUniStreams())
	}
	if !p.H3QUICAllow0RTT() {
		t.Fatal("expected true")
	}
	if !p.H3QUICChromeStyleInitial() {
		t.Fatal("expected true")
	}
	if !p.H3QUICDisableHelloScramble() {
		t.Fatal("expected true")
	}
	if p.H3QUICTransportParamOrder() != "chrome" {
		t.Fatalf("expected 'chrome', got %q", p.H3QUICTransportParamOrder())
	}
	if p.H3MaxResponseHeaderBytes() != 262144 {
		t.Fatalf("expected 262144, got %d", p.H3MaxResponseHeaderBytes())
	}
	if !p.H3SendGreaseFrames() {
		t.Fatal("expected true")
	}
}
