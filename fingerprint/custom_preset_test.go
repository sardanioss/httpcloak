package fingerprint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
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

func TestBuildPresetUnknownBasedOn(t *testing.T) {
	spec := &PresetSpec{
		Name:    "bad",
		BasedOn: "nonexistent-browser-999",
	}
	// Get() returns Chrome146 for unknown names, so this won't error
	// (based_on uses Get() which has a fallback)
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected preset")
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
