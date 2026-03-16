package fingerprint

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func findExamplesDir() string {
	// Navigate from fingerprint/ up to project root, then into examples/presets/
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	return filepath.Join(dir, "..", "examples", "presets")
}

func TestExampleChrome142Windows(t *testing.T) {
	path := filepath.Join(findExamplesDir(), "chrome_142_windows.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("example file not found: %s", path)
	}

	p, err := LoadAndBuildPreset(path)
	if err != nil {
		t.Fatalf("failed to load chrome_142_windows.json: %v", err)
	}

	if p.Name != "chrome-142-windows" {
		t.Fatalf("expected name chrome-142-windows, got %s", p.Name)
	}
	if !strings.Contains(p.UserAgent, "Chrome/142") {
		t.Fatalf("expected UA with Chrome/142, got %s", p.UserAgent)
	}
	if !strings.Contains(p.UserAgent, "Windows NT") {
		t.Fatalf("expected Windows UA, got %s", p.UserAgent)
	}
	if p.ClientHelloID.Client == "" {
		t.Fatal("expected ClientHelloID to be set from chrome-133")
	}
	// TCP should be Windows
	if p.TCPFingerprint.TTL != 128 {
		t.Fatalf("expected TTL 128 (Windows), got %d", p.TCPFingerprint.TTL)
	}
	if p.TCPFingerprint.WindowSize != 64240 {
		t.Fatalf("expected WindowSize 64240 (Windows), got %d", p.TCPFingerprint.WindowSize)
	}
	// Should inherit HTTP2 settings from chrome-141 base
	if p.HTTP2Settings.HeaderTableSize != 65536 {
		t.Fatalf("expected HeaderTableSize 65536, got %d", p.HTTP2Settings.HeaderTableSize)
	}
	if p.HTTP2Settings.InitialWindowSize != 6291456 {
		t.Fatalf("expected InitialWindowSize 6291456, got %d", p.HTTP2Settings.InitialWindowSize)
	}
	// Headers map should have sec-ch-ua with v=142
	if p.Headers["sec-ch-ua"] == "" || !strings.Contains(p.Headers["sec-ch-ua"], "142") {
		t.Fatalf("expected sec-ch-ua with 142, got %q", p.Headers["sec-ch-ua"])
	}
	// HeaderOrder should have 13 entries
	if len(p.HeaderOrder) != 13 {
		t.Fatalf("expected 13 header pairs, got %d", len(p.HeaderOrder))
	}
}

func TestExampleChrome142Linux(t *testing.T) {
	path := filepath.Join(findExamplesDir(), "chrome_142_linux.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("example file not found: %s", path)
	}

	p, err := LoadAndBuildPreset(path)
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if p.Name != "chrome-142-linux" {
		t.Fatalf("expected chrome-142-linux, got %s", p.Name)
	}
	if !strings.Contains(p.UserAgent, "Linux x86_64") {
		t.Fatalf("expected Linux UA, got %s", p.UserAgent)
	}
	// TCP should be Linux
	if p.TCPFingerprint.TTL != 64 {
		t.Fatalf("expected TTL 64 (Linux), got %d", p.TCPFingerprint.TTL)
	}
}

func TestExampleChromeJA3Custom(t *testing.T) {
	path := filepath.Join(findExamplesDir(), "chrome_ja3_custom.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("example file not found: %s", path)
	}

	p, err := LoadAndBuildPreset(path)
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if p.Name != "chrome-ja3-custom" {
		t.Fatalf("expected chrome-ja3-custom, got %s", p.Name)
	}
	if p.JA3 == "" {
		t.Fatal("expected JA3 string to be set")
	}
	if !strings.HasPrefix(p.JA3, "771,") {
		t.Fatalf("expected JA3 starting with 771, got %s", p.JA3[:10])
	}
	if p.JA3Extras == nil {
		t.Fatal("expected JA3Extras to be set")
	}
	if !p.JA3Extras.PermuteExtensions {
		t.Fatal("expected PermuteExtensions true")
	}
	if p.JA3Extras.RecordSizeLimit != 16385 {
		t.Fatalf("expected RSL 16385, got %d", p.JA3Extras.RecordSizeLimit)
	}

	// Verify JA3 can actually be parsed
	spec, err := ParseJA3(p.JA3, p.JA3Extras)
	if err != nil {
		t.Fatalf("JA3 parse failed: %v", err)
	}
	if spec == nil {
		t.Fatal("parsed spec is nil")
	}

	// HTTP2 settings from akamai string
	if p.HTTP2Settings.HeaderTableSize != 65536 {
		t.Fatalf("expected HeaderTableSize 65536, got %d", p.HTTP2Settings.HeaderTableSize)
	}
	if p.TCPFingerprint.TTL != 128 {
		t.Fatalf("expected TTL 128 (Windows), got %d", p.TCPFingerprint.TTL)
	}
}

func TestExampleRotationPool(t *testing.T) {
	path := filepath.Join(findExamplesDir(), "rotation_pool.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("example file not found: %s", path)
	}

	pool, err := NewPresetPoolFromFile(path)
	if err != nil {
		t.Fatalf("failed to load pool: %v", err)
	}
	defer pool.Close()

	if pool.Name() != "chrome-rotation" {
		t.Fatalf("expected chrome-rotation, got %s", pool.Name())
	}
	if pool.Size() != 3 {
		t.Fatalf("expected 3 presets, got %d", pool.Size())
	}

	// Round-robin should cycle through all 3
	names := make([]string, 3)
	for i := 0; i < 3; i++ {
		names[i] = pool.Next().Name
	}
	if names[0] != "pool-chrome-win" {
		t.Fatalf("expected pool-chrome-win first, got %s", names[0])
	}
	if names[1] != "pool-chrome-linux" {
		t.Fatalf("expected pool-chrome-linux second, got %s", names[1])
	}
	if names[2] != "pool-chrome-mac" {
		t.Fatalf("expected pool-chrome-mac third, got %s", names[2])
	}

	// Verify auto-registration
	for _, name := range []string{"pool-chrome-win", "pool-chrome-linux", "pool-chrome-mac"} {
		if got := Get(name); got == nil || got.Name != name {
			t.Fatalf("preset %s not auto-registered", name)
		}
	}

	// Each preset should have proper TCP and inherited Chrome settings
	win := pool.Get(0)
	if win.TCPFingerprint.TTL != 128 {
		t.Fatalf("Windows preset TTL: expected 128, got %d", win.TCPFingerprint.TTL)
	}
	linux := pool.Get(1)
	if linux.TCPFingerprint.TTL != 64 {
		t.Fatalf("Linux preset TTL: expected 64, got %d", linux.TCPFingerprint.TTL)
	}
	mac := pool.Get(2)
	if mac.TCPFingerprint.TTL != 64 {
		t.Fatalf("macOS preset TTL: expected 64, got %d", mac.TCPFingerprint.TTL)
	}
}

func TestExampleFirefoxCustom(t *testing.T) {
	path := filepath.Join(findExamplesDir(), "firefox_custom.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("example file not found: %s", path)
	}

	p, err := LoadAndBuildPreset(path)
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if p.Name != "firefox-134-custom" {
		t.Fatalf("expected firefox-134-custom, got %s", p.Name)
	}
	if !strings.Contains(p.UserAgent, "Firefox/134.0") {
		t.Fatalf("expected Firefox 134 UA, got %s", p.UserAgent)
	}

	// Firefox HTTP2 settings differ from Chrome
	if p.HTTP2Settings.InitialWindowSize != 131072 {
		t.Fatalf("expected Firefox InitialWindowSize 131072, got %d", p.HTTP2Settings.InitialWindowSize)
	}
	if !p.HTTP2Settings.EnablePush {
		t.Fatal("expected Firefox EnablePush true")
	}
	if p.HTTP2Settings.StreamWeight != 42 {
		t.Fatalf("expected Firefox StreamWeight 42, got %d", p.HTTP2Settings.StreamWeight)
	}

	// TCP should be Windows
	if p.TCPFingerprint.TTL != 128 {
		t.Fatalf("expected TTL 128 (Windows), got %d", p.TCPFingerprint.TTL)
	}

	// 8 headers in the order
	if len(p.HeaderOrder) != 8 {
		t.Fatalf("expected 8 header pairs, got %d", len(p.HeaderOrder))
	}

	// Pseudo-header order from HTTP2 spec
	if p.H2Config == nil {
		t.Fatal("expected H2Config to be set")
	}
	if len(p.H2Config.PseudoHeaderOrder) != 4 {
		t.Fatalf("expected 4 pseudo headers, got %d", len(p.H2Config.PseudoHeaderOrder))
	}
	if p.H2Config.PseudoHeaderOrder[0] != ":method" {
		t.Fatalf("expected :method first, got %s", p.H2Config.PseudoHeaderOrder[0])
	}
}
