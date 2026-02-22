//go:build e2e

package httpcloak

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"context"
)

// tlsPeetResponse represents the JSON response from tls.peet.ws/api/all.
// The tls.ciphers, extensions, etc. are strings, not structured objects.
type tlsPeetResponse struct {
	TLS struct {
		JA3     string `json:"ja3"`
		JA3Hash string `json:"ja3_hash"`
	} `json:"tls"`
	HTTP2 struct {
		AkamaiFingerprint     string `json:"akamai_fingerprint"`
		AkamaiFingerprintHash string `json:"akamai_fingerprint_hash"`
	} `json:"http2"`
	HTTPVersion string `json:"http_version"`
}

// isGREASEValue returns true if the value is a TLS GREASE value.
func isGREASEValue(v int) bool {
	if v < 0 {
		return false
	}
	u := uint16(v)
	return u&0x0f0f == 0x0a0a && u>>8 == u&0xff
}

// filterGREASE removes GREASE values from a dash-separated list of integers.
func filterGREASE(dashSeparated string) string {
	if dashSeparated == "" {
		return ""
	}
	parts := strings.Split(dashSeparated, "-")
	var filtered []string
	for _, p := range parts {
		val, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		if !isGREASEValue(val) {
			filtered = append(filtered, p)
		}
	}
	return strings.Join(filtered, "-")
}

// filterJA3GREASE takes a full JA3 string and returns a version with all
// GREASE values removed from each field.
func filterJA3GREASE(ja3 string) string {
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return ja3
	}
	return fmt.Sprintf("%s,%s,%s,%s,%s",
		parts[0],
		filterGREASE(parts[1]),
		filterGREASE(parts[2]),
		filterGREASE(parts[3]),
		parts[4],
	)
}

// TestJA3FingerprintE2E verifies that httpcloak correctly produces a custom
// JA3 fingerprint by making a real request to tls.peet.ws and comparing
// the observed fingerprint against what was configured.
//
// Run with: go test -tags e2e -run TestJA3FingerprintE2E -v -count=1
func TestJA3FingerprintE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Note: extension 21 (padding) is excluded because BoringPaddingStyle only adds
	// padding bytes when ClientHello size is 256-511 bytes. For larger ClientHellos,
	// the padding extension is omitted by uTLS, making it unreliable to include in
	// the expected JA3.
	inputJA3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-18-27-17513-65037,29-23-24,0"

	sess := NewSession("chrome-145",
		WithCustomFingerprint(CustomFingerprint{
			JA3:               inputJA3,
			PermuteExtensions: false,
		}),
		WithForceHTTP1(),
	)
	defer sess.Close()

	resp, err := sess.Get(ctx, "https://tls.peet.ws/api/tls")
	if err != nil {
		t.Fatalf("request to tls.peet.ws failed: %v", err)
	}
	defer resp.Close()

	var result tlsPeetResponse
	if err := resp.JSON(&result); err != nil {
		body, _ := resp.Text()
		t.Fatalf("failed to parse response JSON: %v\nBody: %s", err, body[:min(len(body), 500)])
	}

	t.Logf("Server-observed JA3: %s", result.TLS.JA3)
	t.Logf("Server-observed JA3 hash: %s", result.TLS.JA3Hash)

	// Parse the sent and received JA3 fields, filter GREASE, compare.
	sentFiltered := filterJA3GREASE(inputJA3)
	receivedFiltered := filterJA3GREASE(result.TLS.JA3)

	if sentFiltered != receivedFiltered {
		t.Errorf("JA3 mismatch (after GREASE filtering):\n  sent:     %s\n  received: %s", sentFiltered, receivedFiltered)
	} else {
		t.Logf("JA3 fingerprint matches after GREASE filtering!")
	}

	// Also verify individual fields for clearer diagnostics.
	inputParts := strings.Split(inputJA3, ",")
	receivedParts := strings.Split(result.TLS.JA3, ",")
	if len(receivedParts) != 5 {
		t.Fatalf("received JA3 has %d fields, expected 5", len(receivedParts))
	}

	if receivedParts[0] != inputParts[0] {
		t.Errorf("TLS version mismatch: sent %s, received %s", inputParts[0], receivedParts[0])
	}
	if filterGREASE(receivedParts[1]) != filterGREASE(inputParts[1]) {
		t.Errorf("cipher suites mismatch:\n  sent:     %s\n  received: %s", filterGREASE(inputParts[1]), filterGREASE(receivedParts[1]))
	}
	if filterGREASE(receivedParts[2]) != filterGREASE(inputParts[2]) {
		t.Errorf("extensions mismatch:\n  sent:     %s\n  received: %s", filterGREASE(inputParts[2]), filterGREASE(receivedParts[2]))
	}
	if filterGREASE(receivedParts[3]) != filterGREASE(inputParts[3]) {
		t.Errorf("curves mismatch:\n  sent:     %s\n  received: %s", filterGREASE(inputParts[3]), filterGREASE(receivedParts[3]))
	}
	if receivedParts[4] != inputParts[4] {
		t.Errorf("point formats mismatch: sent %s, received %s", inputParts[4], receivedParts[4])
	}
}

// TestAkamaiFingerprintE2E verifies that httpcloak correctly produces a custom
// Akamai HTTP/2 fingerprint.
//
// Run with: go test -tags e2e -run TestAkamaiFingerprintE2E -v -count=1
func TestAkamaiFingerprintE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	inputAkamai := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

	sess := NewSession("chrome-145",
		WithCustomFingerprint(CustomFingerprint{
			JA3:               "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-18-27-17513-65037,29-23-24,0",
			Akamai:            inputAkamai,
			PermuteExtensions: false,
		}),
		WithForceHTTP2(),
		WithDisableECH(),
	)
	defer sess.Close()

	resp, err := sess.Get(ctx, "https://tls.peet.ws/api/all")
	if err != nil {
		t.Fatalf("request to tls.peet.ws failed: %v", err)
	}
	defer resp.Close()

	var result tlsPeetResponse
	if err := resp.JSON(&result); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	t.Logf("HTTP version: %s", result.HTTPVersion)
	t.Logf("Server-observed Akamai fingerprint: %s", result.HTTP2.AkamaiFingerprint)

	if result.HTTPVersion != "h2" {
		t.Errorf("expected HTTP/2 (h2), got %s", result.HTTPVersion)
	}

	receivedAkamai := result.HTTP2.AkamaiFingerprint
	if receivedAkamai == "" {
		t.Fatal("server returned empty Akamai fingerprint")
	}

	inputParts := strings.Split(inputAkamai, "|")
	receivedParts := strings.Split(receivedAkamai, "|")

	if len(receivedParts) != 4 {
		t.Fatalf("received Akamai has %d parts, expected 4: %q", len(receivedParts), receivedAkamai)
	}

	// Compare SETTINGS (order-independent)
	sentSettings := parseSettingsMap(inputParts[0])
	receivedSettings := parseSettingsMap(receivedParts[0])
	for key, sentVal := range sentSettings {
		if receivedVal, ok := receivedSettings[key]; ok {
			if sentVal != receivedVal {
				t.Errorf("SETTINGS[%s] mismatch: sent %s, received %s", key, sentVal, receivedVal)
			}
		} else {
			t.Errorf("SETTINGS[%s] = %s was sent but not observed", key, sentVal)
		}
	}

	if inputParts[1] != receivedParts[1] {
		t.Errorf("WINDOW_UPDATE mismatch: sent %s, received %s", inputParts[1], receivedParts[1])
	}

	if inputParts[3] != receivedParts[3] {
		t.Errorf("pseudo-header order mismatch: sent %s, received %s", inputParts[3], receivedParts[3])
	}
}

// TestPresetJA3E2E verifies that the built-in chrome-145 preset produces a
// consistent and valid fingerprint without any custom overrides.
//
// Run with: go test -tags e2e -run TestPresetJA3E2E -v -count=1
func TestPresetJA3E2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sess := NewSession("chrome-145",
		WithForceHTTP2(),
		WithDisableECH(),
	)
	defer sess.Close()

	resp, err := sess.Get(ctx, "https://tls.peet.ws/api/all")
	if err != nil {
		t.Fatalf("request to tls.peet.ws failed: %v", err)
	}
	defer resp.Close()

	var result tlsPeetResponse
	if err := resp.JSON(&result); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	t.Logf("Preset JA3: %s", result.TLS.JA3)
	t.Logf("Preset JA3 hash: %s", result.TLS.JA3Hash)
	t.Logf("Preset Akamai: %s", result.HTTP2.AkamaiFingerprint)

	ja3Parts := strings.Split(result.TLS.JA3, ",")
	if len(ja3Parts) != 5 {
		t.Fatalf("preset JA3 has %d fields, expected 5", len(ja3Parts))
	}

	if ja3Parts[0] != "771" {
		t.Errorf("expected TLS version 771, got %s", ja3Parts[0])
	}

	ciphers := strings.Split(filterGREASE(ja3Parts[1]), "-")
	if len(ciphers) < 5 {
		t.Errorf("expected at least 5 cipher suites, got %d", len(ciphers))
	}

	exts := strings.Split(filterGREASE(ja3Parts[2]), "-")
	if len(exts) < 10 {
		t.Errorf("expected at least 10 extensions, got %d", len(exts))
	}

	if result.HTTP2.AkamaiFingerprint == "" {
		t.Error("expected non-empty Akamai fingerprint for HTTP/2 preset")
	}

	if result.HTTPVersion != "h2" {
		t.Errorf("expected h2, got %s", result.HTTPVersion)
	}
}

// TestCustomJA3ReproducibilityE2E verifies that two separate sessions with
// the same custom JA3 produce identical fingerprints.
//
// Run with: go test -tags e2e -run TestCustomJA3ReproducibilityE2E -v -count=1
func TestCustomJA3ReproducibilityE2E(t *testing.T) {
	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-18-27-17513-65037,29-23-24,0"

	var results [2]tlsPeetResponse

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		sess := NewSession("chrome-145",
			WithCustomFingerprint(CustomFingerprint{
				JA3:               ja3,
				PermuteExtensions: false,
			}),
			WithForceHTTP1(),
		)

		resp, err := sess.Get(ctx, "https://tls.peet.ws/api/tls")
		if err != nil {
			cancel()
			sess.Close()
			t.Fatalf("request %d failed: %v", i+1, err)
		}

		if err := resp.JSON(&results[i]); err != nil {
			resp.Close()
			cancel()
			sess.Close()
			t.Fatalf("failed to parse response %d: %v", i+1, err)
		}
		resp.Close()
		cancel()
		sess.Close()
	}

	ja3_1 := filterJA3GREASE(results[0].TLS.JA3)
	ja3_2 := filterJA3GREASE(results[1].TLS.JA3)
	if ja3_1 != ja3_2 {
		t.Errorf("JA3 fingerprints differ between sessions:\n  session 1: %s\n  session 2: %s", ja3_1, ja3_2)
	} else {
		t.Logf("JA3 fingerprints match: %s", ja3_1)
	}
}

// parseSettingsMap parses an Akamai SETTINGS string like "1:65536;2:0;4:6291456"
func parseSettingsMap(settings string) map[string]string {
	m := make(map[string]string)
	if settings == "" {
		return m
	}
	for _, pair := range strings.Split(settings, ";") {
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
