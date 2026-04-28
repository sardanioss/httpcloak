package fingerprint

import (
	"strings"
	"testing"

	tls "github.com/sardanioss/utls"
)

// TestClientHelloIDName_RoundTripAllRegistered checks that every registered
// ID has an inverse mapping, and that the inverse mapping resolves back to
// the same (Client, Version) tuple.
func TestClientHelloIDName_RoundTripAllRegistered(t *testing.T) {
	for name, id := range clientHelloIDs {
		// Skip entries whose ID has empty Client and Version (HelloGolang,
		// HelloCustom, HelloRandomized*). These intentionally have no
		// canonical name in the inverse map — they're not browser fingerprints.
		if id.Client == "" && id.Version == "" {
			continue
		}

		got, ok := ClientHelloIDName(id)
		if !ok {
			t.Errorf("name=%q id=%+v: ClientHelloIDName returned !ok", name, id)
			continue
		}

		// Resolve the returned canonical name back and compare tuples.
		back, err := ResolveClientHelloID(got)
		if err != nil {
			t.Errorf("name=%q -> canonical=%q: ResolveClientHelloID failed: %v", name, got, err)
			continue
		}
		if back.Client != id.Client || back.Version != id.Version {
			t.Errorf("name=%q -> canonical=%q -> id=%+v, want %+v", name, got, back, id)
		}
	}
}

// TestClientHelloIDName_PrefersConcreteOverAuto verifies that when a concrete
// name and an -auto alias share the same (Client, Version), the inverse map
// returns the concrete name.
func TestClientHelloIDName_PrefersConcreteOverAuto(t *testing.T) {
	// HelloFirefox_Auto == HelloFirefox_120 (same Client, same Version).
	got, ok := ClientHelloIDName(tls.HelloFirefox_Auto)
	if !ok {
		t.Fatalf("HelloFirefox_Auto: not found in inverse map")
	}
	if strings.HasSuffix(got, "-auto") {
		t.Errorf("HelloFirefox_Auto resolved to %q, want concrete name (e.g. firefox-120)", got)
	}
	// And the concrete name should be the same one we'd resolve directly.
	want, _ := ClientHelloIDName(tls.HelloFirefox_120)
	if got != want {
		t.Errorf("HelloFirefox_Auto resolved to %q, but HelloFirefox_120 resolved to %q", got, want)
	}
}

// TestClientHelloIDName_ZeroValue ensures the zero-value ID returns ("", false)
// rather than corrupt empty-key matches in the inverse map.
func TestClientHelloIDName_ZeroValue(t *testing.T) {
	got, ok := ClientHelloIDName(tls.ClientHelloID{})
	if ok {
		t.Errorf("zero-value ID resolved to %q, want !ok", got)
	}
}

// TestClientHelloIDName_UnregisteredID covers a hand-built ClientHelloID with
// non-empty fields that doesn't appear in clientHelloIDs.
func TestClientHelloIDName_UnregisteredID(t *testing.T) {
	custom := tls.ClientHelloID{Client: "Synthetic", Version: "0.0"}
	got, ok := ClientHelloIDName(custom)
	if ok {
		t.Errorf("synthetic ID resolved to %q, want !ok", got)
	}
}
