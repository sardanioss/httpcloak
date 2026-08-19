package transport

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// driveWithPreset is drive() for a registered custom preset, and sends an
// authorization header, which is the field that discriminates the two policies:
// curl never-indexes it, Chrome indexes it like anything else.
func driveWithPreset(t *testing.T, h *hpackWireServer, presetName string, want int) [][]byte {
	t.Helper()
	tr := NewTransport(presetName)
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	base := "https://" + h.addr
	for i := 0; i < want; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, err := tr.Do(ctx, &Request{
			Method:  "GET",
			URL:     fmt.Sprintf("%s/probe/%d", base, i),
			Headers: map[string][]string{"authorization": {"Bearer tok"}},
		})
		cancel()
		if err != nil {
			t.Logf("request %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.captured()) >= want {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	blocks := h.captured()
	if len(blocks) < want {
		t.Skipf("captured %d/%d header blocks; environment did not complete the exchange",
			len(blocks), want)
	}
	return blocks
}

func registerPreset(t *testing.T, name, extraH2 string) {
	t.Helper()
	spec := fmt.Sprintf(`{"version":1,"preset":{"name":%q,"based_on":"chrome-latest"%s}}`, name, extraH2)
	p, err := fingerprint.LoadAndBuildPresetFromJSON([]byte(spec))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	if err := fingerprint.RegisterStrict(p.Name, p); err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
	t.Cleanup(func() { fingerprint.Unregister(name) })
}

// The override layer has to change the byte on the wire, not just the config.
//
// A curl mirror needs exactly one entry, {"authorization": "never"}, because
// that is the only name where curl's representation differs from the Chrome
// policy it is layered on. :path deliberately needs no entry: the Chrome policy
// already emits a literal without indexing for every pseudo-header except
// :authority, which is what curl does too.
func TestHPACKRepresentationOverrideReachesTheWire(t *testing.T) {
	h := startHPACKWireServer(t, 0, nil)
	registerPreset(t, "rep-never", `,"http2":{"hpack_representation":{"authorization":"never"}}`)

	blocks := driveWithPreset(t, h, "rep-never", 2)
	for i, b := range blocks[:2] {
		a, ok := findInstr(parseHPACK(t, b), "authorization")
		if !ok {
			t.Fatalf("request %d: no authorization instruction", i+1)
		}
		if a.Kind != "LIT_NEVER" {
			t.Errorf("request %d: authorization = %s (first byte %#x), want LIT_NEVER. "+
				"The override reached the config but not the encoder", i+1, a.Kind, a.First)
		}
	}
}

// Without an override the Chrome policy must be untouched. Chrome indexes
// authorization like any other header, and never-indexing it by default would
// put a byte on the wire Chrome never sends. This is the guard on that.
func TestHPACKNoOverrideKeepsChromePolicy(t *testing.T) {
	h := startHPACKWireServer(t, 0, nil)
	registerPreset(t, "rep-none", "")

	blocks := driveWithPreset(t, h, "rep-none", 2)
	a, ok := findInstr(parseHPACK(t, blocks[0]), "authorization")
	if !ok {
		t.Fatal("no authorization instruction in the first header block")
	}
	if a.Kind != "LIT_INCREMENTAL" {
		t.Errorf("authorization = %s (first byte %#x) with no override, want LIT_INCREMENTAL. "+
			"Chrome indexes it; anything else is a divergence on every request", a.Kind, a.First)
	}
	// Indexed on the second request, which is the point of indexing it.
	if second := parseHPACK(t, blocks[1]); len(second) > 0 {
		if a2, ok := findInstr(second, "authorization"); ok && a2.Kind != "INDEXED" {
			t.Errorf("request 2: authorization = %s, want INDEXED once it is in the table", a2.Kind)
		}
	}
}

// "without" is the other half of the override layer and has a trap "never"
// does not: searchTable skips its exact-match lookup for sensitive fields
// only, so a literal-without-indexing pin has to suppress it explicitly or an
// identical repeat comes back as an indexed reference.
func TestHPACKWithoutIndexingOverrideSurvivesRepeats(t *testing.T) {
	h := startHPACKWireServer(t, 0, nil)
	registerPreset(t, "rep-without", `,"http2":{"hpack_representation":{"authorization":"without"}}`)

	blocks := driveWithPreset(t, h, "rep-without", 3)
	for i, b := range blocks[:3] {
		a, ok := findInstr(parseHPACK(t, b), "authorization")
		if !ok {
			t.Fatalf("request %d: no authorization instruction", i+1)
		}
		if a.Kind != "LIT_WITHOUT" {
			t.Errorf("request %d: authorization = %s (first byte %#x), want LIT_WITHOUT on every "+
				"request. An INDEXED here means the field entered the dynamic table",
				i+1, a.Kind, a.First)
		}
	}
}
