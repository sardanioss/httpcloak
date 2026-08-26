package fingerprint

import (
	"encoding/hex"
	"strings"
	"testing"

	tls "github.com/sardanioss/utls"
)

// chrome152Anchors is the set from six Chrome 152 captures across two hosts and
// both transports, taken in one browser session.
//
// It was 32 when Chrome 152 shipped and is 28 now. The Chrome Root Store is
// component-updated, so the set moves without a browser version bump, which is
// why this list lives in preset JSON rather than in code. Four Google Trust
// Services IDs were dropped and none added: d6790902, d6790903, d6790909 and
// d679090e.
//
// The order below is canonical only; every capture carried a different one.
var chrome152Anchors = []string{
	"82df130201", "82df130206", "82df13020d", "82df13020e", "82df13020f",
	"82df130212", "82df130213", "82df130214",
	"839a648c9b2d0107", "839a648c9b2d0108", "839a648c9b2d0109",
	"839a648c9b2d010a", "839a648c9b2d010b", "839a648c9b2d010c",
	"839a648c9b2d010d", "839a648c9b2d0112", "839a648c9b2d0113",
	"d6790901", "d6790904", "d6790905", "d6790906", "d6790907",
	"d6790908", "d679090a", "d679090b", "d679090c", "d679090d", "d679090f",
}

func anchorBytes(t *testing.T) [][]byte {
	t.Helper()
	out := make([][]byte, len(chrome152Anchors))
	for i, h := range chrome152Anchors {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("fixture %q: %v", h, err)
		}
		out[i] = b
	}
	return out
}

func tailSpec() []tls.TLSExtension {
	return []tls.TLSExtension{
		&tls.UtlsGREASEExtension{},
		&tls.SNIExtension{},
		&tls.SignatureAlgorithmsExtension{},
		&tls.KeyShareExtension{},
		&tls.UtlsGREASEExtension{},
		&tls.UtlsPaddingExtension{},
	}
}

// The extension lands ahead of the trailing run that may not move.
//
// GREASE brackets the list, padding sizes the record and RFC 8446 4.2.11 puts
// pre_shared_key last, so anything appended after those is pinned to the final
// slot. BoringSSL marks trust_anchors out_compressible, which means it takes
// part in the ordinary extension permutation like any other, and it cannot do
// that from a pinned slot.
func TestApplyTrustAnchorsInsertsBeforeThePinnedTail(t *testing.T) {
	exts := tailSpec()
	ApplyTrustAnchors(&exts, anchorBytes(t))

	if len(exts) != 7 {
		t.Fatalf("got %d extensions, want 7", len(exts))
	}
	at := -1
	for i, e := range exts {
		if _, ok := e.(*tls.TrustAnchorsExtension); ok {
			at = i
		}
	}
	if at != 4 {
		t.Fatalf("trust_anchors landed at index %d, want 4, ahead of the "+
			"trailing GREASE and padding", at)
	}
	if _, ok := exts[5].(*tls.UtlsGREASEExtension); !ok {
		t.Error("the trailing GREASE extension moved")
	}
	if _, ok := exts[6].(*tls.UtlsPaddingExtension); !ok {
		t.Error("the padding extension is no longer last")
	}
}

// pre_shared_key is pinned last too, so the extension goes ahead of it.
func TestApplyTrustAnchorsRespectsPreSharedKey(t *testing.T) {
	exts := append(tailSpec(), &tls.FakePreSharedKeyExtension{})
	ApplyTrustAnchors(&exts, anchorBytes(t))
	if _, ok := exts[len(exts)-1].(*tls.FakePreSharedKeyExtension); !ok {
		t.Fatal("pre_shared_key is no longer last, which RFC 8446 4.2.11 requires")
	}
}

// A spec that already carries the extension takes the preset's list rather
// than ending up with two.
func TestApplyTrustAnchorsReplacesRatherThanDuplicating(t *testing.T) {
	exts := tailSpec()
	exts = append(exts[:3], append([]tls.TLSExtension{
		&tls.TrustAnchorsExtension{TrustAnchors: [][]byte{{0x01}}},
	}, exts[3:]...)...)

	ApplyTrustAnchors(&exts, anchorBytes(t))

	var found int
	for _, e := range exts {
		if ta, ok := e.(*tls.TrustAnchorsExtension); ok {
			found++
			if len(ta.TrustAnchors) != 28 {
				t.Errorf("the extension carries %d identifiers, want the preset's 28",
					len(ta.TrustAnchors))
			}
		}
	}
	if found != 1 {
		t.Fatalf("the spec carries %d trust_anchors extensions, want 1", found)
	}
}

// An empty list is a no-op, so no preset starts sending the extension.
func TestApplyTrustAnchorsEmptyIsANoOp(t *testing.T) {
	exts := tailSpec()
	ApplyTrustAnchors(&exts, nil)
	if len(exts) != 6 {
		t.Fatalf("an empty list changed the spec: %d extensions, want 6", len(exts))
	}
}

// The JSON key round-trips through describe, and the loader rejects an
// identifier that cannot go on the wire.
func TestTrustAnchorsJSONRoundTrip(t *testing.T) {
	spec := `{"version":1,"preset":{"name":"ta-rt","based_on":"chrome-151-windows",
		"tls":{"trust_anchors":["` + strings.Join(chrome152Anchors, `","`) + `"]}}}`

	p, err := LoadAndBuildPresetFromJSON([]byte(spec))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(p.TrustAnchors) != 28 {
		t.Fatalf("loaded %d identifiers, want 28", len(p.TrustAnchors))
	}
	if err := RegisterStrict(p.Name, p); err != nil {
		t.Fatalf("register: %v", err)
	}
	defer Unregister(p.Name)

	described, err := Describe(p.Name)
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if !strings.Contains(described, `"trust_anchors"`) {
		t.Fatal("describe dropped trust_anchors, so a round-trip loses the extension")
	}
	rt, err := LoadAndBuildPresetFromJSON([]byte(described))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(rt.TrustAnchors) != len(p.TrustAnchors) {
		t.Fatalf("round-trip left %d identifiers, want %d", len(rt.TrustAnchors), len(p.TrustAnchors))
	}
	for i := range p.TrustAnchors {
		if hex.EncodeToString(rt.TrustAnchors[i]) != hex.EncodeToString(p.TrustAnchors[i]) {
			t.Errorf("identifier %d is %x after round-trip, want %x",
				i, rt.TrustAnchors[i], p.TrustAnchors[i])
		}
	}

	// A preset that sets none does not advertise the key.
	base, err := Describe("chrome-151-windows")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(base, `"trust_anchors"`) {
		t.Error("chrome-151-windows advertises trust_anchors; only Chrome 152 sends it")
	}
}

// Each identifier carries a one-byte length, so one that cannot fit is a load
// error rather than a truncated extension on the wire.
func TestTrustAnchorsRejectsUnusableIdentifiers(t *testing.T) {
	for name, list := range map[string]string{
		"not hex":  `["zz"]`,
		"empty":    `[""]`,
		"too long": `["` + strings.Repeat("ab", 256) + `"]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadAndBuildPresetFromJSON([]byte(
				`{"version":1,"preset":{"name":"ta-bad","based_on":"chrome-151-windows",
				  "tls":{"trust_anchors":` + list + `}}}`))
			if err == nil {
				t.Fatal("the loader accepted an identifier it cannot put on the wire")
			}
		})
	}
}
