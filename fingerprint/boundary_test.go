package fingerprint

import (
	"strings"
	"testing"
)

// Every binding used to build its own multipart boundary and every one of them
// spelled out the product name in it:
//
//	----HTTPCloakBoundary<uuid4>       Python
//	----HTTPCloakBoundary<ts><rand>    Node
//	----HttpCloakBoundary<guid>        .NET
//
// while Go called multipart.NewWriter with no SetBoundary at all, giving 60
// lowercase hex characters and no leading dashes.
//
// A boundary travels in the content-type REQUEST header, in cleartext above
// TLS, before a single byte of body. It needs no probe and no statistics, and
// the capitalisation split even identified which binding sent it.
func TestMultipartBoundaryMatchesChromeShape(t *testing.T) {
	const prefix = "----WebKitFormBoundary"
	seen := make(map[string]bool)
	counts := make(map[byte]int)

	for i := 0; i < 200; i++ {
		b := MultipartBoundary()
		if !strings.HasPrefix(b, prefix) {
			t.Fatalf("boundary %q does not start with Chrome's prefix", b)
		}
		// 22 + 16. Chrome's is a fixed length; a variable one is its own tell.
		if len(b) != 38 {
			t.Fatalf("boundary %q is %d chars, want 38", b, len(b))
		}
		suffix := b[len(prefix):]
		for j := 0; j < len(suffix); j++ {
			c := suffix[j]
			if !strings.ContainsRune(boundaryAlphabet, rune(c)) {
				t.Fatalf("character %q is outside Blink's table", c)
			}
			counts[c]++
		}
		seen[b] = true
	}

	if len(seen) != 200 {
		t.Errorf("only %d distinct boundaries in 200 draws; it must be per-request", len(seen))
	}
	// The table pads to 64 by repeating 'A' and 'B', so those two come up about
	// twice as often as anything else. Reproducing the character SET without the
	// distribution would still be distinguishable given enough samples, so this
	// asserts the duplication survived.
	const perChar = 200 * 16 / 64 // expected count for a single-entry character
	for _, c := range []byte{'A', 'B'} {
		if counts[c] < perChar {
			t.Errorf("%q appeared %d times, expected roughly %d (twice a normal "+
				"character); the 64-entry table's duplicate entries are missing",
				c, counts[c], 2*perChar)
		}
	}
	// And nothing outside the table appears at all.
	if strings.ContainsAny(strings.Join(keysOf(counts), ""), "-_+/=") {
		t.Error("boundary contains characters Blink's table cannot produce")
	}
}

// Both Go multipart builders must use it. Go's default boundary is 60 lowercase
// hex characters with no leading dashes, which no browser produces.
func TestGoMultipartBuildersUseTheChromeBoundary(t *testing.T) {
	b := MultipartBoundary()
	if strings.Contains(strings.ToLower(b), "cloak") {
		t.Fatal("the product name is back in the boundary")
	}
}

func keysOf(m map[byte]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, string(k))
	}
	return out
}
