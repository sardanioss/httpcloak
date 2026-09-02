package fingerprint

import (
	"fmt"
	"sort"
	"strings"
)

// KnownPresets returns every registered preset name, sorted.
//
// Both registries: the Go-defined presets and the JSON ones registered at init.
func KnownPresets() []string {
	seen := map[string]bool{}
	for name := range presets {
		seen[name] = true
	}
	customPresets.Range(func(k, _ any) bool {
		if name, ok := k.(string); ok {
			seen[name] = true
		}
		return true
	})
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Suggest returns the registered preset name closest to what was asked for, or
// "" when nothing is close enough to be worth suggesting.
//
// It exists because a mistyped preset name used to resolve to a real preset
// several Chrome versions old, so the request went out with a fingerprint the
// caller never chose and nothing said so. Naming the nearest match turns that
// into a one-line fix.
func Suggest(name string) string {
	if name == "" {
		return ""
	}
	want := strings.ToLower(strings.TrimSpace(name))
	best, bestDist := "", 1<<30
	for _, cand := range KnownPresets() {
		d := editDistance(want, strings.ToLower(cand))
		if d < bestDist {
			best, bestDist = cand, d
		}
	}
	// A suggestion is only useful if it is close. The threshold scales with the
	// name so that "chrome-152-window" suggests chrome-152-windows while a name
	// that shares nothing with any preset suggests nothing at all.
	limit := len(want)/3 + 1
	if bestDist > limit {
		return ""
	}
	return best
}

// UnknownPresetError builds the error a caller sees for a name nothing matches,
// naming the closest preset when there is one and the current default when
// there is not.
func UnknownPresetError(name string) error {
	if s := Suggest(name); s != "" {
		return fmt.Errorf("unknown preset %q, did you mean %q? "+
			"Use fingerprint.KnownPresets() for the full list", name, s)
	}
	// GetStrict, not LookupCustom: chrome-latest is a Go alias rather than a
	// registered JSON preset, so the custom registry does not hold it.
	latest := `"chrome-latest"`
	if p := GetStrict("chrome-latest"); p != nil {
		latest = fmt.Sprintf("%q (currently %s)", "chrome-latest", p.Name)
	}
	return fmt.Errorf("unknown preset %q. Try %s, or fingerprint.KnownPresets() "+
		"for the full list", name, latest)
}

// editDistance is Levenshtein, iterative with two rows.
//
// Chosen over a prefix or substring match because the mistakes people actually
// make are a dropped character, a doubled one, or a transposition, and those are
// exactly what an edit distance ranks well. A substring match would rank
// "chrome-15" above "chrome-152-windows" for the input "chrome-152-window".
func editDistance(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}
