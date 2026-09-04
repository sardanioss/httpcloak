package transport

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	http "github.com/sardanioss/http"
)

func TestBuildHeadersMap(t *testing.T) {
	h := http.Header{
		"Content-Type":       {"application/json;charset=utf-8"},
		"set-cookie":         {"a=1; Path=/", "b=2; Path=/"},
		"x-WEIRD-Key":        {"v"},
		"X-Empty":            {},
		http.HeaderOrderKey:  {"content-type", "set-cookie"},
		http.PHeaderOrderKey: {":method"},
	}
	want := map[string][]string{
		"content-type": {"application/json;charset=utf-8"},
		"set-cookie":   {"a=1; Path=/", "b=2; Path=/"},
		"x-weird-key":  {"v"},
		"x-empty":      {},
	}
	if got := buildHeadersMap(h); !reflect.DeepEqual(got, want) {
		t.Errorf("buildHeadersMap(%v) = %v, want %v", h, got, want)
	}
}

// Every entry is carved out of one shared backing array; each must keep the
// same isolation that a separate copy per entry gave.
func TestBuildHeadersMapIsolation(t *testing.T) {
	h := http.Header{
		"Set-Cookie":   {"a=1", "b=2"},
		"Content-Type": {"application/json"},
		"X-Extra":      {"one"},
	}
	m := buildHeadersMap(h)

	// Appending to one entry must not disturb its neighbors in the backing.
	before := map[string][]string{}
	for k, v := range m {
		before[k] = append([]string(nil), v...)
	}
	m["set-cookie"] = append(m["set-cookie"], "c=3")
	for _, k := range []string{"content-type", "x-extra"} {
		if !reflect.DeepEqual(m[k], before[k]) {
			t.Errorf("after append to set-cookie, m[%q] = %v, want %v", k, m[k], before[k])
		}
	}

	// Writing an element must not reach back into the source header.
	m["content-type"][0] = "mutated"
	if h["Content-Type"][0] != "application/json" {
		t.Errorf(`h["Content-Type"][0] = %q, want "application/json"`, h["Content-Type"][0])
	}

	// Mutating the source must not show through in the map.
	h["X-Extra"][0] = "changed"
	if m["x-extra"][0] != "one" {
		t.Errorf(`m["x-extra"][0] = %q, want "one"`, m["x-extra"][0])
	}
}

func TestLowerHeaderNameMatchesToLower(t *testing.T) {
	names := []string{
		"", "content-type", "Content-Type", "CONTENT-TYPE", "x-üpper",
		"X-Über", "set-cookie", "Set-Cookie", "hEaDeR", "123-456",
	}
	alpha := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789")
	r := rand.New(rand.NewPCG(21, 22))
	for range 2000 {
		var b strings.Builder
		for range 1 + r.IntN(24) {
			b.WriteRune(alpha[r.IntN(len(alpha))])
		}
		names = append(names, b.String())
	}
	for _, name := range names {
		if got, want := lowerHeaderName(name), strings.ToLower(name); got != want {
			t.Errorf("lowerHeaderName(%q) = %q, want %q", name, got, want)
		}
	}
}

// The value slices are carved out of one array sized to the header count, so
// a response carrying more values than headers reallocates it midway. The
// entries handed out before that point keep pointing into the old array and
// must still read back correctly.
func TestBuildHeadersMapSurvivesBackingGrowth(t *testing.T) {
	h := http.Header{}
	want := map[string][]string{}
	for i := range 12 {
		name := fmt.Sprintf("X-Multi-%02d", i)
		// Three values each against one array slot per header: the backing
		// runs out on the first entry and grows repeatedly after that.
		values := []string{
			fmt.Sprintf("%d-a", i),
			fmt.Sprintf("%d-b", i),
			fmt.Sprintf("%d-c", i),
		}
		h[name] = values
		want[strings.ToLower(name)] = values
	}

	got := buildHeadersMap(h)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildHeadersMap over %d multi-valued headers = %v, want %v", len(h), got, want)
	}
	// Each entry must still own its capacity, whichever array it landed in.
	for name, values := range got {
		if cap(values) != len(values) {
			t.Errorf("m[%q] has cap %d for len %d; appending would reach into a neighbor",
				name, cap(values), len(values))
		}
	}
}

// A cached name must not be the caller's string. Response header names are
// sliced out of read buffers, so retaining one pins the whole buffer for the
// life of the process.
func TestLowerHeaderNameDoesNotRetainCallerStrings(t *testing.T) {
	// A name whose only non-lowercase byte is non-ASCII: the fast path
	// rejects it, and strings.ToLower has nothing to fold, so it returns the
	// input unchanged. That is the case that would otherwise be cached as is.
	// The cache is package global and other tests fill it past its cap, which
	// would make this one pass vacuously.
	lowerHeaderNameCache.Clear()
	lowerHeaderNameCacheSize.Store(0)

	buffer := "leading padding that stands in for a decode buffer x-ünique-probe trailing"
	name := buffer[len("leading padding that stands in for a decode buffer ") : len(buffer)-len(" trailing")]
	if name != "x-ünique-probe" {
		t.Fatalf("test fixture sliced %q, want %q", name, "x-ünique-probe")
	}
	if got := lowerHeaderName(name); got != name {
		t.Fatalf("lowerHeaderName(%q) = %q, want it unchanged", name, got)
	}

	cached, ok := lowerHeaderNameCache.Load(name)
	if !ok {
		t.Fatal("the name was not cached, so this test is no longer covering anything")
	}
	if unsafe.StringData(cached.(string)) == unsafe.StringData(name) {
		t.Error("the cached value is the caller's string; it pins the buffer the name was sliced from")
	}
	// The key is retained for as long as the entry lives, so it needs a copy too.
	found := false
	lowerHeaderNameCache.Range(func(k, _ any) bool {
		if key := k.(string); key == name {
			found = true
			if unsafe.StringData(key) == unsafe.StringData(name) {
				t.Error("the cached key is the caller's string; it pins the buffer the name was sliced from")
			}
			return false
		}
		return true
	})
	if !found {
		t.Error("cached key not found by Range")
	}
}
