package transport

import (
	"strings"
	"testing"

	http "github.com/sardanioss/http"
)

// Headers that a preset does not reserve a slot for used to fall through to Go
// map iteration in both the HTTP/1.1 writer and the HPACK encoder, which
// randomises its order on every range. That produced a different header order
// on every request — a fingerprint no browser emits. These tests pin the
// contract that CompleteHeaderOrder names every header exactly once, in a
// stable order.

func TestCompleteHeaderOrder_UnreservedHeadersAreSortedNotRandom(t *testing.T) {
	presetOrder := []string{"user-agent", "accept", "accept-encoding"}
	header := http.Header{
		"User-Agent": {"chrome"},
		"Accept":     {"*/*"},
		"X-Delta":    {"4"},
		"X-Bravo":    {"2"},
		"X-Alpha":    {"1"},
		"X-Charlie":  {"3"},
	}

	got := CompleteHeaderOrder(presetOrder, presetOrder, header, nil)
	want := []string{
		"user-agent", "accept", "accept-encoding",
		"x-alpha", "x-bravo", "x-charlie", "x-delta",
	}
	assertOrder(t, got, want)
}

func TestCompleteHeaderOrder_IsStableAcrossCalls(t *testing.T) {
	presetOrder := []string{"user-agent", "accept"}
	header := http.Header{
		"User-Agent": {"chrome"},
		"X-Delta":    {"4"},
		"X-Bravo":    {"2"},
		"X-Alpha":    {"1"},
		"X-Charlie":  {"3"},
		"X-Echo":     {"5"},
		"X-Foxtrot":  {"6"},
	}

	first := strings.Join(CompleteHeaderOrder(presetOrder, presetOrder, header, nil), ",")
	for i := 0; i < 200; i++ {
		got := strings.Join(CompleteHeaderOrder(presetOrder, presetOrder, header, nil), ",")
		if got != first {
			t.Fatalf("order varied between calls:\n first: %s\n call %d: %s", first, i, got)
		}
	}
}

// A partial SetHeaderOrder used to place the named headers and then scramble
// every preset header it did not name, so reaching for the documented ordering
// control made the fingerprint worse. The named list is now a prefix override:
// named first, then the preset's own table, then the rest.
func TestCompleteHeaderOrder_PartialCustomOrderKeepsPresetTable(t *testing.T) {
	presetOrder := []string{"sec-ch-ua", "user-agent", "accept", "accept-encoding", "accept-language"}
	custom := []string{"x-delta", "user-agent", "accept"}
	header := http.Header{
		"Sec-Ch-Ua":       {"chrome"},
		"User-Agent":      {"chrome"},
		"Accept":          {"*/*"},
		"Accept-Encoding": {"gzip"},
		"Accept-Language": {"en"},
		"X-Delta":         {"4"},
		"X-Alpha":         {"1"},
	}

	got := CompleteHeaderOrder(custom, presetOrder, header, nil)
	want := []string{
		"x-delta", "user-agent", "accept", // caller's list, in the caller's order
		"sec-ch-ua", "accept-encoding", "accept-language", // preset table, preset order
		"x-alpha", // still unplaced, sorted
	}
	assertOrder(t, got, want)
}

// The ordering keys are internal control entries. Leaking one onto the wire
// would be a header no browser sends.
func TestCompleteHeaderOrder_ExcludesOrderingKeys(t *testing.T) {
	header := http.Header{
		"Accept":             {"*/*"},
		http.HeaderOrderKey:  {"accept"},
		http.PHeaderOrderKey: {":method"},
		"X-Alpha":            {"1"},
	}

	for _, name := range CompleteHeaderOrder([]string{"accept"}, []string{"accept"}, header, nil) {
		if strings.EqualFold(name, http.HeaderOrderKey) || strings.EqualFold(name, http.PHeaderOrderKey) {
			t.Errorf("ordering key %q leaked into the header order", name)
		}
	}
}

func TestCompleteHeaderOrder_MergesUserHeadersAndDeduplicates(t *testing.T) {
	presetOrder := []string{"user-agent"}
	header := http.Header{"User-Agent": {"chrome"}, "X-Bravo": {"2"}}
	// Same header in both sources, differing case; must appear exactly once.
	userHeaders := map[string][]string{"X-BRAVO": {"2"}, "x-alpha": {"1"}}

	got := CompleteHeaderOrder(presetOrder, presetOrder, header, userHeaders)
	assertOrder(t, got, []string{"user-agent", "x-alpha", "x-bravo"})

	seen := map[string]int{}
	for _, name := range got {
		seen[name]++
		if name != strings.ToLower(name) {
			t.Errorf("header order entry %q is not lowercased", name)
		}
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("header %q appears %d times in the order", name, n)
		}
	}
}

func assertOrder(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("header order mismatch\n got: %s\nwant: %s",
			strings.Join(got, " → "), strings.Join(want, " → "))
	}
}
