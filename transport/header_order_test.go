package transport

import (
	"bufio"
	"bytes"
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

// writeH1Order runs the HTTP/1.1 header writer over req and returns the header
// names in the order they hit the wire, lowercased. The writer does not touch
// its receiver, so a zero-value transport is enough and the test stays off the
// network.
func writeH1Order(t *testing.T, req *http.Request) []string {
	t.Helper()
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	(&HTTP1Transport{}).writeHeadersInOrder(bw, req, false)
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	var names []string
	for _, line := range strings.Split(buf.String(), "\r\n") {
		if line == "" {
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		names = append(names, strings.ToLower(strings.TrimSpace(name)))
	}
	return names
}

// The HTTP/1.1 writer's remainder loop is the fallback for any request that
// reaches it without a complete order list. It used to range over req.Header
// directly, and Go randomises map iteration on every range, so it put a
// different header order on the wire for each request. applyPresetHeaders now
// names every header up front and normally leaves this loop empty — this pins
// the fallback, so dropping the sort in writeHeadersInOrder cannot quietly
// restore the per-request randomisation.
func TestWriteHeadersInOrder_RemainderIsSortedNotRandom(t *testing.T) {
	newReq := func() *http.Request {
		return &http.Request{
			Method: "GET",
			Header: http.Header{
				"X-Delta":   {"4"},
				"X-Bravo":   {"2"},
				"X-Alpha":   {"1"},
				"X-Charlie": {"3"},
				"X-Echo":    {"5"},
				"X-Foxtrot": {"6"},
			},
		}
	}

	want := []string{"x-alpha", "x-bravo", "x-charlie", "x-delta", "x-echo", "x-foxtrot"}
	first := writeH1Order(t, newReq())
	assertOrder(t, first, want)

	// Randomised map iteration only shows up across repeated ranges.
	for i := 0; i < 200; i++ {
		got := writeH1Order(t, newReq())
		if strings.Join(got, ",") != strings.Join(first, ",") {
			t.Fatalf("h1 wire order varied between requests:\n first: %s\n run %d: %s",
				strings.Join(first, " → "), i, strings.Join(got, " → "))
		}
	}
}

// The two halves of the fix have to compose: CompleteHeaderOrder names every
// header, so by the time the writer runs its remainder loop there is nothing
// left for it to iterate over, and the wire order is exactly the order list
// (minus the names the request does not actually carry).
func TestWriteHeadersInOrder_CompleteOrderLeavesNoRemainder(t *testing.T) {
	presetOrder := []string{"user-agent", "accept", "accept-encoding"}
	header := http.Header{
		"User-Agent": {"chrome"},
		"Accept":     {"*/*"},
		"X-Delta":    {"4"},
		"X-Alpha":    {"1"},
	}
	header[http.HeaderOrderKey] = CompleteHeaderOrder(nil, presetOrder, header, nil)

	// accept-encoding is reserved by the preset but absent from the request, so
	// it is named in the order list and skipped on the wire.
	assertOrder(t, writeH1Order(t, &http.Request{Method: "GET", Header: header}),
		[]string{"user-agent", "accept", "x-alpha", "x-delta"})
}
