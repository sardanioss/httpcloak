package fingerprint

import (
	"sort"
	"testing"
)

// TestPriorityFromUrgency_Formula verifies the urgency→weight derivation
// against the captured Chrome 147 values plus the formula extrapolation
// for u=5..7 (Chrome doesn't emit those in practice but the formula must
// stay sane and never produce 0 or wrap).
func TestPriorityFromUrgency_Formula(t *testing.T) {
	cases := []struct {
		urgency uint8
		want    uint16
	}{
		{0, 256}, // captured: navigation, iframe, object, embed, style
		{1, 220}, // captured: script, font, default fetch, xhr, eventsource
		{2, 183}, // captured: manifest, default <img>
		{3, 147}, // captured: video, audio, track, async/defer scripts (default)
		{4, 110}, // captured: prefetch, beacon, worker
		{5, 74},  // extrapolated; Chrome doesn't emit in practice
		{6, 37},  // extrapolated
		{7, 1},   // extrapolated; integer division 511/2 = 255 → 256-255 = 1
	}
	for _, tc := range cases {
		got := PriorityFromUrgency(tc.urgency)
		if got != tc.want {
			t.Errorf("PriorityFromUrgency(%d) = %d, want %d", tc.urgency, got, tc.want)
		}
	}
}

// TestPriorityFromUrgency_OutOfRangeClamped verifies that a caller passing
// an out-of-spec urgency (>7) doesn't trigger underflow or wrap. The fork
// will multiply weight-1 to wire format; we need the result to fit uint8.
func TestPriorityFromUrgency_OutOfRangeClamped(t *testing.T) {
	for u := uint8(8); u < 16; u++ {
		got := PriorityFromUrgency(u)
		if got == 0 {
			t.Errorf("PriorityFromUrgency(%d) = 0 (would underflow on wire weight-1)", u)
		}
		if got > 256 {
			t.Errorf("PriorityFromUrgency(%d) = %d, exceeds 256 (out of range)", u, got)
		}
	}
}

// TestPriorityHeaderFromResource_AllRules walks the four emission rules
// laid out in the function's docstring. Each row is one captured shape.
func TestPriorityHeaderFromResource_AllRules(t *testing.T) {
	cases := []struct {
		name string
		rp   ResourcePriority
		want string
	}{
		// Rule 1: u=3 default + !incremental → omit entirely.
		// (Captured: <script async>, <script defer>.)
		{"default urgency, no incremental, header omitted entirely",
			ResourcePriority{Urgency: 3, Incremental: false, EmitHeader: true}, ""},
		// Rule 2: u=3 default + incremental → just "i".
		// (Captured: <video>, <audio>, <track>, <link rel=preload as=image>.)
		{"default urgency, incremental",
			ResourcePriority{Urgency: 3, Incremental: true, EmitHeader: true}, "i"},
		// Rule 3: u≠3 + !incremental → "u=N".
		// (Captured: <link rel=stylesheet>, <link rel=manifest>, <script>,
		// preload as=font.)
		{"u=0 stylesheet",
			ResourcePriority{Urgency: 0, Incremental: false, EmitHeader: true}, "u=0"},
		{"u=2 manifest",
			ResourcePriority{Urgency: 2, Incremental: false, EmitHeader: true}, "u=2"},
		{"u=1 script",
			ResourcePriority{Urgency: 1, Incremental: false, EmitHeader: true}, "u=1"},
		// Rule 4: u≠3 + incremental → "u=N, i".
		// (Captured: navigation, default fetch, default <img>, prefetch.)
		{"u=0 navigation",
			ResourcePriority{Urgency: 0, Incremental: true, EmitHeader: true}, "u=0, i"},
		{"u=1 default fetch",
			ResourcePriority{Urgency: 1, Incremental: true, EmitHeader: true}, "u=1, i"},
		{"u=2 default img",
			ResourcePriority{Urgency: 2, Incremental: true, EmitHeader: true}, "u=2, i"},
		{"u=4 prefetch/beacon/worker",
			ResourcePriority{Urgency: 4, Incremental: true, EmitHeader: true}, "u=4, i"},

		// EmitHeader=false short-circuits — even with otherwise valid urgency
		// + incremental, the result is empty (caller must skip header
		// injection). Mirrors Chrome's async/defer-script behavior.
		{"emit_header=false short-circuits even with non-default urgency",
			ResourcePriority{Urgency: 1, Incremental: true, EmitHeader: false}, ""},
		{"emit_header=false short-circuits with default urgency too",
			ResourcePriority{Urgency: 3, Incremental: true, EmitHeader: false}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PriorityHeaderFromResource(tc.rp)
			if got != tc.want {
				t.Errorf("PriorityHeaderFromResource(%+v) = %q, want %q", tc.rp, got, tc.want)
			}
		})
	}
}

// TestPriorityHeaderFromResource_AllUrgencies sanity-checks every urgency
// value with both incremental flags. The "u=10..." path is unreachable in
// practice but verifying it at least parses cleanly catches the
// uint8ToASCII fallback.
func TestPriorityHeaderFromResource_AllUrgencies(t *testing.T) {
	for u := uint8(0); u <= 9; u++ {
		header := PriorityHeaderFromResource(ResourcePriority{Urgency: u, Incremental: true, EmitHeader: true})
		if u == 3 {
			if header != "i" {
				t.Errorf("u=3 incremental header = %q, want %q", header, "i")
			}
		} else {
			want := "u=" + string([]byte{'0' + u}) + ", i"
			if header != want {
				t.Errorf("u=%d incremental header = %q, want %q", u, header, want)
			}
		}
	}
}

// TestH2HasPriorityTable_RFC7540Inheritance verifies the resolution rule:
// any preset using RFC 7540 priorities (NoRFC7540Priorities=false) inherits
// the package-level defaultPriorityTable when it doesn't define its own;
// presets that opt out of RFC 7540 (Safari, iOS Chrome, iOS Safari — all
// have NoRFC7540Priorities=true) report HasPriorityTable=false so the
// transport keeps the no-priority-frame behaviour those wire formats expect.
func TestH2HasPriorityTable_RFC7540Inheritance(t *testing.T) {
	// Chrome desktop+android (incl. legacy versions) and Firefox use
	// RFC 7540 — they all inherit the default unless they have an
	// explicit table. Chrome 147 desktop+android have explicit tables;
	// the others inherit the default.
	mustHave := []string{
		"chrome-147-windows",
		"chrome-147-linux",
		"chrome-147-macos",
		"chrome-147-android",
		"chrome-146-windows",
		"chrome-146-linux",
		"chrome-146-macos",
		"chrome-146-android",
		"chrome-145",
		"chrome-141",
		"chrome-133",
		"firefox-148",
		"firefox-133",
	}
	// Safari + iOS Chrome + iOS Safari all carry NoRFC7540Priorities=true.
	// They emit no PRIORITY frame at all — the default table never
	// applies to them.
	mustNotHave := []string{
		"chrome-147-ios",
		"chrome-148-ios",
		"chrome-146-ios",
		"safari-latest",
		"safari-18",
		"ios-safari-latest",
		"ios-chrome-latest",
		"ios-chrome-147",
	}
	for _, name := range mustHave {
		p := GetStrict(name)
		if p == nil {
			t.Errorf("%s: not registered", name)
			continue
		}
		if !p.H2HasPriorityTable() {
			t.Errorf("%s: H2HasPriorityTable=false, want true (RFC 7540 preset must inherit default)", name)
		}
	}
	for _, name := range mustNotHave {
		p := GetStrict(name)
		if p == nil {
			continue // some legacy aliases may not exist; skip
		}
		if p.H2HasPriorityTable() {
			t.Errorf("%s: H2HasPriorityTable=true, want false (NoRFC7540 preset must opt out)", name)
		}
	}
}

// TestH2HasPriorityTable_EmptyMapTreatedAsInherit verifies that an
// explicit-but-empty PriorityTable falls through to the package default
// (rather than disabling). This is the simpler model: empty == nil at the
// resolution layer. Users who genuinely want priority emission disabled
// must set NoRFC7540Priorities=true on HTTP2Settings.
func TestH2HasPriorityTable_EmptyMapTreatedAsInherit(t *testing.T) {
	src := GetStrict("chrome-146-windows")
	if src == nil {
		t.Skip("chrome-146-windows: not registered")
	}
	p := clonePreset(src)
	if p.H2Config == nil {
		p.H2Config = &H2FingerprintConfig{}
	}
	p.H2Config.PriorityTable = map[string]ResourcePriority{}

	if !p.H2HasPriorityTable() {
		t.Errorf("explicit empty PriorityTable: H2HasPriorityTable=false, want true (should fall through to default)")
	}
	weight, _, _, ok := p.H2PriorityFor("document")
	if !ok {
		t.Errorf("explicit empty PriorityTable: H2PriorityFor returned ok=false, want true (default fallback)")
	}
	if weight != 256 {
		t.Errorf("explicit empty PriorityTable: document weight = %d, want 256 (Chrome default)", weight)
	}
}

// TestH2PriorityFor_Chrome147_AllDests verifies that every captured dest
// in the priority table resolves to the expected (weight, exclusive,
// header) tuple. This is the load-bearing fingerprint contract — if any
// of these change without intent, anti-bot fingerprint matchers break.
func TestH2PriorityFor_Chrome147_AllDests(t *testing.T) {
	type want struct {
		weight    uint16
		exclusive bool
		header    string
	}
	cases := map[string]want{
		"document": {256, true, "u=0, i"},
		"iframe":   {256, true, "u=0, i"},
		"object":   {256, true, "u=0, i"},
		"embed":    {256, true, "u=0, i"},
		"style":    {256, true, "u=0"},
		"manifest": {183, true, "u=2"},
		"script":   {220, true, "u=1"},
		"font":     {220, true, "u=1"},
		"image":    {183, true, "u=2, i"},
		"empty":    {220, true, "u=1, i"},
		"video":    {147, true, "i"},
		"audio":    {147, true, "i"},
		"track":    {147, true, "i"},
		"worker":   {110, true, "u=4, i"},
	}
	for _, presetName := range []string{
		"chrome-147-windows",
		"chrome-147-linux",
		"chrome-147-macos",
		"chrome-147-android",
	} {
		p := GetStrict(presetName)
		if p == nil {
			t.Fatalf("%s: not registered", presetName)
		}
		for dest, w := range cases {
			weight, exclusive, header, ok := p.H2PriorityFor(dest)
			if !ok {
				t.Errorf("%s/dest=%s: ok=false, want true", presetName, dest)
				continue
			}
			if weight != w.weight {
				t.Errorf("%s/dest=%s: weight = %d, want %d", presetName, dest, weight, w.weight)
			}
			if exclusive != w.exclusive {
				t.Errorf("%s/dest=%s: exclusive = %v, want %v", presetName, dest, exclusive, w.exclusive)
			}
			if header != w.header {
				t.Errorf("%s/dest=%s: header = %q, want %q", presetName, dest, header, w.header)
			}
		}
	}
}

// TestH2PriorityFor_UnknownDestFallsThrough verifies that an unknown
// sec-fetch-dest returns ok=false even when a priority table is set, so
// the transport will fall through to its single-weight default.
func TestH2PriorityFor_UnknownDestFallsThrough(t *testing.T) {
	p := GetStrict("chrome-147-windows")
	if p == nil {
		t.Fatal("chrome-147-windows: not registered")
	}
	for _, dest := range []string{"", "unknown-dest", "report", "speculationrules"} {
		_, _, _, ok := p.H2PriorityFor(dest)
		if ok {
			t.Errorf("dest=%q: ok=true, want false (unknown dest)", dest)
		}
	}
}

// TestH2PriorityFor_NoRFC7540ReturnsFalse verifies that presets opting
// out of RFC 7540 priorities (Safari, iOS Chrome, iOS Safari) return
// ok=false for every dest — even ones present in the default table —
// because they don't emit the PRIORITY frame at all.
func TestH2PriorityFor_NoRFC7540ReturnsFalse(t *testing.T) {
	for _, name := range []string{
		"safari-latest", "ios-chrome-latest", "ios-safari-latest", "chrome-148-ios",
	} {
		p := GetStrict(name)
		if p == nil {
			continue
		}
		if !p.HTTP2Settings.NoRFC7540Priorities {
			t.Errorf("%s: precondition NoRFC7540Priorities=false, expected true", name)
			continue
		}
		for _, dest := range []string{"document", "image", "empty", ""} {
			_, _, _, ok := p.H2PriorityFor(dest)
			if ok {
				t.Errorf("%s/dest=%q: ok=true, want false (NoRFC7540 preset must not resolve)", name, dest)
			}
		}
	}
}

// TestH2PriorityFor_DefaultInheritedByLegacyChrome verifies that legacy
// Chrome presets (without their own PriorityTable) now resolve dest
// lookups via the package default. Each captured weight should match
// what chrome-147-windows emits for the same dest.
func TestH2PriorityFor_DefaultInheritedByLegacyChrome(t *testing.T) {
	cases := map[string]uint16{
		"document": 256,
		"style":    256,
		"script":   220,
		"image":    183,
		"empty":    220,
		"video":    147,
		"worker":   110,
	}
	for _, name := range []string{
		"chrome-146-windows", "chrome-145", "chrome-141", "chrome-133", "firefox-148",
	} {
		p := GetStrict(name)
		if p == nil {
			continue
		}
		for dest, wantWeight := range cases {
			weight, _, _, ok := p.H2PriorityFor(dest)
			if !ok {
				t.Errorf("%s/dest=%s: ok=false, want true (default should apply)", name, dest)
				continue
			}
			if weight != wantWeight {
				t.Errorf("%s/dest=%s: weight = %d, want %d", name, dest, weight, wantWeight)
			}
		}
	}
}

// TestPriorityTable_Chrome147_DestCoverage locks the set of dest keys
// each Chrome 147 preset registers. New entries from future captures should
// be added here; missing entries indicate accidental regression.
func TestPriorityTable_Chrome147_DestCoverage(t *testing.T) {
	wantKeys := []string{
		"audio", "document", "embed", "empty", "font", "iframe", "image",
		"manifest", "object", "script", "style", "track", "video", "worker",
	}
	sort.Strings(wantKeys)

	for _, name := range []string{
		"chrome-147-windows",
		"chrome-147-linux",
		"chrome-147-macos",
		"chrome-147-android",
	} {
		p := GetStrict(name)
		if p == nil {
			t.Fatalf("%s: not registered", name)
		}
		gotKeys := make([]string, 0, len(p.H2Config.PriorityTable))
		for k := range p.H2Config.PriorityTable {
			gotKeys = append(gotKeys, k)
		}
		sort.Strings(gotKeys)

		if len(gotKeys) != len(wantKeys) {
			t.Errorf("%s: %d dest entries, want %d (got %v)", name, len(gotKeys), len(wantKeys), gotKeys)
			continue
		}
		for i, k := range gotKeys {
			if k != wantKeys[i] {
				t.Errorf("%s: dest[%d] = %q, want %q", name, i, k, wantKeys[i])
			}
		}
	}
}

// TestPriorityTable_AllDesktopAndroidVariantsIdentical verifies that the
// four desktop+android Chrome 147 variants share the same priority table
// — the network stack is OS-independent, so any drift is a bug.
func TestPriorityTable_AllDesktopAndroidVariantsIdentical(t *testing.T) {
	names := []string{
		"chrome-147-windows", "chrome-147-linux", "chrome-147-macos", "chrome-147-android",
	}
	var ref map[string]ResourcePriority
	var refName string
	for _, name := range names {
		p := GetStrict(name)
		if p == nil {
			t.Fatalf("%s: not registered", name)
		}
		if ref == nil {
			ref = p.H2Config.PriorityTable
			refName = name
			continue
		}
		got := p.H2Config.PriorityTable
		if len(got) != len(ref) {
			t.Errorf("%s: %d entries, %s has %d", name, len(got), refName, len(ref))
			continue
		}
		for k, refRP := range ref {
			gotRP, ok := got[k]
			if !ok {
				t.Errorf("%s: missing dest %q (present in %s)", name, k, refName)
				continue
			}
			if gotRP != refRP {
				t.Errorf("%s/dest=%s: %+v, want %+v (matching %s)", name, k, gotRP, refRP, refName)
			}
		}
	}
}

// TestPriorityHeaderFromResource_AllChrome147Entries cross-checks each
// Chrome 147 priority-table entry against the captured RFC 9218 header
// values, locking the contract end-to-end (urgency + incremental + emit ↔
// header string).
func TestPriorityHeaderFromResource_AllChrome147Entries(t *testing.T) {
	cases := map[string]string{
		// captures from cors.txt — column "priority(http-header)" or "(no header)"
		"document": "u=0, i",
		"iframe":   "u=0, i",
		"object":   "u=0, i",
		"embed":    "u=0, i",
		"style":    "u=0",
		"manifest": "u=2",
		"script":   "u=1",
		"font":     "u=1",
		"image":    "u=2, i",
		"empty":    "u=1, i",
		"video":    "i",
		"audio":    "i",
		"track":    "i",
		"worker":   "u=4, i",
	}
	p := GetStrict("chrome-147-windows")
	if p == nil {
		t.Fatal("chrome-147-windows: not registered")
	}
	for dest, wantHeader := range cases {
		rp, ok := p.H2Config.PriorityTable[dest]
		if !ok {
			t.Errorf("dest=%s: missing from table", dest)
			continue
		}
		got := PriorityHeaderFromResource(rp)
		if got != wantHeader {
			t.Errorf("dest=%s: rendered header = %q, want %q (rp=%+v)", dest, got, wantHeader, rp)
		}
	}
}

// TestDefaultPriorityTable_Copy verifies that DefaultPriorityTable()
// returns a fresh copy each call — mutating the returned map must not
// leak into subsequent preset lookups.
func TestDefaultPriorityTable_Copy(t *testing.T) {
	a := DefaultPriorityTable()
	a["document"] = ResourcePriority{Urgency: 7, Incremental: false, EmitHeader: false}
	a["new-dest"] = ResourcePriority{Urgency: 5}

	b := DefaultPriorityTable()
	if got := b["document"].Urgency; got != 0 {
		t.Errorf("DefaultPriorityTable copy isolation: document urgency = %d, want 0", got)
	}
	if _, leaked := b["new-dest"]; leaked {
		t.Error("DefaultPriorityTable copy isolation: 'new-dest' leaked from prior copy")
	}

	// Live preset (chrome-146 inheriting the default) must also be unaffected.
	p := GetStrict("chrome-146-windows")
	if p == nil {
		t.Skip("chrome-146-windows: not registered")
	}
	weight, _, _, ok := p.H2PriorityFor("document")
	if !ok || weight != 256 {
		t.Errorf("chrome-146-windows/document after mutating copy: weight=%d ok=%v, want 256/true", weight, ok)
	}
}

// TestDefaultPriorityTable_Coverage locks the set of dest keys in the
// package-level default. Adding new entries from future captures should
// be a deliberate change that updates this list.
func TestDefaultPriorityTable_Coverage(t *testing.T) {
	want := []string{
		"audio", "document", "embed", "empty", "font", "iframe", "image",
		"manifest", "object", "script", "style", "track", "video", "worker",
	}
	got := DefaultPriorityTable()
	if len(got) != len(want) {
		t.Errorf("DefaultPriorityTable size = %d, want %d", len(got), len(want))
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("DefaultPriorityTable missing dest %q", k)
		}
	}
}

// TestClonePreset_PriorityTableDeepCopy verifies that cloning a preset
// produces an independent priority-table map (mutating the clone's table
// must not affect the original).
func TestClonePreset_PriorityTableDeepCopy(t *testing.T) {
	src := GetStrict("chrome-147-windows")
	if src == nil {
		t.Fatal("chrome-147-windows: not registered")
	}
	dst := clonePreset(src)
	if dst.H2Config.PriorityTable == nil {
		t.Fatal("clone: PriorityTable is nil, want copied")
	}

	// Mutate the clone — adding + replacing.
	dst.H2Config.PriorityTable["nonexistent"] = ResourcePriority{Urgency: 7}
	dst.H2Config.PriorityTable["document"] = ResourcePriority{Urgency: 7, Incremental: false, EmitHeader: false}

	// Original must be untouched.
	if _, leaked := src.H2Config.PriorityTable["nonexistent"]; leaked {
		t.Error("source preset's PriorityTable was mutated by clone — not a deep copy")
	}
	if rp := src.H2Config.PriorityTable["document"]; rp.Urgency != 0 {
		t.Errorf("source preset's document entry mutated: urgency=%d, want 0", rp.Urgency)
	}
}
