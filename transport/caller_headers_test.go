package transport

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// TestCanonicalHeaderName checks the memoised path against
// http.CanonicalHeaderKey for every byte value in every position class the
// quick check distinguishes: alone, after a letter, before a letter, after a
// hyphen, and inside an otherwise canonical name.
func TestCanonicalHeaderName(t *testing.T) {
	for c := range 256 {
		b := byte(c)
		for _, name := range []string{
			string([]byte{b}),
			"a" + string([]byte{b}),
			string([]byte{b}) + "a",
			"x-" + string([]byte{b}) + "b",
			"Content-" + string([]byte{b}) + "ype",
		} {
			if got, want := canonicalHeaderName(name), http.CanonicalHeaderKey(name); got != want {
				t.Errorf("canonicalHeaderName(%q) = %q, want %q", name, got, want)
			}
		}
	}

	for _, name := range []string{
		"",
		"accept",
		"Accept",
		"content-type",
		"Content-Type",
		"x-requested-with",
		"sec-ch-ua-platform",
		"ACCEPT-ENCODING",
		"aCCePt",
		"x--double",
		"-leading",
		"trailing-",
		"7-digit-start",
		"bad key",
		"bad:key",
		"bäd-key",
		"Bäd-Key",
		"mixedCase withSpace",
	} {
		if got, want := canonicalHeaderName(name), http.CanonicalHeaderKey(name); got != want {
			t.Errorf("canonicalHeaderName(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestMergeCallerHeaders checks the direct-assignment merge against the
// documented fold: for each caller name the first value replaces whatever the
// preset pipeline produced and the rest append, under the canonical key. That
// is every protocol's behaviour but HTTP/1.1's, which keeps a caller's own
// spelling; see TestMergeCallerHeadersHTTP1Casing.
func TestMergeCallerHeaders(t *testing.T) {
	base := http.Header{
		"User-Agent":     {"preset-agent"},
		"Accept":         {"text/html"},
		"Sec-Fetch-Mode": {"navigate"},
	}
	cases := []struct {
		name    string
		headers map[string][]string
	}{
		{name: "nil"},
		{name: "empty", headers: map[string][]string{}},
		{name: "lowercase override and new", headers: map[string][]string{
			"accept":           {"application/json"},
			"authorization":    {"Bearer t"},
			"x-requested-with": {"XMLHttpRequest"},
		}},
		{name: "multi-value", headers: map[string][]string{
			"cookie": {"a=1", "b=2", "c=3"},
		}},
		{name: "empty value slice leaves the entry alone", headers: map[string][]string{
			"accept": {},
			"x-new":  {},
		}},
		{name: "already canonical", headers: map[string][]string{
			"Content-Type": {"application/json"},
			"User-Agent":   {"caller-agent"},
		}},
		{name: "weird casing", headers: map[string][]string{
			"x-WEIRD-key": {"v"},
			"aCCePt":      {"*/*"},
		}},
		{name: "invalid field byte stays raw", headers: map[string][]string{
			"bad key": {"v"},
		}},
	}
	for _, proto := range []string{"h2", "h3"} {
		for _, c := range cases {
			t.Run(proto+"/"+c.name, func(t *testing.T) {
				got := &http.Request{Header: base.Clone()}
				mergeCallerHeaders(got, &Request{Headers: c.headers}, proto)

				want := base.Clone()
				for key, values := range c.headers {
					for i, value := range values {
						if i == 0 {
							want.Set(key, value)
						} else {
							want.Add(key, value)
						}
					}
				}
				if !reflect.DeepEqual(got.Header, want) {
					t.Errorf("mergeCallerHeaders(%v) header =\n%v\nwant\n%v", c.headers, got.Header, want)
				}
			})
		}
	}
}

// On HTTP/1.1 the caller's own header keeps its spelling, and a name the
// browser writes itself stays canonical so it still lands on the preset's
// entry rather than beside it.
func TestMergeCallerHeadersHTTP1Casing(t *testing.T) {
	cases := []struct {
		name    string
		base    http.Header
		headers map[string][]string
		want    http.Header
	}{
		{
			name:    "a custom name keeps its spelling",
			headers: map[string][]string{"x-queueit-qpage-referral": {""}, "X-Requested-With": {"XMLHttpRequest"}, "X-mixed-Case": {"1"}},
			want:    http.Header{"x-queueit-qpage-referral": {""}, "X-Requested-With": {"XMLHttpRequest"}, "X-mixed-Case": {"1"}},
		},
		{
			name: "a browser-written name lands on the preset's entry",
			base: http.Header{"User-Agent": {"preset"}, "Accept": {"text/html"}, "Sec-Fetch-Dest": {"document"}},
			headers: map[string][]string{
				"user-agent": {"caller"}, "accept": {"*/*"}, "sec-fetch-dest": {"empty"},
				"cookie": {"a=1"}, "connection": {"close"}, "proxy-authorization": {"x"},
			},
			want: http.Header{
				"User-Agent": {"caller"}, "Accept": {"*/*"}, "Sec-Fetch-Dest": {"empty"},
				"Cookie": {"a=1"}, "Connection": {"close"}, "Proxy-Authorization": {"x"},
			},
		},
		{
			name:    "a custom preset header is replaced, not duplicated",
			base:    http.Header{"X-Client-Version": {"preset"}},
			headers: map[string][]string{"x-client-version": {"caller"}},
			want:    http.Header{"x-client-version": {"caller"}},
		},
		{
			name:    "both spellings from the caller both go out",
			base:    http.Header{"X-Dup": {"preset"}},
			headers: map[string][]string{"x-dup": {"lower"}, "X-Dup": {"canonical"}},
			want:    http.Header{"x-dup": {"lower"}, "X-Dup": {"canonical"}},
		},
		{
			name:    "an invalid name is untouched",
			headers: map[string][]string{"bad key": {"v"}},
			want:    http.Header{"bad key": {"v"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Run it repeatedly: the merge ranges over a map, and the result must
			// not depend on the order it is handed.
			for range 20 {
				got := &http.Request{Header: c.base.Clone()}
				if got.Header == nil {
					got.Header = http.Header{}
				}
				mergeCallerHeaders(got, &Request{Headers: c.headers}, "h1")
				if !reflect.DeepEqual(got.Header, c.want) {
					t.Fatalf("mergeCallerHeaders(%v) header =\n%v\nwant\n%v", c.headers, got.Header, c.want)
				}
			}
		})
	}
}

// Every name a built-in preset places has to be browser-cased, or a caller
// passing it in lowercase would see its casing change on HTTP/1.1. This keeps
// the list in browserCasedHeader from falling behind the preset tables.
func TestBrowserCasedHeaderCoversPresetTables(t *testing.T) {
	for _, name := range fingerprint.Available() {
		p := fingerprint.Get(name)
		names := append(append([]string(nil), p.H2HeaderOrder()...), p.H2HeaderOrderFor("script")...)
		for _, hp := range p.HeaderOrder {
			names = append(names, hp.Key)
		}
		for key := range p.Headers {
			names = append(names, key)
		}
		for _, h := range names {
			if !browserCasedHeader(http.CanonicalHeaderKey(h)) {
				t.Errorf("%s places %q, which browserCasedHeader does not cover", name, h)
			}
		}
	}
}

func TestMergeCallerHeadersExactHeadersNoOp(t *testing.T) {
	httpReq := &http.Request{Header: http.Header{"User-Agent": {"preset-agent"}}}
	want := httpReq.Header.Clone()
	mergeCallerHeaders(httpReq, &Request{
		Headers:      map[string][]string{"accept": {"application/json"}, "x-custom": {"1"}},
		ExactHeaders: []fingerprint.HeaderPair{{Key: "user-agent", Value: "exact"}},
	}, "h1")
	if !reflect.DeepEqual(httpReq.Header, want) {
		t.Errorf("mergeCallerHeaders under ExactHeaders mutated the header: got %v, want %v", httpReq.Header, want)
	}
}

// The merged entries are carved out of one shared backing array and must not
// alias the caller's slices; each must keep the same isolation that the
// per-value Set and Add calls gave.
func TestMergeCallerHeadersIsolation(t *testing.T) {
	headers := map[string][]string{
		"cookie":       {"a=1", "b=2"},
		"accept":       {"application/json"},
		"x-first":      {"one"},
		"content-type": {"text/plain"},
	}
	httpReq := &http.Request{Header: http.Header{}}
	mergeCallerHeaders(httpReq, &Request{Headers: headers}, "h2")

	before := map[string][]string{}
	for k, v := range httpReq.Header {
		before[k] = append([]string(nil), v...)
	}

	// Appending through one entry must not disturb its neighbors.
	httpReq.Header.Add("Cookie", "c=3")
	for _, k := range []string{"Accept", "X-First", "Content-Type"} {
		if !reflect.DeepEqual(httpReq.Header[k], before[k]) {
			t.Errorf("after Add to Cookie, header[%q] = %v, want %v", k, httpReq.Header[k], before[k])
		}
	}

	// Writing an element must not reach back into the caller's map.
	httpReq.Header["Accept"][0] = "mutated"
	if headers["accept"][0] != "application/json" {
		t.Errorf(`headers["accept"][0] = %q, want "application/json"`, headers["accept"][0])
	}
}

// A large caller map must not grow the bounded name cache without limit.
func TestCanonicalHeaderNameCacheBounded(t *testing.T) {
	for i := range canonicalHeaderNameCacheMax * 2 {
		canonicalHeaderName(fmt.Sprintf("x-bound-probe-%d", i))
	}
	// Concurrent stores can each overshoot the soft cap by one; anything in
	// that neighborhood is fine, a multiple of it is a leak.
	if n := canonicalHeaderNameCacheSize.Load(); n > canonicalHeaderNameCacheMax+8 {
		t.Errorf("canonicalHeaderNameCacheSize = %d, want <= %d", n, canonicalHeaderNameCacheMax+8)
	}
}

// Neither name cache holds a name longer than headerNameCacheMaxLen, so a peer
// cannot pin long names in them for the life of the process, and such a name
// still converts exactly as the uncached functions would.
func TestHeaderNameCachesSkipLongNames(t *testing.T) {
	long := "X-" + strings.Repeat("Long-Name-", 8) + "End"
	if len(long) <= headerNameCacheMaxLen {
		t.Fatalf("probe name is only %d bytes", len(long))
	}
	if got, want := lowerHeaderName(long), strings.ToLower(long); got != want {
		t.Errorf("lowerHeaderName = %q, want %q", got, want)
	}
	if _, cached := lowerHeaderNameCache.Load(long); cached {
		t.Error("lowerHeaderName cached a name longer than the cap")
	}
	lowerLong := strings.ToLower(long)
	if got, want := canonicalHeaderName(lowerLong), http.CanonicalHeaderKey(lowerLong); got != want {
		t.Errorf("canonicalHeaderName = %q, want %q", got, want)
	}
	if _, cached := canonicalHeaderNameCache.Load(lowerLong); cached {
		t.Error("canonicalHeaderName cached a name longer than the cap")
	}
}
