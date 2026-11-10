package transport

import (
	"bytes"
	"cmp"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	http "github.com/sardanioss/http"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// The request-header pipeline was rewritten for speed (#112): the preset's
// header set is worked out once per preset and cached, caller headers merge
// under memoised canonical names, and the order is completed in one buffer.
// None of that may change a header a request sends. This compares the
// pipeline with a frozen copy of the one it replaced, taken from the branch
// as it stood just before the merge, across every built-in preset, every
// protocol and the request shapes that take different paths through it.
// The wire snapshot covers what the default request sends; this covers the
// rest: caller-pinned Sec-Fetch values in either casing, raw lowercase keys,
// empty and repeated values, odd header names, custom orders, exact headers,
// TLS-only mode and stripped client hints.
//
// The frozen functions below are that pre-merge code, renamed, and must not
// be edited: they are the reference. Changes made to the pipeline on purpose
// since then are applied to their output by laterChanges.
func TestHeaderPipelineMatchesThePreviousOne(t *testing.T) {
	tr := NewTransport("chrome-latest")
	defer tr.Close()

	type shape struct {
		name    string
		method  string
		body    []byte
		headers map[string][]string
	}
	shapes := []shape{
		{"get", "GET", nil, nil},
		{"json post", "POST", []byte(`{"k":1}`), map[string][]string{"Content-Type": {"application/json"}}},
		{"pinned sec-fetch lowercase", "GET", nil, map[string][]string{
			"sec-fetch-dest": {"image"}, "sec-fetch-mode": {"no-cors"}, "sec-fetch-site": {"same-origin"}}},
		{"pinned sec-fetch canonical", "GET", nil, map[string][]string{
			"Sec-Fetch-Dest": {"script"}, "Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Site": {"same-site"}}},
		{"raw lowercase priority", "GET", nil, map[string][]string{"priority": {"u=3"}}},
		{"empty priority", "GET", nil, map[string][]string{"Priority": {}}},
		{"repeated and multi-value", "GET", nil, map[string][]string{
			"Accept-Language": {"de", "en;q=0.5"}, "x-custom": {"a", "b"}, "X-Custom-Two": {""}}},
		{"odd names", "GET", nil, map[string][]string{"x-ünicode": {"v"}, "bad name": {"v"}, "X-OK": {"1"}}},
		{"cookie and referer", "GET", nil, map[string][]string{"Cookie": {"a=1; b=2"}, "referer": {"https://example.com/"}}},
		{"user agent override", "GET", nil, map[string][]string{"user-agent": {"custom/1.0"}}},
	}
	orders := [][]string{nil, {"user-agent", "accept", "x-custom"}, {"User-Agent", "Accept", "X-Custom"}}
	exacts := [][]fingerprint.HeaderPair{nil, {{Key: "accept", Value: "*/*"}, {Key: "x-a", Value: "1"}, {Key: "accept", Value: "text/html"}}}

	names := fingerprint.Available()
	sort.Strings(names)
	cases := 0
	for _, name := range names {
		preset := fingerprint.Get(name)
		for _, proto := range []string{"h1", "h2", "h3"} {
			for _, tlsOnly := range []bool{false, true} {
				for _, strip := range []bool{false, true} {
					for _, exact := range exacts {
						for oi, order := range orders {
							for _, sh := range shapes {
								req := &Request{Method: sh.method, URL: "https://example.com/p?q=1", Body: sh.body, Headers: sh.headers}
								mk := func() *http.Request {
									r, err := http.NewRequest(sh.method, req.URL, bytes.NewReader(sh.body))
									if err != nil {
										t.Fatal(err)
									}
									return r
								}
								old, cur := mk(), mk()
								frozenApplyPresetHeaders(old, preset, order, nil, tlsOnly, proto, req.Headers, strip, exact)
								laterChanges(old.Header, preset, tlsOnly, req, exact)
								frozenMergeCallerHeaders(old, req)
								laterMergeChanges(old.Header, req)
								applyPresetHeaders(cur, tr.wireHeaders(preset), order, nil, tlsOnly, proto, req.Headers, strip, exact)
								mergeCallerHeaders(cur, req)
								cases++
								if !reflect.DeepEqual(old.Header, cur.Header) {
									t.Fatalf("%s %s tlsOnly=%v strip=%v exact=%v order=%d %s:\nold %v\nnew %v",
										name, proto, tlsOnly, strip, exact != nil, oi, sh.name,
										dumpHeader(old.Header), dumpHeader(cur.Header))
								}
								// A caller mutating what it got back must not reach the
								// cached preset entry and change the next request.
								for k, v := range cur.Header {
									if len(v) > 0 {
										cur.Header[k] = append(v, "poison")
										v[0] = "poison"
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Response header maps.
	for _, h := range []http.Header{
		{},
		{"Content-Type": {"text/html"}, "Set-Cookie": {"a=1", "b=2"}, "X-Empty": {}, "X-Nil": nil},
		{"x-lower": {"v"}, "X-ünicode": {"v"}, http.HeaderOrderKey: {"content-type"}},
	} {
		if old, cur := frozenBuildHeadersMap(h), buildHeadersMap(h); !reflect.DeepEqual(old, cur) {
			t.Errorf("buildHeadersMap(%v): old %v, new %v", h, old, cur)
		}
	}
	t.Logf("%d request cases identical", cases)
}

// laterChanges applies to the frozen pipeline's output what has changed in the
// pipeline on purpose since it was frozen, each change tested on its own:
//
//   - A no-cors load sends its destination's Accept, the image Accept on an
//     image (TestApplyPresetHeadersDerivesSubresourceContext). The same change
//     takes a fetch()'s Sec-Fetch-Site and Origin from its Referer, which no
//     shape here sends on a fetch().
//   - A navigation with a Referer takes its Sec-Fetch-Site from it, and one
//     that is not a GET carries the page's Origin
//     (TestApplyPresetHeadersDerivesNavigationSite).
func laterChanges(h http.Header, preset *fingerprint.Preset, tlsOnly bool, req *Request, exact []fingerprint.HeaderPair) {
	if tlsOnly || len(exact) > 0 || !presetSendsSecFetch(preset) {
		return
	}
	if !sniffXHRMode(req.Method, req.Headers) {
		if referer := headerVal(req.Headers, "Referer"); referer != "" {
			u, _ := url.Parse(req.URL)
			site := cmp.Or(headerVal(req.Headers, "Sec-Fetch-Site"), subresourceFetchSite(referer, u))
			h["Sec-Fetch-Site"] = []string{site}
			if origin := requestOrigin(referer, "navigate", site, req.Method); origin != "" && headerVal(req.Headers, "Origin") == "" {
				h["Origin"] = []string{origin}
			}
		}
		return
	}
	if headerVal(req.Headers, "Accept") == "" {
		mode := cmp.Or(headerVal(req.Headers, "Sec-Fetch-Mode"), "cors")
		dest := cmp.Or(headerVal(req.Headers, "Sec-Fetch-Dest"), "empty")
		h["Accept"] = []string{subresourceAccept(preset, mode, dest)}
	}
}

// laterMergeChanges applies to the frozen merge's output what has changed in it
// on purpose since: a caller header whose only value is "" is removed rather
// than sent empty, as the headers documentation says
// (TestMergeCallerHeadersEmptyValueRemoves). Exact mode still merges nothing.
func laterMergeChanges(h http.Header, req *Request) {
	if len(req.ExactHeaders) > 0 {
		return
	}
	for key, values := range req.Headers {
		if len(values) == 1 && values[0] == "" {
			delete(h, http.CanonicalHeaderKey(key))
		}
	}
}

func dumpHeader(h http.Header) string {
	var keys []string
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "\n  %q: %q", k, h[k])
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Frozen reference: the pipeline as it was before #112. Do not edit.
// ---------------------------------------------------------------------------

// frozenCompleteHeaderOrder builds a header-order list that names every header the
// request carries, so none is left to an encoder's map-iteration fallback.
//
// The list is assembled in three passes: explicitOrder (the caller's order for
// this request: Request.HeaderOrder if it names one, else SetHeaderOrder, and
// empty when there is neither); then presetOrder, so a partial
// custom list does not cost the caller the preset's ordering for the headers
// they did not name; then everything still unplaced, sorted by name. An empty
// explicitOrder needs no special case: pass one falls through and pass two
// lays down the preset table on its own. Names are lowercased and
// de-duplicated. userHeaders may be nil when the caller has already merged
// them into header.
//
// Both remainders were previously emitted in Go map order, which is randomised
// on every range. A header order that differs per request is itself a
// fingerprint, and a strong one, since no browser produces one. Sorted is not what a
// browser sends either, but it is stable, which is the detectable part.
func frozenCompleteHeaderOrder(explicitOrder, presetOrder []string, header http.Header, userHeaders map[string][]string) []string {
	seen := make(map[string]bool, len(explicitOrder)+len(presetOrder)+len(header)+len(userHeaders))
	order := make([]string, 0, len(explicitOrder)+len(presetOrder)+len(header)+len(userHeaders))

	place := func(name string) {
		lower := strings.ToLower(name)
		if lower == "" || seen[lower] {
			return
		}
		seen[lower] = true
		order = append(order, lower)
	}
	for _, name := range explicitOrder {
		place(name)
	}
	for _, name := range presetOrder {
		place(name)
	}

	rest := make([]string, 0, len(header)+len(userHeaders))
	collect := func(name string) {
		// The ordering keys are internal control entries, not headers, and must
		// never reach the wire.
		if strings.EqualFold(name, http.HeaderOrderKey) || strings.EqualFold(name, http.PHeaderOrderKey) {
			return
		}
		lower := strings.ToLower(name)
		if lower == "" || seen[lower] {
			return
		}
		seen[lower] = true
		rest = append(rest, lower)
	}
	for name := range header {
		collect(name)
	}
	for name := range userHeaders {
		collect(name)
	}
	sort.Strings(rest)

	return append(order, rest...)
}

// frozenMergeCallerHeaders folds Request.Headers over whatever the preset pipeline
// produced. The first value replaces, the rest append, so a caller can both
// override a preset header and send one name twice.
//
// It is a no-op under ExactHeaders. That mode promises the wire carries the
// listed pairs and nothing else, and req.Headers is not only what the caller
// passed for this request: the session writes the cookie jar's Cookie header
// into it on every attempt, and the client-hint policy adds to it as well. So
// merging here broke the promise in the one place it mattered most, silently
// appending a jar Cookie to a request built to mirror a capture.
//
// It also has to stay out of the way for a structural reason. Exact mode now
// gives every pair its own slot in the order list and the encoders hand slot i
// value i, so a Set or an Add here would leave the order list and the value
// slices it indexes out of step with no error anywhere.
func frozenMergeCallerHeaders(httpReq *http.Request, req *Request) {
	if len(req.ExactHeaders) > 0 {
		return
	}
	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}
}

func frozenApplyPresetHeaders(httpReq *http.Request, preset *fingerprint.Preset, customHeaderOrder []string, customPseudoOrder []string, tlsOnly bool, protocol string, userHeaders map[string][]string, stripClientHints bool, exactHeaders []fingerprint.HeaderPair) {
	if applyExactHeaders(httpReq, exactHeaders, preset, customPseudoOrder, protocol) {
		return
	}
	// In TLS-only mode, skip applying preset headers but still set header order
	if !tlsOnly {
		if len(preset.HeaderOrder) > 0 {
			// Use ordered headers for HTTP/2 and HTTP/3 fingerprinting
			for _, hp := range preset.HeaderOrder {
				if stripClientHints && isClientHintHeader(hp.Key) {
					continue // full opt-out: don't apply the preset sec-ch-* trio
				}
				httpReq.Header.Set(hp.Key, hp.Value)
			}
		} else {
			// Fallback to unordered headers map
			for key, value := range preset.Headers {
				if stripClientHints && isClientHintHeader(key) {
					continue
				}
				httpReq.Header.Set(key, value)
			}
		}
		httpReq.Header.Set("User-Agent", preset.UserAgent)

		// Auto-detect CORS mode from the request shape. Real browsers use
		// cors/empty Sec-Fetch-* for fetch()/XHR and navigate/document for
		// top-level navigations + classic <form> POSTs; infer which one this
		// request is from method, Content-Type, Accept, and any user-supplied
		// Sec-Fetch-* headers. WAFs like Akamai flag navigation headers on
		// API endpoints as bot behavior.
		//
		// Skipped for presets that describe a client sending no Sec-Fetch-* at
		// all; see presetSendsSecFetch for why inferring that from the preset
		// leaves every browser preset untouched.
		if presetSendsSecFetch(preset) && sniffXHRMode(httpReq.Method, userHeaders) {
			// Preserve any explicitly user-supplied Sec-Fetch-Mode/Dest/Site;
			// the sniff coercion is for "user said nothing, infer XHR"; once
			// they pin a value (e.g. mode=no-cors, dest=image, site=same-origin)
			// the request shape is intentional and our preset header defaults
			// (which assume navigation) should yield. Without this, callers
			// can't request browser sub-resource fetches like preload-as=image.
			userMode := headerVal(userHeaders, "Sec-Fetch-Mode")
			userDest := headerVal(userHeaders, "Sec-Fetch-Dest")
			userSite := headerVal(userHeaders, "Sec-Fetch-Site")
			if userMode != "" {
				httpReq.Header.Set("Sec-Fetch-Mode", userMode)
			} else {
				httpReq.Header.Set("Sec-Fetch-Mode", "cors")
			}
			if userDest != "" {
				httpReq.Header.Set("Sec-Fetch-Dest", userDest)
			} else {
				httpReq.Header.Set("Sec-Fetch-Dest", "empty")
			}
			if userSite != "" {
				httpReq.Header.Set("Sec-Fetch-Site", userSite)
			} else {
				httpReq.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			httpReq.Header.Del("Sec-Fetch-User")
			httpReq.Header.Del("sec-fetch-user")
			httpReq.Header.Del("Upgrade-Insecure-Requests")
			httpReq.Header.Del("upgrade-insecure-requests")
			// Real browsers send Accept: */* on fetch()/XHR unless the user
			// explicitly asked for something else; no user Accept means swap
			// the navigation Accept (text/html,...) for the CORS default.
			if headerVal(userHeaders, "Accept") == "" {
				httpReq.Header.Set("Accept", "*/*")
			}
			// CORS uses u=1,i priority (lower urgency than navigation's u=0,i)
			// and is the static fallback when the preset has no per-dest
			// PriorityTable. Presets that ship a PriorityTable (Chrome 147+)
			// override this below.
			if httpReq.Header.Get("Priority") != "" {
				httpReq.Header.Set("Priority", "u=1, i")
			}
			if httpReq.Header.Get("priority") != "" {
				httpReq.Header.Set("priority", "u=1, i")
			}
		}

		// Per-resource-type priority: HTTP header. Chrome 147+ desktop emits
		// a distinct urgency per sec-fetch-dest (style→u=0, script→u=1,
		// manifest→u=2, image→u=2/i, fetch→u=1/i, prefetch→u=4/i, …). Presets
		// that ship a PriorityTable apply that mapping here AFTER the XHR
		// detector runs (so Sec-Fetch-Dest is final). Presets without a table
		// retain the static priority set by HeaderOrder / sniffXHRMode above.
		//
		// On every protocol: Firefox sends the same priority header over
		// HTTP/1.1 as over HTTP/2. Chromium sends none on HTTP/1.1, and the
		// strip below removes it there.
		if preset.H2HasPriorityTable() {
			dest := httpReq.Header.Get("Sec-Fetch-Dest")
			if _, _, hv, ok := preset.H2PriorityFor(dest); ok {
				if hv == "" {
					// Chrome omits the header for this dest (e.g. async/defer scripts).
					httpReq.Header.Del("Priority")
					httpReq.Header.Del("priority")
				} else {
					httpReq.Header.Set("Priority", hv)
					// Mirror the lowercase form for callers that bypassed Set's
					// canonicalization when constructing the request.
					if _, hasLower := httpReq.Header["priority"]; hasLower {
						httpReq.Header["priority"] = []string{hv}
					}
				}
			}
		}

		// Chromium does NOT send the priority header on HTTP/1.1, only on
		// HTTP/2 and HTTP/3, and sending it there is a tell. See
		// SendsPriorityOverHTTP1 for which presets that covers.
		if protocol == "h1" && !preset.SendsPriorityOverHTTP1() {
			httpReq.Header.Del("Priority")
			httpReq.Header.Del("priority")
		}
	} else {
		// TLS-only mode: set empty User-Agent to prevent Go's default "Go-http-client/2.0"
		// This marks didUA=true in httpcommon.EncodeHeaders but skips writing the value
		httpReq.Header.Set("User-Agent", "")
	}

	// Set header order for HTTP/2 and HTTP/3 fingerprinting
	// Chrome uses the same header order for both H2 and H3 (same request_->extra_headers vector)
	//
	// Important: use H2HeaderOrder() (the full HPACK position table), NOT
	// preset.HeaderOrder (the default emit set). The two differ: HeaderOrder
	// only lists headers Chrome sends on every request, while H2HeaderOrder
	// also reserves slots for situational headers (cache-control on F5,
	// content-type/content-length on POST, origin/referer on cross-origin,
	// cookie on subsequent requests). Using HeaderOrder here was a real
	// fingerprinting bug: when callers added cache-control/content-type/
	// cookie, the fork couldn't slot them and appended them after `priority`
	// instead of placing them where real Chrome does.
	//
	// The order is chosen by request shape. Chrome builds a top-level navigation
	// and a subresource through different paths and the leading block comes out
	// differently, so a preset carrying one order gets one of the two wrong. The
	// dest read here is the final one: the Sec-Fetch inference above has already
	// run, and the priority table a few lines up reads the same field.
	httpReq.Header[http.HeaderOrderKey] = frozenCompleteHeaderOrder(
		customHeaderOrder,
		preset.H2HeaderOrderFor(httpReq.Header.Get("Sec-Fetch-Dest"), httpReq.Header.Get("Sec-Purpose")),
		httpReq.Header, userHeaders)

	// Set pseudo-header order: custom (Akamai) > preset H2Config > heuristic
	if len(customPseudoOrder) > 0 {
		httpReq.Header[http.PHeaderOrderKey] = customPseudoOrder
	} else if order := preset.H2PseudoHeaderOrder(); order != nil {
		httpReq.Header[http.PHeaderOrderKey] = order
	} else if preset.HTTP2Settings.NoRFC7540Priorities {
		httpReq.Header[http.PHeaderOrderKey] = []string{":method", ":scheme", ":path", ":authority"}
	} else {
		httpReq.Header[http.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
	}
}

func frozenBuildHeadersMap(h http.Header) map[string][]string {
	headers := make(map[string][]string)
	for key, values := range h {
		// The order key is transport bookkeeping, not a header the peer sent.
		// It reaches the response map because the H2 read path records the
		// arrival order there; it is surfaced separately as Response.HeaderOrder.
		if key == http.HeaderOrderKey || key == http.PHeaderOrderKey ||
			key == h1HeaderCasingKey || key == exactHeadersKey {
			continue
		}
		lowerKey := strings.ToLower(key)
		// Copy values to avoid sharing underlying array
		headerValues := make([]string, len(values))
		copy(headerValues, values)
		headers[lowerKey] = headerValues
	}
	return headers
}
