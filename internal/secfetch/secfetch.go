// Package secfetch holds the request-shape rules behind a request's Sec-Fetch
// metadata: whether a preset sends Sec-Fetch-* at all, and whether a request
// goes out as a fetch or as a navigation. The transport writes the headers
// from them, and the session needs the same answers about a request it sends,
// so both read this one copy.
package secfetch

import (
	"strings"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// PresetSends reports whether a preset describes a client that sends
// Sec-Fetch-* metadata at all.
//
// The transport's XHR coercion rewrites Sec-Fetch-* and Accept to keep a
// *browser* coherent on API-shaped calls. A preset for a non-browser client -
// okhttp, curl, a native mobile SDK - has no navigation headers to correct, so
// running the coercion on one does not fix an incoherence, it invents headers
// that client never sends.
//
// The signal is the preset's EMIT SET, not its HPACK position table. The table
// only says where a header goes if it is sent; the emit set says what is
// actually sent, which is the thing being suppressed. Reading the table instead
// leaves a hole: a custom preset that drops Sec-Fetch-* from its emit set while
// inheriting a browser's position table would still have all of them injected,
// so the opt-out would silently fail for exactly the preset that asked for it.
//
// Every built-in today lists the family in both places, so this changes nothing
// for any shipped fingerprint. Matching is case-insensitive: HTTP/2 field names
// are lowercase by definition (RFC 9113 8.2.1) and the built-in tables follow
// that, but a hand-written custom preset need not.
func PresetSends(preset *fingerprint.Preset) bool {
	if len(preset.HeaderOrder) > 0 {
		// The ordered list IS the emit set when it is populated, so it alone
		// decides. Falling through to the Headers map here would reopen the hole
		// this gate exists to close: a custom preset built with based_on drops
		// Sec-Fetch-* from its own HeaderOrder but still inherits the base's
		// Headers map, so the map would answer true and the headers would be
		// injected anyway - the opt-out failing for exactly the preset that
		// asked for it, one field over from where it failed before.
		for _, h := range preset.HeaderOrder {
			if len(h.Key) >= 10 && strings.EqualFold(h.Key[:10], "sec-fetch-") {
				return true
			}
		}
		return false
	}
	// Only for presets that carry the backward-compatible map and no ordered list.
	for name := range preset.Headers {
		if len(name) >= 10 && strings.EqualFold(name[:10], "sec-fetch-") {
			return true
		}
	}
	return false
}

// SniffXHRMode decides whether a request should send CORS-mode Sec-Fetch-*
// instead of navigation-mode, based on the request method and user headers.
// Browsers send cors/empty for fetch()/XHR and navigate/document for top-level
// navigations + classic <form> POSTs. Libraries that don't know the user's
// intent (session.post / httpcloak_post) have to infer it from the request
// shape.
func SniffXHRMode(method string, userHeaders map[string][]string) bool {
	method = strings.ToUpper(method)

	// Explicit user override on Sec-Fetch-Mode / Sec-Fetch-Dest wins — the
	// caller knows what intent they want to project. "navigate" explicitly
	// asks for navigation mode even for a POST that would otherwise sniff
	// as CORS.
	if v := headerVal(userHeaders, "Sec-Fetch-Mode"); v != "" {
		switch strings.ToLower(v) {
		case "cors", "no-cors", "websocket":
			return true
		case "navigate":
			return false
		}
	}
	if v := headerVal(userHeaders, "Sec-Fetch-Dest"); v != "" {
		// "document" is the only dest compatible with navigate mode — treat
		// an explicit "document" as a nav signal, anything else as API.
		if strings.ToLower(v) == "document" {
			return false
		}
		return true
	}

	// API-style Accept flags any method (also keeps prior GET behavior).
	if v := headerVal(userHeaders, "Accept"); v != "" && isAPIAcceptValue(v) {
		return true
	}

	switch method {
	case "GET", "HEAD", "OPTIONS", "":
		// Bodyless methods stay navigate unless Accept hinted API (above).
		return false
	case "DELETE":
		// DELETE is never a navigation.
		return true
	}

	// Body-carrying methods (POST/PUT/PATCH/...). Use Content-Type to
	// distinguish form submissions (navigate) from programmatic calls (cors).
	if ct := headerVal(userHeaders, "Content-Type"); ct != "" {
		if isFormContentTypeValue(ct) {
			return false
		}
		if isAPIContentTypeValue(ct) {
			return true
		}
	}

	// Unknown Content-Type on a body-carrying method: lean CORS. Real-world
	// POSTs from scrapers are overwhelmingly API calls; form submissions
	// always carry one of the form Content-Types handled above.
	return true
}

// headerVal returns the first value of name in h, matched case-insensitively.
func headerVal(h map[string][]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func isAPIAcceptValue(accept string) bool {
	lower := strings.ToLower(accept)
	return strings.Contains(lower, "application/json") ||
		strings.Contains(lower, "application/xml") ||
		strings.Contains(lower, "text/plain") ||
		strings.Contains(lower, "application/octet-stream") ||
		lower == "*/*"
}

func isFormContentTypeValue(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.HasPrefix(lower, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(lower, "multipart/form-data")
}

func isAPIContentTypeValue(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.HasPrefix(lower, "application/json") ||
		strings.HasPrefix(lower, "application/xml") ||
		strings.HasPrefix(lower, "application/octet-stream") ||
		strings.HasPrefix(lower, "application/grpc") ||
		strings.HasPrefix(lower, "application/x-protobuf") ||
		strings.HasPrefix(lower, "text/plain") ||
		// Any other application/* that isn't a form type is API-ish.
		(strings.HasPrefix(lower, "application/") && !isFormContentTypeValue(lower))
}
