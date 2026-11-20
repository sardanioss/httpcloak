// Package engine tells which browser engine a User-Agent belongs to, for the
// rules that follow the engine rather than the browser: every browser on iOS
// runs on WebKit, whatever its name, and Edge and Opera run on Chromium.
package engine

import "strings"

// Kind is a browser engine.
type Kind int

const (
	// Other is anything that is not one of the three browser engines, such as
	// a curl or okhttp mirror, or a preset with no User-Agent.
	Other Kind = iota
	// Chromium is Chrome on every platform but iOS, and the browsers built on
	// it.
	Chromium
	// Gecko is Firefox on every platform but iOS.
	Gecko
	// WebKit is Safari, and every browser on iOS: Chrome (CriOS), Firefox
	// (FxiOS) and Edge (EdgiOS) there carry neither a Chrome/ nor a Firefox/
	// token.
	WebKit
)

// Of returns the engine of the browser whose User-Agent is userAgent. A
// Chrome/ token means Chromium and a Firefox/ token Gecko. AppleWebKit/ with
// neither means WebKit; Chromium keeps AppleWebKit/ in its User-Agent for
// compatibility, which is why the tokens are checked in this order.
func Of(userAgent string) Kind {
	switch {
	case strings.Contains(userAgent, "Chrome/"):
		return Chromium
	case strings.Contains(userAgent, "Firefox/"):
		return Gecko
	case strings.Contains(userAgent, "AppleWebKit/"):
		return WebKit
	}
	return Other
}
