// Package origin answers the questions a redirect asks about two URLs: are
// they one origin, does the hop leave https for http, and what Referer does
// the redirected request carry. Sessions and the client follow redirects
// separately and must agree on all three.
package origin

import (
	"net/url"
	"strings"
)

// Parse returns a URL's scheme, host and port for origin comparison, all
// lowercased. A missing port is filled in with the scheme's default, so
// http://x:80 and http://x compare equal. A URL with no scheme gives three
// empty strings.
func Parse(urlStr string) (scheme, host, port string) {
	u, err := url.Parse(urlStr)
	if err != nil || u.Scheme == "" {
		return "", "", ""
	}
	scheme = strings.ToLower(u.Scheme)
	host = strings.ToLower(u.Hostname())
	port = u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme, host, port
}

// Same reports whether two URLs share scheme, host and port.
func Same(a, b string) bool {
	as, ah, ap := Parse(a)
	bs, bh, bp := Parse(b)
	if as == "" || bs == "" {
		return false
	}
	return as == bs && ah == bh && ap == bp
}

// Downgrade reports whether going from one URL to the other leaves https for
// http. A browser's default strict-origin-when-cross-origin referrer policy
// sends no Referer across one, and Fetch drops the Authorization the request
// carried.
func Downgrade(from, to string) bool {
	fs, _, _ := Parse(from)
	ts, _, _ := Parse(to)
	return fs == "https" && ts == "http"
}

// RedirectReferer returns the Referer of the request that follows a redirect
// to target, given the Referer of the request that was redirected. Returns ""
// when none is sent.
//
// A redirect does not change who made the request, so a browser follows it
// with the referrer the request already had (the page that made it, never the
// URL that answered with the redirect), written again for where the hop goes
// under the default strict-origin-when-cross-origin policy:
//   - target on the referrer's origin: the referrer's whole URL, less its
//     fragment and credentials, with a default port left off
//   - target on another origin: the referrer's origin alone, with a trailing
//     slash (https://example.com/)
//   - an https referrer and an http target: none
//
// The referrer is known only as the header held it. One already cut down to
// its origin therefore stays cut down on a hop that leads back to that origin,
// where a browser, which remembers the page's whole URL, sends it whole.
func RedirectReferer(referer, target string) string {
	if Downgrade(referer, target) {
		return ""
	}
	u, err := url.Parse(referer)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") { // an IPv6 literal goes back in its brackets
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" && !(scheme == "https" && p == "443") && !(scheme == "http" && p == "80") {
		host += ":" + p
	}
	if !Same(referer, target) {
		return scheme + "://" + host + "/"
	}
	u.Fragment = ""
	u.RawFragment = ""
	u.User = nil
	u.Host = host
	return u.String()
}
