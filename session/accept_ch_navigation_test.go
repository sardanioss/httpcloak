package session

import (
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
)

// Chrome parses Accept-CH only on the response to an outermost main-frame
// navigation. Cloudflare's challenge iframe answers with Accept-CH and
// Critical-CH naming five high-entropy hints, and Chrome sent none of them to
// that host afterwards, on any frame-side request; the session sent all five.
// A fetch's response is the same: it can ask, and nothing is learned.
//
// The first request goes out through Request, and again through
// RequestStream, which learned from every response as well.
func TestAcceptCHIsLearnedOnlyFromANavigation(t *testing.T) {
	iframe := map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}, "Sec-Fetch-Site": {"cross-site"}}
	fetch := map[string][]string{"Accept": {"application/json"}}

	for _, path := range []struct {
		name string
		send func(*acceptCHServer, *testing.T, *Session, map[string][]string, bool) []string
	}{
		{"Request", (*acceptCHServer).send},
		{"RequestStream", (*acceptCHServer).stream},
	} {
		for _, c := range []struct {
			name    string
			first   map[string][]string // the request whose response carries Accept-CH
			learned bool
		}{
			{"navigation", nil, true},
			{"iframe", iframe, false},
			{"fetch", fetch, false},
		} {
			srv := newAcceptCHServer(t, "Sec-CH-UA-Arch, Sec-CH-UA-Platform-Version")
			s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest", ForceHTTP1: true})

			path.send(srv, t, s, c.first, true)
			// The next request is a navigation either way, so only what was
			// learned from the first response decides whether it carries hints.
			lines := srv.send(t, s, nil, false)
			s.Close()

			hasArch := false
			for _, l := range lines {
				if strings.HasPrefix(strings.ToLower(l), "sec-ch-ua-arch:") {
					hasArch = true
				}
			}
			if hasArch != c.learned {
				t.Errorf("%s: Accept-CH on the %s's response: learned %v, want %v\n%s",
					path.name, c.name, hasArch, c.learned, strings.Join(lines, "\n"))
			}
		}
	}
}
