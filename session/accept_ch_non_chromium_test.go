package session

import (
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
)

// Only Chromium implements UA client hints. Firefox 159, loading a page whose
// response carried Accept-CH naming three high-entropy hints, sent no sec-ch-*
// header on that page's requests or after them; Safari implements none either,
// on macOS or iOS, and Chrome on iOS runs on WebKit. The Firefox, Safari and
// iOS Chrome presets send no sec-ch-ua, yet answered Accept-CH with
// sec-ch-ua-arch, -bitness, -model, -platform-version and -wow64, filled in
// from platform defaults.
func TestAcceptCHIsIgnoredWithoutUAClientHints(t *testing.T) {
	for _, c := range []struct {
		preset string
		hints  bool // whether the request after Accept-CH carries high-entropy hints
	}{
		{"chrome-latest", true},
		{"firefox-latest", false},
		{"safari-latest", false},
		{"safari-latest-ios", false},
		{"chrome-latest-ios", false},
	} {
		srv := newAcceptCHServer(t, "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-WoW64")
		s := NewSession("", &protocol.SessionConfig{Preset: c.preset, ForceHTTP1: true})
		srv.send(t, s, nil, true)
		next := srv.send(t, s, nil, false)
		s.Close()

		var sent []string
		for _, l := range next {
			name, _, _ := strings.Cut(l, ":")
			if name = strings.ToLower(strings.TrimSpace(name)); strings.HasPrefix(name, "sec-ch-") {
				sent = append(sent, name)
			}
		}
		if c.hints {
			if !strings.Contains(strings.Join(sent, " "), "sec-ch-ua-arch") {
				t.Errorf("%s: no high-entropy hints after Accept-CH: %v", c.preset, sent)
			}
		} else if len(sent) > 0 {
			t.Errorf("%s: sent %v after Accept-CH; the browser sends no UA client hints", c.preset, sent)
		}
	}
}
