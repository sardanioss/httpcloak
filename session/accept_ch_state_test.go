package session

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
)

// Chrome keeps each host's Accept-CH in the profile, as a durable
// CLIENT_HINTS content setting, so a host that asked before gets the
// high-entropy hints on the first request after a restart. A saved session
// kept its cookies and TLS tickets and dropped what hosts had asked for, so the
// first request after a load went without the hints and the second carried
// them: a first request unlike the ones after it.
func TestSavedSessionKeepsAcceptCH(t *testing.T) {
	srv := newAcceptCHServer(t, "Sec-CH-UA-Arch, Sec-CH-UA-Platform-Version")
	s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest", ForceHTTP1: true})
	srv.send(t, s, nil, true)
	data, err := s.Marshal()
	s.Close()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := UnmarshalSession(data)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if got, want := restored.AcceptCH(srv.host), []string{"sec-ch-ua-arch", "sec-ch-ua-platform-version"}; !slices.Equal(got, want) {
		t.Errorf("restored AcceptCH = %q, want %q", got, want)
	}
	sent := highEntropyHints(srv.send(t, restored, nil, false))
	if _, ok := sent["sec-ch-ua-arch"]; !ok {
		t.Errorf("first request after a load carries no sec-ch-ua-arch: %v", sent)
	}
	if _, ok := sent["sec-ch-ua-platform-version"]; !ok {
		t.Errorf("first request after a load carries no sec-ch-ua-platform-version: %v", sent)
	}
}

// A session rebuilt from state kept elsewhere, cookies in a caller's own store
// say, can be told what a host asked for, and asked what it learned. What
// ClientHintsFor reports is what goes on the wire, because the injector reads
// the same map.
func TestSetAcceptCHSeedsTheFirstRequest(t *testing.T) {
	srv := newAcceptCHServer(t, "")
	s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest", ForceHTTP1: true})
	defer s.Close()

	if got := s.AcceptCH(srv.host); got != nil {
		t.Fatalf("fresh session: AcceptCH = %q, want nil", got)
	}
	s.SetAcceptCH(srv.url, []string{"Sec-CH-UA-Arch", " sec-ch-ua-bitness ", ""})
	if got, want := s.AcceptCH(srv.host), []string{"sec-ch-ua-arch", "sec-ch-ua-bitness"}; !slices.Equal(got, want) {
		t.Errorf("AcceptCH = %q, want %q", got, want)
	}
	reported := s.ClientHintsFor(srv.host)
	if len(reported) != 2 {
		t.Errorf("ClientHintsFor = %v, want sec-ch-ua-arch and sec-ch-ua-bitness", reported)
	}
	if sent := highEntropyHints(srv.send(t, s, nil, false)); !maps.Equal(sent, reported) {
		t.Errorf("first request sent %v, ClientHintsFor said %v", sent, reported)
	}

	s.SetHighEntropyClientHintsEnabled(false)
	if got := s.ClientHintsFor(srv.host); got != nil {
		t.Errorf("high-entropy hints off: ClientHintsFor = %v, want nil", got)
	}
	s.SetHighEntropyClientHintsEnabled(true)

	s.SetAcceptCH(srv.host, nil)
	if got := s.AcceptCH(srv.host); got != nil {
		t.Errorf("after forgetting the host: AcceptCH = %q, want nil", got)
	}
	if sent := highEntropyHints(srv.send(t, s, nil, false)); len(sent) != 0 {
		t.Errorf("after forgetting the host the request sent %v", sent)
	}
}

// highEntropyHints picks the sec-ch-ua-* headers other than the low-entropy
// trio out of a request's header lines, lowercase name to value.
func highEntropyHints(lines []string) map[string]string {
	out := map[string]string{}
	for _, l := range lines {
		name, value, _ := strings.Cut(l, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		switch {
		case !strings.HasPrefix(name, "sec-ch-ua-"), name == "sec-ch-ua-mobile", name == "sec-ch-ua-platform":
			continue
		}
		out[name] = strings.TrimSpace(value)
	}
	return out
}
