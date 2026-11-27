package session

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
)

// Cloudflare's challenge names Sec-CH-UA-Full-Version in both Accept-CH and
// Critical-CH, and Chrome answers it: "156.0.8078.48" from Chrome 156, in a
// side-by-side capture where it was the one header this library left out. The
// session had no value for it and sent everything else the host asked for.
//
// Read off the HTTP/1.1 wire, so the order is checked as well: Chromium adds
// the hints to a navigation as ua, mobile, full-version, arch, platform,
// platform-version, model, bitness, wow64, full-version-list.
func TestAcceptCHFullVersionReachesTheWire(t *testing.T) {
	srv := newAcceptCHServer(t, "Sec-CH-UA-Full-Version, Sec-CH-UA-Arch, Sec-CH-UA-Platform-Version, "+
		"Sec-CH-UA-Model, Sec-CH-UA-Bitness, Sec-CH-UA-WoW64, Sec-CH-UA-Full-Version-List")
	s := NewSession("", &protocol.SessionConfig{Preset: "chrome-155-windows", ForceHTTP1: true})
	defer s.Close()

	var reqs [][]string
	for range 2 {
		reqs = append(reqs, srv.send(t, s, nil, true))
	}

	hints := func(lines []string) ([]string, map[string]string) {
		var names []string
		values := map[string]string{}
		for _, l := range lines {
			name, value, _ := strings.Cut(l, ":")
			if strings.HasPrefix(name, "sec-ch-ua") {
				names = append(names, name)
				values[name] = strings.TrimSpace(value)
			}
		}
		return names, values
	}

	if first, _ := hints(reqs[0]); !reflect.DeepEqual(first, []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}) {
		t.Errorf("first request, before any Accept-CH: hints %v, want the trio", first)
	}
	names, values := hints(reqs[1])
	want := []string{
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-full-version", "sec-ch-ua-arch",
		"sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-model",
		"sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-full-version-list",
	}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("after Accept-CH: hints\n %v\nwant Chromium's\n %v", names, want)
	}
	if got := values["sec-ch-ua-full-version"]; got != `"155.0.8059.39"` {
		t.Errorf("sec-ch-ua-full-version %s, want \"155.0.8059.39\"", got)
	}
}
