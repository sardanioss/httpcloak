package client

import (
	"bufio"
	"context"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/engine"
)

// WebKit adds Upgrade-Insecure-Requests: 1 to the load of a document or an
// iframe whose URL is not https, and to nothing else: Safari 26.3 sent it on
// all 6 of its plain-HTTP navigations and on none of its 20 https ones, and
// the https navigations captured on iPhones behind safari-26-ios and Chrome
// on iOS from 148 on carry none either. Chrome 156 and Firefox 159 sent it
// on every navigation, http and https. The client sends https alone and set
// it on every navigation whatever the preset. The header set is built before
// the protocol is chosen, so HTTP/1.1 covers HTTP/2 too, and
// PreparedRequest.Send goes through Do.
func TestClientWebKitPresetsSendNoUpgradeInsecureRequests(t *testing.T) {
	ln := priorityTLSListener(t, "http/1.1")
	got := make(chan []string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					if _, err := br.ReadString('\n'); err != nil { // request line
						return
					}
					var lines []string
					for {
						l, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if l == "\r\n" {
							break
						}
						lines = append(lines, strings.TrimRight(l, "\r\n"))
					}
					got <- lines
					io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
				}
			}(c)
		}
	}()
	url := "https://" + ln.Addr().String() + "/"

	// Each request gets its own Headers map: Do writes every header it sends
	// back into the caller's map.
	shapes := []struct {
		name       string
		req        func() *Request
		navigation bool
	}{
		{"navigation", func() *Request { return &Request{Method: "GET", URL: url} }, true},
		{"iframe navigation", func() *Request {
			return &Request{Method: "GET", URL: url, Headers: map[string][]string{
				"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"},
			}}
		}, true},
		{"cors", func() *Request { return &Request{Method: "GET", URL: url, FetchMode: FetchModeCORS} }, false},
	}

	// One name per distinct preset, the first alias of each in sorted order.
	names := fingerprint.Available()
	slices.Sort(names)
	seen := map[string]bool{}
	var presets, webkit, webkitNames []string
	for _, name := range names {
		p := fingerprint.Get(name)
		if seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		presets = append(presets, name)
		if engine.Of(p.UserAgent) == engine.WebKit {
			webkit = append(webkit, name)
			webkitNames = append(webkitNames, p.Name)
		}
	}
	for _, want := range []string{"safari-17-ios", "safari-18", "safari-18-ios", "safari-26-ios", "chrome-143-ios", "chrome-155-ios"} {
		if !slices.Contains(webkitNames, want) {
			t.Fatalf("%s is not among the WebKit presets %v", want, webkitNames)
		}
	}

	for _, preset := range presets {
		isWebKit := slices.Contains(webkit, preset)
		c := NewClient(preset, WithForceHTTP1(), WithInsecureSkipVerify())
		for _, s := range shapes {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := c.Do(ctx, s.req())
			cancel()
			if err != nil {
				t.Fatalf("%s %s: %v", preset, s.name, err)
			}
			var uir []string
			mode := ""
			for _, l := range <-got {
				k, v, _ := strings.Cut(l, ":")
				switch strings.ToLower(k) {
				case "upgrade-insecure-requests":
					uir = append(uir, l)
				case "sec-fetch-mode":
					mode = strings.TrimSpace(v)
				}
			}
			switch {
			case s.navigation && mode != "navigate":
				t.Errorf("%s %s: sec-fetch-mode %q, no longer a navigation", preset, s.name, mode)
			case !s.navigation:
				if len(uir) > 0 {
					t.Errorf("%s %s: %q, want none", preset, s.name, uir)
				}
			case isWebKit:
				if len(uir) > 0 {
					t.Errorf("%s %s over https: %q; WebKit sends it only to a URL that is not https", preset, s.name, uir)
				}
			case !slices.Equal(uir, []string{"Upgrade-Insecure-Requests: 1"}):
				t.Errorf("%s %s: %q, want one Upgrade-Insecure-Requests: 1", preset, s.name, uir)
			}
		}
		c.Close()
	}
}
