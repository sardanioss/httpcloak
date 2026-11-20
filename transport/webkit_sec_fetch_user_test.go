package transport

import (
	"bufio"
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// WebKit sends Sec-Fetch-Dest, Sec-Fetch-Mode and Sec-Fetch-Site and no
// Sec-Fetch-User. It turned Fetch Metadata on in November 2022 with those three
// (WebKit bug 246508), the bug for the fourth (247697) is still open, and no
// revision of WebKit's header name table has listed it. Safari 26.3 sent it on
// no request, on macOS or iOS, and neither did the iPhone captures behind
// safari-26-ios and Chrome on iOS from 148 on. The Safari 17 and 18 presets,
// and Chrome on iOS before 148, which Apple makes run on WebKit, sent ?1 on
// every navigation.
func TestWebKitPresetsSendNoSecFetchUser(t *testing.T) {
	h2 := startH2CaptureServer(t)
	h1Addr, h1 := startH1HeaderCapture(t, h2.tlsConfig)

	// navigate sends a top-level navigation, the request a preset's default
	// headers describe, and returns the headers the server read.
	navigate := func(preset string, proto Protocol) map[string]string {
		t.Helper()
		tr := NewTransport(preset)
		defer tr.Close()
		tr.SetProtocol(proto)
		tr.SetInsecureSkipVerify(true)
		addr := h1Addr
		if proto == ProtocolHTTP2 {
			addr = h2.addr
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + addr + "/"})
		if err != nil {
			t.Fatalf("%s over %s: %v", preset, protoName(proto), err)
		}
		resp.Close()
		if proto == ProtocolHTTP2 {
			return (<-h2.captures).Headers
		}
		return <-h1
	}

	webkit := webkitPresets()
	for _, want := range []string{"safari-17-ios", "safari-18", "safari-18-ios", "safari-26-ios", "chrome-143-ios", "chrome-155-ios"} {
		if !slices.Contains(webkit, want) {
			t.Fatalf("%s is not among the WebKit presets %v", want, webkit)
		}
	}
	for _, proto := range []Protocol{ProtocolHTTP1, ProtocolHTTP2} {
		for _, preset := range webkit {
			got := navigate(preset, proto)
			if v, ok := got["sec-fetch-user"]; ok {
				t.Errorf("%s over %s: sec-fetch-user %q on a navigation; WebKit sends none", preset, protoName(proto), v)
			}
			if got["sec-fetch-mode"] != "navigate" || got["sec-fetch-dest"] != "document" {
				t.Errorf("%s over %s: no longer a navigation: %v", preset, protoName(proto), got)
			}
		}
		// Chromium and Gecko do send it, on a navigation a person started.
		for _, preset := range []string{"chrome-latest", "firefox-latest"} {
			if v := navigate(preset, proto)["sec-fetch-user"]; v != "?1" {
				t.Errorf("%s over %s: sec-fetch-user %q, want ?1", preset, protoName(proto), v)
			}
		}
	}
}

// webkitPresets lists one name for each built-in preset of a WebKit browser:
// Safari, and Chrome on iOS. Their User-Agents carry WebKit's frozen
// AppleWebKit/605.1.15, where Chromium's say 537.36.
func webkitPresets() []string {
	var names []string
	for _, name := range fingerprint.Available() {
		p := fingerprint.Get(name)
		if strings.Contains(p.UserAgent, "AppleWebKit/605.1.15") && !slices.Contains(names, p.Name) {
			names = append(names, p.Name)
		}
	}
	slices.Sort(names)
	return names
}

func protoName(p Protocol) string {
	if p == ProtocolHTTP2 {
		return "HTTP/2"
	}
	return "HTTP/1.1"
}

// startH1HeaderCapture serves HTTPS over HTTP/1.1 with cfg's certificate and
// sends the headers of every request it reads, names lowercased, to the
// returned channel.
func startH1HeaderCapture(t *testing.T, cfg *stdtls.Config) (string, <-chan map[string]string) {
	t.Helper()
	cfg = cfg.Clone()
	cfg.NextProtos = []string{"http/1.1"}
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan map[string]string, 16)
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
					h := map[string]string{}
					for {
						l, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if l == "\r\n" {
							break
						}
						if k, v, ok := strings.Cut(l, ":"); ok {
							h[strings.ToLower(k)] = strings.TrimSpace(v)
						}
					}
					got <- h
					io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
				}
			}(c)
		}
	}()
	return ln.Addr().String(), got
}
