package client

import (
	"bytes"
	"context"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
)

// startFieldsH2Server answers every HTTP/2 request with an empty 200 and
// passes on the first value of each regular header field it carried.
func startFieldsH2Server(t *testing.T) (string, <-chan map[string]string) {
	ln := priorityTLSListener(t, "h2")
	got := make(chan map[string]string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := io.ReadFull(c, make([]byte, 24)); err != nil {
					return
				}
				fr := http2.NewFramer(c, c)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					switch f := f.(type) {
					case *http2.SettingsFrame:
						if !f.IsAck() {
							fr.WriteSettingsAck()
						}
					case *http2.MetaHeadersFrame:
						h := map[string]string{}
						for _, hf := range f.RegularFields() {
							if _, ok := h[hf.Name]; !ok {
								h[hf.Name] = hf.Value
							}
						}
						got <- h
						var b bytes.Buffer
						hpack.NewEncoder(&b).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
						fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID,
							BlockFragment: b.Bytes(), EndHeaders: true, EndStream: true})
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), got
}

// A browser sends one Accept-Encoding and one Accept-Language on every request
// a page makes. Chrome 156 and Firefox 159, captured headless over HTTP/2 and
// over HTTP/1.1 with TLS, and Safari 26.3 on macOS (HTTP/1.1, HTTP/2, HTTP/3)
// and on the iOS 26.3.1 simulator (HTTP/1.1, HTTP/2), each sent the same pair
// on navigations, iframes, fetch() and XHR and no-cors style, script and image
// loads, and Safari on fonts too. No-cors loads used to send Chrome's pair
// whatever the preset, so safari-18 advertised zstd on subresources only, and
// firefox-133 sent q=0.9 there.
func TestClientEncodingAndLanguagePerFetchMode(t *testing.T) {
	addr, got := startFieldsH2Server(t)
	var presets []string
	for _, name := range fingerprint.Available() {
		if p := fingerprint.Get(name); !slices.Contains(presets, p.Name) {
			presets = append(presets, p.Name)
		}
	}
	slices.Sort(presets)
	// Presets whose pair is not Chrome's, so a hardcoded pair shows.
	for _, want := range []string{"chrome-144-macos", "chrome-147-ios", "firefox-133", "safari-18", "safari-18-ios"} {
		if !slices.Contains(presets, want) {
			t.Fatalf("%s is not among the presets %v", want, presets)
		}
	}
	for _, preset := range presets {
		p := fingerprint.Get(preset)
		enc, lang := p.Headers["Accept-Encoding"], p.Headers["Accept-Language"]
		if enc == "" || lang == "" {
			t.Fatalf("%s names no Accept-Encoding or Accept-Language", preset)
		}
		// Preferring IPv4 saves the 250 ms the pool otherwise waits for an
		// IPv6 address the listener does not have, once per client.
		c := NewClient(preset, WithForceHTTP2(), WithInsecureSkipVerify(), WithPreferIPv4())
		for _, m := range prioModes {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := c.Do(ctx, &Request{Method: "GET", URL: "https://" + addr + "/", FetchMode: m.mode, FetchDest: m.dest})
			cancel()
			if err != nil {
				t.Fatalf("%s %s: %v", preset, m.name, err)
			}
			if h := <-got; h["accept-encoding"] != enc || h["accept-language"] != lang {
				t.Errorf("%s %s: accept-encoding %q, accept-language %q; want %q, %q",
					preset, m.name, h["accept-encoding"], h["accept-language"], enc, lang)
			}
		}
		c.Close()
	}
}
