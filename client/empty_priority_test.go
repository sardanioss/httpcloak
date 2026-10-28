package client

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
)

// A caller's "" for the priority header asks for a request at Chrome's default
// urgency, which goes out with no header and at weight 147; see
// TestEmptyPriorityHeaderSendsNone in the transport package. The client set
// the empty value with Header.Set and sent an empty priority field at the
// script's 220.
func TestClientEmptyPriorityHeaderSendsNone(t *testing.T) {
	type seen struct {
		header string
		sent   bool
		weight int
	}
	ln := priorityTLSListener(t, "h2")
	got := make(chan seen, 4)
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
						s := seen{weight: int(f.Priority.Weight) + 1}
						for _, hf := range f.Fields {
							if hf.Name == "priority" {
								s.header, s.sent = hf.Value, true
							}
						}
						got <- s
						var b strings.Builder
						hpack.NewEncoder(&b).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
						fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID,
							BlockFragment: []byte(b.String()), EndHeaders: true, EndStream: true})
					}
				}
			}(c)
		}
	}()

	c := NewClient("chrome-155-windows", WithForceHTTP2(), WithInsecureSkipVerify())
	defer c.Close()
	for _, tc := range []struct {
		name    string
		headers map[string][]string
		want    seen
	}{
		{"unset", nil, seen{"u=1", true, 220}},
		{"empty", map[string][]string{"priority": {""}}, seen{"", false, 147}},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := c.Do(ctx, &Request{Method: "GET", URL: "https://" + ln.Addr().String() + "/s.js",
			FetchMode: FetchModeNoCors, FetchDest: "script", Headers: tc.headers})
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if s := <-got; s != tc.want {
			t.Errorf("%s: priority %q (sent: %v) weight %d, want %q (sent: %v) %d",
				tc.name, s.header, s.sent, s.weight, tc.want.header, tc.want.sent, tc.want.weight)
		}
	}
}
