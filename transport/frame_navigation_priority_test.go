package transport

import (
	"context"
	"testing"
	"time"
)

// Firefox 159 loads an iframe's document at priority u=4, where the page
// itself goes at u=0, i; its table has iframe at u=4, weight 22, measured on
// 133, 148 and 152. The priority table read Sec-Fetch-Dest before the caller's
// headers were merged, and a navigation still carries the preset's document
// there, so a Firefox iframe navigation went out with the page's u=0, i beside
// the iframe's weight. Chrome sends an iframe's document at u=0, i like the
// page's, so its requests are unchanged.
func TestFrameNavigationPriority(t *testing.T) {
	iframe := map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}, "Sec-Fetch-Site": {"same-origin"}}
	for _, c := range []struct {
		name     string
		preset   string
		headers  map[string][]string
		priority string
		weight   int
	}{
		{"firefox page", "firefox-148-windows", nil, "u=0, i", 42},
		{"firefox iframe", "firefox-148-windows", iframe, "u=4", 22},
		{"chrome page", "chrome-155-windows", nil, "u=0, i", 256},
		{"chrome iframe", "chrome-155-windows", iframe, "u=0, i", 256},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := startH2CaptureServer(t)
			tr := NewTransport(c.preset)
			tr.SetProtocol(ProtocolHTTP2)
			tr.SetInsecureSkipVerify(true)
			defer tr.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + srv.addr + "/frame", Headers: c.headers})
			if err != nil {
				t.Fatal(err)
			}
			resp.Close()

			got := <-srv.captures
			if got.Headers["priority"] != c.priority {
				t.Errorf("priority %q, want %q", got.Headers["priority"], c.priority)
			}
			if w := int(got.Priority.Weight) + 1; w != c.weight {
				t.Errorf("weight %d, want %d", w, c.weight)
			}
		})
	}
}
