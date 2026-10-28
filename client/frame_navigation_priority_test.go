package client

import (
	"context"
	"testing"
	"time"
)

// The client applies the priority table before the caller's headers, so a
// navigation the caller marks as an iframe's took the page's priority. Firefox
// sends an iframe's document at u=4; see TestFrameNavigationPriority in the
// transport package.
func TestClientFrameNavigationPriority(t *testing.T) {
	addr, got := startPriorityH2Server(t)
	for _, c := range []struct {
		preset string
		want   h2Seen
	}{
		{"firefox-148-windows", h2Seen{"u=4", 22, false}},
		{"chrome-155-windows", h2Seen{"u=0, i", 256, true}},
	} {
		cl := NewClient(c.preset, WithForceHTTP2(), WithInsecureSkipVerify())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := cl.Do(ctx, &Request{Method: "GET", URL: "https://" + addr + "/frame", FetchMode: FetchModeNavigate,
			Headers: map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}}})
		cancel()
		cl.Close()
		if err != nil {
			t.Fatalf("%s: %v", c.preset, err)
		}
		if s := <-got; s != c.want {
			t.Errorf("%s iframe navigation: priority %q weight %d exclusive %v, want %q %d %v",
				c.preset, s.priority, s.weight, s.excl, c.want.priority, c.want.weight, c.want.excl)
		}
	}
}
