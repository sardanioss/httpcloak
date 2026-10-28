package session

import (
	"context"
	"slices"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// A hop the session follows has to go out the way a browser sends one, and
// Firefox orders a hop differently from the request that led to it. Firefox
// 159 settles a hop's Referer before it picks a connection, so on the hop
// Referer comes right after Accept-Encoding; on a first navigation from a page
// that set no Referrer-Policy it comes after Connection. That held for the
// iframe, XMLHttpRequest and fetch() hops and the post-redirect-get hop
// captured on 2026-10-28. The first request names a Referer of its own so the
// hop carries one whatever value the redirect path settles on.
func TestRedirectHopHeaderOrderFirefox(t *testing.T) {
	srv := newBodyCapture(t, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{Preset: "firefox-148-windows", FollowRedirects: true})

	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "hop0",
		Headers: map[string][]string{"Referer": {srv.url + "page"}},
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	hops := srv.recorded()
	if len(hops) != 2 {
		t.Fatalf("server saw %d hops, want 2", len(hops))
	}
	for i, want := range []string{"connection", "accept-encoding"} {
		names := hops[i].allHeaders
		r := slices.Index(names, "referer")
		if r < 1 || names[r-1] != want {
			t.Errorf("hop %d: Referer should follow %s: %q", i+1, want, names)
		}
	}
}
