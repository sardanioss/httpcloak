package client

import (
	"net/url"
	"slices"
	"testing"

	customhttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// The navigation headers here set Sec-Fetch-User: ?1 unconditionally, and
// Chrome sends it only on a navigation a person started; an iframe loading its
// src is not one. A request the caller marks as a frame's navigation goes
// without, unless the caller sets it for a click inside the frame.
func TestClientFrameNavigationSendsNoSecFetchUser(t *testing.T) {
	preset := fingerprint.Get("chrome-latest")
	target, _ := url.Parse("https://example.com/")
	for _, c := range []struct {
		name    string
		headers map[string][]string
		user    string // "" means none
	}{
		{"top-level navigation", nil, "?1"},
		{"iframe", map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}}, ""},
		{"frame, lowercase", map[string][]string{"sec-fetch-mode": {"navigate"}, "sec-fetch-dest": {"frame"}}, ""},
		{"a click inside an iframe", map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}, "Sec-Fetch-User": {"?1"}}, "?1"},
	} {
		req := &Request{Method: "GET", URL: target.String(), Headers: c.headers}
		httpReq, err := customhttp.NewRequest("GET", req.URL, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		applyModeHeaders(httpReq, preset, req, target, nil)

		if got := httpReq.Header.Get("Sec-Fetch-User"); got != c.user {
			t.Errorf("%s: Sec-Fetch-User %q, want %q", c.name, got, c.user)
		}
		if httpReq.Header.Get("Upgrade-Insecure-Requests") != "1" {
			t.Errorf("%s: no longer a navigation: %v", c.name, httpReq.Header)
		}
	}
}

// The same rule through Do, as the server sees it, over HTTP/1.1 and HTTP/2.
func TestClientFrameNavigationSendsNoSecFetchUserOnTheWire(t *testing.T) {
	for _, preset := range []string{"chrome-latest", "firefox-latest"} {
		for _, p := range hopCarryProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				o := newHopCarryOrigin(t)
				c := newHopCarryClient(t, preset, p.force)
				for _, tc := range []struct {
					path    string
					headers map[string][]string
					user    []string // nil means none
				}{
					{"/top", nil, []string{"?1"}},
					{"/iframe", map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}}, nil},
					{"/frame", map[string][]string{"sec-fetch-mode": {"navigate"}, "sec-fetch-dest": {"frame"}}, nil},
					{"/click", map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}, "Sec-Fetch-User": {"?1"}}, []string{"?1"}},
				} {
					followHops(t, c, &Request{Method: "GET", URL: o.url + tc.path, Headers: tc.headers})
					h := o.hit(t, tc.path).header
					if got := h.Values("Sec-Fetch-User"); !slices.Equal(got, tc.user) {
						t.Errorf("%s: Sec-Fetch-User %q, want %q", tc.path, got, tc.user)
					}
					if h.Get("Sec-Fetch-Mode") != "navigate" {
						t.Errorf("%s: Sec-Fetch-Mode %q, want navigate", tc.path, h.Get("Sec-Fetch-Mode"))
					}
				}
			})
		}
	}
}
