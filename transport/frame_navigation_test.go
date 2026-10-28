package transport

import (
	"context"
	"testing"
	"time"
)

// Chrome sends Sec-Fetch-User only on a navigation a person started, and an
// iframe loading its src is not one: on Cloudflare's challenge iframe Chrome
// sent navigate, iframe and upgrade-insecure-requests and no sec-fetch-user.
// The preset's ?1 went out on every navigation regardless, and a caller could
// not take it back, since an empty value goes out as an empty header.
func TestFrameNavigationSendsNoSecFetchUser(t *testing.T) {
	srv := startH2CaptureServer(t)
	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)

	for _, c := range []struct {
		name    string
		headers map[string][]string
		user    string // "" means none on the wire
	}{
		{"top-level navigation", nil, "?1"},
		{"document named outright", map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"document"}}, "?1"},
		{"iframe", map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}, "Sec-Fetch-Site": {"cross-site"}}, ""},
		{"frame, lowercase", map[string][]string{"sec-fetch-mode": {"navigate"}, "sec-fetch-dest": {"frame"}}, ""},
		{"a click inside an iframe", map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}, "Sec-Fetch-User": {"?1"}}, "?1"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + srv.addr + "/", Headers: c.headers})
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		resp.Close()

		got := (<-srv.captures).Headers
		if v, ok := got["sec-fetch-user"]; v != c.user || ok != (c.user != "") {
			t.Errorf("%s: sec-fetch-user %q (sent: %v), want %q", c.name, v, ok, c.user)
		}
		// Still a navigation in every other respect.
		if got["sec-fetch-mode"] != "navigate" || got["upgrade-insecure-requests"] != "1" {
			t.Errorf("%s: no longer a navigation: %v", c.name, got)
		}
	}
}
