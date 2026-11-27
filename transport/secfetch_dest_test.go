package transport

import (
	"context"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/secfetch"
)

// secfetch.Dest is how the session tells a top-level navigation from
// everything else, so it has to name the Sec-Fetch-Dest the request really
// carries. It decides apart from applyPresetHeaders, which composes the
// header, so this sends each shape and checks both against the expected value.
func TestSecFetchDestMatchesTheWire(t *testing.T) {
	srv := startH2CaptureServer(t)
	yes := true
	shapes := []struct {
		name string
		req  Request
		want string // "" means no Sec-Fetch-Dest on the wire
	}{
		{"navigation", Request{Method: "GET"}, "document"},
		{"json fetch", Request{Method: "GET", Headers: map[string][]string{"Accept": {"application/json"}}}, "empty"},
		{"json post", Request{Method: "POST", Body: []byte("{}"), Headers: map[string][]string{"Content-Type": {"application/json"}}}, "empty"},
		{"form post", Request{Method: "POST", Body: []byte("a=1"), Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}}, "document"},
		{"delete", Request{Method: "DELETE"}, "empty"},
		{"iframe", Request{Method: "GET", Headers: map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}}}, "iframe"},
		{"script", Request{Method: "GET", Headers: map[string][]string{"Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Dest": {"script"}}}, "script"},
		{"image, lowercase", Request{Method: "GET", Headers: map[string][]string{"sec-fetch-dest": {"image"}}}, "image"},
		{"tls-only", Request{Method: "GET", TLSOnly: &yes}, ""},
		{"tls-only with a dest", Request{Method: "GET", TLSOnly: &yes, Headers: map[string][]string{"Sec-Fetch-Dest": {"document"}}}, "document"},
		{"exact", Request{Method: "GET", ExactHeaders: []fingerprint.HeaderPair{{Key: "user-agent", Value: "x"}, {Key: "sec-fetch-dest", Value: "empty"}}}, "empty"},
		{"exact without one", Request{Method: "GET", ExactHeaders: []fingerprint.HeaderPair{{Key: "user-agent", Value: "x"}}}, ""},
	}
	for _, preset := range []string{"chrome-latest", "firefox-latest", "safari-latest-ios"} {
		tr := NewTransport(preset)
		tr.SetProtocol(ProtocolHTTP2)
		tr.SetInsecureSkipVerify(true)
		for _, s := range shapes {
			req := s.req
			req.URL = "https://" + srv.addr + "/"
			tlsOnly := req.TLSOnly != nil && *req.TLSOnly
			if got := secfetch.Dest(tr.getPreset(), tlsOnly, req.Method, req.Headers, req.ExactHeaders); got != s.want {
				t.Errorf("%s %s: secfetch.Dest %q, want %q", preset, s.name, got, s.want)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := tr.Do(ctx, &req)
			cancel()
			if err != nil {
				t.Fatalf("%s %s: %v", preset, s.name, err)
			}
			resp.Close()
			if got := (<-srv.captures).Headers["sec-fetch-dest"]; got != s.want {
				t.Errorf("%s %s: the wire carried %q, want %q", preset, s.name, got, s.want)
			}
		}
		tr.Close()
	}
}
