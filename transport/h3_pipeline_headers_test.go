package transport

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// HTTP3Transport.RoundTrip used to put back every preset header a request did
// not carry, after the header pipeline had built it, so whatever the pipeline
// took off came back on HTTP/3 with the preset's navigation value. A fetch went
// out with sec-fetch-user: ?1 and upgrade-insecure-requests: 1, which Chrome
// sends on no fetch; DisableClientHints still sent the sec-ch-ua trio; and a
// per-request TLS-only request carried the whole navigation set. HTTP/1.1 and
// HTTP/2 never did this, so each request here has to reach an HTTP/3 server
// with the same headers it sends over HTTP/2.
func TestHTTP3SendsTheHeadersThePipelineBuilt(t *testing.T) {
	type h3Seen struct {
		names []string
		ua    string
	}
	h3Got := make(chan h3Seen, 1)
	origin := startH3Origin(t, shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		var names []string
		for k := range r.Header {
			names = append(names, strings.ToLower(k))
		}
		slices.Sort(names)
		h3Got <- h3Seen{names, r.Header.Get("User-Agent")}
	}))
	h2 := startH2CaptureServer(t)

	tlsOnly := true
	for _, c := range []struct {
		name string
		req  Request
		gone []string // what the pipeline takes off, which HTTP/3 used to put back
	}{
		{"navigation", Request{}, nil},
		{"fetch", Request{Headers: map[string][]string{"Accept": {"application/json"}}},
			[]string{"sec-fetch-user", "upgrade-insecure-requests"}},
		{"no client hints", Request{DisableClientHints: true},
			[]string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}},
		{"per-request tls-only", Request{TLSOnly: &tlsOnly, Headers: map[string][]string{"User-Agent": {"probe"}, "Accept": {"*/*"}}},
			[]string{"sec-fetch-mode", "sec-ch-ua", "priority"}},
		// With no User-Agent of the caller's, HTTP/3 used to add the preset's.
		{"per-request tls-only, no User-Agent", Request{TLSOnly: &tlsOnly, Headers: map[string][]string{"Accept": {"*/*"}}},
			[]string{"sec-fetch-mode", "sec-ch-ua", "priority"}},
		// Exact pairs keep their lowercase keys, which the back-fill's
		// Header.Get could not see, so it added a second User-Agent and the
		// preset's set beside them.
		{"exact headers", Request{ExactHeaders: []fingerprint.HeaderPair{
			{Key: "user-agent", Value: "probe"}, {Key: "accept", Value: "*/*"}}},
			[]string{"sec-fetch-mode", "sec-ch-ua", "priority"}},
		// The one header HTTP/3 still fills in: with no user-agent field,
		// quic-go would send its own name where HTTP/2 sends the preset's.
		{"exact headers, no User-Agent", Request{ExactHeaders: []fingerprint.HeaderPair{
			{Key: "accept", Value: "*/*"}}},
			[]string{"sec-fetch-mode", "sec-ch-ua", "priority"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sent := map[Protocol][]string{}
			ua := map[Protocol]string{}
			for _, proto := range []Protocol{ProtocolHTTP2, ProtocolHTTP3} {
				tr := NewTransport("chrome-155-windows")
				tr.SetProtocol(proto)
				tr.SetInsecureSkipVerify(true)
				req := c.req
				req.Method = "GET"
				req.URL = "https://" + h2.addr + "/"
				if proto == ProtocolHTTP3 {
					req.URL = origin
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				resp, err := tr.Do(ctx, &req)
				cancel()
				tr.Close()
				if err != nil {
					t.Fatalf("%s: %v", proto, err)
				}
				resp.Close()
				if proto == ProtocolHTTP3 {
					got := <-h3Got
					sent[proto], ua[proto] = got.names, got.ua
					continue
				}
				captured := (<-h2.captures).Headers
				for k := range captured {
					if !strings.HasPrefix(k, ":") {
						sent[proto] = append(sent[proto], k)
					}
				}
				ua[proto] = captured["user-agent"]
				slices.Sort(sent[proto])
			}
			if !slices.Equal(sent[ProtocolHTTP3], sent[ProtocolHTTP2]) {
				t.Errorf("HTTP/3 sent %v\nHTTP/2 sent %v", sent[ProtocolHTTP3], sent[ProtocolHTTP2])
			}
			if ua[ProtocolHTTP3] != ua[ProtocolHTTP2] {
				t.Errorf("HTTP/3 User-Agent %q, HTTP/2 %q", ua[ProtocolHTTP3], ua[ProtocolHTTP2])
			}
			for _, name := range c.gone {
				if slices.Contains(sent[ProtocolHTTP3], name) {
					t.Errorf("HTTP/3 sent %s, which the pipeline took off", name)
				}
			}
		})
	}
}
