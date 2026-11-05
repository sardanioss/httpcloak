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
	h3Names := make(chan []string, 1)
	origin := startH3Origin(t, shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		var names []string
		for k := range r.Header {
			names = append(names, strings.ToLower(k))
		}
		slices.Sort(names)
		h3Names <- names
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
	} {
		t.Run(c.name, func(t *testing.T) {
			sent := map[Protocol][]string{}
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
					sent[proto] = <-h3Names
					continue
				}
				for k := range (<-h2.captures).Headers {
					if !strings.HasPrefix(k, ":") {
						sent[proto] = append(sent[proto], k)
					}
				}
				slices.Sort(sent[proto])
			}
			if !slices.Equal(sent[ProtocolHTTP3], sent[ProtocolHTTP2]) {
				t.Errorf("HTTP/3 sent %v\nHTTP/2 sent %v", sent[ProtocolHTTP3], sent[ProtocolHTTP2])
			}
			for _, name := range c.gone {
				if slices.Contains(sent[ProtocolHTTP3], name) {
					t.Errorf("HTTP/3 sent %s, which the pipeline took off", name)
				}
			}
		})
	}
}
