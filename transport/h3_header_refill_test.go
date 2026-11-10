package transport

import (
	"context"
	stdhttp "net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// A request carries over HTTP/3 the headers it carries over HTTP/2: the ones
// the header pipeline gave it, and none of those it left out. The HTTP/3
// transport used to give a request every preset header it lacked just before
// sending it, which put back what the pipeline had taken out on purpose: a
// fetch() went out with the Sec-Fetch-User and Upgrade-Insecure-Requests of a
// navigation, a request that opted out of client hints carried them, and
// ExactHeaders, which promises that nothing is added, gained the preset's.
func TestHTTP3AddsNoHeaderThePipelineLeftOut(t *testing.T) {
	var mu sync.Mutex
	seen := map[string][]string{}
	record := func(proto string, header map[string][]string) {
		names := make([]string, 0, len(header))
		for name := range header {
			names = append(names, strings.ToLower(name))
		}
		slices.Sort(names)
		mu.Lock()
		seen[proto] = names
		mu.Unlock()
	}
	h2 := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		record(r.Proto, r.Header)
	}))
	h2.EnableHTTP2 = true
	h2.StartTLS()
	t.Cleanup(h2.Close)
	h3URL := startH3Origin(t, func(w shttp.ResponseWriter, r *shttp.Request) { record(r.Proto, r.Header) })

	for _, c := range []struct {
		name   string
		req    func() *Request
		absent []string
	}{
		{
			"a fetch()",
			func() *Request {
				return &Request{Method: "POST", Body: []byte(`{"a":1}`), Headers: map[string][]string{
					"Content-Type": {"application/json"}, "Accept": {"application/json"}, "Referer": {"https://example.com/page"},
				}}
			},
			[]string{"sec-fetch-user", "upgrade-insecure-requests"},
		},
		{
			"a request without client hints",
			func() *Request { return &Request{Method: "GET", DisableClientHints: true} },
			[]string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"},
		},
		{
			"exact headers",
			func() *Request {
				return &Request{Method: "GET", ExactHeaders: []fingerprint.HeaderPair{{Key: "x-one", Value: "1"}, {Key: "user-agent", Value: "probe"}}}
			},
			[]string{"accept", "accept-language", "sec-fetch-mode", "sec-ch-ua"},
		},
	} {
		sent := map[string][]string{}
		for _, p := range []struct {
			protocol Protocol
			proto    string
			url      string
		}{{ProtocolHTTP2, "HTTP/2.0", h2.URL}, {ProtocolHTTP3, "HTTP/3.0", h3URL}} {
			tr := NewTransport("chrome-latest")
			tr.SetInsecureSkipVerify(true)
			tr.SetProtocol(p.protocol)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			req := c.req()
			req.URL = p.url
			_, err := tr.Do(ctx, req)
			cancel()
			tr.Close()
			if err != nil {
				t.Fatalf("%s over %s: %v", c.name, p.proto, err)
			}
			mu.Lock()
			sent[p.proto] = seen[p.proto]
			delete(seen, p.proto)
			mu.Unlock()
		}
		for _, name := range c.absent {
			if slices.Contains(sent["HTTP/3.0"], name) {
				t.Errorf("%s over HTTP/3 carries %s: %v", c.name, name, sent["HTTP/3.0"])
			}
		}
		if !slices.Equal(sent["HTTP/3.0"], sent["HTTP/2.0"]) {
			t.Errorf("%s: headers over HTTP/3 %v, over HTTP/2 %v", c.name, sent["HTTP/3.0"], sent["HTTP/2.0"])
		}
	}
}
