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
	"github.com/sardanioss/quic-go"
	h3qlog "github.com/sardanioss/quic-go/http3/qlog"
	"github.com/sardanioss/quic-go/qlogwriter"
	"github.com/sardanioss/quic-go/testutils/events"
)

// A request with no body says "content-length: 0" on the methods its browser
// says it on, which fetch() and XMLHttpRequest show on every method: Chrome
// 156 and Firefox 159 on a POST and a PUT alone, Safari 26.6 on a PATCH, a
// DELETE and an OPTIONS as well, none of them on a GET or a HEAD, and Chrome
// and Safari the same over HTTP/3. Every preset used to have net/http's rule
// on every protocol (POST, PUT and PATCH), so a Chrome sent a length Chrome
// does not and a Safari left two out.
func TestEmptyBodyDeclaresItsLengthOnTheBrowsersMethods(t *testing.T) {
	var mu sync.Mutex
	seen := map[string][]string{}
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		mu.Lock()
		seen[r.Proto+" "+r.Method] = r.Header.Values("Content-Length")
		mu.Unlock()
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h3URL := startH3Origin(t, func(w shttp.ResponseWriter, r *shttp.Request) {
		mu.Lock()
		seen[r.Proto+" "+r.Method] = r.Header.Values("Content-Length")
		mu.Unlock()
	})

	chrome := []string{"POST", "PUT"}
	safari := []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	for _, c := range []struct {
		preset   string
		declares []string
	}{
		{"chrome-latest", chrome},
		{"chrome-latest-android", chrome},
		{"firefox-latest", chrome},
		{"safari-latest", safari},
		{"safari-latest-ios", safari},
		// Chrome on iOS is WebKit over Apple's network stack, and its newest
		// presets inherit the rule from the one they are based on.
		{"chrome-latest-ios", safari},
	} {
		for _, p := range []struct {
			protocol Protocol
			proto    string
			url      string
		}{{ProtocolHTTP1, "HTTP/1.1", srv.URL}, {ProtocolHTTP2, "HTTP/2.0", srv.URL}, {ProtocolHTTP3, "HTTP/3.0", h3URL}} {
			if p.protocol == ProtocolHTTP3 && !fingerprint.Get(c.preset).SupportHTTP3 {
				continue
			}
			tr := NewTransport(c.preset)
			tr.SetInsecureSkipVerify(true)
			tr.SetProtocol(p.protocol)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			for _, stream := range []bool{false, true} {
				for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
					if stream {
						resp, err := tr.DoStream(ctx, &Request{Method: method, URL: p.url})
						if err != nil {
							t.Fatalf("%s %s DoStream %s: %v", c.preset, p.proto, method, err)
						}
						resp.ReadAll()
					} else if _, err := tr.Do(ctx, &Request{Method: method, URL: p.url}); err != nil {
						t.Fatalf("%s %s Do %s: %v", c.preset, p.proto, method, err)
					}
					mu.Lock()
					got, reached := seen[p.proto+" "+method]
					delete(seen, p.proto+" "+method)
					mu.Unlock()
					if !reached {
						t.Fatalf("%s: no %s %s reached the server", c.preset, p.proto, method)
					}
					var want []string
					if slices.Contains(c.declares, method) {
						want = []string{"0"}
					}
					if !slices.Equal(got, want) {
						t.Errorf("%s %s stream=%v %s: content-length %q, want %q", c.preset, p.proto, stream, method, got, want)
					}
				}
			}
			cancel()
			tr.Close()
		}
	}
}

// Over HTTP/3 a request's content-length goes where its browser puts it, as on
// HTTP/2: Chrome sends it before every other header, and Safari after the
// headers WebKit sets and before the ones its network stack adds. quic-go used
// to write it after everything else, whatever the header order said, so every
// request with a body ended in a header no browser ends with.
func TestHTTP3WritesContentLengthInThePresetsSlot(t *testing.T) {
	url := startH3Origin(t, func(w shttp.ResponseWriter, r *shttp.Request) {})

	// The header fields of the request the transport sends, in the order its
	// HEADERS frame holds them, read from the connection's own event log.
	sent := func(preset string, req *Request) []string {
		tr := NewTransport(preset)
		defer tr.Close()
		tr.SetInsecureSkipVerify(true)
		tr.SetProtocol(ProtocolHTTP3)
		log := &events.Recorder{}
		tr.h3Transport.quicConfig.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &events.Trace{Recorder: log}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		req.URL = url
		if _, err := tr.Do(ctx, req); err != nil {
			t.Fatalf("%s %s: %v", preset, req.Method, err)
		}
		var names []string
		for _, ev := range log.Events(h3qlog.FrameCreated{}) {
			frame, ok := ev.(h3qlog.FrameCreated).Frame.Frame.(h3qlog.HeadersFrame)
			if !ok {
				continue
			}
			for _, field := range frame.HeaderFields {
				if !strings.HasPrefix(field.Name, ":") {
					names = append(names, field.Name)
				}
			}
		}
		if len(names) == 0 {
			t.Fatalf("%s %s: the connection logged no request headers", preset, req.Method)
		}
		return names
	}
	json := func(method string) *Request {
		return &Request{Method: method, Body: []byte(`{"a":1}`), Headers: map[string][]string{"Content-Type": {"application/json"}}}
	}

	// Chrome 156 over HTTP/3: content-length leads a POST's headers, with a
	// body and without one.
	for _, req := range []*Request{json("POST"), {Method: "POST"}} {
		if names := sent("chrome-latest", req); names[0] != "content-length" {
			t.Errorf("chrome-latest POST: content-length is not the first header: %v", names)
		}
	}
	if names := sent("chrome-latest", &Request{Method: "PATCH"}); slices.Contains(names, "content-length") {
		t.Errorf("chrome-latest PATCH with no body declares a length: %v", names)
	}

	// Safari's order is not a list: it depends on what a request holds, so a
	// caller gives each request its own. The length takes the slot that order
	// names, here the one Safari 26 gave a fetch() over HTTP/3: after the
	// headers WebKit sets and before the ones its network stack adds, on a
	// DELETE with no body as on a POST with one.
	order := []string{"accept", "content-type", "sec-fetch-site", "sec-fetch-mode", "user-agent", "sec-fetch-dest", "content-length", "accept-language", "accept-encoding"}
	for _, req := range []*Request{json("POST"), {Method: "DELETE"}} {
		req.HeaderOrder = order
		names := sent("safari-latest-ios", req)
		at := slices.Index(names, "content-length")
		if at < 1 || at+1 >= len(names) || names[at-1] != "sec-fetch-dest" || names[at+1] != "accept-language" {
			t.Errorf("safari-latest-ios %s: content-length is not between sec-fetch-dest and accept-language: %v", req.Method, names)
		}
	}
}
