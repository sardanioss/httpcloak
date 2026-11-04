package transport

import (
	"bufio"
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// Both tests here are about bytes the server reads, so they go through a real
// send on every HTTP/1.1 path rather than inspecting the header map, which
// looks right either way: forced HTTP/1.1, auto mode falling back on an
// http/1.1 ALPN answer (doHTTP1WithTLSConn), and a streamed request.
var h1Paths = []string{"forced", "alpn fallback", "stream"}

// Chrome sends a header a page set exactly as the page spelled it, and the
// ones it writes itself in its own casing. Measured against a Queue-it room:
// jQuery's X-Requested-With went out Title-Cased and Queue-it's
// x-queueit-qpage-referral lowercase, on one page. The merge used to
// canonicalise both, so the second went out as X-Queueit-Qpage-Referral.
func TestCallerHeaderCasingOverHTTP1(t *testing.T) {
	srv := startH1LineCapture(t)
	for _, path := range h1Paths {
		t.Run(path, func(t *testing.T) {
			lines := srv.send(t, path, "chrome-latest", &Request{Headers: map[string][]string{
				"x-queueit-qpage-referral": {""},
				"X-Requested-With":         {"XMLHttpRequest"},
				"user-agent":               {"custom/1.0"},
				"accept":                   {"application/json"},
				"referer":                  {"https://example.com/"},
				"range":                    {"bytes=0-"},
				"if-range":                 {`"v1"`},
				"dnt":                      {"1"},
			}})
			names := map[string]int{}
			folded := map[string]int{}
			for _, l := range lines {
				name, _, _ := strings.Cut(l, ":")
				names[name]++
				folded[strings.ToLower(name)]++
			}
			for _, want := range []string{
				"x-queueit-qpage-referral", "X-Requested-With", // the caller's
				"User-Agent", "Accept", "Referer", // the browser's, whatever the caller typed
				"Range", "If-Range", // written by Chrome's network stack itself
				"DNT",       // Chrome's spelling, not Go's canonical Dnt
				"sec-ch-ua", // Chrome's own lowercase
			} {
				if names[want] != 1 {
					t.Errorf("want %q on the wire once, got\n%s", want, strings.Join(lines, "\n"))
				}
			}
			for name, n := range folded {
				if n > 1 {
					t.Errorf("%q went out %d times:\n%s", name, n, strings.Join(lines, "\n"))
				}
			}
		})
	}
}

// Chromium sends no priority header on HTTP/1.1, and the preset strip ran
// before the caller's headers were merged, so a caller's value went out there:
// the h2 value a caller sets to correct the per-destination table leaked onto
// every HTTP/1.1 request. Firefox sends one on both, so its caller's value
// stays, as it does on HTTP/2 for every preset.
func TestCallerPriorityOverHTTP1(t *testing.T) {
	srv := startH1LineCapture(t)
	want := map[string]string{
		"chrome-155-windows":  "",
		"android-chrome-148":  "",
		"chrome-147-ios":      "",
		"firefox-148-windows": "u=2",
	}
	for _, path := range h1Paths {
		for preset, w := range want {
			for _, spelling := range []string{"priority", "Priority", "PRIORITY"} {
				lines := srv.send(t, path, preset, &Request{Headers: map[string][]string{
					spelling: {"u=2"}, "Sec-Fetch-Dest": {"script"}}})
				if got := lineValue(lines, "priority"); got != w {
					t.Errorf("%s %s, caller %s: priority %q, want %q", path, preset, spelling, got, w)
				}
			}
		}
	}

	// Exact and TLS-only requests are the caller's to compose, and keep it.
	yes := true
	for name, req := range map[string]*Request{
		"exact": {ExactHeaders: []fingerprint.HeaderPair{
			{Key: "user-agent", Value: "x"}, {Key: "priority", Value: "u=2"}}},
		"tls-only": {TLSOnly: &yes, Headers: map[string][]string{"priority": {"u=2"}}},
	} {
		if got := lineValue(srv.send(t, "forced", "chrome-latest", req), "priority"); got != "u=2" {
			t.Errorf("%s request: priority %q, want the caller's u=2", name, got)
		}
	}

	// HTTP/2 is untouched: Chrome sends the header there.
	h2 := startH2CaptureServer(t)
	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + h2.addr + "/",
		Headers: map[string][]string{"priority": {"u=2"}, "Sec-Fetch-Dest": {"script"}}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Close()
	if got := (<-h2.captures).Headers["priority"]; got != "u=2" {
		t.Errorf("HTTP/2: priority %q, want the caller's u=2", got)
	}
}

// h1LineCapture is an HTTP/1.1-over-TLS server that hands back each request's
// header lines exactly as they arrived, casing included.
type h1LineCapture struct {
	url  string
	reqs chan []string
}

func startH1LineCapture(t *testing.T) *h1LineCapture {
	t.Helper()
	base := startH2CaptureServer(t) // for its certificate only
	base.listener.Close()
	cfg := base.tlsConfig.Clone()
	cfg.NextProtos = []string{"http/1.1"}
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &h1LineCapture{url: "https://" + ln.Addr().String() + "/", reqs: make(chan []string, 16)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *h1LineCapture) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		if _, err := br.ReadString('\n'); err != nil { // request line
			return
		}
		var lines []string
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if l = strings.TrimRight(l, "\r\n"); l == "" {
				break
			}
			lines = append(lines, l)
		}
		s.reqs <- lines
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}
}

// send makes one GET over the named HTTP/1.1 path and returns the header lines
// the server read for it.
func (s *h1LineCapture) send(t *testing.T, path, preset string, req *Request) []string {
	t.Helper()
	tr := NewTransport(preset)
	defer tr.Close()
	tr.SetInsecureSkipVerify(true)
	if path == "alpn fallback" {
		tr.SetDisableHTTP3(true)
	} else {
		tr.SetProtocol(ProtocolHTTP1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req.Method, req.URL = "GET", s.url

	var proto string
	if path == "stream" {
		resp, err := tr.DoStream(ctx, req)
		if err != nil {
			t.Fatalf("%s %s: %v", path, preset, err)
		}
		io.Copy(io.Discard, resp)
		resp.Close()
		proto = resp.Protocol
	} else {
		resp, err := tr.Do(ctx, req)
		if err != nil {
			t.Fatalf("%s %s: %v", path, preset, err)
		}
		resp.Close()
		proto = resp.Protocol
	}
	if proto != "h1" {
		t.Fatalf("%s %s: went out over %q, want h1", path, preset, proto)
	}
	return <-s.reqs
}

// lineValue returns the value of the named header, matched case-insensitively,
// or "" when the request carried none.
func lineValue(lines []string, name string) string {
	for _, l := range lines {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(k, name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
