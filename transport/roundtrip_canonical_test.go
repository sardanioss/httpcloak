package transport

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/http/httptrace"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// fullShape exercises everything a canonical map differs on: repeated
// fields, Set-Cookie twice, Location, WWW-Authenticate (whose canonical form
// is Www-Authenticate), a name outside every common header table, a 103
// ahead of the final response, and trailers announced in the header block.
var fullShape = h2Config{
	Body: []byte("ok"),
	Informational: [][2]string{
		{"link", "</a.css>; rel=preload; as=style"},
		{"x-early-thing", "e1"},
	},
	ResponseHeaders: [][2]string{
		{"content-type", "text/plain; charset=utf-8"},
		{"set-cookie", "a=1; Path=/"},
		{"x-multi-value", "one"},
		{"location", "/next"},
		{"set-cookie", "b=2; Path=/"},
		{"www-authenticate", `Basic realm="r"`},
		{"x-multi-value", "two"},
		{"trailer", "x-checksum, x-final-state"},
	},
	Trailers: [][2]string{
		{"x-checksum", "abc"},
		{"x-final-state", "done"},
	},
}

// roundTripResult is what one RoundTrip leaves for its caller to see.
type roundTripResult struct {
	resp          *http.Response
	err           string
	informational []textproto.MIMEHeader // as handed to Got1xxResponse, not copied
	hooks         map[string]int
	readLoop      []string // GotFirstResponseByte and Got1xxResponse, in call order
	sameRequest   bool     // resp.Request is the request passed in
	sameContext   bool     // resp.Request carries the caller's context
	requests      int      // request arrivals the server saw
}

// roundTripOptions shape the request sent.
type roundTripOptions struct {
	traced    bool   // attach a ClientTrace with Got1xxResponse and four other hooks
	body      []byte // non-nil sends a POST whose body can be rewound (GetBody)
	got1xxErr error  // what Got1xxResponse returns
}

// roundTrip sends one request to a fresh server built from cfg through an
// HTTP2Transport's exported RoundTrip and reads the body to the end, so the
// trailers are in. reference builds the transport as releases before wire
// case did: connections with WireCaseResponseHeaders off, no trace layered.
func roundTrip(t *testing.T, cfg h2Config, reference bool, o roundTripOptions) roundTripResult {
	t.Helper()
	s := startH2Server(t, cfg)
	tr := NewHTTP2Transport(fingerprint.Get("chrome-latest"), dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	tr.canonicalHeadersForTest = reference
	defer tr.Close()

	res := roundTripResult{hooks: map[string]int{}}
	var mu sync.Mutex
	note := func(name string, readLoop bool) {
		mu.Lock()
		defer mu.Unlock()
		res.hooks[name]++
		if readLoop {
			res.readLoop = append(res.readLoop, name)
		}
	}
	// WroteRequest runs on the stream's writer goroutine, which can still be
	// finishing when RoundTrip returns, so every call is waited for below.
	wrote := make(chan struct{}, 8)
	ctx := t.Context()
	if o.traced {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotConn:      func(httptrace.GotConnInfo) { note("GotConn", false) },
			WroteHeaders: func() { note("WroteHeaders", false) },
			WroteRequest: func(httptrace.WroteRequestInfo) {
				note("WroteRequest", false)
				wrote <- struct{}{}
			},
			GotFirstResponseByte: func() { note("GotFirstResponseByte", true) },
			Got1xxResponse: func(_ int, h textproto.MIMEHeader) error {
				note("Got1xxResponse", true)
				mu.Lock()
				defer mu.Unlock()
				res.informational = append(res.informational, h)
				return o.got1xxErr
			},
		})
	}

	method, body := "GET", io.Reader(nil)
	if o.body != nil {
		method, body = "POST", bytes.NewReader(o.body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.url("/"), body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		res.err = err.Error()
	} else {
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatalf("reading the body: %v", err)
		}
		resp.Body.Close()
		res.resp = resp
		res.sameRequest = resp.Request == req
		res.sameContext = resp.Request.Context() == ctx
	}
	res.requests = len(s.attempts())
	if o.traced {
		for range res.requests {
			select {
			case <-wrote:
			case <-time.After(10 * time.Second):
				t.Fatalf("WroteRequest did not run for each of %d requests", res.requests)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	return res
}

// diffRoundTrips reports every way got differs from want, as a caller of
// RoundTrip could observe it. Hooks run on different goroutines have no order
// to compare, so only their counts are.
func diffRoundTrips(got, want roundTripResult) []string {
	var diffs []string
	check := func(what string, g, w any) {
		if !reflect.DeepEqual(g, w) {
			diffs = append(diffs, fmt.Sprintf("%s = %#v, want %#v", what, g, w))
		}
	}
	check("error", got.err, want.err)
	check("requests the server saw", got.requests, want.requests)
	check("hook counts", got.hooks, want.hooks)
	check("read loop hooks", got.readLoop, want.readLoop)
	check("1xx maps", got.informational, want.informational)
	check("resp.Request is the caller's", got.sameRequest, want.sameRequest)
	check("resp.Request has the caller's context", got.sameContext, want.sameContext)
	if got.resp != nil && want.resp != nil {
		check("Header", got.resp.Header, want.resp.Header)
		check("Trailer", got.resp.Trailer, want.resp.Trailer)
		check("resp.Request", requestShape(got.resp.Request), requestShape(want.resp.Request))
	}
	return diffs
}

// requestShape is what a replayed request shares with the one it replays.
func requestShape(r *http.Request) string {
	return fmt.Sprint(r.Method, " ", r.URL.Path, " ", r.ContentLength)
}

// manyNames is n distinct names outside every common header table, as many
// as one HEADERS frame from the test server holds.
func manyNames(n int) [][2]string {
	out := make([][2]string, n)
	for i := range out {
		out[i] = [2]string{fmt.Sprintf("x-generated-name-%04d", i), "v"}
	}
	return out
}

// RoundTrip is exported, so whoever calls it directly must see what they saw
// before the connection asked for wire-case names: Header, Trailer and the
// 1xx maps, a ClientTrace's hooks run as often and in the same order, the
// same request and context on the response, and the same failures. Each row
// runs with and without a trace, since a trace is what makes RoundTrip copy
// the request, against a transport built as before.
func TestRoundTripMatchesWireCaseOff(t *testing.T) {
	long := "x-" + strings.Repeat("long-name-", 12)
	refused := fullShape
	refused.ResetStreams = map[int]uint32{1: 0x7} // REFUSED_STREAM
	readBody := fullShape
	readBody.ReadToEndStream = true
	refusedBody := refused
	refusedBody.ReadToEndStream = true
	hookErr := errors.New("stop at 1xx")

	for _, tc := range []struct {
		name      string
		cfg       h2Config
		body      []byte
		got1xxErr error // only meaningful traced
		replayed  bool  // the first stream is refused and sent again
	}{
		{name: "full shape", cfg: fullShape},
		{name: "no fields", cfg: h2Config{Body: []byte("ok")}},
		{name: "unusual names", cfg: h2Config{Body: []byte("ok"), ResponseHeaders: [][2]string{
			{long, "1"}, {"x_under_score", "2"}, {"x-9-digits0", "3"},
			{"p3p", "4"}, {"x--double", "5"}, {long, "6"},
		}}},
		{name: "many names", cfg: h2Config{Body: []byte("ok"), ResponseHeaders: manyNames(500)}},
		{name: "refused and replayed", cfg: refused, replayed: true},
		{name: "post", cfg: readBody, body: []byte("payload")},
		{name: "refused post replayed from GetBody", cfg: refusedBody, body: []byte("payload"), replayed: true},
		{name: "1xx hook error", cfg: fullShape, got1xxErr: hookErr},
		{name: "1xx hook error after a replay", cfg: refused, got1xxErr: hookErr, replayed: true},
	} {
		for _, traced := range []bool{false, true} {
			if tc.got1xxErr != nil && !traced {
				continue
			}
			t.Run(fmt.Sprintf("%s/traced=%v", tc.name, traced), func(t *testing.T) {
				o := roundTripOptions{traced: traced, body: tc.body, got1xxErr: tc.got1xxErr}
				want := roundTrip(t, tc.cfg, true, o)
				got := roundTrip(t, tc.cfg, false, o)
				for _, d := range diffRoundTrips(got, want) {
					t.Error(d)
				}
				if tc.replayed && want.requests != 2 {
					t.Errorf("the server saw %d requests, want 2: the refused stream was not replayed", want.requests)
				}
				if traced && tc.cfg.Informational != nil && len(want.informational) != 1 {
					t.Errorf("the trace saw %d 1xx responses, want 1", len(want.informational))
				}
			})
		}
	}
}

// The net/http accessors that look names up canonically work on what
// RoundTrip returns.
func TestRoundTripCanonicalAccessors(t *testing.T) {
	res := roundTrip(t, fullShape, false, roundTripOptions{traced: true})
	if res.resp == nil {
		t.Fatalf("RoundTrip failed: %s", res.err)
	}
	h := res.resp.Header
	if got, want := h.Get("Content-Type"), "text/plain; charset=utf-8"; got != want {
		t.Errorf("Header.Get(%q) = %q, want %q", "Content-Type", got, want)
	}
	if got, want := h.Get("WWW-Authenticate"), `Basic realm="r"`; got != want {
		t.Errorf("Header.Get(%q) = %q, want %q", "WWW-Authenticate", got, want)
	}
	if got, want := h.Values("X-Multi-Value"), []string{"one", "two"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Header.Values(%q) = %q, want %q", "X-Multi-Value", got, want)
	}
	if c := res.resp.Cookies(); len(c) != 2 || c[0].Name != "a" || c[1].Name != "b" {
		t.Errorf("Cookies() = %v, want a and b", c)
	}
	if loc, err := res.resp.Location(); err != nil || loc.Path != "/next" {
		t.Errorf("Location() = %v, %v, want /next", loc, err)
	}
	if got, want := res.resp.Trailer.Get("X-Checksum"), "abc"; got != want {
		t.Errorf("Trailer.Get(%q) = %q, want %q", "X-Checksum", got, want)
	}
	if len(res.informational) != 1 || res.informational[0].Get("Link") == "" {
		t.Errorf("1xx maps = %#v, want one with Link under its canonical name", res.informational)
	}
}
