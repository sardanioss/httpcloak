package pool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	nethttp "net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/http/httptrace"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/respheader"
)

// startServer starts an HTTP/2 server whose every response carries a 103,
// repeated fields, Location, WWW-Authenticate and a trailer.
func startServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		io.Copy(io.Discard, r.Body)
		h := w.Header()
		h.Set("Link", "</a.css>; rel=preload")
		w.WriteHeader(nethttp.StatusEarlyHints)
		h.Del("Link")
		h["Date"] = nil
		h.Set("Content-Type", "text/plain")
		h.Add("Set-Cookie", "a=1")
		h.Add("Set-Cookie", "b=2")
		h.Set("Location", "/next")
		h.Set("Www-Authenticate", `Basic realm="r"`)
		h.Set("Trailer", "X-Checksum")
		w.WriteHeader(nethttp.StatusOK)
		io.WriteString(w, "ok")
		h.Set("X-Checksum", "abc")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// connMode is how the Manager under test is set up.
type connMode int

const (
	converted connMode = iota // as any caller outside this module gets it
	reference                 // as releases before wire case built connections
	marked                    // as httpcloak's own client marks its Manager
)

// connResult is what one Conn.RoundTrip leaves for its caller to see.
type connResult struct {
	resp          *http.Response
	err           string
	informational []textproto.MIMEHeader // as handed to Got1xxResponse, not copied
	sameRequest   bool
	sameContext   bool
}

// newManager returns a Manager set up for mode, and the HostPool it will use
// for srv.
func newManager(t *testing.T, srv *httptest.Server, mode connMode) (*Manager, *HostPool) {
	t.Helper()
	m := NewManagerWithTLSConfig(fingerprint.Get("chrome-latest"), true)
	t.Cleanup(m.Close)
	if mode == marked {
		respheader.KeepWireCase(m)
	}
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	hp, err := m.GetPool(u.Hostname(), u.Port())
	if err != nil {
		t.Fatal(err)
	}
	hp.canonicalHeadersForTest = mode == reference
	return m, hp
}

// connRoundTrip sends one request over a pooled connection to srv, under a
// ClientTrace whose Got1xxResponse returns got1xxErr, and reads the body to
// the end so the trailer is in. A non-nil body sends a POST. The error is for
// a request that could not be sent; a failed round trip is in res.err.
func connRoundTrip(ctx context.Context, srv *httptest.Server, m *Manager, body []byte, got1xxErr error) (connResult, error) {
	var res connResult
	var mu sync.Mutex
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		Got1xxResponse: func(_ int, h textproto.MIMEHeader) error {
			mu.Lock()
			defer mu.Unlock()
			res.informational = append(res.informational, h)
			return got1xxErr
		},
	})
	method, reqBody := "GET", io.Reader(nil)
	if body != nil {
		method, reqBody = "POST", bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, srv.URL+"/", reqBody)
	if err != nil {
		return res, err
	}
	conn, err := m.GetConn(ctx, req.URL.Hostname(), req.URL.Port())
	if err != nil {
		return res, fmt.Errorf("GetConn: %w", err)
	}
	resp, err := conn.RoundTrip(req)
	if err != nil {
		res.err = err.Error()
	} else {
		_, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			return res, fmt.Errorf("reading the body: %w", err)
		}
		res.resp = resp
		res.sameRequest = resp.Request == req
		res.sameContext = resp.Request.Context() == ctx
	}
	mu.Lock()
	defer mu.Unlock()
	return res, nil
}

// mustConnRoundTrip is connRoundTrip for the test's own goroutine.
func mustConnRoundTrip(t *testing.T, srv *httptest.Server, m *Manager, body []byte, got1xxErr error) connResult {
	t.Helper()
	res, err := connRoundTrip(t.Context(), srv, m, body, got1xxErr)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Conn.RoundTrip is exported, so a caller using the pool directly sees what a
// connection built before wire case gave: Header, Trailer and the 1xx maps,
// the caller's request and context on the response, and the same failure
// when Got1xxResponse returns an error. The pool does not replay a refused
// stream, so there is no replay to compare.
func TestConnRoundTripMatchesWireCaseOff(t *testing.T) {
	srv := startServer(t)
	for _, tc := range []struct {
		name      string
		body      []byte
		got1xxErr error
	}{
		{name: "get"},
		{name: "post", body: []byte("payload")},
		{name: "1xx hook error", got1xxErr: errors.New("stop at 1xx")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantM, _ := newManager(t, srv, reference)
			gotM, _ := newManager(t, srv, converted)
			want := mustConnRoundTrip(t, srv, wantM, tc.body, tc.got1xxErr)
			got := mustConnRoundTrip(t, srv, gotM, tc.body, tc.got1xxErr)

			if got.err != want.err {
				t.Errorf("error = %q, want %q", got.err, want.err)
			}
			if !reflect.DeepEqual(got.informational, want.informational) {
				t.Errorf("1xx maps = %#v, want %#v", got.informational, want.informational)
			}
			if got.sameRequest != want.sameRequest || got.sameContext != want.sameContext {
				t.Errorf("resp.Request is the caller's %v, has its context %v; want %v, %v",
					got.sameRequest, got.sameContext, want.sameRequest, want.sameContext)
			}
			if got.resp != nil && want.resp != nil {
				if !reflect.DeepEqual(got.resp.Header, want.resp.Header) {
					t.Errorf("Header = %#v, want %#v", got.resp.Header, want.resp.Header)
				}
				if !reflect.DeepEqual(got.resp.Trailer, want.resp.Trailer) {
					t.Errorf("Trailer = %#v, want %#v", got.resp.Trailer, want.resp.Trailer)
				}
			}
			if len(want.informational) != 1 {
				t.Errorf("the trace saw %d 1xx responses, want 1", len(want.informational))
			}
		})
	}
}

// The net/http accessors that look names up canonically work on what
// Conn.RoundTrip returns.
func TestConnRoundTripCanonicalAccessors(t *testing.T) {
	srv := startServer(t)
	m, _ := newManager(t, srv, converted)
	res := mustConnRoundTrip(t, srv, m, nil, nil)
	if res.resp == nil {
		t.Fatalf("RoundTrip failed: %s", res.err)
	}
	if got, want := res.resp.Header.Get("WWW-Authenticate"), `Basic realm="r"`; got != want {
		t.Errorf("Header.Get(%q) = %q, want %q", "WWW-Authenticate", got, want)
	}
	if c := res.resp.Cookies(); len(c) != 2 {
		t.Errorf("Cookies() = %v, want two", c)
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

// A Manager marked through respheader.KeepWireCase passes the mark to the
// HostPool and to every connection it makes, including ones made by
// requests from many goroutines at once, and those connections hand the map
// back as the wire keyed it, with the values the conversion would have kept.
func TestKeepWireCaseReachesEveryConn(t *testing.T) {
	srv := startServer(t)
	refM, _ := newManager(t, srv, reference)
	ref := mustConnRoundTrip(t, srv, refM, nil, nil)
	if ref.resp == nil {
		t.Fatalf("RoundTrip failed: %s", ref.err)
	}
	want := ref.resp.Header

	m, hp := newManager(t, srv, marked)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			res, err := connRoundTrip(t.Context(), srv, m, nil, nil)
			if err != nil || res.resp == nil {
				t.Errorf("RoundTrip failed: %v %s", err, res.err)
				return
			}
			for k, v := range res.resp.Header {
				if strings.HasSuffix(k, ":") {
					continue // the bookkeeping entry, spelled the same in both
				}
				if k != strings.ToLower(k) {
					t.Errorf("Header key %q is not as the wire carried it", k)
				}
				if w := want[http.CanonicalHeaderKey(k)]; !reflect.DeepEqual(v, w) {
					t.Errorf("Header[%q] = %q, want %q", k, v, w)
				}
			}
			if len(res.resp.Header) != len(want) {
				t.Errorf("Header has %d keys, want %d", len(res.resp.Header), len(want))
			}
		})
	}
	wg.Wait()

	hp.mu.Lock()
	defer hp.mu.Unlock()
	if !hp.wireCase {
		t.Error("the HostPool did not take the Manager's mark")
	}
	if len(hp.connections) == 0 {
		t.Fatal("the requests left no connection to check")
	}
	for i, c := range hp.connections {
		if !c.wireCase {
			t.Errorf("connection %d did not take the mark", i)
		}
	}
}
