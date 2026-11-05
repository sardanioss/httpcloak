package transport

import (
	"net/url"
	"strings"
	"testing"

	http "github.com/sardanioss/http"
)

// The HTTP/1.1 writer prints the request line and headers verbatim, so a CR or
// LF from the caller would let them write headers, or a whole second request,
// of their choosing. Every such request has to be refused before a connection
// is touched.
func TestValidateH1RequestRefusesLineBreaks(t *testing.T) {
	base := func() *http.Request {
		u, _ := url.Parse("http://example.com/path?q=1")
		return &http.Request{Method: "GET", URL: u, Header: http.Header{"X-Ok": {"fine"}}}
	}
	if err := validateH1Request(base()); err != nil {
		t.Fatalf("a valid request was refused: %v", err)
	}
	bad := map[string]func(r *http.Request){
		"header value":  func(r *http.Request) { r.Header["X-B"] = []string{"v\r\nInjected: 1"} },
		"bare LF":       func(r *http.Request) { r.Header["X-B"] = []string{"v\nInjected: 1"} },
		"header name":   func(r *http.Request) { r.Header["X-B\r\nInjected"] = []string{"1"} },
		"method":        func(r *http.Request) { r.Method = "GET / HTTP/1.1\r\nX:" },
		"host":          func(r *http.Request) { r.Host = "example.com\r\nInjected: 1" },
		"request path":  func(r *http.Request) { r.URL.Opaque = "/a HTTP/1.1\r\nInjected: 1\r\n\r\nGET /b" },
		"lowercase key": func(r *http.Request) { r.Header["x-lower"] = []string{"a\r\nb: c"} },
		"NUL in value":  func(r *http.Request) { r.Header["X-B"] = []string{"a\x00b"} },
	}
	for name, mutate := range bad {
		r := base()
		mutate(r)
		if err := validateH1Request(r); err == nil {
			t.Errorf("%s: a request with a line break was accepted", name)
		}
	}
	// Bookkeeping entries carry names that are not valid header names and
	// never reach the wire; they must not make a request invalid.
	r := base()
	r.Header[http.HeaderOrderKey] = []string{"x-ok"}
	r.Header[exactHeadersKey] = []string{"1"}
	if err := validateH1Request(r); err != nil {
		t.Fatalf("bookkeeping entries were treated as headers: %v", err)
	}
	if err := validateH1Request(&http.Request{Method: "", URL: base().URL, Header: http.Header{"X": {strings.Repeat("a", 10)}}}); err != nil {
		t.Fatalf("an empty method (GET) was refused: %v", err)
	}
}

// Everything 1.7.3 sent that carries no line break must still go out: a
// header dict copied from DevTools for an HTTP/2 request (pseudo-header
// names, which the auto-mode HTTP/1.1 fallback has always carried), a raw
// space in the query, a tab or obs-text in a value. Lenient servers answer
// these, and refusing them broke working code.
func TestValidateH1RequestKeepsWhat1_7_3Sent(t *testing.T) {
	ok := map[string]func(r *http.Request){
		"pseudo-header names": func(r *http.Request) {
			r.Header[":authority"] = []string{"example.com"}
			r.Header[":path"] = []string{"/"}
		},
		"space in query":    func(r *http.Request) { r.URL.RawQuery = "q=a b" },
		"tab in value":      func(r *http.Request) { r.Header["X-T"] = []string{"a\tb"} },
		"obs-text in value": func(r *http.Request) { r.Header["X-U"] = []string{"caf\xc3\xa9"} },
		"name with a space": func(r *http.Request) { r.Header["X Odd"] = []string{"1"} },
		"empty value":       func(r *http.Request) { r.Header["X-E"] = []string{""} },
		"IPv6 host":         func(r *http.Request) { r.Host = "[::1]:8080" },
	}
	for name, mutate := range ok {
		u, _ := url.Parse("http://example.com/path?q=1")
		r := &http.Request{Method: "GET", URL: u, Header: http.Header{}}
		mutate(r)
		if err := validateH1Request(r); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}
