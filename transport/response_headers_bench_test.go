package transport

import (
	"context"
	"io"
	"testing"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// benchFields is a synthetic fourteen-field response header block: a few
// names from the common header tables, a few outside them, and one repeated.
var benchFields = [][2]string{
	{"content-type", "text/html; charset=utf-8"},
	{"content-length", "2"},
	{"cache-control", "private, max-age=0"},
	{"etag", `"abc123"`},
	{"last-modified", "Mon, 01 Jan 2024 00:00:00 GMT"},
	{"vary", "accept-encoding"},
	{"set-cookie", "a=1; Path=/"},
	{"set-cookie", "b=2; Path=/"},
	{"x-request-id", "0123456789abcdef"},
	{"x-frame-options", "SAMEORIGIN"},
	{"x-content-type-options", "nosniff"},
	{"strict-transport-security", "max-age=31536000"},
	{"referrer-policy", "strict-origin-when-cross-origin"},
	{"x-example-trace", "t1"},
}

// benchServer serves benchFields and a two-byte body over HTTP/2 in process.
func benchServer(b *testing.B) *h2Server {
	return startH2Server(b, h2Config{Body: []byte("ok"), ResponseHeaders: benchFields})
}

// BenchmarkHTTP2TransportDo is one request through the Transport, the path a
// Session takes, against the in-process server on a warm connection.
func BenchmarkHTTP2TransportDo(b *testing.B) {
	s := benchServer(b)
	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()
	ctx := context.Background()
	req := &Request{Method: "GET", URL: s.url("/")}

	do := func() {
		resp, err := tr.Do(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
	do()
	b.ReportAllocs()
	for b.Loop() {
		do()
	}
}

// BenchmarkHTTP2TransportRoundTrip is one request through the exported
// HTTP2Transport.RoundTrip, the path a direct caller takes.
func BenchmarkHTTP2TransportRoundTrip(b *testing.B) {
	s := benchServer(b)
	tr := NewHTTP2Transport(fingerprint.Get("chrome-latest"), dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()
	req, err := http.NewRequest("GET", s.url("/"), nil)
	if err != nil {
		b.Fatal(err)
	}

	do := func() {
		resp, err := tr.RoundTrip(req)
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	do()
	b.ReportAllocs()
	for b.Loop() {
		do()
	}
}

// benchHeader builds the map the HTTP/2 read loop produces for benchFields,
// keyed canonically or as the wire carried the names.
func benchHeader(wire bool) http.Header {
	h := make(http.Header, len(benchFields)+1)
	order := make([]string, 0, len(benchFields))
	for _, f := range benchFields {
		k := f[0]
		if !wire {
			k = http.CanonicalHeaderKey(k)
		}
		h[k] = append(h[k], f[1])
		order = append(order, f[0])
	}
	h[http.HeaderOrderKey] = order
	return h
}

// BenchmarkResponseHeaderConversionCopy is the HTTP/2 conversion as it was:
// the order copy, the casing read and a lowercase copy of the canonical map.
func BenchmarkResponseHeaderConversionCopy(b *testing.B) {
	h := benchHeader(false)
	b.ReportAllocs()
	for b.Loop() {
		_ = responseHeaderOrder(h)
		_ = takeHeaderCasing(h)
		_ = buildHeadersMap(h)
	}
}

// BenchmarkResponseHeaderConversionAdopt is the conversion now: the same two
// reads, then the wire-case map adopted. Adoption deletes the order entry, so
// each iteration puts it back, which is one map assignment of overhead.
func BenchmarkResponseHeaderConversionAdopt(b *testing.B) {
	h := benchHeader(true)
	order := h[http.HeaderOrderKey]
	b.ReportAllocs()
	for b.Loop() {
		h[http.HeaderOrderKey] = order
		_ = responseHeaderOrder(h)
		_ = takeHeaderCasing(h)
		_ = adoptWireHeaders(h)
	}
}
