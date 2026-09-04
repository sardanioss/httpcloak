package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"
	"time"

	http "github.com/sardanioss/http"
)

func driveWireHeaders(t *testing.T, cfg h2Config) *Response {
	t.Helper()
	s := startH2Server(t, cfg)

	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/")})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp
}

// The H2 read path now hands over header maps keyed exactly as the wire
// carried the names, which on HTTP/2 is lowercase. The Response contract is
// unchanged: lowercase keys, values per occurrence in arrival order, and the
// wire order recorded separately.
func TestResponseHeadersArriveLowercaseWithOrder(t *testing.T) {
	resp := driveWireHeaders(t, h2Config{
		Body: []byte("ok"),
		ResponseHeaders: [][2]string{
			{"x-custom-thing", "v1"},
			{"set-cookie", "a=1"},
			{"content-type", "text/plain"},
			{"set-cookie", "b=2"},
		},
	})

	if got := resp.Headers["x-custom-thing"]; len(got) != 1 || got[0] != "v1" {
		t.Fatalf("x-custom-thing = %v, want [v1]", got)
	}
	if got := resp.Headers["content-type"]; len(got) != 1 || got[0] != "text/plain" {
		t.Fatalf("content-type = %v, want [text/plain]", got)
	}
	if got := resp.Headers["set-cookie"]; len(got) != 2 || got[0] != "a=1" || got[1] != "b=2" {
		t.Fatalf("set-cookie = %v, want [a=1 b=2]", got)
	}
	for k := range resp.Headers {
		if strings.ToLower(k) != k {
			t.Fatalf("Headers key %q is not lowercase", k)
		}
	}

	want := []string{"x-custom-thing", "set-cookie", "content-type", "set-cookie"}
	if len(resp.HeaderOrder) != len(want) {
		t.Fatalf("HeaderOrder = %v, want %v", resp.HeaderOrder, want)
	}
	for i := range want {
		if resp.HeaderOrder[i] != want[i] {
			t.Fatalf("HeaderOrder = %v, want %v", resp.HeaderOrder, want)
		}
	}
	body, err := readWithin(t, resp.Body, 5*time.Second)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}
}

// Content-Encoding is read from the fork's map before conversion, and
// http.Header.Get canonicalises its argument, so a wire-cased map would make
// it miss and hand the caller a still-compressed body. The lookup goes
// through responseContentEncoding instead; this locks the whole path.
func TestGzipResponseDecompressesUnderWireCase(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte("hello wire case")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	resp := driveWireHeaders(t, h2Config{
		Body: buf.Bytes(),
		ResponseHeaders: [][2]string{
			{"content-encoding", "gzip"},
		},
	})

	body, err := readWithin(t, resp.Body, 5*time.Second)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	resp.Body.Close()
	if string(body) != "hello wire case" {
		t.Fatalf("body = %q, want the decompressed text", body)
	}
}

// The helper reads whichever key set the protocol path produced: canonical
// from the HTTP/1.1 parse and from HTTP/3, wire case from HTTP/2.
func TestResponseContentEncodingReadsBothKeySets(t *testing.T) {
	if got := responseContentEncoding(http.Header{"Content-Encoding": {"br"}}); got != "br" {
		t.Fatalf("canonical key: got %q, want br", got)
	}
	if got := responseContentEncoding(http.Header{"content-encoding": {"gzip"}}); got != "gzip" {
		t.Fatalf("wire-case key: got %q, want gzip", got)
	}
	if got := responseContentEncoding(http.Header{}); got != "" {
		t.Fatalf("absent: got %q, want empty", got)
	}
}

// The conversion cost the wire-case map removes: every canonical key pays an
// allocating ToLower on its way into the response map, an already-lowercase
// key hands the same string back.
func benchHeaders(canonical bool) http.Header {
	names := []string{"content-type", "content-encoding", "date", "server", "vary",
		"cache-control", "x-transaction-id", "x-rate-limit-limit", "x-rate-limit-remaining",
		"x-rate-limit-reset", "x-response-time", "set-cookie", "strict-transport-security", "x-connection-hash"}
	h := make(http.Header, len(names))
	for _, n := range names {
		if canonical {
			h.Set(n, "v")
		} else {
			h[n] = []string{"v"}
		}
	}
	return h
}

func BenchmarkBuildHeadersMapCanonical(b *testing.B) {
	h := benchHeaders(true)
	b.ReportAllocs()
	for b.Loop() {
		buildHeadersMap(h)
	}
}

func BenchmarkBuildHeadersMapWireCase(b *testing.B) {
	h := benchHeaders(false)
	b.ReportAllocs()
	for b.Loop() {
		buildHeadersMap(h)
	}
}
