package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak"
)

func htmlResponse(body string) *httpcloak.Response {
	return &httpcloak.Response{
		StatusCode: 200,
		Headers:    map[string][]string{"content-type": {"text/html; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		FinalURL:   "https://shop.test/",
		Protocol:   "h2",
	}
}

// A body crosses as it was, < > & and all, with no HTML escaping to
// grow it and to be undone, and still reads back as JSON.
func TestAResponseBodyCrossesUnescaped(t *testing.T) {
	const body = "<html><script>if (a < b && c > d) { x = 1 }</script></html>"
	out := responseJSON(htmlResponse(body))
	escaped := `\` + "u003c" // what Go's HTML escaping writes for <
	if !strings.Contains(out, `<html><script>if (a < b && c > d)`) || strings.Contains(out, escaped) {
		t.Fatalf("the body was escaped: %s", out)
	}
	var read ResponseData
	if err := json.Unmarshal([]byte(out), &read); err != nil || read.Body != body || read.StatusCode != 200 {
		t.Fatalf("read back %+v, %v", read, err)
	}
	if strings.HasSuffix(out, "\n") {
		t.Fatal("the JSON ends with the encoder's newline")
	}
}

// A 2 MB product page, the size of the stores' larger HTML pages.
func BenchmarkResponseJSONOfA2MBPage(b *testing.B) {
	var page bytes.Buffer
	for page.Len() < 2<<20 {
		page.WriteString(`<div class="product" data-id="1"><a href="/p?id=1&amp;v=2">Name &amp; more</a><script>if (a < b && c > d) {}</script></div>`)
	}
	body := page.String()
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	var size int
	for b.Loop() {
		size = len(responseJSON(htmlResponse(body)))
	}
	b.ReportMetric(float64(size)/float64(len(body)), "json/body")
}
