package client

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// DoStream decompressed gzip, br and zstd, and handed a deflate body back
// still compressed while Do decompressed the same response. gzip is the
// control: it already worked, so a harness that cannot reach the server
// cannot pass this test.
func TestDoStreamDecompressesDeflate(t *testing.T) {
	const payload = "hello streaming world, long enough to compress properly"

	gz := func() []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write([]byte(payload))
		w.Close()
		return b.Bytes()
	}
	zl := func() []byte {
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		w.Write([]byte(payload))
		w.Close()
		return b.Bytes()
	}
	raw := func() []byte {
		var b bytes.Buffer
		w, _ := flate.NewWriter(&b, flate.DefaultCompression)
		w.Write([]byte(payload))
		w.Close()
		return b.Bytes()
	}

	for _, tc := range []struct {
		name     string
		encoding string
		body     []byte
	}{
		{"gzip, the control", "gzip", gz()},
		{"deflate, zlib framing", "deflate", zl()},
		{"deflate, raw", "deflate", raw()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", tc.encoding)
				w.Write(tc.body)
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()

			c := NewClient("chrome-latest",
				WithForceHTTP2(),
				WithInsecureSkipVerify(),
				WithTimeout(20*time.Second),
			)
			defer c.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			stream, err := c.DoStream(ctx, &Request{Method: http.MethodGet, URL: server.URL})
			if err != nil {
				t.Fatalf("DoStream: %v", err)
			}
			defer stream.Close()

			got, err := io.ReadAll(stream)
			if err != nil {
				t.Fatalf("reading the stream: %v", err)
			}
			if string(got) != payload {
				t.Fatalf("got %d bytes that are not the payload, so the body was not decompressed", len(got))
			}
		})
	}
}
