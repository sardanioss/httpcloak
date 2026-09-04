package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	fhttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/internal/gunzip"
	"github.com/sardanioss/quic-go/http3"
	utls "github.com/sardanioss/utls"
)

func gzipBytes(tb testing.TB, text []byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(text); err != nil {
		tb.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		tb.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// TestSetupDecompressorGzip locks the streaming path's existing contract: the
// header is read before the stream is handed out, and a body whose header
// cannot be read is returned raw rather than failing the request.
func TestSetupDecompressorGzip(t *testing.T) {
	text := []byte("hello")
	body := io.NopCloser(bytes.NewReader(gzipBytes(t, text)))
	reader, closer := setupDecompressor(body, "gzip")
	if _, ok := reader.(*gunzip.Stream); !ok {
		t.Fatalf("setupDecompressor(gzip body) reader = %T, want *gunzip.Stream", reader)
	}
	if closer != nil {
		t.Fatalf("setupDecompressor(gzip body) closer = %v, want nil", closer)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, text) {
		t.Fatalf("ReadAll = %q, want %q", got, text)
	}

	raw := io.NopCloser(bytes.NewReader([]byte("this is not a gzip stream")))
	reader, closer = setupDecompressor(raw, "gzip")
	if reader != raw {
		t.Fatalf("setupDecompressor(unreadable header) reader = %T, want the raw body", reader)
	}
	if closer != nil {
		t.Fatalf("setupDecompressor(unreadable header) closer = %v, want nil", closer)
	}
}

// gzipServer serves text as a gzip-encoded body over HTTP/2, written in
// several flushed chunks so the streaming path sees it arrive piecemeal.
func gzipServer(t *testing.T, text []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		zw := gzip.NewWriter(w)
		for chunk := range slices.Chunk(text, 16<<10) {
			if _, err := zw.Write(chunk); err != nil {
				return
			}
			if err := zw.Flush(); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
		zw.Close()
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestGzipResponsesEndToEnd(t *testing.T) {
	var text bytes.Buffer
	for i := range 4096 {
		fmt.Fprintf(&text, `{"id":%d,"text":"hello, httpcloak"}`+"\n", i)
	}
	server := gzipServer(t, text.Bytes())

	for _, tt := range []struct {
		name  string
		force Option
		want  string
	}{
		{name: "http2", force: WithForceHTTP2(), want: "h2"},
		{name: "http1", force: WithForceHTTP1(), want: "h1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient("chrome-latest",
				tt.force,
				WithInsecureSkipVerify(),
				WithTimeout(30*time.Second),
			)
			defer c.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Several requests in a row, so readers recycled by one response
			// are reused by the next.
			for i := range 3 {
				resp, err := c.Do(ctx, &Request{Method: http.MethodGet, URL: server.URL})
				if err != nil {
					t.Fatalf("Do %d: %v", i, err)
				}
				got, err := resp.Bytes()
				if err != nil {
					t.Fatalf("Do %d: Bytes: %v", i, err)
				}
				if !bytes.Equal(got, text.Bytes()) {
					t.Fatalf("Do %d: body is %d bytes, want %d", i, len(got), text.Len())
				}
				if resp.Protocol != tt.want {
					t.Fatalf("Do %d: protocol = %q, want %q", i, resp.Protocol, tt.want)
				}

				stream, err := c.DoStream(ctx, &Request{Method: http.MethodGet, URL: server.URL})
				if err != nil {
					t.Fatalf("DoStream %d: %v", i, err)
				}
				got, err = stream.ReadAll()
				if err != nil {
					t.Fatalf("DoStream %d: ReadAll: %v", i, err)
				}
				if !bytes.Equal(got, text.Bytes()) {
					t.Fatalf("DoStream %d: body is %d bytes, want %d", i, len(got), text.Len())
				}
				if stream.Protocol != tt.want {
					t.Fatalf("DoStream %d: protocol = %q, want %q", i, stream.Protocol, tt.want)
				}
			}
		})
	}
}

// benchmarkBody is a 54KB JSON-shaped body.
func benchmarkBody(b *testing.B) []byte {
	b.Helper()
	var text bytes.Buffer
	for i := range 1024 {
		fmt.Fprintf(&text, `{"id":%d,"text":"hello, httpcloak","kind":"sample"}`+"\n", i)
	}
	return text.Bytes()
}

func BenchmarkDecompressGzip(b *testing.B) {
	text := benchmarkBody(b)
	data := gzipBytes(b, text)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		got, err := decompress(data, "gzip")
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != len(text) {
			b.Fatalf("decompressed %d bytes, want %d", len(got), len(text))
		}
	}
}

func BenchmarkStreamGzip(b *testing.B) {
	text := benchmarkBody(b)
	data := gzipBytes(b, text)
	buf := make([]byte, 32<<10)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		reader, _ := setupDecompressor(io.NopCloser(bytes.NewReader(data)), "gzip")
		n, err := io.CopyBuffer(io.Discard, reader, buf)
		if err != nil {
			b.Fatal(err)
		}
		if n != int64(len(text)) {
			b.Fatalf("decompressed %d bytes, want %d", n, len(text))
		}
	}
}

// h3GzipTestTLS is a self-signed loopback certificate for a local HTTP/3
// server, in the utls types the forked quic-go expects.
func h3GzipTestTLS(t *testing.T) *utls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyB, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyB})
	cert, err := utls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &utls.Config{Certificates: []utls.Certificate{cert}, NextProtos: []string{"h3"}}
}

func gzipH3Server(t *testing.T, text []byte) string {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		TLSConfig: h3GzipTestTLS(t),
		Handler: fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(200)
			zw := gzip.NewWriter(w)
			for chunk := range slices.Chunk(text, 16<<10) {
				zw.Write(chunk)
				zw.Flush()
				if f, ok := w.(fhttp.Flusher); ok {
					f.Flush()
				}
			}
			zw.Close()
		}),
	}
	go func() { _ = srv.Serve(udpConn) }()
	t.Cleanup(func() { srv.Close(); udpConn.Close() })
	time.Sleep(200 * time.Millisecond)
	return "https://" + udpConn.LocalAddr().String() + "/"
}

// TestGzipHTTP3EndToEnd drives Client.Do and Client.DoStream over HTTP/3.
func TestGzipHTTP3EndToEnd(t *testing.T) {
	var text bytes.Buffer
	for i := range 4096 {
		fmt.Fprintf(&text, `{"id":%d,"text":"hello over quic"}`+"\n", i)
	}
	url := gzipH3Server(t, text.Bytes())

	c := NewClient("chrome-latest",
		WithForceHTTP3(),
		WithInsecureSkipVerify(),
		WithTimeout(30*time.Second),
	)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := range 3 {
		resp, err := c.Do(ctx, &Request{Method: http.MethodGet, URL: url})
		if err != nil {
			t.Fatalf("Do %d: %v", i, err)
		}
		got, err := resp.Bytes()
		if err != nil {
			t.Fatalf("Do %d: Bytes: %v", i, err)
		}
		if !bytes.Equal(got, text.Bytes()) {
			t.Fatalf("Do %d: body is %d bytes, want %d", i, len(got), text.Len())
		}
		if resp.Protocol != "h3" {
			t.Fatalf("Do %d: protocol = %q, want h3", i, resp.Protocol)
		}

		stream, err := c.DoStream(ctx, &Request{Method: http.MethodGet, URL: url})
		if err != nil {
			t.Fatalf("DoStream %d: %v", i, err)
		}
		got, err = stream.ReadAll()
		if err != nil {
			t.Fatalf("DoStream %d: ReadAll: %v", i, err)
		}
		if !bytes.Equal(got, text.Bytes()) {
			t.Fatalf("DoStream %d: body is %d bytes, want %d", i, len(got), text.Len())
		}
		if stream.Protocol != "h3" {
			t.Fatalf("DoStream %d: protocol = %q, want h3", i, stream.Protocol)
		}
	}
}

// TestDecompressHelpersGzip covers the two buffered helpers no local server
// can reach: HTTP3Client's decompressHTTP3 (HTTP3Client has no TLS-verify
// knob) and the exported Decompress. Both must route gzip through the shared
// implementation and leave every other encoding alone.
func TestDecompressHelpersGzip(t *testing.T) {
	text := bytes.Repeat([]byte("helper "), 4096)
	data := gzipBytes(t, text)
	for name, fn := range map[string]func([]byte, string) ([]byte, error){
		"decompress":      decompress,
		"decompressHTTP3": decompressHTTP3,
		"Decompress":      Decompress,
	} {
		t.Run(name, func(t *testing.T) {
			for _, enc := range []string{"gzip", "GZIP", " gzip"} {
				got, err := fn(data, strings.TrimSpace(enc))
				if err != nil {
					t.Fatalf("%s(%q): %v", name, enc, err)
				}
				if !bytes.Equal(got, text) {
					t.Fatalf("%s(%q) = %d bytes, want %d", name, enc, len(got), len(text))
				}
			}
			if got, err := fn(text, ""); err != nil || !bytes.Equal(got, text) {
				t.Fatalf("%s(identity) = %d bytes, %v; want passthrough", name, len(got), err)
			}
			if _, err := fn([]byte("this is not a gzip stream"), "gzip"); err == nil {
				t.Fatalf("%s(not gzip) = nil error, want gzip header error", name)
			}
		})
	}
}
