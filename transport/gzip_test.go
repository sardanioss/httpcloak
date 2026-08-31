package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/internal/gunzip"
	"github.com/sardanioss/quic-go/http3"
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

// TestSetupStreamDecompressorGzip locks the streaming path's existing
// contract: the header is read before the stream is handed out, and a body
// whose header cannot be read is returned raw rather than failing the request.
func TestSetupStreamDecompressorGzip(t *testing.T) {
	text := []byte("hello")
	body := io.NopCloser(bytes.NewReader(gzipBytes(t, text)))
	reader, closer := setupStreamDecompressor(body, "gzip")
	if _, ok := reader.(*gunzip.Stream); !ok {
		t.Fatalf("setupStreamDecompressor(gzip body) reader = %T, want *gunzip.Stream", reader)
	}
	if closer != nil {
		t.Fatalf("setupStreamDecompressor(gzip body) closer = %v, want nil", closer)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, text) {
		t.Fatalf("ReadAll = %q, want %q", got, text)
	}

	raw := io.NopCloser(bytes.NewReader([]byte("this is not a gzip stream")))
	reader, closer = setupStreamDecompressor(raw, "gzip")
	if reader != raw {
		t.Fatalf("setupStreamDecompressor(unreadable header) reader = %T, want the raw body", reader)
	}
	if closer != nil {
		t.Fatalf("setupStreamDecompressor(unreadable header) closer = %v, want nil", closer)
	}
}

// gzipServer serves text as a gzip-encoded body over HTTP/2, written in
// several flushed chunks so the streaming path sees it arrive piecemeal and
// the buffered path has no Content-Length to size its read by.
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

// TestGzipResponsesEndToEnd drives Transport.Do and Transport.DoStream, the
// paths behind Session.Do and Session.DoStream, against a real H2 server.
func TestGzipResponsesEndToEnd(t *testing.T) {
	var text bytes.Buffer
	for i := range 4096 {
		fmt.Fprintf(&text, `{"id":%d,"text":"hello, httpcloak"}`+"\n", i)
	}
	server := gzipServer(t, text.Bytes())

	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(ProtocolHTTP2)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Several requests in a row, so readers and scratch buffers recycled by
	// one response are reused by the next.
	for i := range 3 {
		resp, err := tr.Do(ctx, &Request{Method: "GET", URL: server.URL})
		if err != nil {
			t.Fatalf("Do %d: %v", i, err)
		}
		got, err := io.ReadAll(resp.Body)
		resp.Close()
		if err != nil {
			t.Fatalf("Do %d: read body: %v", i, err)
		}
		if !bytes.Equal(got, text.Bytes()) {
			t.Fatalf("Do %d: body is %d bytes, want %d", i, len(got), text.Len())
		}
		if resp.Protocol != "h2" {
			t.Fatalf("Do %d: protocol = %q, want h2", i, resp.Protocol)
		}

		stream, err := tr.DoStream(ctx, &Request{Method: "GET", URL: server.URL})
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
		reader, _ := setupStreamDecompressor(io.NopCloser(bytes.NewReader(data)), "gzip")
		n, err := io.CopyBuffer(io.Discard, reader, buf)
		if err != nil {
			b.Fatal(err)
		}
		if n != int64(len(text)) {
			b.Fatalf("decompressed %d bytes, want %d", n, len(text))
		}
	}
}

// TestDoStreamCloseWhileReadingGzip closes a gzip stream from another
// goroutine while a Read is blocked on it, the way a caller abandons a
// stream. Under -race this checks the pooled reader adds no data race to
// that path, and it checks the abandoned reader is not recycled.
func TestDoStreamCloseWhileReadingGzip(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		zw := gzip.NewWriter(w)
		zw.Write(bytes.Repeat([]byte("first chunk "), 1024))
		zw.Flush()
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	defer close(release)

	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(ProtocolHTTP2)

	for i := range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		stream, err := tr.DoStream(ctx, &Request{Method: "GET", URL: server.URL})
		if err != nil {
			cancel()
			t.Fatalf("DoStream %d: %v", i, err)
		}
		gs, ok := stream.reader.(*gunzip.Stream)
		if !ok {
			cancel()
			t.Fatalf("DoStream %d: reader = %T, want *gunzip.Stream", i, stream.reader)
		}

		readDone := make(chan error, 1)
		go func() {
			buf := make([]byte, 4096)
			for {
				if _, err := stream.Read(buf); err != nil {
					readDone <- err
					return
				}
			}
		}()
		// Let the reader consume the first chunk and block on the second.
		time.Sleep(50 * time.Millisecond)
		if err := stream.Close(); err != nil {
			t.Logf("Close %d: %v", i, err)
		}
		select {
		case err := <-readDone:
			if err == io.EOF {
				t.Fatalf("DoStream %d: blocked Read returned io.EOF after Close; want a body error", i)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("DoStream %d: Read did not unblock after Close", i)
		}
		if _, err := gs.Read(make([]byte, 1)); err == io.EOF {
			// A stream abandoned before EOF keeps its reader; only EOF recycles.
			t.Fatalf("DoStream %d: abandoned stream reports io.EOF, so its reader was recycled while in use", i)
		}
		cancel()
	}
}

// TestGzipLargeBodyEndToEnd pushes a body past the scratch retention cap
// through Transport.Do, so the drop-rather-than-pool branch runs on the real
// path and the result is still exact.
func TestGzipLargeBodyEndToEnd(t *testing.T) {
	text := make([]byte, 3<<20)
	for i := range text {
		text[i] = byte('a' + i%26)
	}
	server := gzipServer(t, text)

	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(ProtocolHTTP2)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for i := range 2 {
		resp, err := tr.Do(ctx, &Request{Method: "GET", URL: server.URL})
		if err != nil {
			t.Fatalf("Do %d: %v", i, err)
		}
		got, err := io.ReadAll(resp.Body)
		resp.Close()
		if err != nil {
			t.Fatalf("Do %d: read body: %v", i, err)
		}
		if !bytes.Equal(got, text) {
			t.Fatalf("Do %d: body is %d bytes, want %d", i, len(got), len(text))
		}
	}
}

// TestGzipOneTransportManyHostsConcurrently is the shape of a real workload:
// one Transport in auto mode driving several hosts at once from many
// goroutines, some speaking HTTP/2 and one HTTP/1.1 only, mixing buffered and
// streaming requests, with some streams abandoned before EOF. Every response
// is checked against the body its host serves, so a pooled reader or scratch
// buffer that leaked between two in-flight responses shows up as a body
// mismatch, and -race catches the sharing itself.
func TestGzipOneTransportManyHostsConcurrently(t *testing.T) {
	type host struct {
		url  string
		body []byte
	}
	var hosts []host
	for i := range 3 {
		var text bytes.Buffer
		for j := range 1024 * (i + 1) {
			fmt.Fprintf(&text, `{"host":%d,"id":%d,"text":"hello, httpcloak"}`+"\n", i, j)
		}
		body := text.Bytes()
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			zw := gzip.NewWriter(w)
			for chunk := range slices.Chunk(body, 8<<10) {
				zw.Write(chunk)
				zw.Flush()
				w.(http.Flusher).Flush()
			}
			zw.Close()
		}))
		// The last host is HTTP/1.1 only, so auto mode has to pick per host.
		server.EnableHTTP2 = i < 2
		server.StartTLS()
		t.Cleanup(server.Close)
		hosts = append(hosts, host{url: server.URL, body: body})
	}

	// A preset without HTTP/3, so auto mode goes straight to ALPN instead of
	// spending the H3 probe budget against servers that have no UDP listener.
	tr := NewTransport("firefox-latest")
	defer tr.Close()
	tr.SetInsecureSkipVerify(true)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	seen := make([]map[string]bool, len(hosts))
	var seenMu sync.Mutex
	for i := range seen {
		seen[i] = make(map[string]bool)
	}

	var wg sync.WaitGroup
	for g := range 12 {
		wg.Go(func() {
			for i := range 40 {
				h := (g*7 + i*3) % len(hosts)
				switch (g + i) % 3 {
				case 0:
					resp, err := tr.Do(ctx, &Request{Method: "GET", URL: hosts[h].url})
					if err != nil {
						t.Errorf("goroutine %d request %d host %d: Do: %v", g, i, h, err)
						return
					}
					got, err := io.ReadAll(resp.Body)
					resp.Close()
					if err != nil || !bytes.Equal(got, hosts[h].body) {
						t.Errorf("goroutine %d request %d host %d: Do body wrong: err=%v len=%d want=%d", g, i, h, err, len(got), len(hosts[h].body))
						return
					}
					seenMu.Lock()
					seen[h][resp.Protocol] = true
					seenMu.Unlock()
				case 1:
					stream, err := tr.DoStream(ctx, &Request{Method: "GET", URL: hosts[h].url})
					if err != nil {
						t.Errorf("goroutine %d request %d host %d: DoStream: %v", g, i, h, err)
						return
					}
					got, err := stream.ReadAll()
					if err != nil || !bytes.Equal(got, hosts[h].body) {
						t.Errorf("goroutine %d request %d host %d: DoStream body wrong: err=%v len=%d want=%d", g, i, h, err, len(got), len(hosts[h].body))
						return
					}
				case 2:
					// Abandon the stream part way through: the reader must not
					// be recycled, and the next request on this connection
					// must still decode cleanly.
					stream, err := tr.DoStream(ctx, &Request{Method: "GET", URL: hosts[h].url})
					if err != nil {
						t.Errorf("goroutine %d request %d host %d: DoStream (abandon): %v", g, i, h, err)
						return
					}
					head := make([]byte, 3000)
					n, err := io.ReadFull(stream, head)
					stream.Close()
					if err != nil || !bytes.Equal(head[:n], hosts[h].body[:n]) {
						t.Errorf("goroutine %d request %d host %d: partial stream wrong: err=%v", g, i, h, err)
						return
					}
				}
			}
		})
	}
	wg.Wait()

	if !seen[0]["h2"] || !seen[2]["h1"] {
		t.Fatalf("protocols seen per host = %v, want h2 on host 0 and h1 on host 2", seen)
	}
}

// gzipH3Server serves text as a gzip-encoded body over HTTP/3 on a loopback
// UDP port and returns the URL to reach it.
func gzipH3Server(t *testing.T, text []byte) string {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		TLSConfig: h3RaceTestTLS(t),
		Handler: shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(200)
			zw := gzip.NewWriter(w)
			for chunk := range slices.Chunk(text, 16<<10) {
				zw.Write(chunk)
				zw.Flush()
				if f, ok := w.(shttp.Flusher); ok {
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

// TestGzipHTTP3EndToEnd covers doHTTP3 and doStreamHTTP3, the two sites the
// H2 tests cannot reach.
func TestGzipHTTP3EndToEnd(t *testing.T) {
	var text bytes.Buffer
	for i := range 4096 {
		fmt.Fprintf(&text, `{"id":%d,"text":"hello over quic"}`+"\n", i)
	}
	url := gzipH3Server(t, text.Bytes())

	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(ProtocolHTTP3)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := range 3 {
		resp, err := tr.Do(ctx, &Request{Method: "GET", URL: url})
		if err != nil {
			t.Fatalf("Do %d: %v", i, err)
		}
		got, err := io.ReadAll(resp.Body)
		resp.Close()
		if err != nil {
			t.Fatalf("Do %d: read body: %v", i, err)
		}
		if !bytes.Equal(got, text.Bytes()) {
			t.Fatalf("Do %d: body is %d bytes, want %d", i, len(got), text.Len())
		}
		if resp.Protocol != "h3" {
			t.Fatalf("Do %d: protocol = %q, want h3", i, resp.Protocol)
		}

		stream, err := tr.DoStream(ctx, &Request{Method: "GET", URL: url})
		if err != nil {
			t.Fatalf("DoStream %d: %v", i, err)
		}
		if stream.Protocol != "h3" {
			stream.Close()
			t.Fatalf("DoStream %d: protocol = %q, want h3", i, stream.Protocol)
		}
		got, err = stream.ReadAll()
		if err != nil {
			t.Fatalf("DoStream %d: ReadAll: %v", i, err)
		}
		if !bytes.Equal(got, text.Bytes()) {
			t.Fatalf("DoStream %d: body is %d bytes, want %d", i, len(got), text.Len())
		}
	}
}

// TestGzipALPNFallbackToHTTP1 covers doHTTP1WithTLSConn: an auto-mode
// Transport with an H3-capable preset reaching a server that only speaks
// HTTP/1.1 takes the ALPN-mismatch fallback, which reads and decompresses the
// body on its own path.
func TestGzipALPNFallbackToHTTP1(t *testing.T) {
	var text bytes.Buffer
	for i := range 2048 {
		fmt.Fprintf(&text, `{"id":%d,"text":"hello over http/1.1"}`+"\n", i)
	}
	body := text.Bytes()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		zw := gzip.NewWriter(w)
		zw.Write(body)
		zw.Close()
	}))
	defer server.Close()

	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetInsecureSkipVerify(true)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for i := range 2 {
		resp, err := tr.Do(ctx, &Request{Method: "GET", URL: server.URL})
		if err != nil {
			t.Fatalf("Do %d: %v", i, err)
		}
		got, err := io.ReadAll(resp.Body)
		resp.Close()
		if err != nil {
			t.Fatalf("Do %d: read body: %v", i, err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("Do %d: body is %d bytes, want %d", i, len(got), len(body))
		}
		if resp.Protocol != "h1" {
			t.Fatalf("Do %d: protocol = %q, want h1", i, resp.Protocol)
		}
	}
}
