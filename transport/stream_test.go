package transport

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// mockReadCloser wraps a bytes.Reader to implement io.ReadCloser
type mockReadCloser struct {
	*bytes.Reader
}

func (m *mockReadCloser) Close() error {
	return nil
}

func TestSetupStreamDecompressor(t *testing.T) {
	testData := []byte("Hello, World! This is test data for compression.")

	tests := []struct {
		name     string
		encoding string
		compress func([]byte) ([]byte, error)
	}{
		{
			name:     "gzip",
			encoding: "gzip",
			compress: func(data []byte) ([]byte, error) {
				var buf bytes.Buffer
				w := gzip.NewWriter(&buf)
				w.Write(data)
				w.Close()
				return buf.Bytes(), nil
			},
		},
		{
			name:     "brotli",
			encoding: "br",
			compress: func(data []byte) ([]byte, error) {
				var buf bytes.Buffer
				w := brotli.NewWriter(&buf)
				w.Write(data)
				w.Close()
				return buf.Bytes(), nil
			},
		},
		{
			name:     "deflate",
			encoding: "deflate",
			compress: func(data []byte) ([]byte, error) {
				var buf bytes.Buffer
				w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
				w.Write(data)
				w.Close()
				return buf.Bytes(), nil
			},
		},
		{
			name:     "zstd",
			encoding: "zstd",
			compress: func(data []byte) ([]byte, error) {
				var buf bytes.Buffer
				w, _ := zstd.NewWriter(&buf)
				w.Write(data)
				w.Close()
				return buf.Bytes(), nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compress the test data
			compressed, err := tt.compress(testData)
			if err != nil {
				t.Fatalf("Failed to compress: %v", err)
			}

			// Create a mock ReadCloser with compressed data
			body := &mockReadCloser{bytes.NewReader(compressed)}

			// Setup decompressor
			reader, closer := setupStreamDecompressor(body, tt.encoding)
			if closer != nil {
				defer closer.Close()
			}
			defer reader.Close()

			// Read and decompress
			decompressed, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("Failed to read decompressed data: %v", err)
			}

			// Verify
			if !bytes.Equal(decompressed, testData) {
				t.Errorf("Decompressed data mismatch.\nGot: %s\nWant: %s", decompressed, testData)
			}
		})
	}
}

func TestSetupStreamDecompressor_Unknown(t *testing.T) {
	testData := []byte("raw data")
	body := &mockReadCloser{bytes.NewReader(testData)}

	reader, closer := setupStreamDecompressor(body, "unknown")
	if closer != nil {
		t.Error("Expected nil closer for unknown encoding")
	}

	// Should return raw data unchanged
	result, _ := io.ReadAll(reader)
	if !bytes.Equal(result, testData) {
		t.Errorf("Expected raw data for unknown encoding")
	}
}

func TestSetupStreamDecompressor_CaseInsensitive(t *testing.T) {
	var buf bytes.Buffer
	w, _ := zstd.NewWriter(&buf)
	w.Write([]byte("test"))
	w.Close()

	// Test uppercase
	body := &mockReadCloser{bytes.NewReader(buf.Bytes())}
	reader, _ := setupStreamDecompressor(body, "ZSTD")
	result, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed with uppercase encoding: %v", err)
	}
	if string(result) != "test" {
		t.Errorf("Case insensitive test failed")
	}
}

func TestDoStreamAutoFallsBackToHTTP1OnALPNMismatch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetInsecureSkipVerify(true)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := tr.DoStream(ctx, &Request{Method: "GET", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Close()

	body, err := io.ReadAll(resp)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
	if resp.Protocol != "h1" {
		t.Fatalf("protocol = %q, want h1", resp.Protocol)
	}
}

func TestDoStreamForcedHTTP2DoesNotFallbackToHTTP1(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(ProtocolHTTP2)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := tr.DoStream(ctx, &Request{Method: "GET", URL: srv.URL})
	if !errors.Is(err, ErrALPNMismatch) {
		t.Fatalf("err = %v, want ALPN mismatch", err)
	}
}
