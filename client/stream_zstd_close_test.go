package client

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func zstdStreamBody(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(bytes.Repeat([]byte("a streaming response body, "), 200000))
	w.Close()
	return buf.Bytes()
}

// openZstdStream builds a StreamResponse the way DoStream does and reads only
// the start of it, the way a caller does that stops early.
func openZstdStream(t *testing.T, body []byte) *StreamResponse {
	t.Helper()
	raw := io.NopCloser(bytes.NewReader(body))
	reader, decompressor := setupDecompressor(raw, "zstd")
	r := &StreamResponse{reader: reader, decompressor: decompressor, rawReader: raw}
	if _, err := r.Read(make([]byte, 64)); err != nil {
		t.Fatalf("first read: %v", err)
	}
	return r
}

// StreamResponse.Close only closes what setupDecompressor hands back as the
// closer, and for zstd that used to be nil, so the decoder was never closed.
func TestStreamResponseCloseClosesTheZstdDecoder(t *testing.T) {
	r := openZstdStream(t, zstdStreamBody(t))
	r.Close()

	if _, err := r.reader.Read(make([]byte, 64)); !errors.Is(err, zstd.ErrDecoderClosed) {
		t.Fatalf("after Close the decoder still reads (err %v), so it was never closed", err)
	}
}

// What that costs: the decoder runs goroutines until it is closed, so each
// stream closed before its end left them behind for good.
func TestAbandonedZstdStreamsDoNotLeakGoroutines(t *testing.T) {
	body := zstdStreamBody(t)
	before := settledGoroutines()

	const streams = 20
	for i := 0; i < streams; i++ {
		openZstdStream(t, body).Close()
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		after := settledGoroutines()
		if after <= before+2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines left behind by %d closed streams", after-before, streams)
		}
	}
}

func settledGoroutines() int {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	return runtime.NumGoroutine()
}
