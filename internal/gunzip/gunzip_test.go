package gunzip

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"sync"
	"testing"
	"testing/iotest"
)

// members gzips each payload as its own member and concatenates them, which is
// a single valid gzip stream (RFC 1952, section 2.2).
func members(tb testing.TB, payloads ...[]byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	for _, p := range payloads {
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(p); err != nil {
			tb.Fatalf("gzip write: %v", err)
		}
		if err := w.Close(); err != nil {
			tb.Fatalf("gzip close: %v", err)
		}
	}
	return buf.Bytes()
}

// notGzip is at least as long as a gzip header (10 bytes), so it fails the
// header check itself rather than running out of bytes first.
var notGzip = []byte("this is not a gzip stream")

func randomBytes(tb testing.TB, n int) []byte {
	tb.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		tb.Fatalf("rand: %v", err)
	}
	return b
}

func TestBytes(t *testing.T) {
	text := bytes.Repeat([]byte(`{"id":1,"text":"hello, httpcloak"}`), 2048)
	// Random bytes do not compress, so cutting the compressed form in half
	// lands well inside the deflate stream rather than inside the header.
	noise := randomBytes(t, 64<<10)
	truncated := members(t, noise)
	truncated = truncated[:len(truncated)/2]
	// Larger than maxScratch, so the scratch buffer that served it is dropped
	// rather than pooled; the result must not depend on that.
	large := randomBytes(t, 3<<20)

	tests := []struct {
		name    string
		data    []byte
		want    []byte
		wantErr error
	}{
		{name: "single member", data: members(t, text), want: text},
		{name: "empty member", data: members(t, nil), want: []byte{}},
		{name: "concatenated members", data: members(t, text[:1000], text[1000:]), want: text},
		{name: "larger than the scratch cap", data: members(t, large), want: large},
		{name: "not gzip", data: notGzip, wantErr: gzip.ErrHeader},
		{name: "shorter than a header", data: notGzip[:8], wantErr: io.ErrUnexpectedEOF},
		{name: "empty body", data: nil, wantErr: io.EOF},
		{name: "truncated", data: truncated, wantErr: io.ErrUnexpectedEOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Bytes(tt.data)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Bytes() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("Bytes() = %d bytes, want %d bytes", len(got), len(tt.want))
			}
			// Same contract as io.ReadAll: never nil, and the caller owns an
			// exactly sized buffer rather than a window into pooled scratch.
			if got == nil {
				t.Fatal("Bytes() = nil, want a non-nil slice")
			}
			if cap(got) != len(got) {
				t.Fatalf("cap(Bytes()) = %d, want %d (result aliases a larger buffer)", cap(got), len(got))
			}
		})
	}
}

// TestBytesResultIsOwned locks the aliasing invariant directly: a result must
// survive later calls untouched, since those reuse the scratch buffer.
func TestBytesResultIsOwned(t *testing.T) {
	first := bytes.Repeat([]byte("first "), 1000)
	second := bytes.Repeat([]byte("second "), 1000)
	got, err := Bytes(members(t, first))
	if err != nil {
		t.Fatalf("Bytes(first): %v", err)
	}
	for range 4 {
		if _, err := Bytes(members(t, second)); err != nil {
			t.Fatalf("Bytes(second): %v", err)
		}
	}
	if !bytes.Equal(got, first) {
		t.Fatal("an earlier result was overwritten by a later call")
	}
}

// TestBytesConcurrent runs good, unreadable and truncated bodies through the
// shared pools from many goroutines at once. Under -race it catches a reader
// or scratch buffer being handed to two bodies; without it, it checks that a
// reader recycled after an error still decodes correctly.
func TestBytesConcurrent(t *testing.T) {
	text := bytes.Repeat([]byte("the quick brown fox "), 4096)
	good := members(t, text)
	truncated := members(t, randomBytes(t, 16<<10))
	truncated = truncated[:len(truncated)/2]

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 200 {
				switch (g + i) % 3 {
				case 0:
					got, err := Bytes(good)
					if err != nil {
						t.Errorf("goroutine %d iteration %d: Bytes(good) error = %v", g, i, err)
					} else if !bytes.Equal(got, text) {
						t.Errorf("goroutine %d iteration %d: Bytes(good) returned %d bytes, want %d", g, i, len(got), len(text))
					}
				case 1:
					if _, err := Bytes(notGzip); !errors.Is(err, gzip.ErrHeader) {
						t.Errorf("goroutine %d iteration %d: Bytes(not gzip) error = %v, want %v", g, i, err, gzip.ErrHeader)
					}
				case 2:
					if _, err := Bytes(truncated); !errors.Is(err, io.ErrUnexpectedEOF) {
						t.Errorf("goroutine %d iteration %d: Bytes(truncated) error = %v, want %v", g, i, err, io.ErrUnexpectedEOF)
					}
				}
			}
		})
	}
	wg.Wait()
}

func TestStream(t *testing.T) {
	text := bytes.Repeat([]byte("streamed "), 8192)
	data := members(t, text[:len(text)/2], text[len(text)/2:])

	t.Run("reads to EOF and recycles", func(t *testing.T) {
		// Small reads on both sides, so the member boundary and the EOF are
		// crossed inside Read rather than swallowed by one large call.
		stream, err := NewStream(iotest.HalfReader(bytes.NewReader(data)))
		if err != nil {
			t.Fatalf("NewStream: %v", err)
		}
		var got bytes.Buffer
		buf := make([]byte, 1000)
		for {
			n, err := stream.Read(buf)
			got.Write(buf[:n])
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
		}
		if !bytes.Equal(got.Bytes(), text) {
			t.Fatalf("stream produced %d bytes, want %d", got.Len(), len(text))
		}
		if !stream.recycled() {
			t.Fatal("reader was not recycled at EOF")
		}
		if n, err := stream.Read(buf); n != 0 || err != io.EOF {
			t.Fatalf("Read after EOF = %d, %v; want 0, io.EOF", n, err)
		}
		if err := stream.Close(); err != nil {
			t.Fatalf("Close after EOF: %v", err)
		}
	})

	t.Run("close before EOF does not recycle", func(t *testing.T) {
		stream, err := NewStream(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("NewStream: %v", err)
		}
		if _, err := stream.Read(make([]byte, 10)); err != nil {
			t.Fatalf("Read: %v", err)
		}
		if err := stream.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		// Close may be racing a blocked Read on this same stream, so the reader
		// must stay attached: recycling it here could hand a reader that is
		// still in use to an unrelated response.
		if stream.recycled() {
			t.Fatal("Close before EOF recycled the reader")
		}
	})

	t.Run("bad header", func(t *testing.T) {
		if _, err := NewStream(bytes.NewReader(notGzip)); !errors.Is(err, gzip.ErrHeader) {
			t.Fatalf("NewStream error = %v, want %v", err, gzip.ErrHeader)
		}
	})

	t.Run("truncated", func(t *testing.T) {
		truncated := members(t, randomBytes(t, 16<<10))
		stream, err := NewStream(bytes.NewReader(truncated[:len(truncated)/2]))
		if err != nil {
			t.Fatalf("NewStream: %v", err)
		}
		if _, err := io.ReadAll(stream); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("ReadAll error = %v, want %v", err, io.ErrUnexpectedEOF)
		}
		if stream.recycled() {
			t.Fatal("a failed stream recycled its reader")
		}
	})
}

// stdlibBytes is the code Bytes replaced, kept as the reference.
func stdlibBytes(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// stdlibStream is the code NewStream replaced: the header read eagerly by
// gzip.NewReader, the rest read through the reader.
func stdlibStream(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

func sameResult(t *testing.T, what string, i int, input []byte, got []byte, gotErr error, want []byte, wantErr error) {
	t.Helper()
	if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
		t.Fatalf("%s case %d (%d input bytes): error = %v, stdlib = %v", what, i, len(input), gotErr, wantErr)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s case %d (%d input bytes): output %d bytes, stdlib %d bytes", what, i, len(input), len(got), len(want))
	}
	if (got == nil) != (want == nil) {
		t.Fatalf("%s case %d: nil-ness differs: got nil=%v, stdlib nil=%v", what, i, got == nil, want == nil)
	}
}

// mutatedCorpus builds gzip streams and then damages them the ways a network
// body can arrive damaged: truncated at any point, a byte flipped anywhere
// (header, deflate data, CRC, length), members concatenated, garbage
// appended, or empty.
func mutatedCorpus(tb testing.TB) [][]byte {
	tb.Helper()
	rng := mathrand.New(mathrand.NewPCG(1, 2))
	text := bytes.Repeat([]byte(`{"id":1,"text":"hello, httpcloak"}`), 512)
	noise := make([]byte, 8<<10)
	rand.Read(noise)
	bases := [][]byte{
		members(tb, text),
		members(tb, noise),
		members(tb, text[:100], text[100:]),
		members(tb, nil),
		members(tb, []byte("x")),
	}
	var corpus [][]byte
	corpus = append(corpus, nil, []byte{}, []byte{0x1f}, []byte{0x1f, 0x8b})
	// Bodies around and past the scratch cap, whole and truncated, so the
	// io.ReadAll hand-off is compared against the old path too.
	for _, size := range []int{maxScratch - 1, maxScratch, maxScratch + 1, maxScratch + maxScratch/2, 3 * maxScratch} {
		big := make([]byte, size)
		for i := range big {
			big[i] = byte('a' + i%26)
		}
		whole := members(tb, big)
		corpus = append(corpus, whole, whole[:len(whole)*2/3], whole[:len(whole)-1])
	}
	for _, base := range bases {
		corpus = append(corpus, base)
		for range 200 {
			m := bytes.Clone(base)
			switch rng.IntN(4) {
			case 0:
				m = m[:rng.IntN(len(m)+1)]
			case 1:
				m[rng.IntN(len(m))] ^= byte(1 + rng.IntN(255))
			case 2:
				m = append(m, noise[:rng.IntN(64)]...)
			case 3:
				m[rng.IntN(len(m))] ^= byte(1 + rng.IntN(255))
				m = m[:rng.IntN(len(m)+1)]
			}
			corpus = append(corpus, m)
		}
	}
	return corpus
}

// TestBytesMatchesStdlib is the behavioural lock for the buffered path: for
// every input in the mutated corpus, Bytes must return exactly the bytes and
// exactly the error that gzip.NewReader + io.ReadAll returned.
func TestBytesMatchesStdlib(t *testing.T) {
	for i, input := range mutatedCorpus(t) {
		want, wantErr := stdlibBytes(input)
		got, gotErr := Bytes(input)
		sameResult(t, "Bytes", i, input, got, gotErr, want, wantErr)
	}
}

// TestStreamMatchesStdlib is the same lock for the streaming path, including
// which failures surface at construction and which surface on Read.
func TestStreamMatchesStdlib(t *testing.T) {
	for i, input := range mutatedCorpus(t) {
		want, wantErr := stdlibStream(input)

		var got []byte
		stream, gotErr := NewStream(bytes.NewReader(input))
		_, wantCtorErr := gzip.NewReader(bytes.NewReader(input))
		if (gotErr == nil) != (wantCtorErr == nil) {
			t.Fatalf("Stream case %d: NewStream error = %v, gzip.NewReader error = %v", i, gotErr, wantCtorErr)
		}
		if gotErr == nil {
			got, gotErr = io.ReadAll(stream)
		}
		sameResult(t, "Stream", i, input, got, gotErr, want, wantErr)
	}
}

// TestPoolSurvivesCorpus runs the whole corpus through the pools from several
// goroutines and then checks that a clean body still decodes: no damaged
// input may leave a reader or scratch buffer in a state that corrupts the
// next body.
func TestPoolSurvivesCorpus(t *testing.T) {
	corpus := mutatedCorpus(t)
	text := bytes.Repeat([]byte("clean body "), 4096)
	clean := members(t, text)

	var wg sync.WaitGroup
	for g := range 4 {
		wg.Go(func() {
			for i, input := range corpus {
				Bytes(input)
				if s, err := NewStream(bytes.NewReader(input)); err == nil {
					io.ReadAll(s)
				}
				if (i+g)%7 == 0 {
					got, err := Bytes(clean)
					if err != nil || !bytes.Equal(got, text) {
						t.Errorf("goroutine %d after case %d: clean body decoded wrong: err=%v len=%d", g, i, err, len(got))
						return
					}
				}
			}
		})
	}
	wg.Wait()
}

// TestLargeResultIsOwned: a body past the scratch cap is handed back without
// a copy, so lock that the buffer it lives in is never reused by a later call.
func TestLargeResultIsOwned(t *testing.T) {
	large := randomBytes(t, 2<<20)
	got, err := Bytes(members(t, large))
	if err != nil {
		t.Fatalf("Bytes(large): %v", err)
	}
	for range 3 {
		if _, err := Bytes(members(t, randomBytes(t, 2<<20))); err != nil {
			t.Fatalf("Bytes(another large): %v", err)
		}
		if _, err := Bytes(members(t, []byte("small"))); err != nil {
			t.Fatalf("Bytes(small): %v", err)
		}
	}
	if !bytes.Equal(got, large) {
		t.Fatal("a large result was overwritten by a later call")
	}
}

func benchmarkBytes(b *testing.B, size int, fn func([]byte) ([]byte, error)) {
	var text bytes.Buffer
	for i := 0; text.Len() < size; i++ {
		fmt.Fprintf(&text, `{"id":%d,"text":"hello, httpcloak","kind":"sample"}`+"\n", i)
	}
	data := members(b, text.Bytes())
	b.SetBytes(int64(text.Len()))
	b.ReportAllocs()
	for b.Loop() {
		got, err := fn(data)
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != text.Len() {
			b.Fatalf("decompressed %d bytes, want %d", len(got), text.Len())
		}
	}
}

func BenchmarkBytes(b *testing.B) {
	for _, size := range []int{4 << 10, 64 << 10, 512 << 10, 3 << 20} {
		b.Run(fmt.Sprintf("%dKiB/stdlib", size>>10), func(b *testing.B) { benchmarkBytes(b, size, stdlibBytes) })
		b.Run(fmt.Sprintf("%dKiB/pooled", size>>10), func(b *testing.B) { benchmarkBytes(b, size, Bytes) })
	}
}
