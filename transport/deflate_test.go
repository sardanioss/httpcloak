package transport

import (
	"bytes"
	stdflate "compress/flate"
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

// deflateCorpus builds raw deflate streams with the standard library's
// compressor, then damages them the ways a body arrives damaged.
func deflateCorpus(tb testing.TB) [][]byte {
	tb.Helper()
	compress := func(p []byte) []byte {
		var buf bytes.Buffer
		w, err := stdflate.NewWriter(&buf, stdflate.DefaultCompression)
		if err != nil {
			tb.Fatal(err)
		}
		w.Write(p)
		w.Close()
		return buf.Bytes()
	}
	text := bytes.Repeat([]byte(`{"id":1,"text":"hello, deflate"}`), 4096)
	noise := make([]byte, 64<<10)
	rand.Read(noise)
	var corpus [][]byte
	for _, base := range [][]byte{compress(text), compress(noise), compress(nil), compress([]byte("x"))} {
		corpus = append(corpus, base, base[:len(base)/2], base[:len(base)-1], append(bytes.Clone(base), 0xff, 0x00))
		flipped := bytes.Clone(base)
		flipped[len(flipped)/3] ^= 0x5a
		corpus = append(corpus, flipped)
	}
	corpus = append(corpus, nil, []byte{}, []byte("this is not deflate"))
	return corpus
}

func stdlibInflate(data []byte) ([]byte, error) {
	r := stdflate.NewReader(bytes.NewReader(data))
	defer r.Close()
	return io.ReadAll(r)
}

// sameInflate compares an inflate result with the standard library's for the
// same input: the same success or failure, the same bytes on success, and on
// failure the same error, up to the byte offset a corrupt-input error names,
// with the partial output a prefix of stdlib's (the inflater may report a
// damaged stream a byte later and before flushing its last window).
func sameInflate(t *testing.T, what string, i int, got []byte, gotErr error, want []byte, wantErr error) {
	t.Helper()
	if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && strings.TrimRight(gotErr.Error(), "0123456789") != strings.TrimRight(wantErr.Error(), "0123456789")) {
		t.Fatalf("%s case %d: error = %v, stdlib = %v", what, i, gotErr, wantErr)
	}
	if gotErr != nil {
		if !bytes.HasPrefix(want, got) {
			t.Fatalf("%s case %d: partial output is not a prefix of stdlib's (%d vs %d bytes)", what, i, len(got), len(want))
		}
		return
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s case %d: %d bytes, stdlib %d bytes", what, i, len(got), len(want))
	}
}

// TestDeflateMatchesStdlib holds the inflater, on both the buffered and the
// streaming path, to what the standard library's produced for the same input.
func TestDeflateMatchesStdlib(t *testing.T) {
	for i, input := range deflateCorpus(t) {
		want, wantErr := stdlibInflate(input)
		got, gotErr := decompress(input, "deflate")
		sameInflate(t, "decompress", i, got, gotErr, want, wantErr)

		reader, _ := setupStreamDecompressor(io.NopCloser(bytes.NewReader(input)), "deflate")
		got, gotErr = io.ReadAll(reader)
		sameInflate(t, "stream", i, got, gotErr, want, wantErr)
	}
}
