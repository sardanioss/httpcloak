package compress

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

// deflateCorpus builds zlib and raw deflate bodies with the standard library's
// compressor, then damages them the ways a body arrives damaged.
func deflateCorpus(tb testing.TB) [][]byte {
	tb.Helper()
	text := bytes.Repeat([]byte(`{"id":1,"text":"hello, deflate"}`), 4096)
	noise := make([]byte, 64<<10)
	rand.Read(noise)
	var corpus [][]byte
	for _, p := range [][]byte{text, noise, nil, []byte("x")} {
		for _, base := range [][]byte{zlibOf(nil, p), rawOf(nil, p)} {
			corpus = append(corpus, base, base[:len(base)/2], base[:len(base)-1], append(bytes.Clone(base), 0xff, 0x00))
			flipped := bytes.Clone(base)
			flipped[len(flipped)/3] ^= 0x5a
			corpus = append(corpus, flipped)
		}
	}
	return append(corpus, nil, []byte{}, []byte("this is not deflate"))
}

// stdlibInflate is InflateDeflate as it decoded with the standard library's
// inflaters: the same framing choice, then compress/zlib or compress/flate
// over the whole body.
func stdlibInflate(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	var r io.ReadCloser
	if zlibVerdict(data[:min(len(data), sniffLimit)], true) == framingZlib {
		zr, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return []byte{}, err
		}
		r = zr
	} else {
		r = flate.NewReader(bytes.NewReader(data))
	}
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
		got, gotErr := InflateDeflate(input)
		sameInflate(t, "InflateDeflate", i, got, gotErr, want, wantErr)

		got, gotErr = io.ReadAll(NewDeflateReader(bytes.NewReader(input)))
		sameInflate(t, "NewDeflateReader", i, got, gotErr, want, wantErr)
	}
}
