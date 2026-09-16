package compress

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"io"
	"strings"
	"testing"
)

const payload = "hello deflate world, long enough to actually compress"

func zlibBody(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return b.Bytes()
}

func rawBody(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return b.Bytes()
}

// Content-Encoding: deflate is the zlib framing of RFC 1950, and raw RFC 1951
// is the common variant. Both have to read.
func TestInflateReadsBothFramings(t *testing.T) {
	for _, tc := range []struct {
		name string
		body func(*testing.T, string) []byte
	}{
		{"zlib", zlibBody},
		{"raw", rawBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewInflateReader(bytes.NewReader(tc.body(t, payload)))
			defer r.Close()

			out, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if string(out) != payload {
				t.Fatalf("got %q, want %q", out, payload)
			}
		})
	}
}

// A body too short to be a stream is still too short once the framing is
// sniffed. flate.NewReader on each of these reports unexpected EOF, and so
// does this, so the sniff changes nothing for them.
func TestInflateShortBodiesBehaveAsBefore(t *testing.T) {
	for _, in := range [][]byte{
		{},           // nothing at all
		{0x78},       // one byte, too short to sniff
		{0x78, 0x9c}, // a valid zlib header and nothing after it
	} {
		want := errOf(io.ReadAll(flate.NewReader(bytes.NewReader(in))))

		r := NewInflateReader(bytes.NewReader(in))
		got := errOf(io.ReadAll(r))
		r.Close()

		if got != want {
			t.Errorf("body %x: got %v, flate.NewReader gives %v", in, got, want)
		}
	}
}

func errOf(_ []byte, err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Nothing is read from the body until the caller reads, so a streaming
// response is not held up while the response is being built.
func TestInflateDoesNotReadUntilItIsRead(t *testing.T) {
	src := &countingReader{Reader: bytes.NewReader(zlibBody(t, payload))}
	r := NewInflateReader(src)
	if src.reads != 0 {
		t.Fatalf("the source was read %d times before the first Read", src.reads)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatal(err)
	}
	if src.reads == 0 {
		t.Fatal("the source was never read")
	}
	r.Close()
}

type countingReader struct {
	io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.Reader.Read(p)
}

// The header check is compared against compress/zlib itself over every
// possible two-byte header, so it cannot drift from the reference and no
// header has to be worked out by hand. A header naming a preset dictionary is
// still a zlib header; zlib's own error surfaces for it instead of the body
// being read as raw deflate.
func TestLooksLikeZlibAgreesWithCompressZlib(t *testing.T) {
	var accepted int
	for cmf := 0; cmf < 256; cmf++ {
		for flg := 0; flg < 256; flg++ {
			header := []byte{byte(cmf), byte(flg)}
			_, err := zlib.NewReader(bytes.NewReader(append(header, make([]byte, 8)...)))
			want := err == nil || err == zlib.ErrDictionary
			if want {
				accepted++
			}
			if got := LooksLikeZlib(byte(cmf), byte(flg)); got != want {
				t.Errorf("header %#02x %#02x: LooksLikeZlib = %v, compress/zlib says %v", cmf, flg, got, want)
			}
		}
	}
	if accepted == 0 {
		t.Fatal("compress/zlib accepted no header at all, so the comparison proves nothing")
	}
}

// A read error from the body is reported and then stays reported.
func TestInflateKeepsAReadError(t *testing.T) {
	r := NewInflateReader(errReader{})
	if _, err := r.Read(make([]byte, 8)); err == nil {
		t.Fatal("the read error was swallowed")
	}
	if _, err := r.Read(make([]byte, 8)); err == nil {
		t.Fatal("the second read did not report the error again")
	}
	r.Close()
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }

// Close before any read must not panic, and must not report an error of its
// own: there is nothing open yet.
func TestCloseBeforeAnyRead(t *testing.T) {
	if err := NewInflateReader(strings.NewReader("")).Close(); err != nil {
		t.Fatalf("Close before reading: %v", err)
	}
}
