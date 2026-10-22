// Package compress holds content-coding decoders shared by the transport and
// client packages, so a decoding rule lives in one place instead of in each
// request path.
package compress

import (
	"bytes"
	stdzlib "compress/zlib"
	"errors"
	"io"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/zlib"
)

// sniffLimit is how much of a deflate body is examined before the framing is
// decided, matching kMaxZlibHeaderSniffBytes in Chromium's GzipSourceStream.
const sniffLimit = 128

// NewDeflateReader decodes a body sent with Content-Encoding: deflate.
//
// RFC 9110 section 8.4.1.2 defines that coding as the zlib format of RFC 1950,
// a two-byte header and an Adler-32 trailer around a raw RFC 1951 stream. Many
// servers send the raw stream instead, and browsers accept both, so servers get
// away with either. Every deflate path here used flate.NewReader, which reads
// raw only, so a body in the framing the RFC actually specifies failed to
// decode (#115).
//
// The choice between the two follows Chromium, net/filter/gzip_source_stream.cc:
// it inflates as zlib, and if that fails before producing any output and
// within the first 128 bytes, it restarts the body as raw deflate. A body whose
// zlib header is valid but whose data is corrupt after that point fails, as it
// does in Chrome.
//
// Nothing is read from r until the first Read, so a streaming body is not
// consumed before the caller asks for it. Close releases the decoder; it does
// not close r, which stays with its owner.
func NewDeflateReader(r io.Reader) io.ReadCloser {
	return &deflateReader{src: r}
}

// InflateDeflate decodes a whole deflate body. See NewDeflateReader.
func InflateDeflate(data []byte) ([]byte, error) {
	r := NewDeflateReader(bytes.NewReader(data))
	defer r.Close()
	return io.ReadAll(r)
}

type deflateReader struct {
	src     io.Reader
	dec     io.ReadCloser
	err     error
	started bool
}

func (d *deflateReader) Read(p []byte) (int, error) {
	if !d.started {
		d.started = true
		d.dec, d.err = choose(d.src)
	}
	if d.err != nil {
		return 0, d.err
	}
	return d.dec.Read(p)
}

func (d *deflateReader) Close() error {
	if d.dec != nil {
		return d.dec.Close()
	}
	return nil
}

// choose decides the framing and returns a decoder over the bytes it read
// followed by the rest of src.
//
// It reads only what src has ready and decides as soon as it can, as Chromium
// does: zlib once inflating the prefix produces output, raw once it fails.
// While neither has happened it reads on, up to sniffLimit bytes or the end
// of the body, and then takes zlib, which is valid as far as it goes. Waiting
// for a full sniffLimit before deciding held back the first bytes of a slow
// stream, such as server-sent events, until 128 compressed bytes had built
// up, which no browser does.
func choose(src io.Reader) (io.ReadCloser, error) {
	prefix := make([]byte, 0, sniffLimit)
	for {
		n, err := src.Read(prefix[len(prefix):sniffLimit])
		prefix = prefix[:len(prefix)+n]
		eof := errors.Is(err, io.EOF)
		if err != nil && !eof {
			return nil, err
		}
		if eof && len(prefix) == 0 {
			// An empty body decodes to nothing, under either framing.
			return io.NopCloser(bytes.NewReader(nil)), nil
		}
		final := eof || len(prefix) == sniffLimit
		if n == 0 && !final {
			continue
		}
		whole := io.MultiReader(bytes.NewReader(prefix), src)
		switch zlibVerdict(prefix, final) {
		case framingZlib:
			return zlib.NewReader(whole)
		case framingRaw:
			return flate.NewReader(whole), nil
		}
	}
}

type framing int

const (
	framingUndecided framing = iota
	framingZlib
	framingRaw
)

// zlibVerdict inflates prefix as zlib and says what that settles. It produces
// output or reaches the end of the stream: zlib. It fails in any other way: raw,
// which is what makes Chrome fall back. It runs out of input with neither
// having happened: undecided, unless final says no more is coming, in which
// case zlib, valid as far as it goes. A header too short to judge is undecided
// too, and raw once final.
func zlibVerdict(prefix []byte, final bool) framing {
	// compress/zlib gives output as early as Chrome's zlib; klauspost reads ahead and would delay this.
	zr, err := stdzlib.NewReader(bytes.NewReader(prefix))
	if err != nil {
		// A bad header or a preset dictionary is raw. So is a body that
		// ends before a header is complete, but a prefix may only be short
		// for now.
		if !final && (errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) {
			return framingUndecided
		}
		return framingRaw
	}
	defer zr.Close()
	var one [1]byte
	n, err := zr.Read(one[:])
	switch {
	case n > 0, errors.Is(err, io.EOF):
		return framingZlib
	case err == nil, errors.Is(err, io.ErrUnexpectedEOF):
		// Valid so far and wants more input.
		if final {
			return framingZlib
		}
		return framingUndecided
	default:
		return framingRaw
	}
}
