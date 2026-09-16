// Package compress holds decompression the client and the transport both need.
package compress

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"io"
)

// LooksLikeZlib reports whether the two bytes are an RFC 1950 zlib header:
// the compression method is deflate, the window size is in range, and the
// pair is a multiple of 31. A raw deflate stream can satisfy all three by
// chance, so this is a heuristic, but it is the one browsers use and it is
// the only way to tell the two framings apart.
func LooksLikeZlib(cmf, flg byte) bool {
	if cmf&0x0f != 8 { // CM, 8 is deflate
		return false
	}
	if cmf>>4 > 7 { // CINFO, window size
		return false
	}
	return (uint16(cmf)<<8|uint16(flg))%31 == 0 // FCHECK
}

// NewInflateReader inflates a Content-Encoding: deflate body. RFC 9110 defines
// that encoding as the zlib framing of RFC 1950, while raw RFC 1951 deflate is
// the common variant, so both are read.
//
// The framing is sniffed on the first Read and the sniffed bytes are put back,
// so a streaming body is not touched until the caller reads it.
func NewInflateReader(r io.Reader) io.ReadCloser {
	return &inflateReader{src: r}
}

type inflateReader struct {
	src io.Reader
	dec io.ReadCloser
	err error // sticky
}

func (d *inflateReader) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	if d.dec == nil {
		var head [2]byte
		n, err := io.ReadFull(d.src, head[:])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			d.err = err
			return 0, err
		}
		body := io.MultiReader(bytes.NewReader(head[:n]), d.src)
		if n == len(head) && LooksLikeZlib(head[0], head[1]) {
			zr, err := zlib.NewReader(body)
			if err != nil {
				d.err = err
				return 0, err
			}
			d.dec = zr
		} else {
			d.dec = flate.NewReader(body)
		}
	}
	return d.dec.Read(p)
}

func (d *inflateReader) Close() error {
	if d.dec != nil {
		return d.dec.Close()
	}
	return nil
}
