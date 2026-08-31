// Package gunzip decompresses gzip response bodies without allocating a
// decompressor per body.
//
// A gzip.Reader owns a 32KB decompression window plus Huffman decoding tables,
// and allocating them per response dominates the allocation profile of a
// client that reads many compressed bodies. The readers here come from a
// sync.Pool and are reset onto the next body, so a body only allocates when
// the pool is empty. A pooled reader keeps a reference to the body it last
// read until it is reused, but sync.Pool drops its contents on every GC, so
// that reference cannot outlive a GC cycle.
package gunzip

import (
	"bytes"
	"io"
	"sync"

	"github.com/klauspost/compress/gzip"
)

var readerPool sync.Pool

// reader returns a gzip.Reader positioned at the start of the stream in r,
// taking it from the pool when one is available.
//
// A failed Reset returns the reader to the pool rather than dropping it: Reset
// reassigns all of the reader's state, so it stays reusable, and a body that
// cannot be read (an empty body reads as an unexpected EOF) must not drain the
// pool one reader at a time.
func reader(r io.Reader) (*gzip.Reader, error) {
	zr, _ := readerPool.Get().(*gzip.Reader)
	if zr == nil {
		zr = new(gzip.Reader)
	}
	if err := zr.Reset(r); err != nil {
		readerPool.Put(zr)
		return nil, err
	}
	return zr, nil
}

// maxScratch is the largest scratch buffer Bytes keeps for reuse. It matches
// the smallest size class of the transport package's body pools: a buffer that
// grew past it served an unusually large body and is dropped rather than held
// for the life of the process.
const maxScratch = 1 << 20

var scratchPool sync.Pool

// Bytes decompresses a fully buffered gzip body. The result is exactly sized
// and owned by the caller; like io.ReadAll it is non-nil, and on an error it
// holds whatever was decompressed before the error.
//
// The body is decompressed into a pooled scratch buffer and then copied out
// once. io.ReadAll instead builds a chain of growing intermediate buffers
// before its own final copy, which for a body of n bytes allocates more than
// 2n on the way; a retained scratch buffer that already fits the body does
// not allocate at all, so the one allocation left is the n-byte result. A
// body that fills the scratch to maxScratch has the rest read by io.ReadAll,
// with what is already decoded in front of it, so bodies past the cap cost
// exactly what they did before.
func Bytes(data []byte) ([]byte, error) {
	zr, err := reader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	scratch, _ := scratchPool.Get().(*[]byte)
	if scratch == nil {
		scratch = new([]byte)
		*scratch = make([]byte, 0, 512)
	}
	buf := (*scratch)[:0]
	var out []byte
	for {
		n, rerr := zr.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if rerr != nil {
			if rerr != io.EOF {
				err = rerr
			}
			out = make([]byte, len(buf))
			copy(out, buf)
			break
		}
		if len(buf) < cap(buf) {
			continue
		}
		if cap(buf) >= maxScratch {
			out, err = io.ReadAll(io.MultiReader(bytes.NewReader(buf), zr))
			break
		}
		grown := make([]byte, len(buf), min(2*cap(buf), maxScratch))
		copy(grown, buf)
		buf = grown
	}
	// The whole input is in memory and nothing else holds zr, so it goes back
	// however the read ended; the next Reset clears any error state. The
	// scratch never grows past maxScratch, so it always goes back too.
	readerPool.Put(zr)
	*scratch = buf[:0]
	scratchPool.Put(scratch)
	return out, err
}

// Stream decompresses a streaming body through a pooled gzip.Reader and
// recycles the reader once the body has been fully decompressed.
//
// The reader is recycled when Read returns io.EOF, never on Close: a stream's
// Close may run concurrently with a blocked Read in order to unblock it, so
// recycling on Close could hand a reader that is still in use to an unrelated
// response. A body that is abandoned before EOF is simply not recycled.
//
// Read, like that of any io.Reader, must not be called concurrently on the
// same stream.
type Stream struct {
	zr   *gzip.Reader // nil once recycled
	zerr error        // returned by every Read after zr is recycled
}

// NewStream reads the gzip header from body and returns a stream over the
// members that follow. It fails when the header cannot be read, exactly as
// gzip.NewReader does.
func NewStream(body io.Reader) (*Stream, error) {
	zr, err := reader(body)
	if err != nil {
		return nil, err
	}
	return &Stream{zr: zr}, nil
}

// Read decompresses into p.
func (s *Stream) Read(p []byte) (n int, err error) {
	if s.zr == nil {
		return 0, s.zerr
	}
	n, err = s.zr.Read(p)
	if err == io.EOF {
		// The body is fully decompressed, including any concatenated members,
		// and the reader is done with it, so this is the one point where
		// recycling cannot collide with a read in progress. Detach the reader
		// before publishing it to the pool.
		zr := s.zr
		s.zr = nil
		s.zerr = io.EOF
		readerPool.Put(zr)
	}
	return n, err
}

// Close releases nothing: the underlying body is closed by its owner, and the
// reader is recycled at EOF rather than here (see the type comment).
func (s *Stream) Close() error { return nil }

// recycled reports whether the stream has handed its reader back to the pool.
// It exists for tests.
func (s *Stream) recycled() bool { return s.zr == nil }
