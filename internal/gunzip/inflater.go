package gunzip

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"hash/crc32"
	"io"

	"github.com/klauspost/compress/flate"
)

// RFC 1952, section 2.3.1.
const (
	gzipID1     = 0x1f
	gzipID2     = 0x8b
	gzipDeflate = 8
	flagHdrCrc  = 1 << 1
	flagExtra   = 1 << 2
	flagName    = 1 << 3
	flagComment = 1 << 4
)

// inflater reads a gzip body with klauspost/compress inflating its members.
//
// The gzip framing is read here rather than by klauspost's gzip.Reader,
// because that reader refuses a header with RFC 1952's reserved flag bits set
// and Chrome ignores them: net/filter/gzip_header.cc masks the flag byte to
// FHCRC, FEXTRA, FNAME and FCOMMENT before acting on it. compress/gzip ignores
// them too, since it only tests the four bits it knows. Everything else about
// the framing follows compress/gzip's Reader step for step: the magic and
// method check, the optional fields and their 511-byte string limit, the
// header CRC, the trailer CRC and length, and further members after a
// trailer, with compress/gzip's own error values.
type inflater struct {
	r       flate.Reader  // the body, as an io.ByteReader so the inflate stops at the end of a member
	br      *bufio.Reader // wraps a body that is not an io.ByteReader; kept across resets
	inflate io.ReadCloser // kept across resets
	digest  uint32        // CRC-32 of the member's header, then of its data
	size    uint32        // the member's data length so far, mod 2^32
	buf     [512]byte
	err     error
}

// noEOF converts io.EOF to io.ErrUnexpectedEOF.
func noEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// Reset discards z's state and reads the first header from r. A body that is
// not an io.ByteReader is read through a bufio.Reader that z keeps for the
// next body, where gzip.Reader allocates a new one per body.
func (z *inflater) Reset(r io.Reader) error {
	z.digest, z.size = 0, 0
	if rr, ok := r.(flate.Reader); ok {
		z.r = rr
	} else {
		if z.br == nil {
			z.br = bufio.NewReader(r)
		} else {
			z.br.Reset(r)
		}
		z.r = z.br
	}
	z.err = z.readHeader()
	return z.err
}

// skipString reads a NUL-terminated header string as gzip.Reader's
// readString does: the terminator is covered by the header CRC, and a string
// longer than the 512-byte buffer is refused.
func (z *inflater) skipString() error {
	for i := range len(z.buf) {
		b, err := z.r.ReadByte()
		if err != nil {
			return err
		}
		z.buf[i] = b
		if b == 0 {
			z.digest = crc32.Update(z.digest, crc32.IEEETable, z.buf[:i+1])
			return nil
		}
	}
	return gzip.ErrHeader
}

// readHeader reads a member header and points the inflate at the data after
// it. A body with no bytes left returns io.EOF, which ends a body cleanly
// after a trailer, as in compress/gzip.
func (z *inflater) readHeader() error {
	if _, err := io.ReadFull(z.r, z.buf[:10]); err != nil {
		return err
	}
	if z.buf[0] != gzipID1 || z.buf[1] != gzipID2 || z.buf[2] != gzipDeflate {
		return gzip.ErrHeader
	}
	// net/filter/gzip_header.cc: flags_ = (*pos) & (FLAG_FHCRC |
	// FLAG_FEXTRA | FLAG_FNAME | FLAG_FCOMMENT).
	flg := z.buf[3] & (flagHdrCrc | flagExtra | flagName | flagComment)
	z.digest = crc32.ChecksumIEEE(z.buf[:10])

	if flg&flagExtra != 0 {
		if _, err := io.ReadFull(z.r, z.buf[:2]); err != nil {
			return noEOF(err)
		}
		z.digest = crc32.Update(z.digest, crc32.IEEETable, z.buf[:2])
		for n := int(binary.LittleEndian.Uint16(z.buf[:2])); n > 0; {
			chunk := z.buf[:min(n, len(z.buf))]
			if _, err := io.ReadFull(z.r, chunk); err != nil {
				return noEOF(err)
			}
			z.digest = crc32.Update(z.digest, crc32.IEEETable, chunk)
			n -= len(chunk)
		}
	}
	if flg&flagName != 0 {
		if err := z.skipString(); err != nil {
			return noEOF(err)
		}
	}
	if flg&flagComment != 0 {
		if err := z.skipString(); err != nil {
			return noEOF(err)
		}
	}
	if flg&flagHdrCrc != 0 {
		if _, err := io.ReadFull(z.r, z.buf[:2]); err != nil {
			return noEOF(err)
		}
		if binary.LittleEndian.Uint16(z.buf[:2]) != uint16(z.digest) {
			return gzip.ErrHeader
		}
	}

	z.digest = 0
	if z.inflate == nil {
		z.inflate = flate.NewReader(z.r)
	} else {
		z.inflate.(flate.Resetter).Reset(z.r, nil)
	}
	return nil
}

// Read decompresses into p, checking each member's trailer at its end and
// moving on to the next member.
func (z *inflater) Read(p []byte) (n int, err error) {
	if z.err != nil {
		return 0, z.err
	}
	for n == 0 {
		n, z.err = z.inflate.Read(p)
		z.digest = crc32.Update(z.digest, crc32.IEEETable, p[:n])
		z.size += uint32(n)
		if z.err != io.EOF {
			return n, z.err
		}

		// The member's data is done; check its trailer.
		if _, err := io.ReadFull(z.r, z.buf[:8]); err != nil {
			z.err = noEOF(err)
			return n, z.err
		}
		digest := binary.LittleEndian.Uint32(z.buf[:4])
		size := binary.LittleEndian.Uint32(z.buf[4:8])
		if digest != z.digest || size != z.size {
			z.err = gzip.ErrChecksum
			return n, z.err
		}
		z.digest, z.size = 0, 0

		// Another member, or the end of the body.
		if z.err = z.readHeader(); z.err != nil {
			return n, z.err
		}
	}
	return n, nil
}
