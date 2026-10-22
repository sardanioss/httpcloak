package gunzip

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	kgzip "github.com/klauspost/compress/gzip"
)

// header is the part of a gzip member a test sets by hand.
type header struct {
	flg     byte // written as given, so reserved bits can be set
	extra   []byte
	name    string
	comment string
	badHCRC bool // write a header CRC that does not match
}

// rawMember builds one gzip member byte by byte, so its header carries
// exactly the flags and fields h names.
func rawMember(tb testing.TB, h header, payload []byte) []byte {
	tb.Helper()
	m := []byte{gzipID1, gzipID2, gzipDeflate, h.flg, 0, 0, 0, 0, 0, 255}
	if h.flg&flagExtra != 0 {
		m = binary.LittleEndian.AppendUint16(m, uint16(len(h.extra)))
		m = append(m, h.extra...)
	}
	if h.flg&flagName != 0 {
		m = append(append(m, h.name...), 0)
	}
	if h.flg&flagComment != 0 {
		m = append(append(m, h.comment...), 0)
	}
	if h.flg&flagHdrCrc != 0 {
		crc := uint16(crc32.ChecksumIEEE(m))
		if h.badHCRC {
			crc++
		}
		m = binary.LittleEndian.AppendUint16(m, crc)
	}
	var data bytes.Buffer
	w, err := flate.NewWriter(&data, flate.DefaultCompression)
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		tb.Fatal(err)
	}
	if err := w.Close(); err != nil {
		tb.Fatal(err)
	}
	m = append(m, data.Bytes()...)
	m = binary.LittleEndian.AppendUint32(m, crc32.ChecksumIEEE(payload))
	return binary.LittleEndian.AppendUint32(m, uint32(len(payload)))
}

// readChunked reads r to the end in reads of n bytes.
func readChunked(r io.Reader, n int) ([]byte, error) {
	out := []byte{} // non-nil, like io.ReadAll's
	p := make([]byte, n)
	for {
		k, err := r.Read(p)
		out = append(out, p[:k]...)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

// The gzip framing is read as compress/gzip reads it: every optional header
// field, the header CRC, the trailer CRC and length, the string limit and
// further members give the same bytes and the same error through Bytes and
// through Stream in small and large reads. A header with the flag bits RFC
// 1952 reserves set decodes, as it does in Chrome and compress/gzip, where
// klauspost's own gzip reader refuses it.
func TestGzipFramingMatchesStdlib(t *testing.T) {
	text := []byte(strings.Repeat("compressible text, repeated. ", 40))
	fields := header{flg: flagExtra | flagName | flagComment | flagHdrCrc, extra: []byte("ex"), name: "n.txt", comment: "c"}
	withReserved := func(bits byte) header {
		h := fields
		h.flg |= bits
		return h
	}
	badCRC := rawMember(t, header{}, text)
	badCRC[len(badCRC)-8] ^= 1
	badSize := rawMember(t, header{}, text)
	badSize[len(badSize)-1] ^= 1

	for _, tc := range []struct {
		name     string
		data     []byte
		reserved bool // sets a reserved flag bit
	}{
		{name: "FEXTRA", data: rawMember(t, header{flg: flagExtra, extra: bytes.Repeat([]byte{7}, 700)}, text)},
		{name: "FNAME", data: rawMember(t, header{flg: flagName, name: "file.txt"}, text)},
		{name: "FNAME at 511 bytes", data: rawMember(t, header{flg: flagName, name: strings.Repeat("n", 511)}, text)},
		{name: "FNAME at 512 bytes", data: rawMember(t, header{flg: flagName, name: strings.Repeat("n", 512)}, text)},
		{name: "FCOMMENT", data: rawMember(t, header{flg: flagComment, comment: "a comment"}, text)},
		{name: "FHCRC", data: rawMember(t, header{flg: flagHdrCrc}, text)},
		{name: "every field", data: rawMember(t, fields, text)},
		{name: "bad header CRC", data: rawMember(t, header{flg: flagHdrCrc, badHCRC: true}, text)},
		{name: "bad trailer CRC", data: badCRC},
		{name: "bad ISIZE", data: badSize},
		{name: "multistream", data: append(rawMember(t, header{}, text[:7]), rawMember(t, fields, text)...)},
		{name: "reserved bit 0x20", data: rawMember(t, header{flg: 0x20}, text), reserved: true},
		{name: "reserved bit 0x40", data: rawMember(t, header{flg: 0x40}, text), reserved: true},
		{name: "reserved bit 0x80", data: rawMember(t, header{flg: 0x80}, text), reserved: true},
		{name: "reserved bits with every field", data: rawMember(t, withReserved(0xe0), text), reserved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, wantErr := stdlibBytes(tc.data)
			if tc.reserved {
				if wantErr != nil || !bytes.Equal(want, text) {
					t.Fatalf("compress/gzip decoded %d bytes, %v; want the payload", len(want), wantErr)
				}
				if _, err := kgzip.NewReader(bytes.NewReader(tc.data)); err == nil {
					t.Errorf("klauspost's gzip reader accepted the header; the reason for reading it here is gone")
				}
			}
			got, err := Bytes(tc.data)
			if fmt.Sprint(err) != fmt.Sprint(wantErr) || !bytes.Equal(got, want) {
				t.Errorf("Bytes = %d bytes, %v; want %d bytes, %v", len(got), err, len(want), wantErr)
			}
			for _, n := range []int{7, 64 << 10} {
				var got []byte
				s, err := NewStream(bytes.NewReader(tc.data))
				if err == nil {
					got, err = readChunked(s, n)
				}
				if fmt.Sprint(err) != fmt.Sprint(wantErr) || !bytes.Equal(got, want) {
					t.Errorf("Stream in %d-byte reads = %d bytes, %v; want %d bytes, %v", n, len(got), err, len(want), wantErr)
				}
			}
		})
	}
}
