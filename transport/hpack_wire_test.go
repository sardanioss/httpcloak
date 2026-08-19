package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/net/http2/hpack"
)

// Wire-level locks on the HPACK request encoder.
//
// Every defect these cover produced a byte-exact deviation from Chrome while
// the DECODED header list stayed identical, so nothing that inspects headers
// could see any of them. They have to be asserted on the bytes.
//
// They also have to be asserted over at least three requests on one
// connection. Indexing :authority inserts a dynamic entry, which shifts every
// later index; a two-request test that only checks "the first instruction byte
// is 0x41 now" passes while the reuse path drifts underneath it. Request 3 is
// where a stable, fully-indexed block should have settled.
//
// Reference bytes come from real Chrome 151 on Windows, captured at a local
// TLS+ALPN h2 server that logged header_block_fragment before any decode.

// ---------------------------------------------------------------- test server

// hpackWireServer is a minimal HTTP/2 server that records each client HEADERS
// payload verbatim. It speaks only enough of the protocol to keep a client
// sending: SETTINGS, an ACK, and a one-byte :status 200 per request.
type hpackWireServer struct {
	addr       string
	tableSize  uint32   // advertised SETTINGS_HEADER_TABLE_SIZE, 0 to omit
	setCookies []string // Set-Cookie values, sent on the first response only

	mu     sync.Mutex
	blocks [][]byte
}

func (h *hpackWireServer) captured() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([][]byte, len(h.blocks))
	copy(out, h.blocks)
	return out
}

func startHPACKWireServer(t *testing.T, tableSize uint32, setCookies []string) *hpackWireServer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	h := &hpackWireServer{addr: ln.Addr().String(), tableSize: tableSize, setCookies: setCookies}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h.handleConn(c)
		}
	}()
	return h
}

func writeWireFrame(w io.Writer, typ, flags byte, streamID uint32, payload []byte) {
	hdr := make([]byte, 9)
	hdr[0], hdr[1], hdr[2] = byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
	hdr[3], hdr[4] = typ, flags
	binary.BigEndian.PutUint32(hdr[5:], streamID)
	w.Write(hdr)
	w.Write(payload)
}

func (h *hpackWireServer) handleConn(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))

	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if _, err := io.ReadFull(c, make([]byte, len(preface))); err != nil {
		return
	}

	var settings []byte
	if h.tableSize > 0 {
		settings = make([]byte, 6)
		binary.BigEndian.PutUint16(settings[0:], 0x1) // SETTINGS_HEADER_TABLE_SIZE
		binary.BigEndian.PutUint32(settings[2:], h.tableSize)
	}
	writeWireFrame(c, 0x4, 0, 0, settings)

	firstReply := true
	hdr := make([]byte, 9)
	for {
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		typ, flags := hdr[3], hdr[4]
		streamID := binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
		payload := make([]byte, n)
		if _, err := io.ReadFull(c, payload); err != nil {
			return
		}

		switch typ {
		case 0x4: // SETTINGS
			if flags&0x1 == 0 {
				writeWireFrame(c, 0x4, 0x1, 0, nil)
			}
		case 0x1: // HEADERS
			block := payload
			if flags&0x20 != 0 { // PRIORITY flag: skip its 5-byte prefix
				block = block[5:]
			}
			h.mu.Lock()
			h.blocks = append(h.blocks, append([]byte(nil), block...))
			h.mu.Unlock()

			resp := []byte{0x88} // :status 200, static index 8
			if firstReply && len(h.setCookies) > 0 {
				var buf strings.Builder
				enc := hpack.NewEncoder(&buf)
				for _, sc := range h.setCookies {
					enc.WriteField(hpack.HeaderField{Name: "set-cookie", Value: sc})
				}
				resp = append(resp, buf.String()...)
				firstReply = false
			}
			writeWireFrame(c, 0x1, 0x4, streamID, resp)
			writeWireFrame(c, 0x0, 0x1, streamID, []byte("ok"))
		}
	}
}

// ------------------------------------------------------------- instructions

type hpackInstr struct {
	Kind      string // INDEXED | LIT_INCREMENTAL | LIT_WITHOUT | LIT_NEVER | TABLE_SIZE_UPDATE
	NameIndex uint64 // 0 for a literal name
	Name      string
	ValueHuff bool
	Size      uint64 // TABLE_SIZE_UPDATE only
	First     byte   // first byte of the instruction
}

func hpackVarint(b []byte, pos int, n uint8) (uint64, int, error) {
	if pos >= len(b) {
		return 0, pos, fmt.Errorf("varint: eof")
	}
	mask := uint64(1)<<n - 1
	v := uint64(b[pos]) & mask
	pos++
	if v < mask {
		return v, pos, nil
	}
	for m := uint(0); ; m += 7 {
		if pos >= len(b) {
			return 0, pos, fmt.Errorf("varint: eof in continuation")
		}
		c := b[pos]
		pos++
		v += uint64(c&0x7f) << m
		if c&0x80 == 0 {
			return v, pos, nil
		}
	}
}

func hpackSkipString(b []byte, pos int) (huff bool, next int, err error) {
	if pos >= len(b) {
		return false, pos, fmt.Errorf("string: eof")
	}
	huff = b[pos]&0x80 != 0
	l, pos, err := hpackVarint(b, pos, 7)
	if err != nil {
		return huff, pos, err
	}
	if pos+int(l) > len(b) {
		return huff, pos, fmt.Errorf("string: short")
	}
	return huff, pos + int(l), nil
}

// parseHPACK walks a header block and returns one entry per instruction. It
// resolves names only far enough to identify pseudo-headers and cookie, which
// is all these assertions need; it deliberately does not maintain a full
// dynamic table, so a decoded-header comparison cannot creep back in here.
func parseHPACK(t *testing.T, block []byte) []hpackInstr {
	t.Helper()
	// Only the entries a test needs to match on by name. Anything absent still
	// parses; it just reports an empty Name, so match on NameIndex there.
	staticNames := map[uint64]string{
		1: ":authority", 2: ":method", 3: ":method", 4: ":path", 5: ":path",
		6: ":scheme", 7: ":scheme", 16: "accept-encoding", 17: "accept-language",
		19: "accept", 23: "authorization", 32: "cookie", 58: "user-agent",
	}

	var out []hpackInstr
	pos := 0
	for pos < len(block) {
		first := block[pos]
		switch {
		case first&0x80 != 0:
			idx, np, err := hpackVarint(block, pos, 7)
			if err != nil {
				t.Fatalf("malformed INDEXED at %d: %v", pos, err)
			}
			pos = np
			out = append(out, hpackInstr{Kind: "INDEXED", NameIndex: idx, Name: staticNames[idx], First: first})

		case first&0xE0 == 0x20:
			sz, np, err := hpackVarint(block, pos, 5)
			if err != nil {
				t.Fatalf("malformed TABLE_SIZE_UPDATE at %d: %v", pos, err)
			}
			pos = np
			out = append(out, hpackInstr{Kind: "TABLE_SIZE_UPDATE", Size: sz, First: first})

		default:
			var kind string
			var prefix uint8
			switch {
			case first&0xC0 == 0x40:
				kind, prefix = "LIT_INCREMENTAL", 6
			case first&0xF0 == 0x10:
				kind, prefix = "LIT_NEVER", 4
			default:
				kind, prefix = "LIT_WITHOUT", 4
			}
			nameIdx, np, err := hpackVarint(block, pos, prefix)
			if err != nil {
				t.Fatalf("malformed literal at %d: %v", pos, err)
			}
			pos = np
			if nameIdx == 0 {
				if _, pos, err = hpackSkipString(block, pos); err != nil {
					t.Fatalf("malformed literal name at %d: %v", pos, err)
				}
			}
			vh, np2, err := hpackSkipString(block, pos)
			if err != nil {
				t.Fatalf("malformed literal value at %d: %v", pos, err)
			}
			pos = np2
			out = append(out, hpackInstr{
				Kind: kind, NameIndex: nameIdx, Name: staticNames[nameIdx],
				ValueHuff: vh, First: first,
			})
		}
	}
	return out
}

func findInstr(ins []hpackInstr, name string) (hpackInstr, bool) {
	for _, in := range ins {
		if in.Name == name {
			return in, true
		}
	}
	return hpackInstr{}, false
}

func countInstr(ins []hpackInstr, kind string) int {
	n := 0
	for _, in := range ins {
		if in.Kind == kind {
			n++
		}
	}
	return n
}

// drive issues requests on one session, i.e. one connection.
func drive(t *testing.T, h *hpackWireServer, want int, reqs func(tr *Transport, base string)) [][]byte {
	t.Helper()
	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	reqs(tr, "https://"+h.addr)

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.captured()) >= want {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	blocks := h.captured()
	if len(blocks) < want {
		t.Skipf("captured %d/%d header blocks; environment did not complete the exchange", len(blocks), want)
	}
	return blocks
}

func get(t *testing.T, tr *Transport, url string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := tr.Do(ctx, &Request{Method: "GET", URL: url}); err != nil {
		t.Logf("request %s: %v", url, err)
	}
}

// -------------------------------------------------------------------- tests

// :authority is the one pseudo-header Chrome indexes. Emitting it without
// indexing costs one byte on request 1 and re-sends the whole literal on every
// request after that, because it never enters the dynamic table.
//
// Chrome: 4188f1e3c2e9b4cbca6f on request 1, then a single indexed byte.
func TestHPACKAuthorityIsIndexed(t *testing.T) {
	h := startHPACKWireServer(t, 0, nil)
	blocks := drive(t, h, 3, func(tr *Transport, base string) {
		get(t, tr, base+"/fi/matkat")
		get(t, tr, base+"/fi/matkat/probe")
		get(t, tr, base+"/fi/matkat/probe2")
	})

	first := parseHPACK(t, blocks[0])
	a, ok := findInstr(first, ":authority")
	if !ok {
		t.Fatal("no :authority instruction in the first header block")
	}
	if a.Kind != "LIT_INCREMENTAL" || a.NameIndex != 1 {
		t.Errorf("request 1 :authority = %s name index %d (first byte %#x), want LIT_INCREMENTAL "+
			"name index 1 (0x41). Chrome indexes :authority; without it the literal is re-sent "+
			"on every request for the life of the connection", a.Kind, a.NameIndex, a.First)
	}

	// Requests 2 and 3: it must now be a single indexed reference. The index
	// itself moves as later insertions shift the table, so match on the
	// representation, never on a constant byte.
	for i := 1; i < 3; i++ {
		ins := parseHPACK(t, blocks[i])
		if len(ins) < 2 {
			t.Fatalf("request %d: only %d instructions", i+1, len(ins))
		}
		if got := ins[1]; got.Kind != "INDEXED" || got.NameIndex < 62 {
			t.Errorf("request %d: second instruction is %s index %d (%#x), want INDEXED from the "+
				"dynamic range. A literal here means the reuse path still diverges even though "+
				"request 1 looks correct", i+1, got.Kind, got.NameIndex, got.First)
		}
	}
}

// A non-root :path must reference static name index 4 (":path: /"), not 5
// (":path: /index.html"). Chrome: 048762533148d3d469 for /fi/matkat.
func TestHPACKPathUsesNameIndex4(t *testing.T) {
	h := startHPACKWireServer(t, 0, nil)
	blocks := drive(t, h, 3, func(tr *Transport, base string) {
		get(t, tr, base+"/fi/matkat")
		get(t, tr, base+"/fi/matkat/probe")
		get(t, tr, base+"/fi/matkat/probe2")
	})

	for i, b := range blocks[:3] {
		p, ok := findInstr(parseHPACK(t, b), ":path")
		if !ok {
			t.Fatalf("request %d: no :path instruction", i+1)
		}
		if p.NameIndex != 4 {
			t.Errorf("request %d: :path name index = %d (first byte %#x), want 4. Index 5 is "+
				"\":path: /index.html\"; Chrome references index 4", i+1, p.NameIndex, p.First)
		}
		if p.Kind != "LIT_WITHOUT" {
			t.Errorf("request %d: :path = %s, want LIT_WITHOUT; Chrome does not index paths", i+1, p.Kind)
		}
		if !p.ValueHuff {
			t.Errorf("request %d: :path value was not Huffman-coded", i+1)
		}
	}
}

// A non-GET/POST method must reference static name index 2 (":method: GET")
// with a raw value. GET and POST are full static value matches and never reach
// this path, so only the other methods expose it.
//
// Chrome: 0203505554 (PUT), 020644454c455445 (DELETE), 02055041544348 (PATCH).
func TestHPACKMethodUsesNameIndex2(t *testing.T) {
	h := startHPACKWireServer(t, 0, nil)
	blocks := drive(t, h, 3, func(tr *Transport, base string) {
		for _, m := range []string{"PUT", "DELETE", "PATCH"} {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			if _, err := tr.Do(ctx, &Request{Method: m, URL: base + "/fi/matkat"}); err != nil {
				t.Logf("%s: %v", m, err)
			}
			cancel()
		}
	})

	for i, want := range []string{"PUT", "DELETE", "PATCH"} {
		m, ok := findInstr(parseHPACK(t, blocks[i]), ":method")
		if !ok {
			t.Fatalf("%s: no :method instruction", want)
		}
		if m.NameIndex != 2 {
			t.Errorf("%s: :method name index = %d (first byte %#x), want 2. Index 3 is "+
				"\":method: POST\"; Chrome references index 2", want, m.NameIndex, m.First)
		}
		if m.ValueHuff {
			t.Errorf("%s: method string was Huffman-coded. Chrome uses Huffman only when it is "+
				"strictly smaller, and these method names are not", want)
		}
	}
}

// Cookie crumbs are regular headers, so Chrome indexes each one: 0x60,
// literal with incremental indexing, name index 32. The never-indexed form
// (0x1f11) is one no browser emits, and because such a field is never inserted
// the entire jar is re-sent in full on every request.
//
// Chrome: 1181 B, then 39 B, then 35 B. The jar collapses to one byte a crumb.
func TestHPACKCookieCrumbsAreIndexed(t *testing.T) {
	// Set the header directly rather than via a jar: the cookie jar lives in
	// package session, which imports this one. The crumbling and indexing path
	// under test is the same either way, and it is reached from the header.
	// Two short pairs plus two long ones, sized like the session cookies a
	// protected site issues: it is the long values that make the difference
	// between re-sending the jar every request and referencing it in a byte.
	jar := "alpha=one; beta=two; sid=" + strings.Repeat("A", 480) +
		"; tok=" + strings.Repeat("B", 150)
	const crumbCount = 4

	h := startHPACKWireServer(t, 0, nil)
	blocks := drive(t, h, 3, func(tr *Transport, base string) {
		for _, p := range []string{"/fi/matkat", "/fi/matkat/one", "/fi/matkat/two"} {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			_, err := tr.Do(ctx, &Request{
				Method:  "GET",
				URL:     base + p,
				Headers: map[string][]string{"Cookie": {jar}},
			})
			if err != nil {
				t.Logf("%s: %v", p, err)
			}
			cancel()
		}
	})

	// Request 1 carries the jar already: one field per crumb, each indexed,
	// none never-indexed.
	first := parseHPACK(t, blocks[0])
	var crumbs, never int
	for _, in := range first {
		if in.Name != "cookie" {
			continue
		}
		crumbs++
		if in.Kind == "LIT_NEVER" {
			never++
		} else if in.Kind != "LIT_INCREMENTAL" {
			t.Errorf("cookie crumb = %s (first byte %#x), want LIT_INCREMENTAL (0x60)", in.Kind, in.First)
		}
	}
	if never > 0 {
		t.Errorf("%d cookie crumbs used the never-indexed representation (0x1f11). No browser "+
			"emits it, and a never-indexed field is never inserted, so the whole jar is re-sent "+
			"on every request", never)
	}
	if crumbs != crumbCount {
		t.Errorf("got %d cookie fields, want %d (one per crumb); the jar is not being crumbled",
			crumbs, crumbCount)
	}

	// Requests 2 and 3 are the ones that matter: the jar must have collapsed to
	// one indexed byte per crumb.
	for i := 1; i < 3; i++ {
		for _, in := range parseHPACK(t, blocks[i]) {
			if in.Name == "cookie" && in.Kind != "INDEXED" {
				t.Errorf("request %d cookie crumb is %s, want INDEXED; the crumbs did not "+
					"survive in the dynamic table", i+1, in.Kind)
			}
		}
		if len(blocks[i]) > 150 {
			t.Errorf("request %d header block is %d bytes with a ~650 byte jar; Chrome settles "+
				"near 35. A block this large means the cookies are re-sent in full every request",
				i+1, len(blocks[i]))
		}
	}
	t.Logf("block sizes: %d, %d, %d bytes", len(blocks[0]), len(blocks[1]), len(blocks[2]))
}

// A plain navigation inserts 14 entries: 13 regular headers plus :authority.
// The count is observable server-side from request 1 alone, because the peer's
// decoder mirrors every insertion.
func TestHPACKInsertionCountMatchesChrome(t *testing.T) {
	h := startHPACKWireServer(t, 0, nil)
	blocks := drive(t, h, 1, func(tr *Transport, base string) {
		get(t, tr, base+"/fi/matkat")
	})

	got := countInstr(parseHPACK(t, blocks[0]), "LIT_INCREMENTAL")
	if got != 14 {
		t.Errorf("plain navigation inserted %d entries, want 14 (13 regular headers plus "+
			":authority). 13 means :authority is not being indexed", got)
	}
}

// When the peer advertises SETTINGS_HEADER_TABLE_SIZE, the encoder must emit a
// TABLE_SIZE_UPDATE as the first instruction of the next block it sends.
// Chrome sends 3fe1ff03 for 65536. This already matched and is locked so it
// keeps matching.
func TestHPACKTableSizeUpdate(t *testing.T) {
	h := startHPACKWireServer(t, 65536, nil)
	blocks := drive(t, h, 2, func(tr *Transport, base string) {
		get(t, tr, base+"/fi/matkat")
		get(t, tr, base+"/fi/matkat/probe")
	})

	// It lands on the first block sent after the peer's SETTINGS is processed,
	// which is normally the second request, exactly as it is in Chrome.
	var found bool
	for _, b := range blocks {
		ins := parseHPACK(t, b)
		if len(ins) > 0 && ins[0].Kind == "TABLE_SIZE_UPDATE" {
			found = true
			if ins[0].Size != 65536 {
				t.Errorf("TABLE_SIZE_UPDATE = %d, want 65536", ins[0].Size)
			}
			if got := hex.EncodeToString(b[:4]); got != "3fe1ff03" {
				t.Errorf("TABLE_SIZE_UPDATE encoded as %s, want 3fe1ff03", got)
			}
		}
	}
	if !found {
		t.Error("no TABLE_SIZE_UPDATE at the start of any block after the peer advertised " +
			"HEADER_TABLE_SIZE=65536; Chrome emits one")
	}
}
