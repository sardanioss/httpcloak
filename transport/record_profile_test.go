package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	tls "github.com/sardanioss/utls"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// recordingConn parses TLS record headers off the raw client stream before the
// TLS layer sees them. Record type and length travel in cleartext, so this is
// exactly what a server, or anything on the path, reads for free.
type recordingConn struct {
	net.Conn
	mu   sync.Mutex
	recs []int
	buf  []byte
}

func (r *recordingConn) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.mu.Lock()
		r.buf = append(r.buf, p[:n]...)
		for len(r.buf) >= 5 {
			l := int(binary.BigEndian.Uint16(r.buf[3:5]))
			if len(r.buf) < 5+l {
				break
			}
			if r.buf[0] == 0x17 { // application_data
				r.recs = append(r.recs, 5+l)
			}
			r.buf = r.buf[5+l:]
		}
		r.mu.Unlock()
	}
	return n, err
}

func (r *recordingConn) snapshot() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.recs...)
}

func runRecordProbe(t *testing.T, preset string) ([]int, []int) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2"},
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	var rec *recordingConn
	var dataFrames []int
	done := make(chan struct{})

	go func() {
		defer close(done)
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		rec = &recordingConn{Conn: raw}
		c := tls.Server(rec, cfg)
		c.SetDeadline(time.Now().Add(30 * time.Second))
		if err := c.Handshake(); err != nil {
			return
		}
		io.ReadFull(c, make([]byte, 24)) // preface
		// SETTINGS with a large MAX_FRAME_SIZE: Chrome ignores it, Go honours it.
		var s bytes.Buffer
		binary.Write(&s, binary.BigEndian, uint16(5))
		binary.Write(&s, binary.BigEndian, uint32(1<<20))
		writeWireFrame(c, 0x4, 0x0, 0, s.Bytes())
		writeWireFrame(c, 0x4, 0x1, 0, nil)

		hdr := make([]byte, 9)
		for {
			if _, err := io.ReadFull(c, hdr); err != nil {
				return
			}
			ln := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
			payload := make([]byte, ln)
			io.ReadFull(c, payload)
			if hdr[3] == 0x0 { // DATA
				dataFrames = append(dataFrames, ln)
			}
			if hdr[3] == 0x1 && hdr[4]&0x1 == 0 {
				continue
			}
			if hdr[3] == 0x0 && hdr[4]&0x1 == 1 {
				resp := []byte{0x88}
				streamID := binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff
				writeWireFrame(c, 0x1, 0x4, streamID, resp)
				writeWireFrame(c, 0x0, 0x1, streamID, []byte("ok"))
				return
			}
		}
	}()

	tr := NewTransport(preset)
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	body := bytes.Repeat([]byte("x"), 140*1024)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tr.Do(ctx, &Request{Method: "POST", URL: "https://" + ln.Addr().String() + "/u", Body: body})
	<-done

	return dataFrames, rec.snapshot()
}

// Two divergences that had to be fixed together, because fixing either alone
// makes the profile worse.
//
// Go ramps its TLS record sizes (1186*N until 128KB) to trade latency for
// throughput. No browser does that, and an arithmetic ramp identifies the TLS
// stack lineage rather than merely saying "not a browser".
//
// Separately, writing a full 16384-byte DATA payload makes the frame 16393
// bytes with its 9-byte header, which the record layer splits into one
// full-size record plus a tiny tail. Measured before this fix, with the ramp
// already disabled:
//
//	records  16406, 31, 16406, 31, 16406, 31, 16406, 30    <- tail per frame
//	frames   16384, 16384, 16384, 16383
//
// and after:
//
//	records  16406, 16406, 16406, 16406                    <- one per frame
//	frames   16375, 16375, 16375, 16375
//
// Chromium caps at 16375, which is 16384 minus the frame header, precisely so
// header plus payload occupy exactly one record.
//
// The server here advertises SETTINGS_MAX_FRAME_SIZE of 1 MiB. Chromium ignores
// that value entirely; its chunk size is a compile-time constant. A client that
// honours it and sends one enormous DATA frame has answered a one-request probe.
func TestDataFramesAndRecordsMatchChrome(t *testing.T) {
	dataFrames, recs := runRecordProbe(t, "chrome-latest")

	if len(dataFrames) < 2 {
		t.Skipf("environment sent only %d DATA frames", len(dataFrames))
	}
	// Every full frame is Chrome's size, and the peer's 1 MiB advertisement is
	// ignored.
	for i, n := range dataFrames[:len(dataFrames)-1] {
		if n != 16375 {
			t.Errorf("DATA frame %d payload = %d, want 16375. Either the cap is not "+
				"wired, or the peer's SETTINGS_MAX_FRAME_SIZE is being honoured", i, n)
		}
	}
	// No short record wedged between two full ones. That pattern is the frame
	// spilling past the record boundary, and it repeats forever.
	for i := 1; i < len(recs)-1; i++ {
		if recs[i] < 100 && recs[i-1] > 16000 && recs[i+1] > 16000 {
			t.Errorf("record %d is %d bytes between two full records (%v); a DATA frame "+
				"is spilling past the record boundary", i, recs[i], recs[max(0, i-2):min(len(recs), i+3)])
		}
	}
	// And no arithmetic ramp. With dynamic sizing on, the first records of a
	// large write climb 1186 bytes at a time (1203, 2389, 3575, ...), so the
	// giveaway is mid-sized records that are neither a small control frame nor
	// a full one. With it off every record is one or the other.
	//
	// Checking only that the FULL records agree in size is not enough: once the
	// frame payload is clamped the ramp still produces its mid-sized steps while
	// every full record remains identical, so that version of this assertion
	// passes with the fix reverted.
	// The ramp is payloadBytes*(packetsSent+1) with payloadBytes around 1186, so
	// with the flag removed the body records climb in an arithmetic progression.
	// Measured with it removed, this test reports:
	//
	//	3580 4766 5952 2174 9510 6918 11882 4546 14254 2174
	//
	// every one of them 1186k plus overhead. That progression is the signature:
	// it does not merely say "not a browser", it names the TLS stack.
	var mid []int
	for _, r := range recs {
		if r >= 500 && r < 16000 {
			mid = append(mid, r)
		}
	}
	if len(mid) > 0 {
		t.Errorf("records of intermediate size %v; Go's dynamic record sizing ramp is "+
			"still on. Full profile: %v", mid, recs)
	}
	var full []int
	for _, r := range recs {
		if r > 16000 {
			full = append(full, r)
		}
	}
	for i := 1; i < len(full); i++ {
		if full[i] != full[0] {
			t.Errorf("full records vary in size (%v)", full)
			break
		}
	}
}

// Chromium caps DATA frames at 16375. Firefox and the WebKit family do not,
// they use the full 16384. Applying Chrome's cap everywhere would fix one tell
// by handing Chrome's framing to every other profile, so the value is derived
// from the client family and this pins that.
func TestDataFrameCapIsPerFamily(t *testing.T) {
	for _, tc := range []struct {
		preset string
		want   uint32
	}{
		{"chrome-latest", 16375},
		{"chrome-146-windows", 16375},
		{"safari-18", 0},
		{"firefox-148", 0},
	} {
		p := fingerprint.Get(tc.preset)
		if p == nil {
			continue
		}
		if got := p.H2DataFrameMaxSize(); got != tc.want {
			t.Errorf("%s: H2DataFrameMaxSize = %d, want %d", tc.preset, got, tc.want)
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Second layer for the same flag, at the config rather than the wire.
//
// The wire test above covers the H2 path. This one covers every TCP path,
// including H1 and the pool, without needing an exchange on each. A new
// transport that forgets the flag is how this regresses, and that would not
// show up in a test that only drives H2.
func TestEveryTCPTLSConfigDisablesDynamicRecordSizing(t *testing.T) {
	// Only TCP paths. QUIC does its own framing and has no TLS record layer.
	for _, f := range []string{
		"http2_transport.go",
		"http1_transport.go",
		"../pool/pool.go",
	} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		body := string(src)
		configs := strings.Count(body, "utls.Config{")
		flags := strings.Count(body, "DynamicRecordSizingDisabled")
		if configs == 0 {
			t.Errorf("%s: no utls.Config literal found; this test is watching the wrong file", f)
			continue
		}
		if flags < configs {
			t.Errorf("%s has %d utls.Config literals but only %d set "+
				"DynamicRecordSizingDisabled. Go's record ramp identifies the TLS stack "+
				"lineage and no browser produces it", f, configs, flags)
		}
	}
}
