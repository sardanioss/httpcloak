package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/net/http2/hpack"
)

// A configurable HTTP/2 server for wire-level locks.
//
// The older hpackWireServer in hpack_wire_test.go records HEADERS blocks and
// nothing else: it advertises no window, answers the instant it sees HEADERS,
// never acks a PING and never sends a mid-connection SETTINGS. Anything that
// posts a body over about four DATA frames stalls against it and then gets its
// stream ended underneath, which surfaces as an RST_STREAM rather than as a
// readable assertion failure.
//
// This one records every frame with the instant it arrived, honours the
// client's flow control in both directions, and can be told to drip a body,
// hold END_STREAM on a signal, or change its SETTINGS mid-connection. That
// covers the flow control, ping and HPACK table size locks from one place.
//
// Deliberately absent: any t.Skipf. A short capture is a failure, not a skip.

// ------------------------------------------------------------------- frames

const (
	frData         = 0x0
	frHeaders      = 0x1
	frRSTStream    = 0x3
	frSettings     = 0x4
	frPing         = 0x6
	frGoAway       = 0x7
	frWindowUpdate = 0x8
)

const (
	flAck        = 0x1
	flEndStream  = 0x1
	flEndHeaders = 0x4
	flPadded     = 0x8
	flPriority   = 0x20
)

// h2Frame is one frame as it arrived from the client, with the instant it was
// fully read. The timestamps are what the cadence locks assert on.
type h2Frame struct {
	Type     byte
	Flags    byte
	StreamID uint32
	Payload  []byte
	At       time.Time
}

func (f h2Frame) name() string {
	switch f.Type {
	case frData:
		return "DATA"
	case frHeaders:
		return "HEADERS"
	case frRSTStream:
		return "RST_STREAM"
	case frSettings:
		return "SETTINGS"
	case frPing:
		return "PING"
	case frGoAway:
		return "GOAWAY"
	case frWindowUpdate:
		return "WINDOW_UPDATE"
	}
	return fmt.Sprintf("type=%d", f.Type)
}

// increment reports the increment carried by a WINDOW_UPDATE frame.
func (f h2Frame) increment() uint32 {
	if f.Type != frWindowUpdate || len(f.Payload) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(f.Payload) & 0x7fffffff
}

// ------------------------------------------------------------------- config

type h2Setting struct {
	ID  uint16
	Val uint32
}

// h2Config shapes one server. The zero value is a server that answers every
// request immediately with a two-byte body, which is what most locks want.
type h2Config struct {
	// Settings advertised in the server preface. Nil sends an empty SETTINGS
	// frame, which is legal and means "every default".
	Settings []h2Setting

	// ConnWindowIncrement, when non-zero, is sent as a connection-level
	// WINDOW_UPDATE right after the preface, the way a real server grows its
	// receive window past the 65535 default.
	ConnWindowIncrement uint32

	// MidSettings sends further SETTINGS frames once the server has finished
	// responding to the given number of requests. Keyed on that count so a
	// lock can land them between two specific header blocks, and a LIST of
	// frames rather than one, because some encoder state only diverges when
	// two SETTINGS arrive with no header block encoded in between.
	MidSettings map[int][][]h2Setting

	// ReadToEndStream waits for the client's END_STREAM before responding, so
	// an upload is not cut short by an early reply.
	ReadToEndStream bool

	// GrantCredit emits WINDOW_UPDATE frames as request DATA arrives, at both
	// scopes, so an upload larger than the initial window can finish.
	GrantCredit bool

	// Body is the response body. Nil means "ok".
	Body []byte

	// SendContentLength puts a content-length on the response. Without it the
	// client sees an unknown length, which adds a trailing empty DATA frame.
	SendContentLength bool

	// Chunk splits the response body into frames of at most this many bytes,
	// each separated by ChunkDelay. Zero sends the body as one frame.
	Chunk      int
	ChunkDelay time.Duration

	// HoldEndStream, when non-nil, is waited on after the last body chunk and
	// before END_STREAM. That keeps the stream live while the client drains,
	// which is the only way to observe stream-scope behaviour on a body the
	// client has already consumed.
	HoldEndStream <-chan struct{}

	// OnRequest fires as soon as a HEADERS frame with END_HEADERS arrives,
	// before any response. Used to release a test barrier.
	OnRequest func(streamID uint32, n int)

	// OnBodyChunk fires after each response body chunk is written.
	OnBodyChunk func(streamID uint32, sent, total int)

	// AckPings answers client PINGs. Default true; set NoPingAck to suppress.
	NoPingAck bool
}

// ------------------------------------------------------------------- server

type h2Server struct {
	addr string
	cfg  h2Config

	mu       sync.Mutex
	frames   []h2Frame
	blocks   [][]byte
	conns    int
	firstErr error
}

// recorded returns every frame the client has sent so far.
func (s *h2Server) recorded() []h2Frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]h2Frame, len(s.frames))
	copy(out, s.frames)
	return out
}

// only returns the recorded frames of one type.
func (s *h2Server) only(typ byte) []h2Frame {
	var out []h2Frame
	for _, f := range s.recorded() {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

// headerBlocks returns every HEADERS payload with its block fragment isolated.
func (s *h2Server) headerBlocks() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.blocks))
	copy(out, s.blocks)
	return out
}

func (s *h2Server) connCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

// dump renders the recorded frames for a failure message.
func (s *h2Server) dump() string {
	var b strings.Builder
	frames := s.recorded()
	if len(frames) == 0 {
		return "(no frames recorded)"
	}
	base := frames[0].At
	for _, f := range frames {
		fmt.Fprintf(&b, "  %7.3fs %-13s stream=%d len=%d",
			f.At.Sub(base).Seconds(), f.name(), f.StreamID, len(f.Payload))
		if f.Type == frWindowUpdate {
			fmt.Fprintf(&b, " increment=%d", f.increment())
		}
		if f.Type == frPing {
			fmt.Fprintf(&b, " payload=%x ack=%v", f.Payload, f.Flags&flAck != 0)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func startH2Server(t *testing.T, cfg h2Config) *h2Server {
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

	s := &h2Server{addr: ln.Addr().String(), cfg: cfg}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns++
			s.mu.Unlock()
			go s.serve(c)
		}
	}()
	return s
}

func (s *h2Server) url(path string) string { return "https://" + s.addr + path }

// h2Conn is the per-connection state: the write side is serialised through wmu
// because the response goroutines and the read loop both write.
type h2Conn struct {
	s   *h2Server
	c   net.Conn
	wmu sync.Mutex

	// Outbound flow control, from the client's point of view. connWin is the
	// connection-level send window, streamWin the per-stream one. Overrunning
	// either makes the client kill the connection, which is the failure mode
	// that reads as an unrelated RST_STREAM.
	fcMu       sync.Mutex
	fcCond     *sync.Cond
	connWin    int64
	streamWin  map[uint32]int64
	initialWin int64
	closed     bool

	// maxFrame is the client's advertised SETTINGS_MAX_FRAME_SIZE. Every DATA
	// frame is clamped to it; overrunning it is a connection error the client
	// reports as "frame too large", which reads as an unrelated failure.
	maxFrame int

	// Inbound accounting for GrantCredit.
	recvSinceUpdate map[uint32]int
	connRecv        int

	doneMu    sync.Mutex
	responded int
}

func (s *h2Server) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(120 * time.Second))

	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if _, err := io.ReadFull(c, make([]byte, len(preface))); err != nil {
		return
	}

	hc := &h2Conn{
		s:               s,
		c:               c,
		connWin:         65535,
		streamWin:       map[uint32]int64{},
		initialWin:      65535,
		maxFrame:        16384,
		recvSinceUpdate: map[uint32]int{},
	}
	hc.fcCond = sync.NewCond(&hc.fcMu)
	defer func() {
		hc.fcMu.Lock()
		hc.closed = true
		hc.fcMu.Unlock()
		hc.fcCond.Broadcast()
	}()

	hc.writeSettings(s.cfg.Settings, 0)
	if inc := s.cfg.ConnWindowIncrement; inc > 0 {
		var p [4]byte
		binary.BigEndian.PutUint32(p[:], inc)
		hc.writeFrame(frWindowUpdate, 0, 0, p[:])
	}

	var (
		hdr      [9]byte
		reqCount int
	)
	for {
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		typ, flags := hdr[3], hdr[4]
		streamID := binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
		payload := make([]byte, n)
		if _, err := io.ReadFull(c, payload); err != nil {
			return
		}

		s.mu.Lock()
		s.frames = append(s.frames, h2Frame{
			Type: typ, Flags: flags, StreamID: streamID,
			Payload: payload, At: time.Now(),
		})
		s.mu.Unlock()

		switch typ {
		case frSettings:
			if flags&flAck == 0 {
				hc.applyClientSettings(payload)
				hc.writeFrame(frSettings, flAck, 0, nil)
			}

		case frWindowUpdate:
			inc := int64(binary.BigEndian.Uint32(payload) & 0x7fffffff)
			hc.fcMu.Lock()
			if streamID == 0 {
				hc.connWin += inc
			} else {
				hc.streamWin[streamID] += inc
			}
			hc.fcMu.Unlock()
			hc.fcCond.Broadcast()

		case frPing:
			if flags&flAck == 0 && !s.cfg.NoPingAck {
				hc.writeFrame(frPing, flAck, 0, payload)
			}

		case frHeaders:
			block := payload
			if flags&flPadded != 0 && len(block) > 0 {
				pad := int(block[0])
				block = block[1:]
				if pad <= len(block) {
					block = block[:len(block)-pad]
				}
			}
			if flags&flPriority != 0 && len(block) >= 5 {
				block = block[5:]
			}
			s.mu.Lock()
			s.blocks = append(s.blocks, append([]byte(nil), block...))
			s.mu.Unlock()

			hc.fcMu.Lock()
			if _, ok := hc.streamWin[streamID]; !ok {
				hc.streamWin[streamID] = hc.initialWin
			}
			hc.fcMu.Unlock()

			reqCount++
			if s.cfg.OnRequest != nil {
				s.cfg.OnRequest(streamID, reqCount)
			}
			if flags&flEndHeaders != 0 {
				if flags&flEndStream != 0 || !s.cfg.ReadToEndStream {
					go hc.respond(streamID)
				}
			}

		case frData:
			if s.cfg.GrantCredit {
				hc.grantCredit(streamID, n)
			}
			if flags&flEndStream != 0 && s.cfg.ReadToEndStream {
				go hc.respond(streamID)
			}

		case frGoAway:
			return
		}
	}
}

// applyClientSettings tracks the client's INITIAL_WINDOW_SIZE so the server's
// per-stream send window starts where the client says it does.
func (hc *h2Conn) applyClientSettings(p []byte) {
	for len(p) >= 6 {
		id := binary.BigEndian.Uint16(p)
		val := binary.BigEndian.Uint32(p[2:])
		switch id {
		case 0x4: // SETTINGS_INITIAL_WINDOW_SIZE
			hc.fcMu.Lock()
			delta := int64(val) - hc.initialWin
			hc.initialWin = int64(val)
			for id := range hc.streamWin {
				hc.streamWin[id] += delta
			}
			hc.fcMu.Unlock()
			hc.fcCond.Broadcast()
		case 0x5: // SETTINGS_MAX_FRAME_SIZE
			hc.fcMu.Lock()
			hc.maxFrame = int(val)
			hc.fcMu.Unlock()
		}
		p = p[6:]
	}
}

// grantCredit refunds inbound flow control as request DATA arrives, at both
// scopes, once half the default window has accumulated.
func (hc *h2Conn) grantCredit(streamID uint32, n int) {
	const threshold = 32 << 10
	hc.fcMu.Lock()
	hc.connRecv += n
	hc.recvSinceUpdate[streamID] += n
	conn, stream := 0, 0
	if hc.connRecv >= threshold {
		conn, hc.connRecv = hc.connRecv, 0
	}
	if hc.recvSinceUpdate[streamID] >= threshold {
		stream, hc.recvSinceUpdate[streamID] = hc.recvSinceUpdate[streamID], 0
	}
	hc.fcMu.Unlock()

	var p [4]byte
	if conn > 0 {
		binary.BigEndian.PutUint32(p[:], uint32(conn))
		hc.writeFrame(frWindowUpdate, 0, 0, p[:])
	}
	if stream > 0 {
		binary.BigEndian.PutUint32(p[:], uint32(stream))
		hc.writeFrame(frWindowUpdate, 0, streamID, p[:])
	}
}

func (hc *h2Conn) writeFrame(typ, flags byte, streamID uint32, payload []byte) {
	hdr := make([]byte, 9)
	hdr[0] = byte(len(payload) >> 16)
	hdr[1] = byte(len(payload) >> 8)
	hdr[2] = byte(len(payload))
	hdr[3], hdr[4] = typ, flags
	binary.BigEndian.PutUint32(hdr[5:], streamID)

	hc.wmu.Lock()
	defer hc.wmu.Unlock()
	hc.c.Write(hdr)
	if len(payload) > 0 {
		hc.c.Write(payload)
	}
}

func (hc *h2Conn) writeSettings(s []h2Setting, flags byte) {
	p := make([]byte, 0, len(s)*6)
	for _, kv := range s {
		var b [6]byte
		binary.BigEndian.PutUint16(b[0:], kv.ID)
		binary.BigEndian.PutUint32(b[2:], kv.Val)
		p = append(p, b[:]...)
	}
	hc.writeFrame(frSettings, flags, 0, p)
}

// takeCredit blocks until the client's windows allow at least one byte, then
// takes up to want bytes from both scopes. It returns 0 once the connection is
// gone.
func (hc *h2Conn) takeCredit(streamID uint32, want int) int {
	hc.fcMu.Lock()
	defer hc.fcMu.Unlock()
	for {
		if hc.closed {
			return 0
		}
		avail := hc.connWin
		if sw := hc.streamWin[streamID]; sw < avail {
			avail = sw
		}
		if avail > 0 {
			n := int64(want)
			if avail < n {
				n = avail
			}
			hc.connWin -= n
			hc.streamWin[streamID] -= n
			return int(n)
		}
		hc.fcCond.Wait()
	}
}

func (hc *h2Conn) respond(streamID uint32) {
	cfg := hc.s.cfg

	body := cfg.Body
	if body == nil {
		body = []byte("ok")
	}

	var buf strings.Builder
	enc := hpack.NewEncoder(&buf)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	if cfg.SendContentLength {
		enc.WriteField(hpack.HeaderField{
			Name:  "content-length",
			Value: strconv.Itoa(len(body)),
		})
	}
	hc.writeFrame(frHeaders, flEndHeaders, streamID, []byte(buf.String()))

	hc.fcMu.Lock()
	maxFrame := hc.maxFrame
	hc.fcMu.Unlock()

	chunk := cfg.Chunk
	if chunk <= 0 {
		chunk = len(body)
	}
	if chunk > maxFrame {
		chunk = maxFrame
	}
	if chunk <= 0 {
		chunk = 1
	}

	sent := 0
	for sent < len(body) {
		want := chunk
		if rem := len(body) - sent; rem < want {
			want = rem
		}
		n := hc.takeCredit(streamID, want)
		if n == 0 {
			return
		}
		hc.writeFrame(frData, 0, streamID, body[sent:sent+n])
		sent += n
		if cfg.OnBodyChunk != nil {
			cfg.OnBodyChunk(streamID, sent, len(body))
		}
		if cfg.ChunkDelay > 0 && sent < len(body) {
			time.Sleep(cfg.ChunkDelay)
		}
	}

	if cfg.HoldEndStream != nil {
		<-cfg.HoldEndStream
	}
	hc.writeFrame(frData, flEndStream, streamID, nil)

	hc.doneMu.Lock()
	hc.responded++
	n := hc.responded
	hc.doneMu.Unlock()

	for _, extra := range cfg.MidSettings[n] {
		hc.writeSettings(extra, 0)
	}
}
