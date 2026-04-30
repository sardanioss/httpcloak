package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
)

// h2Capture is a single HEADERS frame captured by the local server. We
// capture only what's relevant to priority-table verification: the wire
// priority frame plus the request headers (so the test can correlate by
// :path or sec-fetch-dest).
type h2Capture struct {
	StreamID    uint32
	HasPriority bool
	Priority    http2.PriorityParam // wire-format weight (effective-1)
	Headers     map[string]string
	// HeaderOrder is the ordered list of header NAMES exactly as the client
	// emitted them on the wire. Tests that need to verify HPACK position
	// (vs. just presence/value) read this; existing tests stay on Headers.
	HeaderOrder []string
}

// h2CaptureServer is a minimal HTTP/2-over-TLS listener that uses the
// raw http2.Framer to read incoming HEADERS frames so the test can
// inspect the PRIORITY field that net/http abstracts away. After
// capturing, it sends a 200 OK response so the client side completes
// normally.
type h2CaptureServer struct {
	addr      string
	tlsConfig *stdtls.Config
	captures  chan h2Capture
	listener  net.Listener
	closed    chan struct{}
}

// startH2CaptureServer spins up the local server with a fresh self-signed
// EC certificate. Returns the server (use .addr for the URL host:port and
// .captures to receive frames) and a cleanup func.
func startH2CaptureServer(t *testing.T) *h2CaptureServer {
	t.Helper()

	// Self-signed P-256 cert valid for 1h, CN=localhost, SAN=127.0.0.1+localhost.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	derBytes, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("certgen: %v", err)
	}
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := stdtls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}

	cfg := &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   stdtls.VersionTLS12,
	}
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &h2CaptureServer{
		addr:      ln.Addr().String(),
		tlsConfig: cfg,
		captures:  make(chan h2Capture, 64),
		listener:  ln,
		closed:    make(chan struct{}),
	}

	go s.acceptLoop(t)
	t.Cleanup(func() {
		close(s.closed)
		_ = ln.Close()
	})
	return s
}

func (s *h2CaptureServer) acceptLoop(t *testing.T) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				return
			}
		}
		go s.handleConn(t, conn)
	}
}

const h2PrefaceStr = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func (s *h2CaptureServer) handleConn(t *testing.T, c net.Conn) {
	defer c.Close()

	tlsConn, ok := c.(*stdtls.Conn)
	if !ok {
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	// Read connection preface.
	preface := make([]byte, len(h2PrefaceStr))
	if _, err := io.ReadFull(c, preface); err != nil {
		return
	}
	if string(preface) != h2PrefaceStr {
		return
	}

	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	// Send our SETTINGS first (clients buffer pending requests until they
	// see server SETTINGS).
	if err := fr.WriteSettings(); err != nil {
		return
	}

	enc := hpack.NewEncoder(nil)
	var encBuf strings.Builder
	enc = hpack.NewEncoder(&encBuf)

	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.WindowUpdateFrame:
			// ignore
		case *http2.MetaHeadersFrame:
			cap := h2Capture{
				StreamID:    f.StreamID,
				HasPriority: f.HasPriority(),
				Priority:    f.Priority,
				Headers:     map[string]string{},
				HeaderOrder: make([]string, 0, len(f.Fields)),
			}
			for _, hf := range f.Fields {
				cap.Headers[hf.Name] = hf.Value
				cap.HeaderOrder = append(cap.HeaderOrder, hf.Name)
			}
			select {
			case s.captures <- cap:
			default:
				// channel full — test isn't reading; drop to avoid blocking.
			}

			// Send a 200 response so client RoundTrip returns.
			encBuf.Reset()
			_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			_ = enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "0"})
			_ = fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      f.StreamID,
				BlockFragment: []byte(encBuf.String()),
				EndHeaders:    true,
				EndStream:     true,
			})
		case *http2.PingFrame:
			if !f.IsAck() {
				_ = fr.WritePing(true, f.Data)
			}
		case *http2.GoAwayFrame:
			return
		}
	}
}

// fireGet sends a GET to the capture server using httpcloak's HTTP2Transport
// with the given preset and explicit Sec-Fetch-Dest. Returns the captured
// HEADERS frame (caller must drain other captures if any).
//
// applyPresetHeaders is called explicitly to mirror the higher-level
// transport wrapper's behavior: it sets the preset's static headers,
// runs the sniff/coerce pass, and applies the per-dest priority table.
// Without this, the priority HTTP header would never be injected.
func fireGet(t *testing.T, srv *h2CaptureServer, preset *fingerprint.Preset, secFetchDest string) h2Capture {
	t.Helper()

	tr := NewHTTP2Transport(preset, dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	host, port, _ := net.SplitHostPort(srv.addr)
	url := "https://" + net.JoinHostPort(host, port) + "/r/" + secFetchDest
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	userHeaders := map[string][]string{}
	if secFetchDest != "" {
		req.Header.Set("Sec-Fetch-Dest", secFetchDest)
		userHeaders["Sec-Fetch-Dest"] = []string{secFetchDest}
	}

	// Mirror what the higher-level Transport.RoundTrip wrapper does on the
	// httpcloak side before handing the *http.Request to HTTP2Transport.
	applyPresetHeaders(req, preset, nil, nil, false, "h2", userHeaders)

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	select {
	case c := <-srv.captures:
		return c
	case <-time.After(3 * time.Second):
		t.Fatalf("no capture within 3s")
		return h2Capture{}
	}
}

// TestPriorityTable_WireEmission_Chrome147 is the load-bearing integration
// test: it verifies that for every dest in the chrome-147-windows priority
// table, the actual H2 PRIORITY frame on the wire matches the captured
// Chrome 147 weight + exclusive bit.
func TestPriorityTable_WireEmission_Chrome147(t *testing.T) {
	preset := fingerprint.Get("chrome-147-windows")
	if preset == nil {
		t.Skip("chrome-147-windows preset unavailable")
	}

	cases := []struct {
		dest          string
		wantWireWt    uint8 // wire weight (effective-1)
		wantExclusive bool
	}{
		{"document", 255, true}, // u=0 → 256 → wire 255
		{"iframe", 255, true},
		{"object", 255, true},
		{"embed", 255, true},
		{"style", 255, true},
		{"script", 219, true},   // u=1 → 220 → 219
		{"font", 219, true},     // u=1 → 220
		{"empty", 219, true},    // u=1 → 220
		{"manifest", 182, true}, // u=2 → 183 → 182
		{"image", 182, true},    // u=2 → 183
		{"video", 146, true},    // u=3 → 147 → 146
		{"audio", 146, true},
		{"track", 146, true},
		{"worker", 109, true}, // u=4 → 110 → 109
	}

	for _, tc := range cases {
		t.Run(tc.dest, func(t *testing.T) {
			srv := startH2CaptureServer(t)
			c := fireGet(t, srv, preset, tc.dest)

			if !c.HasPriority {
				t.Fatalf("dest=%s: HasPriority=false on wire frame", tc.dest)
			}
			if c.Priority.Weight != tc.wantWireWt {
				t.Errorf("dest=%s: wire weight = %d, want %d (effective want %d)",
					tc.dest, c.Priority.Weight, tc.wantWireWt, tc.wantWireWt+1)
			}
			if c.Priority.Exclusive != tc.wantExclusive {
				t.Errorf("dest=%s: exclusive = %v, want %v",
					tc.dest, c.Priority.Exclusive, tc.wantExclusive)
			}
			if c.Priority.StreamDep != 0 {
				t.Errorf("dest=%s: StreamDep = %d, want 0", tc.dest, c.Priority.StreamDep)
			}
		})
	}
}

// TestPriorityTable_WireEmission_LegacyChromeInheritsDefault verifies
// that legacy Chrome presets (no explicit PriorityTable) inherit the
// package default and emit per-dest priorities matching chrome-147.
// This is the "default for all RFC 7540 profiles" contract.
func TestPriorityTable_WireEmission_LegacyChromeInheritsDefault(t *testing.T) {
	preset := fingerprint.Get("chrome-146-windows")
	if preset == nil {
		t.Skip("chrome-146-windows preset unavailable")
	}
	if !preset.H2HasPriorityTable() {
		t.Fatalf("chrome-146-windows: H2HasPriorityTable=false, want true (must inherit default)")
	}

	cases := []struct {
		dest       string
		wantWireWt uint8
	}{
		{"document", 255}, // u=0 → 256 → wire 255
		{"image", 182},    // u=2 → 183
		{"empty", 219},    // u=1 → 220
		{"script", 219},   // u=1 → 220
	}
	for _, tc := range cases {
		t.Run(tc.dest, func(t *testing.T) {
			srv := startH2CaptureServer(t)
			c := fireGet(t, srv, preset, tc.dest)

			if !c.HasPriority {
				t.Fatalf("dest=%s: HasPriority=false (chrome-146 should inherit default table)", tc.dest)
			}
			if c.Priority.Weight != tc.wantWireWt {
				t.Errorf("dest=%s: wire weight = %d, want %d (inherited default)",
					tc.dest, c.Priority.Weight, tc.wantWireWt)
			}
			if !c.Priority.Exclusive {
				t.Errorf("dest=%s: exclusive=false, want true", tc.dest)
			}
		})
	}
}

// TestPriorityTable_WireEmission_NoRFC7540PresetSingleWeight verifies the
// other side of the contract: presets that opt out of RFC 7540 (Safari,
// iOS Chrome, iOS Safari — all carry NoRFC7540Priorities=true) keep the
// legacy single-weight code path. The default table never applies to
// them, because they don't emit per-resource RFC 7540 priorities at all.
func TestPriorityTable_WireEmission_NoRFC7540PresetSingleWeight(t *testing.T) {
	preset := fingerprint.Get("chrome-148-ios")
	if preset == nil {
		t.Skip("chrome-148-ios preset unavailable")
	}
	if !preset.HTTP2Settings.NoRFC7540Priorities {
		t.Fatalf("chrome-148-ios: NoRFC7540Priorities=false, expected true")
	}
	if preset.H2HasPriorityTable() {
		t.Fatalf("chrome-148-ios: H2HasPriorityTable=true, want false (NoRFC7540 must opt out)")
	}

	staticWeight := uint8(preset.HTTP2Settings.StreamWeight)
	if preset.HTTP2Settings.StreamWeight > 0 {
		staticWeight = uint8(preset.HTTP2Settings.StreamWeight - 1)
	}

	for _, dest := range []string{"document", "image", "empty", "script"} {
		t.Run(dest, func(t *testing.T) {
			srv := startH2CaptureServer(t)
			c := fireGet(t, srv, preset, dest)

			// NoRFC7540 presets either carry no priority frame OR carry
			// the static StreamWeight (depends on whether the preset
			// sets StreamWeight=0). Both are accepted — what we lock is
			// "the same thing across every dest".
			if c.HasPriority && c.Priority.Weight != staticWeight {
				t.Errorf("dest=%s: wire weight = %d, want %d (static, NoRFC7540 must not vary by dest)",
					dest, c.Priority.Weight, staticWeight)
			}
		})
	}
}

// TestPriorityTable_WireEmission_UnknownDestFallsBack verifies that when a
// chrome-147 preset receives a Sec-Fetch-Dest it doesn't know about, the
// transport falls back to the static StreamWeight. This means the dest
// table is purely additive: weird dests never break things.
func TestPriorityTable_WireEmission_UnknownDestFallsBack(t *testing.T) {
	preset := fingerprint.Get("chrome-147-windows")
	if preset == nil {
		t.Skip("chrome-147-windows preset unavailable")
	}

	staticWeight := uint8(preset.HTTP2Settings.StreamWeight - 1)
	staticExcl := preset.HTTP2Settings.StreamExclusive

	srv := startH2CaptureServer(t)
	c := fireGet(t, srv, preset, "made-up-dest-xyz")

	if !c.HasPriority {
		t.Fatalf("HasPriority=false (should fall back to static, not omit)")
	}
	if c.Priority.Weight != staticWeight {
		t.Errorf("unknown dest: wire weight = %d, want %d (fall back to static)",
			c.Priority.Weight, staticWeight)
	}
	if c.Priority.Exclusive != staticExcl {
		t.Errorf("unknown dest: exclusive = %v, want %v (fall back)",
			c.Priority.Exclusive, staticExcl)
	}
}

// TestPriorityTable_WireEmission_PerRequestDistinctOnSameConn fires several
// requests with different Sec-Fetch-Dest on the SAME connection and
// verifies each gets a distinct wire priority. This is the architectural
// claim: HeaderPriorityFunc is called per-request even when streams share
// a ClientConn.
func TestPriorityTable_WireEmission_PerRequestDistinctOnSameConn(t *testing.T) {
	preset := fingerprint.Get("chrome-147-windows")
	if preset == nil {
		t.Skip("chrome-147-windows preset unavailable")
	}

	srv := startH2CaptureServer(t)

	// Single Transport — connection pooling means all three requests
	// reuse the same H2 ClientConn. The PriorityTable lookup must
	// resolve per-request, not once at conn creation.
	tr := NewHTTP2Transport(preset, dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	host, port, _ := net.SplitHostPort(srv.addr)
	dests := []string{"document", "image", "empty"}
	wantWires := map[string]uint8{
		"document": 255, // u=0 → 256 → wire 255
		"image":    182, // u=2 → 183 → wire 182
		"empty":    219, // u=1 → 220 → wire 219
	}

	got := map[string]h2Capture{}
	for _, d := range dests {
		req, _ := http.NewRequest("GET", "https://"+net.JoinHostPort(host, port)+"/r/"+d, nil)
		req.Header.Set("Sec-Fetch-Dest", d)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("dest=%s RoundTrip: %v", d, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		select {
		case c := <-srv.captures:
			got[d] = c
		case <-time.After(3 * time.Second):
			t.Fatalf("dest=%s: no capture within 3s", d)
		}
	}

	for d, c := range got {
		if !c.HasPriority {
			t.Errorf("dest=%s: HasPriority=false", d)
			continue
		}
		if c.Priority.Weight != wantWires[d] {
			t.Errorf("dest=%s: wire weight = %d, want %d", d, c.Priority.Weight, wantWires[d])
		}
	}

	// Sanity: all three captures should have come over the same connection
	// (different stream IDs on the same ClientConn). We can't directly
	// check the underlying conn from the test, but if connection pooling
	// is working the second & third RoundTrips would have observed the
	// peer's settings already (no fresh handshake delay). The presence
	// of distinct stream IDs (1, 3, 5...) implies same-conn reuse.
	streamIDs := map[uint32]bool{}
	for _, c := range got {
		streamIDs[c.StreamID] = true
	}
	if len(streamIDs) != 3 {
		t.Errorf("captures had %d distinct stream IDs, want 3", len(streamIDs))
	}
}

// TestPriorityTable_WireEmission_PriorityHeaderInjection verifies the
// RFC 9218 priority: HTTP header is set per the table even though the
// preset's static "priority" header is "u=0, i". Each dest must surface
// its own priority header on the wire.
//
// (This is a separate concern from the H2 PRIORITY frame above — the
// HTTP header lives in the request headers map; the frame lives in the
// HEADERS frame metadata.)
func TestPriorityTable_WireEmission_PriorityHeaderInjection(t *testing.T) {
	preset := fingerprint.Get("chrome-147-windows")
	if preset == nil {
		t.Skip("chrome-147-windows preset unavailable")
	}

	cases := []struct {
		dest       string
		wantHeader string // empty → header must NOT be present
	}{
		{"document", "u=0, i"},
		{"style", "u=0"},
		{"manifest", "u=2"},
		{"script", "u=1"},
		{"image", "u=2, i"},
		{"empty", "u=1, i"},
		{"video", "i"},
		{"track", "i"},
		{"worker", "u=4, i"},
	}

	for _, tc := range cases {
		t.Run(tc.dest, func(t *testing.T) {
			srv := startH2CaptureServer(t)
			c := fireGet(t, srv, preset, tc.dest)

			got, present := c.Headers["priority"]
			if tc.wantHeader == "" {
				if present {
					t.Errorf("dest=%s: priority header = %q, want absent", tc.dest, got)
				}
				return
			}
			if !present {
				t.Errorf("dest=%s: priority header absent, want %q", tc.dest, tc.wantHeader)
				return
			}
			if got != tc.wantHeader {
				t.Errorf("dest=%s: priority header = %q, want %q", tc.dest, got, tc.wantHeader)
			}
		})
	}
}

// TestPriorityTable_WireEmission_ConcurrentRequests stresses the per-request
// callback under genuine concurrency. With -race, this catches any data race
// in the closure or the fork's HeaderPriorityFunc dispatch.
func TestPriorityTable_WireEmission_ConcurrentRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrency stress in short mode")
	}
	preset := fingerprint.Get("chrome-147-windows")
	if preset == nil {
		t.Skip("chrome-147-windows preset unavailable")
	}

	srv := startH2CaptureServer(t)
	tr := NewHTTP2Transport(preset, dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	host, port, _ := net.SplitHostPort(srv.addr)
	const goroutines = 16
	const perGoroutine = 4
	dests := []string{"document", "image", "empty", "script", "font", "style", "manifest", "worker"}
	wantWires := map[string]uint8{
		"document": 255, "image": 182, "empty": 219, "script": 219,
		"font": 219, "style": 255, "manifest": 182, "worker": 109,
	}

	var wg sync.WaitGroup
	errs := make(chan error, goroutines*perGoroutine)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				d := dests[(g+i)%len(dests)]
				req, _ := http.NewRequest("GET", "https://"+net.JoinHostPort(host, port)+"/r/"+d, nil)
				req.Header.Set("Sec-Fetch-Dest", d)
				resp, err := tr.RoundTrip(req)
				if err != nil {
					errs <- err
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("concurrent RoundTrip error: %v", e)
	}

	// Drain captures and verify each dest produced its expected wire
	// weight at least once.
	seenByDest := map[string]uint8{}
	timeout := time.After(5 * time.Second)
collect:
	for i := 0; i < goroutines*perGoroutine; i++ {
		select {
		case c := <-srv.captures:
			d, ok := c.Headers[":path"]
			if !ok {
				continue
			}
			// :path is "/r/<dest>"
			if !strings.HasPrefix(d, "/r/") {
				continue
			}
			dest := d[3:]
			if c.HasPriority {
				seenByDest[dest] = c.Priority.Weight
			}
		case <-timeout:
			break collect
		}
	}
	for dest, want := range wantWires {
		if got, ok := seenByDest[dest]; ok && got != want {
			t.Errorf("dest=%s observed wire weight = %d, want %d", dest, got, want)
		}
	}
}
