package transport

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/h2build"
)

// Wire locks on the preface ping.
//
// Chromium, net/spdy/spdy_session.cc:
//
//	void SpdySession::MaybeSendPrefacePing() {
//	  if (ping_in_flight_ || check_ping_status_pending_ ||
//	      !enable_ping_based_connection_checking_) {
//	    return;
//	  }
//	  if (time_func_() > last_read_time_ + connection_at_risk_of_loss_time_)
//	    WritePingFrame(next_ping_id_, false);
//	}
//
// with kSpdyDefaultConnectionAtRiskOfLossSeconds = 10, next_ping_id_ starting
// at 1 and incrementing, and at most one in flight. Ten seconds is unusable in
// a test, so these drive it through the preset knob at 200 milliseconds.
//
// The frame ORDER is asymmetric on purpose and both halves are locked below.
// On the header path MaybeSendPrefacePing runs inside CreateHeaders, which the
// write loop calls only after it has already dequeued the HEADERS producer, so
// the HEADERS goes out and the ping follows. On the body path
// CreateDataBuffer calls it before EnqueueStreamWrite, so the ping goes first.
// Getting either backwards replaces the tell being closed with a new one.

const pingIdleMs = 200

// pingPreset registers a chrome-latest derivative with the ping thresholds
// scaled down so these stay sub-second.
func pingPreset(t *testing.T, name string, idleMs, hangMs int) string {
	t.Helper()
	registerPreset(t, name, fmt.Sprintf(
		`,"http2":{"preface_ping_idle_ms":%d,"preface_ping_hang_ms":%d}`, idleMs, hangMs))
	return name
}

func pingTransport(t *testing.T, preset string) *Transport {
	t.Helper()
	tr := NewTransport(preset)
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(tr.Close)
	return tr
}

func getOnce(t *testing.T, tr *Transport, url string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := tr.Do(ctx, &Request{Method: "GET", URL: url}); err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
}

// clientPings returns the non-ack PING frames the client sent.
func clientPings(s *h2Server) []h2Frame {
	var out []h2Frame
	for _, f := range s.only(frPing) {
		if f.Flags&flAck == 0 {
			out = append(out, f)
		}
	}
	return out
}

// --------------------------------------------------------------- the order

// HEADERS first, then the PING, and the payload is a counter rather than eight
// random bytes. A byte-entropy check on a random payload flags on one sample.
func TestPrefacePingFollowsHeaders(t *testing.T) {
	name := pingPreset(t, "ping-order", pingIdleMs, 5000)
	s := startH2Server(t, h2Config{})
	tr := pingTransport(t, name)

	getOnce(t, tr, s.url("/one"))
	time.Sleep(2 * pingIdleMs * time.Millisecond)
	getOnce(t, tr, s.url("/two"))
	time.Sleep(100 * time.Millisecond)

	frames := s.recorded()
	var headersSeen int
	for i, f := range frames {
		if f.Type != frHeaders {
			continue
		}
		headersSeen++
		if headersSeen != 2 {
			continue
		}
		// The next client frame after the second request's HEADERS.
		if i+1 >= len(frames) {
			t.Fatalf("nothing followed the second HEADERS; expected a PING\n%s", s.dump())
		}
		next := frames[i+1]
		if next.Type != frPing || next.Flags&flAck != 0 {
			t.Fatalf("frame after the second HEADERS is %s, want a non-ack PING\n%s",
				next.name(), s.dump())
		}
		if got := hex.EncodeToString(next.Payload); got != "0000000000000001" {
			t.Fatalf("first preface ping payload = %s, want 0000000000000001\n%s", got, s.dump())
		}
		return
	}
	t.Fatalf("only saw %d HEADERS frames\n%s", headersSeen, s.dump())
}

// -------------------------------------------------------------- the counter

// next_ping_id_ starts at 1 and increments per ping. Four requests, because
// request 1 on a fresh connection cannot cross the idle threshold by design.
// waitForPings waits until the server has recorded n client pings, or gives up.
//
// A fixed sleep here was the source of an intermittent failure. The last ping is
// written by the client just before the test looks for it, and under a loaded
// machine, which is exactly what a full parallel test run is, the write lands
// after the sleep expires. The test then reported one ping fewer than were
// actually sent, which reads like a real defect and is not one. Waiting for the
// condition rather than for a duration removes the race without slowing the
// passing case, which still returns in about the same time.
func waitForPings(t *testing.T, s *h2Server, n int) []h2Frame {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var pings []h2Frame
	for {
		pings = clientPings(s)
		if len(pings) >= n || time.Now().After(deadline) {
			return pings
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPrefacePingCounterIncrements(t *testing.T) {
	name := pingPreset(t, "ping-counter", pingIdleMs, 5000)
	s := startH2Server(t, h2Config{})
	tr := pingTransport(t, name)

	for i := 0; i < 4; i++ {
		if i > 0 {
			time.Sleep(2 * pingIdleMs * time.Millisecond)
		}
		getOnce(t, tr, s.url(fmt.Sprintf("/req%d", i)))
	}
	pings := waitForPings(t, s, 3)

	if n := s.connCount(); n != 1 {
		t.Fatalf("server saw %d connections, want 1; the pings below are not from one session\n%s",
			n, s.dump())
	}
	if len(pings) != 3 {
		t.Fatalf("got %d pings for 4 requests, want 3 (request 1 is on a fresh connection)\n%s",
			len(pings), s.dump())
	}
	for i, p := range pings {
		want := uint64(i + 1)
		if len(p.Payload) != 8 {
			t.Fatalf("ping %d payload is %d bytes, want 8", i, len(p.Payload))
		}
		if got := binary.BigEndian.Uint64(p.Payload); got != want {
			t.Fatalf("ping %d payload = %d, want %d (big-endian counter from 1)\n%s",
				i, got, want, s.dump())
		}
	}
}

// ------------------------------------------------------------ the thresholds

// Below the threshold, nothing. This is the half that stops the fix from
// emitting more pings than the browser rather than the right ones.
func TestNoPrefacePingBelowThreshold(t *testing.T) {
	name := pingPreset(t, "ping-below", 5000, 5000)
	s := startH2Server(t, h2Config{})
	tr := pingTransport(t, name)

	for i := 0; i < 4; i++ {
		getOnce(t, tr, s.url(fmt.Sprintf("/quick%d", i)))
	}
	time.Sleep(100 * time.Millisecond)

	if n := len(clientPings(s)); n != 0 {
		t.Fatalf("got %d pings across four back-to-back requests with a 5s threshold, want 0\n%s",
			n, s.dump())
	}
}

// No ping on the first request of a fresh connection, at any threshold. The
// zero value of the read clock is the Unix epoch, so a connection that forgets
// to seed it reads as idle by decades and pings on request one, which is
// louder than the silence it replaces.
func TestNoPrefacePingOnFreshConnection(t *testing.T) {
	name := pingPreset(t, "ping-fresh", 1, 5000) // 1ms: as eager as it gets
	s := startH2Server(t, h2Config{})
	tr := pingTransport(t, name)

	getOnce(t, tr, s.url("/first"))
	time.Sleep(100 * time.Millisecond)

	if n := len(clientPings(s)); n != 0 {
		t.Fatalf("got %d pings on the first request of a fresh connection, want 0\n%s",
			n, s.dump())
	}
}

// ------------------------------------------------------------- the body path

// slowBody yields its content in pieces with a pause between them, so the
// connection crosses the idle threshold in the middle of the request body.
type slowBody struct {
	pieces [][]byte
	pause  time.Duration
	i      int
}

func (b *slowBody) Read(p []byte) (int, error) {
	if b.i >= len(b.pieces) {
		return 0, io.EOF
	}
	if b.i > 0 {
		time.Sleep(b.pause)
	}
	n := copy(p, b.pieces[b.i])
	b.i++
	return n, nil
}

func (b *slowBody) Close() error { return nil }

// On the body path the ping comes BEFORE the DATA frame, because Chromium
// fires the check from CreateDataBuffer and enqueues the DATA afterwards.
func TestPrefacePingPrecedesData(t *testing.T) {
	name := pingPreset(t, "ping-data", pingIdleMs, 5000)
	s := startH2Server(t, h2Config{ReadToEndStream: true, GrantCredit: true})
	tr := pingTransport(t, name)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	body := &slowBody{
		pieces: [][]byte{[]byte("first"), []byte("second")},
		pause:  3 * pingIdleMs * time.Millisecond,
	}
	req, err := http.NewRequestWithContext(ctx, "POST", s.url("/upload"), body)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := tr.GetHTTP2Transport().RoundTrip(req)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	time.Sleep(100 * time.Millisecond)

	frames := s.recorded()
	for i, f := range frames {
		if f.Type != frPing || f.Flags&flAck != 0 {
			continue
		}
		if i+1 >= len(frames) || frames[i+1].Type != frData {
			t.Fatalf("the preface ping on the body path is not immediately "+
				"followed by a DATA frame\n%s", s.dump())
		}
		if i == 0 || frames[i-1].Type == frHeaders {
			t.Fatalf("the ping followed the HEADERS; this exchange was meant to "+
				"cross the threshold mid-body, not before it\n%s", s.dump())
		}
		return
	}
	t.Fatalf("no preface ping at all on a body that paused past the threshold\n%s", s.dump())
}

// -------------------------------------------------------- the frozen clock

// The read clock is stamped on every frame, outside the health-check timer's
// branch. Stamped inside it, the clock freezes at connection setup for every
// profile with the health check off, which is all of them: every reused
// connection then pings regardless of how recently the peer spoke, and the
// hang check evaluates against a frozen clock and tears down a healthy
// connection about one interval after its first reuse.
//
// None of the ping-count locks above catches that, because they never keep the
// peer talking. This one does, and it asserts connection survival rather than
// only the count.
func TestPrefacePingClockTracksReads(t *testing.T) {
	name := pingPreset(t, "ping-clock", pingIdleMs, 5000)
	s := startH2Server(t, h2Config{
		Body:              make([]byte, 20<<10),
		SendContentLength: true,
		Chunk:             1 << 10,
		ChunkDelay:        50 * time.Millisecond,
	})
	tr := pingTransport(t, name)

	// About a second of steady frames, five times the idle threshold, with no
	// gap in it longer than a quarter of the threshold.
	getOnce(t, tr, s.url("/drip"))
	// Straight into the next two requests, no pause.
	getOnce(t, tr, s.url("/second"))
	getOnce(t, tr, s.url("/third"))
	time.Sleep(100 * time.Millisecond)

	if n := len(clientPings(s)); n != 0 {
		t.Fatalf("got %d pings after a transfer that kept the peer talking throughout, want 0\n%s",
			n, s.dump())
	}
	if n := s.connCount(); n != 1 {
		t.Fatalf("server saw %d connections for three requests, want 1; a healthy "+
			"connection was torn down\n%s", n, s.dump())
	}
	if n := len(s.headerBlocks()); n != 3 {
		t.Fatalf("server saw %d header blocks, want 3", n)
	}
}

// ------------------------------------------------------- the retired RST ping

// A cancelled request sends a bare RST_STREAM. It used to carry a PING with
// eight random bytes, which no browser sends and which one sample is enough to
// tell apart from a counter. The threshold is pinned to zero here so a
// legitimate preface ping cannot appear and turn this red for the wrong reason.
func TestCancelledRequestSendsNoPing(t *testing.T) {
	name := pingPreset(t, "ping-cancel", 0, 0)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s := startH2Server(t, h2Config{HoldEndStream: release, Body: []byte("x")})
	tr := pingTransport(t, name)

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if _, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/hang")}); err == nil {
		t.Fatal("expected the request to be cancelled")
	}
	time.Sleep(200 * time.Millisecond)

	if n := len(clientPings(s)); n != 0 {
		t.Fatalf("got %d pings alongside a cancellation, want 0\n%s", n, s.dump())
	}
	var sawReset bool
	for _, f := range s.recorded() {
		if f.Type == frRSTStream {
			sawReset = true
		}
	}
	if !sawReset {
		t.Fatalf("no RST_STREAM for a cancelled request\n%s", s.dump())
	}
}

// The reset back-pressure counter used to be cleared by the ack to that PING.
// With the PING gone it is cleared by any frame from the peer, and it is
// bounded, so a run of cancellations cannot hold the connection at its
// concurrency limit for ever.
func TestCancellationsDoNotWedgeTheConnection(t *testing.T) {
	name := pingPreset(t, "ping-wedge", 0, 0)
	release := make(chan struct{})
	s := startH2Server(t, h2Config{HoldEndStream: release, Body: []byte("x")})
	tr := pingTransport(t, name)

	for i := 0; i < 8; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		tr.Do(ctx, &Request{Method: "GET", URL: s.url(fmt.Sprintf("/hang%d", i))})
		cancel()
	}
	close(release)

	// The same connection must still take work.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/after")}); err != nil {
		t.Fatalf("request after eight cancellations: %v\n%s", err, s.dump())
	}
	if n := s.connCount(); n != 1 {
		t.Fatalf("server saw %d connections, want 1; the first was abandoned\n%s", n, s.dump())
	}
}

// ------------------------------------------------------------ static locks

// The shipped defaults, asserted directly rather than inferred from the wire.
func TestPresetPingDefaults(t *testing.T) {
	for _, name := range []string{"chrome-latest", "chrome-151", "chrome-150"} {
		p := fingerprint.Get(name)
		if p == nil {
			t.Fatalf("preset %s missing", name)
			continue
		}
		if got := p.H2PrefacePingIdle(); got != 10*time.Second {
			t.Errorf("%s preface ping idle = %v, want 10s "+
				"(kSpdyDefaultConnectionAtRiskOfLossSeconds)", name, got)
		}
		if got := p.H2PrefacePingHang(); got != 10*time.Second {
			t.Errorf("%s preface ping hang = %v, want 10s (kHungIntervalSeconds)", name, got)
		}
		if got := p.H2IdlePing(); got != 0 {
			t.Errorf("%s health-check ping = %v, want 0; no browser sends a PING "+
				"with no frame behind it", name, got)
		}
	}

	// A profile that does not name the key sends nothing. This is what stops a
	// mirror preset, an example JSON preset or a user preset in the wild from
	// inheriting Chrome's ping.
	blank := &fingerprint.Preset{}
	if got := blank.H2PrefacePingIdle(); got != 0 {
		t.Errorf("a preset with no H2 config has preface ping idle = %v, want 0", got)
	}
}

// The health check reaches the transport as zero, asserted on the builder's
// return value rather than on the getter. Asserting the getter would pass
// whether or not the production path still reads it.
func TestBuiltTransportHasNoHealthCheckPing(t *testing.T) {
	h2 := h2build.Transport(h2build.Options{Preset: fingerprint.Get("chrome-latest")})
	if h2.ReadIdleTimeout != 0 {
		t.Errorf("ReadIdleTimeout = %v, want 0", h2.ReadIdleTimeout)
	}
	if h2.PrefacePingIdle != 10*time.Second {
		t.Errorf("PrefacePingIdle = %v, want 10s", h2.PrefacePingIdle)
	}

	// And a preset that asks for the health check still gets it, so the knob
	// is a knob and not a constant.
	registerPreset(t, "ping-healthcheck", `,"http2":{"idle_ping_ms":45000}`)
	h2 = h2build.Transport(h2build.Options{Preset: fingerprint.Get("ping-healthcheck")})
	if h2.ReadIdleTimeout != 45*time.Second {
		t.Errorf("ReadIdleTimeout with idle_ping_ms set = %v, want 45s", h2.ReadIdleTimeout)
	}
}

// The pool path and the transport path build the same transport from the same
// preset. They used to build it from two separate literals, and the pool one
// had lost HeaderPriorityFunc, so a Session never emitted the per-resource
// stream weights that a Transport did.
func TestBuiltTransportCarriesPriorityFunc(t *testing.T) {
	p := fingerprint.Get("chrome-latest")
	if !p.H2HasPriorityTable() {
		t.Skip("chrome-latest carries no priority table")
	}
	h2 := h2build.Transport(h2build.Options{Preset: p})
	if h2.HeaderPriorityFunc == nil {
		t.Fatal("HeaderPriorityFunc is nil for a preset with a priority table")
	}
}
