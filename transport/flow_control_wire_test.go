package transport

import (
	"context"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// Wire locks on inbound flow control.
//
// The model these assert is Chromium's, from net/spdy/spdy_stream.cc:
//
//	unacked_recv_window_bytes_ += delta_window_size;
//	const base::TimeDelta elapsed = base::TimeTicks::Now() - last_recv_window_update_;
//	if (unacked_recv_window_bytes_ > max_recv_window_size_ / 2 ||
//	    elapsed >= session_->TimeToBufferSmallWindowUpdates()) {
//
// with kDefaultTimeToBufferSmallWindowUpdates = 5 seconds. Two arms, no third.
// Go's stack carries a third, "this update at least doubles the peer's
// window", and carries no timer at all, so it produces both a silence Chrome
// never produces and a burst Chrome never produces.
//
// Note which client entrypoint each lock uses. Transport.Do buffers the whole
// response through readBodyOptimized before it returns, so the caller can
// never be the slow reader and the byte arm can never be observed through it.
// The streaming path (client.DoStream, session.RequestStream, and
// HTTP2Transport.RoundTrip underneath them) is the one that exposes it.

// inflowBufferInterval mirrors inflowSmallUpdateInterval in the net fork,
// which is unexported. Chromium's kDefaultTimeToBufferSmallWindowUpdates.
const inflowBufferInterval = 5 * time.Second

// streamRecvWindow is the window each of these locks is measured against.
func streamRecvWindow(t *testing.T) uint32 {
	t.Helper()
	p := fingerprint.Get("chrome-latest")
	if p == nil {
		t.Fatal("chrome-latest preset missing")
	}
	return p.HTTP2Settings.InitialWindowSize
}

// afterFirstRequest returns the WINDOW_UPDATE frames that arrived after the
// first HEADERS, which excludes the connection-level preface update.
func afterFirstRequest(frames []h2Frame) []h2Frame {
	seenHeaders := false
	var out []h2Frame
	for _, f := range frames {
		if f.Type == frHeaders {
			seenHeaders = true
			continue
		}
		if seenHeaders && f.Type == frWindowUpdate {
			out = append(out, f)
		}
	}
	return out
}

func split(frames []h2Frame) (conn, stream []h2Frame) {
	for _, f := range frames {
		if f.StreamID == 0 {
			conn = append(conn, f)
		} else {
			stream = append(stream, f)
		}
	}
	return
}

// ------------------------------------------------------------- the timed arm

// A body that arrives slowly must still produce WINDOW_UPDATEs on a roughly
// five second cadence, at both scopes. Without the timed arm a client that
// consumes slowly emits nothing at all for the life of the transfer, which is
// the state Chromium's own comment describes as making "servers consider the
// connection or stream idle".
//
// 32 KB in 1 KB pieces, half a second apart: sixteen seconds of transfer, far
// below the byte threshold at every point, so every update here can only have
// come from the timer.
func TestFlowControlTimedArm(t *testing.T) {
	if testing.Short() {
		t.Skip("16 second transfer")
	}
	s := startH2Server(t, h2Config{
		Settings:            []h2Setting{{ID: 0x4, Val: 1 << 20}, {ID: 0x5, Val: 16384}},
		ConnWindowIncrement: 1 << 20,
		Body:                make([]byte, 32<<10),
		SendContentLength:   true,
		Chunk:               1 << 10,
		ChunkDelay:          500 * time.Millisecond,
	})

	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/drip")}); err != nil {
		t.Fatalf("request: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	conn, stream := split(afterFirstRequest(s.recorded()))
	if len(conn) < 2 || len(stream) < 2 {
		t.Fatalf("got %d connection and %d stream WINDOW_UPDATEs over a 16s transfer, want at least 2 of each;\n%s",
			len(conn), len(stream), s.dump())
	}

	// Every one of them must be below the byte threshold, or the transfer was
	// not slow enough and this is not testing the timer.
	half := streamRecvWindow(t) / 2
	for _, f := range append(append([]h2Frame{}, conn...), stream...) {
		if f.increment() > half {
			t.Fatalf("WINDOW_UPDATE increment %d is above half the window (%d); "+
				"this transfer was meant to stay under the byte arm\n%s",
				f.increment(), half, s.dump())
		}
	}

	// The cadence itself. Chromium buffers for five seconds; allow for a slow
	// machine on either side but not for a different mechanism.
	for i := 1; i < len(conn); i++ {
		gap := conn[i].At.Sub(conn[i-1].At)
		if gap < 4*time.Second || gap > 7*time.Second {
			t.Fatalf("connection WINDOW_UPDATEs %d and %d are %v apart, want 4s to 7s\n%s",
				i-1, i, gap, s.dump())
		}
	}
}

// ------------------------------------------------------------- the byte arm

// On the streaming path, where the caller really can read more slowly than the
// peer sends, no update may go out below half the window unless the timer put
// it there.
//
// The old doubling clause fires as soon as the unacknowledged count reaches
// the window the peer has left, which on an exhausted window means every
// single read gets its own frame. Reverted, this exchange emits a 4096 byte
// WINDOW_UPDATE, which no browser produces.
func TestFlowControlByteArmNeverBelowHalf(t *testing.T) {
	s := startH2Server(t, h2Config{
		Settings:            []h2Setting{{ID: 0x4, Val: 1 << 20}, {ID: 0x5, Val: 16384}},
		ConnWindowIncrement: 16 << 20,
		Body:                make([]byte, 8<<20),
		SendContentLength:   true,
	})

	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", s.url("/stream"), nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := tr.GetHTTP2Transport().RoundTrip(req)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}

	// Let the peer spend the whole window before reading a byte, so the old
	// clause has the exhausted window it needs.
	time.Sleep(1500 * time.Millisecond)

	start := time.Now()
	buf := make([]byte, 4<<10)
	read := 0
	for {
		n, err := resp.Body.Read(buf)
		read += n
		if err != nil {
			break
		}
	}
	resp.Body.Close()
	time.Sleep(200 * time.Millisecond)

	if read != 8<<20 {
		t.Fatalf("read %d bytes, want %d", read, 8<<20)
	}
	// The drain has to finish inside the buffering interval, or a timed update
	// could be mistaken for a byte-arm one and this asserts nothing.
	if elapsed := time.Since(start); elapsed >= inflowBufferInterval {
		t.Fatalf("drain took %v, which is past the %v buffering interval; "+
			"this lock cannot tell the two arms apart on a machine this slow",
			elapsed, inflowBufferInterval)
	}

	_, stream := split(afterFirstRequest(s.recorded()))
	if len(stream) == 0 {
		t.Fatalf("no stream WINDOW_UPDATE at all for an 8MB body\n%s", s.dump())
	}
	half := streamRecvWindow(t) / 2
	for _, f := range stream {
		if f.increment() <= half {
			t.Fatalf("stream WINDOW_UPDATE increment %d is not above half the window (%d), "+
				"and the drain was too quick for the timer to have sent it\n%s",
				f.increment(), half, s.dump())
		}
	}
}

// ------------------------------------------- no stream update after END_STREAM

// Chromium's SpdyStream::IncreaseRecvWindowSize opens with
//
//	if (!session_->IsStreamActive(stream_id_)) return;
//
// so a browser never returns stream-scope credit for a stream it has already
// seen END_STREAM on. The existence of that early return is itself the proof:
// if streams stayed active while the delegate drained buffered data it would
// be dead code.
//
// Connection-scope credit must keep flowing, because the peer really has spent
// that much of its send window. That is the positive control here: without it
// a client that simply failed to drain would pass.
func TestNoStreamWindowUpdateAfterEndStream(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the buffering interval")
	}
	s := startH2Server(t, h2Config{
		Settings:            []h2Setting{{ID: 0x4, Val: 1 << 20}, {ID: 0x5, Val: 16384}},
		ConnWindowIncrement: 1 << 20,
		Body:                make([]byte, 64<<10),
		SendContentLength:   true,
	})

	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", s.url("/ended"), nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := tr.GetHTTP2Transport().RoundTrip(req)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}

	// The whole 64 KB and its END_STREAM land well inside this, so every byte
	// the client is about to read belongs to a stream the peer has closed. The
	// wait also carries the connection past the buffering interval, which is
	// what makes the positive control fire.
	time.Sleep(6 * time.Second)

	buf := make([]byte, 4<<10)
	read := 0
	for {
		n, err := resp.Body.Read(buf)
		read += n
		if err != nil {
			break
		}
	}
	resp.Body.Close()
	time.Sleep(200 * time.Millisecond)

	if read != 64<<10 {
		t.Fatalf("read %d bytes, want %d", read, 64<<10)
	}

	conn, stream := split(afterFirstRequest(s.recorded()))
	if len(conn) == 0 {
		t.Fatalf("no connection WINDOW_UPDATE after the drain; the positive control "+
			"failed, so the stream assertion below proves nothing\n%s", s.dump())
	}
	if len(stream) != 0 {
		t.Fatalf("got %d stream WINDOW_UPDATEs for a stream the peer had already "+
			"ended, want 0\n%s", len(stream), s.dump())
	}
}

// --------------------------------------------------------------- tripwire

// The connection-level preface WINDOW_UPDATE is hashed into the HTTP/2
// fingerprint. Nobody tuning the cadence above may re-derive that value from a
// threshold.
func TestPrefaceWindowUpdateMatchesPreset(t *testing.T) {
	s := startH2Server(t, h2Config{})

	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/")}); err != nil {
		t.Fatalf("request: %v", err)
	}

	want := fingerprint.Get("chrome-latest").HTTP2Settings.ConnectionWindowUpdate
	for _, f := range s.recorded() {
		if f.Type == frHeaders {
			break
		}
		if f.Type == frWindowUpdate && f.StreamID == 0 {
			if f.increment() != want {
				t.Fatalf("preface connection WINDOW_UPDATE = %d, want %d from the preset",
					f.increment(), want)
			}
			return
		}
	}
	t.Fatalf("no connection WINDOW_UPDATE before the first HEADERS\n%s", s.dump())
}
