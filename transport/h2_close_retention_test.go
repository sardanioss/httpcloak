package transport

import (
	"io"
	"net"
	"runtime"
	"testing"

	http "github.com/sardanioss/http"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// A closed HTTP/2 transport has to become collectable straight away.
//
// It did not. x/net/http2 parks a connection that was never reused for five
// seconds after it closes, so the read loop's cleanup can still report an error
// on a fresh connection that failed by itself. The park is a time.AfterFunc
// holding the ClientConn, which holds the utls Conn, both bufio buffers, the
// HPACK tables and the ML-KEM key, so every closed session pinned roughly 50KB
// for five seconds whether or not anything had gone wrong.
//
// A session pool notices immediately. Measured over 1000 create-request-close
// cycles before the fix: 99MB RSS and 49MB of live heap after a full GC. After:
// 25MB and 1.2MB, flat no matter how many cycles run. Go's own HTTP/2 client
// against the same server retains nothing, which is what said the park was ours
// to fix rather than something inherent.
//
// This asserts on live heap rather than RSS because RSS lags the scavenger and
// says nothing about reachability. The budget is deliberately loose: the
// regression is about 50x the threshold, so a noisy neighbour in the same test
// binary cannot fake either result.
func TestClosedH2TransportIsCollectable(t *testing.T) {
	testH2TeardownIsCollectable(t, func(tr *HTTP2Transport) { tr.Close() })
}

// CloseGraceful defers a connection's close until its last body is done rather
// than cutting it off, which is what a session rotating under load wants. That
// is also the shape that churns closed sessions fastest, so it is the one the
// park hurt most.
//
// Every deferred close still lands on persistentConn.close and so on the same
// ClientConn.Close, meaning it inherits the opt-out. Asserting it rather than
// reading it keeps the two changes from drifting apart: retiring a connection
// through some other path later would silently reintroduce the five second
// hold for exactly the callers who rotate most.
func TestGracefullyClosedH2TransportIsCollectable(t *testing.T) {
	testH2TeardownIsCollectable(t, func(tr *HTTP2Transport) { tr.CloseGraceful() })
}

func testH2TeardownIsCollectable(t *testing.T, teardown func(*HTTP2Transport)) {
	t.Helper()
	const (
		cycles = 100
		budget = 2 << 20 // 2MB total, against ~5MB of regression
	)

	srv := startH2CaptureServer(t)
	host, port, _ := net.SplitHostPort(srv.addr)
	url := "https://" + net.JoinHostPort(host, port) + "/x"
	preset := fingerprint.Get("chrome-152-windows")

	cycle := func() {
		tr := NewHTTP2Transport(preset, dns.NewCache())
		tr.SetInsecureSkipVerify(true)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		applyPresetHeaders(req, preset, nil, nil, false, "h2", nil, false, nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("roundtrip: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		teardown(tr)
	}

	// One warm-up cycle so the certificate pool, the preset clone and the
	// package-level pools are already allocated when the baseline is taken.
	cycle()

	live := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}

	before := live()
	for i := 0; i < cycles; i++ {
		cycle()
	}
	after := live()

	if after > before && after-before > budget {
		t.Errorf("%d closed HTTP/2 transports still hold %d bytes of live heap "+
			"(%d per transport), budget %d.\nA closed connection is being pinned "+
			"after Close, most likely the unused-connection park in the fork's "+
			"read loop cleanup, which ClientConn.Close must opt out of.",
			cycles, after-before, (after-before)/cycles, budget)
	} else {
		t.Logf("%d cycles retained %d bytes of live heap", cycles, int64(after)-int64(before))
	}
}
