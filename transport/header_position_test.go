package transport

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// TestUserSuppliedCacheControl_RespectsHPACKPosition reproduces a wire-level
// fingerprint regression noticed against a real Chrome 147 capture: real
// Chrome on F5 reload emits `cache-control: max-age=0` between :path and
// sec-ch-ua (HPACK position 0 in our preset's H2HeaderOrder table). When
// a user supplies the header explicitly, we currently append it AFTER
// `priority` — a fingerprintable mis-ordering. This test pins the correct
// position so the next fix can't drift.
//
// What we assert:
//   - cache-control is present in the wire HEADERS frame
//   - it appears at the position the preset's HPACK table dictates
//     (right after the pseudo-headers, before sec-ch-ua), NOT at the end
func TestUserSuppliedCacheControl_RespectsHPACKPosition(t *testing.T) {
	preset := fingerprint.Get("chrome-147-windows")
	if preset == nil {
		t.Skip("chrome-147-windows preset unavailable")
	}

	srv := startH2CaptureServer(t)
	host, port, _ := net.SplitHostPort(srv.addr)
	url := "https://" + net.JoinHostPort(host, port) + "/api/all"

	tr := NewHTTP2Transport(preset, dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// User supplies cache-control. Mirror the binding's flow: pass it
	// through user_headers and Set on the request.
	req.Header.Set("cache-control", "max-age=0")
	uh := map[string][]string{"cache-control": {"max-age=0"}}
	applyPresetHeaders(req, preset, nil, nil, false, "h2", uh)
	// Also mirror what bindings/transport.go:1444 does: re-apply user headers
	// AFTER applyPresetHeaders. This is the exact production path.
	req.Header.Set("cache-control", "max-age=0")

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

		// Find positions of the headers we care about.
		idxOf := func(name string) int {
			lname := strings.ToLower(name)
			for i, h := range c.HeaderOrder {
				if strings.ToLower(h) == lname {
					return i
				}
			}
			return -1
		}
		ccIdx := idxOf("cache-control")
		secCHIdx := idxOf("sec-ch-ua")
		priorityIdx := idxOf("priority")
		pathIdx := idxOf(":path")

		if ccIdx < 0 {
			t.Fatalf("cache-control absent from wire HEADERS frame")
		}
		// Must come before sec-ch-ua per real Chrome ordering (HPACK position 0
		// in the preset's H2HeaderOrder).
		if secCHIdx >= 0 && ccIdx > secCHIdx {
			t.Errorf("cache-control at wire pos %d, sec-ch-ua at %d — real Chrome 147 emits cache-control BEFORE sec-ch-ua",
				ccIdx, secCHIdx)
		}
		// Must NOT be appended after `priority` (our current bug).
		if priorityIdx >= 0 && ccIdx > priorityIdx {
			t.Errorf("cache-control at wire pos %d is AFTER priority at %d — appended-to-end bug",
				ccIdx, priorityIdx)
		}
		// And must come after :path (it's a regular header, not a pseudo-header).
		if pathIdx >= 0 && ccIdx < pathIdx {
			t.Errorf("cache-control at wire pos %d is BEFORE :path at %d — regular header before pseudo-headers",
				ccIdx, pathIdx)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("no capture")
	}
}
