package transport

import (
	"context"
	"errors"
	"testing"

	tls "github.com/sardanioss/utls"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	quic "github.com/sardanioss/quic-go"
)

// When a server rejects early data, the retry used to recreate the transport
// and dial again with the SAME session ticket, so it offered 0-RTT a second and
// third time and was rejected identically each time. Six dials, several
// seconds, then a hard failure against a host that answers a plain handshake in
// about 150ms.
//
// Observed on a live Akamai host, one request:
//
//	attempt=0  dials 0->2  0-RTT rejected
//	attempt=1  dials 2->4  0-RTT rejected
//	attempt=2  dials 4->6  0-RTT rejected
//
// A retry has to differ from the attempt that just failed. Dropping the session
// cache for that host is what makes it differ: no ticket means no early data
// means nothing to reject.
func TestZeroRTTRejectionSuppressesResumptionOnRetry(t *testing.T) {
	tr, err := NewHTTP3Transport(fingerprint.Get("chrome-latest"), dns.NewCache())
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	defer tr.Close()

	var sawCache []bool
	probe := tr.recordHandshakeState(func(_ context.Context, _ string, tlsCfg *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		sawCache = append(sawCache, tlsCfg != nil && tlsCfg.ClientSessionCache != nil)
		return nil, errors.New("dial not attempted in this test")
	})

	cfg := &tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
	const addr = "rejects-early-data.example:443"

	// Before any rejection the cache must be attached, or resumption never
	// happens for anyone and this test would pass for the wrong reason.
	_, _ = probe(context.Background(), addr, cfg, nil)
	if len(sawCache) != 1 || !sawCache[0] {
		t.Fatalf("first dial saw ClientSessionCache=%v, want it attached", sawCache)
	}

	// Mark the host the way the 0-RTT retry path does.
	tr.mu.Lock()
	tr.zeroRTTRejected = map[string]bool{"rejects-early-data.example": true}
	tr.mu.Unlock()

	_, _ = probe(context.Background(), addr, cfg, nil)
	if len(sawCache) != 2 || sawCache[1] {
		t.Errorf("after a 0-RTT rejection the dial still carried a session cache (%v); "+
			"the retry will offer early data again and be rejected again", sawCache)
	}

	// The caller's config must not be mutated; other hosts still resume.
	if cfg.ClientSessionCache == nil {
		t.Error("the shared tls.Config was mutated; every other host just lost resumption")
	}
	_, _ = probe(context.Background(), "other-host.example:443", cfg, nil)
	if len(sawCache) != 3 || !sawCache[2] {
		t.Errorf("an unrelated host lost its session cache (%v); the marker must be per-host", sawCache)
	}
}
