package transport

import (
	"context"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// SetDisableECH is documented as turning the ECH lookup off. dialQUIC honoured
// it; Connect and getECHConfig did not, so on a new host the probe that runs
// FIRST in auto mode still made the HTTPS-record query. That query walks three
// public resolvers serially at 500ms each, sitting in front of the dial. A
// caller who had explicitly opted out kept paying for it, and kept emitting a
// DNS query they had asked not to make.
//
// The check has to sit ahead of the cache read, so a config already in hand is
// suppressed too. Seeding the cache is what makes this deterministic and
// offline: without it getECHConfig returns nil for an ordinary host either way,
// and the test would pass whether or not the flag is consulted.
func TestDisableECHIsHonouredEverywhere(t *testing.T) {
	tr, err := NewHTTP3Transport(fingerprint.Get("chrome-latest"), dns.NewCache())
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	defer tr.Close()

	const host = "ech-probe.example"
	want := []byte{0xfe, 0x0d, 0x00, 0x01}
	tr.echConfigCacheMu.Lock()
	tr.echConfigCache[host] = &echCachedConfig{config: want, expiresAt: time.Now().Add(time.Hour)}
	tr.echConfigCacheMu.Unlock()

	// Enabled: the cached config comes back, proving the path reaches the cache.
	tr.SetDisableECH(false)
	if got := tr.getECHConfig(context.Background(), host); len(got) != len(want) {
		t.Fatalf("with ECH enabled, getECHConfig returned %d bytes, want %d. The test "+
			"cannot detect the disable flag if this path never returns anything",
			len(got), len(want))
	}

	// Disabled: nothing, even though a fresh config is sitting in the cache.
	tr.SetDisableECH(true)
	if got := tr.getECHConfig(context.Background(), host); got != nil {
		t.Errorf("getECHConfig returned %d bytes with ECH disabled; the flag is not "+
			"consulted on this path", len(got))
	}
}
