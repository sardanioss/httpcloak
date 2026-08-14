package client

import (
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// Regression lock: SetPreset must reach every protocol, not just HTTP/2.
//
// It used to update only c.preset and the HTTP/2 pool manager, and even that did
// not work: the manager swapped its preset field while keeping the ClientHello
// specs derived from the ORIGINAL profile and the connections dialled with it.
//
// Measured on the wire before the fix, switching chrome-151 -> firefox-148:
//
//	h1  t13d1516h1_8daaf6152771_806a8c22fdea  (unchanged, still Chrome)
//	h2  t13d1517h2_8daaf6152771_a87ad97598a9  (Chrome ciphers + PSK, not Firefox)
//
// After:
//
//	h1  t13d1717h1_5b57614c22b0_3cbfd9057e0d  (Firefox)
//	h2  t13d1717h2_5b57614c22b0_3cbfd9057e0d  (Firefox, identical to a fresh client)
//
// The failure mode is the dangerous kind: headers and User-Agent switched while
// TLS did not, so the client advertised one browser and handshook as another.
// Nothing surfaces that except a capture.
func TestSetPresetReachesEveryProtocol(t *testing.T) {
	if fingerprint.Get("firefox-148") == nil || fingerprint.Get("chrome-151") == nil {
		t.Skip("presets unavailable")
	}

	// The bare names auto-detect the host OS, so compare against whatever the
	// registry resolves them to rather than the literal string.
	startName := fingerprint.Get("chrome-151").Name
	wantName := fingerprint.Get("firefox-148").Name

	c := NewClient("chrome-151")
	defer c.Close()

	if c.preset == nil || c.preset.Name != startName {
		t.Fatalf("starting preset = %v, want %s", c.preset, startName)
	}

	c.SetPreset("firefox-148")

	if c.preset == nil || c.preset.Name != wantName {
		t.Fatalf("client preset = %v, want %s", c.preset, wantName)
	}
	if got := c.poolManager.Preset(); got == nil || got.Name != wantName {
		t.Errorf("HTTP/2 pool manager preset = %v, want %s", got, wantName)
	}
	if c.h1Transport != nil {
		if got := c.h1Transport.Preset(); got == nil || got.Name != wantName {
			t.Errorf("HTTP/1.1 transport preset = %v, want firefox-148; a profile switch that "+
				"misses a protocol makes the client present two different browsers", got)
		}
	}
	q, m, s5 := c.h3Transports()
	if q != nil {
		if got := q.Preset(); got == nil || got.Name != wantName {
			t.Errorf("QUIC manager preset = %v, want %s", got, wantName)
		}
	}
	if m != nil {
		if got := m.Preset(); got == nil || got.Name != wantName {
			t.Errorf("MASQUE transport preset = %v, want %s", got, wantName)
		}
	}
	if s5 != nil {
		if got := s5.Preset(); got == nil || got.Name != wantName {
			t.Errorf("SOCKS5 H3 transport preset = %v, want %s", got, wantName)
		}
	}
}
