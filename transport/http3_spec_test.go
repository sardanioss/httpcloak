package transport

import (
	"fmt"
	"sort"
	"testing"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// The H3 transport regenerates the ClientHelloSpec per dial (the fix for the
// concurrent-dial data race: utls ApplyPreset mutates the spec in place, so a
// shared cached spec races under concurrency). This regression test locks the
// two properties that fix depends on:
//
//  1. each call returns a DISTINCT spec object (structural race-safety: no two
//     concurrent dials ever hold the same mutable spec), and
//  2. the extension and cipher-suite ORDER is byte-identical across calls, so
//     JA3/JA4 stay stable between connections of one session.
func TestH3SpecRegenDeterministic(t *testing.T) {
	tr, err := NewHTTP3Transport(fingerprint.Chrome146(), dns.NewCache())
	if err != nil {
		t.Fatalf("NewHTTP3Transport: %v", err)
	}

	s1 := tr.getSpecForHost("example.com")
	s2 := tr.getSpecForHost("example.com")
	if s1 == nil || s2 == nil {
		t.Fatal("getSpecForHost returned nil")
	}

	// (1) distinct objects: a shared pointer would mean concurrent dials race.
	if s1 == s2 {
		t.Fatal("getSpecForHost returned the SAME spec pointer twice; concurrent dials would race-mutate it")
	}

	// (2a) extension order identical (drives JA4).
	if len(s1.Extensions) != len(s2.Extensions) {
		t.Fatalf("extension count drift: %d vs %d", len(s1.Extensions), len(s2.Extensions))
	}
	for i := range s1.Extensions {
		a, b := fmt.Sprintf("%T", s1.Extensions[i]), fmt.Sprintf("%T", s2.Extensions[i])
		if a != b {
			t.Fatalf("extension order drift at %d: %s vs %s (JA4 would change between connections)", i, a, b)
		}
	}

	// (2b) cipher-suite order identical (drives JA3).
	if len(s1.CipherSuites) != len(s2.CipherSuites) {
		t.Fatalf("cipher count drift: %d vs %d", len(s1.CipherSuites), len(s2.CipherSuites))
	}
	for i := range s1.CipherSuites {
		if s1.CipherSuites[i] != s2.CipherSuites[i] {
			t.Fatalf("cipher order drift at %d: %#x vs %#x", i, s1.CipherSuites[i], s2.CipherSuites[i])
		}
	}
}

// A TCP-only fingerprint source must not degrade the HTTP/3 hello.
//
// A preset carries one RawClientHello and one JA3, and which transport they
// describe is a property of the bytes: a QUIC hello carries
// quic_transport_parameters and a TCP hello does not. Building a preset from a
// TCP capture used to erase the QUIC identity it inherited, which left this
// transport with nothing to build from. getSpecForHost then returned nil and
// the QUIC stack quietly used its own default hello.
//
// Quietly is the problem. Measured against a live endpoint before the fix,
// chrome-151-windows over HTTP/3 gave q13d311_55b375c5d22e_653d80c3fe9d with 11
// extensions; the same preset with a TCP ja3 added gave
// q13d37_55b375c5d22e_4ca1098a2eeb with 7. Every request succeeded, so nothing
// reported it. Anyone running HTTP/3 with a custom fingerprint was affected.
//
// This asserts offline what that measurement showed: adding a TCP source leaves
// the HTTP/3 hello byte-identical to the base preset's.
func TestH3HelloSurvivesATCPOnlySource(t *testing.T) {
	base := fingerprint.Get("chrome-151-windows")
	if base == nil {
		t.Skip("chrome-151-windows unavailable")
	}

	// A TCP JA3, the shape a caller supplies when mirroring a TCP capture.
	spec := &fingerprint.PresetSpec{
		Name:    "h3-degrade-probe",
		BasedOn: "chrome-151-windows",
		TLS:     &fingerprint.TLSSpec{JA3: "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0"},
	}
	withJA3, err := fingerprint.BuildPreset(spec)
	if err != nil {
		t.Fatalf("BuildPreset: %v", err)
	}

	specOf := func(p *fingerprint.Preset, label string) []string {
		tr, err := NewHTTP3Transport(p, dns.NewCache())
		if err != nil {
			t.Fatalf("NewHTTP3Transport(%s): %v", label, err)
		}
		t.Cleanup(func() { _ = tr.Close() })
		s := tr.getSpecForHost("example.com")
		if s == nil {
			t.Fatalf("%s: getSpecForHost returned nil, so HTTP/3 would fall back "+
				"to the QUIC stack's default hello and carry no configured "+
				"fingerprint at all", label)
		}
		// Sorted, not in wire order: the QUIC hello permutes its extensions per
		// handshake the way Chromium does, so two transports legitimately differ
		// in order. What must not differ is WHICH extensions are present.
		names := make([]string, len(s.Extensions))
		for i, e := range s.Extensions {
			names[i] = fmt.Sprintf("%T", e)
		}
		sort.Strings(names)
		return names
	}

	want := specOf(base, "chrome-151-windows")
	got := specOf(withJA3, "chrome-151-windows + TCP ja3")

	if len(got) != len(want) {
		t.Fatalf("HTTP/3 hello lost extensions when a TCP ja3 was added: %d vs %d.\n"+
			"A TCP source says nothing about QUIC, so the QUIC identity must "+
			"survive it untouched.\n  base: %v\n  with ja3: %v",
			len(got), len(want), want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("HTTP/3 extension set differs after adding a TCP ja3: %s vs %s\n"+
				"  base: %v\n  with ja3: %v", want[i], got[i], want, got)
		}
	}
}
