package fingerprint

import (
	"encoding/binary"
	"testing"

	utls "github.com/sardanioss/utls"
)

// A captured ClientHello that carries a pre_shared_key extension has to be
// parsed with RealPSKResumption set, or the spec is not usable for resumption.
//
// Without it uTLS builds a FakePreSharedKeyExtension, which is a shape-only
// placeholder: it puts the right bytes on the wire for a fingerprint but has
// no identities and no binders. uTLS refuses to drive one and says so by
// panicking, at u_pre_shared_key.go:
//
//	panic("InitializeByUtls failed: don't let utls initialize
//	       FakePreSharedKeyExtension; provide your own identities and binders
//	       or use UtlsPreSharedKeyExtension")
//
// So the failure is not a degraded handshake, it is a panic in the caller's
// process, and it only appears once a session ticket exists for the host,
// which means the first request works and a later one takes the program down.

// withPSKExtension appends a well-formed pre_shared_key extension to a
// captured ClientHello and fixes up the three nested lengths.
//
// The captured Chrome hello in this package is a fresh handshake and carries
// no PSK extension, so without this there is nothing here to test and both
// locks below would skip. A skip reads as a pass, which is the whole failure
// mode these locks exist to prevent.
//
// Nothing validates the binder: the parser is reading shape, not verifying a
// handshake, so a zero binder of the right length is enough. pre_shared_key
// must be the LAST extension, per RFC 8446 4.2.11, which is also where it ends
// up in a real capture.
func withPSKExtension(t *testing.T, raw []byte) []byte {
	t.Helper()

	// record header 5, handshake header 4, client_version 2, random 32
	p := 5 + 4 + 2 + 32
	if len(raw) < p+1 {
		t.Fatal("hello too short for a session id")
	}
	p += 1 + int(raw[p]) // session_id
	if len(raw) < p+2 {
		t.Fatal("hello too short for cipher suites")
	}
	p += 2 + int(binary.BigEndian.Uint16(raw[p:])) // cipher_suites
	if len(raw) < p+1 {
		t.Fatal("hello too short for compression methods")
	}
	p += 1 + int(raw[p]) // compression_methods
	if len(raw) < p+2 {
		t.Fatal("hello too short for an extensions block")
	}
	extLenAt := p

	// identity list: one identity of 32 bytes plus a 4-byte ticket age.
	// binder list: one 32-byte binder for SHA-256.
	identity := make([]byte, 32)
	binder := make([]byte, 32)

	var body []byte
	body = binary.BigEndian.AppendUint16(body, uint16(2+len(identity)+4))
	body = binary.BigEndian.AppendUint16(body, uint16(len(identity)))
	body = append(body, identity...)
	body = binary.BigEndian.AppendUint32(body, 0) // obfuscated_ticket_age
	body = binary.BigEndian.AppendUint16(body, uint16(1+len(binder)))
	body = append(body, byte(len(binder)))
	body = append(body, binder...)

	var ext []byte
	ext = binary.BigEndian.AppendUint16(ext, 41) // pre_shared_key
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(body)))
	ext = append(ext, body...)

	out := append(append([]byte(nil), raw...), ext...)
	add := uint16(len(ext))
	binary.BigEndian.PutUint16(out[extLenAt:], binary.BigEndian.Uint16(out[extLenAt:])+add)

	// handshake length is 3 bytes at offset 6
	hs := uint32(out[6])<<16 | uint32(out[7])<<8 | uint32(out[8])
	hs += uint32(add)
	out[6], out[7], out[8] = byte(hs>>16), byte(hs>>8), byte(hs)

	// record length is 2 bytes at offset 3
	binary.BigEndian.PutUint16(out[3:], binary.BigEndian.Uint16(out[3:])+add)
	return out
}

// pskExtension returns the pre_shared_key extension of a spec, if it has one.
func pskExtension(spec *utls.ClientHelloSpec) utls.TLSExtension {
	if spec == nil {
		return nil
	}
	for _, ext := range spec.Extensions {
		if _, ok := ext.(utls.PreSharedKeyExtension); ok {
			return ext
		}
	}
	return nil
}

// The parse flag decides which of the two extension types comes back.
func TestRawPSKHelloParsesToARealExtension(t *testing.T) {
	raw := withPSKExtension(t, mustDecode(t, rawChromeHello))
	if pskExtension(mustSpec(t, raw, false)) == nil {
		t.Fatal("the hello built for this test carries no pre_shared_key " +
			"extension; withPSKExtension or the parser has changed")
	}

	real := pskExtension(mustSpec(t, raw, true))
	if _, fake := real.(*utls.FakePreSharedKeyExtension); fake {
		t.Fatalf("parsed with RealPSKResumption, the pre_shared_key extension is "+
			"still a %T; uTLS panics rather than drive one of those", real)
	}
	if _, ok := real.(*utls.UtlsPreSharedKeyExtension); !ok {
		t.Fatalf("parsed with RealPSKResumption, the pre_shared_key extension is a "+
			"%T, want *utls.UtlsPreSharedKeyExtension", real)
	}

	// The negative half, so this is not asserting a constant: without the flag
	// it really is the placeholder, which is what makes the flag load-bearing.
	fake := pskExtension(mustSpec(t, raw, false))
	if _, ok := fake.(*utls.FakePreSharedKeyExtension); !ok {
		t.Fatalf("parsed without RealPSKResumption, the pre_shared_key extension "+
			"is a %T, want *utls.FakePreSharedKeyExtension; if uTLS changed this, "+
			"the reasoning above needs rechecking", fake)
	}
}

// The wiring, which is the half that actually ships. A preset with a captured
// resumption hello must resolve to a spec that can resume.
func TestResolvedPSKSpecCanResume(t *testing.T) {
	plainRaw := mustDecode(t, rawChromeHello)
	raw := withPSKExtension(t, plainRaw)
	p := &Preset{RawClientHello: plainRaw, RawPSKClientHello: raw}

	spec, src, err := ResolveClientHelloSpec(p, "", nil, true, 0)
	if err != nil {
		t.Fatalf("resolve with PSK wanted: %v", err)
	}
	if src != SourceRaw {
		t.Fatalf("source = %v, want SourceRaw", src)
	}
	ext := pskExtension(spec)
	if ext == nil {
		t.Fatal("the resumption spec carries no pre_shared_key extension at all")
	}
	if _, fake := ext.(*utls.FakePreSharedKeyExtension); fake {
		t.Fatal("the resumption spec carries a FakePreSharedKeyExtension; the " +
			"first request on this preset works and a later one panics")
	}

	// And the non-resumption spec is unaffected, so nothing gained a real PSK
	// extension that was not asked for one.
	plain, _, err := ResolveClientHelloSpec(p, "", nil, false, 0)
	if err != nil {
		t.Fatalf("resolve without PSK wanted: %v", err)
	}
	if ext := pskExtension(plain); ext != nil {
		if _, ok := ext.(*utls.FakePreSharedKeyExtension); !ok {
			t.Fatalf("the non-resumption spec carries a %T; it is never driven "+
				"for resumption and should stay the shape-only placeholder", ext)
		}
	}
}

// The validation path deliberately parses without the flag. A spec built there
// is round-tripped to see whether it parses at all and then discarded, so
// asking for real resumption machinery would be asking uTLS to do work for a
// spec that will never handshake.
func TestDecodeValidationDoesNotNeedRealPSK(t *testing.T) {
	raw := mustDecode(t, rawChromeHello)
	if _, err := SpecFromRawClientHello(raw, false, false); err != nil {
		t.Fatalf("validation parse failed: %v", err)
	}
}

func mustSpec(t *testing.T, raw []byte, realPSK bool) *utls.ClientHelloSpec {
	t.Helper()
	spec, err := SpecFromRawClientHello(raw, false, realPSK)
	if err != nil {
		t.Fatalf("parse (realPSK=%v): %v", realPSK, err)
	}
	return spec
}
