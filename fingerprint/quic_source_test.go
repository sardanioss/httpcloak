package fingerprint

import (
	"testing"

	utls "github.com/sardanioss/utls"
)

// A preset carries one raw hello and one JA3, and which transport they describe
// is a property of the bytes: a QUIC hello carries quic_transport_parameters
// and a TCP hello does not. Each resolver must take only the source that
// matches it, and fall back to its own identity rather than send the other
// transport's hello.

func specWithQUICParams() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{
		&utls.SNIExtension{},
		&utls.GenericExtension{Id: 57, Data: []byte{0x01, 0x02}},
	}}
}

func specWithoutQUICParams() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{
		&utls.SNIExtension{},
		&utls.SupportedCurvesExtension{},
	}}
}

// The discriminator has to see the shape a real capture produces. uTLS
// recognises extension 57 but its type has no Write method, so a QUIC capture
// only parses under blunt mimicry and arrives as a GenericExtension. Matching
// only the named type would miss every genuine capture.
func TestSpecHasQUICTransportParameters(t *testing.T) {
	if !SpecHasQUICTransportParameters(specWithQUICParams()) {
		t.Error("a GenericExtension carrying id 57 was not recognised as QUIC; " +
			"that is the shape every parsed QUIC capture actually has")
	}
	if SpecHasQUICTransportParameters(specWithoutQUICParams()) {
		t.Error("a TCP hello was reported as QUIC")
	}
	if !SpecHasQUICTransportParameters(&utls.ClientHelloSpec{Extensions: []utls.TLSExtension{
		&utls.QUICTransportParametersExtension{},
	}}) {
		t.Error("the named extension type was not recognised")
	}
	if SpecHasQUICTransportParameters(nil) {
		t.Error("nil spec reported as QUIC")
	}
}

// A TCP JA3 must not decide the QUIC hello: QUIC falls back to its own
// identity, which is the fix for the silent downgrade.
func TestQUICResolverIgnoresATCPSource(t *testing.T) {
	base := Get("chrome-151-windows")
	if base == nil {
		t.Skip("chrome-151-windows unavailable")
	}
	p := clonePreset(base)
	p.JA3 = "771,4865-4866-4867,0-23-65281-10-11,29-23-24,0"

	spec, src, err := ResolveQUICClientHelloSpec(p, false, 42)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if src != SourceClientHelloID {
		t.Errorf("QUIC took source %v from a TCP JA3; it should fall back to the "+
			"QUIC client hello id", src)
	}
	if SpecHasQUICTransportParameters(spec) == false && len(spec.Extensions) == 0 {
		t.Error("resolver produced an empty spec")
	}
}

// And a preset with no QUIC identity at all is an error, not a nil spec. Nil is
// what let the QUIC stack substitute its own default hello unnoticed.
func TestQUICResolverErrorsWithNoIdentity(t *testing.T) {
	p := &Preset{Name: "no-quic"}
	spec, _, err := ResolveQUICClientHelloSpec(p, false, 1)
	if err == nil {
		t.Fatal("expected an error when the preset has no QUIC identity; " +
			"returning nil silently is what produced a default hello on the wire")
	}
	if spec != nil {
		t.Error("expected no spec alongside the error")
	}
}
