package fingerprint

import (
	"encoding/base64"
	"fmt"
	"strings"

	utls "github.com/sardanioss/utls"
)

// ClientHelloSource names where a connection's ClientHelloSpec came from.
type ClientHelloSource int

const (
	SourceClientHelloID ClientHelloSource = iota
	SourceJA3
	SourceRaw
)

func (s ClientHelloSource) String() string {
	switch s {
	case SourceJA3:
		return "ja3"
	case SourceRaw:
		return "raw_client_hello"
	default:
		return "client_hello"
	}
}

// ResolveClientHelloSpec builds a FRESH ClientHelloSpec for one connection.
//
// Fresh per connection is not an optimisation choice, it is required: uTLS
// ApplyPreset mutates the spec it is handed (it clears KeyShares.Data among
// other things), so a spec cached on a Preset is corrupt after the first
// handshake. Every source below therefore re-derives.
//
// Precedence, highest first:
//
//	config.CustomJA3   an explicit per-session override from the caller
//	preset.RawClientHello
//	preset.JA3
//	preset.ClientHelloID
//
// wantPSK asks for the resumption variant of whichever source wins. It is
// honoured only when that source actually has one; there is no cross-source
// fallback, because a PSK-shaped hello from a different client is a worse
// fingerprint than a non-resuming one from the right client.
//
// This function exists to replace an inline if/else chain that was duplicated
// per transport. That chain is why a JA3 preset could never resume: its first
// branch was `if ja3String != ""`, taken unconditionally, so the PSK branch
// below it was unreachable no matter what the preset asked for. Adding a
// fourth source to that shape would have reproduced the same class of bug, so
// the decision lives in one place now and every caller shares it.
func ResolveClientHelloSpec(
	p *Preset,
	customJA3 string,
	customJA3Extras *JA3Extras,
	wantPSK bool,
	seed int64,
) (*utls.ClientHelloSpec, ClientHelloSource, error) {
	if p == nil {
		return nil, SourceClientHelloID, fmt.Errorf("nil preset")
	}

	// A caller-supplied JA3 overrides the preset entirely, including its PSK
	// variant, since the caller cannot express one.
	if customJA3 != "" {
		spec, err := ParseJA3(customJA3, customJA3Extras)
		if err != nil {
			return nil, SourceJA3, fmt.Errorf("parse custom ja3: %w", err)
		}
		return spec, SourceJA3, nil
	}

	if len(p.RawClientHello) > 0 {
		raw := p.RawClientHello
		if wantPSK && len(p.RawPSKClientHello) > 0 {
			raw = p.RawPSKClientHello
		}
		spec, err := SpecFromRawClientHello(raw, p.RawBluntMimicry)
		if err != nil {
			return nil, SourceRaw, err
		}
		return spec, SourceRaw, nil
	}

	if p.JA3 != "" {
		ja3 := p.JA3
		if wantPSK && p.PSKJA3 != "" {
			ja3 = p.PSKJA3
		}
		spec, err := ParseJA3(ja3, p.JA3Extras)
		if err != nil {
			return nil, SourceJA3, fmt.Errorf("parse ja3: %w", err)
		}
		return spec, SourceJA3, nil
	}

	id := p.ClientHelloID
	if wantPSK && p.PSKClientHelloID.Client != "" {
		id = p.PSKClientHelloID
	}
	spec, err := utls.UTLSIdToSpecWithSeed(id, seed)
	if err != nil {
		return nil, SourceClientHelloID, fmt.Errorf("build spec for %s/%s: %w", id.Client, id.Version, err)
	}
	return &spec, SourceClientHelloID, nil
}

// HasPSKVariant reports whether the preset can produce a resumption-shaped
// ClientHello for whichever source ResolveClientHelloSpec would pick.
//
// The old derivation asked whether the JA3 string contained extension 41. That
// can only ever be true for a JA3 captured mid-resumption, and a first capture
// never is, so a JA3 preset reported no PSK support and never resumed. Asking
// the preset what it actually carries removes the guesswork.
func HasPSKVariant(p *Preset, customJA3 string) bool {
	if p == nil || customJA3 != "" {
		return false // a caller-supplied JA3 has no PSK counterpart
	}
	if len(p.RawClientHello) > 0 {
		return len(p.RawPSKClientHello) > 0
	}
	if p.JA3 != "" {
		return p.PSKJA3 != ""
	}
	return p.PSKClientHelloID.Client != ""
}

// SpecFromRawClientHello turns captured ClientHello bytes into a spec.
//
// blunt passes unknown extensions through verbatim. Without it uTLS rejects
// anything it does not model, which is how a curl hello fails: "unsupported
// extension 22".
func SpecFromRawClientHello(raw []byte, blunt bool) (*utls.ClientHelloSpec, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty client hello")
	}
	fp := &utls.Fingerprinter{AllowBluntMimicry: blunt}
	spec, err := fp.RawClientHello(raw)
	if err != nil {
		return nil, err
	}
	return spec, nil
}

// DecodeRawClientHello decodes and validates a base64 ClientHello at load time,
// so an unusable capture is a named error rather than a handshake failure on
// the first request. The decoded bytes are returned for the preset to keep;
// the parsed spec is thrown away, since it has to be re-derived per connection
// anyway.
func DecodeRawClientHello(field, b64 string, blunt bool) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64: %w", field, err)
	}
	if len(raw) < 6 || raw[0] != 0x16 {
		return nil, fmt.Errorf("%s does not look like a TLS record: want a 0x16 handshake record, "+
			"got %d bytes starting 0x%02x", field, len(raw), firstByte(raw))
	}
	if _, err := SpecFromRawClientHello(raw, blunt); err != nil {
		if !blunt && strings.Contains(err.Error(), "unsupported extension") {
			return nil, fmt.Errorf("%s: %w. Set tls.allow_blunt_mimicry=true to pass unknown "+
				"extensions through verbatim; some clients (curl among them) need it", field, err)
		}
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return raw, nil
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

// SpecHasPSKExtension reports whether a resolved spec carries a pre_shared_key
// extension, i.e. whether it is shaped for resumption.
//
// This replaces asking a JA3 string whether its extension list contains 41.
// That question only worked for one of the three sources and could not be
// asked of a captured raw hello at all. Inspecting the spec answers it for
// every source, and answers it about the thing actually going on the wire.
//
// It matters because attaching a session cache to a spec with no PSK extension
// can break the handshake, so the caller needs to know before it decides.
func SpecHasPSKExtension(spec *utls.ClientHelloSpec) bool {
	if spec == nil {
		return false
	}
	for _, ext := range spec.Extensions {
		if _, ok := ext.(utls.PreSharedKeyExtension); ok {
			return true
		}
	}
	return false
}

// ClientHelloSourceOf reports which source ResolveClientHelloSpec would pick,
// without building a spec.
//
// The H1 transport needs the answer before it decides between HelloCustom and
// a named ClientHelloID, and only the first of those wants a spec. Resolving
// eagerly there would build one on every connection just to discard it.
func ClientHelloSourceOf(p *Preset, customJA3 string) ClientHelloSource {
	if customJA3 != "" {
		return SourceJA3
	}
	if p == nil {
		return SourceClientHelloID
	}
	if len(p.RawClientHello) > 0 {
		return SourceRaw
	}
	if p.JA3 != "" {
		return SourceJA3
	}
	return SourceClientHelloID
}
