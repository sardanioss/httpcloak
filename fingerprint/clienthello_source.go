package fingerprint

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sardanioss/quic-go/quicvarint"
	utls "github.com/sardanioss/utls"
)

// ClientHelloSource names where a connection's ClientHelloSpec came from.
type ClientHelloSource int

const (
	SourceClientHelloID ClientHelloSource = iota
	SourceJA3
	SourceRaw
	SourceRawQUIC
)

func (s ClientHelloSource) String() string {
	switch s {
	case SourceJA3:
		return "ja3"
	case SourceRaw:
		return "raw_client_hello"
	case SourceRawQUIC:
		return "raw_quic_client_hello"
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
		spec, err := specFromCapture(p.RawClientHello, p.RawPSKClientHello, wantPSK, p.RawBluntMimicry)
		if err != nil {
			return nil, SourceRaw, err
		}
		// A captured hello is one connection's worth of evidence, so its
		// extension order is frozen unless the preset says the client varies it.
		// Chromium does; NSS, Apple's stack and Go do not.
		//
		// Blunt mimicry used to opt out of this on the reasoning that an
		// extension with no model behind it cannot be moved safely. That is not
		// what the classifier does. Everything whose position is actually
		// constrained is modelled and stays pinned through a blunt parse: GREASE
		// brackets the list, padding sizes the record, and pre_shared_key is
		// required by RFC 8446 4.2.11 to be last. All three are writable, so a
		// blunt parse yields their real types and the shuffle leaves them where
		// they are. Only genuinely unmodellable extensions become a
		// GenericExtension, and RFC 8446 4.2 puts no ordering constraint on
		// those at all.
		//
		// The old coupling was also self-defeating for the one caller that needs
		// both. A QUIC capture cannot be parsed without blunt mimicry, because
		// quic_transport_parameters is the single extension uTLS recognises and
		// cannot write, so requiring blunt to disable permutation meant every
		// HTTP/3 mirror was frozen at one order no matter what the preset asked
		// for. That is the snapshot-versus-behaviour gap, and declaring
		// permute_extensions was silently ignored rather than refused.
		//
		// Fresh randomness per call, not the caller's seed. Chromium permutes on
		// every handshake, because BoringSSL keeps extension_permutation on the
		// handshake rather than the context, and the ClientHelloID path already
		// behaves that way: utlsIdToSpec shuffles a Chrome parrot's literal with
		// fresh randomness every time a spec is built.
		//
		// Seeding this shuffle instead made the raw path the odd one out. The
		// seed is drawn once per transport, so every connection in a session
		// repeated one order, and the HTTP/1.1 call site passes a constant 0,
		// which pinned the order for every process on every machine. A captured
		// hello is exactly what a caller reaches for when they want to look like
		// one specific build, so a permutation that never moves is the wrong
		// answer twice over.
		// A QUIC capture on a TCP connection is the same error as the reverse:
		// quic_transport_parameters is meaningless here and its absence is part
		// of what a TCP hello looks like. Fall through to the TCP identity
		// rather than send a hello no TCP client would.
		if !SpecHasQUICTransportParameters(spec) {
			if p.RawPermuteExtensions {
				spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
			}
			return spec, SourceRaw, nil
		}
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
		if !SpecHasQUICTransportParameters(spec) {
			return spec, SourceJA3, nil
		}
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

// HasQUICPSKVariant reports whether a QUIC handshake has a resumption-shaped
// hello to send: the captured one when the preset carries a QUIC capture, the
// named QUIC PSK id otherwise.
func HasQUICPSKVariant(p *Preset) bool {
	if p == nil {
		return false
	}
	if len(p.RawQUICClientHello) > 0 {
		return len(p.RawQUICPSKClientHello) > 0
	}
	return p.QUICPSKClientHelloID.Client != ""
}

// specFromCapture parses the resumption capture when one is wanted and present,
// and the fresh capture otherwise.
func specFromCapture(raw, pskRaw []byte, wantPSK, blunt bool) (*utls.ClientHelloSpec, error) {
	if wantPSK && len(pskRaw) > 0 {
		return SpecFromRawClientHello(pskRaw, blunt, true)
	}
	return SpecFromRawClientHello(raw, blunt, false)
}

// SpecFromRawClientHello turns captured ClientHello bytes into a spec.
//
// blunt passes unknown extensions through verbatim. Without it uTLS rejects
// anything it does not model, which is how a curl hello fails: "unsupported
// extension 22".
func SpecFromRawClientHello(raw []byte, blunt bool, realPSK bool) (*utls.ClientHelloSpec, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty client hello")
	}
	// realPSK must be true whenever this spec is actually going to resume.
	// Parsed with realPSK false, a captured hello carrying a pre_shared_key
	// extension yields a FakePreSharedKeyExtension, which is a shape-only
	// placeholder: uTLS refuses to drive it and panics outright, in
	// u_pre_shared_key.go, the moment a session ticket exists for the host.
	//
	//	panic("InitializeByUtls failed: don't let utls initialize
	//	       FakePreSharedKeyExtension; provide your own identities and
	//	       binders or use UtlsPreSharedKeyExtension")
	//
	// It stays false on the validation path, where the spec is parsed to check
	// that it round-trips and is then discarded.
	fp := &utls.Fingerprinter{AllowBluntMimicry: blunt, RealPSKResumption: realPSK}
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
	if _, err := SpecFromRawClientHello(raw, blunt, false); err != nil {
		if !blunt && strings.Contains(err.Error(), "unsupported extension") {
			return nil, fmt.Errorf("%s: %w. Set tls.allow_blunt_mimicry=true to pass unknown "+
				"extensions through verbatim; some clients (curl among them) need it", field, err)
		}
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return raw, nil
}

// DecodeRawQUICClientHello is DecodeRawClientHello for a field that must hold a
// QUIC capture. A TCP hello there would be sent on QUIC with no transport
// parameters, so it is refused at load rather than on the first HTTP/3 dial.
func DecodeRawQUICClientHello(field, b64 string, blunt bool) ([]byte, error) {
	raw, err := DecodeRawClientHello(field, b64, blunt)
	if err != nil {
		return nil, err
	}
	spec, err := SpecFromRawClientHello(raw, blunt, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	body, ok := quicTransportParametersBody(spec)
	if !ok {
		return nil, fmt.Errorf("%s has no quic_transport_parameters extension, so it was not "+
			"captured from a QUIC handshake; a TCP capture belongs in tls.raw_client_hello", field)
	}
	// HTTP/3 reads the capture's parameter list to decide what it sends, so an
	// unreadable one is refused here rather than on the first dial.
	if _, err := decodeQUICTransportParameters(body); err != nil {
		return nil, fmt.Errorf("%s: quic_transport_parameters: %w", field, err)
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

// SpecHasQUICTransportParameters reports whether a resolved spec carries
// quic_transport_parameters (extension 57), which is what distinguishes a hello
// captured from a QUIC handshake from one captured off TCP.
//
// Two shapes count, because uTLS represents the extension differently depending
// on how the capture was parsed. ExtensionFromID recognises 57 and hands back a
// QUICTransportParametersExtension, but that type has no Write method, so it is
// not a TLSExtensionWriter and the parser cannot fill it from captured bytes.
// A QUIC capture therefore only parses under blunt mimicry, where the extension
// arrives as a GenericExtension carrying the raw id. Matching only the named
// type would miss every real capture.
func SpecHasQUICTransportParameters(spec *utls.ClientHelloSpec) bool {
	_, ok := quicTransportParametersBody(spec)
	return ok
}

// quicTransportParametersBody returns the body of a spec's
// quic_transport_parameters extension, in either of the two shapes described
// on SpecHasQUICTransportParameters. A named extension that came from a parrot
// rather than a capture has no body yet, and yields nil with ok true.
func quicTransportParametersBody(spec *utls.ClientHelloSpec) ([]byte, bool) {
	if spec == nil {
		return nil, false
	}
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.QUICTransportParametersExtension:
			return e.RawData, true
		case *utls.GenericExtension:
			if e.Id == quicTransportParametersExtensionID {
				return e.Data, true
			}
		}
	}
	return nil, false
}

// decodeQUICTransportParameters splits a quic_transport_parameters body into
// its parameters, keyed by id. Each is a varint id, a varint length and that
// many bytes of value (RFC 9000 section 18).
func decodeQUICTransportParameters(body []byte) (map[uint64][]byte, error) {
	params := make(map[uint64][]byte)
	for len(body) > 0 {
		id, n, err := quicvarint.Parse(body)
		if err != nil {
			return nil, fmt.Errorf("transport parameter id: %w", err)
		}
		body = body[n:]

		length, n, err := quicvarint.Parse(body)
		if err != nil {
			return nil, fmt.Errorf("transport parameter 0x%x length: %w", id, err)
		}
		body = body[n:]

		if length > uint64(len(body)) {
			return nil, fmt.Errorf("transport parameter 0x%x claims %d bytes, %d remain", id, length, len(body))
		}
		if _, dup := params[id]; dup {
			return nil, fmt.Errorf("transport parameter 0x%x appears twice", id)
		}
		params[id] = body[:length]
		body = body[length:]
	}
	return params, nil
}

// QUICCaptureTransportParameters returns the transport parameters carried by
// the capture an HTTP/3 ClientHello is built from, keyed by id. ok is false
// when HTTP/3 is not built from a capture at all.
//
// The captured values never reach the wire as a block: the QUIC layer replaces
// extension 57 with its own parameters, since some of them are per connection.
// What the capture does settle is which parameters the client sends, and that
// is the question a preset with a capture cannot answer from its identity,
// because the capture is what cleared it.
//
// The candidates are taken in ResolveQUICClientHelloSpec's order, so the answer
// describes the same hello that goes on the wire.
func QUICCaptureTransportParameters(p *Preset) (map[uint64][]byte, bool, error) {
	if p == nil {
		return nil, false, nil
	}
	for _, raw := range [][]byte{p.RawQUICClientHello, p.RawClientHello} {
		if len(raw) == 0 {
			continue
		}
		spec, err := SpecFromRawClientHello(raw, p.RawBluntMimicry, false)
		if err != nil {
			return nil, true, fmt.Errorf("parse quic capture: %w", err)
		}
		body, isQUIC := quicTransportParametersBody(spec)
		if !isQUIC {
			continue
		}
		params, err := decodeQUICTransportParameters(body)
		if err != nil {
			return nil, true, fmt.Errorf("decode quic_transport_parameters: %w", err)
		}
		return params, true, nil
	}
	return nil, false, nil
}

// quicTransportParametersExtensionID is extension 57, quic_transport_parameters
// (RFC 9001 section 8.2). Every QUIC ClientHello carries it and no TCP one does,
// which makes it the discriminator between the two.
const quicTransportParametersExtensionID uint16 = 57

// ResolveQUICClientHelloSpec is ResolveClientHelloSpec for a QUIC handshake.
//
// It exists because the two transports need different answers from the same
// preset. A preset carries one RawClientHello and one JA3, and which transport
// those describe is a property of the bytes rather than of the field they sit
// in. Handing a TCP capture to QUIC produces a hello with no transport
// parameters, which is not the configured fingerprint and is not a valid QUIC
// hello either.
//
// Precedence, highest first, and each source after the first is skipped unless
// it actually describes a QUIC handshake:
//
//	preset.RawQUICClientHello
//	preset.RawClientHello   when it carries quic_transport_parameters
//	preset.JA3              when it carries quic_transport_parameters
//	preset.QUICClientHelloID
//
// The last is the common case and the reason the QUIC identities are no longer
// cleared when a TCP source is set: a TCP capture says nothing about QUIC, so
// QUIC keeps the identity it inherited.
//
// An unusable source is an error rather than a silent fall-through to the next
// one. Falling through is how a capture that failed to parse turned into a
// default hello that still connected, which is the failure this whole path was
// built to stop.
func ResolveQUICClientHelloSpec(p *Preset, wantPSK bool, seed int64) (*utls.ClientHelloSpec, ClientHelloSource, error) {
	if p == nil {
		return nil, SourceClientHelloID, fmt.Errorf("nil preset")
	}

	if len(p.RawQUICClientHello) > 0 {
		spec, err := specFromCapture(p.RawQUICClientHello, p.RawQUICPSKClientHello, wantPSK, p.RawBluntMimicry)
		if err != nil {
			return nil, SourceRawQUIC, fmt.Errorf("parse raw quic client hello: %w", err)
		}
		if p.RawPermuteExtensions {
			spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
		}
		return spec, SourceRawQUIC, nil
	}

	if len(p.RawClientHello) > 0 {
		spec, err := specFromCapture(p.RawClientHello, p.RawPSKClientHello, wantPSK, p.RawBluntMimicry)
		if err != nil {
			return nil, SourceRaw, fmt.Errorf("parse raw client hello for quic: %w", err)
		}
		if SpecHasQUICTransportParameters(spec) {
			if p.RawPermuteExtensions {
				spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
			}
			return spec, SourceRaw, nil
		}
		// A TCP capture. Fall through to the QUIC identity rather than send a
		// hello with no transport parameters.
	}

	if p.JA3 != "" {
		ja3 := p.JA3
		if wantPSK && p.PSKJA3 != "" {
			ja3 = p.PSKJA3
		}
		spec, err := ParseJA3(ja3, p.JA3Extras)
		if err != nil {
			return nil, SourceJA3, fmt.Errorf("parse ja3 for quic: %w", err)
		}
		if SpecHasQUICTransportParameters(spec) {
			return spec, SourceJA3, nil
		}
	}

	id := p.QUICClientHelloID
	if wantPSK && p.QUICPSKClientHelloID.Client != "" {
		id = p.QUICPSKClientHelloID
	}
	if id.Client == "" {
		return nil, SourceClientHelloID, fmt.Errorf(
			"preset %q has no QUIC client hello: no capture or ja3 carrying "+
				"quic_transport_parameters, and no quic_client_hello_id", p.Name)
	}
	spec, err := SpecForQUICWithAnchors(id, seed, p.QUICSignatureAlgorithms, p.TrustAnchors, p.QUICTrustAnchorShuffle)
	if err != nil {
		return nil, SourceClientHelloID, fmt.Errorf(
			"build quic spec for %s/%s: %w", id.Client, id.Version, err)
	}
	return spec, SourceClientHelloID, nil
}
