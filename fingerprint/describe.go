package fingerprint

import (
	"bytes"
	"encoding/json"
	"fmt"

	tls "github.com/sardanioss/utls"
)

// Describe returns a fully-resolved JSON dump of a preset's effective state.
//
// All inheritance is flattened (no based_on in output). Default values
// produced by H2Config / H3Config getters are emitted explicitly, so a
// preset built with H2Config=nil and one built with H2Config set to the
// equivalent Chrome defaults describe to byte-identical JSON.
//
// The result is suitable for round-tripping through LoadAndBuildPresetFromJSON
// to reconstruct an equivalent preset:
//
//	JSON1 := Describe(name)
//	p, _ := LoadAndBuildPresetFromJSON([]byte(JSON1))
//	Register(p.Name, p)
//	JSON2 := Describe(p.Name)
//	// JSON1 == JSON2 byte-for-byte
//
// Returns an error if the preset is not registered or if it references a
// utls ClientHelloID that is not in the canonical name registry.
func Describe(name string) (string, error) {
	p := GetStrict(name)
	if p == nil {
		return "", fmt.Errorf("preset %q not registered", name)
	}
	spec, err := flattenToSpec(p)
	if err != nil {
		return "", err
	}
	pf := &PresetFile{Version: 1, Preset: spec}
	return marshalCanonical(pf)
}

// flattenToSpec walks a Preset and produces a fully-populated PresetSpec.
// Use of getters resolves nil H2Config / H3Config to Chrome defaults so the
// flat output is reproducible across processes regardless of how the preset
// was originally constructed.
func flattenToSpec(p *Preset) (*PresetSpec, error) {
	spec := &PresetSpec{Name: p.Name}

	tlsSpec, err := flattenTLS(p)
	if err != nil {
		return nil, err
	}
	spec.TLS = tlsSpec

	spec.Headers = flattenHeaders(p)
	spec.HTTP2 = flattenHTTP2(p)
	if p.SupportHTTP3 {
		spec.HTTP3 = flattenHTTP3(p)
	}
	if tcp := flattenTCP(p); tcp != nil {
		spec.TCP = tcp
	}

	// Always emit Protocol so round-trip preserves SupportHTTP3 explicitly.
	http3 := p.SupportHTTP3
	spec.Protocol = &ProtocolSpec{HTTP3: &http3}

	return spec, nil
}

// flattenTLS resolves the TLS section. Either ja3 OR client_hello is emitted,
// never both, matching the BuildPreset mutual-exclusivity rule.
func flattenTLS(p *Preset) (*TLSSpec, error) {
	out := &TLSSpec{}

	if p.JA3 != "" {
		out.JA3 = p.JA3
		if p.JA3Extras != nil {
			out.JA3ExtrasSpec = flattenJA3Extras(p.JA3Extras)
		}
		return out, nil
	}

	// client_hello path. Reverse-lookup each utls ID to its canonical name.
	if p.ClientHelloID.Client != "" || p.ClientHelloID.Version != "" {
		name, ok := ClientHelloIDName(p.ClientHelloID)
		if !ok {
			return nil, fmt.Errorf("preset %q: unregistered ClientHelloID %+v (cannot describe)", p.Name, p.ClientHelloID)
		}
		out.ClientHello = name
	}
	if p.PSKClientHelloID.Client != "" || p.PSKClientHelloID.Version != "" {
		name, ok := ClientHelloIDName(p.PSKClientHelloID)
		if !ok {
			return nil, fmt.Errorf("preset %q: unregistered PSKClientHelloID %+v (cannot describe)", p.Name, p.PSKClientHelloID)
		}
		out.PSKClientHello = name
	}
	if p.QUICClientHelloID.Client != "" || p.QUICClientHelloID.Version != "" {
		name, ok := ClientHelloIDName(p.QUICClientHelloID)
		if !ok {
			return nil, fmt.Errorf("preset %q: unregistered QUICClientHelloID %+v (cannot describe)", p.Name, p.QUICClientHelloID)
		}
		out.QUICClientHello = name
	}
	if p.QUICPSKClientHelloID.Client != "" || p.QUICPSKClientHelloID.Version != "" {
		name, ok := ClientHelloIDName(p.QUICPSKClientHelloID)
		if !ok {
			return nil, fmt.Errorf("preset %q: unregistered QUICPSKClientHelloID %+v (cannot describe)", p.Name, p.QUICPSKClientHelloID)
		}
		out.QUICPSKClientHello = name
	}

	if out.ClientHello == "" && out.JA3 == "" {
		// Preset has no TLS configuration at all. Drop the TLS section.
		return nil, nil
	}
	return out, nil
}

func flattenJA3Extras(e *JA3Extras) *JA3ExtrasSpec {
	out := &JA3ExtrasSpec{}
	if len(e.SignatureAlgorithms) > 0 {
		out.SignatureAlgorithms = make([]uint16, len(e.SignatureAlgorithms))
		for i, s := range e.SignatureAlgorithms {
			out.SignatureAlgorithms[i] = uint16(s)
		}
	}
	if len(e.DelegatedCredentialAlgorithms) > 0 {
		out.DelegatedCredentialAlgorithms = make([]uint16, len(e.DelegatedCredentialAlgorithms))
		for i, s := range e.DelegatedCredentialAlgorithms {
			out.DelegatedCredentialAlgorithms[i] = uint16(s)
		}
	}
	if len(e.ALPN) > 0 {
		out.ALPN = make([]string, len(e.ALPN))
		copy(out.ALPN, e.ALPN)
	}
	if len(e.CertCompAlgs) > 0 {
		out.CertCompression = certCompAlgsToNames(e.CertCompAlgs)
	}
	if e.PermuteExtensions {
		v := true
		out.PermuteExtensions = &v
	}
	if e.RecordSizeLimit != 0 {
		v := e.RecordSizeLimit
		out.RecordSizeLimit = &v
	}
	if e.KeyShareCurves != 0 {
		v := e.KeyShareCurves
		out.KeyShareCurves = &v
	}
	return out
}

// flattenHeaders dumps the User-Agent, headers map, and ordered header list.
// json.Marshal sorts map keys alphabetically, so Values is naturally
// deterministic. Order is emitted in slice order to preserve wire ordering.
func flattenHeaders(p *Preset) *HeaderSpec {
	if p.UserAgent == "" && len(p.Headers) == 0 && len(p.HeaderOrder) == 0 {
		return nil
	}
	out := &HeaderSpec{UserAgent: p.UserAgent}
	if len(p.Headers) > 0 {
		out.Values = make(map[string]string, len(p.Headers))
		for k, v := range p.Headers {
			out.Values[k] = v
		}
	}
	if len(p.HeaderOrder) > 0 {
		out.Order = make([]HeaderPairSpec, len(p.HeaderOrder))
		for i, hp := range p.HeaderOrder {
			out.Order[i] = HeaderPairSpec{Key: hp.Key, Value: hp.Value}
		}
	}
	return out
}

// flattenHTTP2 emits all HTTP/2 settings as discrete fields plus the resolved
// H2Config getters. Always emitted (every real preset has H2 state).
//
// Discrete settings fields are always populated, even for zero values, so
// round-trip preserves explicit zeros (e.g. Chrome's MaxFrameSize=0 omitted).
// The Akamai shorthand is never emitted — discrete fields are unambiguous.
func flattenHTTP2(p *Preset) *HTTP2Spec {
	out := &HTTP2Spec{}

	s := p.HTTP2Settings
	htSize := s.HeaderTableSize
	out.HeaderTableSize = &htSize
	enablePush := s.EnablePush
	out.EnablePush = &enablePush
	maxConcurrent := s.MaxConcurrentStreams
	out.MaxConcurrentStreams = &maxConcurrent
	initialWindow := s.InitialWindowSize
	out.InitialWindowSize = &initialWindow
	maxFrame := s.MaxFrameSize
	out.MaxFrameSize = &maxFrame
	maxHeaderList := s.MaxHeaderListSize
	out.MaxHeaderListSize = &maxHeaderList
	connWindow := s.ConnectionWindowUpdate
	out.ConnectionWindowUpdate = &connWindow
	streamWeight := s.StreamWeight
	out.StreamWeight = &streamWeight
	streamExcl := s.StreamExclusive
	out.StreamExclusive = &streamExcl
	noRFC := s.NoRFC7540Priorities
	out.NoRFC7540Priorities = &noRFC

	// H2Config: dump resolved values via getters. nil-safe.
	out.HPACKHeaderOrder = append([]string(nil), p.H2HeaderOrder()...)
	policy := p.H2HPACKIndexingPolicy()
	out.HPACKIndexingPolicy = &policy
	out.HPACKNeverIndex = append([]string(nil), p.H2HPACKNeverIndex()...)
	priorityMode := p.H2StreamPriorityMode()
	out.StreamPriorityMode = &priorityMode
	disableCookie := p.H2DisableCookieSplit()
	out.DisableCookieSplit = &disableCookie

	if so := p.H2SettingsOrder(); so != nil {
		out.SettingsOrder = append([]uint16(nil), so...)
	}
	if po := p.H2PseudoHeaderOrder(); po != nil {
		out.PseudoOrder = append([]string(nil), po...)
	}

	return out
}

// flattenHTTP3 dumps the resolved H3Config getters. Only called when
// SupportHTTP3 is true (per flattenToSpec).
func flattenHTTP3(p *Preset) *HTTP3Spec {
	out := &HTTP3Spec{}

	qpackCap := p.H3QPACKMaxTableCapacity()
	out.QPACKMaxTableCapacity = &qpackCap
	qpackBlocked := p.H3QPACKBlockedStreams()
	out.QPACKBlockedStreams = &qpackBlocked
	maxField := p.H3MaxFieldSectionSize()
	out.MaxFieldSectionSize = &maxField
	enableDatagrams := p.H3EnableDatagrams()
	out.EnableDatagrams = &enableDatagrams
	pktSize := p.H3QUICInitialPacketSize()
	out.QUICInitialPacketSize = &pktSize
	maxStreams := p.H3QUICMaxIncomingStreams()
	out.QUICMaxIncomingStreams = &maxStreams
	maxUniStreams := p.H3QUICMaxIncomingUniStreams()
	out.QUICMaxIncomingUniStreams = &maxUniStreams
	allow0RTT := p.H3QUICAllow0RTT()
	out.QUICAllow0RTT = &allow0RTT
	chromeStyle := p.H3QUICChromeStyleInitial()
	out.QUICChromeStyleInitial = &chromeStyle
	disableScramble := p.H3QUICDisableHelloScramble()
	out.QUICDisableHelloScramble = &disableScramble
	paramOrder := p.H3QUICTransportParamOrder()
	out.QUICTransportParamOrder = &paramOrder
	cidLen := p.H3QUICConnectionIDLength()
	out.QUICConnectionIDLength = &cidLen
	maxDgram := p.H3QUICMaxDatagramFrameSize()
	out.QUICMaxDatagramFrameSize = &maxDgram
	maxRespHdr := p.H3MaxResponseHeaderBytes()
	out.MaxResponseHeaderBytes = &maxRespHdr
	grease := p.H3SendGreaseFrames()
	out.SendGreaseFrames = &grease

	// Optional flow-control overrides — only emit when set explicitly so
	// presets that leave them at quic-go defaults (the vast majority) don't
	// collect noisy zero-value entries in their describe output.
	if p.H3Config != nil && p.H3Config.QUICInitialStreamReceiveWindow != nil {
		v := *p.H3Config.QUICInitialStreamReceiveWindow
		out.QUICInitialStreamReceiveWindow = &v
	}
	if p.H3Config != nil && p.H3Config.QUICInitialConnectionReceiveWindow != nil {
		v := *p.H3Config.QUICInitialConnectionReceiveWindow
		out.QUICInitialConnectionReceiveWindow = &v
	}

	return out
}

// flattenTCP returns nil if all TCP fingerprint fields are zero (no TCP
// fingerprint configured). Otherwise emits the discrete fields. The
// "platform" shorthand is input-only — describe never emits it.
func flattenTCP(p *Preset) *TCPSpec {
	t := p.TCPFingerprint
	if t.TTL == 0 && t.MSS == 0 && t.WindowSize == 0 && t.WindowScale == 0 && !t.DFBit {
		return nil
	}
	out := &TCPSpec{}
	ttl := t.TTL
	out.TTL = &ttl
	mss := t.MSS
	out.MSS = &mss
	winSize := t.WindowSize
	out.WindowSize = &winSize
	winScale := t.WindowScale
	out.WindowScale = &winScale
	df := t.DFBit
	out.DFBit = &df
	return out
}

// certCompAlgsToNames is the inverse of parseCertCompAlgs in custom_preset.go.
// Unknown algs are skipped (unreachable in practice — utls only has 3).
func certCompAlgsToNames(algs []tls.CertCompressionAlgo) []string {
	out := make([]string, 0, len(algs))
	for _, a := range algs {
		switch a {
		case tls.CertCompressionBrotli:
			out = append(out, "brotli")
		case tls.CertCompressionZlib:
			out = append(out, "zlib")
		case tls.CertCompressionZstd:
			out = append(out, "zstd")
		}
	}
	return out
}

// marshalCanonical produces deterministic indented JSON. Settings used:
//   - 2-space indent
//   - Map keys sorted (Go's json.Marshal default for map[string]X)
//   - HTML escaping disabled (we emit User-Agent strings unmodified)
//   - Trailing newline (encoder default)
func marshalCanonical(pf *PresetFile) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(pf); err != nil {
		return "", fmt.Errorf("marshal preset: %w", err)
	}
	return buf.String(), nil
}
