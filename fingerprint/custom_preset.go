package fingerprint

import (
	"encoding/json"
	"fmt"
	"os"

	tls "github.com/sardanioss/utls"
)

// --- JSON Types ---

// PresetFile is the top-level JSON structure for preset files.
type PresetFile struct {
	Version int         `json:"version"`
	Preset  *PresetSpec `json:"preset,omitempty"`
	Pool    *PoolSpec   `json:"pool,omitempty"`
}

// PoolSpec defines a pool of presets for rotation.
type PoolSpec struct {
	Name     string       `json:"name"`
	Strategy string       `json:"strategy"` // "random" or "round-robin"
	Presets  []PresetSpec `json:"presets"`
}

// PresetSpec defines a single preset in JSON.
type PresetSpec struct {
	Name     string        `json:"name"`
	BasedOn  string        `json:"based_on,omitempty"`
	TLS      *TLSSpec      `json:"tls,omitempty"`
	HTTP2    *HTTP2Spec    `json:"http2,omitempty"`
	HTTP3    *HTTP3Spec    `json:"http3,omitempty"`
	Headers  *HeaderSpec   `json:"headers,omitempty"`
	TCP      *TCPSpec      `json:"tcp,omitempty"`
	Protocol *ProtocolSpec `json:"protocols,omitempty"`
}

// TLSSpec defines TLS fingerprint configuration.
type TLSSpec struct {
	// Mutually exclusive: use client_hello OR ja3, not both
	ClientHello     string `json:"client_hello,omitempty"`      // e.g., "chrome-146-windows"
	PSKClientHello  string `json:"psk_client_hello,omitempty"`  // e.g., "chrome-146-windows-psk"
	QUICClientHello string `json:"quic_client_hello,omitempty"` // e.g., "chrome-146-quic"
	QUICPSKClientHello string `json:"quic_psk_client_hello,omitempty"`

	JA3 string    `json:"ja3,omitempty"` // JA3 string
	JA3ExtrasSpec *JA3ExtrasSpec `json:"ja3_extras,omitempty"`

	// Individual extension data (supplements client_hello or ja3)
	SignatureAlgorithms            []uint16 `json:"signature_algorithms,omitempty"`
	DelegatedCredentialAlgorithms  []uint16 `json:"delegated_credential_algorithms,omitempty"`
	ALPN                           []string `json:"alpn,omitempty"`
	CertCompression    []string `json:"cert_compression,omitempty"` // "brotli", "zlib", "zstd"
	PermuteExtensions  *bool    `json:"permute_extensions,omitempty"`
	RecordSizeLimit    *uint16  `json:"record_size_limit,omitempty"`
	KeyShareCurves     *int     `json:"key_share_curves,omitempty"` // number of curves to send key shares for; nil/0 = 1
}

// JA3ExtrasSpec is the JSON representation of JA3Extras.
type JA3ExtrasSpec struct {
	SignatureAlgorithms            []uint16 `json:"signature_algorithms,omitempty"`
	DelegatedCredentialAlgorithms  []uint16 `json:"delegated_credential_algorithms,omitempty"`
	ALPN                           []string `json:"alpn,omitempty"`
	CertCompression                []string `json:"cert_compression,omitempty"`
	PermuteExtensions              *bool    `json:"permute_extensions,omitempty"`
	RecordSizeLimit                *uint16  `json:"record_size_limit,omitempty"`
	KeyShareCurves                 *int     `json:"key_share_curves,omitempty"`
}

// HTTP2Spec defines HTTP/2 fingerprint configuration.
type HTTP2Spec struct {
	// Akamai string (parsed first, then individual fields overlay)
	Akamai string `json:"akamai,omitempty"`

	// Individual SETTINGS fields (overlay on top of akamai if both set)
	HeaderTableSize      *uint32 `json:"header_table_size,omitempty"`
	EnablePush           *bool   `json:"enable_push,omitempty"`
	MaxConcurrentStreams  *uint32 `json:"max_concurrent_streams,omitempty"`
	InitialWindowSize    *uint32 `json:"initial_window_size,omitempty"`
	MaxFrameSize         *uint32 `json:"max_frame_size,omitempty"`
	MaxHeaderListSize    *uint32 `json:"max_header_list_size,omitempty"`
	ConnectionWindowUpdate *uint32 `json:"connection_window_update,omitempty"`
	StreamWeight         *uint16 `json:"stream_weight,omitempty"`
	StreamExclusive      *bool   `json:"stream_exclusive,omitempty"`
	NoRFC7540Priorities  *bool   `json:"no_rfc7540_priorities,omitempty"`

	// H2 fingerprinting config
	Settings      []HTTP2SettingSpec `json:"settings,omitempty"`
	SettingsOrder []uint16           `json:"settings_order,omitempty"`
	PseudoOrder   []string           `json:"pseudo_order,omitempty"`

	// HPACK config
	HPACKHeaderOrder    []string `json:"hpack_header_order,omitempty"`
	HPACKIndexingPolicy *string  `json:"hpack_indexing_policy,omitempty"` // "chrome","never","always","default"
	HPACKNeverIndex     []string `json:"hpack_never_index,omitempty"`
	StreamPriorityMode  *string  `json:"stream_priority_mode,omitempty"` // "chrome","default"
	DisableCookieSplit  *bool    `json:"disable_cookie_split,omitempty"`
}

// HTTP2SettingSpec represents a single HTTP/2 SETTINGS frame entry.
type HTTP2SettingSpec struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

// HTTP3Spec defines HTTP/3 and QUIC fingerprint configuration.
type HTTP3Spec struct {
	QPACKMaxTableCapacity        *uint64 `json:"qpack_max_table_capacity,omitempty"`
	QPACKBlockedStreams           *uint64 `json:"qpack_blocked_streams,omitempty"`
	MaxFieldSectionSize          *uint64 `json:"max_field_section_size,omitempty"`
	EnableDatagrams              *bool   `json:"enable_datagrams,omitempty"`
	QUICInitialPacketSize        *uint16 `json:"quic_initial_packet_size,omitempty"`
	QUICMaxIncomingStreams        *int64  `json:"quic_max_incoming_streams,omitempty"`
	QUICMaxIncomingUniStreams     *int64  `json:"quic_max_incoming_uni_streams,omitempty"`
	QUICAllow0RTT                *bool   `json:"quic_allow_0rtt,omitempty"`
	QUICChromeStyleInitial       *bool   `json:"quic_chrome_style_initial,omitempty"`
	QUICDisableHelloScramble     *bool   `json:"quic_disable_hello_scramble,omitempty"`
	QUICTransportParamOrder      *string `json:"quic_transport_param_order,omitempty"` // "chrome","random"
	QUICConnectionIDLength       *int    `json:"quic_connection_id_length,omitempty"`
	QUICMaxDatagramFrameSize     *uint64 `json:"quic_max_datagram_frame_size,omitempty"`
	MaxResponseHeaderBytes       *uint64 `json:"max_response_header_bytes,omitempty"`
	SendGreaseFrames             *bool   `json:"send_grease_frames,omitempty"`

	// QUIC flow-control windows. These map to quic.Config fields and ultimately
	// to wire transport parameters initial_max_data (4) and initial_max_stream_data_*
	// (5/6/7). nil = quic-go default. iOS Chrome / Safari uses larger conn (16 MiB)
	// + smaller per-stream (2 MiB) than Chrome desktop.
	QUICInitialStreamReceiveWindow     *uint64 `json:"quic_initial_stream_receive_window,omitempty"`
	QUICInitialConnectionReceiveWindow *uint64 `json:"quic_initial_connection_receive_window,omitempty"`
}

// HeaderSpec defines header fingerprint configuration.
type HeaderSpec struct {
	UserAgent string            `json:"user_agent,omitempty"`
	Values    map[string]string `json:"values,omitempty"`
	Order     []HeaderPairSpec  `json:"order,omitempty"`
}

// HeaderPairSpec is a key-value pair for ordered headers in JSON.
type HeaderPairSpec struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// TCPSpec defines TCP/IP fingerprint configuration.
type TCPSpec struct {
	Platform    string `json:"platform,omitempty"` // "Windows","macOS","Linux" — shorthand
	TTL         *int   `json:"ttl,omitempty"`
	MSS         *int   `json:"mss,omitempty"`
	WindowSize  *int   `json:"window_size,omitempty"`
	WindowScale *int   `json:"window_scale,omitempty"`
	DFBit       *bool  `json:"df_bit,omitempty"`
}

// ProtocolSpec defines protocol support.
type ProtocolSpec struct {
	HTTP3 *bool `json:"http3,omitempty"`
}

// --- Loading Functions ---

// LoadPresetFromFile reads and parses a JSON preset file.
func LoadPresetFromFile(path string) (*PresetFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read preset file: %w", err)
	}
	return LoadPresetFromJSON(data)
}

// LoadPresetFromJSON parses JSON bytes into a PresetFile.
func LoadPresetFromJSON(data []byte) (*PresetFile, error) {
	var pf PresetFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse preset JSON: %w", err)
	}
	return &pf, nil
}

// LoadAndBuildPreset is a convenience function: load + build a single preset from a file.
func LoadAndBuildPreset(path string) (*Preset, error) {
	pf, err := LoadPresetFromFile(path)
	if err != nil {
		return nil, err
	}
	if pf.Preset == nil {
		return nil, fmt.Errorf("preset file has no 'preset' field")
	}
	return BuildPreset(pf.Preset)
}

// LoadAndBuildPresetFromJSON is a convenience function: parse JSON + build a single preset.
func LoadAndBuildPresetFromJSON(data []byte) (*Preset, error) {
	pf, err := LoadPresetFromJSON(data)
	if err != nil {
		return nil, err
	}
	if pf.Preset == nil {
		return nil, fmt.Errorf("preset JSON has no 'preset' field")
	}
	return BuildPreset(pf.Preset)
}

// --- Core Build ---

// BuildPreset converts a PresetSpec (parsed from JSON) into a Preset.
// If based_on is set, clones the base preset first and overlays changes.
func BuildPreset(spec *PresetSpec) (*Preset, error) {
	if spec == nil {
		return nil, fmt.Errorf("preset spec is nil")
	}

	var p *Preset

	// Start from base preset or empty
	if spec.BasedOn != "" {
		base := GetStrict(spec.BasedOn)
		if base == nil {
			return nil, fmt.Errorf("unknown based_on preset: %q", spec.BasedOn)
		}
		p = clonePreset(base)
	} else {
		p = &Preset{}
	}

	// Set name
	if spec.Name != "" {
		p.Name = spec.Name
	}

	// Apply each section
	if spec.TLS != nil {
		if err := applyTLS(p, spec.TLS); err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
	}
	if spec.HTTP2 != nil {
		if err := applyHTTP2(p, spec.HTTP2); err != nil {
			return nil, fmt.Errorf("http2: %w", err)
		}
	}
	if spec.HTTP3 != nil {
		applyHTTP3(p, spec.HTTP3)
	}
	if spec.Headers != nil {
		applyHeaders(p, spec.Headers)
	}
	if spec.TCP != nil {
		if err := applyTCP(p, spec.TCP); err != nil {
			return nil, fmt.Errorf("tcp: %w", err)
		}
	}
	if spec.Protocol != nil {
		applyProtocols(p, spec.Protocol)
	}

	if err := validatePreset(p, spec); err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}

	return p, nil
}

// clonePreset performs a deep copy of a Preset.
func clonePreset(src *Preset) *Preset {
	dst := *src // shallow copy

	// Deep copy Headers map
	if src.Headers != nil {
		dst.Headers = make(map[string]string, len(src.Headers))
		for k, v := range src.Headers {
			dst.Headers[k] = v
		}
	}

	// Deep copy HeaderOrder slice
	if src.HeaderOrder != nil {
		dst.HeaderOrder = make([]HeaderPair, len(src.HeaderOrder))
		copy(dst.HeaderOrder, src.HeaderOrder)
	}

	// Deep copy H2Config
	if src.H2Config != nil {
		h2 := *src.H2Config
		if src.H2Config.HPACKHeaderOrder != nil {
			h2.HPACKHeaderOrder = make([]string, len(src.H2Config.HPACKHeaderOrder))
			copy(h2.HPACKHeaderOrder, src.H2Config.HPACKHeaderOrder)
		}
		if src.H2Config.HPACKNeverIndex != nil {
			h2.HPACKNeverIndex = make([]string, len(src.H2Config.HPACKNeverIndex))
			copy(h2.HPACKNeverIndex, src.H2Config.HPACKNeverIndex)
		}
		if src.H2Config.SettingsOrder != nil {
			h2.SettingsOrder = make([]uint16, len(src.H2Config.SettingsOrder))
			copy(h2.SettingsOrder, src.H2Config.SettingsOrder)
		}
		if src.H2Config.PseudoHeaderOrder != nil {
			h2.PseudoHeaderOrder = make([]string, len(src.H2Config.PseudoHeaderOrder))
			copy(h2.PseudoHeaderOrder, src.H2Config.PseudoHeaderOrder)
		}
		if src.H2Config.DisableCookieSplit != nil {
			v := *src.H2Config.DisableCookieSplit
			h2.DisableCookieSplit = &v
		}
		dst.H2Config = &h2
	}

	// Deep copy H3Config
	if src.H3Config != nil {
		h3 := *src.H3Config
		if src.H3Config.QPACKMaxTableCapacity != nil {
			v := *src.H3Config.QPACKMaxTableCapacity
			h3.QPACKMaxTableCapacity = &v
		}
		if src.H3Config.QPACKBlockedStreams != nil {
			v := *src.H3Config.QPACKBlockedStreams
			h3.QPACKBlockedStreams = &v
		}
		if src.H3Config.MaxFieldSectionSize != nil {
			v := *src.H3Config.MaxFieldSectionSize
			h3.MaxFieldSectionSize = &v
		}
		if src.H3Config.EnableDatagrams != nil {
			v := *src.H3Config.EnableDatagrams
			h3.EnableDatagrams = &v
		}
		if src.H3Config.QUICInitialPacketSize != nil {
			v := *src.H3Config.QUICInitialPacketSize
			h3.QUICInitialPacketSize = &v
		}
		if src.H3Config.QUICMaxIncomingStreams != nil {
			v := *src.H3Config.QUICMaxIncomingStreams
			h3.QUICMaxIncomingStreams = &v
		}
		if src.H3Config.QUICMaxIncomingUniStreams != nil {
			v := *src.H3Config.QUICMaxIncomingUniStreams
			h3.QUICMaxIncomingUniStreams = &v
		}
		if src.H3Config.QUICAllow0RTT != nil {
			v := *src.H3Config.QUICAllow0RTT
			h3.QUICAllow0RTT = &v
		}
		if src.H3Config.QUICChromeStyleInitial != nil {
			v := *src.H3Config.QUICChromeStyleInitial
			h3.QUICChromeStyleInitial = &v
		}
		if src.H3Config.QUICDisableHelloScramble != nil {
			v := *src.H3Config.QUICDisableHelloScramble
			h3.QUICDisableHelloScramble = &v
		}
		if src.H3Config.MaxResponseHeaderBytes != nil {
			v := *src.H3Config.MaxResponseHeaderBytes
			h3.MaxResponseHeaderBytes = &v
		}
		if src.H3Config.QUICConnectionIDLength != nil {
			v := *src.H3Config.QUICConnectionIDLength
			h3.QUICConnectionIDLength = &v
		}
		if src.H3Config.QUICMaxDatagramFrameSize != nil {
			v := *src.H3Config.QUICMaxDatagramFrameSize
			h3.QUICMaxDatagramFrameSize = &v
		}
		if src.H3Config.SendGreaseFrames != nil {
			v := *src.H3Config.SendGreaseFrames
			h3.SendGreaseFrames = &v
		}
		if src.H3Config.QUICInitialStreamReceiveWindow != nil {
			v := *src.H3Config.QUICInitialStreamReceiveWindow
			h3.QUICInitialStreamReceiveWindow = &v
		}
		if src.H3Config.QUICInitialConnectionReceiveWindow != nil {
			v := *src.H3Config.QUICInitialConnectionReceiveWindow
			h3.QUICInitialConnectionReceiveWindow = &v
		}
		dst.H3Config = &h3
	}

	// Deep copy JA3Extras
	if src.JA3Extras != nil {
		extras := *src.JA3Extras
		if src.JA3Extras.SignatureAlgorithms != nil {
			extras.SignatureAlgorithms = make([]tls.SignatureScheme, len(src.JA3Extras.SignatureAlgorithms))
			copy(extras.SignatureAlgorithms, src.JA3Extras.SignatureAlgorithms)
		}
		if src.JA3Extras.DelegatedCredentialAlgorithms != nil {
			extras.DelegatedCredentialAlgorithms = make([]tls.SignatureScheme, len(src.JA3Extras.DelegatedCredentialAlgorithms))
			copy(extras.DelegatedCredentialAlgorithms, src.JA3Extras.DelegatedCredentialAlgorithms)
		}
		if src.JA3Extras.ALPN != nil {
			extras.ALPN = make([]string, len(src.JA3Extras.ALPN))
			copy(extras.ALPN, src.JA3Extras.ALPN)
		}
		if src.JA3Extras.CertCompAlgs != nil {
			extras.CertCompAlgs = make([]tls.CertCompressionAlgo, len(src.JA3Extras.CertCompAlgs))
			copy(extras.CertCompAlgs, src.JA3Extras.CertCompAlgs)
		}
		dst.JA3Extras = &extras
	}

	return &dst
}

// --- Apply Functions ---

func applyTLS(p *Preset, spec *TLSSpec) error {
	// ja3 and client_hello are mutually exclusive (validated catches both set)
	if spec.JA3 != "" {
		p.JA3 = spec.JA3
		// Clear ClientHelloID fields — JA3 takes over TLS fingerprinting
		p.ClientHelloID = tls.ClientHelloID{}
		p.PSKClientHelloID = tls.ClientHelloID{}
		p.QUICClientHelloID = tls.ClientHelloID{}
		p.QUICPSKClientHelloID = tls.ClientHelloID{}
		// Build JA3Extras from the spec
		if spec.JA3ExtrasSpec != nil {
			extras, err := buildJA3Extras(spec.JA3ExtrasSpec)
			if err != nil {
				return fmt.Errorf("ja3_extras: %w", err)
			}
			p.JA3Extras = extras
		} else {
			// Check if top-level TLS fields provide extras
			extras, err := buildJA3ExtrasFromTLS(spec)
			if err != nil {
				return fmt.Errorf("ja3 extras: %w", err)
			}
			if extras != nil {
				p.JA3Extras = extras
			}
		}
	} else if spec.ClientHello != "" {
		// Clear JA3 fields — ClientHelloID takes over TLS fingerprinting
		p.JA3 = ""
		p.JA3Extras = nil

		id, err := ResolveClientHelloID(spec.ClientHello)
		if err != nil {
			return err
		}
		p.ClientHelloID = id

		if spec.PSKClientHello != "" {
			pskID, err := ResolveClientHelloID(spec.PSKClientHello)
			if err != nil {
				return fmt.Errorf("psk: %w", err)
			}
			p.PSKClientHelloID = pskID
		}
		if spec.QUICClientHello != "" {
			quicID, err := ResolveClientHelloID(spec.QUICClientHello)
			if err != nil {
				return fmt.Errorf("quic: %w", err)
			}
			p.QUICClientHelloID = quicID
		}
		if spec.QUICPSKClientHello != "" {
			quicPSKID, err := ResolveClientHelloID(spec.QUICPSKClientHello)
			if err != nil {
				return fmt.Errorf("quic_psk: %w", err)
			}
			p.QUICPSKClientHelloID = quicPSKID
		}
	} else {
		// Neither JA3 nor ClientHello in this spec — overlay PSK/QUIC hellos
		// on the inherited base preset (if any of these fields are set).
		if spec.PSKClientHello != "" {
			pskID, err := ResolveClientHelloID(spec.PSKClientHello)
			if err != nil {
				return fmt.Errorf("psk: %w", err)
			}
			p.PSKClientHelloID = pskID
		}
		if spec.QUICClientHello != "" {
			quicID, err := ResolveClientHelloID(spec.QUICClientHello)
			if err != nil {
				return fmt.Errorf("quic: %w", err)
			}
			p.QUICClientHelloID = quicID
		}
		if spec.QUICPSKClientHello != "" {
			quicPSKID, err := ResolveClientHelloID(spec.QUICPSKClientHello)
			if err != nil {
				return fmt.Errorf("quic_psk: %w", err)
			}
			p.QUICPSKClientHelloID = quicPSKID
		}
	}

	return nil
}

func buildJA3Extras(spec *JA3ExtrasSpec) (*JA3Extras, error) {
	extras := &JA3Extras{}

	if len(spec.SignatureAlgorithms) > 0 {
		extras.SignatureAlgorithms = make([]tls.SignatureScheme, len(spec.SignatureAlgorithms))
		for i, v := range spec.SignatureAlgorithms {
			extras.SignatureAlgorithms[i] = tls.SignatureScheme(v)
		}
	}
	if len(spec.DelegatedCredentialAlgorithms) > 0 {
		extras.DelegatedCredentialAlgorithms = make([]tls.SignatureScheme, len(spec.DelegatedCredentialAlgorithms))
		for i, v := range spec.DelegatedCredentialAlgorithms {
			extras.DelegatedCredentialAlgorithms[i] = tls.SignatureScheme(v)
		}
	}
	if len(spec.ALPN) > 0 {
		extras.ALPN = make([]string, len(spec.ALPN))
		copy(extras.ALPN, spec.ALPN)
	}
	if len(spec.CertCompression) > 0 {
		algs, err := parseCertCompAlgs(spec.CertCompression)
		if err != nil {
			return nil, err
		}
		extras.CertCompAlgs = algs
	}
	if spec.PermuteExtensions != nil {
		extras.PermuteExtensions = *spec.PermuteExtensions
	}
	if spec.RecordSizeLimit != nil {
		extras.RecordSizeLimit = *spec.RecordSizeLimit
	}
	if spec.KeyShareCurves != nil {
		extras.KeyShareCurves = *spec.KeyShareCurves
	}

	return extras, nil
}

func buildJA3ExtrasFromTLS(spec *TLSSpec) (*JA3Extras, error) {
	// Check if any top-level TLS fields are set that would create extras
	hasSigAlgs := len(spec.SignatureAlgorithms) > 0
	hasDCAlgs := len(spec.DelegatedCredentialAlgorithms) > 0
	hasALPN := len(spec.ALPN) > 0
	hasCertComp := len(spec.CertCompression) > 0
	hasPermute := spec.PermuteExtensions != nil
	hasRSL := spec.RecordSizeLimit != nil
	hasKSC := spec.KeyShareCurves != nil

	if !hasSigAlgs && !hasDCAlgs && !hasALPN && !hasCertComp && !hasPermute && !hasRSL && !hasKSC {
		return nil, nil
	}

	extras := &JA3Extras{}
	if hasSigAlgs {
		extras.SignatureAlgorithms = make([]tls.SignatureScheme, len(spec.SignatureAlgorithms))
		for i, v := range spec.SignatureAlgorithms {
			extras.SignatureAlgorithms[i] = tls.SignatureScheme(v)
		}
	}
	if hasDCAlgs {
		extras.DelegatedCredentialAlgorithms = make([]tls.SignatureScheme, len(spec.DelegatedCredentialAlgorithms))
		for i, v := range spec.DelegatedCredentialAlgorithms {
			extras.DelegatedCredentialAlgorithms[i] = tls.SignatureScheme(v)
		}
	}
	if hasALPN {
		extras.ALPN = make([]string, len(spec.ALPN))
		copy(extras.ALPN, spec.ALPN)
	}
	if hasCertComp {
		algs, err := parseCertCompAlgs(spec.CertCompression)
		if err != nil {
			return nil, err
		}
		extras.CertCompAlgs = algs
	}
	if hasPermute {
		extras.PermuteExtensions = *spec.PermuteExtensions
	}
	if hasRSL {
		extras.RecordSizeLimit = *spec.RecordSizeLimit
	}
	if hasKSC {
		extras.KeyShareCurves = *spec.KeyShareCurves
	}

	return extras, nil
}

func parseCertCompAlgs(names []string) ([]tls.CertCompressionAlgo, error) {
	algs := make([]tls.CertCompressionAlgo, 0, len(names))
	for _, name := range names {
		switch name {
		case "brotli":
			algs = append(algs, tls.CertCompressionBrotli)
		case "zlib":
			algs = append(algs, tls.CertCompressionZlib)
		case "zstd":
			algs = append(algs, tls.CertCompressionZstd)
		default:
			return nil, fmt.Errorf("unknown cert compression algorithm: %q (valid: brotli, zlib, zstd)", name)
		}
	}
	return algs, nil
}

func applyHTTP2(p *Preset, spec *HTTP2Spec) error {
	// Parse akamai string first if provided
	if spec.Akamai != "" {
		settings, pseudoOrder, err := ParseAkamai(spec.Akamai)
		if err != nil {
			return fmt.Errorf("akamai: %w", err)
		}
		p.HTTP2Settings = *settings
		// Apply pseudo order to H2Config
		if len(pseudoOrder) > 0 {
			if p.H2Config == nil {
				p.H2Config = &H2FingerprintConfig{}
			}
			p.H2Config.PseudoHeaderOrder = pseudoOrder
		}
	}

	// Individual SETTINGS fields overlay on top of akamai
	if spec.HeaderTableSize != nil {
		p.HTTP2Settings.HeaderTableSize = *spec.HeaderTableSize
	}
	if spec.EnablePush != nil {
		p.HTTP2Settings.EnablePush = *spec.EnablePush
	}
	if spec.MaxConcurrentStreams != nil {
		p.HTTP2Settings.MaxConcurrentStreams = *spec.MaxConcurrentStreams
	}
	if spec.InitialWindowSize != nil {
		p.HTTP2Settings.InitialWindowSize = *spec.InitialWindowSize
	}
	if spec.MaxFrameSize != nil {
		p.HTTP2Settings.MaxFrameSize = *spec.MaxFrameSize
	}
	if spec.MaxHeaderListSize != nil {
		p.HTTP2Settings.MaxHeaderListSize = *spec.MaxHeaderListSize
	}
	if spec.ConnectionWindowUpdate != nil {
		p.HTTP2Settings.ConnectionWindowUpdate = *spec.ConnectionWindowUpdate
	}
	if spec.StreamWeight != nil {
		p.HTTP2Settings.StreamWeight = *spec.StreamWeight
	}
	if spec.StreamExclusive != nil {
		p.HTTP2Settings.StreamExclusive = *spec.StreamExclusive
	}
	if spec.NoRFC7540Priorities != nil {
		p.HTTP2Settings.NoRFC7540Priorities = *spec.NoRFC7540Priorities
	}

	// Apply SETTINGS from structured list (overrides akamai/individual if same ID)
	for _, s := range spec.Settings {
		switch s.ID {
		case 1:
			p.HTTP2Settings.HeaderTableSize = s.Value
		case 2:
			p.HTTP2Settings.EnablePush = s.Value != 0
		case 3:
			p.HTTP2Settings.MaxConcurrentStreams = s.Value
		case 4:
			p.HTTP2Settings.InitialWindowSize = s.Value
		case 5:
			p.HTTP2Settings.MaxFrameSize = s.Value
		case 6:
			p.HTTP2Settings.MaxHeaderListSize = s.Value
		case 9:
			p.HTTP2Settings.NoRFC7540Priorities = s.Value != 0
		}
	}

	// H2 fingerprinting config
	if spec.SettingsOrder != nil || spec.PseudoOrder != nil ||
		spec.HPACKHeaderOrder != nil || spec.HPACKIndexingPolicy != nil ||
		spec.HPACKNeverIndex != nil || spec.StreamPriorityMode != nil ||
		spec.DisableCookieSplit != nil {
		if p.H2Config == nil {
			p.H2Config = &H2FingerprintConfig{}
		}
	}
	if p.H2Config != nil {
		if spec.SettingsOrder != nil {
			p.H2Config.SettingsOrder = make([]uint16, len(spec.SettingsOrder))
			copy(p.H2Config.SettingsOrder, spec.SettingsOrder)
		}
		if spec.PseudoOrder != nil {
			p.H2Config.PseudoHeaderOrder = make([]string, len(spec.PseudoOrder))
			copy(p.H2Config.PseudoHeaderOrder, spec.PseudoOrder)
		}
		if spec.HPACKHeaderOrder != nil {
			p.H2Config.HPACKHeaderOrder = make([]string, len(spec.HPACKHeaderOrder))
			copy(p.H2Config.HPACKHeaderOrder, spec.HPACKHeaderOrder)
		}
		if spec.HPACKIndexingPolicy != nil {
			p.H2Config.HPACKIndexingPolicy = *spec.HPACKIndexingPolicy
		}
		if spec.HPACKNeverIndex != nil {
			p.H2Config.HPACKNeverIndex = make([]string, len(spec.HPACKNeverIndex))
			copy(p.H2Config.HPACKNeverIndex, spec.HPACKNeverIndex)
		}
		if spec.StreamPriorityMode != nil {
			p.H2Config.StreamPriorityMode = *spec.StreamPriorityMode
		}
		if spec.DisableCookieSplit != nil {
			v := *spec.DisableCookieSplit
			p.H2Config.DisableCookieSplit = &v
		}
	}

	return nil
}

func applyHTTP3(p *Preset, spec *HTTP3Spec) {
	if p.H3Config == nil {
		p.H3Config = &H3FingerprintConfig{}
	}
	h3 := p.H3Config

	if spec.QPACKMaxTableCapacity != nil {
		v := *spec.QPACKMaxTableCapacity
		h3.QPACKMaxTableCapacity = &v
	}
	if spec.QPACKBlockedStreams != nil {
		v := *spec.QPACKBlockedStreams
		h3.QPACKBlockedStreams = &v
	}
	if spec.MaxFieldSectionSize != nil {
		v := *spec.MaxFieldSectionSize
		h3.MaxFieldSectionSize = &v
	}
	if spec.EnableDatagrams != nil {
		v := *spec.EnableDatagrams
		h3.EnableDatagrams = &v
	}
	if spec.QUICInitialPacketSize != nil {
		v := *spec.QUICInitialPacketSize
		h3.QUICInitialPacketSize = &v
	}
	if spec.QUICMaxIncomingStreams != nil {
		v := *spec.QUICMaxIncomingStreams
		h3.QUICMaxIncomingStreams = &v
	}
	if spec.QUICMaxIncomingUniStreams != nil {
		v := *spec.QUICMaxIncomingUniStreams
		h3.QUICMaxIncomingUniStreams = &v
	}
	if spec.QUICAllow0RTT != nil {
		v := *spec.QUICAllow0RTT
		h3.QUICAllow0RTT = &v
	}
	if spec.QUICChromeStyleInitial != nil {
		v := *spec.QUICChromeStyleInitial
		h3.QUICChromeStyleInitial = &v
	}
	if spec.QUICDisableHelloScramble != nil {
		v := *spec.QUICDisableHelloScramble
		h3.QUICDisableHelloScramble = &v
	}
	if spec.QUICTransportParamOrder != nil {
		h3.QUICTransportParamOrder = *spec.QUICTransportParamOrder
	}
	if spec.QUICConnectionIDLength != nil {
		v := *spec.QUICConnectionIDLength
		h3.QUICConnectionIDLength = &v
	}
	if spec.QUICMaxDatagramFrameSize != nil {
		v := *spec.QUICMaxDatagramFrameSize
		h3.QUICMaxDatagramFrameSize = &v
	}
	if spec.MaxResponseHeaderBytes != nil {
		v := *spec.MaxResponseHeaderBytes
		h3.MaxResponseHeaderBytes = &v
	}
	if spec.SendGreaseFrames != nil {
		v := *spec.SendGreaseFrames
		h3.SendGreaseFrames = &v
	}
	if spec.QUICInitialStreamReceiveWindow != nil {
		v := *spec.QUICInitialStreamReceiveWindow
		h3.QUICInitialStreamReceiveWindow = &v
	}
	if spec.QUICInitialConnectionReceiveWindow != nil {
		v := *spec.QUICInitialConnectionReceiveWindow
		h3.QUICInitialConnectionReceiveWindow = &v
	}
}

func applyHeaders(p *Preset, spec *HeaderSpec) {
	if spec.UserAgent != "" {
		p.UserAgent = spec.UserAgent
	}

	// Merge values into Headers map
	if len(spec.Values) > 0 {
		if p.Headers == nil {
			p.Headers = make(map[string]string)
		}
		for k, v := range spec.Values {
			p.Headers[k] = v
		}
	}

	// Convert Order to HeaderOrder
	if len(spec.Order) > 0 {
		p.HeaderOrder = make([]HeaderPair, len(spec.Order))
		for i, hp := range spec.Order {
			p.HeaderOrder[i] = HeaderPair{Key: hp.Key, Value: hp.Value}
		}
	}
}

func applyTCP(p *Preset, spec *TCPSpec) error {
	// Platform shorthand first
	if spec.Platform != "" {
		switch spec.Platform {
		case "Windows", "macOS", "Linux":
			p.TCPFingerprint = PlatformTCPFingerprint(spec.Platform)
		default:
			return fmt.Errorf("unknown TCP platform: %q (valid: Windows, macOS, Linux)", spec.Platform)
		}
	}

	// Individual fields override platform
	if spec.TTL != nil {
		p.TCPFingerprint.TTL = *spec.TTL
	}
	if spec.MSS != nil {
		p.TCPFingerprint.MSS = *spec.MSS
	}
	if spec.WindowSize != nil {
		p.TCPFingerprint.WindowSize = *spec.WindowSize
	}
	if spec.WindowScale != nil {
		p.TCPFingerprint.WindowScale = *spec.WindowScale
	}
	if spec.DFBit != nil {
		p.TCPFingerprint.DFBit = *spec.DFBit
	}
	return nil
}

func applyProtocols(p *Preset, spec *ProtocolSpec) {
	if spec.HTTP3 != nil {
		p.SupportHTTP3 = *spec.HTTP3
	}
}

// --- Validation ---

func validatePreset(p *Preset, spec *PresetSpec) error {
	if spec.TLS != nil {
		// ja3 and client_hello are mutually exclusive
		if spec.TLS.JA3 != "" && spec.TLS.ClientHello != "" {
			return fmt.Errorf("ja3 and client_hello are mutually exclusive")
		}
		// PSK/QUIC hello IDs require a primary client_hello or JA3 on the built preset
		// (could come from based_on inheritance, not just the spec)
		hasPrimary := p.ClientHelloID.Client != "" || p.JA3 != ""
		if !hasPrimary {
			if spec.TLS.PSKClientHello != "" {
				return fmt.Errorf("psk_client_hello requires client_hello to be set (directly or via based_on)")
			}
			if spec.TLS.QUICClientHello != "" {
				return fmt.Errorf("quic_client_hello requires client_hello to be set (directly or via based_on)")
			}
			if spec.TLS.QUICPSKClientHello != "" {
				return fmt.Errorf("quic_psk_client_hello requires client_hello to be set (directly or via based_on)")
			}
		}
		// JA3 mode cannot control QUIC TLS — check both spec and built preset
		isJA3Mode := p.JA3 != ""
		if isJA3Mode {
			if spec.TLS.QUICClientHello != "" {
				return fmt.Errorf("quic_client_hello cannot be used with ja3; JA3 does not control QUIC TLS fingerprinting — use client_hello mode instead")
			}
			if spec.TLS.QUICPSKClientHello != "" {
				return fmt.Errorf("quic_psk_client_hello cannot be used with ja3; JA3 does not control QUIC TLS fingerprinting — use client_hello mode instead")
			}
			if spec.TLS.PSKClientHello != "" {
				return fmt.Errorf("psk_client_hello cannot be used with ja3; use ja3_extras for PSK configuration instead")
			}
		}
		// ja3_extras without ja3 is invalid
		if spec.TLS.JA3ExtrasSpec != nil && spec.TLS.JA3 == "" {
			return fmt.Errorf("ja3_extras requires ja3 to be set")
		}
		// TLS extension fields (sig algs, ALPN, cert comp, etc.) only apply in ja3 mode
		hasExtFields := len(spec.TLS.SignatureAlgorithms) > 0 || len(spec.TLS.ALPN) > 0 ||
			len(spec.TLS.CertCompression) > 0 || spec.TLS.PermuteExtensions != nil ||
			spec.TLS.RecordSizeLimit != nil
		if hasExtFields && spec.TLS.JA3 == "" && spec.TLS.ClientHello != "" {
			return fmt.Errorf("tls extension fields (signature_algorithms, alpn, cert_compression, permute_extensions, record_size_limit) only apply with ja3, not client_hello")
		}
	}

	if spec.HTTP2 != nil {
		// Validate HPACK indexing policy
		if spec.HTTP2.HPACKIndexingPolicy != nil {
			switch *spec.HTTP2.HPACKIndexingPolicy {
			case "chrome", "never", "always", "default":
				// valid
			default:
				return fmt.Errorf("invalid hpack_indexing_policy: %q (must be chrome/never/always/default)", *spec.HTTP2.HPACKIndexingPolicy)
			}
		}

		// Validate stream priority mode
		if spec.HTTP2.StreamPriorityMode != nil {
			switch *spec.HTTP2.StreamPriorityMode {
			case "chrome", "default":
				// valid
			default:
				return fmt.Errorf("invalid stream_priority_mode: %q (must be chrome/default)", *spec.HTTP2.StreamPriorityMode)
			}
		}
	}

	if spec.HTTP3 != nil {
		// Validate QUIC transport param order
		if spec.HTTP3.QUICTransportParamOrder != nil {
			switch *spec.HTTP3.QUICTransportParamOrder {
			case "chrome", "random":
				// valid
			default:
				return fmt.Errorf("invalid quic_transport_param_order: %q (must be chrome/random)", *spec.HTTP3.QUICTransportParamOrder)
			}
		}
	}

	return nil
}
