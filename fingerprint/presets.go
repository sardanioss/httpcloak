package fingerprint

import (
	"runtime"

	tls "github.com/sardanioss/utls"
)

// PlatformInfo contains platform-specific header values
type PlatformInfo struct {
	UserAgentOS        string // e.g., "(Windows NT 10.0; Win64; x64)" or "(X11; Linux x86_64)"
	Platform           string // e.g., "Windows", "Linux", "macOS"
	Arch               string // e.g., "x86", "arm"
	PlatformVersion    string // e.g., "10.0.0", "6.12.0", "14.7.0"
	FirefoxUserAgentOS string // Firefox has slightly different format
}

// GetPlatformInfo returns platform-specific info based on runtime OS
func GetPlatformInfo() PlatformInfo {
	switch runtime.GOOS {
	case "windows":
		return PlatformInfo{
			UserAgentOS:        "(Windows NT 10.0; Win64; x64)",
			Platform:           "Windows",
			Arch:               "x86",
			PlatformVersion:    "10.0.0",
			FirefoxUserAgentOS: "(Windows NT 10.0; Win64; x64; rv:133.0)",
		}
	case "darwin":
		return PlatformInfo{
			UserAgentOS:        "(Macintosh; Intel Mac OS X 10_15_7)",
			Platform:           "macOS",
			Arch:               "arm",
			PlatformVersion:    "14.7.0",
			FirefoxUserAgentOS: "(Macintosh; Intel Mac OS X 10.15; rv:133.0)",
		}
	default: // linux and others
		return PlatformInfo{
			UserAgentOS:        "(X11; Linux x86_64)",
			Platform:           "Linux",
			Arch:               "x86",
			PlatformVersion:    "6.12.0",
			FirefoxUserAgentOS: "(X11; Linux x86_64; rv:133.0)",
		}
	}
}

// ClientHintsProfile holds preset-level values for the high-entropy UA client
// hints (the ones Chrome only sends after a host advertises Accept-CH). Every
// field is optional: an empty field is derived coherently from the preset's
// low-entropy sec-ch-ua trio and platform (see Preset.ResolveClientHints), so a
// preset only needs to spell out what differs from the coherent default. This is
// the single source of truth that keeps full-version-list, arch, platform-version
// etc. in lockstep with sec-ch-ua + User-Agent.
type ClientHintsProfile struct {
	FullVersionList string // sec-ch-ua-full-version-list; "" -> derived from sec-ch-ua (brands/order/GREASE preserved, versions expanded)
	PlatformVersion string // sec-ch-ua-platform-version override; "" -> platform default (Linux is "")
	Arch            string // sec-ch-ua-arch; "" -> platform default
	Bitness         string // sec-ch-ua-bitness; "" -> platform default
	Model           string // sec-ch-ua-model; "" -> platform default (desktop is "")
	Wow64           string // sec-ch-ua-wow64; "" -> "?0"
}

// HeaderPair represents a single header key-value pair for ordered headers
type HeaderPair struct {
	Key   string
	Value string
}

// Preset represents a browser fingerprint configuration
type Preset struct {
	Name                 string
	ClientHelloID        tls.ClientHelloID // For TCP/TLS (HTTP/1.1, HTTP/2)
	PSKClientHelloID     tls.ClientHelloID // For TCP/TLS with PSK (session resumption)
	QUICClientHelloID    tls.ClientHelloID // For QUIC/HTTP/3 (different TLS extensions)
	QUICPSKClientHelloID tls.ClientHelloID // For QUIC/HTTP/3 with PSK (session resumption)
	UserAgent            string
	Headers              map[string]string  // For backward compatibility
	HeaderOrder          []HeaderPair       // Ordered headers for HTTP/2
	ClientHints          ClientHintsProfile // High-entropy UA client hint overrides; empty fields are derived from sec-ch-ua (see Preset.ResolveClientHints)
	HTTP2Settings        HTTP2Settings
	TCPFingerprint       TCPFingerprint
	SupportHTTP3         bool
	DisableHTTP2         bool                 // When true, auto mode skips HTTP/2 and goes straight to HTTP/1.1 (zero value = H2 enabled)
	H2Config             *H2FingerprintConfig // nil = Chrome defaults for all H2 fingerprinting
	H3Config             *H3FingerprintConfig // nil = Chrome defaults for all H3/QUIC fingerprinting
	JA3                  string               // JA3 fingerprint string. When set, parsed fresh per connection instead of using ClientHelloID.
	JA3Extras            *JA3Extras           // Supplements JA3 parsing. nil = Chrome defaults.
	BasedOn              string               // For custom presets: name of the parent preset (used by inheritance-loop detection). Empty for built-ins.

	// SignatureAlgorithms, when non-empty, replaces the signature_algorithms
	// extension emitted on TCP (HTTP/1.1 + HTTP/2), on top of whatever base spec
	// the ClientHelloID (or JA3) produces. It lets a preset keep a byte-exact
	// hand-tuned base spec (correct ALPS/ECH/key_share/GREASE ordering) while
	// changing ONLY the sig-algs — e.g. adding Chrome 150's ML-DSA post-quantum
	// codepoints (0x0904-0x0906) on top of the Chrome 146 base. Values are raw
	// SignatureScheme (uint16) codepoints, so schemes uTLS has no named constant
	// for (like ML-DSA) are still emitted verbatim.
	SignatureAlgorithms []tls.SignatureScheme

	// QUICSignatureAlgorithms is the HTTP/3 (QUIC) counterpart of
	// SignatureAlgorithms. It is separate because a browser's QUIC ClientHello can
	// advertise a DIFFERENT sig-algs set than its TCP one — e.g. Chrome 150 sends
	// ML-DSA on TCP but NOT on QUIC (QUIC anti-amplification limits make large PQ
	// certificate chains impractical), and adds rsa_pkcs1_sha1 there instead.
	// Empty = leave the QUIC base ClientHelloID untouched.
	QUICSignatureAlgorithms []tls.SignatureScheme
}

// SpecFor generates the uTLS ClientHelloSpec for id at the given shuffle seed and
// overrides its signature_algorithms with sigAlgs (a no-op when sigAlgs is empty,
// so a stock preset keeps its byte-exact base). Callers pass the TCP list
// (Preset.SignatureAlgorithms) or the QUIC list (Preset.QUICSignatureAlgorithms).
// A drop-in replacement for tls.UTLSIdToSpecWithSeed so every transport spec path
// (H2/H3, fresh and PSK) can share one override point.
func SpecFor(id tls.ClientHelloID, seed int64, sigAlgs []tls.SignatureScheme) (*tls.ClientHelloSpec, error) {
	spec, err := tls.UTLSIdToSpecWithSeed(id, seed)
	if err != nil {
		return nil, err
	}
	ApplySignatureAlgorithms(spec.Extensions, sigAlgs)
	return &spec, nil
}

// ApplySignatureAlgorithms replaces the signature_algorithms extension's list in
// exts with algs when algs is non-empty. It operates on the shared []TLSExtension
// slice, so the ClientHelloID-direct path (H1, mutating a live UConn's Extensions)
// and the generated-spec path (H2/H3) use one override.
func ApplySignatureAlgorithms(exts []tls.TLSExtension, algs []tls.SignatureScheme) {
	if len(algs) == 0 {
		return
	}
	for _, ext := range exts {
		if sa, ok := ext.(*tls.SignatureAlgorithmsExtension); ok {
			sa.SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), algs...)
			return
		}
	}
}

// TCPFingerprint contains TCP/IP stack parameters that identify the OS.
// Anti-bot systems check TTL, window size, and other TCP options in the SYN packet
// to verify the claimed browser platform matches the actual OS.
type TCPFingerprint struct {
	TTL         int  // IP Time-To-Live: 128=Windows, 64=Linux/macOS/iOS/Android
	MSS         int  // TCP Maximum Segment Size: 1460 for standard Ethernet
	WindowSize  int  // TCP Window Size in SYN: 64240=Win10/11, 65535=Linux/macOS
	WindowScale int  // TCP Window Scale option: 8=Win10/11, 7=Linux/Android, 6=macOS/iOS
	DFBit       bool // IP Don't Fragment flag
}

// WindowsTCPFingerprint returns TCP fingerprint values for Windows 10/11
func WindowsTCPFingerprint() TCPFingerprint {
	return TCPFingerprint{TTL: 128, MSS: 1460, WindowSize: 64240, WindowScale: 8, DFBit: true}
}

// LinuxTCPFingerprint returns TCP fingerprint values for Linux
func LinuxTCPFingerprint() TCPFingerprint {
	return TCPFingerprint{TTL: 64, MSS: 1460, WindowSize: 65535, WindowScale: 7, DFBit: true}
}

// MacOSTCPFingerprint returns TCP fingerprint values for macOS
func MacOSTCPFingerprint() TCPFingerprint {
	return TCPFingerprint{TTL: 64, MSS: 1460, WindowSize: 65535, WindowScale: 6, DFBit: true}
}

// PlatformTCPFingerprint returns the TCP fingerprint matching the given platform string.
// Used by auto-platform presets that detect the running OS at runtime.
func PlatformTCPFingerprint(platform string) TCPFingerprint {
	switch platform {
	case "Windows":
		return WindowsTCPFingerprint()
	case "macOS":
		return MacOSTCPFingerprint()
	default:
		return LinuxTCPFingerprint()
	}
}

// HTTP2Settings contains HTTP/2 connection settings
type HTTP2Settings struct {
	HeaderTableSize      uint32
	EnablePush           bool
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32
	// Window update and stream settings
	ConnectionWindowUpdate uint32
	StreamWeight           uint16 // Chrome sends 255 on wire (set to 256, code does -1)
	StreamExclusive        bool
	// RFC 9218 - disables RFC 7540 stream priorities
	NoRFC7540Priorities bool
}

// H2FingerprintConfig controls HTTP/2 fingerprinting behavior beyond SETTINGS frame values.
// When nil on a Preset, all getters return Chrome defaults. Individual nil/zero fields
// also fall back to Chrome defaults, so you can override just the fields you need.
type H2FingerprintConfig struct {
	HPACKHeaderOrder    []string // HPACK wire encoding order. nil = Chrome 143 default.
	HPACKIndexingPolicy string   // "chrome"/"never"/"always"/"default". "" = "chrome".
	HPACKNeverIndex     []string // Headers never HPACK-indexed. nil = Chrome default.
	StreamPriorityMode  string   // "chrome"/"default". "" = "chrome".
	DisableCookieSplit  *bool    // nil = true (single field). Chrome+Firefox crumble (false); Safari single (true).
	SettingsOrder       []uint16 // H2 SETTINGS frame ID order. nil = dynamic from HTTP2Settings.
	PseudoHeaderOrder   []string // Pseudo-header order. nil = heuristic (Chrome m,a,s,p / Safari m,s,p,a).

	// PriorityTable maps sec-fetch-dest values to RFC 7540 stream priorities and
	// the matching RFC 9218 priority: header value. Populated for browsers (e.g.
	// Chrome 147 desktop) that emit a different urgency per resource type.
	//
	// When nil, the transport uses HTTP2Settings.StreamWeight / StreamExclusive
	// for every request — the legacy single-weight behaviour. When non-nil, the
	// transport selects an entry based on the request's sec-fetch-dest header,
	// derives the H2 wire weight from urgency via PriorityFromUrgency, and
	// injects the priority: header per the RFC 9218 emission rules.
	//
	// Map keys are sec-fetch-dest values exactly as Chrome emits them
	// ("document", "image", "script", "empty", etc.). Lookups are case-sensitive.
	PriorityTable map[string]ResourcePriority
}

// ResourcePriority describes a single browser priority decision for one
// resource class (sec-fetch-dest). Three orthogonal facts:
//
//   - Urgency (0–7) drives the RFC 7540 H2 stream weight via the formula
//     weight = 256 - (urgency * 73) / 2. 3 is Chrome's internal default and
//     emits no `u=` parameter on the priority: header.
//   - Incremental flag drives the RFC 9218 `i` parameter on the priority:
//     header. The H2 wire frame ignores it (RFC 7540 has no incremental).
//   - EmitHeader controls whether the priority: HTTP header is sent at all.
//     Chrome omits the header entirely on async/defer scripts even though
//     the wire weight defaults to 147 (urgency=3). The wire frame is still
//     emitted; only the HTTP header is suppressed.
type ResourcePriority struct {
	Urgency     uint8 // 0–7; 3 = default (no `u=` on header)
	Incremental bool  // RFC 9218 `i` parameter
	EmitHeader  bool  // false → suppress the priority: HTTP header entirely
}

// chromePriorityDefaultUrgency is Chrome's internal default urgency when no
// resource-type override applies. The header omits `u=N` at this value.
const chromePriorityDefaultUrgency uint8 = 3

// defaultPriorityTable is the Chrome 147 desktop priority mapping captured
// from real Chrome traffic. It serves as the implicit fallback for any
// preset that uses RFC 7540 priorities (NoRFC7540Priorities=false) and
// doesn't define its own H2Config.PriorityTable. Presets with
// NoRFC7540Priorities=true (Safari, iOS Chrome, iOS Safari) opt out
// entirely — those don't emit the RFC 7540 PRIORITY frame at all.
//
// Rationale: real browsers vary the H2 stream weight per resource type;
// emitting a constant weight on every HEADERS frame is detectable by
// passive H2 fingerprinters. The Chrome 147 table is the best per-dest
// approximation we have ground-truth captures for. Firefox has slightly
// different urgencies in its RFC 9218 emission; until we have Firefox
// captures, Firefox will inherit this Chrome-shaped table — a closer
// approximation than the prior single-weight fallback, but not byte-exact
// to real Firefox. Override per-preset by setting H2Config.PriorityTable
// to either an explicit table (use that) or an empty map (disable
// priority emission entirely).
var defaultPriorityTable = map[string]ResourcePriority{
	"audio":    {Urgency: 3, Incremental: true, EmitHeader: true},
	"document": {Urgency: 0, Incremental: true, EmitHeader: true},
	"embed":    {Urgency: 0, Incremental: true, EmitHeader: true},
	"empty":    {Urgency: 1, Incremental: true, EmitHeader: true},
	"font":     {Urgency: 1, Incremental: false, EmitHeader: true},
	"iframe":   {Urgency: 0, Incremental: true, EmitHeader: true},
	"image":    {Urgency: 2, Incremental: true, EmitHeader: true},
	"manifest": {Urgency: 2, Incremental: false, EmitHeader: true},
	"object":   {Urgency: 0, Incremental: true, EmitHeader: true},
	"script":   {Urgency: 1, Incremental: false, EmitHeader: true},
	"style":    {Urgency: 0, Incremental: false, EmitHeader: true},
	"track":    {Urgency: 3, Incremental: true, EmitHeader: true},
	"video":    {Urgency: 3, Incremental: true, EmitHeader: true},
	"worker":   {Urgency: 4, Incremental: true, EmitHeader: true},
}

// DefaultPriorityTable returns a copy of the package-level default
// priority table. Callers can use this as a starting point when
// constructing custom per-preset tables, or to inspect the values that
// will be emitted for presets that don't define their own.
//
// The returned map is a fresh copy; mutating it does not affect future
// preset lookups.
func DefaultPriorityTable() map[string]ResourcePriority {
	out := make(map[string]ResourcePriority, len(defaultPriorityTable))
	for k, v := range defaultPriorityTable {
		out[k] = v
	}
	return out
}

// PriorityFromUrgency converts an RFC 9218 urgency value into the RFC 7540
// stream weight Chrome emits on the H2 HEADERS frame. Verified against
// Chrome 147 captures for urgency 0–4; the formula extrapolates linearly
// for 5–7 (Chrome doesn't emit those values in practice).
//
// Formula: weight = 256 - (urgency * 73) / 2  (integer division).
//
// Mapping: 0→256, 1→220, 2→183, 3→147, 4→110, 5→74, 6→37, 7→1.
//
// The returned weight is the *effective* weight (1–256). Wire format uses
// weight-1; conversion happens at the transport boundary.
func PriorityFromUrgency(urgency uint8) uint16 {
	if urgency > 7 {
		urgency = 7
	}
	return uint16(256 - (uint32(urgency)*73)/2)
}

// PriorityHeaderFromResource renders the RFC 9218 priority: HTTP header
// value for a ResourcePriority, applying Chrome's emission rules:
//
//	urgency=3 (default) + !incremental → ""        (omit the header)
//	urgency=3 (default) +  incremental → "i"
//	urgency≠3           + !incremental → "u=N"
//	urgency≠3           +  incremental → "u=N, i"
//
// EmitHeader=false short-circuits to "" regardless of urgency/incremental
// (Chrome's async/defer-script behaviour). Caller must skip injection when
// the result is empty.
func PriorityHeaderFromResource(rp ResourcePriority) string {
	if !rp.EmitHeader {
		return ""
	}
	uIsDefault := rp.Urgency == chromePriorityDefaultUrgency
	switch {
	case uIsDefault && !rp.Incremental:
		return ""
	case uIsDefault && rp.Incremental:
		return "i"
	case !uIsDefault && !rp.Incremental:
		return "u=" + uint8ToASCII(rp.Urgency)
	default: // !uIsDefault && rp.Incremental
		return "u=" + uint8ToASCII(rp.Urgency) + ", i"
	}
}

// uint8ToASCII formats a small uint8 (0–9 expected for urgency) without the
// strconv dependency cost. Falls back to direct conversion for >9 (which
// shouldn't occur — urgency is 0–7).
func uint8ToASCII(v uint8) string {
	if v <= 9 {
		return string([]byte{'0' + v})
	}
	// Two-digit fallback for safety; never reached for valid urgency.
	return string([]byte{'0' + v/10, '0' + v%10})
}

// H3FingerprintConfig controls HTTP/3 and QUIC fingerprinting behavior.
// When nil on a Preset, all getters return Chrome defaults (with Safari fallback
// for presets that have NoRFC7540Priorities set). Individual nil fields fall back
// to Chrome defaults independently.
type H3FingerprintConfig struct {
	QPACKMaxTableCapacity     *uint64 // nil = 65536 (Chrome). Safari heuristic fallback.
	QPACKBlockedStreams       *uint64 // nil = 100
	MaxFieldSectionSize       *uint64 // nil = 262144 (Chrome). 0 to omit (Safari).
	EnableDatagrams           *bool   // nil = true (Chrome). Safari heuristic fallback.
	QUICInitialPacketSize     *uint16 // nil = 1250 (Chrome). MASQUE overrides to 1350.
	QUICMaxIncomingStreams    *int64  // nil = 100
	QUICMaxIncomingUniStreams *int64  // nil = 103
	QUICAllow0RTT             *bool   // nil = true
	QUICChromeStyleInitial    *bool   // nil = true
	QUICDisableHelloScramble  *bool   // nil = true
	QUICTransportParamOrder   string  // "chrome"/"random". "" = "chrome".
	QUICConnectionIDLength    *int    // nil = 0 (Chrome empty SCID). Firefox uses 8.
	QUICMaxDatagramFrameSize  *uint64 // nil = 65536 (Chrome). 0 to use quic-go default (16383).
	MaxResponseHeaderBytes    *uint64 // nil = 262144
	SendGreaseFrames          *bool   // nil = true

	// QUIC flow-control windows. quic-go translates these to wire transport
	// parameters initial_max_data (4) and initial_max_stream_data_* (5/6/7).
	// nil = quic-go default (~7.5 MB conn, ~512 KB stream). Safari/iOS Chrome
	// uses larger conn (16 MB) and smaller per-stream (2 MB) — set both to
	// match.
	QUICInitialStreamReceiveWindow     *uint64 // nil = quic-go default. iOS Chrome sends 2097152.
	QUICInitialConnectionReceiveWindow *uint64 // nil = quic-go default. iOS Chrome sends 16777216.
}

// --- H2 Preset Getters ---
// Each getter checks H2Config first, then returns Chrome default.

// H2HeaderOrder returns the HPACK wire encoding order for HTTP/2 headers.
func (p *Preset) H2HeaderOrder() []string {
	if p.H2Config != nil && p.H2Config.HPACKHeaderOrder != nil {
		return p.H2Config.HPACKHeaderOrder
	}
	// Chrome 143 header order (verified via tls.peet.ws). Kept in lockstep with
	// chromeH2Config().HPACKHeaderOrder so the nil-H2Config fallback path emits
	// the session-injected client hints in the same deterministic wire order.
	return []string{
		"cache-control",
		"sec-ch-ua", "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version-list",
		"sec-ch-ua-mobile", "sec-ch-ua-model",
		"sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-wow64",
		"upgrade-insecure-requests", "user-agent",
		"content-type", "content-length",
		"accept", "origin",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
		"referer",
		"if-none-match", "if-modified-since",
		"accept-encoding", "accept-language",
		"cookie", "priority",
	}
}

// H2HPACKIndexingPolicy returns the HPACK indexing policy name.
func (p *Preset) H2HPACKIndexingPolicy() string {
	if p.H2Config != nil && p.H2Config.HPACKIndexingPolicy != "" {
		return p.H2Config.HPACKIndexingPolicy
	}
	return "chrome"
}

// H2HPACKNeverIndex returns headers that should never be HPACK-indexed, i.e.
// emitted as a literal with the never-indexed bit set (0x10) so intermediaries
// cannot add them to their own tables.
//
// Empty by default, because Chrome never uses that representation. RFC 7541
// 7.1.3 recommends it for sensitive headers and Chromium declines: quiche's
// HpackEncoder indexes every regular header, cookie and authorization
// included. Listing them here looks like hardening and is actually a
// fingerprint, twice over. The instruction changes (0x1f11 rather than Chrome's
// 0x60 for a cookie crumb), and because a never-indexed field is never
// inserted, the whole jar is re-sent in full on every request where Chrome
// sends one byte per crumb. On a session carrying a large jar that is an
// ~880-byte header block against Chrome's ~35.
//
// Set H2Config.HPACKNeverIndex explicitly to opt in for a non-browser profile.
func (p *Preset) H2HPACKNeverIndex() []string {
	if p.H2Config != nil && p.H2Config.HPACKNeverIndex != nil {
		return p.H2Config.HPACKNeverIndex
	}
	return nil
}

// H2StreamPriorityMode returns the stream priority mode name.
func (p *Preset) H2StreamPriorityMode() string {
	if p.H2Config != nil && p.H2Config.StreamPriorityMode != "" {
		return p.H2Config.StreamPriorityMode
	}
	return "chrome"
}

// H2DisableCookieSplit reports whether to send the Cookie header as a single
// field instead of crumbling it into one field per cookie-pair. Chrome and
// Firefox crumble (false) per RFC 9113 8.2.3 / Chromium HpackEncoder
// CookieToCrumbs; Safari/WebKit sends a single field (true). Used for both the
// H2 (sardanioss/net HPACK encoder) and H3 (pre-split in HTTP3Transport) paths.
func (p *Preset) H2DisableCookieSplit() bool {
	if p.H2Config != nil && p.H2Config.DisableCookieSplit != nil {
		return *p.H2Config.DisableCookieSplit
	}
	return true // conservative single-field fallback; built-in presets set this explicitly
}

// H2SettingsOrder returns the explicit H2 SETTINGS frame ID order.
// nil signals "use dynamic builder" (existing behavior).
func (p *Preset) H2SettingsOrder() []uint16 {
	if p.H2Config != nil && p.H2Config.SettingsOrder != nil {
		return p.H2Config.SettingsOrder
	}
	return nil
}

// H2PseudoHeaderOrder returns the pseudo-header order for HTTP/2.
// nil signals "use heuristic" (Chrome m,a,s,p / Safari m,s,p,a).
func (p *Preset) H2PseudoHeaderOrder() []string {
	if p.H2Config != nil && p.H2Config.PseudoHeaderOrder != nil {
		return p.H2Config.PseudoHeaderOrder
	}
	return nil
}

// H2HasPriorityTable reports whether this preset will resolve per-dest
// priority data. Three states:
//
//   - H2Config.PriorityTable populated (len > 0) → true (explicit override).
//   - H2Config.PriorityTable nil or empty AND NoRFC7540Priorities=false →
//     true (inherits the package-level defaultPriorityTable).
//   - NoRFC7540Priorities=true → false (Safari / iOS Chrome / iOS Safari
//     opt out of RFC 7540 priorities entirely; the wire frame is not
//     emitted).
//
// When false, callers fall back to the legacy HTTP2Settings.StreamWeight
// / StreamExclusive single-weight behaviour. To genuinely disable priority
// emission for a single preset, set NoRFC7540Priorities=true on its
// HTTP2Settings — the priority_table mechanism is purely additive.
func (p *Preset) H2HasPriorityTable() bool {
	if p.H2Config != nil && len(p.H2Config.PriorityTable) > 0 {
		return true
	}
	if p.HTTP2Settings.NoRFC7540Priorities {
		return false
	}
	return len(defaultPriorityTable) > 0
}

// H2PriorityFor returns the resolved (weight, exclusive, headerValue) for
// a given sec-fetch-dest. Resolution order:
//
//  1. Preset's explicit H2Config.PriorityTable (when populated, len > 0).
//  2. Package-level defaultPriorityTable, but only if the preset uses
//     RFC 7540 priorities (NoRFC7540Priorities=false).
//
// ok=false in two cases:
//   - the preset opts out of RFC 7540 priorities entirely (Safari etc.), or
//   - the dest is not registered in whichever table applies.
//
// In both cases the caller should fall back to
// HTTP2Settings.StreamWeight / StreamExclusive (legacy behaviour).
//
// weight is the effective weight (1–256). The transport converts to wire
// format (weight-1) at the boundary.
//
// headerValue is the RFC 9218 priority: header value rendered per the
// emission rules; empty string means "do not inject the header" (caller
// must skip Set/Add for this request).
//
// Lookup is case-sensitive — Chrome emits "document", "image", etc. as
// lowercase ASCII. Pass req.Header.Get("Sec-Fetch-Dest") directly.
func (p *Preset) H2PriorityFor(dest string) (weight uint16, exclusive bool, headerValue string, ok bool) {
	var table map[string]ResourcePriority
	switch {
	case p.H2Config != nil && len(p.H2Config.PriorityTable) > 0:
		table = p.H2Config.PriorityTable
	case p.HTTP2Settings.NoRFC7540Priorities:
		return 0, false, "", false
	default:
		table = defaultPriorityTable
	}
	rp, found := table[dest]
	if !found {
		return 0, false, "", false
	}
	return PriorityFromUrgency(rp.Urgency), true, PriorityHeaderFromResource(rp), true
}

// --- H3 Preset Getters ---
// Each getter checks H3Config first, then uses Safari heuristic (NoRFC7540Priorities)
// where applicable, then returns Chrome default.

// H3QPACKMaxTableCapacity returns the QPACK max dynamic table capacity.
func (p *Preset) H3QPACKMaxTableCapacity() uint64 {
	if p.H3Config != nil && p.H3Config.QPACKMaxTableCapacity != nil {
		return *p.H3Config.QPACKMaxTableCapacity
	}
	// Safari heuristic fallback
	if p.HTTP2Settings.NoRFC7540Priorities {
		return 16383
	}
	return 65536 // Chrome default
}

// H3QPACKBlockedStreams returns the QPACK blocked streams limit.
func (p *Preset) H3QPACKBlockedStreams() uint64 {
	if p.H3Config != nil && p.H3Config.QPACKBlockedStreams != nil {
		return *p.H3Config.QPACKBlockedStreams
	}
	return 100
}

// H3MaxFieldSectionSize returns the max field section size.
// 0 means omit the setting (Safari behavior).
func (p *Preset) H3MaxFieldSectionSize() uint64 {
	if p.H3Config != nil && p.H3Config.MaxFieldSectionSize != nil {
		return *p.H3Config.MaxFieldSectionSize
	}
	// Safari heuristic: omit MAX_FIELD_SECTION_SIZE
	if p.HTTP2Settings.NoRFC7540Priorities {
		return 0
	}
	return 262144 // Chrome default
}

// H3EnableDatagrams returns whether to enable H3 datagrams.
func (p *Preset) H3EnableDatagrams() bool {
	if p.H3Config != nil && p.H3Config.EnableDatagrams != nil {
		return *p.H3Config.EnableDatagrams
	}
	// Safari heuristic: no datagrams
	if p.HTTP2Settings.NoRFC7540Priorities {
		return false
	}
	return true // Chrome default
}

// H3QUICInitialPacketSize returns the QUIC initial packet size.
func (p *Preset) H3QUICInitialPacketSize() uint16 {
	if p.H3Config != nil && p.H3Config.QUICInitialPacketSize != nil {
		return *p.H3Config.QUICInitialPacketSize
	}
	return 1250 // Chrome default
}

// H3QUICMaxIncomingStreams returns the max incoming bidirectional streams.
func (p *Preset) H3QUICMaxIncomingStreams() int64 {
	if p.H3Config != nil && p.H3Config.QUICMaxIncomingStreams != nil {
		return *p.H3Config.QUICMaxIncomingStreams
	}
	return 100
}

// H3QUICMaxIncomingUniStreams returns the max incoming unidirectional streams.
func (p *Preset) H3QUICMaxIncomingUniStreams() int64 {
	if p.H3Config != nil && p.H3Config.QUICMaxIncomingUniStreams != nil {
		return *p.H3Config.QUICMaxIncomingUniStreams
	}
	return 103
}

// H3QUICAllow0RTT returns whether to allow 0-RTT.
func (p *Preset) H3QUICAllow0RTT() bool {
	if p.H3Config != nil && p.H3Config.QUICAllow0RTT != nil {
		return *p.H3Config.QUICAllow0RTT
	}
	return true
}

// H3QUICChromeStyleInitial returns whether to use Chrome-style initial packets.
func (p *Preset) H3QUICChromeStyleInitial() bool {
	if p.H3Config != nil && p.H3Config.QUICChromeStyleInitial != nil {
		return *p.H3Config.QUICChromeStyleInitial
	}
	return true
}

// H3QUICDisableHelloScramble returns whether to disable ClientHello scrambling.
func (p *Preset) H3QUICDisableHelloScramble() bool {
	if p.H3Config != nil && p.H3Config.QUICDisableHelloScramble != nil {
		return *p.H3Config.QUICDisableHelloScramble
	}
	return true
}

// H3QUICTransportParamOrder returns the QUIC transport parameter order mode name.
func (p *Preset) H3QUICTransportParamOrder() string {
	if p.H3Config != nil && p.H3Config.QUICTransportParamOrder != "" {
		return p.H3Config.QUICTransportParamOrder
	}
	return "chrome"
}

// H3QUICConnectionIDLength returns the QUIC connection ID length in bytes.
// Chrome uses 0 (empty SCID), Firefox uses 8.
func (p *Preset) H3QUICConnectionIDLength() int {
	if p.H3Config != nil && p.H3Config.QUICConnectionIDLength != nil {
		return *p.H3Config.QUICConnectionIDLength
	}
	return 0 // Chrome default: empty SCID
}

// H3QUICMaxDatagramFrameSize returns the max_datagram_frame_size transport parameter.
// Chrome uses 65536, default quic-go is 16383.
func (p *Preset) H3QUICMaxDatagramFrameSize() uint64 {
	if p.H3Config != nil && p.H3Config.QUICMaxDatagramFrameSize != nil {
		return *p.H3Config.QUICMaxDatagramFrameSize
	}
	return 65536 // Chrome default
}

// H3MaxResponseHeaderBytes returns the max response header bytes.
func (p *Preset) H3MaxResponseHeaderBytes() uint64 {
	if p.H3Config != nil && p.H3Config.MaxResponseHeaderBytes != nil {
		return *p.H3Config.MaxResponseHeaderBytes
	}
	return 262144
}

// H3SendGreaseFrames returns whether to send GREASE frames on the control stream.
func (p *Preset) H3SendGreaseFrames() bool {
	if p.H3Config != nil && p.H3Config.SendGreaseFrames != nil {
		return *p.H3Config.SendGreaseFrames
	}
	return true
}

// H3QUICInitialStreamReceiveWindow returns the quic-go InitialStreamReceiveWindow
// value (which becomes initial_max_stream_data_* on the wire). 0 means
// "use quic-go default" (~512 KB). iOS Chrome sets 2 MiB.
func (p *Preset) H3QUICInitialStreamReceiveWindow() uint64 {
	if p.H3Config != nil && p.H3Config.QUICInitialStreamReceiveWindow != nil {
		return *p.H3Config.QUICInitialStreamReceiveWindow
	}
	return 0
}

// H3QUICInitialConnectionReceiveWindow returns the quic-go InitialConnectionReceiveWindow
// value (which becomes initial_max_data on the wire). 0 means
// "use quic-go default" (~7.5 MB). iOS Chrome sets 16 MiB.
func (p *Preset) H3QUICInitialConnectionReceiveWindow() uint64 {
	if p.H3Config != nil && p.H3Config.QUICInitialConnectionReceiveWindow != nil {
		return *p.H3Config.QUICInitialConnectionReceiveWindow
	}
	return 0
}

// chromeH2Config returns the explicit H2 fingerprint config for Chrome presets.
func chromeH2Config() *H2FingerprintConfig {
	f := false
	return &H2FingerprintConfig{
		HPACKHeaderOrder: []string{
			"cache-control",
			// Low- AND high-entropy UA client hints emit as one fixed cluster.
			// The session injects the high-entropy set (sec-ch-ua-arch, -bitness,
			// -full-version-list, -model, -platform-version, -wow64) once a host
			// advertises Accept-CH; without them in this table they'd fall through
			// to Go map iteration = random wire order per request = a stable tell.
			// Real Chrome groups the high-entropy hints with the trio in this
			// sequence, so we mirror it here.
			"sec-ch-ua", "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version-list",
			"sec-ch-ua-mobile", "sec-ch-ua-model",
			"sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-wow64",
			"upgrade-insecure-requests", "user-agent",
			"content-type", "content-length",
			"accept", "origin",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
			"referer",
			// Conditional-cache validators in a fixed slot (ETag validator first),
			// so the session-injected If-None-Match / If-Modified-Since don't shuffle.
			"if-none-match", "if-modified-since",
			"accept-encoding", "accept-language",
			"cookie", "priority",
		},
		HPACKIndexingPolicy: "chrome",
		StreamPriorityMode:  "chrome",
		// Chrome crumbles the Cookie header into one field per cookie-pair on the
		// wire (Chromium HpackEncoder::CookieToCrumbs; crumble_cookies_ defaults
		// true and Chrome's production SpdyFramer never calls DisableCookieCrumbling).
		// false => crumble. Verified against live Chromium/QUICHE main 2026-05.
		DisableCookieSplit: &f,
		SettingsOrder:      []uint16{1, 2, 4, 6},
		PseudoHeaderOrder:  []string{":method", ":authority", ":scheme", ":path"},
	}
}

// firefoxH2Config returns the explicit H2 fingerprint config for Firefox presets.
func firefoxH2Config() *H2FingerprintConfig {
	f := false
	return &H2FingerprintConfig{
		HPACKHeaderOrder: []string{
			"user-agent",
			"accept", "accept-language", "accept-encoding",
			"upgrade-insecure-requests",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
			"priority", "te",
			"referer", "cookie",
			"content-type", "content-length", "origin",
		},
		HPACKIndexingPolicy: "default",
		StreamPriorityMode:  "default",
		DisableCookieSplit:  &f,
		SettingsOrder:       []uint16{1, 2, 4, 5},
		PseudoHeaderOrder:   []string{":method", ":path", ":authority", ":scheme"},
	}
}

// safariH2Config returns the explicit H2 fingerprint config for Safari/WebKit presets.
func safariH2Config() *H2FingerprintConfig {
	t := true
	return &H2FingerprintConfig{
		HPACKHeaderOrder: []string{
			"accept",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
			"accept-language", "accept-encoding",
			"user-agent", "referer", "cookie",
			"content-type", "content-length", "origin",
		},
		HPACKIndexingPolicy: "default",
		StreamPriorityMode:  "default",
		DisableCookieSplit:  &t,
		SettingsOrder:       []uint16{2, 4, 3, 5, 9},
		PseudoHeaderOrder:   []string{":method", ":scheme", ":path", ":authority"},
	}
}

// safariH3Config returns the explicit H3 fingerprint config for Safari/WebKit presets.
// Replaces the NoRFC7540Priorities heuristic fallback with explicit values.
func safariH3Config() *H3FingerprintConfig {
	f := false
	qpackCap := uint64(16383)
	maxField := uint64(0) // Safari omits MAX_FIELD_SECTION_SIZE
	return &H3FingerprintConfig{
		QPACKMaxTableCapacity:    &qpackCap,
		MaxFieldSectionSize:      &maxField,
		EnableDatagrams:          &f,
		QUICChromeStyleInitial:   &f, // Safari doesn't mimic Chrome's initial packet pattern
		QUICDisableHelloScramble: &f, // Safari uses default scrambling
		QUICTransportParamOrder:  "random",
		SendGreaseFrames:         &f, // Safari doesn't send GREASE frames on control stream
	}
}

// Chrome133 returns the Chrome 133 fingerprint preset
func Chrome133() *Preset {
	p := GetPlatformInfo()
	return &Preset{
		Name:             "chrome-133",
		ClientHelloID:    tls.HelloChrome_133,     // Chrome 133 with X25519MLKEM768 (correct post-quantum)
		PSKClientHelloID: tls.HelloChrome_133_PSK, // PSK for session resumption
		UserAgent:        "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="133", "Chromium";v="133", "Not_A Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"` + p.Platform + `"`,
			// Standard navigation headers (human clicked link)
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		// Chrome header order for HTTP/2 and HTTP/3 (order matters!)
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="133", "Chromium";v="133", "Not_A Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   false, // Legacy preset, no proper QUIC fingerprint
	}
}

// Chrome141 returns the Chrome 141 fingerprint preset
func Chrome141() *Preset {
	p := GetPlatformInfo()
	return &Preset{
		Name:             "chrome-141",
		ClientHelloID:    tls.HelloChrome_133,     // Chrome 133 TLS fingerprint with X25519MLKEM768
		PSKClientHelloID: tls.HelloChrome_133_PSK, // PSK for session resumption
		UserAgent:        "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"` + p.Platform + `"`,
			// Standard navigation headers (human clicked link)
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		// Chrome header order for HTTP/2 and HTTP/3 (order matters!)
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   false, // Legacy preset, no proper QUIC fingerprint
	}
}

// Firefox133 returns the Firefox 133 fingerprint preset
func Firefox133() *Preset {
	p := GetPlatformInfo()
	return &Preset{
		Name:          "firefox-133",
		ClientHelloID: tls.HelloFirefox_120,
		UserAgent:     "Mozilla/5.0 " + p.FirefoxUserAgentOS + " Gecko/20100101 Firefox/133.0",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
		},
		// Firefox header order for HTTP/2 (different from Chrome)
		HeaderOrder: []HeaderPair{
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
			{"accept-language", "en-US,en;q=0.5"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             true,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      131072,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 12517377,
			StreamWeight:           42,
			StreamExclusive:        false,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       firefoxH2Config(),
		SupportHTTP3:   false, // No Firefox QUIC fingerprint in utls
	}
}

// Firefox148 returns the Firefox 148 fingerprint preset using JA3 for TLS.
// Uses the exact JA3 fingerprint captured from real Firefox 148 on Linux.
func Firefox148() *Preset {
	p := GetPlatformInfo()
	// Firefox 148 UA format
	firefoxUA := "Mozilla/5.0 " + p.FirefoxUserAgentOS + " Gecko/20100101 Firefox/148.0"
	// Override the rv: version in the UA OS string for Firefox 148
	if p.Platform == "Windows" {
		firefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0"
	} else if p.Platform == "macOS" {
		firefoxUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0"
	} else {
		firefoxUA = "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"
	}
	return &Preset{
		Name: "firefox-148",
		// JA3 from real Firefox 148 capture (tls.peet.ws)
		JA3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0",
		JA3Extras: &JA3Extras{
			SignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1,
			},
			DelegatedCredentialAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.ECDSAWithSHA1,
			},
			ALPN: []string{"h2", "http/1.1"},
			CertCompAlgs: []tls.CertCompressionAlgo{
				tls.CertCompressionZlib,
				tls.CertCompressionBrotli,
				tls.CertCompressionZstd,
			},
			RecordSizeLimit: 0x4001,
			KeyShareCurves:  3, // Firefox sends key shares for X25519MLKEM768, X25519, P-256
		},
		UserAgent: firefoxUA,
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Priority":                  "u=0, i",
			"TE":                        "trailers",
		},
		HeaderOrder: []HeaderPair{
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"accept-language", "en-US,en;q=0.9"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"upgrade-insecure-requests", "1"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
			{"priority", "u=0, i"},
			{"te", "trailers"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false, // Firefox 148 sends ENABLE_PUSH=0
			MaxConcurrentStreams:   0,
			InitialWindowSize:      131072,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 12517377,
			StreamWeight:           42,
			StreamExclusive:        false,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       firefoxH2Config(),
		SupportHTTP3:   false, // No Firefox QUIC fingerprint in utls
	}
}

// Firefox133Windows returns Firefox 133 on Windows. Firefox has no UA Client
// Hints and NSS emits the same ClientHello on every OS, so a platform variant
// differs from the auto-detected base in exactly one place: the OS token of the
// User-Agent. The variant presets live in embedded JSON (based_on the auto base,
// user_agent override only); this falls back to the auto-detected base if the
// JSON didn't load, mirroring the Chrome 150 accessors.
func Firefox133Windows() *Preset {
	if p := LookupCustom("firefox-133-windows"); p != nil {
		return p
	}
	return Firefox133()
}

// Firefox133Linux returns Firefox 133 on Linux. See Firefox133Windows.
func Firefox133Linux() *Preset {
	if p := LookupCustom("firefox-133-linux"); p != nil {
		return p
	}
	return Firefox133()
}

// Firefox133macOS returns Firefox 133 on macOS. See Firefox133Windows.
func Firefox133macOS() *Preset {
	if p := LookupCustom("firefox-133-macos"); p != nil {
		return p
	}
	return Firefox133()
}

// Firefox148Windows returns Firefox 148 on Windows. See Firefox133Windows.
func Firefox148Windows() *Preset {
	if p := LookupCustom("firefox-148-windows"); p != nil {
		return p
	}
	return Firefox148()
}

// Firefox148Linux returns Firefox 148 on Linux. See Firefox133Windows.
func Firefox148Linux() *Preset {
	if p := LookupCustom("firefox-148-linux"); p != nil {
		return p
	}
	return Firefox148()
}

// Firefox148macOS returns Firefox 148 on macOS. See Firefox133Windows.
func Firefox148macOS() *Preset {
	if p := LookupCustom("firefox-148-macos"); p != nil {
		return p
	}
	return Firefox148()
}

// Chrome143 returns the Chrome 143 fingerprint preset with platform-specific TLS fingerprint
func Chrome143() *Preset {
	p := GetPlatformInfo()
	// Use platform-specific TLS fingerprint with fixed extension order
	var clientHelloID, pskClientHelloID tls.ClientHelloID
	switch p.Platform {
	case "Windows":
		clientHelloID = tls.HelloChrome_143_Windows
		pskClientHelloID = tls.HelloChrome_143_Windows_PSK
	case "macOS":
		clientHelloID = tls.HelloChrome_143_macOS
		pskClientHelloID = tls.HelloChrome_143_macOS_PSK
	default: // Linux and others
		clientHelloID = tls.HelloChrome_143_Linux
		pskClientHelloID = tls.HelloChrome_143_Linux_PSK
	}
	return &Preset{
		Name:                 "chrome-143",
		ClientHelloID:        clientHelloID,
		PSKClientHelloID:     pskClientHelloID,
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,     // QUIC-specific preset for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK, // QUIC with PSK for session resumption
		UserAgent:            "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"` + p.Platform + `"`,
			// Standard navigation headers (human clicked link)
			// Note: Cache-Control is NOT sent on normal navigation, only on hard refresh (Ctrl+F5)
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		// Chrome 143 header order for HTTP/2 and HTTP/3 (order matters!)
		// Verified against real Chrome 143 on Linux via tls.peet.ws
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome143Windows returns Chrome 143 with Windows platform and fixed TLS extension order
func Chrome143Windows() *Preset {
	return &Preset{
		Name:                 "chrome-143-windows",
		ClientHelloID:        tls.HelloChrome_143_Windows,     // Chrome 143 Windows with fixed extension order
		PSKClientHelloID:     tls.HelloChrome_143_Windows_PSK, // PSK for session resumption
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,        // QUIC-specific preset for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK,    // QUIC with PSK for session resumption
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"Windows"`,
			// Standard navigation headers (human clicked link)
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		// Chrome 143 header order for HTTP/2 and HTTP/3 (order matters!)
		// Verified against real Chrome 143 on Windows via tls.peet.ws
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome143Linux returns Chrome 143 with Linux platform and fixed TLS extension order
func Chrome143Linux() *Preset {
	return &Preset{
		Name:                 "chrome-143-linux",
		ClientHelloID:        tls.HelloChrome_143_Linux,     // Chrome 143 Linux with fixed extension order
		PSKClientHelloID:     tls.HelloChrome_143_Linux_PSK, // PSK for session resumption
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,      // QUIC-specific preset for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK,  // QUIC with PSK for session resumption
		UserAgent:            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"Linux"`,
			// Standard navigation headers (human clicked link)
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		// Chrome 143 header order for HTTP/2 and HTTP/3 (order matters!)
		// Verified against real Chrome 143 on Linux via tls.peet.ws
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Linux"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome143macOS returns Chrome 143 with macOS platform and fixed TLS extension order
func Chrome143macOS() *Preset {
	return &Preset{
		Name:                 "chrome-143-macos",
		ClientHelloID:        tls.HelloChrome_143_macOS,     // Chrome 143 macOS with fixed extension order
		PSKClientHelloID:     tls.HelloChrome_143_macOS_PSK, // PSK for session resumption
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,      // QUIC-specific preset for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK,  // QUIC with PSK for session resumption
		UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"macOS"`,
			// Standard navigation headers (human clicked link)
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		// Chrome 143 header order for HTTP/2 and HTTP/3 (order matters!)
		// Verified against real Chrome 143 on macOS via tls.peet.ws
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"macOS"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome144 returns the Chrome 144 fingerprint preset with platform-specific TLS fingerprint
func Chrome144() *Preset {
	p := GetPlatformInfo()
	// Chrome 144 uses same TLS fingerprint as Chrome 143
	var clientHelloID, pskClientHelloID tls.ClientHelloID
	switch p.Platform {
	case "Windows":
		clientHelloID = tls.HelloChrome_144_Windows
		pskClientHelloID = tls.HelloChrome_144_Windows_PSK
	case "macOS":
		clientHelloID = tls.HelloChrome_144_macOS
		pskClientHelloID = tls.HelloChrome_144_macOS_PSK
	default: // Linux and others
		clientHelloID = tls.HelloChrome_144_Linux
		pskClientHelloID = tls.HelloChrome_144_Linux_PSK
	}
	return &Preset{
		Name:                 "chrome-144",
		ClientHelloID:        clientHelloID,
		PSKClientHelloID:     pskClientHelloID,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"` + p.Platform + `"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome144Windows returns Chrome 144 with Windows platform
func Chrome144Windows() *Preset {
	return &Preset{
		Name:                 "chrome-144-windows",
		ClientHelloID:        tls.HelloChrome_144_Windows,
		PSKClientHelloID:     tls.HelloChrome_144_Windows_PSK,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Windows"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome144Linux returns Chrome 144 with Linux platform
func Chrome144Linux() *Preset {
	return &Preset{
		Name:                 "chrome-144-linux",
		ClientHelloID:        tls.HelloChrome_144_Linux,
		PSKClientHelloID:     tls.HelloChrome_144_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Linux"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Linux"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome144macOS returns Chrome 144 with macOS platform
func Chrome144macOS() *Preset {
	return &Preset{
		Name:                 "chrome-144-macos",
		ClientHelloID:        tls.HelloChrome_144_macOS,
		PSKClientHelloID:     tls.HelloChrome_144_macOS_PSK,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"macOS"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-GB,en-US;q=0.9,en;q=0.8",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"macOS"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-GB,en-US;q=0.9,en;q=0.8"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome145 returns the Chrome 145 fingerprint preset with platform-specific TLS fingerprint
func Chrome145() *Preset {
	p := GetPlatformInfo()
	// Chrome 145 uses same TLS fingerprint as Chrome 144/143
	var clientHelloID, pskClientHelloID tls.ClientHelloID
	switch p.Platform {
	case "Windows":
		clientHelloID = tls.HelloChrome_145_Windows
		pskClientHelloID = tls.HelloChrome_145_Windows_PSK
	case "macOS":
		clientHelloID = tls.HelloChrome_145_macOS
		pskClientHelloID = tls.HelloChrome_145_macOS_PSK
	default: // Linux and others
		clientHelloID = tls.HelloChrome_145_Linux
		pskClientHelloID = tls.HelloChrome_145_Linux_PSK
	}
	return &Preset{
		Name:                 "chrome-145",
		ClientHelloID:        clientHelloID,
		PSKClientHelloID:     pskClientHelloID,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"` + p.Platform + `"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome doesn't send setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome145Windows returns Chrome 145 with Windows platform
func Chrome145Windows() *Preset {
	return &Preset{
		Name:                 "chrome-145-windows",
		ClientHelloID:        tls.HelloChrome_145_Windows,
		PSKClientHelloID:     tls.HelloChrome_145_Windows_PSK,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Windows"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome doesn't send setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome145Linux returns Chrome 145 with Linux platform
func Chrome145Linux() *Preset {
	return &Preset{
		Name:                 "chrome-145-linux",
		ClientHelloID:        tls.HelloChrome_145_Linux,
		PSKClientHelloID:     tls.HelloChrome_145_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Linux"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Linux"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome145macOS returns Chrome 145 with macOS platform
func Chrome145macOS() *Preset {
	return &Preset{
		Name:                 "chrome-145-macos",
		ClientHelloID:        tls.HelloChrome_145_macOS,
		PSKClientHelloID:     tls.HelloChrome_145_macOS_PSK,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"macOS"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"macOS"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome146 returns the Chrome 146 fingerprint preset with platform-specific TLS fingerprint
func Chrome146() *Preset {
	p := GetPlatformInfo()
	// Chrome 146 uses same TLS fingerprint as Chrome 145/144/143
	var clientHelloID, pskClientHelloID tls.ClientHelloID
	switch p.Platform {
	case "Windows":
		clientHelloID = tls.HelloChrome_146_Windows
		pskClientHelloID = tls.HelloChrome_146_Windows_PSK
	case "macOS":
		clientHelloID = tls.HelloChrome_146_macOS
		pskClientHelloID = tls.HelloChrome_146_macOS_PSK
	default: // Linux and others
		clientHelloID = tls.HelloChrome_146_Linux
		pskClientHelloID = tls.HelloChrome_146_Linux_PSK
	}
	return &Preset{
		Name:                 "chrome-146",
		ClientHelloID:        clientHelloID,
		PSKClientHelloID:     pskClientHelloID,
		QUICClientHelloID:    tls.HelloChrome_146_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_146_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"` + p.Platform + `"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome146Windows returns Chrome 146 with Windows platform
func Chrome146Windows() *Preset {
	return &Preset{
		Name:                 "chrome-146-windows",
		ClientHelloID:        tls.HelloChrome_146_Windows,
		PSKClientHelloID:     tls.HelloChrome_146_Windows_PSK,
		QUICClientHelloID:    tls.HelloChrome_146_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_146_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Windows"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome146Linux returns Chrome 146 with Linux platform
func Chrome146Linux() *Preset {
	return &Preset{
		Name:                 "chrome-146-linux",
		ClientHelloID:        tls.HelloChrome_146_Linux,
		PSKClientHelloID:     tls.HelloChrome_146_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_146_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_146_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Linux"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Linux"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Chrome146macOS returns Chrome 146 with macOS platform
func Chrome146macOS() *Preset {
	return &Preset{
		Name:                 "chrome-146-macos",
		ClientHelloID:        tls.HelloChrome_146_macOS,
		PSKClientHelloID:     tls.HelloChrome_146_macOS_PSK,
		QUICClientHelloID:    tls.HelloChrome_146_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_146_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"macOS"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"macOS"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// Safari18 returns the Safari 18 fingerprint preset
// Note: Safari is macOS-only, so no platform detection needed
func Safari18() *Preset {
	return &Preset{
		Name:              "safari-18",
		ClientHelloID:     tls.HelloSafari_18,
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // Safari uses same QUIC as iOS
		UserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
		},
		// Safari header order for HTTP/2 (different from Chrome)
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
			{"accept-language", "en-US,en;q=0.9"},
			{"accept-encoding", "gzip, deflate, br"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
		},
		// Safari HTTP/2 settings (WebKit)
		// Similar to iOS but may have ENABLE_PUSH=1 on macOS
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false, // Match iOS behavior
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // Safari sends NO_RFC7540_PRIORITIES=1
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   true,
	}
}

// Chrome147Windows returns Chrome 147 with Windows platform.
//
// The preset is provided by the embedded JSON registry (fingerprint/embedded/chrome-147-windows.json),
// which inherits TLS bytes from chrome-146-windows and overrides only the User-Agent
// and sec-ch-ua header. If the embedded JSON failed to load, the factory falls back
// to Chrome146Windows so callers don't get a Chrome146 fallback by accident.
func Chrome147Windows() *Preset {
	if p := LookupCustom("chrome-147-windows"); p != nil {
		return p
	}
	return Chrome146Windows()
}

// Chrome147Linux returns Chrome 147 with Linux platform. See Chrome147Windows.
func Chrome147Linux() *Preset {
	if p := LookupCustom("chrome-147-linux"); p != nil {
		return p
	}
	return Chrome146Linux()
}

// Chrome147macOS returns Chrome 147 with macOS platform. See Chrome147Windows.
func Chrome147macOS() *Preset {
	if p := LookupCustom("chrome-147-macos"); p != nil {
		return p
	}
	return Chrome146macOS()
}

// Chrome147 returns the Chrome 147 fingerprint preset auto-detected from the
// running OS. Mirrors Chrome146's platform-aware behavior.
func Chrome147() *Preset {
	switch GetPlatformInfo().Platform {
	case "Windows":
		return Chrome147Windows()
	case "macOS":
		return Chrome147macOS()
	default:
		return Chrome147Linux()
	}
}

// IOSChrome147 returns Chrome 147 on iOS. Embedded JSON only overrides the
// User-Agent (CriOS major version) — everything else (no sec-ch-ua due to
// WebKit, Safari TLS via HelloIOS_18, Safari H2 config) inherits unchanged
// from chrome-146-ios. Falls back to IOSChrome146 if the JSON didn't load.
func IOSChrome147() *Preset {
	if p := LookupCustom("chrome-147-ios"); p != nil {
		return p
	}
	return IOSChrome146()
}

// IOSChrome148 returns Chrome 148 on iOS — captured against real iOS Chrome
// 148.0.7778.47, with deeper changes than the 147 bump:
//   - User-Agent: iOS 26_4_2, CriOS/148.0.7778.47
//   - HTTP/2 wire: SettingsOrder [2,3,4,9] (drops MAX_FRAME_SIZE), pseudo-order
//     m,s,a,p (was m,s,p,a in safariH2Config), ConnectionWindowUpdate 10420225
//   - HTTP/2 headers: priority added, sec-fetch-user removed, accept-encoding
//     gains zstd, header order completely reshuffled
//   - HTTP/3 QUIC: 2 MiB stream / 16 MiB connection flow control, 8 max
//     incoming uni streams (vs Chrome's 103). TLS bytes (HelloIOS_18,
//     HelloIOS_18_QUIC) match Chrome 146 iOS exactly — no utls update needed
//
// Note: chrome-146-ios and chrome-147-ios are intentionally NOT updated; this
// preset captures the deeper iOS-Chrome-specific divergences as of 148 only.
func IOSChrome148() *Preset {
	if p := LookupCustom("chrome-148-ios"); p != nil {
		return p
	}
	return IOSChrome146()
}

// IOSChrome150 returns Chrome 150 on iOS — a pure header/UA bump over the 148 iOS
// base (User-Agent: iOS 26_5_0, CriOS/150.0.7871.51). The TLS bytes (Safari/WebKit
// HelloIOS_18) are unchanged, and verified byte-exact against a real iOS 26.5
// capture: JA4 t13d2013h2_a09f3c656075_7f0f34a4126d, matching Akamai H2 and
// peetprint. iOS Chrome does NOT advertise ML-DSA (that is a desktop/Android
// Chromium-BoringSSL trait; iOS uses Safari's stack), so unlike the desktop
// chrome-150 line this preset carries no signature_algorithms override.
// Falls back to IOSChrome148 if the JSON didn't load.
func IOSChrome150() *Preset {
	if p := LookupCustom("chrome-150-ios"); p != nil {
		return p
	}
	return IOSChrome148()
}

// AndroidChrome147 returns Chrome 147 on Android. Same diff pattern as
// desktop (UA bump + sec-ch-ua brand rotation); inherits Linux-flavored
// TLS from chrome-146-android. Falls back to AndroidChrome146.
func AndroidChrome147() *Preset {
	if p := LookupCustom("chrome-147-android"); p != nil {
		return p
	}
	return AndroidChrome146()
}

// Chrome148Windows returns Chrome 148 on Windows. Wire-level diff vs 147 is
// two header values: User-Agent version bump and sec-ch-ua brand list rotation
// (Chromium moved to first position, GREASE brand "Not.A/Brand" v="8" became
// "Not/A)Brand" v="99"). TLS extension order keeps shuffling per-handshake the
// same way 147 already does. Embedded JSON only overrides the two header
// values; everything else inherits from chrome-147-windows. Falls back to
// Chrome147Windows if the JSON didn't load.
func Chrome148Windows() *Preset {
	if p := LookupCustom("chrome-148-windows"); p != nil {
		return p
	}
	return Chrome147Windows()
}

// Chrome148Linux returns Chrome 148 on Linux. See Chrome148Windows.
func Chrome148Linux() *Preset {
	if p := LookupCustom("chrome-148-linux"); p != nil {
		return p
	}
	return Chrome147Linux()
}

// Chrome148macOS returns Chrome 148 on macOS. See Chrome148Windows.
func Chrome148macOS() *Preset {
	if p := LookupCustom("chrome-148-macos"); p != nil {
		return p
	}
	return Chrome147macOS()
}

// Chrome148 returns the Chrome 148 fingerprint preset auto-detected from the
// running OS.
func Chrome148() *Preset {
	switch GetPlatformInfo().Platform {
	case "Windows":
		return Chrome148Windows()
	case "macOS":
		return Chrome148macOS()
	default:
		return Chrome148Linux()
	}
}

// AndroidChrome148 returns Chrome 148 on Android. Same two-header diff
// pattern as the desktop variants. Falls back to AndroidChrome147.
func AndroidChrome148() *Preset {
	if p := LookupCustom("chrome-148-android"); p != nil {
		return p
	}
	return AndroidChrome147()
}

// AndroidChrome150 returns Chrome 150 on Android. Android Chrome runs the same
// Chromium/BoringSSL stack as desktop (the iOS line is the WebKit exception), and
// the Android TLS base is HelloChrome_146_Linux — identical to desktop Linux — so
// this preset carries the SAME ML-DSA signature_algorithms override as the desktop
// chrome-150 line (ML-DSA on TCP, none on QUIC). Headers are the reduced-UA mobile
// bump: Chrome/150 with the frozen "Android 10; K" model, sec-ch-ua-mobile ?1,
// sec-ch-ua-platform "Android", and the version-keyed (platform-independent)
// sec-ch-ua brand shared with desktop 150.
//
// DERIVED (not yet captured from a device): the TLS/JA4 and reduced UA/sec-ch-ua
// are deterministic, but whether Chrome ships the ML-DSA sig-algs field trial on
// Android is assumed to match desktop pending a real Android 150 capture.
// Falls back to AndroidChrome148 if the JSON didn't load.
func AndroidChrome150() *Preset {
	if p := LookupCustom("chrome-150-android"); p != nil {
		return p
	}
	return AndroidChrome148()
}

// Chrome149Windows returns Chrome 149 on Windows. The wire-level fingerprint is
// byte-identical to 148 (verified against a real Chrome 149 capture: JA4
// t13d1516h2_8daaf6152771_d8a2da3f94cd, peetprint
// 1d4ffe9b0e34acac0bd883fa7f79d7b5, and Akamai H2
// 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p all match 148). The only
// diff is two header values: the User-Agent version bump and a sec-ch-ua brand
// rotation (Google Chrome moved to first position, GREASE brand became
// "Not)A;Brand" v="24"). Embedded JSON overrides just those; everything else
// inherits from chrome-148-windows. Falls back to Chrome148Windows if the JSON
// didn't load.
func Chrome149Windows() *Preset {
	if p := LookupCustom("chrome-149-windows"); p != nil {
		return p
	}
	return Chrome148Windows()
}

// Chrome149Linux returns Chrome 149 on Linux. See Chrome149Windows.
func Chrome149Linux() *Preset {
	if p := LookupCustom("chrome-149-linux"); p != nil {
		return p
	}
	return Chrome148Linux()
}

// Chrome149macOS returns Chrome 149 on macOS. See Chrome149Windows.
func Chrome149macOS() *Preset {
	if p := LookupCustom("chrome-149-macos"); p != nil {
		return p
	}
	return Chrome148macOS()
}

// Chrome149 returns the Chrome 149 fingerprint preset auto-detected from the
// running OS.
func Chrome149() *Preset {
	switch GetPlatformInfo().Platform {
	case "Windows":
		return Chrome149Windows()
	case "macOS":
		return Chrome149macOS()
	default:
		return Chrome149Linux()
	}
}

// Chrome150Windows returns Chrome 150 on Windows. The base TLS/H2/QUIC fingerprint
// is inherited byte-for-byte from the chrome-149 chain; Chrome 150 adds two things
// over 149, both captured from a real Chrome 150:
//   - TCP signature_algorithms now prepend the three ML-DSA post-quantum codepoints
//     (0x0904-0x0906 = ML-DSA-44/65/87, draft-ietf-tls-mldsa), giving JA4
//     t13d1516h2_8daaf6152771_806a8c22fdea. QUIC is left unchanged (Chrome does NOT
//     advertise ML-DSA over QUIC — anti-amplification limits — so JA4 stays
//     q13d0311h3_55b375c5d22e_653d80c3fe9d).
//   - User-Agent bump and a sec-ch-ua brand rotation (GREASE brand became
//     "Not;A=Brand" v="8", moved to first position).
//
// Embedded JSON overrides just those; everything else inherits. Falls back to
// Chrome149Windows if the JSON didn't load.
func Chrome150Windows() *Preset {
	if p := LookupCustom("chrome-150-windows"); p != nil {
		return p
	}
	return Chrome149Windows()
}

// Chrome150Linux returns Chrome 150 on Linux. See Chrome150Windows.
func Chrome150Linux() *Preset {
	if p := LookupCustom("chrome-150-linux"); p != nil {
		return p
	}
	return Chrome149Linux()
}

// Chrome150macOS returns Chrome 150 on macOS. See Chrome150Windows.
func Chrome150macOS() *Preset {
	if p := LookupCustom("chrome-150-macos"); p != nil {
		return p
	}
	return Chrome149macOS()
}

// Chrome150 returns the Chrome 150 fingerprint preset auto-detected from the
// running OS.
func Chrome150() *Preset {
	switch GetPlatformInfo().Platform {
	case "Windows":
		return Chrome150Windows()
	case "macOS":
		return Chrome150macOS()
	default:
		return Chrome150Linux()
	}
}

// Chrome151Windows returns Chrome 151 on Windows. Pure header diff over the
// chrome-150 chain, verified against real Chrome 151 captures over both TCP and
// QUIC. Everything below the header layer is unchanged: the same cipher list,
// supported groups, ALPS, ECH and brotli cert compression, the same Akamai H2
// fingerprint (1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p), and the same
// signature_algorithms including the three ML-DSA codepoints inherited from 150
// (JA4 t13d1516h2_8daaf6152771_806a8c22fdea).
//
// Two header values move, and the second is not what a naive version bump would
// produce - Chrome's greased brand list reseeds off the major version, so the
// separator characters, the GREASE version and the brand ORDER all changed at
// once:
//
//	150: "Not;A=Brand";v="8",  "Chromium";v="150", "Google Chrome";v="150"
//	151: "Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"
//
// Falls back to Chrome150Windows if the JSON didn't load.
func Chrome151Windows() *Preset {
	if p := LookupCustom("chrome-151-windows"); p != nil {
		return p
	}
	return Chrome150Windows()
}

// Chrome151Linux returns Chrome 151 on Linux. See Chrome151Windows.
func Chrome151Linux() *Preset {
	if p := LookupCustom("chrome-151-linux"); p != nil {
		return p
	}
	return Chrome150Linux()
}

// Chrome151macOS returns Chrome 151 on macOS. See Chrome151Windows.
func Chrome151macOS() *Preset {
	if p := LookupCustom("chrome-151-macos"); p != nil {
		return p
	}
	return Chrome150macOS()
}

// Chrome151 returns the Chrome 151 fingerprint preset auto-detected from the
// running OS.
func Chrome151() *Preset {
	switch GetPlatformInfo().Platform {
	case "Windows":
		return Chrome151Windows()
	case "macOS":
		return Chrome151macOS()
	default:
		return Chrome151Linux()
	}
}

// AndroidChrome151 returns Chrome 151 on Android. Same header diff as desktop
// (UA bump plus the reseeded sec-ch-ua brand list); Android uses the reduced UA
// so there is no build number to track. Inherits the chrome-150-android TLS
// bytes. Falls back to AndroidChrome150.
func AndroidChrome151() *Preset {
	if p := LookupCustom("chrome-151-android"); p != nil {
		return p
	}
	return AndroidChrome150()
}

// IOSChrome151 returns Chrome 151 on iOS. Like the rest of the iOS Chrome line
// this is WebKit underneath, so it carries Safari's TLS and H2 fingerprint and
// sends no client hints at all - which means the User-Agent is the only thing
// that changes between iOS versions.
//
// PROVISIONAL: iOS Chrome spells its version out in full (CriOS/150.0.7871.51
// for 150) rather than using the reduced desktop form, and that build number
// cannot be derived from the major version. The value here is a placeholder
// pending a real iOS 151 capture. Because of that, "chrome-latest-ios"
// deliberately still resolves to IOSChrome150, so nobody gets an unverified
// fingerprint without asking for it by name. Once a capture lands, correct the
// user_agent in fingerprint/embedded/chrome-151-ios.json and repoint the alias.
//
// Falls back to IOSChrome150.
func IOSChrome151() *Preset {
	if p := LookupCustom("chrome-151-ios"); p != nil {
		return p
	}
	return IOSChrome150()
}

// IOSChrome143 returns Chrome 143 on iOS fingerprint preset
// Note: iOS Chrome uses WebKit (Apple requirement), so it has Safari's TLS AND HTTP/2 fingerprint
// WebKit doesn't support Client Hints, so no sec-ch-ua headers
func IOSChrome143() *Preset {
	return &Preset{
		Name:              "chrome-143-ios",
		ClientHelloID:     tls.HelloIOS_18,      // iOS Chrome uses Safari's TLS (WebKit requirement)
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Chrome uses Safari's QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/143.0.6917.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			// WebKit doesn't support Client Hints - no sec-ch-ua headers
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Dest":  "document",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Mode":  "navigate",
			"Accept-Language": "en-US,en;q=0.9",
			"Sec-Fetch-User":  "?1",
		},
		// Safari/WebKit header order
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-mode", "navigate"},
			{"user-agent", ""},
			{"accept-language", "en-US,en;q=0.9"},
			{"sec-fetch-user", "?1"},
		},
		// Safari/WebKit HTTP/2 settings
		// Akamai fingerprint: 2:0;4:2097152;3:100;9:1|10485760|0|m,s,p,a
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false, // iOS sends ENABLE_PUSH=0
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // iOS sends NO_RFC7540_PRIORITIES=1
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   true,
	}
}

// IOSChrome144 returns Chrome 144 on iOS fingerprint preset
// Note: iOS Chrome uses WebKit (Apple requirement), so it has Safari's TLS AND HTTP/2 fingerprint
// WebKit doesn't support Client Hints, so no sec-ch-ua headers
func IOSChrome144() *Preset {
	return &Preset{
		Name:              "chrome-144-ios",
		ClientHelloID:     tls.HelloIOS_18,      // iOS Chrome uses Safari's TLS (WebKit requirement)
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Chrome uses Safari's QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/144.0.6917.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			// WebKit doesn't support Client Hints - no sec-ch-ua headers
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Dest":  "document",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Mode":  "navigate",
			"Accept-Language": "en-US,en;q=0.9",
			"Sec-Fetch-User":  "?1",
		},
		// Safari/WebKit header order (from real iOS Chrome capture)
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-mode", "navigate"},
			{"user-agent", ""},
			{"accept-language", "en-US,en;q=0.9"},
			{"sec-fetch-user", "?1"},
		},
		// Safari/WebKit HTTP/2 settings (from real iOS Chrome capture)
		// Akamai fingerprint: 2:0;4:2097152;3:100;9:1|10485760|0|m,s,p,a
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false, // iOS sends ENABLE_PUSH=0
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // iOS sends NO_RFC7540_PRIORITIES=1
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   true,
	}
}

// IOSChrome145 returns Chrome 145 on iOS fingerprint preset
// Note: iOS Chrome uses WebKit (Apple requirement), so it has Safari's TLS AND HTTP/2 fingerprint
// WebKit doesn't support Client Hints, so no sec-ch-ua headers
func IOSChrome145() *Preset {
	return &Preset{
		Name:              "chrome-145-ios",
		ClientHelloID:     tls.HelloIOS_18,      // iOS Chrome uses Safari's TLS (WebKit requirement)
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Chrome uses Safari's QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/145.0.6917.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			// WebKit doesn't support Client Hints - no sec-ch-ua headers
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Dest":  "document",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Mode":  "navigate",
			"Accept-Language": "en-US,en;q=0.9",
			"Sec-Fetch-User":  "?1",
		},
		// Safari/WebKit header order (from real iOS Chrome capture)
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-mode", "navigate"},
			{"user-agent", ""},
			{"accept-language", "en-US,en;q=0.9"},
			{"sec-fetch-user", "?1"},
		},
		// Safari/WebKit HTTP/2 settings (from real iOS Chrome capture)
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false,
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   true,
	}
}

// IOSSafari17 returns Safari 17 on iOS fingerprint preset
func IOSSafari17() *Preset {
	return &Preset{
		Name:          "safari-17-ios",
		ClientHelloID: tls.HelloIOS_14,
		UserAgent:     "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.7 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			// Safari doesn't send Client Hints
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
		},
		// iOS Safari header order for HTTP/2 (same as macOS Safari)
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
			{"accept-language", "en-US,en;q=0.9"},
			{"accept-encoding", "gzip, deflate, br"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             true,
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // Safari uses m,s,p,a pseudo header order
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   false, // iOS Safari 17 doesn't have proper H3 TLS spec
	}
}

// IOSSafari18 returns Safari 18 on iOS fingerprint preset
func IOSSafari18() *Preset {
	return &Preset{
		Name:              "safari-18-ios",
		ClientHelloID:     tls.HelloIOS_18,
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Safari QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			// Safari doesn't send Client Hints
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
		},
		// iOS Safari header order for HTTP/2 (same as macOS Safari)
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
			{"accept-language", "en-US,en;q=0.9"},
			{"accept-encoding", "gzip, deflate, br"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
		},
		// iOS Safari HTTP/2 settings
		// Akamai fingerprint: 2:0;4:2097152;3:100;9:1|10485760|0|m,s,p,a
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false, // iOS 18 sends ENABLE_PUSH=0
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // iOS sends NO_RFC7540_PRIORITIES=1
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   true,
	}
}

// AndroidChrome143 returns Chrome 143 on Android fingerprint preset
// Note: Chrome on Android uses Chrome's TLS fingerprint (not WebKit restricted like iOS)
func AndroidChrome143() *Preset {
	return &Preset{
		Name:                 "chrome-143-android",
		ClientHelloID:        tls.HelloChrome_143_Linux,     // Android Chrome uses Chrome's TLS
		PSKClientHelloID:     tls.HelloChrome_143_Linux_PSK, // PSK for session resumption
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,      // QUIC for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK,  // QUIC PSK for session resumption
		UserAgent:            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Mobile Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints for mobile
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?1",
			"sec-ch-ua-platform": `"Android"`,
			// Standard navigation headers
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		// Chrome 143 header order for HTTP/2 and HTTP/3 (order matters!)
		// Same as desktop Chrome but with mobile flag
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?1"},
			{"sec-ch-ua-platform", `"Android"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			// Android Chrome uses same HTTP/2 settings as desktop Chrome
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// AndroidChrome144 returns Chrome 144 on Android fingerprint preset
func AndroidChrome144() *Preset {
	return &Preset{
		Name:                 "chrome-144-android",
		ClientHelloID:        tls.HelloChrome_144_Linux,
		PSKClientHelloID:     tls.HelloChrome_144_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?1",
			"sec-ch-ua-platform":        `"Android"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?1"},
			{"sec-ch-ua-platform", `"Android"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// IOSChrome146 returns Chrome 146 on iOS fingerprint preset
// Note: iOS Chrome uses WebKit (Apple requirement), so it has Safari's TLS AND HTTP/2 fingerprint
// WebKit doesn't support Client Hints, so no sec-ch-ua headers
func IOSChrome146() *Preset {
	return &Preset{
		Name:              "chrome-146-ios",
		ClientHelloID:     tls.HelloIOS_18,      // iOS Chrome uses Safari's TLS (WebKit requirement)
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Chrome uses Safari's QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/146.0.6917.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			// WebKit doesn't support Client Hints - no sec-ch-ua headers
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Dest":  "document",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Mode":  "navigate",
			"Accept-Language": "en-US,en;q=0.9",
			"Sec-Fetch-User":  "?1",
		},
		// Safari/WebKit header order (from real iOS Chrome capture)
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-mode", "navigate"},
			{"user-agent", ""},
			{"accept-language", "en-US,en;q=0.9"},
			{"sec-fetch-user", "?1"},
		},
		// Safari/WebKit HTTP/2 settings (from real iOS Chrome capture)
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false,
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   true,
	}
}

// AndroidChrome146 returns Chrome 146 on Android fingerprint preset
func AndroidChrome146() *Preset {
	return &Preset{
		Name:                 "chrome-146-android",
		ClientHelloID:        tls.HelloChrome_146_Linux,
		PSKClientHelloID:     tls.HelloChrome_146_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_146_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_146_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
			"sec-ch-ua-mobile":          "?1",
			"sec-ch-ua-platform":        `"Android"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`},
			{"sec-ch-ua-mobile", "?1"},
			{"sec-ch-ua-platform", `"Android"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// AndroidChrome145 returns Chrome 145 on Android fingerprint preset
func AndroidChrome145() *Preset {
	return &Preset{
		Name:                 "chrome-145-android",
		ClientHelloID:        tls.HelloChrome_145_Linux,
		PSKClientHelloID:     tls.HelloChrome_145_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?1",
			"sec-ch-ua-platform":        `"Android"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?1"},
			{"sec-ch-ua-platform", `"Android"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

// presets is a map of all available presets
var presets = map[string]func() *Preset{
	"chrome-133":          Chrome133,
	"chrome-141":          Chrome141,
	"chrome-143":          Chrome143,
	"chrome-143-windows":  Chrome143Windows,
	"chrome-143-linux":    Chrome143Linux,
	"chrome-143-macos":    Chrome143macOS,
	"chrome-144":          Chrome144,
	"chrome-144-windows":  Chrome144Windows,
	"chrome-144-linux":    Chrome144Linux,
	"chrome-144-macos":    Chrome144macOS,
	"chrome-145":          Chrome145,
	"chrome-145-windows":  Chrome145Windows,
	"chrome-145-linux":    Chrome145Linux,
	"chrome-145-macos":    Chrome145macOS,
	"chrome-146":          Chrome146,
	"chrome-146-windows":  Chrome146Windows,
	"chrome-146-linux":    Chrome146Linux,
	"chrome-146-macos":    Chrome146macOS,
	"chrome-147":          Chrome147,
	"chrome-147-windows":  Chrome147Windows,
	"chrome-147-linux":    Chrome147Linux,
	"chrome-147-macos":    Chrome147macOS,
	"firefox-133":         Firefox133,
	"firefox-133-windows": Firefox133Windows,
	"firefox-133-linux":   Firefox133Linux,
	"firefox-133-macos":   Firefox133macOS,
	"firefox-148":         Firefox148,
	"firefox-148-windows": Firefox148Windows,
	"firefox-148-linux":   Firefox148Linux,
	"firefox-148-macos":   Firefox148macOS,
	"safari-18":           Safari18,
	"chrome-143-ios":      IOSChrome143,
	"chrome-144-ios":      IOSChrome144,
	"chrome-145-ios":      IOSChrome145,
	"chrome-146-ios":      IOSChrome146,
	"safari-17-ios":       IOSSafari17,
	"safari-18-ios":       IOSSafari18,
	"chrome-143-android":  AndroidChrome143,
	"chrome-144-android":  AndroidChrome144,
	"chrome-145-android":  AndroidChrome145,
	"chrome-146-android":  AndroidChrome146,
	"chrome-147-ios":      IOSChrome147,
	"chrome-147-android":  AndroidChrome147,
	"chrome-148-ios":      IOSChrome148,
	"chrome-148":          Chrome148,
	"chrome-148-windows":  Chrome148Windows,
	"chrome-148-linux":    Chrome148Linux,
	"chrome-148-macos":    Chrome148macOS,
	"chrome-148-android":  AndroidChrome148,
	"chrome-149":          Chrome149,
	"chrome-149-windows":  Chrome149Windows,
	"chrome-149-linux":    Chrome149Linux,
	"chrome-149-macos":    Chrome149macOS,
	"chrome-150":          Chrome150,
	"chrome-150-windows":  Chrome150Windows,
	"chrome-150-linux":    Chrome150Linux,
	"chrome-150-macos":    Chrome150macOS,
	"chrome-150-ios":      IOSChrome150,
	"chrome-150-android":  AndroidChrome150,
	"chrome-151":          Chrome151,
	"chrome-151-windows":  Chrome151Windows,
	"chrome-151-linux":    Chrome151Linux,
	"chrome-151-macos":    Chrome151macOS,
	"chrome-151-ios":      IOSChrome151,
	"chrome-151-android":  AndroidChrome151,

	// -latest aliases (always point to the newest version). Desktop and Android
	// track 151. iOS stays on 150 on purpose: the iOS User-Agent carries a full
	// build number that cannot be derived from the major version, so
	// chrome-151-ios is provisional until a real capture confirms it (see
	// IOSChrome151).
	"chrome-latest":          Chrome151,
	"chrome-latest-windows":  Chrome151Windows,
	"chrome-latest-linux":    Chrome151Linux,
	"chrome-latest-macos":    Chrome151macOS,
	"firefox-latest":         Firefox148,
	"firefox-latest-windows": Firefox148Windows,
	"firefox-latest-linux":   Firefox148Linux,
	"firefox-latest-macos":   Firefox148macOS,
	"safari-latest":          Safari18,
	"chrome-latest-ios":      IOSChrome150,
	"safari-latest-ios":      IOSSafari18,
	"chrome-latest-android":  AndroidChrome151,

	// Backwards compatibility aliases (old naming convention)
	"ios-chrome-143":        IOSChrome143,
	"ios-chrome-144":        IOSChrome144,
	"ios-chrome-145":        IOSChrome145,
	"ios-chrome-146":        IOSChrome146,
	"ios-chrome-147":        IOSChrome147,
	"ios-chrome-148":        IOSChrome148,
	"ios-safari-17":         IOSSafari17,
	"ios-safari-18":         IOSSafari18,
	"android-chrome-143":    AndroidChrome143,
	"android-chrome-144":    AndroidChrome144,
	"android-chrome-145":    AndroidChrome145,
	"android-chrome-146":    AndroidChrome146,
	"android-chrome-147":    AndroidChrome147,
	"android-chrome-148":    AndroidChrome148,
	"ios-chrome-latest":     IOSChrome148,
	"ios-safari-latest":     IOSSafari18,
	"android-chrome-latest": AndroidChrome148,
}

// Get returns a preset by name. Checks custom registry first, then built-in
// presets. Falls back to Chrome146 if not found.
func Get(name string) *Preset {
	if p := LookupCustom(name); p != nil {
		return p
	}
	if fn, ok := presets[name]; ok {
		return fn()
	}
	return Chrome146()
}

// GetStrict returns a preset by name, returning nil if not found (no fallback).
func GetStrict(name string) *Preset {
	if p := LookupCustom(name); p != nil {
		return p
	}
	if fn, ok := presets[name]; ok {
		return fn()
	}
	return nil
}

// Available returns a list of available preset names
func Available() []string {
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	return names
}

// PresetInfo contains metadata about a preset's protocol support.
type PresetInfo struct {
	Protocols []string `json:"protocols"`
}

// AvailableWithInfo returns a map of preset names to their supported protocols.
func AvailableWithInfo() map[string]PresetInfo {
	result := make(map[string]PresetInfo, len(presets))
	for name, presetFn := range presets {
		p := presetFn()
		protocols := []string{"h1", "h2"}
		if p.SupportHTTP3 {
			protocols = append(protocols, "h3")
		}
		result[name] = PresetInfo{Protocols: protocols}
	}
	return result
}
