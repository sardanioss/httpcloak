package transport

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/proxy"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	"github.com/sardanioss/udpbara"
	tls "github.com/sardanioss/utls"
	utls "github.com/sardanioss/utls"
)

// HTTP/3 SETTINGS identifiers
const (
	settingQPACKMaxTableCapacity = 0x1
	settingMaxFieldSectionSize   = 0x6
	settingQPACKBlockedStreams   = 0x7
	settingH3Datagram            = 0x33
)

// QUIC transport parameter IDs (Chrome-specific)
//
// Only the two below are actually sent. Chrome was previously also credited
// with google_version (0x4752 / 18258) and initial_rtt (0x3127 / 12583), but a
// real Chrome 151 QUIC capture sends neither: its ClientHello carries exactly
// 1, 3, 4, 5, 6, 7, 8, 9, 15, 17, 32, 12584 and one GREASE parameter. Sending
// the extra two was a fingerprint mismatch on every Chrome H3 request.
const (
	tpVersionInformation      = 0x11   // RFC 9368 version negotiation
	tpGoogleConnectionOptions = 0x3128 // Google's connection options param (12584)
)

// BuildChromeTransportParams creates Chrome-like QUIC transport parameters.
// Exported so pool and other packages can reference the canonical set.
func BuildChromeTransportParams() map[uint64][]byte {
	params := make(map[uint64][]byte)

	// version_information (0x11) - RFC 9368
	// Format: chosen_version (4 bytes) + available_versions (4 bytes each)
	// Chrome sends: QUICv1 (chosen) + [GREASE, QUICv1] (available)
	versionInfo := make([]byte, 0, 12)
	// Chosen version: QUICv1 (0x00000001)
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, 0x00000001)
	// Available versions: GREASE first (Chrome puts GREASE before QUICv1)
	greaseVersion := generateGREASEVersion()
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, greaseVersion)
	// Available versions: QUICv1
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, 0x00000001)
	params[tpVersionInformation] = versionInfo

	// google_connection_options (0x3128 / 12584) - 4-byte QUIC tag(s).
	// Stable Chrome ships with kQuicOptions default "ORIG" (origin-frame
	// experiment hint), per Chromium net/base/features.cc:
	//   BASE_FEATURE_PARAM(std::string, kQuicOptions, &kTryQuicByDefault,
	//                      "quic_options", "ORIG");
	// The previous "B2ON" value (Enable BBRv2) only appears when a Chrome
	// install has --enable-features=QuicConnectionOptions=B2ON or a Finch
	// override, which is rare on the open web — bot fingerprinters flag it.
	params[tpGoogleConnectionOptions] = []byte("ORIG")

	// Note: GREASE transport param is NOT added here — quic-go's Chrome-mode
	// marshaling (transport_parameters.go) already inserts exactly 1 GREASE param
	// at the correct position (after max_datagram_frame_size).

	return params
}

// MeasureInitialRTT returns the Chrome QUIC transport parameter set.
//
// Deprecated: this used to open a throwaway TCP connection to the target purely
// to time the SYN-ACK, so the round-trip could be sent as Chrome's initial_rtt
// (0x3127) transport parameter. Real Chrome sends no such parameter, so it has
// been dropped, and with it the probe: a stray TCP connect to the origin ahead
// of an HTTP/3 request was itself an observable tell. The function is kept so
// existing callers keep compiling, and now simply returns the standard Chrome
// parameters without touching the network.
func MeasureInitialRTT(_ context.Context, _ string, _ int) map[uint64][]byte {
	return BuildChromeTransportParams()
}

// MeasureAndSetInitialRTT sets the global Chrome transport params.
//
// Deprecated: pass params via quic.Config.AdditionalTransportParameters
// instead. No RTT is measured; see MeasureInitialRTT.
func MeasureAndSetInitialRTT(ctx context.Context, host string, port int) {
	quic.SetAdditionalTransportParameters(MeasureInitialRTT(ctx, host, port))
}

// ResetInitialRTT is a no-op.
//
// Deprecated: there is no cached RTT state to reset any more; see
// MeasureInitialRTT.
func ResetInitialRTT() {}

// AdditionalTransportParamsForPreset returns per-connection additional QUIC
// transport params appropriate for the given preset. For Chrome presets that is
// version_information (0x11) and google_connection_options (0x3128). For
// non-Chrome presets (e.g. Firefox) it returns nil so these Chrome-specific
// params are not sent.
//
// The ctx/host/port parameters are unused and retained for API compatibility;
// they previously drove the initial_rtt probe.
func AdditionalTransportParamsForPreset(preset *fingerprint.Preset, _ context.Context, _ string, _ int) map[uint64][]byte {
	if preset == nil {
		return nil
	}
	if preset.H3QUICTransportParamOrder() != "chrome" {
		return nil
	}
	return BuildChromeTransportParams()
}

// generateGREASEVersion generates a GREASE version of form 0x?a?a?a?a
func generateGREASEVersion() uint32 {
	// GREASE versions are of form 0x?a?a?a?a where ? is random nibble
	nibble := byte(rand.Intn(16))
	return uint32(nibble)<<28 | 0x0a000000 |
		uint32(nibble)<<20 | 0x000a0000 |
		uint32(nibble)<<12 | 0x00000a00 |
		uint32(nibble)<<4 | 0x0000000a
}

// proxyQUICConn bundles an udpbara connection with its per-connection quic.Transport.
// Both must be closed together: quic.Transport first (sends CONNECTION_CLOSE),
// then udpbara.Connection (closes sockets, deregisters from tunnel).
// Uses sync.Once to prevent double-close between auto-cleanup goroutine and closeAllProxyConns.
type proxyQUICConn struct {
	udpConn   *udpbara.Connection
	quicTr    *quic.Transport
	closeOnce sync.Once
}

// HTTP3Transport is an HTTP/3 transport with proper QUIC connection reuse
// http3.Transport handles connection pooling internally - we just provide DNS resolution
type HTTP3Transport struct {
	transport *http3.Transport
	preset    *fingerprint.Preset
	dnsCache  *dns.Cache

	// TLS session cache for 0-RTT resumption
	sessionCache tls.ClientSessionCache

	// Cached ClientHelloSpec for consistent TLS fingerprint
	// Chrome shuffles TLS extensions once per session, not per connection
	cachedClientHelloSpec *utls.ClientHelloSpec
	// PSK variant of the spec for session resumption (includes pre_shared_key extension)
	cachedClientHelloSpecPSK *utls.ClientHelloSpec

	// Separate cached spec for inner MASQUE connections (not shared with outer)
	cachedClientHelloSpecInner *utls.ClientHelloSpec
	// PSK variant for inner MASQUE connections
	cachedClientHelloSpecInnerPSK *utls.ClientHelloSpec

	// Resolved ClientHelloID (QUIC-specific, or TCP fallback). Used to regenerate
	// a FRESH ClientHelloSpec per dial. utls ApplyPreset mutates the spec in place
	// (KeyShares.Data, GREASE), so sharing one cached spec across concurrent QUIC
	// dials is a data race; each dial gets its own spec generated from this ID +
	// shuffleSeed, which keeps extension order (and thus JA3/JA4) byte-stable.
	clientHelloID *utls.ClientHelloID

	// Shuffle seed for TLS and transport parameter ordering (consistent per session)
	shuffleSeed int64

	// Track requests for timing
	requestCount int64
	dialCount    int64 // Number of times dialQUIC was called (new connections)
	mu           sync.RWMutex

	// ipv4FirstOverride transiently forces the Happy-Eyeballs QUIC dial to lead
	// with IPv4 regardless of the DNS cache's PreferIPv4 knob. doHTTP3 sets it for
	// a single redial after a forced-H3 roundtrip stalls on a path that completed
	// its QUIC handshake but then blackholes application data (the IPv6 PMTU
	// black-hole case), so the retry avoids the dead family. Reset right after.
	ipv4FirstOverride atomic.Bool

	// Configuration
	quicConfig *quic.Config
	tlsConfig  *tls.Config

	// Proxy support for SOCKS5 UDP relay via udpbara
	proxyConfig   *ProxyConfig
	usesUDPProxy  bool            // true when configured for a SOCKS5 UDP relay (drives dialFunc selection before the tunnel is connected)
	udpbaraTunnel *udpbara.Tunnel // SOCKS5 UDP relay tunnel (shared across dials; connected lazily on first H3 dial)
	udpbaraMu     sync.Mutex      // guards lazy connect of udpbaraTunnel
	proxyConns    []*proxyQUICConn
	proxyConnsMu  sync.Mutex
	quicTransport *quic.Transport // Only used for direct connections

	// MASQUE proxy support
	masqueConn *proxy.MASQUEConn

	// Advanced configuration (ConnectTo, ECH override)
	config *TransportConfig

	// ECH config cache - stores ECH configs per host for session resumption
	// Per-host ECH config cache. Entries carry an expiry so a long-lived
	// transport refetches periodically instead of pinning one config forever;
	// pinning forever strands the session on a stale config after the CDN
	// rotates ECH keys, which the server rejects with illegal_parameter on every
	// handshake until restart. Also invalidated on a handshake rejection for
	// fast self-healing (see invalidateECHConfig).
	echConfigCache   map[string]*echCachedConfig
	echConfigCacheMu sync.RWMutex

	// Skip TLS certificate verification (for testing)
	insecureSkipVerify bool
	tlsVerify          *TLSVerify

	// Skip ECH lookup for faster first request (ECH is optional privacy feature)
	disableECH bool

	// Local address for binding outgoing connections (IPv6 rotation)
	localAddr string
}

// SetInsecureSkipVerify sets whether to skip TLS certificate verification
// SetTLSVerify installs caller-supplied certificate verification hooks.
// Only verification is configurable; nothing here affects the ClientHello.
func (t *HTTP3Transport) SetTLSVerify(v *TLSVerify) {
	t.tlsVerify = v
}

func (t *HTTP3Transport) SetInsecureSkipVerify(skip bool) {
	t.insecureSkipVerify = skip
	if t.tlsConfig != nil {
		t.tlsConfig.InsecureSkipVerify = skip
	}
}

// SetLocalAddr sets the local IP address for outgoing connections
func (t *HTTP3Transport) SetLocalAddr(addr string) {
	t.localAddr = addr
}

// SetDisableECH disables ECH (Encrypted Client Hello) lookup for faster first request
// ECH is an optional privacy feature - disabling it saves ~15-20ms on first connection
func (t *HTTP3Transport) SetDisableECH(disable bool) {
	t.disableECH = disable
}

// hasSessionForHost checks if there's a cached TLS session for the given host
// This is used to determine whether to use PSK spec (for resumption) or regular spec
func (t *HTTP3Transport) hasSessionForHost(host string) bool {
	if t.sessionCache == nil {
		return false
	}
	// Session key format is just the server name in TLS 1.3
	cache, ok := t.sessionCache.(*PersistableSessionCache)
	if !ok {
		return false
	}
	_, found := cache.Get(host)
	return found
}

// getSpecForHost returns a FRESH ClientHelloSpec for this dial. utls ApplyPreset
// (and quic-go's GREASE write-back) mutate the spec in place, so handing the same
// cached spec to concurrent QUIC dials is a data race. We regenerate per call from
// the stored ClientHelloID + shuffleSeed: the seed makes the extension order (and
// therefore JA3/JA4) byte-identical every time, while each connection mutates its
// own private spec. This mirrors the HTTP/2 transport, which is already race-clean.
//
// The PSK variant (which carries the early_data + pre_shared_key extensions) is
// used only when there is a cached session to resume; Chrome does not send
// early_data on a fresh connection.
func (t *HTTP3Transport) getSpecForHost(host string) *utls.ClientHelloSpec {
	if t.preset.QUICPSKClientHelloID.Client != "" && t.hasSessionForHost(host) {
		if spec, err := fingerprint.SpecFor(t.preset.QUICPSKClientHelloID, t.shuffleSeed, t.preset.QUICSignatureAlgorithms); err == nil {
			return spec
		}
	}
	if t.clientHelloID != nil {
		if spec, err := fingerprint.SpecFor(*t.clientHelloID, t.shuffleSeed, t.preset.QUICSignatureAlgorithms); err == nil {
			return spec
		}
	}
	return nil
}

// getInnerSpecForHost is the inner-MASQUE counterpart of getSpecForHost. Same
// fresh-per-dial regeneration so concurrent MASQUE inner dials never share a spec;
// kept a separate object from the outer connection for a consistent inner JA4.
func (t *HTTP3Transport) getInnerSpecForHost(host string) *utls.ClientHelloSpec {
	if t.preset.QUICPSKClientHelloID.Client != "" && t.hasSessionForHost(host) {
		if spec, err := fingerprint.SpecFor(t.preset.QUICPSKClientHelloID, t.shuffleSeed, t.preset.QUICSignatureAlgorithms); err == nil {
			return spec
		}
	}
	if t.clientHelloID != nil {
		if spec, err := fingerprint.SpecFor(*t.clientHelloID, t.shuffleSeed, t.preset.QUICSignatureAlgorithms); err == nil {
			return spec
		}
	}
	return nil
}

// NewHTTP3Transport creates a new HTTP/3 transport
func NewHTTP3Transport(preset *fingerprint.Preset, dnsCache *dns.Cache) (*HTTP3Transport, error) {
	return NewHTTP3TransportWithTransportConfig(preset, dnsCache, nil)
}

// NewHTTP3TransportWithTransportConfig creates a new HTTP/3 transport with advanced config
func NewHTTP3TransportWithTransportConfig(preset *fingerprint.Preset, dnsCache *dns.Cache, config *TransportConfig) (*HTTP3Transport, error) {
	// Generate shuffle seed for session-consistent ordering
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	// Create session cache - with optional distributed backend
	var sessionCache *PersistableSessionCache
	if config != nil && config.SessionCacheBackend != nil {
		sessionCache = NewPersistableSessionCacheWithBackend(
			config.SessionCacheBackend,
			preset.Name,
			"h3",
			config.SessionCacheErrorCallback,
		)
	} else {
		sessionCache = NewPersistableSessionCache()
	}

	t := &HTTP3Transport{
		preset:         preset,
		dnsCache:       dnsCache,
		sessionCache:   sessionCache,
		shuffleSeed:    shuffleSeed,
		config:         config,
		echConfigCache: make(map[string]*echCachedConfig), // Cache for ECH configs (for session resumption)
	}

	// Get the ClientHelloID for TLS fingerprinting in QUIC
	// Use QUIC-specific preset if available (different TLS extensions for HTTP/3)
	var clientHelloID *utls.ClientHelloID
	if preset.QUICClientHelloID.Client != "" {
		// Use QUIC-specific ClientHello (proper HTTP/3 fingerprint)
		clientHelloID = &preset.QUICClientHelloID
	} else if preset.ClientHelloID.Client != "" {
		// Fallback to TCP ClientHello if no QUIC-specific one
		clientHelloID = &preset.ClientHelloID
	}
	t.clientHelloID = clientHelloID // stored for fresh-spec-per-dial regeneration

	// Cache the ClientHelloSpec for consistent TLS fingerprint across connections
	// Chrome shuffles TLS extensions once per session, not per connection
	// Use the shuffle seed for deterministic ordering
	if clientHelloID != nil {
		spec, err := utls.UTLSIdToSpecWithSeed(*clientHelloID, shuffleSeed)
		if err == nil {
			fingerprint.ApplySignatureAlgorithms(spec.Extensions, preset.QUICSignatureAlgorithms)
			t.cachedClientHelloSpec = &spec
		}
	}

	// Also cache the PSK spec for session resumption (includes pre_shared_key extension)
	// Chrome uses a different TLS extension set when resuming with PSK
	if preset.QUICPSKClientHelloID.Client != "" {
		if pskSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			fingerprint.ApplySignatureAlgorithms(pskSpec.Extensions, preset.QUICSignatureAlgorithms)
			t.cachedClientHelloSpecPSK = &pskSpec
		}
	}

	// Determine key log writer - config override or global
	var keyLogWriter io.Writer
	if config != nil && config.KeyLogWriter != nil {
		keyLogWriter = config.KeyLogWriter
	} else {
		keyLogWriter = GetKeyLogWriter()
	}

	// Create TLS config for QUIC
	// Only enable session cache if we have PSK spec - prevents panic when session
	// is cached but spec doesn't have PSK extension (TOCTOU race mitigation)
	t.tlsConfig = &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: t.insecureSkipVerify,
		KeyLogWriter:       keyLogWriter,
	}
	t.tlsVerify.Apply(t.tlsConfig)
	if t.cachedClientHelloSpecPSK != nil {
		t.tlsConfig.ClientSessionCache = t.sessionCache
	}

	// Determine QUIC idle timeout (default 30s, configurable)
	quicIdleTimeout := 30 * time.Second
	if config != nil && config.QuicIdleTimeout > 0 {
		quicIdleTimeout = config.QuicIdleTimeout
	}

	// Build QUIC config from preset getters (0 = use preset default for InitialPacketSize)
	t.quicConfig = t.buildQUICConfig(clientHelloID, quicIdleTimeout, 0)

	// Build H3 additional settings from preset getters
	additionalSettings := t.buildH3AdditionalSettings()

	// Apply localAddr from config
	if config != nil && config.LocalAddr != "" {
		t.localAddr = config.LocalAddr
	}

	// Create QUIC transport for direct connections
	// We need a bound UDP socket for quic.Transport
	var localUDPAddr *net.UDPAddr
	if t.localAddr != "" {
		localUDPAddr = &net.UDPAddr{IP: net.ParseIP(t.localAddr)}
	} else {
		localUDPAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	udpConn, err := ListenUDPWithLocalAddr("udp", localUDPAddr, t.localAddr)
	if err != nil {
		if t.localAddr != "" {
			// localAddr is set — retrying with the same IP on "udp6" won't help
			return nil, fmt.Errorf("failed to create UDP socket for %s: %w", t.localAddr, err)
		}
		// Fallback to IPv6 if IPv4 fails (no localAddr — try IPv6zero)
		localUDPAddr = &net.UDPAddr{IP: net.IPv6zero, Port: 0}
		udpConn, err = ListenUDPWithLocalAddr("udp6", localUDPAddr, t.localAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create UDP socket (IPv4 and IPv6 both failed): %w", err)
		}
	}
	t.quicTransport = &quic.Transport{
		Conn:                         udpConn,
		ConnectionIDLength:           t.preset.H3QUICConnectionIDLength(),
		AllowZeroLengthConnectionIDs: true,
	}

	// Create HTTP/3 transport with custom dial for DNS caching
	// http3.Transport handles connection pooling internally
	t.transport = t.buildHTTP3Transport(t.dialQUIC, additionalSettings)

	return t, nil
}

// NewHTTP3TransportWithProxy creates a new HTTP/3 transport with SOCKS5 proxy support
// Only SOCKS5 proxies support UDP relay needed for QUIC/HTTP3
func NewHTTP3TransportWithProxy(preset *fingerprint.Preset, dnsCache *dns.Cache, proxyConfig *ProxyConfig) (*HTTP3Transport, error) {
	return NewHTTP3TransportWithConfig(preset, dnsCache, proxyConfig, nil)
}

// NewHTTP3TransportWithConfig creates a new HTTP/3 transport with SOCKS5 proxy and advanced config
func NewHTTP3TransportWithConfig(preset *fingerprint.Preset, dnsCache *dns.Cache, proxyConfig *ProxyConfig, config *TransportConfig) (*HTTP3Transport, error) {
	// Require a SOCKS5 proxy — this constructor is specifically for proxied H3.
	// Use NewHTTP3TransportWithTransportConfig for direct (non-proxied) H3.
	if proxyConfig == nil || proxyConfig.URL == "" {
		return nil, fmt.Errorf("NewHTTP3TransportWithConfig requires a proxy; use NewHTTP3TransportWithTransportConfig for direct connections")
	}
	// Validate proxy scheme - only SOCKS5 works for UDP/QUIC
	if proxyConfig.URL != "" {
		proxyURL, err := url.Parse(proxyConfig.URL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		if proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h" {
			return nil, fmt.Errorf("HTTP/3 requires SOCKS5 proxy for UDP relay, got: %s", proxyURL.Scheme)
		}
	}

	// Generate shuffle seed for session-consistent ordering
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	// Create session cache - with optional distributed backend
	var sessionCache *PersistableSessionCache
	if config != nil && config.SessionCacheBackend != nil {
		sessionCache = NewPersistableSessionCacheWithBackend(
			config.SessionCacheBackend,
			preset.Name,
			"h3",
			config.SessionCacheErrorCallback,
		)
	} else {
		sessionCache = NewPersistableSessionCache()
	}

	t := &HTTP3Transport{
		preset:         preset,
		dnsCache:       dnsCache,
		sessionCache:   sessionCache,
		shuffleSeed:    shuffleSeed,
		proxyConfig:    proxyConfig,
		config:         config,
		echConfigCache: make(map[string]*echCachedConfig),
	}

	// Apply localAddr from config
	if config != nil && config.LocalAddr != "" {
		t.localAddr = config.LocalAddr
	}

	// Get ClientHelloID for TLS fingerprinting
	var clientHelloID *utls.ClientHelloID
	if preset.QUICClientHelloID.Client != "" {
		clientHelloID = &preset.QUICClientHelloID
	} else if preset.ClientHelloID.Client != "" {
		clientHelloID = &preset.ClientHelloID
	}

	t.clientHelloID = clientHelloID // stored for fresh-spec-per-dial regeneration

	// Cache ClientHelloSpec for consistent fingerprint
	if clientHelloID != nil {
		spec, err := utls.UTLSIdToSpecWithSeed(*clientHelloID, shuffleSeed)
		if err == nil {
			fingerprint.ApplySignatureAlgorithms(spec.Extensions, preset.QUICSignatureAlgorithms)
			t.cachedClientHelloSpec = &spec
		}
	}

	// Also cache the PSK spec for session resumption (includes pre_shared_key extension)
	if preset.QUICPSKClientHelloID.Client != "" {
		if pskSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			fingerprint.ApplySignatureAlgorithms(pskSpec.Extensions, preset.QUICSignatureAlgorithms)
			t.cachedClientHelloSpecPSK = &pskSpec
		}
	}

	// Determine key log writer - config override or global
	var keyLogWriter io.Writer
	if config != nil && config.KeyLogWriter != nil {
		keyLogWriter = config.KeyLogWriter
	} else {
		keyLogWriter = GetKeyLogWriter()
	}

	// Create TLS config for QUIC
	// Only enable session cache if we have PSK spec - prevents panic when session
	// is cached but spec doesn't have PSK extension (TOCTOU race mitigation)
	t.tlsConfig = &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: t.insecureSkipVerify,
		KeyLogWriter:       keyLogWriter,
	}
	t.tlsVerify.Apply(t.tlsConfig)
	if t.cachedClientHelloSpecPSK != nil {
		t.tlsConfig.ClientSessionCache = t.sessionCache
	}

	// Determine QUIC idle timeout (default 30s, configurable)
	quicIdleTimeout := 30 * time.Second
	if config != nil && config.QuicIdleTimeout > 0 {
		quicIdleTimeout = config.QuicIdleTimeout
	}

	// Build QUIC config from preset getters (0 = use preset default for InitialPacketSize)
	t.quicConfig = t.buildQUICConfig(clientHelloID, quicIdleTimeout, 0)

	// Mark this transport as a SOCKS5 UDP relay when a proxy is configured. The
	// udpbara tunnel itself is connected lazily on the first H3 dial (see
	// ensureUDPTunnel) rather than here. Connecting at construction made
	// NewSession do blocking network I/O against the proxy — a stalling proxy
	// hung session creation indefinitely, and it ran even for forced-H1/H2
	// sessions that never touch H3. Lazy connect keeps construction instant and
	// bounds the connect by the dial's own context.
	if proxyConfig != nil && proxyConfig.URL != "" {
		t.usesUDPProxy = true
		// Note: quicTransport is NOT created here — each dial creates its own per-connection
	}

	// Build H3 additional settings from preset getters
	additionalSettings := t.buildH3AdditionalSettings()

	// Create HTTP/3 transport with appropriate dial function
	var dialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)
	if t.usesUDPProxy {
		dialFunc = t.dialQUICWithProxy
	} else {
		dialFunc = t.dialQUIC
	}
	t.transport = t.buildHTTP3Transport(dialFunc, additionalSettings)

	return t, nil
}

// NewHTTP3TransportWithMASQUE creates a new HTTP/3 transport with MASQUE proxy support.
// MASQUE allows HTTP/3 (QUIC) traffic to be tunneled through an HTTP/3 proxy using
// the CONNECT-UDP method defined in RFC 9298.
func NewHTTP3TransportWithMASQUE(preset *fingerprint.Preset, dnsCache *dns.Cache, proxyConfig *ProxyConfig, config *TransportConfig) (*HTTP3Transport, error) {
	// Generate shuffle seed for session-consistent ordering
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	// Create session cache - with optional distributed backend
	var sessionCache *PersistableSessionCache
	if config != nil && config.SessionCacheBackend != nil {
		sessionCache = NewPersistableSessionCacheWithBackend(
			config.SessionCacheBackend,
			preset.Name,
			"h3",
			config.SessionCacheErrorCallback,
		)
	} else {
		sessionCache = NewPersistableSessionCache()
	}

	t := &HTTP3Transport{
		preset:         preset,
		dnsCache:       dnsCache,
		sessionCache:   sessionCache,
		shuffleSeed:    shuffleSeed,
		proxyConfig:    proxyConfig,
		config:         config,
		echConfigCache: make(map[string]*echCachedConfig),
	}

	// Apply localAddr from config
	if config != nil && config.LocalAddr != "" {
		t.localAddr = config.LocalAddr
	}

	// Get ClientHelloID for TLS fingerprinting
	var clientHelloID *utls.ClientHelloID
	if preset.QUICClientHelloID.Client != "" {
		clientHelloID = &preset.QUICClientHelloID
	} else if preset.ClientHelloID.Client != "" {
		clientHelloID = &preset.ClientHelloID
	}

	t.clientHelloID = clientHelloID // stored for fresh-spec-per-dial regeneration

	// Cache ClientHelloSpec for consistent fingerprint (outer connection to proxy)
	if clientHelloID != nil {
		spec, err := utls.UTLSIdToSpecWithSeed(*clientHelloID, shuffleSeed)
		if err == nil {
			fingerprint.ApplySignatureAlgorithms(spec.Extensions, preset.QUICSignatureAlgorithms)
			t.cachedClientHelloSpec = &spec
		}
		// Create separate cached spec for inner connections (not shared with outer)
		// This ensures JA4 hash is consistent across inner requests
		innerSpec, err := utls.UTLSIdToSpecWithSeed(*clientHelloID, shuffleSeed)
		if err == nil {
			fingerprint.ApplySignatureAlgorithms(innerSpec.Extensions, preset.QUICSignatureAlgorithms)
			t.cachedClientHelloSpecInner = &innerSpec
		}
	}

	// Also cache PSK specs for session resumption (includes pre_shared_key extension)
	if preset.QUICPSKClientHelloID.Client != "" {
		// Outer PSK spec
		if pskSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			fingerprint.ApplySignatureAlgorithms(pskSpec.Extensions, preset.QUICSignatureAlgorithms)
			t.cachedClientHelloSpecPSK = &pskSpec
		}
		// Inner PSK spec for MASQUE connections
		if innerPskSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			fingerprint.ApplySignatureAlgorithms(innerPskSpec.Extensions, preset.QUICSignatureAlgorithms)
			t.cachedClientHelloSpecInnerPSK = &innerPskSpec
		}
	}

	// Determine key log writer - config override or global
	var keyLogWriter io.Writer
	if config != nil && config.KeyLogWriter != nil {
		keyLogWriter = config.KeyLogWriter
	} else {
		keyLogWriter = GetKeyLogWriter()
	}

	// Create TLS config for QUIC
	// Only enable session cache if we have PSK spec - prevents panic when session
	// is cached but spec doesn't have PSK extension (TOCTOU race mitigation)
	t.tlsConfig = &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: t.insecureSkipVerify,
		KeyLogWriter:       keyLogWriter,
	}
	t.tlsVerify.Apply(t.tlsConfig)
	if t.cachedClientHelloSpecPSK != nil {
		t.tlsConfig.ClientSessionCache = t.sessionCache
	}

	// Determine QUIC idle timeout (default 30s, configurable)
	quicIdleTimeout := 30 * time.Second
	if config != nil && config.QuicIdleTimeout > 0 {
		quicIdleTimeout = config.QuicIdleTimeout
	}

	// Build QUIC config with MASQUE-specific InitialPacketSize override (1350).
	// MASQUE encapsulates inner QUIC packets (up to 1200 bytes) as HTTP/3 datagrams,
	// which adds overhead. If outer packets are too small, inner packets get fragmented
	// and the connection hangs.
	t.quicConfig = t.buildQUICConfig(clientHelloID, quicIdleTimeout, 1350)

	// Create MASQUE connection
	masqueConn, err := proxy.NewMASQUEConn(proxyConfig.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create MASQUE connection: %w", err)
	}
	t.masqueConn = masqueConn

	// Build H3 additional settings from preset getters
	additionalSettings := t.buildH3AdditionalSettings()

	// Create HTTP/3 transport with MASQUE dial function
	t.transport = t.buildHTTP3Transport(t.dialQUICWithMASQUE, additionalSettings)

	return t, nil
}

// dialQUICWithMASQUE dials a QUIC connection through a MASQUE proxy.
// The connection is tunneled through the proxy using HTTP/3 CONNECT-UDP.
func (t *HTTP3Transport) dialQUICWithMASQUE(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	t.mu.Lock()
	t.dialCount++
	t.mu.Unlock()

	// Parse host:port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	// Get the connection host (may be different for domain fronting)
	connectHost := t.getConnectHost(host)

	// Convert port to int
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// Establish MASQUE tunnel with Chrome fingerprinting.
	// Clone the config and hand the outer establish its own fresh ClientHelloSpec
	// (rather than the shared t.quicConfig base) so a concurrent first-use of the
	// tunnel can't race-mutate one spec via ApplyPreset.
	masqueCfg := t.quicConfig.Clone()
	masqueCfg.CachedClientHelloSpec = t.getSpecForHost(connectHost)
	err = t.masqueConn.EstablishWithQUICConfig(ctx, connectHost, portInt, t.tlsConfig, masqueCfg)
	if err != nil {
		return nil, fmt.Errorf("MASQUE tunnel establishment failed: %w", err)
	}

	// Resolve target DNS
	ip, err := t.dnsCache.ResolveOne(ctx, connectHost)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", connectHost, err)
	}

	targetAddr := &net.UDPAddr{IP: ip, Port: portInt}

	// Set resolved target so ReadFrom returns the correct source address
	t.masqueConn.SetResolvedTarget(targetAddr)

	// Set ServerName in TLS config - use request host (SNI), not connection host
	tlsCfgCopy := tlsCfg.Clone()
	tlsCfgCopy.ServerName = host
	// Clone() doesn't preserve ClientSessionCache, restore it for session resumption
	// Only if we have PSK spec to prevent TOCTOU race
	if t.cachedClientHelloSpecPSK != nil {
		tlsCfgCopy.ClientSessionCache = t.sessionCache
	}

	// Fetch ECH config for inner connection
	echConfigList := t.getECHConfig(ctx, host)

	// Get ClientHelloID for inner connection - required for ECH to work
	// ECH is only applied when using uTLS (ClientHelloID or CachedClientHelloSpec)
	var clientHelloID *utls.ClientHelloID
	if t.preset.QUICClientHelloID.Client != "" {
		clientHelloID = &t.preset.QUICClientHelloID
	} else if t.preset.ClientHelloID.Client != "" {
		clientHelloID = &t.preset.ClientHelloID
	}

	// For inner connection through MASQUE tunnel, use Chrome fingerprinting + ECH.
	// MASQUE FINGERPRINT LIMITATIONS (see docs/MASQUE_FINGERPRINT_LIMITATIONS.md):
	// - CachedClientHelloSpec: Uses SEPARATE spec (not shared with outer) for consistent JA4
	// - ChromeStyleInitialPackets: FAILS - multi-packet patterns break through tunnel
	// - DisableClientHelloScrambling: WORKS - simplifies handshake
	// - ClientHelloID: WORKS - uTLS generates Chrome-like ClientHello
	// - TransportParameterOrder: WORKS - Chrome transport param ordering

	// Switch to PSK ClientHelloSpec for resumed connections
	// If there's a cached session, use PSK spec (includes early_data + pre_shared_key extensions)
	// This tells utls to actually load and use the cached session for 0-RTT
	innerSpec := t.getInnerSpecForHost(host)

	// Determine QUIC idle timeout (default 30s, configurable)
	quicIdleTimeout := 30 * time.Second
	if t.config != nil && t.config.QuicIdleTimeout > 0 {
		quicIdleTimeout = t.config.QuicIdleTimeout
	}
	keepAlivePeriod := quicIdleTimeout / 2

	cfgCopy := &quic.Config{
		MaxIdleTimeout:                 quicIdleTimeout,
		KeepAlivePeriod:                keepAlivePeriod,
		MaxIncomingStreams:             t.preset.H3QUICMaxIncomingStreams(),
		MaxIncomingUniStreams:          t.preset.H3QUICMaxIncomingUniStreams(),
		Allow0RTT:                      t.preset.H3QUICAllow0RTT(),
		EnableDatagrams:                true, // Always true at QUIC level
		InitialPacketSize:              1200, // MASQUE inner constraint (not fingerprint)
		DisablePathMTUDiscovery:        true, // MASQUE tunnel constraint
		DisableClientHelloScrambling:   t.preset.H3QUICDisableHelloScramble(),
		InitialStreamReceiveWindow:     512 * 1024,           // MASQUE flow control
		MaxStreamReceiveWindow:         6 * 1024 * 1024,      // MASQUE flow control
		InitialConnectionReceiveWindow: 15 * 1024 * 1024 / 2, // MASQUE flow control
		MaxConnectionReceiveWindow:     15 * 1024 * 1024,     // MASQUE flow control
		TransportParameterOrder:        resolveTransportParamOrder(t.preset.H3QUICTransportParamOrder()),
		TransportParameterShuffleSeed:  t.shuffleSeed,
		ClientHelloID:                  clientHelloID,
		CachedClientHelloSpec:          innerSpec, // Separate spec for consistent JA4, uses PSK for resumed
		ECHConfigList:                  echConfigList,
		AdditionalTransportParameters:  AdditionalTransportParamsForPreset(t.preset, nil, "", 0),
		MaxDatagramFrameSize:           t.preset.H3QUICMaxDatagramFrameSize(),
	}

	// Dial QUIC over the MASQUE tunnel using quic.DialEarly for 0-RTT support
	// This properly supports ECH, unlike quic.Transport.Dial
	return quic.DialEarly(ctx, t.masqueConn, targetAddr, tlsCfgCopy, cfgCopy)
}

// ensureUDPTunnel returns the SOCKS5 UDP relay tunnel, connecting it on first
// use. The connect is deferred out of construction so NewSession never blocks on
// proxy network I/O; it happens here, on the first H3 dial, bounded by the dial's
// context. A failed connect is not cached — the next dial retries, so a transient
// proxy hiccup at session start does not permanently disable H3.
func (t *HTTP3Transport) ensureUDPTunnel(ctx context.Context) (*udpbara.Tunnel, error) {
	t.udpbaraMu.Lock()
	defer t.udpbaraMu.Unlock()

	if t.udpbaraTunnel != nil {
		return t.udpbaraTunnel, nil
	}
	if t.proxyConfig == nil || t.proxyConfig.URL == "" {
		return nil, fmt.Errorf("no SOCKS5 proxy configured for UDP relay")
	}

	tunnel, err := udpbara.NewTunnel(t.proxyConfig.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 tunnel: %w", err)
	}
	if err := connectTunnelBounded(ctx, tunnel, 15*time.Second); err != nil {
		tunnel.Close()
		return nil, fmt.Errorf("SOCKS5 proxy does not support UDP relay (required for HTTP/3): %w", err)
	}
	t.udpbaraTunnel = tunnel
	return tunnel, nil
}

// connectTunnelBounded runs tunnel.ConnectContext under a hard upper bound. The
// udpbara handshake honors the context only for the TCP dial, not the SOCKS5
// greeting reads, so a proxy that accepts TCP then goes silent would otherwise
// block forever. We cap the wait at min(ctx deadline, max) and, on timeout,
// abandon the connect and tear the tunnel down so the caller fails fast instead
// of hanging.
func connectTunnelBounded(parent context.Context, tunnel *udpbara.Tunnel, max time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, max)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- tunnel.ConnectContext(ctx) }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// Abandon the stalled connect. Close() unblocks the connect once udpbara
		// has installed its control socket; a proxy stuck before that point leaves
		// one udpbara goroutine parked on a socket read until the process exits —
		// a known udpbara limitation (its handshake reads set no deadline). Far
		// better than hanging the dial.
		tunnel.Close()
		return fmt.Errorf("SOCKS5 UDP relay connect timed out: %w", ctx.Err())
	}
}

// dialQUICWithProxy dials a QUIC connection through SOCKS5 proxy via udpbara.
// DNS resolution is handled by the proxy (hostname preserved in SOCKS5 UDP header),
// eliminating client-side DNS and Happy Eyeballs entirely.
func (t *HTTP3Transport) dialQUICWithProxy(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	t.mu.Lock()
	t.dialCount++
	t.mu.Unlock()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	connectHost := t.getConnectHost(host)
	target := net.JoinHostPort(connectHost, port)

	// Fetch ECH config (still needed for end-to-end TLS privacy)
	echConfigList := t.getECHConfig(ctx, host)

	// Connect the SOCKS5 UDP relay tunnel on first use (lazy). Bounded by ctx so
	// a stalling proxy fails the dial instead of hanging it.
	tunnel, err := t.ensureUDPTunnel(ctx)
	if err != nil {
		return nil, err
	}

	// Create udpbara connection through the tunnel
	// This creates a local UDP socket pair — instant, no network I/O
	udpConn, err := tunnel.DialContext(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("udpbara dial failed: %w", err)
	}

	// Create per-connection quic.Transport with real *net.UDPConn
	// quic-go gets full OOB/ECN/GSO support via the real kernel socket
	qt := &quic.Transport{
		Conn:                         udpConn.PacketConn(),
		ConnectionIDLength:           t.preset.H3QUICConnectionIDLength(),
		AllowZeroLengthConnectionIDs: true,
	}

	// Track both for cleanup on Close/Refresh
	pc := &proxyQUICConn{udpConn: udpConn, quicTr: qt}
	t.proxyConnsMu.Lock()
	t.proxyConns = append(t.proxyConns, pc)
	t.proxyConnsMu.Unlock()

	// Clone TLS config — ServerName is the actual host (not connectHost)
	tlsCfgCopy := t.tlsConfig.Clone()
	tlsCfgCopy.ServerName = host
	if t.cachedClientHelloSpecPSK != nil {
		tlsCfgCopy.ClientSessionCache = t.sessionCache
	}

	// Clone QUIC config with fingerprinting
	cfgCopy := t.quicConfig.Clone()
	cfgCopy.CachedClientHelloSpec = t.getSpecForHost(host)
	if echConfigList != nil {
		cfgCopy.ECHConfigList = echConfigList
	}

	// Dial through the local relay → udpbara wraps in SOCKS5 → proxy forwards
	conn, err := qt.DialEarly(ctx, udpConn.RelayAddr(), tlsCfgCopy, cfgCopy)
	if err != nil {
		closeProxyConn(pc)
		t.removeProxyConn(pc)
		return nil, err
	}

	// Auto-cleanup when the QUIC connection closes (timeout, error, idle, explicit).
	// Without this, failed requests leave quic.Transport goroutines + udpbara relay
	// goroutines running until session.Close(), burning CPU on Linux (ECN/GSO syscalls).
	go func() {
		<-conn.Context().Done()
		closeProxyConn(pc)
		t.removeProxyConn(pc)
	}()

	return conn, nil
}

// raceQUICDial implements Happy Eyeballs-style connection racing (legacy, fetches ECH internally)
// Tries IPv6 first with a short timeout, then falls back to IPv4 if needed
func (t *HTTP3Transport) raceQUICDial(ctx context.Context, host string, ipv6Addrs, ipv4Addrs []*net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	// Fetch ECH config (legacy path - used by proxy dial functions)
	echConfigList := t.getECHConfig(ctx, host)
	return t.raceQUICDialWithECH(ctx, host, ipv6Addrs, ipv4Addrs, tlsCfg, cfg, echConfigList)
}

// SetIPv4FirstOverride transiently biases the next Happy-Eyeballs QUIC dials to
// lead with IPv4. doHTTP3 flips it on for a single forced-H3 retry after the
// leading family stalled the roundtrip, then flips it back.
func (t *HTTP3Transport) SetIPv4FirstOverride(v bool) {
	t.ipv4FirstOverride.Store(v)
}

// preferIPv4Ordering reports whether the QUIC dial should interleave IPv4 first.
// It honors both the persistent DNS-cache PreferIPv4 knob and the transient
// per-retry override set by SetIPv4FirstOverride.
func (t *HTTP3Transport) preferIPv4Ordering() bool {
	if t.ipv4FirstOverride.Load() {
		return true
	}
	return t.dnsCache != nil && t.dnsCache.PreferIPv4()
}

// raceQUICDialWithECH implements Happy Eyeballs-style connection racing with pre-fetched ECH config
// Tries IPv6 first with a short timeout, then falls back to IPv4 if needed
func (t *HTTP3Transport) raceQUICDialWithECH(ctx context.Context, host string, ipv6Addrs, ipv4Addrs []*net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config, echConfigList []byte) (*quic.Conn, error) {
	// If only one address family available, just dial it directly
	if len(ipv6Addrs) == 0 && len(ipv4Addrs) == 0 {
		return nil, fmt.Errorf("no addresses to dial")
	}

	// Capture PSK spec for 0-RTT before racing (was set in dialQUICWithDNS)
	pskSpec := cfg.CachedClientHelloSpec

	// Helper to create config with a given ECH config for each dial attempt.
	// Parameterised by ech so the same racer can be retried WITHOUT ECH (ech=nil)
	// when the supplied config is rejected (see the graceful-degradation retry
	// below). We preserve PSK spec for 0-RTT session resumption.
	makeConfigWith := func(ech []byte) func() *quic.Config {
		return func() *quic.Config {
			cfgCopy := cfg.Clone()
			// Keep PSK spec for 0-RTT (includes early_data extension)
			cfgCopy.CachedClientHelloSpec = pskSpec
			// Enable ECH for all connections (fresh and resumed)
			// PSK info is now properly copied to inner ClientHello
			if ech != nil {
				cfgCopy.ECHConfigList = ech
			}
			return cfgCopy
		}
	}

	// Interleave the families and race them with a staggered start — rather than
	// trying one whole family for 2s before the other, which stalled up to 2s on
	// IPv6-broken networks. The leading family gets the ~250ms head start, so we
	// honor the DNS cache's PreferIPv4 knob here to stay in step with the H1/H2
	// direct path and the connection pools; default stays IPv6-first (RFC 8305).
	var addrs []*net.UDPAddr
	if t.preferIPv4Ordering() {
		addrs = interleaveAddrs(ipv4Addrs, ipv6Addrs)
	} else {
		addrs = interleaveAddrs(ipv6Addrs, ipv4Addrs)
	}

	if echConfigList == nil {
		return t.happyEyeballsDialQUIC(ctx, addrs, tlsCfg, makeConfigWith(nil))
	}
	// Graceful ECH degradation (issue #74). Time-box the ECH attempt so a target
	// that STALLS on an incompatible ECH ClientHello (a rotated/stale key, or an
	// ECHConfigDomain that does not front this target) fails fast instead of
	// burning the whole request deadline and cascading to H2/H1.
	echCtx, cancel := boundedECHAttempt(ctx)
	conn, err := t.happyEyeballsDialQUIC(echCtx, addrs, tlsCfg, makeConfigWith(echConfigList))
	cancel()
	if err == nil {
		return conn, nil
	}
	if ctx.Err() != nil {
		return conn, err // overall request budget exhausted
	}
	// The ECH attempt failed with budget to spare (reject, cert mismatch, or a
	// stall caught by the ECH sub-deadline — ctx is not done, so a DeadlineExceeded
	// here is echCtx's). Remember the host so later H3 dials skip ECH, and retry
	// now without it so the connection still establishes.
	if echCausedDialFailure(err) || errors.Is(err, context.DeadlineExceeded) {
		dns.MarkECHIncompatible(host)
		return t.happyEyeballsDialQUIC(ctx, addrs, tlsCfg, makeConfigWith(nil))
	}
	return conn, err
}

// interleaveAddrs alternates two address families (first list first) so the
// staggered race tries one of each in turn instead of exhausting one family
// before the other.
func interleaveAddrs(first, second []*net.UDPAddr) []*net.UDPAddr {
	out := make([]*net.UDPAddr, 0, len(first)+len(second))
	i, j := 0, 0
	for i < len(first) || j < len(second) {
		if i < len(first) {
			out = append(out, first[i])
			i++
		}
		if j < len(second) {
			out = append(out, second[j])
			j++
		}
	}
	return out
}

// happyEyeballsDialQUIC races QUIC dials across addrs with a staggered start
// (RFC 8305 Happy Eyeballs v2): dial the first address, start each subsequent
// address after a short Connection Attempt Delay — or immediately when a prior
// attempt fails — and take the first connection that completes, cancelling and
// closing the losers. This replaces "try all IPv6 for 2s, then all IPv4", which
// added up to 2s of dead time before IPv4 on IPv6-broken networks.
func (t *HTTP3Transport) happyEyeballsDialQUIC(ctx context.Context, addrs []*net.UDPAddr, tlsCfg *tls.Config, makeConfig func() *quic.Config) (*quic.Conn, error) {
	const attemptDelay = 250 * time.Millisecond
	return staggeredRace(ctx, len(addrs), attemptDelay,
		func(rctx context.Context, idx int) (*quic.Conn, error) {
			// Each attempt gets its own config clone (fresh ECH/PSK spec), so
			// concurrent dials never share/mutate one config.
			return t.quicTransport.DialEarly(rctx, addrs[idx], tlsCfg, makeConfig())
		},
		func(c *quic.Conn) { c.CloseWithError(0, "lost happy-eyeballs race") },
	)
}

// dialFirstSuccessful tries each address in order until one succeeds.
// Per-address timeout prevents a single unresponsive IP from consuming the entire timeout budget.
func (t *HTTP3Transport) dialFirstSuccessful(ctx context.Context, addrs []*net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	var lastErr error
	for i, addr := range addrs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Per-address timeout: divide remaining time evenly, cap at 10s
		remaining := len(addrs) - i
		perAddrTimeout := 10 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			budget := time.Until(deadline) / time.Duration(remaining)
			if budget < perAddrTimeout {
				perAddrTimeout = budget
			}
		}
		addrCtx, addrCancel := context.WithTimeout(ctx, perAddrTimeout)
		conn, err := t.quicTransport.DialEarly(addrCtx, addr, tlsCfg, cfg)
		addrCancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// resolveTransportParamOrder converts a string order to the quic constant.
func resolveTransportParamOrder(order string) quic.TransportParameterOrderMode {
	switch order {
	case "chrome":
		return quic.TransportParameterOrderChrome
	case "random":
		return quic.TransportParameterOrderDefault
	default:
		return quic.TransportParameterOrderChrome
	}
}

// buildQUICConfig builds a QUIC config from preset getters.
// initialPacketSizeOverride > 0 overrides the preset value (used for MASQUE's 1350 requirement).
func (t *HTTP3Transport) buildQUICConfig(clientHelloID *utls.ClientHelloID, quicIdleTimeout time.Duration, initialPacketSizeOverride uint16) *quic.Config {
	keepAlivePeriod := quicIdleTimeout / 2
	initialPacketSize := t.preset.H3QUICInitialPacketSize()
	if initialPacketSizeOverride > 0 {
		initialPacketSize = initialPacketSizeOverride
	}
	cfg := &quic.Config{
		MaxIdleTimeout:                quicIdleTimeout,
		KeepAlivePeriod:               keepAlivePeriod,
		MaxIncomingStreams:            t.preset.H3QUICMaxIncomingStreams(),
		MaxIncomingUniStreams:         t.preset.H3QUICMaxIncomingUniStreams(),
		Allow0RTT:                     t.preset.H3QUICAllow0RTT(),
		EnableDatagrams:               true, // Always true at QUIC level (original behavior); H3 SETTINGS controls per-browser advertisement
		InitialPacketSize:             initialPacketSize,
		DisablePathMTUDiscovery:       false,
		DisableClientHelloScrambling:  t.preset.H3QUICDisableHelloScramble(),
		ChromeStyleInitialPackets:     t.preset.H3QUICChromeStyleInitial(),
		ClientHelloID:                 clientHelloID,
		CachedClientHelloSpec:         t.cachedClientHelloSpec,
		TransportParameterOrder:       resolveTransportParamOrder(t.preset.H3QUICTransportParamOrder()),
		TransportParameterShuffleSeed: t.shuffleSeed,
		AdditionalTransportParameters: AdditionalTransportParamsForPreset(t.preset, nil, "", 0),
		MaxDatagramFrameSize:          t.preset.H3QUICMaxDatagramFrameSize(),
	}
	// Optional per-preset flow-control overrides. Zero means "leave at quic-go
	// default" — required for Chrome-style presets that match quic-go defaults
	// out of the box. Only Safari/iOS-Chrome-style presets set non-zero values.
	if v := t.preset.H3QUICInitialStreamReceiveWindow(); v != 0 {
		cfg.InitialStreamReceiveWindow = v
	}
	if v := t.preset.H3QUICInitialConnectionReceiveWindow(); v != 0 {
		cfg.InitialConnectionReceiveWindow = v
	}
	return cfg
}

// buildH3AdditionalSettings builds the HTTP/3 additional settings map from preset getters.
func (t *HTTP3Transport) buildH3AdditionalSettings() map[uint64]uint64 {
	// Generate GREASE setting
	greaseSettingID := generateGREASESettingID()
	greaseSettingValue := uint64(1 + rand.Uint32()%(1<<32-1))

	settings := map[uint64]uint64{
		settingQPACKMaxTableCapacity: t.preset.H3QPACKMaxTableCapacity(),
		settingQPACKBlockedStreams:   t.preset.H3QPACKBlockedStreams(),
		greaseSettingID:              greaseSettingValue,
	}

	// Conditionally add settings based on preset
	if maxField := t.preset.H3MaxFieldSectionSize(); maxField > 0 {
		settings[settingMaxFieldSectionSize] = maxField
	}
	if t.preset.H3EnableDatagrams() {
		settings[settingH3Datagram] = 1
	}

	return settings
}

// buildHTTP3Transport builds the http3.Transport from preset getters.
func (t *HTTP3Transport) buildHTTP3Transport(dialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error), additionalSettings map[uint64]uint64) *http3.Transport {
	return &http3.Transport{
		TLSClientConfig:        t.tlsConfig,
		QUICConfig:             t.quicConfig,
		Dial:                   dialFunc,
		EnableDatagrams:        true, // Always true at HTTP/3 level (original behavior); H3 SETTINGS controls per-browser advertisement
		AdditionalSettings:     additionalSettings,
		MaxResponseHeaderBytes: int(t.preset.H3MaxResponseHeaderBytes()),
		SendGreaseFrames:       t.preset.H3SendGreaseFrames(),
	}
}

// generateGREASESettingID generates a valid GREASE setting ID
// GREASE IDs are of the form 0x1f * N + 0x21 where N is random
// Chrome uses very large N values, producing setting IDs like 57836956465
func generateGREASESettingID() uint64 {
	// Generate large N values similar to Chrome (produces 10-11 digit IDs)
	n := uint64(1000000000 + rand.Int63n(9000000000))
	return 0x1f*n + 0x21
}

// dialQUIC provides DNS resolution and ECH config fetching with Happy Eyeballs
// http3.Transport handles connection caching
func (t *HTTP3Transport) dialQUIC(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	// Track dial calls - each call = new connection
	t.mu.Lock()
	t.dialCount++
	t.mu.Unlock()

	// Parse host:port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	// Get the connection host (may be different for domain fronting)
	connectHost := t.getConnectHost(host)

	// Run DNS resolution and ECH config fetch in parallel
	// Both are independent network lookups that can be done concurrently
	var ips []net.IP
	var dnsErr error
	var echConfigList []byte

	if t.disableECH {
		// ECH disabled - just do DNS
		ips, dnsErr = t.dnsCache.Resolve(ctx, connectHost)
	} else {
		// Run DNS and ECH in parallel
		var wg sync.WaitGroup
		wg.Add(2)

		// DNS resolution goroutine
		go func() {
			defer wg.Done()
			ips, dnsErr = t.dnsCache.Resolve(ctx, connectHost)
		}()

		// ECH config fetch goroutine
		go func() {
			defer wg.Done()
			echConfigList = t.getECHConfig(ctx, host)
		}()

		// Context-aware wait: unblock if context expires even if goroutines are still running
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Check DNS result
	if dnsErr != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", connectHost, dnsErr)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %s", connectHost)
	}

	// Convert port to int
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// Measure RTT and build per-connection transport params with measured initial_rtt.
	// For Chrome presets, includes google_connection_options, google_version, etc.
	// For non-Chrome presets (Firefox), returns nil so Chrome-specific params aren't sent.
	// Compute per-dial params (do NOT mutate the shared t.quicConfig — concurrent
	// dials to different hosts would race on it). Applied to the per-dial clone
	// (cfgCopy) below.
	addlParams := AdditionalTransportParamsForPreset(t.preset, ctx, ips[0].String(), portInt)

	// Filter IPs by local address family if set
	if t.localAddr != "" {
		localIP := net.ParseIP(t.localAddr)
		if localIP != nil {
			isLocalIPv6 := localIP.To4() == nil
			var filtered []net.IP
			for _, ip := range ips {
				if (ip.To4() == nil) == isLocalIPv6 {
					filtered = append(filtered, ip)
				}
			}
			ips = filtered
			if len(ips) == 0 {
				family := "IPv4"
				if isLocalIPv6 {
					family = "IPv6"
				}
				return nil, fmt.Errorf("no %s addresses found for host (local address is %s)", family, t.localAddr)
			}
		}
	}

	// Separate IPv4 and IPv6 addresses
	var ipv4Addrs, ipv6Addrs []*net.UDPAddr
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4Addrs = append(ipv4Addrs, &net.UDPAddr{IP: ip.To4(), Port: portInt})
		} else if ip.To16() != nil {
			ipv6Addrs = append(ipv6Addrs, &net.UDPAddr{IP: ip, Port: portInt})
		}
	}

	// Use our own TLS config instead of the one passed by http3.Transport
	// http3.Transport may not include ClientSessionCache in the config it passes
	tlsCfgCopy := t.tlsConfig.Clone()
	tlsCfgCopy.ServerName = host
	// Clone() doesn't preserve ClientSessionCache, restore it for session resumption
	// Only if we have PSK spec to prevent TOCTOU race
	if t.cachedClientHelloSpecPSK != nil {
		tlsCfgCopy.ClientSessionCache = t.sessionCache
	}

	// Clone our QUIC config (with proper fingerprinting settings)
	cfgCopy := t.quicConfig.Clone()
	if addlParams != nil {
		cfgCopy.AdditionalTransportParameters = addlParams
	}

	// Switch to PSK ClientHelloSpec for resumed connections
	// If there's a cached session, use PSK spec (includes early_data + pre_shared_key extensions)
	// This matches real Chrome's behavior for 0-RTT resumption
	// Note: The PSK spec (HelloChrome_143_QUIC_PSK) has the pre_shared_key extension which
	// tells utls to actually load and use the cached session for 0-RTT
	cfgCopy.CachedClientHelloSpec = t.getSpecForHost(host)

	// Race IPv6 and IPv4 connections (Happy Eyeballs style)
	// Try IPv6 first, then IPv4 after short timeout
	// Pass pre-fetched ECH config (fetched in parallel with DNS)
	return t.raceQUICDialWithECH(ctx, host, ipv6Addrs, ipv4Addrs, tlsCfgCopy, cfgCopy, echConfigList)
}

// RoundTrip implements http.RoundTripper
func (t *HTTP3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Track request count BEFORE making request
	t.mu.Lock()
	t.requestCount++
	reqNum := t.requestCount
	dialsBefore := t.dialCount
	t.mu.Unlock()

	// Use ordered headers if available (HTTP/3 header order matters for fingerprinting)
	// Skip if in TLS-only mode (headers handled by applyPresetHeaders which respects tlsOnly)
	tlsOnly := t.config != nil && t.config.TLSOnly
	if !tlsOnly {
		if len(t.preset.HeaderOrder) > 0 {
			// Apply headers in the specified order
			for _, hp := range t.preset.HeaderOrder {
				if req.Header.Get(hp.Key) == "" {
					req.Header.Set(hp.Key, hp.Value)
				}
			}
		} else {
			// Fallback to unordered headers map
			for key, value := range t.preset.Headers {
				if req.Header.Get(key) == "" {
					req.Header.Set(key, value)
				}
			}
		}

		// Set User-Agent if not set
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", t.preset.UserAgent)
		}
	}

	// Cookie crumbling (H3/QPACK). Chrome and Firefox split the Cookie header
	// into one QPACK field per cookie-pair (Chromium ValueSplittingHeaderList,
	// CookieCrumbling::kEnabled). quic-go's request writer emits one field per
	// header value and does NOT crumble, so we pre-split the single joined Cookie
	// value into crumbs here; quic-go then writes one "cookie" field per crumb,
	// contiguous in the cookie header-order slot and already marked never-indexed.
	// Gated by the preset's cookie-split flag (false => crumble): Chrome and
	// Firefox crumble, Safari/WebKit sends a single field. Safe to mutate
	// req.Header: each request is per-call, and raceH3H2 dispatches a request to
	// exactly one protocol (doHTTP3 OR doHTTP2), never both concurrently.
	if !t.preset.H2DisableCookieSplit() {
		if cookies := req.Header.Values("Cookie"); len(cookies) > 0 {
			crumbs := make([]string, 0, len(cookies))
			for _, c := range cookies {
				crumbs = append(crumbs, crumbleCookie(c)...)
			}
			if len(crumbs) > 0 {
				req.Header["Cookie"] = crumbs
			}
		}
	}

	// For domain fronting: swap req.URL.Host to connectHost so http3.Transport
	// pools connections by connect host (multiple request hosts share one QUIC connection).
	// Preserve original host in req.Host for the :authority pseudo-header.
	requestHost := req.URL.Hostname()
	connectHost := t.getConnectHost(requestHost)
	if connectHost != requestHost {
		// Set req.Host to preserve original :authority header
		if req.Host == "" {
			req.Host = req.URL.Host
		}
		// Swap URL host to connectHost for pool key
		origURLHost := req.URL.Host
		if req.URL.Port() != "" {
			req.URL.Host = net.JoinHostPort(connectHost, req.URL.Port())
		} else {
			req.URL.Host = connectHost
		}
		defer func() { req.URL.Host = origURLHost }()
	}

	// Make request - http3.Transport handles connection pooling
	// Capture transport pointer under lock to avoid data race with recreateTransport/Refresh
	t.mu.RLock()
	transport := t.transport
	t.mu.RUnlock()

	// Retry up to 3 times on 0-RTT rejection (can happen multiple times after Refresh)
	var resp *http.Response
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		resp, err = transport.RoundTrip(req)
		if err == nil || !is0RTTRejectedError(err) {
			break
		}
		// 0-RTT rejected - close unusable connection and recreate transport
		// Use timeout to prevent blocking if QUIC drain takes too long
		closeWithTimeout(transport, 3*time.Second)
		t.recreateTransport()
		// Re-read transport pointer after recreate
		t.mu.RLock()
		transport = t.transport
		t.mu.RUnlock()
	}

	// Check if a new connection was created during this request
	t.mu.RLock()
	dialsAfter := t.dialCount
	t.mu.RUnlock()

	// If dialCount increased, a new connection was created
	// If dialCount stayed the same, connection was reused
	_ = reqNum
	_ = dialsBefore
	_ = dialsAfter

	// A handshake-level rejection on H3 usually means the cached ECH config went
	// stale (e.g. the CDN rotated ECH keys). Drop it so the next request refetches
	// a fresh config instead of spamming the same failure until a process restart.
	if isECHRejectionError(err) {
		t.invalidateECHConfig(connectHost)
	}

	return resp, err
}

// IsConnectionReused returns true if requests > dials (meaning reuse happened)
func (t *HTTP3Transport) IsConnectionReused(host string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	// If we've made more requests than dial calls, connections are being reused
	return t.requestCount > t.dialCount
}

// GetDialCount returns the number of new connections created
func (t *HTTP3Transport) GetDialCount() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.dialCount
}

// GetRequestCount returns the total number of requests made
func (t *HTTP3Transport) GetRequestCount() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.requestCount
}

// removeProxyConn removes a single proxy QUIC connection from tracking
func (t *HTTP3Transport) removeProxyConn(pc *proxyQUICConn) {
	t.proxyConnsMu.Lock()
	defer t.proxyConnsMu.Unlock()
	for i, c := range t.proxyConns {
		if c == pc {
			t.proxyConns = append(t.proxyConns[:i], t.proxyConns[i+1:]...)
			return
		}
	}
}

// closeProxyConn closes a single proxyQUICConn exactly once.
func closeProxyConn(pc *proxyQUICConn) {
	pc.closeOnce.Do(func() {
		closeWithTimeout(pc.quicTr, 3*time.Second)
		pc.udpConn.Close()
	})
}

// closeAllProxyConns closes all tracked proxy QUIC connections.
// Closes quic.Transport first (sends CONNECTION_CLOSE), then udpbara (closes sockets).
func (t *HTTP3Transport) closeAllProxyConns() {
	t.proxyConnsMu.Lock()
	conns := t.proxyConns
	t.proxyConns = nil
	t.proxyConnsMu.Unlock()
	for _, c := range conns {
		closeProxyConn(c)
	}
}

// Close shuts down the transport and all connections
func (t *HTTP3Transport) Close() error {
	// Capture transport pointer under lock to avoid data race with recreateTransport/Refresh
	t.mu.RLock()
	transport := t.transport
	t.mu.RUnlock()

	// Use timeout for QUIC closes to prevent blocking on graceful drain
	closeWithTimeout(transport, 3*time.Second)

	if t.quicTransport != nil {
		closeWithTimeout(t.quicTransport, 3*time.Second)
	}

	// Close udpbara tunnel (if it was ever connected) and all proxy QUIC
	// connections. Guard the tunnel handle with udpbaraMu since it is connected
	// lazily from dial goroutines.
	t.udpbaraMu.Lock()
	tunnel := t.udpbaraTunnel
	t.udpbaraMu.Unlock()
	if tunnel != nil {
		t.closeAllProxyConns()
		tunnel.Close()
	}

	// Close MASQUE connection if using MASQUE proxy
	if t.masqueConn != nil {
		t.masqueConn.Close()
	}

	// Allow next session to re-measure RTT (may connect to different host)
	ResetInitialRTT()

	return nil
}

// Refresh closes all QUIC connections but keeps the TLS session cache intact.
// This simulates a browser page refresh - new QUIC connections but TLS resumption.
func (t *HTTP3Transport) Refresh() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Reset counters so IsConnectionReused/Stats are accurate after refresh
	t.dialCount = 0
	t.requestCount = 0

	// Close the current transport (this closes all QUIC connections)
	// Use timeout to prevent blocking if QUIC drain takes too long
	if t.transport != nil {
		closeWithTimeout(t.transport, 3*time.Second)
	}

	// Close and recreate quicTransport if it exists (for direct connections only)
	if t.quicTransport != nil && !t.usesUDPProxy && t.masqueConn == nil {
		closeWithTimeout(t.quicTransport, 3*time.Second)
		// Create new UDP socket with localAddr binding if configured
		var localUDPAddr *net.UDPAddr
		if t.localAddr != "" {
			localUDPAddr = &net.UDPAddr{IP: net.ParseIP(t.localAddr)}
		} else {
			localUDPAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		}
		udpConn, err := ListenUDPWithLocalAddr("udp", localUDPAddr, t.localAddr)
		if err != nil {
			if t.localAddr != "" {
				return fmt.Errorf("failed to create UDP socket for %s: %w", t.localAddr, err)
			}
			localUDPAddr = &net.UDPAddr{IP: net.IPv6zero, Port: 0}
			udpConn, err = ListenUDPWithLocalAddr("udp6", localUDPAddr, t.localAddr)
			if err != nil {
				return fmt.Errorf("failed to create UDP socket (IPv4 and IPv6 both failed): %w", err)
			}
		}
		t.quicTransport = &quic.Transport{
			Conn:                         udpConn,
			ConnectionIDLength:           t.preset.H3QUICConnectionIDLength(),
			AllowZeroLengthConnectionIDs: true,
		}
	}

	// Close old proxy QUIC connections; tunnel stays alive for new dials.
	// Keyed off usesUDPProxy (immutable) so it is race-free even if the tunnel
	// has not been lazily connected yet.
	if t.usesUDPProxy {
		t.closeAllProxyConns()
	}

	// Reset the MASQUE tunnel so the next dial re-establishes over a fresh QUIC
	// connection. Without this, Refresh left the tunnel marked established over
	// the now-closed transport, and its datagram-receive goroutine + UDP socket
	// leaked.
	if t.masqueConn != nil {
		t.masqueConn.Reset()
	}

	// Build additional settings from preset getters
	additionalSettings := t.buildH3AdditionalSettings()

	// Determine which dial function to use and recreate transport
	var dialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)
	if t.masqueConn != nil {
		dialFunc = t.dialQUICWithMASQUE
	} else if t.usesUDPProxy {
		dialFunc = t.dialQUICWithProxy
	} else {
		dialFunc = t.dialQUIC
	}

	// Recreate the transport with same configuration
	t.transport = t.buildHTTP3Transport(dialFunc, additionalSettings)

	return nil
}

// closeWithTimeout closes a closer with a timeout to prevent blocking indefinitely.
// QUIC connections may block on Close() waiting for graceful drain.
func closeWithTimeout(c io.Closer, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		c.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// is0RTTRejectedError checks if the error is due to 0-RTT rejection.
// Only matches actual 0-RTT rejection, not generic "conn unusable" errors
// (which can also be caused by idle timeout, peer reset, etc.).
func is0RTTRejectedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "0-RTT rejected")
}

// isECHRejectionError reports whether a QUIC dial error looks like a TLS
// handshake rejection of the ClientHello, which on H3 most often means the
// cached ECH config went stale (e.g. the CDN rotated its ECH keys). Matched
// narrowly on handshake/TLS signals so plain network timeouts (which the cache
// TTL handles anyway) do not churn the ECH cache.
func isECHRejectionError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, m := range []string{
		"CRYPTO_ERROR",
		"illegal parameter",
		"bad_record_mac",
		"decrypt_error",
		"decode_error",
		"handshake failure",
		"ECH",
		"encrypted_client_hello",
	} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// echCausedDialFailure reports whether a dial that had an ECH config applied
// failed for a reason plausibly caused by that ECH config — a rotated/stale key,
// or (issue #74) an ECHConfigDomain that does not actually front this target, so
// the server rejects or mis-serves the ECH ClientHello. It is the trigger for
// retrying the dial WITHOUT ECH: ECH is best-effort, so degrading to a working
// (SNI-visible) connection beats failing the whole H3/H2 attempt and cascading to
// the next protocol (which, on a target whose TCP path is slow, ends in a dial
// timeout). It matches the same handshake/crypto signals as isECHRejectionError
// plus certificate/TLS-alert failures (a cross-domain ECH public_name makes the
// server present a mismatched certificate), but deliberately NOT i/o timeouts or
// connection errors — retrying those without ECH would only double the wait.
func echCausedDialFailure(err error) bool {
	if err == nil {
		return false
	}
	if isECHRejectionError(err) {
		return true
	}
	s := err.Error()
	for _, m := range []string{
		"certificate",
		"x509",
		"tls: handshake",
		"tls: server",
	} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// echAttemptMaxBudget caps how long an ECH-enabled dial/handshake is allowed
// before it is abandoned in favour of a no-ECH retry. A real ECH handshake
// completes in well under a second; a target that stalls on an incompatible ECH
// ClientHello (issue #74) otherwise consumes the whole request deadline, leaving
// nothing to retry without ECH.
const echAttemptMaxBudget = 6 * time.Second

// boundedECHAttempt returns a child context that time-boxes an ECH-enabled dial
// so a stall fails fast and leaves budget for a no-ECH retry within the caller's
// deadline. With no deadline it caps the attempt at echAttemptMaxBudget; with a
// deadline it reserves roughly half the remaining budget for the retry.
func boundedECHAttempt(ctx context.Context) (context.Context, context.CancelFunc) {
	dl, ok := ctx.Deadline()
	if !ok {
		return context.WithTimeout(ctx, echAttemptMaxBudget)
	}
	remaining := time.Until(dl)
	if remaining <= 0 {
		// Already expired; hand back the context unchanged (the dial fails fast).
		return context.WithCancel(ctx)
	}
	budget := remaining / 2
	if budget > echAttemptMaxBudget {
		budget = echAttemptMaxBudget
	}
	return context.WithTimeout(ctx, budget)
}

// recreateTransport recreates the HTTP/3 transport after 0-RTT rejection

// recreateTransport recreates the HTTP/3 transport after 0-RTT rejection
// This is called from RoundTrip when the server rejects early data
func (t *HTTP3Transport) recreateTransport() {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Build additional settings from preset getters
	additionalSettings := t.buildH3AdditionalSettings()

	// Determine which dial function to use
	var dialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)
	if t.masqueConn != nil {
		dialFunc = t.dialQUICWithMASQUE
	} else if t.usesUDPProxy {
		dialFunc = t.dialQUICWithProxy
	} else {
		dialFunc = t.dialQUIC
	}

	// Recreate the transport
	t.transport = t.buildHTTP3Transport(dialFunc, additionalSettings)
}

// GetSessionCache returns the TLS session cache
func (t *HTTP3Transport) GetSessionCache() tls.ClientSessionCache {
	return t.sessionCache
}

// SetSessionCache sets the TLS session cache
func (t *HTTP3Transport) SetSessionCache(cache tls.ClientSessionCache) {
	t.sessionCache = cache
	// Update the tlsConfig as well since it holds a reference
	if t.tlsConfig != nil {
		t.tlsConfig.ClientSessionCache = cache
	}
}

// GetECHConfigCache returns all cached ECH configs
// This is used for session persistence - ECH configs must be saved alongside
// TLS session tickets to ensure proper session resumption
func (t *HTTP3Transport) GetECHConfigCache() map[string][]byte {
	t.echConfigCacheMu.RLock()
	defer t.echConfigCacheMu.RUnlock()

	// Return a copy to avoid race conditions. Skip negative (nil-config) entries —
	// they exist only to suppress re-fetching a no-ECH host, and exporting them
	// would pollute the persisted cache with meaningless nil configs.
	result := make(map[string][]byte, len(t.echConfigCache))
	for k, v := range t.echConfigCache {
		if v.config == nil {
			continue
		}
		result[k] = v.config
	}
	return result
}

// SetECHConfigCache imports ECH configs from session persistence
// This should be called before importing TLS sessions to ensure the
// correct ECH config is used when resuming connections
func (t *HTTP3Transport) SetECHConfigCache(configs map[string][]byte) {
	t.echConfigCacheMu.Lock()
	defer t.echConfigCacheMu.Unlock()

	exp := time.Now().Add(echTransportCacheTTL)
	for k, v := range configs {
		t.echConfigCache[k] = &echCachedConfig{config: v, expiresAt: exp}
	}
}

// invalidateECHConfig drops the cached ECH config for a host on both the
// transport and the shared DNS cache, so the next dial refetches a fresh one.
// Called after a handshake rejection that suggests the config went stale (for
// example the CDN rotated ECH keys), so a long-lived session self-heals instead
// of spamming the same failure until restart.
func (t *HTTP3Transport) invalidateECHConfig(host string) {
	t.echConfigCacheMu.Lock()
	delete(t.echConfigCache, host)
	t.echConfigCacheMu.Unlock()
	dns.InvalidateECHConfig(host)
}

// Connect establishes a QUIC connection to the host without making a request.
// This is used for protocol racing - the first protocol to connect wins.
func (t *HTTP3Transport) Connect(ctx context.Context, host, port string) error {
	// Proxied transports MUST probe through the proxy. The direct quic.DialAddr
	// probe below would dial the target straight from the local socket, leaking
	// the real client IP and never actually testing whether QUIC relays through
	// the proxy. Route through the same dial path doHTTP3 uses for real requests.
	// Keyed off usesUDPProxy (not the tunnel handle) because the tunnel is
	// connected lazily — on the first probe it is still nil, and falling through
	// to the direct path here would leak the real IP.
	if t.masqueConn != nil || t.usesUDPProxy {
		return t.connectViaProxy(ctx, host, port)
	}

	// Use connect host for DNS resolution (may differ for domain fronting)
	connectHost := t.getConnectHost(host)
	addr := net.JoinHostPort(connectHost, port)

	// Use DNS cache for resolution - resolve connectHost, not request host
	ip, err := t.dnsCache.ResolveOne(ctx, connectHost)
	if err != nil {
		return fmt.Errorf("DNS resolution failed: %w", err)
	}

	resolvedAddr := net.JoinHostPort(ip.String(), port)

	// Determine key log writer - config override or global
	var keyLogWriter io.Writer
	if t.config != nil && t.config.KeyLogWriter != nil {
		keyLogWriter = t.config.KeyLogWriter
	} else {
		keyLogWriter = GetKeyLogWriter()
	}

	// Create TLS config - use request host for SNI
	tlsCfg := &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: t.insecureSkipVerify,
		KeyLogWriter:       keyLogWriter,
	}
	t.tlsVerify.Apply(tlsCfg)

	// Fetch ECH configs from DNS HTTPS records (use request host for ECH). Skipped
	// for a host that recently stalled/rejected ECH (issue #74). Non-blocking - if
	// it fails, we proceed without ECH.
	var echConfigList []byte
	if !dns.IsECHIncompatible(host) {
		echConfigList, _ = dns.FetchECHConfigs(ctx, host)
	}

	// Determine QUIC idle timeout (default 30s, configurable)
	quicIdleTimeout := 30 * time.Second
	if t.config != nil && t.config.QuicIdleTimeout > 0 {
		quicIdleTimeout = t.config.QuicIdleTimeout
	}

	// Get ClientHelloID for the probe connection
	var clientHelloID *utls.ClientHelloID
	if t.preset.QUICClientHelloID.Client != "" {
		clientHelloID = &t.preset.QUICClientHelloID
	} else if t.preset.ClientHelloID.Client != "" {
		clientHelloID = &t.preset.ClientHelloID
	}

	// Build QUIC config from preset getters (same fingerprint as real connections)
	quicCfg := t.buildQUICConfig(clientHelloID, quicIdleTimeout, 0)
	// buildQUICConfig embeds the shared base spec; concurrent probes would
	// race-mutate it via ApplyPreset. Hand this probe its own fresh spec
	// (same seed -> identical fingerprint, private object -> no race).
	quicCfg.CachedClientHelloSpec = t.getSpecForHost(host)
	if len(echConfigList) > 0 {
		quicCfg.ECHConfigList = echConfigList
	}

	// Try to establish QUIC connection. When ECH is applied, time-box the attempt
	// (issue #74) so a stall on an incompatible ECH ClientHello fails fast, then
	// retry the probe once WITHOUT ECH so H3 stays a viable race winner. The real
	// request dial applies the same degradation.
	var conn *quic.Conn
	if len(echConfigList) > 0 {
		echCtx, cancel := boundedECHAttempt(ctx)
		conn, err = quic.DialAddr(echCtx, resolvedAddr, tlsCfg, quicCfg)
		cancel()
		if err != nil && ctx.Err() == nil && (echCausedDialFailure(err) || errors.Is(err, context.DeadlineExceeded)) {
			dns.MarkECHIncompatible(host)
			t.invalidateECHConfig(host)
			echlessCfg := t.buildQUICConfig(clientHelloID, quicIdleTimeout, 0)
			echlessCfg.CachedClientHelloSpec = t.getSpecForHost(host)
			conn, err = quic.DialAddr(ctx, resolvedAddr, tlsCfg, echlessCfg)
		}
	} else {
		conn, err = quic.DialAddr(ctx, resolvedAddr, tlsCfg, quicCfg)
	}
	if err != nil {
		// Stale ECH (e.g. CDN key rotation) shows up here as a handshake
		// rejection; drop the cached config so the next probe refetches.
		if isECHRejectionError(err) {
			t.invalidateECHConfig(host)
		}
		return fmt.Errorf("QUIC dial failed: %w", err)
	}

	// Connection established successfully - the http3.Transport will reuse this
	// via its internal pooling when we make a real request
	// For now, just track that we successfully dialed
	t.mu.Lock()
	t.dialCount++
	t.mu.Unlock()

	// Close this test connection - http3.Transport will create its own
	// This is just to verify QUIC/H3 is reachable
	_ = conn.CloseWithError(0, "connect probe")
	_ = addr // suppress unused warning

	return nil
}

// connectViaProxy runs the H3 reachability probe THROUGH the configured proxy
// (SOCKS5 UDP relay or MASQUE), mirroring the dial path doHTTP3 uses for real
// requests. This is what makes raceH3H2 safe over a proxy: the probe tunnels
// instead of dialing the target directly, so no real-IP leak and the race
// actually learns whether QUIC relays through the proxy. The dialFunc selection
// must stay in sync with Refresh()/recreateTransport().
func (t *HTTP3Transport) connectViaProxy(ctx context.Context, host, port string) error {
	var dialFunc func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error)
	if t.masqueConn != nil {
		dialFunc = t.dialQUICWithMASQUE
	} else {
		dialFunc = t.dialQUICWithProxy
	}

	// Match the key log writer selection used by the direct probe / dial path.
	var keyLogWriter io.Writer
	if t.config != nil && t.config.KeyLogWriter != nil {
		keyLogWriter = t.config.KeyLogWriter
	} else {
		keyLogWriter = GetKeyLogWriter()
	}

	// SNI = request host, h3 ALPN. dialQUICWithMASQUE clones this and overrides
	// ServerName; dialQUICWithProxy clones t.tlsConfig and ignores this. Both
	// build their own quic.Config, so the cfg arg is unused (pass nil).
	tlsCfg := &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: t.insecureSkipVerify,
		KeyLogWriter:       keyLogWriter,
	}
	t.tlsVerify.Apply(tlsCfg)

	conn, err := dialFunc(ctx, net.JoinHostPort(host, port), tlsCfg, nil)
	if err != nil {
		// A handshake rejection here usually means stale ECH (CDN key rotation);
		// drop the cached config so the next probe refetches.
		if isECHRejectionError(err) {
			t.invalidateECHConfig(host)
		}
		return fmt.Errorf("QUIC dial via proxy failed: %w", err)
	}

	// Probe only: tear down so the real request dials its own connection. The
	// per-connection cleanup goroutine in the dial func removes proxy state.
	_ = conn.CloseWithError(0, "connect probe")
	return nil
}

// Stats returns transport statistics
func (t *HTTP3Transport) Stats() HTTP3Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return HTTP3Stats{
		RequestCount: t.requestCount,
		DialCount:    t.dialCount,
		Reusing:      t.requestCount > t.dialCount,
	}
}

// HTTP3Stats contains HTTP/3 transport statistics
type HTTP3Stats struct {
	RequestCount int64
	DialCount    int64 // Number of new connections created
	Reusing      bool  // True if connections are being reused
}

// GetDNSCache returns the DNS cache
func (t *HTTP3Transport) GetDNSCache() *dns.Cache {
	return t.dnsCache
}

// SetConnectTo sets a host mapping for domain fronting
func (t *HTTP3Transport) SetConnectTo(requestHost, connectHost string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	if t.config.ConnectTo == nil {
		t.config.ConnectTo = make(map[string]string)
	}
	t.config.ConnectTo[requestHost] = connectHost
}

// SetECHConfig sets a custom ECH configuration
func (t *HTTP3Transport) SetECHConfig(echConfig []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfig = echConfig
}

// SetECHConfigDomain sets a domain to fetch ECH config from
func (t *HTTP3Transport) SetECHConfigDomain(domain string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfigDomain = domain
}

// getConnectHost returns the connection host for DNS resolution
func (t *HTTP3Transport) getConnectHost(requestHost string) string {
	if t.config == nil || t.config.ConnectTo == nil {
		return requestHost
	}
	if connectHost, ok := t.config.ConnectTo[requestHost]; ok {
		return connectHost
	}
	return requestHost
}

// echCachedConfig is a per-host ECH config with an expiry, so a long-lived
// transport refetches periodically instead of pinning one config forever.
type echCachedConfig struct {
	config    []byte
	expiresAt time.Time
}

// echTransportCacheTTL bounds how long the transport reuses a cached ECH config
// before re-consulting DNS. Short enough to pick up a CDN key rotation without
// waiting for a process restart; the underlying DNS cache still honors the
// record's own TTL, so this is just an upper bound on staleness.
const echTransportCacheTTL = 5 * time.Minute

// getECHConfig returns the ECH config for a host, refetching once the cached
// entry expires. (The cache mainly keeps the same config across the connections
// of one logical request; it must NOT pin a stale config forever, or a CDN ECH
// key rotation strands the session on a retired key until restart.)
func (t *HTTP3Transport) getECHConfig(ctx context.Context, targetHost string) []byte {
	// Skip ECH entirely for a host that recently stalled or rejected an ECH
	// handshake (issue #74), so H3 stops paying the stall until the incompatibility
	// window lapses and ECH is retried for self-heal.
	if dns.IsECHIncompatible(targetHost) {
		return nil
	}

	t.echConfigCacheMu.RLock()
	if cached, ok := t.echConfigCache[targetHost]; ok && time.Now().Before(cached.expiresAt) {
		t.echConfigCacheMu.RUnlock()
		return cached.config
	}
	t.echConfigCacheMu.RUnlock()

	// The client-side ECH fetch is a cleartext HTTPS-record (type 65) query to a
	// public resolver. On a PROXIED transport that would carry the target hostname
	// to 8.8.8.8 OUTSIDE the proxy tunnel — leaking exactly the name the SOCKS5/
	// MASQUE path otherwise keeps inside the tunnel. So over a proxy we never do a
	// DNS-driven ECH fetch; the handshake just proceeds without ECH. An explicitly
	// supplied ECH config (raw bytes, no DNS) is still honored. Non-proxied H3
	// keeps full ECH auto-discovery.
	proxied := t.proxyConfig != nil && t.proxyConfig.URL != ""

	// No fresh cached config - fetch from DNS or config
	var echConfig []byte
	if t.config == nil {
		if proxied {
			return nil
		}
		echConfig, _ = dns.FetchECHConfigs(ctx, targetHost)
	} else if proxied {
		// Only the caller-provided raw ECH bytes are safe over a proxy; a
		// domain/target HTTPS-record fetch inside GetECHConfig would leak.
		echConfig = t.config.ECHConfig
	} else {
		echConfig = t.config.GetECHConfig(ctx, targetHost)
	}

	// Cache the result — INCLUDING a nil (no-ECH) config as a negative entry — so a
	// host that advertises no ECH is remembered for echTransportCacheTTL instead of
	// re-fetched on every dial. (The DNS layer also negative-caches, but this keeps
	// the per-dial lookup a single map read.) GetECHConfigCache skips nil entries so
	// the persisted/exported format stays positive-only.
	t.echConfigCacheMu.Lock()
	t.echConfigCache[targetHost] = &echCachedConfig{
		config:    echConfig,
		expiresAt: time.Now().Add(echTransportCacheTTL),
	}
	t.echConfigCacheMu.Unlock()

	return echConfig
}
