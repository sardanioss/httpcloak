package transport

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/proxy"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	"github.com/sardanioss/quic-go/quicvarint"
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
const (
	tpVersionInformation = 0x11   // RFC 9368 version negotiation
	tpGoogleVersion      = 0x4752 // Google's custom version param (18258)
	tpInitialRTT              = 0x3127 // initial_rtt (12583) - Chrome's cached SRTT
	tpGoogleConnectionOptions = 0x3128 // Google's connection options param (12584)
)

// RTT measurement state — measure once per process, re-measure after ResetInitialRTT().
var (
	rttMu       sync.Mutex
	rttMeasured bool
)

func init() {
	// Set Chrome-like additional transport parameters
	quic.SetAdditionalTransportParameters(BuildChromeTransportParams())
}

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

	// google_version (0x4752 / 18258) - Google's custom parameter
	// Format: 4-byte version
	googleVersion := make([]byte, 4)
	binary.BigEndian.PutUint32(googleVersion, 0x00000001) // QUICv1
	params[tpGoogleVersion] = googleVersion

	// google_connection_options (0x3128 / 12584) - Chrome sends "B2ON"
	params[tpGoogleConnectionOptions] = []byte("B2ON")

	// initial_rtt (0x3127) - Chrome sends cached SRTT in microseconds
	// Default 100ms (100000μs); MeasureAndSetInitialRTT overrides with real RTT
	initialRTT := make([]byte, 0, 8)
	initialRTT = quicvarint.Append(initialRTT, 100000) // 100ms fallback
	params[tpInitialRTT] = initialRTT

	// Note: GREASE transport param is NOT added here — quic-go's Chrome-mode
	// marshaling (transport_parameters.go) already inserts exactly 1 GREASE param
	// at the correct position (after max_datagram_frame_size).

	return params
}

// MeasureAndSetInitialRTT measures TCP RTT to host:port and updates the
// initial_rtt QUIC transport parameter. Called once before first QUIC dial.
// If measurement fails, keeps the default 100ms.
func MeasureAndSetInitialRTT(ctx context.Context, host string, port int) {
	rttMu.Lock()
	defer rttMu.Unlock()
	if rttMeasured {
		return
	}
	rttMeasured = true

	// Quick TCP SYN-ACK RTT probe (connect + immediate close)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	start := time.Now()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(probeCtx, "tcp", addr)
	rtt := time.Since(start)
	if conn != nil {
		conn.Close()
	}
	if err != nil {
		return // keep default 100ms
	}

	// Rebuild transport params with measured RTT
	params := BuildChromeTransportParams()
	rttValue := make([]byte, 0, 8)
	rttValue = quicvarint.Append(rttValue, uint64(rtt.Microseconds()))
	params[tpInitialRTT] = rttValue
	quic.SetAdditionalTransportParameters(params)
}

// ResetInitialRTT allows re-measurement for new sessions/hosts.
func ResetInitialRTT() {
	rttMu.Lock()
	defer rttMu.Unlock()
	rttMeasured = false
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

	// Shuffle seed for TLS and transport parameter ordering (consistent per session)
	shuffleSeed int64

	// Track requests for timing
	requestCount int64
	dialCount    int64 // Number of times dialQUIC was called (new connections)
	mu           sync.RWMutex

	// Configuration
	quicConfig *quic.Config
	tlsConfig  *tls.Config

	// Proxy support for SOCKS5 UDP relay via udpbara
	proxyConfig   *ProxyConfig
	udpbaraTunnel *udpbara.Tunnel // SOCKS5 UDP relay tunnel (shared across dials)
	proxyConns    []*proxyQUICConn
	proxyConnsMu  sync.Mutex
	quicTransport *quic.Transport // Only used for direct connections

	// MASQUE proxy support
	masqueConn *proxy.MASQUEConn

	// Advanced configuration (ConnectTo, ECH override)
	config *TransportConfig

	// ECH config cache - stores ECH configs per host for session resumption
	// When resuming a session, we must use the same ECH config that was used
	// to create the original session ticket, not a fresh one from DNS
	echConfigCache   map[string][]byte
	echConfigCacheMu sync.RWMutex

	// Skip TLS certificate verification (for testing)
	insecureSkipVerify bool

	// Skip ECH lookup for faster first request (ECH is optional privacy feature)
	disableECH bool

	// Local address for binding outgoing connections (IPv6 rotation)
	localAddr string
}

// SetInsecureSkipVerify sets whether to skip TLS certificate verification
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

// getSpecForHost returns the appropriate ClientHelloSpec for consistent TLS fingerprint
// Only use PSK spec (which includes early_data extension) when there's an actual session to resume.
// Chrome does NOT send early_data extension on fresh connections - only on resumption.
func (t *HTTP3Transport) getSpecForHost(host string) *utls.ClientHelloSpec {
	// Only use PSK spec when there's a cached session for this host
	// This matches Chrome's behavior: no early_data on fresh connections
	if t.cachedClientHelloSpecPSK != nil && t.hasSessionForHost(host) {
		return t.cachedClientHelloSpecPSK
	}
	return t.cachedClientHelloSpec
}

// getInnerSpecForHost returns the appropriate inner ClientHelloSpec for MASQUE connections
// Only use PSK spec when there's an actual session to resume.
func (t *HTTP3Transport) getInnerSpecForHost(host string) *utls.ClientHelloSpec {
	// Only use PSK spec when there's a cached session for this host
	if t.cachedClientHelloSpecInnerPSK != nil && t.hasSessionForHost(host) {
		return t.cachedClientHelloSpecInnerPSK
	}
	return t.cachedClientHelloSpecInner
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
		echConfigCache: make(map[string][]byte), // Cache for ECH configs (for session resumption)
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

	// Cache the ClientHelloSpec for consistent TLS fingerprint across connections
	// Chrome shuffles TLS extensions once per session, not per connection
	// Use the shuffle seed for deterministic ordering
	if clientHelloID != nil {
		spec, err := utls.UTLSIdToSpecWithSeed(*clientHelloID, shuffleSeed)
		if err == nil {
			t.cachedClientHelloSpec = &spec
		}
	}

	// Also cache the PSK spec for session resumption (includes pre_shared_key extension)
	// Chrome uses a different TLS extension set when resuming with PSK
	if preset.QUICPSKClientHelloID.Client != "" {
		if pskSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
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
	udpConn, err := net.ListenUDP("udp", localUDPAddr)
	if err != nil {
		if t.localAddr != "" {
			// localAddr is set — retrying with the same IP on "udp6" won't help
			return nil, fmt.Errorf("failed to create UDP socket for %s: %w", t.localAddr, err)
		}
		// Fallback to IPv6 if IPv4 fails (no localAddr — try IPv6zero)
		localUDPAddr = &net.UDPAddr{IP: net.IPv6zero, Port: 0}
		udpConn, err = net.ListenUDP("udp6", localUDPAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create UDP socket (IPv4 and IPv6 both failed): %w", err)
		}
	}
	t.quicTransport = &quic.Transport{
		Conn: udpConn,
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
		echConfigCache: make(map[string][]byte),
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

	// Cache ClientHelloSpec for consistent fingerprint
	if clientHelloID != nil {
		spec, err := utls.UTLSIdToSpecWithSeed(*clientHelloID, shuffleSeed)
		if err == nil {
			t.cachedClientHelloSpec = &spec
		}
	}

	// Also cache the PSK spec for session resumption (includes pre_shared_key extension)
	if preset.QUICPSKClientHelloID.Client != "" {
		if pskSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
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

	// Set up SOCKS5 UDP relay via udpbara if proxy is configured
	// udpbara creates local UDP socket pairs so quic-go gets real *net.UDPConn with OOB/ECN support
	if proxyConfig != nil && proxyConfig.URL != "" {
		tunnel, err := udpbara.NewTunnel(proxyConfig.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 tunnel: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := tunnel.ConnectContext(ctx); err != nil {
			tunnel.Close()
			return nil, fmt.Errorf("SOCKS5 proxy does not support UDP relay (required for HTTP/3): %w", err)
		}
		t.udpbaraTunnel = tunnel
		// Note: quicTransport is NOT created here — each dial creates its own per-connection
	}

	// Build H3 additional settings from preset getters
	additionalSettings := t.buildH3AdditionalSettings()

	// Create HTTP/3 transport with appropriate dial function
	var dialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)
	if t.udpbaraTunnel != nil {
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
		echConfigCache: make(map[string][]byte),
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

	// Cache ClientHelloSpec for consistent fingerprint (outer connection to proxy)
	if clientHelloID != nil {
		spec, err := utls.UTLSIdToSpecWithSeed(*clientHelloID, shuffleSeed)
		if err == nil {
			t.cachedClientHelloSpec = &spec
		}
		// Create separate cached spec for inner connections (not shared with outer)
		// This ensures JA4 hash is consistent across inner requests
		innerSpec, err := utls.UTLSIdToSpecWithSeed(*clientHelloID, shuffleSeed)
		if err == nil {
			t.cachedClientHelloSpecInner = &innerSpec
		}
	}

	// Also cache PSK specs for session resumption (includes pre_shared_key extension)
	if preset.QUICPSKClientHelloID.Client != "" {
		// Outer PSK spec
		if pskSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			t.cachedClientHelloSpecPSK = &pskSpec
		}
		// Inner PSK spec for MASQUE connections
		if innerPskSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
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

	// Establish MASQUE tunnel with Chrome fingerprinting
	// Use the preset's TLS/QUIC config for the proxy connection too
	err = t.masqueConn.EstablishWithQUICConfig(ctx, connectHost, portInt, t.tlsConfig, t.quicConfig)
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
		MaxIdleTimeout:                  quicIdleTimeout,
		KeepAlivePeriod:                 keepAlivePeriod,
		MaxIncomingStreams:              t.preset.H3QUICMaxIncomingStreams(),
		MaxIncomingUniStreams:           t.preset.H3QUICMaxIncomingUniStreams(),
		Allow0RTT:                       t.preset.H3QUICAllow0RTT(),
		EnableDatagrams:                 true,  // Always true at QUIC level
		InitialPacketSize:               1200,  // MASQUE inner constraint (not fingerprint)
		DisablePathMTUDiscovery:         true,  // MASQUE tunnel constraint
		DisableClientHelloScrambling:    t.preset.H3QUICDisableHelloScramble(),
		InitialStreamReceiveWindow:      512 * 1024,            // MASQUE flow control
		MaxStreamReceiveWindow:          6 * 1024 * 1024,       // MASQUE flow control
		InitialConnectionReceiveWindow:  15 * 1024 * 1024 / 2,  // MASQUE flow control
		MaxConnectionReceiveWindow:      15 * 1024 * 1024,      // MASQUE flow control
		TransportParameterOrder:         resolveTransportParamOrder(t.preset.H3QUICTransportParamOrder()),
		TransportParameterShuffleSeed:   t.shuffleSeed,
		ClientHelloID:                   clientHelloID,
		CachedClientHelloSpec:           innerSpec, // Separate spec for consistent JA4, uses PSK for resumed
		ECHConfigList:                   echConfigList,
	}

	// Dial QUIC over the MASQUE tunnel using quic.DialEarly for 0-RTT support
	// This properly supports ECH, unlike quic.Transport.Dial
	return quic.DialEarly(ctx, t.masqueConn, targetAddr, tlsCfgCopy, cfgCopy)
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

	// Create udpbara connection through the tunnel
	// This creates a local UDP socket pair — instant, no network I/O
	udpConn, err := t.udpbaraTunnel.DialContext(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("udpbara dial failed: %w", err)
	}

	// Create per-connection quic.Transport with real *net.UDPConn
	// quic-go gets full OOB/ECN/GSO support via the real kernel socket
	qt := &quic.Transport{Conn: udpConn.PacketConn()}

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

// raceQUICDialWithECH implements Happy Eyeballs-style connection racing with pre-fetched ECH config
// Tries IPv6 first with a short timeout, then falls back to IPv4 if needed
func (t *HTTP3Transport) raceQUICDialWithECH(ctx context.Context, host string, ipv6Addrs, ipv4Addrs []*net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config, echConfigList []byte) (*quic.Conn, error) {
	// If only one address family available, just dial it directly
	if len(ipv6Addrs) == 0 && len(ipv4Addrs) == 0 {
		return nil, fmt.Errorf("no addresses to dial")
	}

	// Capture PSK spec for 0-RTT before racing (was set in dialQUICWithDNS)
	pskSpec := cfg.CachedClientHelloSpec

	// Helper to create config with ECH for each dial attempt
	// We preserve PSK spec for 0-RTT session resumption
	makeConfig := func() *quic.Config {
		cfgCopy := cfg.Clone()
		// Keep PSK spec for 0-RTT (includes early_data extension)
		cfgCopy.CachedClientHelloSpec = pskSpec
		// Enable ECH for all connections (fresh and resumed)
		// PSK info is now properly copied to inner ClientHello
		if echConfigList != nil {
			cfgCopy.ECHConfigList = echConfigList
		}
		return cfgCopy
	}

	if len(ipv6Addrs) == 0 {
		return t.dialFirstSuccessful(ctx, ipv4Addrs, tlsCfg, makeConfig())
	}
	if len(ipv4Addrs) == 0 {
		return t.dialFirstSuccessful(ctx, ipv6Addrs, tlsCfg, makeConfig())
	}

	// Try IPv6 first with a short timeout (Happy Eyeballs style)
	// If IPv6 fails or times out quickly, fall back to IPv4
	ipv6Timeout := 2 * time.Second // Give IPv6 a reasonable chance
	ipv6Ctx, ipv6Cancel := context.WithTimeout(ctx, ipv6Timeout)

	conn, _ := t.dialFirstSuccessful(ipv6Ctx, ipv6Addrs, tlsCfg, makeConfig())
	ipv6Cancel()

	if conn != nil {
		return conn, nil
	}

	// IPv6 failed, try IPv4 with fresh config
	return t.dialFirstSuccessful(ctx, ipv4Addrs, tlsCfg, makeConfig())
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
	return &quic.Config{
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
	}
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

	// Measure RTT to target before QUIC dial so initial_rtt matches real latency.
	// Uses first resolved IP; runs once per process (cached via rttMeasured flag).
	MeasureAndSetInitialRTT(ctx, ips[0].String(), portInt)

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

	// Close udpbara tunnel and all proxy QUIC connections
	if t.udpbaraTunnel != nil {
		t.closeAllProxyConns()
		t.udpbaraTunnel.Close()
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
	if t.quicTransport != nil && t.udpbaraTunnel == nil && t.masqueConn == nil {
		closeWithTimeout(t.quicTransport, 3*time.Second)
		// Create new UDP socket with localAddr binding if configured
		var localUDPAddr *net.UDPAddr
		if t.localAddr != "" {
			localUDPAddr = &net.UDPAddr{IP: net.ParseIP(t.localAddr)}
		} else {
			localUDPAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		}
		udpConn, err := net.ListenUDP("udp", localUDPAddr)
		if err != nil {
			if t.localAddr != "" {
				return fmt.Errorf("failed to create UDP socket for %s: %w", t.localAddr, err)
			}
			localUDPAddr = &net.UDPAddr{IP: net.IPv6zero, Port: 0}
			udpConn, err = net.ListenUDP("udp6", localUDPAddr)
			if err != nil {
				return fmt.Errorf("failed to create UDP socket (IPv4 and IPv6 both failed): %w", err)
			}
		}
		t.quicTransport = &quic.Transport{
			Conn: udpConn,
		}
	}

	// Close old proxy QUIC connections; tunnel stays alive for new dials
	if t.udpbaraTunnel != nil {
		t.closeAllProxyConns()
	}

	// Build additional settings from preset getters
	additionalSettings := t.buildH3AdditionalSettings()

	// Determine which dial function to use and recreate transport
	var dialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)
	if t.masqueConn != nil {
		dialFunc = t.dialQUICWithMASQUE
	} else if t.udpbaraTunnel != nil {
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
	} else if t.udpbaraTunnel != nil {
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

	// Return a copy to avoid race conditions
	result := make(map[string][]byte, len(t.echConfigCache))
	for k, v := range t.echConfigCache {
		result[k] = v
	}
	return result
}

// SetECHConfigCache imports ECH configs from session persistence
// This should be called before importing TLS sessions to ensure the
// correct ECH config is used when resuming connections
func (t *HTTP3Transport) SetECHConfigCache(configs map[string][]byte) {
	t.echConfigCacheMu.Lock()
	defer t.echConfigCacheMu.Unlock()

	for k, v := range configs {
		t.echConfigCache[k] = v
	}
}

// Connect establishes a QUIC connection to the host without making a request.
// This is used for protocol racing - the first protocol to connect wins.
func (t *HTTP3Transport) Connect(ctx context.Context, host, port string) error {
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

	// Fetch ECH configs from DNS HTTPS records (use request host for ECH)
	// This is non-blocking - if it fails, we proceed without ECH
	echConfigList, _ := dns.FetchECHConfigs(ctx, host)

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
	if len(echConfigList) > 0 {
		quicCfg.ECHConfigList = echConfigList
	}

	// Try to establish QUIC connection
	conn, err := quic.DialAddr(ctx, resolvedAddr, tlsCfg, quicCfg)
	if err != nil {
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

// getECHConfig returns the ECH config for a host
func (t *HTTP3Transport) getECHConfig(ctx context.Context, targetHost string) []byte {
	// First, check if we have a cached ECH config for this host
	// This is critical for session resumption - we must use the same ECH config
	// that was used when creating the original session ticket
	t.echConfigCacheMu.RLock()
	if cachedConfig, ok := t.echConfigCache[targetHost]; ok {
		t.echConfigCacheMu.RUnlock()
		return cachedConfig
	}
	t.echConfigCacheMu.RUnlock()

	// No cached config - fetch from DNS or config
	var echConfig []byte
	if t.config == nil {
		echConfig, _ = dns.FetchECHConfigs(ctx, targetHost)
	} else {
		echConfig = t.config.GetECHConfig(ctx, targetHost)
	}

	// Cache the ECH config for future use (session resumption)
	if echConfig != nil {
		t.echConfigCacheMu.Lock()
		t.echConfigCache[targetHost] = echConfig
		t.echConfigCacheMu.Unlock()
	}

	return echConfig
}
