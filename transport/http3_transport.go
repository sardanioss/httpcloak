package transport

import (
	"context"
	crand "crypto/rand"
	tls "github.com/sardanioss/utls"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	http "github.com/sardanioss/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/proxy"
	utls "github.com/sardanioss/utls"
)

// Debug logging helper - disabled by default
var logDebugEnabled = false

func logDebug(format string, args ...interface{}) {
	if !logDebugEnabled {
		return
	}
	msg := fmt.Sprintf("[DEBUG] "+format+"\n", args...)
	f, err := os.OpenFile("/tmp/httpcloak_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return // Silently ignore if can't write
	}
	f.WriteString(msg)
	f.Close()
}

// HTTP/3 SETTINGS identifiers
const (
	settingQPACKMaxTableCapacity = 0x1
	settingQPACKBlockedStreams   = 0x7
	settingH3Datagram            = 0x33
)

// QUIC transport parameter IDs (Chrome-specific)
const (
	tpVersionInformation = 0x11   // RFC 9368 version negotiation
	tpGoogleVersion      = 0x4752 // Google's custom version param (18258)
)

func init() {
	// Suppress quic-go UDP buffer size warning
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "1")

	// Set Chrome-like additional transport parameters
	// These are sent in addition to the standard QUIC parameters
	quic.SetAdditionalTransportParameters(buildChromeTransportParams())

	// Test debug logging at init
	logDebug("http3_transport init called")
}

// buildChromeTransportParams creates Chrome-like QUIC transport parameters
func buildChromeTransportParams() map[uint64][]byte {
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

	return params
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

	// Cached PSK ClientHelloSpec for session resumption with 0-RTT
	// Used when there's a cached session (includes early_data and pre_shared_key extensions)
	cachedQUICPSKSpec *utls.ClientHelloSpec

	// Separate cached spec for inner MASQUE connections (not shared with outer)
	cachedClientHelloSpecInner *utls.ClientHelloSpec

	// Separate PSK spec for inner MASQUE connections (session resumption)
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

	// Proxy support for SOCKS5 UDP relay
	proxyConfig   *ProxyConfig
	socks5Conn    *proxy.SOCKS5UDPConn
	quicTransport *quic.Transport

	// MASQUE proxy support
	masqueConn *proxy.MASQUEConn

	// Advanced configuration (ConnectTo, ECH override)
	config *TransportConfig
}

// NewHTTP3Transport creates a new HTTP/3 transport
func NewHTTP3Transport(preset *fingerprint.Preset, dnsCache *dns.Cache) *HTTP3Transport {
	return NewHTTP3TransportWithTransportConfig(preset, dnsCache, nil)
}

// NewHTTP3TransportWithTransportConfig creates a new HTTP/3 transport with advanced config
func NewHTTP3TransportWithTransportConfig(preset *fingerprint.Preset, dnsCache *dns.Cache, config *TransportConfig) *HTTP3Transport {
	// Generate shuffle seed for session-consistent ordering
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	t := &HTTP3Transport{
		preset:       preset,
		dnsCache:     dnsCache,
		sessionCache: NewPersistableSessionCache(), // Cache for 0-RTT resumption
		shuffleSeed:  shuffleSeed,
		config:       config,
	}

	// Create TLS config for QUIC with session cache for 0-RTT
	t.tlsConfig = &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
		ClientSessionCache: t.sessionCache, // Enable 0-RTT session resumption
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

	// Cache PSK ClientHelloSpec for session resumption (includes early_data + pre_shared_key)
	// Used when there's a cached session for the host - matches real Chrome resumed connections
	if preset.QUICPSKClientHelloID.Client != "" {
		spec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed)
		if err == nil {
			t.cachedQUICPSKSpec = &spec
		}
	}

	// Create QUIC config with connection reuse settings and TLS fingerprinting
	t.quicConfig = &quic.Config{
		MaxIdleTimeout:               30 * time.Second, // Chrome uses 30s, not 90s
		KeepAlivePeriod:              30 * time.Second,
		MaxIncomingStreams:           100,
		MaxIncomingUniStreams:        103, // Chrome uses 103
		Allow0RTT:                    true,
		EnableDatagrams:              true,  // Chrome enables QUIC datagrams
		InitialPacketSize:            1250,  // Chrome uses ~1250
		DisablePathMTUDiscovery:      false, // Still allow PMTUD for optimal performance
		DisableClientHelloScrambling: true,  // Chrome doesn't scramble SNI, sends fewer packets
		ChromeStyleInitialPackets:    true,  // Chrome-like frame patterns in Initial packets
		ClientHelloID:                 clientHelloID,           // Fallback if cached spec fails
		CachedClientHelloSpec:         t.cachedClientHelloSpec, // Cached spec for consistent fingerprint
		TransportParameterOrder:       quic.TransportParameterOrderChrome, // Chrome transport param ordering with large GREASE IDs
		TransportParameterShuffleSeed: shuffleSeed, // Consistent transport param shuffle per session
	}

	// Generate GREASE setting ID (must be of form 0x1f * N + 0x21)
	// Chrome uses random GREASE values
	greaseSettingID := generateGREASESettingID()
	// Generate non-zero random 32-bit value (Chrome never sends 0)
	greaseSettingValue := uint64(1 + rand.Uint32()%(1<<32-1))

	// Chrome-like HTTP/3 settings
	// These match what Chrome 143 sends in SETTINGS frame
	additionalSettings := map[uint64]uint64{
		settingQPACKMaxTableCapacity: 65536,             // Chrome's QPACK table capacity
		settingQPACKBlockedStreams:   100,               // Chrome's blocked streams limit
		greaseSettingID:              greaseSettingValue, // GREASE setting
	}

	// Create QUIC transport for direct connections
	// We need a bound UDP socket for quic.Transport
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		// Fallback to IPv6 if IPv4 fails
		udpConn, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
		if err != nil {
			return nil // Will use http3.Transport's default behavior
		}
	}
	t.quicTransport = &quic.Transport{
		Conn: udpConn,
	}

	// Create HTTP/3 transport with custom dial for DNS caching
	// http3.Transport handles connection pooling internally
	t.transport = &http3.Transport{
		TLSClientConfig:        t.tlsConfig,
		QUICConfig:             t.quicConfig,
		Dial:                   t.dialQUIC, // Just for DNS resolution
		EnableDatagrams:        true,       // Chrome enables H3_DATAGRAM
		AdditionalSettings:     additionalSettings,
		MaxResponseHeaderBytes: 262144,     // Chrome's MAX_FIELD_SECTION_SIZE
		SendGreaseFrames:       true,       // Chrome sends GREASE frames on control stream
	}

	return t
}

// NewHTTP3TransportWithProxy creates a new HTTP/3 transport with SOCKS5 proxy support
// Only SOCKS5 proxies support UDP relay needed for QUIC/HTTP3
func NewHTTP3TransportWithProxy(preset *fingerprint.Preset, dnsCache *dns.Cache, proxyConfig *ProxyConfig) (*HTTP3Transport, error) {
	return NewHTTP3TransportWithConfig(preset, dnsCache, proxyConfig, nil)
}

// NewHTTP3TransportWithConfig creates a new HTTP/3 transport with SOCKS5 proxy and advanced config
func NewHTTP3TransportWithConfig(preset *fingerprint.Preset, dnsCache *dns.Cache, proxyConfig *ProxyConfig, config *TransportConfig) (*HTTP3Transport, error) {
	// Validate proxy scheme - only SOCKS5 works for UDP/QUIC
	if proxyConfig != nil && proxyConfig.URL != "" {
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

	t := &HTTP3Transport{
		preset:       preset,
		dnsCache:     dnsCache,
		sessionCache: NewPersistableSessionCache(),
		shuffleSeed:  shuffleSeed,
		proxyConfig:  proxyConfig,
		config:       config,
	}

	// Create TLS config for QUIC
	t.tlsConfig = &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
		ClientSessionCache: t.sessionCache,
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

	// Create QUIC config
	t.quicConfig = &quic.Config{
		MaxIdleTimeout:                30 * time.Second,
		KeepAlivePeriod:               30 * time.Second,
		MaxIncomingStreams:            100,
		MaxIncomingUniStreams:         103,
		Allow0RTT:                     true,
		EnableDatagrams:               true,
		InitialPacketSize:             1250,
		DisablePathMTUDiscovery:       false,
		DisableClientHelloScrambling:  true,
		ChromeStyleInitialPackets:     true,
		ClientHelloID:                 clientHelloID,
		CachedClientHelloSpec:         t.cachedClientHelloSpec,
		TransportParameterOrder:       quic.TransportParameterOrderChrome,
		TransportParameterShuffleSeed: shuffleSeed,
	}

	// Set up SOCKS5 UDP relay if proxy is configured
	if proxyConfig != nil && proxyConfig.URL != "" {
		socks5Conn, err := proxy.NewSOCKS5UDPConn(proxyConfig.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 UDP connection: %w", err)
		}

		// Establish UDP ASSOCIATE (with 15 second timeout)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := socks5Conn.Establish(ctx); err != nil {
			socks5Conn.Close()
			return nil, fmt.Errorf("SOCKS5 UDP ASSOCIATE failed: %w", err)
		}

		t.socks5Conn = socks5Conn

		// Create quic.Transport with our SOCKS5 PacketConn
		t.quicTransport = &quic.Transport{
			Conn: socks5Conn,
		}
	}

	// Generate GREASE settings
	greaseSettingID := generateGREASESettingID()
	greaseSettingValue := uint64(1 + rand.Uint32()%(1<<32-1))

	additionalSettings := map[uint64]uint64{
		settingQPACKMaxTableCapacity: 65536,
		settingQPACKBlockedStreams:   100,
		greaseSettingID:              greaseSettingValue,
	}

	// Create HTTP/3 transport with appropriate dial function
	if t.socks5Conn != nil {
		// Use proxy-aware dial function
		t.transport = &http3.Transport{
			TLSClientConfig:        t.tlsConfig,
			QUICConfig:             t.quicConfig,
			Dial:                   t.dialQUICWithProxy,
			EnableDatagrams:        true,
			AdditionalSettings:     additionalSettings,
			MaxResponseHeaderBytes: 262144,
			SendGreaseFrames:       true,
		}
	} else {
		// Use standard dial function
		t.transport = &http3.Transport{
			TLSClientConfig:        t.tlsConfig,
			QUICConfig:             t.quicConfig,
			Dial:                   t.dialQUIC,
			EnableDatagrams:        true,
			AdditionalSettings:     additionalSettings,
			MaxResponseHeaderBytes: 262144,
			SendGreaseFrames:       true,
		}
	}

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

	t := &HTTP3Transport{
		preset:       preset,
		dnsCache:     dnsCache,
		sessionCache: NewPersistableSessionCache(),
		shuffleSeed:  shuffleSeed,
		proxyConfig:  proxyConfig,
		config:       config,
	}

	// Create TLS config for QUIC
	t.tlsConfig = &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
		ClientSessionCache: t.sessionCache,
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

	// Cache PSK spec for outer connections
	if preset.QUICPSKClientHelloID.Client != "" {
		spec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed)
		if err == nil {
			t.cachedQUICPSKSpec = &spec
		}
		// Create separate PSK spec for inner connections
		innerPSKSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed)
		if err == nil {
			t.cachedClientHelloSpecInnerPSK = &innerPSKSpec
		}
	}

	// Create QUIC config with MASQUE-specific settings
	t.quicConfig = &quic.Config{
		MaxIdleTimeout:                30 * time.Second,
		KeepAlivePeriod:               30 * time.Second,
		MaxIncomingStreams:            100,
		MaxIncomingUniStreams:         103,
		Allow0RTT:                     true,
		EnableDatagrams:               true, // Required for MASQUE
		InitialPacketSize:             1250,
		DisablePathMTUDiscovery:       false,
		DisableClientHelloScrambling:  true,
		ChromeStyleInitialPackets:     true,
		ClientHelloID:                 clientHelloID,
		CachedClientHelloSpec:         t.cachedClientHelloSpec,
		TransportParameterOrder:       quic.TransportParameterOrderChrome,
		TransportParameterShuffleSeed: shuffleSeed,
	}

	// Create MASQUE connection
	masqueConn, err := proxy.NewMASQUEConn(proxyConfig.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create MASQUE connection: %w", err)
	}
	t.masqueConn = masqueConn

	// Generate GREASE settings
	greaseSettingID := generateGREASESettingID()
	greaseSettingValue := uint64(1 + rand.Uint32()%(1<<32-1))

	additionalSettings := map[uint64]uint64{
		settingQPACKMaxTableCapacity: 65536,
		settingQPACKBlockedStreams:   100,
		greaseSettingID:              greaseSettingValue,
	}

	// Create HTTP/3 transport with MASQUE dial function
	t.transport = &http3.Transport{
		TLSClientConfig:        t.tlsConfig,
		QUICConfig:             t.quicConfig,
		Dial:                   t.dialQUICWithMASQUE,
		EnableDatagrams:        true,
		AdditionalSettings:     additionalSettings,
		MaxResponseHeaderBytes: 262144,
		SendGreaseFrames:       true,
	}

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

	// Create quic.Transport with MASQUE PacketConn
	if t.quicTransport == nil {
		t.quicTransport = &quic.Transport{
			Conn: t.masqueConn,
		}
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
	tlsCfgCopy.ClientSessionCache = t.sessionCache

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

	// Choose spec based on session cache - use PSK spec for resumed connections
	innerSpec := t.cachedClientHelloSpecInner
	if t.cachedClientHelloSpecInnerPSK != nil && t.sessionCache != nil {
		if session, ok := t.sessionCache.Get(host); ok && session != nil {
			innerSpec = t.cachedClientHelloSpecInnerPSK
		}
	}

	cfgCopy := &quic.Config{
		MaxIdleTimeout:                  30 * time.Second,
		KeepAlivePeriod:                 30 * time.Second,
		MaxIncomingStreams:              100,
		MaxIncomingUniStreams:           103,
		Allow0RTT:                       true,
		EnableDatagrams:                 true,
		InitialPacketSize:               1200,
		DisablePathMTUDiscovery:         true, // Disable PMTUD through tunnel
		DisableClientHelloScrambling:    true, // Chrome doesn't scramble, simplifies tunnel handshake
		InitialStreamReceiveWindow:      512 * 1024,
		MaxStreamReceiveWindow:          6 * 1024 * 1024,
		InitialConnectionReceiveWindow:  15 * 1024 * 1024 / 2,
		MaxConnectionReceiveWindow:      15 * 1024 * 1024,
		TransportParameterOrder:         quic.TransportParameterOrderChrome,
		TransportParameterShuffleSeed:   t.shuffleSeed,
		ClientHelloID:                   clientHelloID,
		CachedClientHelloSpec:           innerSpec, // Separate spec for consistent JA4, uses PSK for resumed
		ECHConfigList:                   echConfigList,
	}

	// Dial QUIC over the MASQUE tunnel using quic.DialEarly for 0-RTT support
	// This properly supports ECH, unlike quic.Transport.Dial
	return quic.DialEarly(ctx, t.masqueConn, targetAddr, tlsCfgCopy, cfgCopy)
}

// dialQUICWithProxy dials a QUIC connection through SOCKS5 proxy
// Uses Happy Eyeballs-style racing between IPv4 and IPv6 addresses
func (t *HTTP3Transport) dialQUICWithProxy(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
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

	// Resolve DNS to get all addresses - resolve connection host, not request host
	ips, err := t.dnsCache.Resolve(ctx, connectHost)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", connectHost, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %s", connectHost)
	}

	// Convert port to int
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
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

	// Use our own TLS config (with session cache) instead of the one passed by http3.Transport
	tlsCfgCopy := t.tlsConfig.Clone()
	tlsCfgCopy.ServerName = host
	// Clone() doesn't preserve ClientSessionCache, restore it for session resumption
	tlsCfgCopy.ClientSessionCache = t.sessionCache

	// Clone our QUIC config (with proper fingerprinting settings)
	cfgCopy := t.quicConfig.Clone()

	// Switch to PSK ClientHelloSpec for resumed connections
	if t.cachedQUICPSKSpec != nil && t.sessionCache != nil {
		if session, ok := t.sessionCache.Get(host); ok && session != nil {
			cfgCopy.CachedClientHelloSpec = t.cachedQUICPSKSpec
		}
	}

	// Race IPv6 and IPv4 connections (Happy Eyeballs style)
	// Try IPv6 first, then IPv4 after short timeout
	// Pass request host for ECH config fetching
	return t.raceQUICDial(ctx, host, ipv6Addrs, ipv4Addrs, tlsCfgCopy, cfgCopy)
}

// raceQUICDial implements Happy Eyeballs-style connection racing
// Tries IPv6 first with a short timeout, then falls back to IPv4 if needed
func (t *HTTP3Transport) raceQUICDial(ctx context.Context, host string, ipv6Addrs, ipv4Addrs []*net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	// If only one address family available, just dial it directly
	if len(ipv6Addrs) == 0 && len(ipv4Addrs) == 0 {
		return nil, fmt.Errorf("no addresses to dial")
	}

	// Fetch ECH config - use custom config if set, otherwise from target host
	echConfigList := t.getECHConfig(ctx, host)

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

// dialFirstSuccessful tries each address in order until one succeeds
func (t *HTTP3Transport) dialFirstSuccessful(ctx context.Context, addrs []*net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	var lastErr error
	for _, addr := range addrs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		conn, err := t.quicTransport.Dial(ctx, addr, tlsCfg, cfg)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
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
	logDebug("dialQUIC called for addr: %s", addr)
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

	// Resolve DNS to get all addresses - resolve connection host, not request host
	ips, err := t.dnsCache.Resolve(ctx, connectHost)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", connectHost, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %s", connectHost)
	}

	// Convert port to int
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
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

	// Use our own TLS config (with session cache) instead of the one passed by http3.Transport
	// http3.Transport may not include ClientSessionCache in the config it passes
	tlsCfgCopy := t.tlsConfig.Clone()
	tlsCfgCopy.ServerName = host
	// Clone() doesn't preserve ClientSessionCache, restore it for session resumption
	tlsCfgCopy.ClientSessionCache = t.sessionCache

	// Clone our QUIC config (with proper fingerprinting settings)
	cfgCopy := t.quicConfig.Clone()

	// Switch to PSK ClientHelloSpec for resumed connections
	// If there's a cached session, use PSK spec (includes early_data + pre_shared_key)
	// This matches real Chrome's behavior for 0-RTT resumption
	logDebug("dialQUICWithDNS: checking PSK spec and session cache for host: %s", host)
	logDebug("  cachedQUICPSKSpec nil: %v", t.cachedQUICPSKSpec == nil)
	logDebug("  sessionCache nil: %v", t.sessionCache == nil)
	if t.sessionCache != nil {
		if psc, ok := t.sessionCache.(*PersistableSessionCache); ok {
			logDebug("  sessionCache is PersistableSessionCache with %d sessions", psc.Count())
		}
	}
	// Switch to PSK ClientHelloSpec for resumed connections with 0-RTT
	if t.cachedQUICPSKSpec != nil && t.sessionCache != nil {
		if session, ok := t.sessionCache.Get(host); ok && session != nil {
			cfgCopy.CachedClientHelloSpec = t.cachedQUICPSKSpec
			logDebug("Using PSK spec for cached session host: %s", host)
		} else {
			logDebug("No cached session for host: %s", host)
		}
	}

	// Race IPv6 and IPv4 connections (Happy Eyeballs style)
	// Try IPv6 first, then IPv4 after short timeout
	// Pass request host for ECH config fetching
	return t.raceQUICDial(ctx, host, ipv6Addrs, ipv4Addrs, tlsCfgCopy, cfgCopy)
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

	// Make request - http3.Transport handles connection pooling
	resp, err := t.transport.RoundTrip(req)

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

// Close shuts down the transport and all connections
func (t *HTTP3Transport) Close() error {
	var errs []error

	// Close HTTP/3 transport
	if err := t.transport.Close(); err != nil {
		errs = append(errs, err)
	}

	// Close QUIC transport if using proxy
	if t.quicTransport != nil {
		if err := t.quicTransport.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// Close SOCKS5 UDP connection if using proxy
	if t.socks5Conn != nil {
		if err := t.socks5Conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// Close MASQUE connection if using MASQUE proxy
	if t.masqueConn != nil {
		if err := t.masqueConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
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

// Connect establishes a QUIC connection to the host without making a request.
// This is used for protocol racing - the first protocol to connect wins.
func (t *HTTP3Transport) Connect(ctx context.Context, host, port string) error {
	addr := net.JoinHostPort(host, port)

	// Use DNS cache for resolution
	ip, err := t.dnsCache.ResolveOne(ctx, host)
	if err != nil {
		return fmt.Errorf("DNS resolution failed: %w", err)
	}

	resolvedAddr := net.JoinHostPort(ip.String(), port)

	// Create TLS config
	tlsCfg := &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: false,
	}

	// Fetch ECH configs from DNS HTTPS records
	// This is non-blocking - if it fails, we proceed without ECH
	echConfigList, _ := dns.FetchECHConfigs(ctx, host)

	// QUIC config with Chrome-like settings and ECH
	quicCfg := &quic.Config{
		MaxIdleTimeout:                  30 * time.Second,
		InitialStreamReceiveWindow:     512 * 1024,
		MaxStreamReceiveWindow:         6 * 1024 * 1024,
		InitialConnectionReceiveWindow: 15 * 1024 * 1024 / 2,
		MaxConnectionReceiveWindow:     15 * 1024 * 1024,
		ECHConfigList:                  echConfigList,
		TransportParameterOrder:        quic.TransportParameterOrderChrome, // Chrome transport param ordering
		TransportParameterShuffleSeed:  t.shuffleSeed, // Consistent transport param shuffle per session
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
	if t.config == nil {
		echConfig, _ := dns.FetchECHConfigs(ctx, targetHost)
		return echConfig
	}
	return t.config.GetECHConfig(ctx, targetHost)
}
