package pool

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"io"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/keylog"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	"github.com/sardanioss/quic-go/quicvarint"
	tls "github.com/sardanioss/utls"
	utls "github.com/sardanioss/utls"
)

// HTTP/3 SETTINGS identifiers (Chrome-like)
const (
	settingQPACKMaxTableCapacity = 0x1
	settingMaxFieldSectionSize   = 0x6
	settingQPACKBlockedStreams   = 0x7
	settingH3Datagram            = 0x33
)

// QUIC Transport Parameter IDs
const (
	transportParamVersionInfo  = 0x11   // version_information
	transportParamGoogleVer    = 0x4752 // google_version (18258)
	transportParamInitialRTT   = 0x3127 // initial_rtt (12583)
)

func init() {
	// Set Chrome-like connection ID length (0 bytes - Chrome sends empty SCID)
	quic.SetDefaultConnectionIDLength(0)

	// Set Chrome-like max_datagram_frame_size (65536 vs default 16383)
	quic.SetMaxDatagramSize(65536)

	// Set additional transport parameters to match Chrome fingerprint
	quic.SetAdditionalTransportParameters(buildChromeTransportParams())
}

// buildChromeTransportParams builds Chrome-like QUIC transport parameters
func buildChromeTransportParams() map[uint64][]byte {
	params := make(map[uint64][]byte)

	// version_information (0x11): chosen_version=QUICv1, available_versions=[QUICv1, GREASE]
	// Format: chosen_version (4 bytes) + available_versions_length (varint) + versions...
	versionInfo := make([]byte, 0, 16)
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, 0x00000001) // QUICv1 chosen
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, 0x00000001) // QUICv1 available
	// Chrome uses consistent GREASE version pattern: 0xdadadada is common
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, 0xdadadada)
	params[transportParamVersionInfo] = versionInfo

	// google_version (0x4752): QUICv1
	googleVer := make([]byte, 4)
	binary.BigEndian.PutUint32(googleVer, 0x00000001) // QUICv1
	params[transportParamGoogleVer] = googleVer

	// initial_rtt (12583/0x3127): Chrome typically uses values around 100-300ms
	// Use a consistent value to avoid fingerprint variation
	initialRTT := make([]byte, 0, 8)
	initialRTT = quicvarint.Append(initialRTT, 100000) // 100ms in microseconds
	params[transportParamInitialRTT] = initialRTT

	// GREASE transport parameter - Chrome uses large random N values
	// GREASE IDs are of form 27 + 31*N where N is random
	// Chrome uses values like 25319800860025788 (very large N)
	greaseID := generateGREASETransportParamID()
	params[greaseID] = []byte{} // Empty GREASE data is valid and common

	return params
}

// generateGREASEVersion generates a GREASE version value
// GREASE versions are of form 0x?a?a?a?a where ? is any hex digit
func generateGREASEVersion() uint32 {
	n := rand.Uint32()
	return (n & 0xf0f0f0f0) | 0x0a0a0a0a
}

// generateGREASETransportParamID generates a GREASE transport parameter ID
// GREASE IDs are of form 27 + 31*N for some N
// Chrome uses very large N values, producing IDs like 25319800860025788
func generateGREASETransportParamID() uint64 {
	// Generate large N values similar to Chrome (produces 15-17 digit IDs)
	n := uint64(100000000000000 + rand.Int63n(900000000000000))
	return 27 + 31*n
}

// Note: quic-go may print buffer size warnings to stderr. These are informational
// and don't affect functionality. We don't suppress them globally as that would
// break logging for the entire application.

// QUICConn represents a persistent QUIC connection
type QUICConn struct {
	Host       string
	RemoteAddr net.Addr
	QUICConn   *quic.Conn
	HTTP3RT    *http3.Transport
	CreatedAt  time.Time
	LastUsedAt time.Time
	UseCount   int64
	mu         sync.Mutex
	closed     bool
}

// IsHealthy checks if the QUIC connection is still usable
func (c *QUICConn) IsHealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return false
	}

	// Check if we have a raw QUIC connection (set when Dial completes)
	if c.QUICConn != nil {
		select {
		case <-c.QUICConn.Context().Done():
			return false
		default:
			return true
		}
	}

	// If we only have the HTTP3 transport, it handles its own connection pooling
	// The transport will dial a new connection if needed
	if c.HTTP3RT != nil {
		return true
	}

	return false
}

// Age returns how long the connection has been open
func (c *QUICConn) Age() time.Duration {
	return time.Since(c.CreatedAt)
}

// IdleTime returns how long since the connection was last used
func (c *QUICConn) IdleTime() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.LastUsedAt)
}

// MarkUsed updates the last used timestamp
func (c *QUICConn) MarkUsed() {
	c.mu.Lock()
	c.LastUsedAt = time.Now()
	c.UseCount++
	c.mu.Unlock()
}

// Close closes the QUIC connection
func (c *QUICConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	var errs []error
	if c.HTTP3RT != nil {
		if err := c.HTTP3RT.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.QUICConn != nil {
		if err := c.QUICConn.CloseWithError(quic.ApplicationErrorCode(0), "closing"); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// QUICHostPool manages QUIC connections to a single host
type QUICHostPool struct {
	host        string
	port        string
	preset      *fingerprint.Preset
	dnsCache    *dns.Cache
	connections []*QUICConn
	mu          sync.Mutex

	// Cached ClientHelloSpec for consistent TLS fingerprint
	// Chrome shuffles TLS extensions once per session, not per connection
	cachedClientHelloSpec *utls.ClientHelloSpec

	// Cached PSK ClientHelloSpec for session resumption
	// Used when a valid session exists in the cache (includes PSK extension)
	cachedPSKSpec *utls.ClientHelloSpec

	// Shuffle seed for transport parameter ordering (consistent per session)
	shuffleSeed int64

	// Session cache for TLS session resumption (0-RTT)
	sessionCache tls.ClientSessionCache

	// Configuration
	maxConns           int
	maxIdleTime        time.Duration
	maxConnAge         time.Duration
	connectTimeout     time.Duration
	echConfig          []byte // Custom ECH configuration
	echConfigDomain    string // Domain to fetch ECH config from
	disableECH         bool   // Disable automatic ECH fetching (Chrome doesn't always use ECH)
	insecureSkipVerify bool   // Skip TLS certificate verification (for testing)
	localAddr          string // Local IP to bind outgoing connections
}

// NewQUICHostPool creates a new QUIC pool for a specific host
func NewQUICHostPool(host, port string, preset *fingerprint.Preset, dnsCache *dns.Cache) *QUICHostPool {
	// Generate spec and seed for standalone usage (backward compatibility)
	var cachedSpec *utls.ClientHelloSpec
	var cachedPSKSpec *utls.ClientHelloSpec
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	if preset != nil && preset.QUICClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.QUICClientHelloID, shuffleSeed); err == nil {
			cachedSpec = &spec
		}
	}
	// Also generate PSK spec for session resumption
	if preset != nil && preset.QUICPSKClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			cachedPSKSpec = &spec
		}
	}
	return NewQUICHostPoolWithCachedSpec(host, port, preset, dnsCache, cachedSpec, cachedPSKSpec, shuffleSeed)
}

// NewQUICHostPoolWithCachedSpec creates a QUIC pool with a pre-cached ClientHelloSpec and shuffle seed
// This ensures consistent TLS extension order and transport parameter order across all hosts in a session
// cachedSpec is used for initial connections, cachedPSKSpec is used when resuming sessions
func NewQUICHostPoolWithCachedSpec(host, port string, preset *fingerprint.Preset, dnsCache *dns.Cache, cachedSpec *utls.ClientHelloSpec, cachedPSKSpec *utls.ClientHelloSpec, shuffleSeed int64) *QUICHostPool {
	pool := &QUICHostPool{
		host:                  host,
		port:                  port,
		preset:                preset,
		dnsCache:              dnsCache,
		connections:           make([]*QUICConn, 0),
		maxConns:              0, // 0 = unlimited
		maxIdleTime:           90 * time.Second,
		maxConnAge:            5 * time.Minute,
		connectTimeout:        30 * time.Second,
		cachedClientHelloSpec: cachedSpec,                       // Use manager's cached spec for consistent TLS shuffle
		cachedPSKSpec:         cachedPSKSpec,                    // PSK spec for session resumption
		shuffleSeed:           shuffleSeed,                      // Use manager's seed for consistent transport param shuffle
		sessionCache:          tls.NewLRUClientSessionCache(32), // Session cache for 0-RTT resumption
	}

	return pool
}

// SetMaxConns sets the maximum connections for this pool (0 = unlimited)
func (p *QUICHostPool) SetMaxConns(max int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxConns = max
}

// SetLocalAddr sets the local IP address for outgoing connections
func (p *QUICHostPool) SetLocalAddr(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.localAddr = addr
}

// GetConn returns an available QUIC connection or creates a new one
func (p *QUICHostPool) GetConn(ctx context.Context) (*QUICConn, error) {
	p.mu.Lock()

	// First, try to find an existing healthy connection
	for i, conn := range p.connections {
		if conn.IsHealthy() && conn.IdleTime() < p.maxIdleTime && conn.Age() < p.maxConnAge {
			// Move to end (LRU)
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			p.connections = append(p.connections, conn)
			p.mu.Unlock()
			conn.MarkUsed()
			return conn, nil
		}
	}

	// Clean up unhealthy connections
	healthy := make([]*QUICConn, 0, len(p.connections))
	for _, conn := range p.connections {
		if conn.IsHealthy() && conn.Age() < p.maxConnAge {
			healthy = append(healthy, conn)
		} else {
			go conn.Close()
		}
	}
	p.connections = healthy

	// Check if we can create a new connection (0 = unlimited)
	if p.maxConns > 0 && len(p.connections) >= p.maxConns {
		p.mu.Unlock()
		return nil, ErrNoConnections
	}

	p.mu.Unlock()

	// Create new connection (outside lock to avoid blocking)
	conn, err := p.createConn(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.connections = append(p.connections, conn)
	p.mu.Unlock()

	return conn, nil
}

// createConn creates a new QUIC connection to the host
// Implements IPv6-first connection strategy
func (p *QUICHostPool) createConn(ctx context.Context) (*QUICConn, error) {
	// Get key log writer from global setting
	var keyLogWriter io.Writer = keylog.GetWriter()

	// TLS config for QUIC (HTTP/3)
	tlsConfig := &tls.Config{
		ServerName:         p.host,
		InsecureSkipVerify: p.insecureSkipVerify,
		NextProtos:         []string{http3.NextProtoH3}, // HTTP/3 ALPN
		MinVersion:         tls.VersionTLS13,
		KeyLogWriter:       keyLogWriter,
	}

	// Only enable session cache if we have PSK spec - prevents panic when session
	// is cached but spec doesn't have PSK extension (TOCTOU race mitigation)
	if p.cachedPSKSpec != nil {
		tlsConfig.ClientSessionCache = p.sessionCache
	}

	// Generate fresh spec for this connection to avoid race condition
	// utls's ApplyPreset (used internally by QUIC) mutates the spec, so each
	// connection needs its own copy. Use same shuffleSeed for consistent ordering.
	var selectedSpec *utls.ClientHelloSpec
	var clientHelloID *utls.ClientHelloID

	// Check if we have a cached session for this host
	// PSK spec (with early_data extension) should ONLY be used for session resumption
	// Using PSK spec on fresh connections causes handshake failures on some servers
	// Note: There's a small TOCTOU window here (another goroutine could add a session
	// after this check), but this matches the proxy path behavior and the window is
	// small enough that it rarely causes issues in practice.
	hasSession := p.hasSessionForHost()

	// Use PSK spec ONLY when resuming a session (matches proxy path behavior)
	if hasSession && p.cachedPSKSpec != nil && p.preset != nil && p.preset.QUICPSKClientHelloID.Client != "" {
		// Generate fresh PSK spec for this connection
		if spec, err := utls.UTLSIdToSpecWithSeed(p.preset.QUICPSKClientHelloID, p.shuffleSeed); err == nil {
			selectedSpec = &spec
		}
		clientHelloID = &p.preset.QUICPSKClientHelloID
	}
	// Use regular spec for fresh connections
	if selectedSpec == nil && p.cachedClientHelloSpec != nil && p.preset != nil && p.preset.QUICClientHelloID.Client != "" {
		// Generate fresh regular spec
		if spec, err := utls.UTLSIdToSpecWithSeed(p.preset.QUICClientHelloID, p.shuffleSeed); err == nil {
			selectedSpec = &spec
		}
		clientHelloID = &p.preset.QUICClientHelloID
	}

	// Get ECH configuration - use custom config if set, otherwise fetch from DNS
	// Skip ECH if disabled (Chrome doesn't always use ECH even when available)
	var echConfigList []byte
	if !p.disableECH {
		if len(p.echConfig) > 0 {
			echConfigList = p.echConfig
		} else if p.echConfigDomain != "" {
			echConfigList, _ = dns.FetchECHConfigs(ctx, p.echConfigDomain)
		} else if clientHelloID != nil {
			// Fetch ECH configs from DNS HTTPS records for real ECH negotiation
			echConfigList, _ = dns.FetchECHConfigs(ctx, p.host)
		}
	}

	// QUIC config with Chrome-like settings
	quicConfig := &quic.Config{
		MaxIdleTimeout:               30 * time.Second, // Chrome uses 30s
		KeepAlivePeriod:              15 * time.Second, // Send keepalives before idle timeout
		MaxIncomingStreams:           100,
		MaxIncomingUniStreams:        103, // Chrome uses 103
		Allow0RTT:                    true,
		EnableDatagrams:              true,  // Chrome enables QUIC datagrams
		InitialPacketSize:            1250,  // Chrome uses ~1250
		DisableClientHelloScrambling: true,  // Chrome doesn't scramble SNI, sends fewer packets
		ChromeStyleInitialPackets:    true,  // Chrome-like frame patterns in Initial packets
		ClientHelloID:                 clientHelloID,   // Fallback if cached spec fails
		CachedClientHelloSpec:         selectedSpec,    // Selected spec (regular or PSK) for fingerprint
		TransportParameterOrder:       quic.TransportParameterOrderChrome, // Chrome transport param ordering
		TransportParameterShuffleSeed: p.shuffleSeed, // Consistent transport param shuffle per session
	}
	// Only set ECHConfigList if we have a config - matches proxy path behavior
	// Setting nil explicitly vs not setting at all triggers different behavior in quic-go
	if len(echConfigList) > 0 {
		quicConfig.ECHConfigList = echConfigList
	}

	// Get IPv6 and IPv4 addresses separately
	ipv6, ipv4, err := p.dnsCache.ResolveIPv6First(ctx, p.host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}

	// Check if user prefers IPv4
	preferIPv4 := p.dnsCache != nil && p.dnsCache.PreferIPv4()

	port, _ := net.LookupPort("udp", p.port)
	if port == 0 {
		port = 443
	}

	// Generate large GREASE setting ID like Chrome (0x1f * N + 0x21 where N is large)
	greaseSettingN := uint64(1000000000 + rand.Int63n(9000000000))
	greaseSettingID := 0x1f*greaseSettingN + 0x21
	// Generate non-zero random 32-bit value (Chrome never sends 0)
	greaseSettingValue := uint64(1 + rand.Uint32()%(1<<32-1))

	// HTTP/3 QPACK settings - Safari/iOS uses different values than Chrome
	// Safari/iOS: QPACK_MAX_TABLE_CAPACITY=16383 (0x3fff)
	// Chrome: QPACK_MAX_TABLE_CAPACITY=65536 (0x10000)
	qpackMaxTableCapacity := uint64(65536) // Chrome default
	if p.preset != nil && p.preset.HTTP2Settings.NoRFC7540Priorities {
		// Safari/iOS uses smaller QPACK table
		qpackMaxTableCapacity = 16383
	}

	// HTTP/3 additional settings
	additionalSettings := map[uint64]uint64{
		settingQPACKMaxTableCapacity: qpackMaxTableCapacity, // Browser-specific QPACK table capacity
		settingQPACKBlockedStreams:   100,                   // Both Chrome and Safari use 100
		greaseSettingID:              greaseSettingValue,    // Random non-zero GREASE value
	}

	// Add Chrome-specific settings (not sent by Safari/iOS)
	if p.preset == nil || !p.preset.HTTP2Settings.NoRFC7540Priorities {
		additionalSettings[settingMaxFieldSectionSize] = 262144 // Chrome's MAX_FIELD_SECTION_SIZE
		additionalSettings[settingH3Datagram] = 1               // Chrome enables H3_DATAGRAM
	}

	// Order IPs based on preference
	var preferredIPs, fallbackIPs []net.IP
	if preferIPv4 {
		preferredIPs = ipv4
		fallbackIPs = ipv6
	} else {
		preferredIPs = ipv6
		fallbackIPs = ipv4
	}

	// Capture localAddr for the dial closure
	localAddr := p.localAddr

	// Create HTTP/3 transport - simple sequential dial (no racing for fingerprint consistency)
	h3Transport := &http3.Transport{
		TLSClientConfig:        tlsConfig,
		QUICConfig:             quicConfig,
		EnableDatagrams:        true,       // Chrome enables H3_DATAGRAM
		AdditionalSettings:     additionalSettings,
		MaxResponseHeaderBytes: 262144,     // Chrome's MAX_FIELD_SECTION_SIZE (256KB)
		SendGreaseFrames:       true,       // Chrome sends GREASE frames
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			// Combine all IPs, preferred first
			allIPs := append(preferredIPs, fallbackIPs...)
			if len(allIPs) == 0 {
				return nil, fmt.Errorf("no IP addresses available for %s", addr)
			}

			var lastErr error
			for _, remoteIP := range allIPs {
				network := "udp4"
				if remoteIP.To4() == nil {
					network = "udp6"
				}
				udpAddr := &net.UDPAddr{IP: remoteIP, Port: port}

				// Create local UDP address if specified (for IPv6 rotation)
				var localUDPAddr *net.UDPAddr
				if localAddr != "" {
					localUDPAddr = &net.UDPAddr{IP: net.ParseIP(localAddr)}
				}

				udpConn, err := net.ListenUDP(network, localUDPAddr)
				if err != nil {
					lastErr = err
					continue
				}

				// Use quic.Transport.DialEarly instead of quic.DialEarly directly
				// This matches the proxy path behavior and handles ECH/GREASE correctly
				quicTransport := &quic.Transport{
					Conn: udpConn,
				}

				conn, err := quicTransport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
				if err != nil {
					quicTransport.Close()
					lastErr = err
					continue
				}

				return conn, nil
			}

			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("all QUIC connection attempts failed for %s", addr)
		},
	}

	conn := &QUICConn{
		Host:       p.host,
		RemoteAddr: nil,
		QUICConn:   nil,
		HTTP3RT:    h3Transport,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
		UseCount:   0,
	}

	return conn, nil
}

// CloseIdle closes connections that have been idle too long
func (p *QUICHostPool) CloseIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()

	active := make([]*QUICConn, 0, len(p.connections))
	for _, conn := range p.connections {
		if conn.IdleTime() > p.maxIdleTime || conn.Age() > p.maxConnAge || !conn.IsHealthy() {
			go conn.Close()
		} else {
			active = append(active, conn)
		}
	}
	p.connections = active
}

// Close closes all connections in the pool
func (p *QUICHostPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		go conn.Close()
	}
	p.connections = nil
}

// CloseConnections closes all connections but keeps the pool usable
// This allows testing session resumption by forcing new connections
func (p *QUICHostPool) CloseConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		go conn.Close()
	}
	p.connections = make([]*QUICConn, 0)
}

// hasSessionForHost checks if there's a cached TLS session for the given host
// This is used to determine whether to use PSK spec (for resumption) or regular spec
// Returns false if no valid session exists (fresh connection should use regular spec)
func (p *QUICHostPool) hasSessionForHost() bool {
	if p.sessionCache == nil {
		return false
	}
	// TLS 1.3 session key is typically just the server name
	session, ok := p.sessionCache.Get(p.host)
	// Must have both a valid lookup AND a non-nil session state
	return ok && session != nil
}

// Stats returns pool statistics
func (p *QUICHostPool) Stats() (total int, healthy int, totalRequests int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		total++
		if conn.IsHealthy() {
			healthy++
		}
		totalRequests += conn.UseCount
	}
	return
}

// QUICManager manages QUIC connection pools for multiple hosts
type QUICManager struct {
	pools    map[string]*QUICHostPool
	mu       sync.RWMutex
	dnsCache *dns.Cache
	preset   *fingerprint.Preset
	closed   bool

	// Configuration
	maxConnsPerHost    int               // 0 = unlimited
	connectTo          map[string]string // Domain fronting: request host -> connect host
	echConfig          []byte            // Custom ECH configuration
	echConfigDomain    string            // Domain to fetch ECH config from
	disableECH         bool              // Disable automatic ECH fetching
	insecureSkipVerify bool              // Skip TLS certificate verification
	localAddr          string            // Local IP to bind outgoing connections

	// Cached TLS specs - shared across all QUICHostPools for consistent fingerprint
	// Chrome shuffles extension order once per session, not per connection
	cachedSpec    *utls.ClientHelloSpec
	cachedPSKSpec *utls.ClientHelloSpec
	shuffleSeed   int64 // Seed used for extension shuffling

	// Background cleanup
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// NewQUICManager creates a new QUIC connection pool manager
func NewQUICManager(preset *fingerprint.Preset, dnsCache *dns.Cache) *QUICManager {
	// Generate random seed for extension shuffling
	// This seed is used for all QUIC connections in this manager (session)
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	m := &QUICManager{
		pools:           make(map[string]*QUICHostPool),
		dnsCache:        dnsCache,
		preset:          preset,
		maxConnsPerHost: 0, // 0 = unlimited by default
		shuffleSeed:     shuffleSeed,
		cleanupInterval: 30 * time.Second,
		stopCleanup:     make(chan struct{}),
	}

	// Generate and cache ClientHelloSpec with shuffled extensions
	// Chrome shuffles extensions once per session, not per connection
	if preset != nil && preset.QUICClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.QUICClientHelloID, shuffleSeed); err == nil {
			m.cachedSpec = &spec
		}
	}

	// Also cache PSK variant if available
	if preset != nil && preset.QUICPSKClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			m.cachedPSKSpec = &spec
		}
	}

	// Start background cleanup
	go m.cleanupLoop()

	return m
}

// SetMaxConnsPerHost sets the max connections per host for new pools (0 = unlimited)
func (m *QUICManager) SetMaxConnsPerHost(max int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxConnsPerHost = max
}

// SetConnectTo sets a host mapping for domain fronting
func (m *QUICManager) SetConnectTo(requestHost, connectHost string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connectTo == nil {
		m.connectTo = make(map[string]string)
	}
	m.connectTo[requestHost] = connectHost
}

// SetECHConfig sets a custom ECH configuration
func (m *QUICManager) SetECHConfig(echConfig []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.echConfig = echConfig
}

// SetECHConfigDomain sets a domain to fetch ECH config from
func (m *QUICManager) SetECHConfigDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.echConfigDomain = domain
}

// SetDisableECH disables automatic ECH fetching
// Chrome doesn't always use ECH even when available from DNS
func (m *QUICManager) SetDisableECH(disable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disableECH = disable
}

// SetInsecureSkipVerify sets whether to skip TLS certificate verification
func (m *QUICManager) SetInsecureSkipVerify(skip bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.insecureSkipVerify = skip
}

// SetLocalAddr sets the local IP address for outgoing connections
func (m *QUICManager) SetLocalAddr(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.localAddr = addr
}

// GetPool returns a pool for the given host, creating one if needed
func (m *QUICManager) GetPool(host, port string) (*QUICHostPool, error) {
	if port == "" {
		port = "443"
	}
	key := net.JoinHostPort(host, port)

	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrPoolClosed
	}
	pool, exists := m.pools[key]
	m.mu.RUnlock()

	if exists {
		return pool, nil
	}

	// Create new pool
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrPoolClosed
	}

	// Double-check after acquiring write lock
	if pool, exists = m.pools[key]; exists {
		return pool, nil
	}

	pool = NewQUICHostPoolWithCachedSpec(host, port, m.preset, m.dnsCache, m.cachedSpec, m.cachedPSKSpec, m.shuffleSeed)
	if m.maxConnsPerHost > 0 {
		pool.SetMaxConns(m.maxConnsPerHost)
	}
	// Pass ECH configuration to the pool
	if len(m.echConfig) > 0 {
		pool.echConfig = m.echConfig
	}
	if m.echConfigDomain != "" {
		pool.echConfigDomain = m.echConfigDomain
	}
	// Pass disableECH flag to the pool
	pool.disableECH = m.disableECH
	// Pass InsecureSkipVerify to the pool
	pool.insecureSkipVerify = m.insecureSkipVerify
	// Pass localAddr for IPv6 rotation
	if m.localAddr != "" {
		pool.localAddr = m.localAddr
	}
	m.pools[key] = pool
	return pool, nil
}

// GetConn gets a QUIC connection to the specified host
func (m *QUICManager) GetConn(ctx context.Context, host, port string) (*QUICConn, error) {
	pool, err := m.GetPool(host, port)
	if err != nil {
		return nil, err
	}
	return pool.GetConn(ctx)
}

// cleanupLoop periodically cleans up idle connections
func (m *QUICManager) cleanupLoop() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCleanup:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

// cleanup removes idle connections and empty pools
func (m *QUICManager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, pool := range m.pools {
		pool.CloseIdle()
		total, _, _ := pool.Stats()
		if total == 0 {
			delete(m.pools, key)
		}
	}
}

// Close shuts down the manager and all pools
func (m *QUICManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}
	m.closed = true

	close(m.stopCleanup)

	for _, pool := range m.pools {
		pool.Close()
	}
	m.pools = nil
}

// CloseAllConnections closes all QUIC connections across all pools
// but keeps the pools usable with their session caches intact
// This is useful for testing session resumption
func (m *QUICManager) CloseAllConnections() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, pool := range m.pools {
		pool.CloseConnections()
	}
}

// CloseAllPools closes all pools and removes them entirely
// This is used when switching proxies - old connections/sessions are invalid for new proxy route
func (m *QUICManager) CloseAllPools() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, pool := range m.pools {
		pool.Close()
	}
	m.pools = make(map[string]*QUICHostPool)
}

// Stats returns overall manager statistics
func (m *QUICManager) Stats() map[string]struct {
	Total    int
	Healthy  int
	Requests int64
} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]struct {
		Total    int
		Healthy  int
		Requests int64
	})

	for key, pool := range m.pools {
		t, h, r := pool.Stats()
		stats[key] = struct {
			Total    int
			Healthy  int
			Requests int64
		}{t, h, r}
	}

	return stats
}

// generateGREASESettingID generates a valid GREASE setting ID
// GREASE IDs are of the form 0x1f * N + 0x21 where N is random
// Chrome uses very large N values, producing setting IDs like 57836956465
func generateGREASESettingID() uint64 {
	// Generate large N values similar to Chrome (produces 10-11 digit IDs)
	n := uint64(1000000000 + rand.Int63n(9000000000))
	return 0x1f*n + 0x21
}
