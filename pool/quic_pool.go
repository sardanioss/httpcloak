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
	"github.com/sardanioss/httpcloak/transport"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
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

// Note: Connection ID length, max datagram size, and additional transport params
// are all set per-connection on quic.Config / quic.Transport based on the preset.
// No process-global state is needed.

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
	host        string // Connection host (for DNS resolution - may be connectTo target)
	sniHost     string // SNI host (for TLS ServerName - always the original request host)
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
	return NewQUICHostPoolWithCachedSpec(host, "", port, preset, dnsCache, cachedSpec, cachedPSKSpec, shuffleSeed)
}

// NewQUICHostPoolWithCachedSpec creates a QUIC pool with a pre-cached ClientHelloSpec and shuffle seed
// This ensures consistent TLS extension order and transport parameter order across all hosts in a session
// cachedSpec is used for initial connections, cachedPSKSpec is used when resuming sessions
// host is the connection host (for DNS), sniHost is the TLS ServerName (original request host)
// If sniHost is empty, host is used for both
func NewQUICHostPoolWithCachedSpec(host, sniHost, port string, preset *fingerprint.Preset, dnsCache *dns.Cache, cachedSpec *utls.ClientHelloSpec, cachedPSKSpec *utls.ClientHelloSpec, shuffleSeed int64) *QUICHostPool {
	if sniHost == "" {
		sniHost = host
	}
	pool := &QUICHostPool{
		host:                  host,
		sniHost:               sniHost,
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
	var keyLogWriter io.Writer = transport.GetKeyLogWriter()

	// TLS config for QUIC (HTTP/3)
	// Use sniHost (original request host) for TLS ServerName, not p.host (which may be connectTo target)
	tlsConfig := &tls.Config{
		ServerName:         p.sniHost,
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
			// Use sniHost since ECH encrypts the SNI (original request host)
			echConfigList, _ = dns.FetchECHConfigs(ctx, p.sniHost)
		}
	}

	// QUIC config from preset getters
	quicConfig := &quic.Config{
		MaxIdleTimeout:                30 * time.Second, // Chrome uses 30s
		KeepAlivePeriod:               15 * time.Second, // Send keepalives before idle timeout
		MaxIncomingStreams:            p.preset.H3QUICMaxIncomingStreams(),
		MaxIncomingUniStreams:         p.preset.H3QUICMaxIncomingUniStreams(),
		Allow0RTT:                     p.preset.H3QUICAllow0RTT(),
		EnableDatagrams:               true, // Always true at QUIC level (original behavior); H3 SETTINGS controls per-browser advertisement
		InitialPacketSize:             p.preset.H3QUICInitialPacketSize(),
		DisableClientHelloScrambling:  p.preset.H3QUICDisableHelloScramble(),
		ChromeStyleInitialPackets:     p.preset.H3QUICChromeStyleInitial(),
		ClientHelloID:                 clientHelloID,
		CachedClientHelloSpec:         selectedSpec,
		TransportParameterOrder:       resolveTransportParamOrder(p.preset.H3QUICTransportParamOrder()),
		TransportParameterShuffleSeed: p.shuffleSeed,
		MaxDatagramFrameSize:          p.preset.H3QUICMaxDatagramFrameSize(),
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

	// Measure RTT and build per-connection additional transport params.
	// For Chrome presets, includes google_connection_options, google_version, etc.
	// For non-Chrome presets, returns nil (no Chrome-specific params sent).
	var rttHost string
	if len(ipv6) > 0 {
		rttHost = ipv6[0].String()
	} else if len(ipv4) > 0 {
		rttHost = ipv4[0].String()
	}
	quicConfig.AdditionalTransportParameters = transport.AdditionalTransportParamsForPreset(p.preset, ctx, rttHost, port)

	// Generate large GREASE setting ID like Chrome (0x1f * N + 0x21 where N is large)
	greaseSettingN := uint64(1000000000 + rand.Int63n(9000000000))
	greaseSettingID := 0x1f*greaseSettingN + 0x21
	// Generate non-zero random 32-bit value (Chrome never sends 0)
	greaseSettingValue := uint64(1 + rand.Uint32()%(1<<32-1))

	// HTTP/3 additional settings from preset getters
	additionalSettings := map[uint64]uint64{
		settingQPACKMaxTableCapacity: p.preset.H3QPACKMaxTableCapacity(),
		settingQPACKBlockedStreams:   p.preset.H3QPACKBlockedStreams(),
		greaseSettingID:              greaseSettingValue,
	}

	// Conditionally add settings based on preset
	if maxField := p.preset.H3MaxFieldSectionSize(); maxField > 0 {
		additionalSettings[settingMaxFieldSectionSize] = maxField
	}
	if p.preset.H3EnableDatagrams() {
		additionalSettings[settingH3Datagram] = 1
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
		EnableDatagrams:        true, // Always true at HTTP/3 level (original behavior); H3 SETTINGS controls per-browser advertisement
		AdditionalSettings:     additionalSettings,
		MaxResponseHeaderBytes: int(p.preset.H3MaxResponseHeaderBytes()),
		SendGreaseFrames:       p.preset.H3SendGreaseFrames(),
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
					Conn:                         udpConn,
					ConnectionIDLength:           p.preset.H3QUICConnectionIDLength(),
					AllowZeroLengthConnectionIDs: true,
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
	// TLS 1.3 session key is typically just the server name (use sniHost for consistency)
	session, ok := p.sessionCache.Get(p.sniHost)
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

	// Use connect host for pool key (domain fronting: multiple request hosts share one connection)
	connectHost := host
	if m.connectTo != nil {
		if mapped, ok := m.connectTo[host]; ok {
			connectHost = mapped
		}
	}
	key := net.JoinHostPort(connectHost, port)

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

	// Use connectHost for DNS resolution, but host (request host) for TLS SNI
	sniHost := ""
	if connectHost != host {
		sniHost = host // Original request host for TLS ServerName
	}
	pool = NewQUICHostPoolWithCachedSpec(connectHost, sniHost, port, m.preset, m.dnsCache, m.cachedSpec, m.cachedPSKSpec, m.shuffleSeed)
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

