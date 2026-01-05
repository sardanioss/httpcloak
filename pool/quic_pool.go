package pool

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	"github.com/sardanioss/quic-go/quicvarint"
	utls "github.com/sardanioss/utls"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// HTTP/3 SETTINGS identifiers (Chrome-like)
const (
	settingQPACKMaxTableCapacity = 0x1
	settingQPACKBlockedStreams   = 0x7
)

// QUIC Transport Parameter IDs
const (
	transportParamVersionInfo  = 0x11   // version_information
	transportParamGoogleVer    = 0x4752 // google_version (18258)
	transportParamInitialRTT   = 0x3127 // initial_rtt (12583)
)

func init() {
	// Set Chrome-like connection ID length (8 bytes vs default 4)
	quic.SetDefaultConnectionIDLength(8)

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
	greaseVersion := generateGREASEVersion()
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, greaseVersion) // GREASE version
	params[transportParamVersionInfo] = versionInfo

	// google_version (0x4752): QUICv1
	googleVer := make([]byte, 4)
	binary.BigEndian.PutUint32(googleVer, 0x00000001) // QUICv1
	params[transportParamGoogleVer] = googleVer

	// initial_rtt (12583/0x3127): varies, use ~230ms in microseconds
	initialRTT := make([]byte, 0, 8)
	initialRTT = quicvarint.Append(initialRTT, 230000+uint64(rand.Intn(10000))) // ~230-240ms
	params[transportParamInitialRTT] = initialRTT

	// GREASE transport parameter
	greaseID := generateGREASETransportParamID()
	greaseData := make([]byte, 9)
	rand.Read(greaseData)
	params[greaseID] = greaseData

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
func generateGREASETransportParamID() uint64 {
	n := rand.Uint64() % (1 << 16)
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

	// Check if QUIC connection context is still valid
	if c.QUICConn != nil {
		select {
		case <-c.QUICConn.Context().Done():
			return false
		default:
			return true
		}
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

	// Configuration
	maxConns       int
	maxIdleTime    time.Duration
	maxConnAge     time.Duration
	connectTimeout time.Duration
}

// NewQUICHostPool creates a new QUIC pool for a specific host
func NewQUICHostPool(host, port string, preset *fingerprint.Preset, dnsCache *dns.Cache) *QUICHostPool {
	return &QUICHostPool{
		host:           host,
		port:           port,
		preset:         preset,
		dnsCache:       dnsCache,
		connections:    make([]*QUICConn, 0),
		maxConns:       0, // 0 = unlimited
		maxIdleTime:    90 * time.Second,
		maxConnAge:     5 * time.Minute,
		connectTimeout: 30 * time.Second,
	}
}

// SetMaxConns sets the maximum connections for this pool (0 = unlimited)
func (p *QUICHostPool) SetMaxConns(max int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxConns = max
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
	// TLS config for QUIC (HTTP/3)
	tlsConfig := &tls.Config{
		ServerName:         p.host,
		InsecureSkipVerify: false,
		NextProtos:         []string{http3.NextProtoH3}, // HTTP/3 ALPN
		MinVersion:         tls.VersionTLS13,
	}

	// Get ClientHelloID from preset for TLS fingerprinting
	var clientHelloID *utls.ClientHelloID
	if p.preset != nil && p.preset.QUICClientHelloID.Client != "" {
		clientHelloID = &p.preset.QUICClientHelloID
	}

	// QUIC config with Chrome-like settings
	quicConfig := &quic.Config{
		MaxIdleTimeout:        30 * time.Second, // Chrome uses 30s
		KeepAlivePeriod:       30 * time.Second,
		MaxIncomingStreams:    100,
		MaxIncomingUniStreams: 103, // Chrome uses 103
		Allow0RTT:             true,
		EnableDatagrams:       true, // Chrome enables QUIC datagrams
		InitialPacketSize:     1200,
		ClientHelloID:         clientHelloID, // uTLS TLS fingerprinting
	}

	// Get IPv6 and IPv4 addresses
	ipv6, ipv4, err := p.dnsCache.ResolveIPv6First(ctx, p.host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}

	port, _ := net.LookupPort("udp", p.port)
	if port == 0 {
		port = 443
	}

	// Generate GREASE setting ID (must be of form 0x1f * N + 0x21)
	greaseSettingID := generateGREASESettingID()

	// Chrome-like HTTP/3 additional settings
	// Chrome uses GREASE setting with value 0
	additionalSettings := map[uint64]uint64{
		settingQPACKMaxTableCapacity: 65536, // Chrome's QPACK table capacity
		settingQPACKBlockedStreams:   100,   // Chrome's blocked streams limit
		greaseSettingID:              0,     // GREASE setting with value 0
	}

	// Create HTTP/3 transport with custom dial function for IPv6-first
	h3Transport := &http3.Transport{
		TLSClientConfig:        tlsConfig,
		QUICConfig:             quicConfig,
		EnableDatagrams:        true,       // Chrome enables H3_DATAGRAM
		AdditionalSettings:     additionalSettings,
		MaxResponseHeaderBytes: 262144,     // Chrome's MAX_FIELD_SECTION_SIZE
		SendGreaseFrames:       true,       // Chrome sends GREASE frames
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			// Try IPv6 first
			for _, ip := range ipv6 {
				udpAddr := &net.UDPAddr{IP: ip, Port: port}
				udpConn, err := net.ListenUDP("udp6", nil)
				if err != nil {
					continue
				}
				conn, err := quic.Dial(ctx, udpConn, udpAddr, tlsCfg, cfg)
				if err == nil {
					return conn, nil
				}
				udpConn.Close()
			}

			// Fallback to IPv4
			for _, ip := range ipv4 {
				udpAddr := &net.UDPAddr{IP: ip, Port: port}
				udpConn, err := net.ListenUDP("udp4", nil)
				if err != nil {
					continue
				}
				conn, err := quic.Dial(ctx, udpConn, udpAddr, tlsCfg, cfg)
				if err == nil {
					return conn, nil
				}
				udpConn.Close()
			}

			return nil, fmt.Errorf("all connection attempts failed for %s", addr)
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
	maxConnsPerHost int // 0 = unlimited

	// Background cleanup
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// NewQUICManager creates a new QUIC connection pool manager
func NewQUICManager(preset *fingerprint.Preset, dnsCache *dns.Cache) *QUICManager {
	m := &QUICManager{
		pools:           make(map[string]*QUICHostPool),
		dnsCache:        dnsCache,
		preset:          preset,
		maxConnsPerHost: 0, // 0 = unlimited by default
		cleanupInterval: 30 * time.Second,
		stopCleanup:     make(chan struct{}),
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

	pool = NewQUICHostPool(host, port, m.preset, m.dnsCache)
	if m.maxConnsPerHost > 0 {
		pool.SetMaxConns(m.maxConnsPerHost)
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
func generateGREASESettingID() uint64 {
	n := rand.Uint64() % (1 << 16)
	return 0x1f*n + 0x21
}
