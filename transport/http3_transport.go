package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	utls "github.com/sardanioss/utls"
)

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
}

// buildChromeTransportParams creates Chrome-like QUIC transport parameters
func buildChromeTransportParams() map[uint64][]byte {
	params := make(map[uint64][]byte)

	// version_information (0x11) - RFC 9368
	// Format: chosen_version (4 bytes) + available_versions (4 bytes each)
	// Chrome sends: QUICv1 (chosen) + [QUICv1, GREASE] (available)
	versionInfo := make([]byte, 0, 12)
	// Chosen version: QUICv1 (0x00000001)
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, 0x00000001)
	// Available versions: QUICv1
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, 0x00000001)
	// Available versions: GREASE (random value of form 0x?a?a?a?a)
	greaseVersion := generateGREASEVersion()
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, greaseVersion)
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

	// Track requests for timing
	requestCount int64
	dialCount    int64 // Number of times dialQUIC was called (new connections)
	mu           sync.RWMutex

	// Configuration
	quicConfig *quic.Config
	tlsConfig  *tls.Config
}

// NewHTTP3Transport creates a new HTTP/3 transport
func NewHTTP3Transport(preset *fingerprint.Preset, dnsCache *dns.Cache) *HTTP3Transport {
	t := &HTTP3Transport{
		preset:       preset,
		dnsCache:     dnsCache,
		sessionCache: tls.NewLRUClientSessionCache(64), // Cache for 0-RTT resumption
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

	// Create QUIC config with connection reuse settings and TLS fingerprinting
	t.quicConfig = &quic.Config{
		MaxIdleTimeout:        30 * time.Second, // Chrome uses 30s, not 90s
		KeepAlivePeriod:       30 * time.Second,
		MaxIncomingStreams:    100,
		MaxIncomingUniStreams: 103, // Chrome uses 103
		Allow0RTT:             true,
		EnableDatagrams:       true, // Chrome enables QUIC datagrams
		// Use smaller initial packet size to work within default buffer limits
		// This avoids the "failed to sufficiently increase receive buffer size" warning
		InitialPacketSize:       1200,
		DisablePathMTUDiscovery: false, // Still allow PMTUD for optimal performance
		// Use uTLS for TLS fingerprinting to match the preset's browser fingerprint
		ClientHelloID: clientHelloID,
	}

	// Generate GREASE setting ID (must be of form 0x1f * N + 0x21)
	// Chrome uses random GREASE values
	greaseSettingID := generateGREASESettingID()
	greaseSettingValue := rand.Uint64() & 0xFFFFFFFF // Random 32-bit value

	// Chrome-like HTTP/3 settings
	// These match what Chrome 143 sends in SETTINGS frame
	additionalSettings := map[uint64]uint64{
		settingQPACKMaxTableCapacity: 65536,             // Chrome's QPACK table capacity
		settingQPACKBlockedStreams:   100,               // Chrome's blocked streams limit
		greaseSettingID:              greaseSettingValue, // GREASE setting
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

// generateGREASESettingID generates a valid GREASE setting ID
// GREASE IDs are of the form 0x1f * N + 0x21 where N is random
func generateGREASESettingID() uint64 {
	// Generate a random N value (Chrome uses large values)
	n := rand.Uint64() % (1 << 32)
	return 0x1f*n + 0x21
}

// dialQUIC provides DNS resolution - http3.Transport handles connection caching
func (t *HTTP3Transport) dialQUIC(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	// Track dial calls - each call = new connection
	t.mu.Lock()
	t.dialCount++
	currentDialCount := t.dialCount
	t.mu.Unlock()

	// Parse host:port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	// Use DNS cache for resolution
	ip, err := t.dnsCache.ResolveOne(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}

	// Create new address with resolved IP
	resolvedAddr := net.JoinHostPort(ip.String(), port)

	// Set ServerName in TLS config
	tlsCfgCopy := tlsCfg.Clone()
	tlsCfgCopy.ServerName = host

	// Log for debugging (this is called only for NEW connections)
	_ = currentDialCount // Dial #N means this is the Nth new connection

	// Dial QUIC connection - http3.Transport will cache this
	return quic.DialAddr(ctx, resolvedAddr, tlsCfgCopy, cfg)
}

// RoundTrip implements http.RoundTripper
func (t *HTTP3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Track request count BEFORE making request
	t.mu.Lock()
	t.requestCount++
	reqNum := t.requestCount
	dialsBefore := t.dialCount
	t.mu.Unlock()

	// Add preset headers
	for key, value := range t.preset.Headers {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
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
	return t.transport.Close()
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
