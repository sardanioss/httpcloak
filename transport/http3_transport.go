package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

func init() {
	// Suppress quic-go UDP buffer size warning
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "1")
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

	// Create QUIC config with connection reuse settings
	t.quicConfig = &quic.Config{
		MaxIdleTimeout:        90 * time.Second,
		KeepAlivePeriod:       30 * time.Second,
		MaxIncomingStreams:    100,
		MaxIncomingUniStreams: 100,
		Allow0RTT:             true,
		// Use smaller initial packet size to work within default buffer limits
		// This avoids the "failed to sufficiently increase receive buffer size" warning
		InitialPacketSize:       1200,
		DisablePathMTUDiscovery: false, // Still allow PMTUD for optimal performance
	}

	// Create HTTP/3 transport with custom dial for DNS caching
	// http3.Transport handles connection pooling internally
	t.transport = &http3.Transport{
		TLSClientConfig: t.tlsConfig,
		QUICConfig:      t.quicConfig,
		Dial:            t.dialQUIC, // Just for DNS resolution
	}

	return t
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
