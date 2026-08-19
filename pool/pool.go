package pool

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"io"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/transport"
	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
	tls "github.com/sardanioss/utls"
	utls "github.com/sardanioss/utls"
)

var (
	ErrPoolClosed    = errors.New("connection pool is closed")
	ErrNoConnections = errors.New("no available connections")
	// ErrConnRetired means the connection was retired between GetConn and
	// RoundTrip, so the request was never written. Callers may safely retry it
	// on a fresh connection: nothing was sent, so the request body is untouched.
	// (Diagnosis and this sentinel come from PR #84.)
	ErrConnRetired = errors.New("connection retired before request started")
)

// Conn represents a persistent connection
type Conn struct {
	Host       string
	RemoteAddr net.Addr
	TLSConn    *utls.UConn
	HTTP2Conn  *http2.ClientConn
	CreatedAt  time.Time
	// LastUsedAt and UseCount are written under mu for the whole life of the
	// connection, so once the pool owns it read them through IdleTime() and
	// Uses() rather than off the struct.
	LastUsedAt time.Time
	UseCount   int64
	mu         sync.Mutex
	closed     bool

	// inFlight counts requests still using this connection, INCLUDING the time
	// their response bodies spend streaming. closeRequested defers an eviction
	// until that count reaches zero. Both are unexported and only ever touched
	// under mu (issue #83).
	inFlight       int32
	closeRequested bool

	// lastProgress is the unix-nano timestamp of the most recent body read.
	// Deliberately outside the mutex because it is touched on every Read. Only
	// meaningful while inFlight > 0, where it separates a slow-but-live download
	// from a body the caller walked away from without closing.
	lastProgress atomic.Int64
}

// release marks one request as finished with the connection. If a close was
// deferred because requests were still streaming, it happens here.
//
// This is the ONLY place inFlight is decremented. A bare decrement anywhere
// else would skip the deferred close and strand the socket; there is a source
// scan in the tests enforcing that.
func (c *Conn) release() {
	c.mu.Lock()
	c.inFlight--
	c.LastUsedAt = time.Now()
	shouldClose := c.closeRequested && c.inFlight <= 0
	c.mu.Unlock()

	if shouldClose {
		c.Close()
	}
}

// requestClose closes the connection now if nothing is using it, otherwise
// defers the close until the last in-flight response body is done. Evicting a
// connection from the pool must never yank the socket out from under a response
// that is still streaming (issue #83), which is what surfaced to callers as
// "use of closed network connection" mid-download.
func (c *Conn) requestClose() {
	c.mu.Lock()
	if c.inFlight > 0 {
		c.closeRequested = true
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	c.Close()
}

// RoundTrip sends a request on this connection and keeps the connection marked
// in-use for the lifetime of the response body.
//
// The acquire/release pair lives here rather than in GetConn because the pool
// hands the *Conn across a package boundary: a caller may take a connection and
// never send on it, so incrementing at acquisition would pin the socket. Doing
// it here keeps the two halves symmetric and impossible to forget at a call
// site.
//
// UseCount is deliberately NOT bumped here. It is still incremented only by
// MarkUsed() at acquisition, so the `UseCount == 1` timing branches in
// client/ keep firing exactly when they used to.
func (c *Conn) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	// Retired or dead: reject BEFORE anything is written, so the caller can
	// retry on a fresh connection with the request body still intact.
	if c.closed || c.closeRequested || c.HTTP2Conn == nil {
		c.mu.Unlock()
		return nil, ErrConnRetired
	}
	c.inFlight++
	c.LastUsedAt = time.Now()
	h2Conn := c.HTTP2Conn
	c.mu.Unlock()
	c.lastProgress.Store(time.Now().UnixNano())

	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		// release(), never a bare decrement: if this conn was evicted while the
		// request was in flight, its close was deferred and only release() fires
		// it once the count reaches zero.
		c.release()
		return nil, err
	}

	// Stay marked in-use until the caller finishes with the body. RoundTrip
	// returning only means the response headers arrived; the body may stream for
	// minutes, and releasing here made the pool think the connection was idle.
	c.mu.Lock()
	c.LastUsedAt = time.Now()
	c.mu.Unlock()
	c.lastProgress.Store(time.Now().UnixNano())

	if resp.Body == nil {
		c.release()
	} else {
		resp.Body = &connBodyGuard{ReadCloser: resp.Body, conn: c}
	}
	return resp, nil
}

// connBodyGuard keeps a pooled connection marked in-use for as long as the
// caller is reading the response body, and records read progress so an
// abandoned body can still be told apart from a live one.
type connBodyGuard struct {
	io.ReadCloser
	conn *Conn
	once sync.Once
}

func (g *connBodyGuard) Read(p []byte) (int, error) {
	n, err := g.ReadCloser.Read(p)
	if n > 0 {
		g.conn.lastProgress.Store(time.Now().UnixNano())
	}
	if err != nil {
		// io.EOF included: the transfer is over, stop holding the connection
		// even if the caller forgets to Close.
		g.release()
	}
	return n, err
}

func (g *connBodyGuard) Close() error {
	err := g.ReadCloser.Close()
	g.release()
	return err
}

func (g *connBodyGuard) release() {
	g.once.Do(g.conn.release)
}

// IsHealthy checks if the connection is still usable
func (c *Conn) IsHealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return false
	}

	// Check if HTTP/2 connection is usable
	if c.HTTP2Conn != nil {
		return c.HTTP2Conn.CanTakeNewRequest()
	}

	return false
}

// Age returns how long the connection has been open
func (c *Conn) Age() time.Duration {
	return time.Since(c.CreatedAt)
}

// IdleTime returns how long since the connection was last used
func (c *Conn) IdleTime() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.LastUsedAt)
}

// Uses returns how many times the pool has handed this connection out.
//
// MarkUsed() writes UseCount under c.mu on every acquisition, so anything on
// another goroutine has to read it through here. Two requests multiplexing on
// the same HTTP/2 connection otherwise race outright: GetConn calls MarkUsed on
// the connection it returns, so one caller is inside that write while the other
// reads the field bare.
func (c *Conn) Uses() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.UseCount
}

// MarkUsed updates the last used timestamp
func (c *Conn) MarkUsed() {
	c.mu.Lock()
	c.LastUsedAt = time.Now()
	c.UseCount++
	c.mu.Unlock()
}

// Close closes the connection
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	var errs []error
	if c.HTTP2Conn != nil {
		// HTTP/2 connection close is handled by the underlying TLS conn
	}
	if c.TLSConn != nil {
		if err := c.TLSConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// HostPool manages connections to a single host
type HostPool struct {
	host        string // Connection host (for DNS resolution - may be connectTo target)
	sniHost     string // SNI host (for TLS ServerName - always the original request host)
	port        string
	preset      *fingerprint.Preset
	dnsCache    *dns.Cache
	connections []*Conn
	mu          sync.Mutex

	// TLS session cache for PSK/session resumption
	// Chrome reuses sessions - this makes subsequent connections look like real browser
	sessionCache utls.ClientSessionCache

	// Cached ClientHelloSpec - used to check if PSK spec is available
	// Note: Do not reuse directly - generate fresh spec per connection to avoid race
	cachedSpec    *utls.ClientHelloSpec
	cachedPSKSpec *utls.ClientHelloSpec

	// Shuffle seed for generating fresh specs per connection
	// utls's ApplyPreset mutates specs, so each connection needs its own copy
	shuffleSeed int64

	// Configuration
	maxConns    int
	maxIdleTime time.Duration
	maxConnAge  time.Duration
	// abandonedBodyTimeout bounds how long a connection may be held by a
	// response body that has produced no bytes. Without it, a caller that never
	// closes a body would pin the socket forever.
	abandonedBodyTimeout time.Duration
	connectTimeout       time.Duration
	insecureSkipVerify   bool
	tlsVerify            *transport.TLSVerify
	proxyURL             string
	localAddr            string // Local IP to bind outgoing connections

	// ECH (Encrypted Client Hello) configuration
	echConfig       []byte // Custom ECH configuration
	echConfigDomain string // Domain to fetch ECH config from
}

// NewHostPool creates a new pool for a specific host
// Note: This generates its own shuffled specs. For consistent session fingerprinting,
// use Manager.GetPool() instead which shares cached specs across all hosts.
func NewHostPool(host, port string, preset *fingerprint.Preset, dnsCache *dns.Cache) *HostPool {
	// Generate shuffle seed for standalone usage
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	// Generate specs for standalone usage (backward compatibility)
	var cachedSpec, cachedPSKSpec *utls.ClientHelloSpec
	if preset.JA3 != "" {
		if spec, err := fingerprint.ParseJA3(preset.JA3, preset.JA3Extras); err == nil {
			cachedSpec = spec
		}
	} else if spec, err := tcpClientHelloSpec(preset, preset.ClientHelloID, shuffleSeed); err == nil {
		cachedSpec = spec
	}
	if preset.JA3 == "" && preset.PSKClientHelloID.Client != "" {
		if spec, err := tcpClientHelloSpec(preset, preset.PSKClientHelloID, shuffleSeed); err == nil {
			cachedPSKSpec = spec
		}
	}
	return NewHostPoolWithConfig(host, "", port, preset, dnsCache, false, "", cachedSpec, cachedPSKSpec, shuffleSeed, nil)
}

// NewHostPoolWithConfig creates a pool with TLS and proxy configuration
// host is the connection host (for DNS resolution, may be connectTo target)
// sniHost is the TLS ServerName host (original request host, used for SNI)
// If sniHost is empty, host is used for both DNS and SNI
func NewHostPoolWithConfig(host, sniHost, port string, preset *fingerprint.Preset, dnsCache *dns.Cache, insecureSkipVerify bool, proxyURL string, cachedSpec, cachedPSKSpec *utls.ClientHelloSpec, shuffleSeed int64, sessionCache utls.ClientSessionCache) *HostPool {
	// Use provided session cache or create a new one for backward compatibility
	if sessionCache == nil {
		sessionCache = utls.NewLRUClientSessionCache(32)
	}
	if sniHost == "" {
		sniHost = host
	}
	pool := &HostPool{
		host:                 host,
		sniHost:              sniHost,
		port:                 port,
		preset:               preset,
		dnsCache:             dnsCache,
		connections:          make([]*Conn, 0),
		sessionCache:         sessionCache, // Use shared session cache for persistence
		maxConns:             0,            // 0 = unlimited connections
		maxIdleTime:          90 * time.Second,
		maxConnAge:           5 * time.Minute,
		abandonedBodyTimeout: 10 * time.Minute,
		connectTimeout:       30 * time.Second,
		insecureSkipVerify:   insecureSkipVerify,
		proxyURL:             proxyURL,
		cachedSpec:           cachedSpec,    // Reference spec (for availability check)
		cachedPSKSpec:        cachedPSKSpec, // Reference PSK spec (for availability check)
		shuffleSeed:          shuffleSeed,   // Seed for generating fresh specs per connection
	}

	return pool
}

// SetMaxConns sets the maximum connections for this pool (0 = unlimited)
func (p *HostPool) SetMaxConns(max int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxConns = max
}

// SetECHConfig sets a custom ECH configuration for this pool
func (p *HostPool) SetECHConfig(echConfig []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.echConfig = echConfig
}

// SetECHConfigDomain sets a domain to fetch ECH config from
func (p *HostPool) SetECHConfigDomain(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.echConfigDomain = domain
}

// SetLocalAddr sets the local IP address for outgoing connections
func (p *HostPool) SetLocalAddr(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.localAddr = addr
}

// isConnUsable reports whether a connection may be handed out for a NEW request.
//
// Deliberately separate from isConnDestroyable: "too old to start another
// request on" and "safe to close" are different questions, and conflating them
// is what let the reaper close connections that were still streaming a response
// (issue #83).
//
// Field snapshot under c.mu, evaluation outside it: callers already hold p.mu
// (p.mu -> c.mu is the established order), and CanTakeNewRequest() must not run
// with c.mu held.
func (p *HostPool) isConnUsable(conn *Conn) bool {
	conn.mu.Lock()
	closed := conn.closed
	retired := conn.closeRequested
	createdAt := conn.CreatedAt
	lastUsedAt := conn.LastUsedAt
	inFlight := conn.inFlight
	h2Conn := conn.HTTP2Conn
	conn.mu.Unlock()

	if closed || retired {
		return false
	}
	if time.Since(createdAt) > p.maxConnAge {
		return false
	}
	// Idle only counts when nothing is on the wire. Without this guard a long
	// download (> maxIdleTime) looked idle the moment its headers arrived.
	if inFlight == 0 && time.Since(lastUsedAt) > p.maxIdleTime {
		return false
	}
	if h2Conn == nil {
		return false
	}
	return h2Conn.CanTakeNewRequest()
}

// isConnDestroyable reports whether a connection can be closed right now.
//
// A connection with requests still on it is never destroyable, however old or
// idle-looking, with one exception: if its response body has made no progress
// for abandonedBodyTimeout the caller has clearly walked away without closing
// it, and holding the socket forever would be a leak.
func (p *HostPool) isConnDestroyable(conn *Conn) bool {
	conn.mu.Lock()
	closed := conn.closed
	inFlight := conn.inFlight
	createdAt := conn.CreatedAt
	lastUsedAt := conn.LastUsedAt
	h2Conn := conn.HTTP2Conn
	conn.mu.Unlock()

	// Already closed: there is no fd left to protect, so sweep the shell out of
	// the slice instead of pinning a dead entry for the abandoned-body window.
	if closed {
		return true
	}

	if inFlight > 0 {
		last := lastUsedAt
		if progress := conn.lastProgress.Load(); progress > 0 {
			if t := time.Unix(0, progress); t.After(last) {
				last = t
			}
		}
		return time.Since(last) > p.abandonedBodyTimeout
	}

	if h2Conn == nil {
		return true
	}
	if time.Since(createdAt) > p.maxConnAge {
		return true
	}
	return time.Since(lastUsedAt) > p.maxIdleTime
}

// isRetired reports whether a close has already been requested on this
// connection, so it is draining and will never serve another request.
func (c *Conn) isRetired() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeRequested
}

// isConnRetirable reports whether a connection is PERMANENTLY unusable and
// should therefore be retired.
//
// This is deliberately NOT the negation of isConnUsable. isConnUsable ends with
// h2Conn.CanTakeNewRequest(), which is a TRANSIENT signal: a perfectly healthy
// connection sitting at the server's SETTINGS_MAX_CONCURRENT_STREAMS reports
// false, and reports true again the moment one of those streams finishes.
// Retiring on it would be a one-way door, because closeRequested is never
// cleared - a single burst of concurrent requests would permanently throw away
// a warm connection and force a fresh TLS handshake for the next one.
//
// Only conditions a connection can never recover from belong here.
func (p *HostPool) isConnRetirable(conn *Conn) bool {
	conn.mu.Lock()
	closed := conn.closed
	retired := conn.closeRequested
	createdAt := conn.CreatedAt
	h2Conn := conn.HTTP2Conn
	conn.mu.Unlock()

	if closed || retired {
		return false // already handled; nothing further to request
	}
	if h2Conn == nil {
		return true
	}
	return time.Since(createdAt) > p.maxConnAge
}

// GetConn returns an available connection or creates a new one
func (p *HostPool) GetConn(ctx context.Context) (*Conn, error) {
	p.mu.Lock()

	// First, try to find an existing healthy connection
	for i, conn := range p.connections {
		if p.isConnUsable(conn) {
			// Move to end (LRU)
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			p.connections = append(p.connections, conn)
			p.mu.Unlock()
			conn.MarkUsed()
			return conn, nil
		}
	}

	// Clean up connections we can no longer use. A conn that is unusable but
	// still streaming is retired, not closed, and STAYS TRACKED in
	// p.connections: dropping it here would hide it from Stats(), from a later
	// CloseIdle() pass (so the abandoned-body backstop could never fire) and
	// from HostPool.Close(), leaking the fd past client.Close().
	kept := make([]*Conn, 0, len(p.connections))
	serving := 0
	for _, conn := range p.connections {
		if p.isConnDestroyable(conn) {
			go conn.Close()
			continue
		}
		if p.isConnRetirable(conn) {
			go conn.requestClose()
		} else if !conn.isRetired() {
			// Counts against the cap even though the loop above did not hand it
			// out. Reaching this sweep means nothing was usable RIGHT NOW, but a
			// connection that is merely at its stream-concurrency limit will
			// serve again shortly, so it still occupies a slot. Counting only
			// what was usable would make `serving` structurally zero here and
			// the cap below unreachable.
			serving++
		}
		kept = append(kept, conn)
	}
	p.connections = kept

	// Check if we can create a new connection (0 = unlimited).
	//
	// The cap counts connections that can still serve a request, now or shortly.
	// A retired connection draining its last response body occupies a slot it
	// can never serve again, so counting it would answer ErrNoConnections for
	// the whole download instead of opening a replacement. The socket count can
	// therefore sit above maxConns while a body drains, which is the same trade
	// the transport pool makes.
	if p.maxConns > 0 && serving >= p.maxConns {
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

// createConn creates a new connection to the host
// Implements Happy Eyeballs (RFC 8305) for IPv6/IPv4 connection racing
func (p *HostPool) createConn(ctx context.Context) (*Conn, error) {
	var rawConn net.Conn
	var err error

	if p.proxyURL != "" {
		// Connect through proxy
		rawConn, err = p.dialThroughProxy(ctx)
		if err != nil {
			return nil, fmt.Errorf("proxy connect failed: %w", err)
		}
	} else {
		// Direct connection - resolve DNS and use Happy Eyeballs
		ipv6, ipv4, err := p.dnsCache.ResolveIPv6First(ctx, p.host)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}

		// Order IPs based on preference
		var preferredIPs, fallbackIPs []net.IP
		if p.dnsCache.PreferIPv4() {
			preferredIPs = ipv4
			fallbackIPs = ipv6
		} else {
			preferredIPs = ipv6
			fallbackIPs = ipv4
		}

		// Use Happy Eyeballs to establish connection
		rawConn, err = p.dialHappyEyeballs(ctx, preferredIPs, fallbackIPs)
		if err != nil {
			return nil, fmt.Errorf("TCP connect failed: %w", err)
		}
	}

	// Fetch ECH config if needed
	var echConfigList []byte
	if len(p.echConfig) > 0 {
		echConfigList = p.echConfig
	} else if p.echConfigDomain != "" {
		// Fetch ECH config from DNS
		echConfigList, err = dns.FetchECHConfigs(ctx, p.echConfigDomain)
		if err != nil {
			// ECH fetch failed - continue without ECH (SNI will be visible)
			echConfigList = nil
		}
	}

	// Determine MinVersion based on ECH usage
	// ECH requires TLS 1.3, so set MinVersion accordingly
	minVersion := uint16(tls.VersionTLS12)
	if len(echConfigList) > 0 {
		minVersion = tls.VersionTLS13
	}

	// Get key log writer from global setting
	var keyLogWriter io.Writer = transport.GetKeyLogWriter()

	// Wrap with uTLS for fingerprinting
	// Enable session tickets for PSK resumption (Chrome does this)
	// Use sniHost (original request host) for TLS ServerName, not p.host (which may be connectTo target)
	// Only set session cache on tlsConfig when PSK is available (via cached PSK spec
	// or JA3 with extension 41). Prevents the TLS library from attempting session
	// resumption on specs without PSK extension.
	hasPSK := p.cachedPSKSpec != nil || (p.preset.JA3 != "" && fingerprint.JA3HasExtension(p.preset.JA3, "41"))
	var sessionCache utls.ClientSessionCache
	if hasPSK {
		sessionCache = p.sessionCache
	}

	tlsConfig := &utls.Config{
		ServerName:                         p.sniHost,
		InsecureSkipVerify:                 p.insecureSkipVerify,
		MinVersion:                         minVersion,
		MaxVersion:                         tls.VersionTLS13,
		SessionTicketsDisabled:             false,         // Enable session tickets
		ClientSessionCache:                 sessionCache,  // Only set when PSK is available
		OmitEmptyPsk:                       true,          // Chrome doesn't send empty PSK on first connection
		PreferSkipResumptionOnNilExtension: true,          // Safety net: skip resumption if spec lacks PSK extension
		EncryptedClientHelloConfigList:     echConfigList, // ECH configuration (if available)
		KeyLogWriter:                       keyLogWriter,
	}
	p.tlsVerify.Apply(tlsConfig)

	// Generate fresh spec for this connection to avoid race condition
	// utls's ApplyPreset mutates the spec (clears KeyShares.Data, etc.), so each
	// connection needs its own copy. Use same shuffleSeed for consistent ordering.
	var specToUse *utls.ClientHelloSpec
	var tlsConn *utls.UConn

	// JA3 preset: parse fresh per connection (ApplyPreset mutates the spec)
	if p.preset.JA3 != "" {
		spec, err := fingerprint.ParseJA3(p.preset.JA3, p.preset.JA3Extras)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to parse JA3: %w", err)
		}
		specToUse = spec
	} else if p.cachedPSKSpec != nil && p.preset.PSKClientHelloID.Client != "" {
		// Prefer PSK spec when available - Chrome always includes PSK extension structure
		// Generate fresh PSK spec for this connection
		if spec, err := tcpClientHelloSpec(p.preset, p.preset.PSKClientHelloID, p.shuffleSeed); err == nil {
			specToUse = spec
		}
	}
	if specToUse == nil && p.cachedSpec != nil && p.preset.JA3 == "" {
		// Generate fresh regular spec
		if spec, err := tcpClientHelloSpec(p.preset, p.preset.ClientHelloID, p.shuffleSeed); err == nil {
			specToUse = spec
		}
	}

	// Create UClient with HelloCustom and apply the fresh spec
	if specToUse != nil {
		tlsConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
		if err := tlsConn.ApplyPreset(specToUse); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to apply TLS preset: %w", err)
		}
	} else {
		// Fallback to ClientHelloID if spec generation failed - prefer PSK variant
		clientHelloID := p.preset.ClientHelloID
		if p.preset.PSKClientHelloID.Client != "" {
			clientHelloID = p.preset.PSKClientHelloID
		}
		tlsConn = utls.UClient(rawConn, tlsConfig, clientHelloID)
	}

	// Enable session cache if PSK is available (either via cached PSK spec or JA3 with extension 41)
	if p.cachedPSKSpec != nil || (p.preset.JA3 != "" && fingerprint.JA3HasExtension(p.preset.JA3, "41")) {
		tlsConn.SetSessionCache(p.sessionCache)
	}

	// Perform TLS handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Build HTTP/2 settings from preset
	settings := p.preset.HTTP2Settings

	// Create HTTP/2 transport with native fingerprinting (no frame interception needed)
	h2Transport := &http2.Transport{
		AllowHTTP:                  false,
		DisableCompression:         false,
		StrictMaxConcurrentStreams: false,
		MaxHeaderListSize:          settings.MaxHeaderListSize,
		MaxReadFrameSize:           settings.MaxFrameSize,
		MaxDecoderHeaderTableSize:  settings.HeaderTableSize,
		MaxEncoderHeaderTableSize:  settings.HeaderTableSize,

		// Native fingerprinting via sardanioss/net
		ConnectionFlow: settings.ConnectionWindowUpdate,
		Settings:       buildHTTP2Settings(settings),
		SettingsOrder:  buildHTTP2SettingsOrder(settings, p.preset),
		PseudoHeaderOrder: func() []string {
			// Preset H2Config > Safari/Chrome heuristic
			if order := p.preset.H2PseudoHeaderOrder(); order != nil {
				return order
			}
			if settings.NoRFC7540Priorities {
				return []string{":method", ":scheme", ":path", ":authority"} // Safari order (m,s,p,a)
			}
			return []string{":method", ":authority", ":scheme", ":path"} // Chrome order (m,a,s,p)
		}(),
		HeaderPriority: func() *http2.PriorityParam {
			// Chrome 120+ uses RFC 9218 extensible priorities (priority: header)
			// instead of RFC 7540 PRIORITY frames. StreamWeight=0 means no PRIORITY data.
			if settings.StreamWeight > 0 {
				return &http2.PriorityParam{
					Weight:    uint8(settings.StreamWeight - 1), // Wire format is weight-1
					Exclusive: settings.StreamExclusive,
					StreamDep: 0,
				}
			}
			return nil
		}(),
		HeaderOrder:          p.preset.H2HeaderOrder(),
		UserAgent:            p.preset.UserAgent,
		StreamPriorityMode:   resolveStreamPriorityMode(p.preset.H2StreamPriorityMode()),
		HPACKIndexingPolicy:  resolveHPACKIndexingPolicy(p.preset.H2HPACKIndexingPolicy()),
		HPACKRepresentations: hpackRepresentations(p.preset.H2HPACKRepresentation()),
		HPACKNeverIndex:      p.preset.H2HPACKNeverIndex(),
		DisableCookieSplit:   p.preset.H2DisableCookieSplit(),
	}

	h2Conn, err := h2Transport.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("HTTP/2 setup failed: %w", err)
	}

	conn := &Conn{
		Host:       p.host,
		RemoteAddr: rawConn.RemoteAddr(),
		TLSConn:    tlsConn,
		HTTP2Conn:  h2Conn,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
		UseCount:   0,
	}

	return conn, nil
}

// dialHappyEyeballs implements RFC 8305 Happy Eyeballs v2
// Starts preferred IPs first, waits 250ms, then starts fallback IPs
func (p *HostPool) dialHappyEyeballs(ctx context.Context, preferredIPs, fallbackIPs []net.IP) (net.Conn, error) {
	// Filter IPs by local address family if set
	if p.localAddr != "" {
		localIP := net.ParseIP(p.localAddr)
		if localIP != nil {
			isLocalIPv6 := localIP.To4() == nil
			filterByFamily := func(ips []net.IP) []net.IP {
				var filtered []net.IP
				for _, ip := range ips {
					isIPv6 := ip.To4() == nil
					if isIPv6 == isLocalIPv6 {
						filtered = append(filtered, ip)
					}
				}
				return filtered
			}
			preferredIPs = filterByFamily(preferredIPs)
			fallbackIPs = filterByFamily(fallbackIPs)
		}
	}

	totalIPs := len(preferredIPs) + len(fallbackIPs)
	if totalIPs == 0 {
		return nil, fmt.Errorf("no IP addresses available")
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}

	dialCtx, cancel := context.WithCancel(ctx)
	resultCh := make(chan dialResult, totalIPs)
	perAddrTimeout := 5 * time.Second
	started := 0

	// Helper to start a dial
	startDial := func(ip net.IP) {
		go func(ip net.IP) {
			network := "tcp4"
			if ip.To4() == nil {
				network = "tcp6"
			}
			addr := net.JoinHostPort(ip.String(), p.port)
			dialer := &net.Dialer{Timeout: perAddrTimeout}
			transport.SetDialerControl(dialer, &p.preset.TCPFingerprint)
			if p.localAddr != "" {
				dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(p.localAddr)}
			}
			conn, err := dialer.DialContext(dialCtx, network, addr)
			select {
			case resultCh <- dialResult{conn: conn, err: err}:
			case <-dialCtx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}(ip)
	}

	// Start preferred IPs (IPv6 by default) in parallel
	for _, ip := range preferredIPs {
		startDial(ip)
		started++
	}

	// RFC 8305: Wait 250ms before starting fallback IPs
	if len(fallbackIPs) > 0 {
		select {
		case result := <-resultCh:
			if result.conn != nil {
				cancel()
				return result.conn, nil
			}
			started-- // One failed, adjust count
		case <-time.After(250 * time.Millisecond):
			// Preferred IPs haven't succeeded yet, start fallback
		case <-ctx.Done():
			cancel()
			return nil, ctx.Err()
		}

		// Start fallback IPs in parallel
		for _, ip := range fallbackIPs {
			startDial(ip)
			started++
		}
	}

	// Wait for first success or all failures
	var lastErr error
	for i := 0; i < started; i++ {
		select {
		case result := <-resultCh:
			if result.conn != nil {
				cancel()
				return result.conn, nil
			}
			lastErr = result.err
		case <-ctx.Done():
			cancel()
			return nil, ctx.Err()
		}
	}

	cancel()
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("all connection attempts failed")
}

// dialThroughProxy connects to the target host through a proxy
// Supports HTTP/HTTPS (CONNECT) and SOCKS5 proxies
func (p *HostPool) dialThroughProxy(ctx context.Context) (net.Conn, error) {
	proxyURL, err := parseProxyURL(p.proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	switch proxyURL.Scheme {
	case "http", "https":
		return p.dialHTTPProxy(ctx, proxyURL)
	case "socks5", "socks5h":
		return p.dialSOCKS5Proxy(ctx, proxyURL)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", proxyURL.Scheme)
	}
}

// parseProxyURL parses the proxy URL
func parseProxyURL(proxyURL string) (*proxyConfig, error) {
	// Simple parser for proxy URLs
	// Format: scheme://[user:pass@]host:port
	if !hasScheme(proxyURL) {
		proxyURL = "http://" + proxyURL
	}

	scheme := "http"
	rest := proxyURL

	if idx := indexOf(proxyURL, "://"); idx != -1 {
		scheme = proxyURL[:idx]
		rest = proxyURL[idx+3:]
	}

	var username, password string
	if idx := indexOf(rest, "@"); idx != -1 {
		userInfo := rest[:idx]
		rest = rest[idx+1:]
		if pwIdx := indexOf(userInfo, ":"); pwIdx != -1 {
			username = userInfo[:pwIdx]
			password = userInfo[pwIdx+1:]
		} else {
			username = userInfo
		}
	}

	host := rest
	port := ""
	if idx := lastIndexOf(rest, ":"); idx != -1 {
		host = rest[:idx]
		port = rest[idx+1:]
	}

	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		}
	}

	return &proxyConfig{
		Scheme:   scheme,
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
	}, nil
}

// proxyConfig holds parsed proxy configuration
type proxyConfig struct {
	Scheme   string
	Host     string
	Port     string
	Username string
	Password string
}

// Addr returns the proxy address as host:port
func (p *proxyConfig) Addr() string {
	return net.JoinHostPort(p.Host, p.Port)
}

// hasScheme checks if URL has a scheme
func hasScheme(url string) bool {
	return indexOf(url, "://") != -1
}

// indexOf returns index of substr in s, or -1 if not found
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// lastIndexOf returns last index of substr in s, or -1 if not found
func lastIndexOf(s, substr string) int {
	for i := len(s) - len(substr); i >= 0; i-- {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// dialHTTPProxy establishes a connection through an HTTP CONNECT proxy
func (p *HostPool) dialHTTPProxy(ctx context.Context, proxy *proxyConfig) (net.Conn, error) {
	// Pre-resolve proxy hostname using CGO-compatible resolver
	// Required for shared library usage where Go's pure-Go resolver doesn't work
	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxy.Host, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxy.Host)
	}

	dialer := &net.Dialer{Timeout: p.connectTimeout}
	transport.SetDialerControl(dialer, &p.preset.TCPFingerprint)
	if p.localAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(p.localAddr)}
	}
	proxyAddr := net.JoinHostPort(proxyIPs[0], proxy.Port)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}
	clearDeadline, err := armProxyHandshakeDeadline(ctx, conn, p.connectTimeout)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set proxy handshake deadline: %w", err)
	}
	defer clearDeadline()

	// Send CONNECT request
	targetAddr := net.JoinHostPort(p.host, p.port)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	// Add proxy authentication if provided
	if proxy.Username != "" {
		auth := proxy.Username + ":" + proxy.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(auth))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encoded)
	}

	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}

	response := string(buf[:n])
	if !isHTTP200(response) {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", getFirstLine(response))
	}

	return conn, nil
}

// dialSOCKS5Proxy establishes a connection through a SOCKS5 proxy
func (p *HostPool) dialSOCKS5Proxy(ctx context.Context, proxy *proxyConfig) (net.Conn, error) {
	// Pre-resolve proxy hostname using CGO-compatible resolver
	// Required for shared library usage where Go's pure-Go resolver doesn't work
	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxy.Host, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxy.Host)
	}

	dialer := &net.Dialer{Timeout: p.connectTimeout}
	transport.SetDialerControl(dialer, &p.preset.TCPFingerprint)
	if p.localAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(p.localAddr)}
	}
	proxyAddr := net.JoinHostPort(proxyIPs[0], proxy.Port)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
	}
	clearDeadline, err := armProxyHandshakeDeadline(ctx, conn, p.connectTimeout)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set SOCKS5 handshake deadline: %w", err)
	}
	defer clearDeadline()

	// SOCKS5 handshake
	// Version 5, 1 auth method (no auth or username/password)
	var authMethods []byte
	if proxy.Username != "" {
		authMethods = []byte{0x05, 0x02, 0x00, 0x02} // No auth and username/password
	} else {
		authMethods = []byte{0x05, 0x01, 0x00} // No auth only
	}

	if _, err := conn.Write(authMethods); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
	}

	// Read server's chosen auth method
	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 auth response failed: %w", err)
	}

	if resp[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: invalid version: %d", resp[0])
	}

	// Handle authentication
	switch resp[1] {
	case 0x00:
		// No authentication required
	case 0x02:
		// Username/password authentication
		if err := p.socks5Auth(conn, proxy); err != nil {
			conn.Close()
			return nil, err
		}
	case 0xFF:
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: no acceptable auth methods")
	default:
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: unsupported auth method: %d", resp[1])
	}

	// Send CONNECT request
	// Version 5, CMD connect (1), reserved (0), address type
	targetPort, _ := parsePort(p.port)
	var connectReq []byte

	// Try to parse as IP address first
	if ip := net.ParseIP(p.host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			connectReq = append([]byte{0x05, 0x01, 0x00, 0x01}, ip4...)
		} else {
			// IPv6
			connectReq = append([]byte{0x05, 0x01, 0x00, 0x04}, ip...)
		}
	} else {
		// Domain name
		connectReq = []byte{0x05, 0x01, 0x00, 0x03, byte(len(p.host))}
		connectReq = append(connectReq, []byte(p.host)...)
	}

	// Append port (big endian)
	connectReq = append(connectReq, byte(targetPort>>8), byte(targetPort))

	if _, err := conn.Write(connectReq); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect request failed: %w", err)
	}

	// Read connect response (minimum 10 bytes for IPv4)
	respBuf := make([]byte, 10)
	if _, err := conn.Read(respBuf); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect response failed: %w", err)
	}

	if respBuf[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: invalid version in response")
	}

	if respBuf[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed with code: %d", respBuf[1])
	}

	return conn, nil
}

// socks5Auth performs SOCKS5 username/password authentication
func (p *HostPool) socks5Auth(conn net.Conn, proxy *proxyConfig) error {
	// Version 1, username length, username, password length, password
	authReq := []byte{0x01, byte(len(proxy.Username))}
	authReq = append(authReq, []byte(proxy.Username)...)
	authReq = append(authReq, byte(len(proxy.Password)))
	authReq = append(authReq, []byte(proxy.Password)...)

	if _, err := conn.Write(authReq); err != nil {
		return fmt.Errorf("SOCKS5 auth request failed: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return fmt.Errorf("SOCKS5 auth response failed: %w", err)
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 authentication failed")
	}

	return nil
}

// parsePort parses port string to int
func parsePort(port string) (int, error) {
	var p int
	for _, c := range port {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port: %s", port)
		}
		p = p*10 + int(c-'0')
	}
	return p, nil
}

// isHTTP200 checks if response starts with HTTP/1.x 200
func isHTTP200(response string) bool {
	return len(response) >= 12 && response[9] == '2' && response[10] == '0' && response[11] == '0'
}

// getFirstLine returns the first line of a string
func getFirstLine(s string) string {
	for i, c := range s {
		if c == '\r' || c == '\n' {
			return s[:i]
		}
	}
	return s
}

// CloseIdle closes connections that have been idle too long.
//
// Note the predicate: destroyable, NOT "not usable". A connection that is
// merely too old or too idle to take a NEW request may still be streaming a
// response body, and closing it there is exactly the issue #83 failure
// ("use of closed network connection" mid-download). Such a connection is
// retired instead and stays tracked until its last body finishes, or until the
// abandoned-body bound inside isConnDestroyable reclaims it.
func (p *HostPool) CloseIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()

	active := make([]*Conn, 0, len(p.connections))
	for _, conn := range p.connections {
		if p.isConnDestroyable(conn) {
			go conn.Close()
			continue
		}
		// Retire only what can never recover. A connection that is momentarily
		// at its stream-concurrency limit must survive this pass; see
		// isConnRetirable.
		if p.isConnRetirable(conn) {
			go conn.requestClose()
		}
		active = append(active, conn)
	}
	p.connections = active
}

// Close closes all connections in the pool
func (p *HostPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		go conn.Close()
	}
	p.connections = nil
}

// Stats returns pool statistics
func (p *HostPool) Stats() (total int, healthy int, totalRequests int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		total++
		if conn.IsHealthy() {
			healthy++
		}
		totalRequests += conn.Uses()
	}
	return
}

// Manager manages connection pools for multiple hosts
type Manager struct {
	pools    map[string]*HostPool
	mu       sync.RWMutex
	dnsCache *dns.Cache
	preset   *fingerprint.Preset
	closed   bool

	// Configuration
	maxConnsPerHost    int                  // 0 = unlimited
	proxyURL           string               // Proxy URL (optional)
	insecureSkipVerify bool                 // Skip TLS verification
	tlsVerify          *transport.TLSVerify // Caller-supplied cert verification hooks
	connectTo          map[string]string    // Domain fronting: request host -> connect host
	echConfig          []byte               // Custom ECH configuration
	echConfigDomain    string               // Domain to fetch ECH config from

	// Cached TLS specs - shared across all HostPools for consistent fingerprint
	// Chrome shuffles extension order once per session, not per connection
	cachedSpec    *utls.ClientHelloSpec
	cachedPSKSpec *utls.ClientHelloSpec
	shuffleSeed   int64 // Seed used for extension shuffling

	// Shared session cache for TLS session resumption across all pools
	// This allows session persistence to work across Save/Load
	sessionCache utls.ClientSessionCache

	// Background cleanup
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// NewManager creates a new connection pool manager
func NewManager(preset *fingerprint.Preset) *Manager {
	return NewManagerWithTLSConfig(preset, false)
}

// NewManagerWithTLSConfig creates a manager with TLS configuration
func NewManagerWithTLSConfig(preset *fingerprint.Preset, insecureSkipVerify bool) *Manager {
	// Generate random seed for extension shuffling
	// This seed is used for all connections in this manager (session)
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	m := &Manager{
		pools:              make(map[string]*HostPool),
		dnsCache:           dns.NewCache(),
		preset:             preset,
		maxConnsPerHost:    0, // 0 = unlimited by default
		insecureSkipVerify: insecureSkipVerify,
		shuffleSeed:        shuffleSeed,
		cleanupInterval:    30 * time.Second,
		stopCleanup:        make(chan struct{}),
	}

	// Generate and cache ClientHelloSpec with shuffled extensions
	// Chrome shuffles extensions once per session, not per connection
	if preset.JA3 != "" {
		if spec, err := fingerprint.ParseJA3(preset.JA3, preset.JA3Extras); err == nil {
			m.cachedSpec = spec
		}
	} else if spec, err := tcpClientHelloSpec(preset, preset.ClientHelloID, shuffleSeed); err == nil {
		m.cachedSpec = spec
	}

	// Also cache PSK variant if available (not applicable for JA3 presets)
	if preset.JA3 == "" && preset.PSKClientHelloID.Client != "" {
		if spec, err := tcpClientHelloSpec(preset, preset.PSKClientHelloID, shuffleSeed); err == nil {
			m.cachedPSKSpec = spec
		}
	}

	// Start background cleanup
	go m.cleanupLoop()

	return m
}

// NewManagerWithProxy creates a manager with proxy support
func NewManagerWithProxy(preset *fingerprint.Preset, proxyURL string, insecureSkipVerify bool) *Manager {
	// Generate random seed for extension shuffling
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	m := &Manager{
		pools:              make(map[string]*HostPool),
		dnsCache:           dns.NewCache(),
		preset:             preset,
		maxConnsPerHost:    0, // 0 = unlimited by default
		proxyURL:           proxyURL,
		insecureSkipVerify: insecureSkipVerify,
		shuffleSeed:        shuffleSeed,
		cleanupInterval:    30 * time.Second,
		stopCleanup:        make(chan struct{}),
	}

	// Generate and cache ClientHelloSpec with shuffled extensions
	if preset.JA3 != "" {
		if spec, err := fingerprint.ParseJA3(preset.JA3, preset.JA3Extras); err == nil {
			m.cachedSpec = spec
		}
	} else if spec, err := tcpClientHelloSpec(preset, preset.ClientHelloID, shuffleSeed); err == nil {
		m.cachedSpec = spec
	}

	// Also cache PSK variant if available (not applicable for JA3 presets)
	if preset.JA3 == "" && preset.PSKClientHelloID.Client != "" {
		if spec, err := tcpClientHelloSpec(preset, preset.PSKClientHelloID, shuffleSeed); err == nil {
			m.cachedPSKSpec = spec
		}
	}

	// Start background cleanup
	go m.cleanupLoop()

	return m
}

// SetMaxConnsPerHost sets the max connections per host for new pools (0 = unlimited)
func (m *Manager) SetMaxConnsPerHost(max int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxConnsPerHost = max
}

// SetSessionCache sets the shared TLS session cache for all pools
// This allows session persistence to work across Save/Load
func (m *Manager) SetSessionCache(cache utls.ClientSessionCache) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessionCache = cache
}

// GetSessionCache returns the shared TLS session cache
func (m *Manager) GetSessionCache() utls.ClientSessionCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessionCache
}

// GetPool returns a pool for the given host, creating one if needed
func (m *Manager) GetPool(host, port string) (*HostPool, error) {
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
	pool = NewHostPoolWithConfig(connectHost, sniHost, port, m.preset, m.dnsCache, m.insecureSkipVerify, m.proxyURL, m.cachedSpec, m.cachedPSKSpec, m.shuffleSeed, m.sessionCache)
	pool.tlsVerify = m.tlsVerify
	if m.maxConnsPerHost > 0 {
		pool.SetMaxConns(m.maxConnsPerHost)
	}
	// Pass ECH configuration to the pool
	if len(m.echConfig) > 0 {
		pool.SetECHConfig(m.echConfig)
	}
	if m.echConfigDomain != "" {
		pool.SetECHConfigDomain(m.echConfigDomain)
	}
	m.pools[key] = pool
	return pool, nil
}

// GetConn gets a connection to the specified host
func (m *Manager) GetConn(ctx context.Context, host, port string) (*Conn, error) {
	pool, err := m.GetPool(host, port)
	if err != nil {
		return nil, err
	}
	return pool.GetConn(ctx)
}

// Preset returns the profile new connections are built from.
func (m *Manager) Preset() *fingerprint.Preset {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.preset
}

// SetPreset changes the fingerprint preset for new connections
// SetPreset swaps the browser profile for subsequent connections.
//
// Swapping the field alone is not enough, and used not to be: the ClientHello
// specs are derived from the profile ONCE at construction and handed to every
// host pool, and the existing pooled connections were dialled with the old one.
// So a caller who switched profile kept sending the previous browser's
// ClientHello over HTTP/2 - the switch appeared to work (the User-Agent and
// headers changed) while the TLS layer still said the old browser, which is a
// self-contradicting fingerprint and worse than not switching at all.
func (m *Manager) SetPreset(preset *fingerprint.Preset) {
	if preset == nil {
		return
	}

	// Rebuild the cached specs from the new profile, mirroring construction.
	var cachedSpec, cachedPSKSpec *utls.ClientHelloSpec
	if preset.JA3 != "" {
		if spec, err := fingerprint.ParseJA3(preset.JA3, preset.JA3Extras); err == nil {
			cachedSpec = spec
		}
	} else if spec, err := tcpClientHelloSpec(preset, preset.ClientHelloID, m.shuffleSeed); err == nil {
		cachedSpec = spec
	}
	if preset.JA3 == "" && preset.PSKClientHelloID.Client != "" {
		if spec, err := tcpClientHelloSpec(preset, preset.PSKClientHelloID, m.shuffleSeed); err == nil {
			cachedPSKSpec = spec
		}
	}

	m.mu.Lock()
	m.preset = preset
	m.cachedSpec = cachedSpec
	m.cachedPSKSpec = cachedPSKSpec
	pools := m.pools
	m.pools = make(map[string]*HostPool)
	m.mu.Unlock()

	// Drop connections dialled with the previous profile.
	for _, p := range pools {
		go p.Close()
	}
}

// GetDNSCache returns the DNS cache
func (m *Manager) GetDNSCache() *dns.Cache {
	return m.dnsCache
}

// SetConnectTo sets a host mapping for domain fronting
// SetTLSVerify installs caller-supplied certificate verification hooks on every
// pool created from here on. Verification only; the ClientHello is untouched.
func (m *Manager) SetTLSVerify(v *transport.TLSVerify) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tlsVerify = v
}

func (m *Manager) SetConnectTo(requestHost, connectHost string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connectTo == nil {
		m.connectTo = make(map[string]string)
	}
	m.connectTo[requestHost] = connectHost
}

// SetECHConfig sets a custom ECH configuration
func (m *Manager) SetECHConfig(echConfig []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.echConfig = echConfig
}

// SetECHConfigDomain sets a domain to fetch ECH config from
func (m *Manager) SetECHConfigDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.echConfigDomain = domain
}

// cleanupLoop periodically cleans up idle connections
func (m *Manager) cleanupLoop() {
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
func (m *Manager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, pool := range m.pools {
		pool.CloseIdle()
		total, _, _ := pool.Stats()
		if total == 0 {
			delete(m.pools, key)
		}
	}

	// Also cleanup DNS cache
	m.dnsCache.Cleanup()
}

// Close shuts down the manager and all pools
func (m *Manager) Close() {
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

// CloseAllPools closes all connection pools and clears session cache
// This is used when switching proxies - old connections are invalid for new proxy route
func (m *Manager) CloseAllPools() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, pool := range m.pools {
		pool.Close()
	}
	m.pools = make(map[string]*HostPool)
}

// SetProxy changes the proxy URL and closes all existing connections
// TLS sessions from old proxy route are invalid, so we clear everything
func (m *Manager) SetProxy(proxyURL string) {
	m.CloseAllPools()
	m.mu.Lock()
	m.proxyURL = proxyURL
	m.mu.Unlock()
}

// GetProxy returns the current proxy URL
func (m *Manager) GetProxy() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.proxyURL
}

// Stats returns overall manager statistics
func (m *Manager) Stats() map[string]struct {
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

// resolveStreamPriorityMode converts a string mode to the http2 constant.
func resolveStreamPriorityMode(mode string) http2.StreamPriorityMode {
	switch mode {
	case "chrome":
		return http2.StreamPriorityChrome
	case "default":
		return http2.StreamPriorityDefault
	default:
		return http2.StreamPriorityChrome
	}
}

// resolveHPACKIndexingPolicy converts a string policy to the hpack constant.
func resolveHPACKIndexingPolicy(policy string) hpack.IndexingPolicy {
	switch policy {
	case "chrome":
		return hpack.IndexingChrome
	case "never":
		return hpack.IndexingNever
	case "always":
		return hpack.IndexingAlways
	case "default":
		return hpack.IndexingDefault
	default:
		return hpack.IndexingChrome
	}
}

// uint16sToSettingIDs converts uint16 slice to http2.SettingID slice.
func uint16sToSettingIDs(ids []uint16) []http2.SettingID {
	result := make([]http2.SettingID, len(ids))
	for i, id := range ids {
		result[i] = http2.SettingID(id)
	}
	return result
}

// boolToUint32 converts a bool to uint32 (for HTTP/2 SETTINGS)
func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// buildHTTP2Settings creates the settings map dynamically based on preset configuration.
// Mirrors http2_transport.go's approach: base settings + conditional additions.
func buildHTTP2Settings(settings fingerprint.HTTP2Settings) map[http2.SettingID]uint32 {
	h2Settings := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   settings.HeaderTableSize,
		http2.SettingEnablePush:        boolToUint32(settings.EnablePush),
		http2.SettingInitialWindowSize: settings.InitialWindowSize,
		http2.SettingMaxHeaderListSize: settings.MaxHeaderListSize,
	}
	if settings.MaxConcurrentStreams > 0 {
		h2Settings[http2.SettingMaxConcurrentStreams] = settings.MaxConcurrentStreams
	}
	if settings.MaxFrameSize > 0 {
		h2Settings[http2.SettingMaxFrameSize] = settings.MaxFrameSize
	}
	if settings.NoRFC7540Priorities {
		h2Settings[http2.SettingNoRFC7540Priorities] = 1
	}
	return h2Settings
}

// buildHTTP2SettingsOrder creates the settings order based on preset configuration.
// If the preset has an explicit SettingsOrder, it takes precedence over the heuristic.
// The fallback dynamically appends conditional settings to match buildHTTP2Settings().
func buildHTTP2SettingsOrder(settings fingerprint.HTTP2Settings, preset *fingerprint.Preset) []http2.SettingID {
	if order := preset.H2SettingsOrder(); order != nil {
		return uint16sToSettingIDs(order)
	}
	// Build order dynamically to stay consistent with buildHTTP2Settings() map.
	// Base order depends on browser type, then conditional settings are appended.
	var order []http2.SettingID
	if settings.NoRFC7540Priorities {
		// Safari/iOS base order: 2, 4
		order = []http2.SettingID{
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
		}
	} else {
		// Chrome base order: 1, 2, 4, 6
		order = []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}
	}
	if settings.MaxConcurrentStreams > 0 {
		order = append(order, http2.SettingMaxConcurrentStreams)
	}
	if settings.MaxFrameSize > 0 {
		order = append(order, http2.SettingMaxFrameSize)
	}
	if settings.NoRFC7540Priorities {
		order = append(order, http2.SettingNoRFC7540Priorities)
	}
	return order
}

// hpackRepresentations mirrors the transport helper: preset representation
// overrides in their typed form, with anything unparseable dropped rather than
// guessed at. Names are validated when the preset is loaded.
func hpackRepresentations(m map[string]string) map[string]hpack.Representation {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]hpack.Representation, len(m))
	for name, rep := range m {
		if r, ok := hpack.ParseRepresentation(rep); ok && r != hpack.RepresentationDefault {
			out[name] = r
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
