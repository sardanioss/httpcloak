package transport

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/h2build"
	"github.com/sardanioss/httpcloak/proxy"
	"github.com/sardanioss/net/http2"
	tls "github.com/sardanioss/utls"
	utls "github.com/sardanioss/utls"
	"golang.org/x/sync/singleflight"
)

// HTTP2Transport is a custom HTTP/2 transport with uTLS fingerprinting
// and proper connection reuse
type HTTP2Transport struct {
	preset   *fingerprint.Preset
	dnsCache *dns.Cache
	proxy    *ProxyConfig
	config   *TransportConfig

	// Connection tracking
	conns   map[string]*persistentConn
	connsMu sync.RWMutex

	// retired holds connections evicted from conns while a response body was
	// still streaming on them. Their close is deferred until the body finishes,
	// and without this list nothing would ever revisit them: cleanup() only
	// walks conns, so an evicted connection whose body is never closed would
	// keep its socket for the process lifetime and Close() could not reclaim it.
	retired   []*persistentConn
	retiredMu sync.Mutex

	// dialGroup collapses concurrent dials for the same pool key into a single
	// connection attempt, so a burst of requests to one host (especially behind
	// a proxy) opens one connection instead of a storm of N.
	dialGroup singleflight.Group

	// TLS session resumption cache (shared across connections)
	sessionCache utls.ClientSessionCache

	// Shuffle seed for consistent TLS extension order across all connections
	// Chrome shuffles extensions once per session, not per connection
	// Each connection needs a fresh spec (ApplyPreset mutates it), but same seed
	shuffleSeed int64

	// Cached spec presence flags - indicate if preset supports these specs
	// We don't cache the actual spec objects as ApplyPreset mutates them
	hasPSKSpec bool

	// Configuration
	maxIdleTime          time.Duration
	maxConnAge           time.Duration
	abandonedBodyTimeout time.Duration
	connectTimeout       time.Duration
	insecureSkipVerify   bool
	tlsVerify            *TLSVerify
	localAddr            string // Local IP to bind outgoing connections

	// Cleanup
	stopCleanup chan struct{}
	closed      bool
}

// persistentConn represents a persistent HTTP/2 connection
type persistentConn struct {
	host           string
	tlsConn        *utls.UConn
	h2Conn         *http2.ClientConn
	createdAt      time.Time
	lastUsedAt     time.Time
	useCount       int64
	inFlight       int32 // requests still using this conn, including their response bodies
	closeRequested bool  // close as soon as the last in-flight request finishes
	closed         bool  // close() has already run
	sessionResumed bool  // True if TLS session was resumed (faster handshake)

	// Measured setup phases in milliseconds, filled during creation. These
	// replace a fabricated breakdown: the response path used to report
	// DNSLookup, TCPConnect and TLSHandshake as fixed fractions of FirstByte
	// (0.2, 0.3 and 0.5 of 70% of it), which are invented numbers in a public
	// API field. A phase that is not measured on a path stays zero, which is
	// the same value the struct already documents for "cached or reused".
	dnsMs       float64
	tcpMs       float64
	tlsMs       float64
	tlsVersion  uint16
	cipherSuite uint16
	mu          sync.Mutex

	// lastProgress is the unix-nano timestamp of the most recent body read.
	// Kept outside the mutex because it is touched on every Read. Only
	// meaningful while inFlight > 0, where it distinguishes a slow-but-live
	// download from a body the caller abandoned without closing.
	lastProgress atomic.Int64
}

// release marks one request as finished with the connection. If a close was
// deferred because requests were still streaming, it happens here.
func (c *persistentConn) release() {
	c.mu.Lock()
	c.inFlight--
	c.lastUsedAt = time.Now()
	shouldClose := c.closeRequested && c.inFlight <= 0
	c.mu.Unlock()

	if shouldClose {
		c.close()
	}
}

// requestClose closes the connection now if nothing is using it, otherwise
// defers the close until the last in-flight response body is done. Evicting a
// connection from the pool must never yank the socket out from under a
// response that is still streaming (issue #83).
func (c *persistentConn) requestClose() {
	c.mu.Lock()
	if c.inFlight > 0 {
		c.closeRequested = true
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	c.close()
}

// retire evicts a connection that is no longer wanted in the pool.
//
// If nothing is using it the socket closes immediately. If a response body is
// still streaming, the close is deferred until that body finishes AND the
// connection is tracked in t.retired, so cleanup() can still apply the
// abandoned-body bound to it and Close() can still reclaim it. Dropping an
// evicted-but-draining connection on the floor - which is what a bare
// requestClose() at an eviction site does - leaks the socket, its h2 ClientConn
// and that connection's reader goroutine for the process lifetime whenever the
// caller never closes the body.
func (t *HTTP2Transport) retire(conn *persistentConn) {
	conn.mu.Lock()
	deferred := conn.inFlight > 0 && !conn.closed
	if deferred {
		conn.closeRequested = true
	}
	conn.mu.Unlock()

	if !deferred {
		conn.close()
		return
	}

	t.retiredMu.Lock()
	t.retired = append(t.retired, conn)
	t.retiredMu.Unlock()
}

// sweepRetired closes evicted connections whose bodies have finished, and
// applies the abandoned-body bound to those whose caller walked away.
func (t *HTTP2Transport) sweepRetired() {
	t.retiredMu.Lock()
	defer t.retiredMu.Unlock()

	kept := t.retired[:0]
	for _, conn := range t.retired {
		conn.mu.Lock()
		done := conn.closed
		conn.mu.Unlock()
		if done {
			continue // release() already fired the deferred close
		}
		if t.isConnDestroyable(conn) {
			go conn.close()
			continue
		}
		kept = append(kept, conn)
	}
	t.retired = kept
}

// connBodyGuard keeps a pooled connection marked in-use for as long as the
// caller is reading the response body.
//
// HTTP/2 RoundTrip returns as soon as the response *headers* arrive, so without
// this the connection looked idle the moment a download started. A transfer
// lasting longer than maxIdleTime was then closed underneath the reader by the
// pool cleanup, which is what issue #83 reported at roughly 120s (90s idle plus
// the 30s cleanup tick).
type connBodyGuard struct {
	io.ReadCloser
	conn *persistentConn
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

// NewHTTP2Transport creates a new HTTP/2 transport with uTLS
func NewHTTP2Transport(preset *fingerprint.Preset, dnsCache *dns.Cache) *HTTP2Transport {
	return NewHTTP2TransportWithProxy(preset, dnsCache, nil)
}

// NewHTTP2TransportWithProxy creates a new HTTP/2 transport with optional proxy support
func NewHTTP2TransportWithProxy(preset *fingerprint.Preset, dnsCache *dns.Cache, proxy *ProxyConfig) *HTTP2Transport {
	return NewHTTP2TransportWithConfig(preset, dnsCache, proxy, nil)
}

// NewHTTP2TransportWithConfig creates a new HTTP/2 transport with proxy and advanced config
func NewHTTP2TransportWithConfig(preset *fingerprint.Preset, dnsCache *dns.Cache, proxy *ProxyConfig, config *TransportConfig) *HTTP2Transport {
	// Create session cache - with optional distributed backend
	var sessionCache *PersistableSessionCache
	if config != nil && config.SessionCacheBackend != nil {
		sessionCache = NewPersistableSessionCacheWithBackend(
			config.SessionCacheBackend,
			preset.Name,
			"h2",
			config.SessionCacheErrorCallback,
		)
	} else {
		sessionCache = NewPersistableSessionCache()
	}

	// Generate random seed for TLS extension shuffling
	// Chrome shuffles extensions once per session, not per connection
	// This seed ensures consistent ordering across all connections in this transport
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	// Whether this preset can produce a resumption-shaped ClientHello at all.
	//
	// This used to ask whether the JA3 string contained extension 41. That can
	// only be true of a JA3 captured mid-resumption, and a first capture never
	// is, so a JA3 preset always reported "no PSK" and never resumed. Asking the
	// preset what it actually carries removes the guess.
	customJA3 := ""
	if config != nil {
		customJA3 = config.CustomJA3
	}
	hasPSKSpec := fingerprint.HasPSKVariant(preset, customJA3)

	t := &HTTP2Transport{
		preset:       preset,
		dnsCache:     dnsCache,
		proxy:        proxy,
		config:       config,
		conns:        make(map[string]*persistentConn),
		sessionCache: sessionCache,
		shuffleSeed:  shuffleSeed,
		hasPSKSpec:   hasPSKSpec,
		maxIdleTime:  90 * time.Second,
		maxConnAge:   5 * time.Minute,
		// A response body that has not produced a single byte for this long is
		// treated as abandoned by its caller, so the connection can be
		// reclaimed. Without a bound here, a caller that never closes a body
		// would pin the socket forever.
		abandonedBodyTimeout: 10 * time.Minute,
		connectTimeout:       30 * time.Second,
		stopCleanup:          make(chan struct{}),
	}

	// Apply localAddr from config
	if config != nil && config.LocalAddr != "" {
		t.localAddr = config.LocalAddr
	}

	// Start background cleanup
	go t.cleanupLoop()

	return t
}

// RoundTrip implements http.RoundTripper
func (t *HTTP2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.connsMu.RLock()
	if t.closed {
		t.connsMu.RUnlock()
		return nil, fmt.Errorf("http2: transport closed")
	}
	t.connsMu.RUnlock()

	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	// Use connect host for pool key (domain fronting: multiple request hosts share one connection)
	connectHost := t.getConnectHost(host)
	key := net.JoinHostPort(connectHost, port)

	// Try to get existing connection (pass request host for SNI, connectHost used internally for DNS)
	conn, err := t.getOrCreateConn(req.Context(), host, port, key)
	if err != nil {
		return nil, err
	}

	// Mark conn as in-use so cleanup() doesn't close it mid-flight
	conn.mu.Lock()
	conn.lastUsedAt = time.Now()
	conn.inFlight++
	conn.mu.Unlock()

	// Make request
	resp, err := conn.h2Conn.RoundTrip(req)
	if err != nil {
		// release(), not a bare decrement: if this conn was evicted while the
		// request was in flight its close was deferred, and only release()
		// fires it once the count reaches zero.
		conn.release()

		// Connection might be dead, remove it before deciding anything.
		t.removeConn(key)

		// Don't retry if context is already done (e.g. timeout expired)
		if req.Context().Err() != nil {
			return nil, req.Context().Err()
		}

		// Ask whether this is a failure worth replaying, and get the request
		// to replay with, rather than blindly re-sending the same one.
		//
		// Two things were wrong with re-sending it. The body: RoundTrip
		// streams it out as it writes, so the first attempt has consumed it,
		// and the replay went out carrying the content-length it had already
		// computed with zero DATA behind it. That is malformed under RFC 9113
		// 8.1.1, it is trivially visible to the server, and it is a silent
		// correctness bug in its own right, because every retried request with
		// a body lost the body. The H1 path next door has had this right, with
		// a comment describing the same failure.
		//
		// And the classification: a browser replays a refused stream or a
		// graceful GOAWAY, and gives up on RST_STREAM(INTERNAL_ERROR) before
		// headers, and never makes a second HTTP/2 attempt after
		// HTTP_1_1_REQUIRED. Retrying everything produced two HEADERS arrivals
		// where a real client produces one, on exactly the errors a server
		// chooses to send.
		retryReq, retryErr := http2.ShouldRetryRequest(req, err)
		if retryErr != nil || retryReq == nil {
			return nil, err
		}

		conn, err = t.getOrCreateConn(req.Context(), host, port, key)
		if err != nil {
			return nil, err
		}

		conn.mu.Lock()
		conn.inFlight++
		conn.mu.Unlock()

		resp, err = conn.h2Conn.RoundTrip(retryReq)
		if err != nil {
			conn.release()
			t.removeConn(key)
			return nil, err
		}
	}

	// Keep the connection marked in-use until the caller finishes with the body.
	// RoundTrip returning only means the headers arrived; the body may stream for
	// minutes, and releasing here made the pool think the connection was idle.
	conn.mu.Lock()
	conn.lastUsedAt = time.Now()
	conn.useCount++
	conn.mu.Unlock()
	conn.lastProgress.Store(time.Now().UnixNano())

	if resp.Body == nil {
		conn.release()
	} else {
		resp.Body = &connBodyGuard{ReadCloser: resp.Body, conn: conn}
	}

	return resp, nil
}

// getOrCreateConn gets an existing connection or creates a new one.
// The TCP+TLS dial is performed outside the lock to avoid blocking all
// hosts while one host is connecting (head-of-line blocking).
func (t *HTTP2Transport) getOrCreateConn(ctx context.Context, host, port, key string) (*persistentConn, error) {
	// Try to get existing connection
	t.connsMu.RLock()
	if t.closed {
		t.connsMu.RUnlock()
		return nil, fmt.Errorf("http2: transport closed")
	}
	conn, exists := t.conns[key]
	t.connsMu.RUnlock()

	if exists && t.isConnUsable(conn) {
		return conn, nil
	}

	// Need to create new connection — verify under write lock first
	t.connsMu.Lock()
	if t.closed {
		t.connsMu.Unlock()
		return nil, fmt.Errorf("http2: transport closed")
	}

	// Double-check after acquiring write lock
	if conn, exists = t.conns[key]; exists && t.isConnUsable(conn) {
		t.connsMu.Unlock()
		return conn, nil
	}

	// Close old unusable connection and remove from map
	if exists {
		go t.retire(conn)
		delete(t.conns, key)
	}
	t.connsMu.Unlock()

	// Create new connection OUTSIDE lock — TCP+TLS dial can take seconds.
	// Deduplicate concurrent dials for the same pool key via singleflight: without
	// this, N simultaneous requests to a host with no usable connection each open
	// their own TCP+TLS (and, behind an HTTP proxy, their own CONNECT) — a
	// connection storm that wastes resources and trips proxy rate limits. The
	// single winning dial's result is shared by every caller (H2 multiplexes all
	// streams over one connection anyway). Dials for *different* keys still run in
	// parallel.
	// leader is set only inside the closure singleflight actually executes (the
	// winner); coalesced waiters pass their own closures which never run, so their
	// leader stays false. This lets a waiter recognise when it received the
	// leader's result and react differently for connection-bearing errors.
	leader := false
	v, err, _ := t.dialGroup.Do(key, func() (interface{}, error) {
		leader = true
		// A usable conn may have been published between our checks above and
		// winning the singleflight slot.
		t.connsMu.RLock()
		if c, ok := t.conns[key]; ok && t.isConnUsable(c) {
			t.connsMu.RUnlock()
			return c, nil
		}
		t.connsMu.RUnlock()

		// Detach from the triggering request's cancellation so one caller going
		// away doesn't abort the dial the others are waiting on — but PRESERVE
		// that caller's deadline, otherwise a stalling host/proxy would ride
		// past the configured timeout (context.WithoutCancel drops the deadline
		// too). retryDial bounds each attempt by this deadline, so the whole
		// dial (including retries) still aborts at the request budget.
		dialParent := context.WithoutCancel(ctx)
		if dl, ok := ctx.Deadline(); ok {
			var dcancel context.CancelFunc
			dialParent, dcancel = context.WithDeadline(dialParent, dl)
			defer dcancel()
		}
		// When a proxy is configured, retry transient connection failures a
		// couple of times (pre-send, so method-safe).
		attempts := 1
		if t.proxy != nil && t.proxy.URL != "" {
			attempts = proxyDialAttempts
		}
		newConn, derr := retryDial(dialParent, attempts, t.connectTimeout+10*time.Second,
			func(c context.Context) (*persistentConn, error) {
				return t.createConn(c, host, port)
			})
		if derr != nil {
			return nil, derr
		}

		t.connsMu.Lock()
		if t.closed {
			t.connsMu.Unlock()
			go newConn.close()
			return nil, fmt.Errorf("http2: transport closed")
		}
		// Another goroutine may have created a conn while we were dialing
		if existingConn, ok := t.conns[key]; ok && t.isConnUsable(existingConn) {
			t.connsMu.Unlock()
			go newConn.close()
			return existingConn, nil
		}
		t.conns[key] = newConn
		t.connsMu.Unlock()
		return newConn, nil
	})
	if err != nil {
		// An ALPN downgrade returns a single live TLS connection carried inside
		// the error, meant for ONE owner to serve over HTTP/1.1. singleflight
		// hands every coalesced caller the same error (same connection), so only
		// the leader may use it; waiters must dial their own connection instead
		// of racing/double-closing the shared one. (Each waiter's own dial will
		// itself downgrade and yield its own dedicated connection.)
		var alpnErr *ALPNMismatchError
		if errors.As(err, &alpnErr) && !leader {
			return t.createConn(ctx, host, port)
		}
		return nil, err
	}
	return v.(*persistentConn), nil
}

// isConnUsable reports whether a connection may be handed out for a NEW request.
//
// This is deliberately separate from isConnDestroyable: "too old to start
// another request on" and "safe to close" are different questions, and
// conflating them is what let cleanup close connections that were still
// streaming a response (issue #83).
//
// Note: We don't check CanTakeNewRequest() here because it can return false
// even when the connection is fine. We'll handle errors during actual use.
func (t *HTTP2Transport) isConnUsable(conn *persistentConn) bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Already evicted and waiting for its last body to finish.
	if conn.closeRequested {
		return false
	}

	// Check age
	if time.Since(conn.createdAt) > t.maxConnAge {
		return false
	}

	// Check idle time — but not if requests are actively in-flight.
	// Without this, long downloads (>maxIdleTime) get killed by cleanup.
	if conn.inFlight == 0 && time.Since(conn.lastUsedAt) > t.maxIdleTime {
		return false
	}

	// Just check if connection object exists - we'll handle errors during RoundTrip
	if conn.h2Conn == nil {
		return false
	}

	return true
}

// isConnDestroyable reports whether a connection can be closed right now.
//
// A connection with requests still on it is never destroyable, however old or
// idle-looking it is, with one exception: if its response body has made no
// progress for abandonedBodyTimeout the caller has clearly walked away without
// closing it, and holding the socket forever would be a leak.
func (t *HTTP2Transport) isConnDestroyable(conn *persistentConn) bool {
	conn.mu.Lock()
	inFlight := conn.inFlight
	lastUsedAt := conn.lastUsedAt
	h2Conn := conn.h2Conn
	conn.mu.Unlock()

	if inFlight > 0 {
		last := lastUsedAt
		if p := conn.lastProgress.Load(); p > 0 {
			if progressed := time.Unix(0, p); progressed.After(last) {
				last = progressed
			}
		}
		return time.Since(last) > t.abandonedBodyTimeout
	}

	if h2Conn == nil {
		return true
	}
	if time.Since(conn.createdAt) > t.maxConnAge {
		return true
	}
	return time.Since(lastUsedAt) > t.maxIdleTime
}

// createConn creates a new persistent H2 connection, degrading gracefully when
// an applied ECH config is rejected. ECH is best-effort: if the first attempt
// fails for an ECH/handshake-level reason (issue #74 — an ECHConfigDomain that
// does not front this target, or a rotated/stale key), retry ONCE without ECH so
// the connection still establishes (SNI visible) instead of failing H2 and
// cascading to H1. An ALPNMismatchError is never retried here — it carries a live
// TLS connection the caller reuses for H1.
func (t *HTTP2Transport) createConn(ctx context.Context, host, port string) (*persistentConn, error) {
	// No ECH configured, or this host recently stalled/rejected ECH: dial once,
	// skipping ECH when the host is known ECH-incompatible.
	if !t.echConfigured() || dns.IsECHIncompatible(host) {
		return t.establishConn(ctx, host, port, t.echConfigured() && dns.IsECHIncompatible(host))
	}
	// Time-box the ECH attempt so a target that STALLS on an incompatible ECH
	// ClientHello (issue #74 — some servers stall rather than cleanly reject) fails
	// fast, leaving budget to retry without ECH within the same request deadline.
	echCtx, cancel := boundedECHAttempt(ctx)
	conn, err := t.establishConn(echCtx, host, port, false)
	cancel()
	if err == nil {
		return conn, nil
	}
	var alpnErr *ALPNMismatchError
	if errors.As(err, &alpnErr) {
		return conn, err // carries a live TLS conn for H1 reuse; never retry
	}
	if ctx.Err() != nil {
		return conn, err // overall request budget exhausted, nothing to retry with
	}
	// The ECH attempt failed with budget to spare: a reject, a certificate
	// mismatch, or a stall caught by the ECH sub-deadline (ctx is not done, so a
	// DeadlineExceeded here is echCtx's). Remember the host as ECH-incompatible so
	// future connections skip the stall, and retry now without ECH.
	if echCausedDialFailure(err) || errors.Is(err, context.DeadlineExceeded) {
		dns.MarkECHIncompatible(host)
		return t.establishConn(ctx, host, port, true)
	}
	return conn, err
}

// echConfigured reports whether this transport has any ECH source configured
// (raw bytes or an ECHConfigDomain), i.e. whether a no-ECH retry is meaningful.
func (t *HTTP2Transport) echConfigured() bool {
	return t.config != nil && (len(t.config.ECHConfig) > 0 || t.config.ECHConfigDomain != "")
}

// establishConn creates a new persistent connection. skipECH forces a no-ECH
// handshake (see createConn's graceful-degradation retry).
func (t *HTTP2Transport) establishConn(ctx context.Context, host, port string, skipECH bool) (*persistentConn, error) {
	var rawConn net.Conn
	var err error

	// Measured setup phases, in milliseconds. They stay zero on the proxy path,
	// where DNS and the TCP connect happen inside the proxy dial and are not
	// separable from here. Zero is what the Timing struct already documents for
	// a phase that did not happen, and reporting zero is the point: these
	// numbers used to be fabricated as fixed fractions of FirstByte.
	var dnsMs, dnsElapsed, tcpElapsed, tlsElapsed float64

	// Get the connection host (may be different for domain fronting)
	connectHost := t.getConnectHost(host)

	targetAddr := net.JoinHostPort(host, port)

	if t.proxy != nil && t.proxy.URL != "" {
		// Connect through proxy - use connectHost for proxy CONNECT
		rawConn, err = t.dialThroughProxy(ctx, connectHost, port)
		if err != nil {
			return nil, fmt.Errorf("proxy connection failed: %w", err)
		}
	} else {
		// Direct connection with DNS resolution and IPv4/IPv6 fallback
		// Resolve the connection host, not request host
		dnsStart := time.Now()
		ips, err := t.dnsCache.ResolveAllSorted(ctx, connectHost)
		dnsElapsed = float64(time.Since(dnsStart).Microseconds()) / 1000
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("DNS resolution failed: no IP addresses found")
		}

		dialer := &net.Dialer{
			Timeout:   t.connectTimeout,
			KeepAlive: 30 * time.Second,
		}
		SetDialerControl(dialer, &t.preset.TCPFingerprint)
		ApplyLocalAddrControl(dialer, t.localAddr)
		if t.localAddr != "" {
			localIP := net.ParseIP(t.localAddr)
			dialer.LocalAddr = &net.TCPAddr{IP: localIP}
			// Filter IPs to match local address family
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

		// Race the resolved addresses with a staggered start (Happy Eyeballs):
		// an unreachable address no longer delays the next, and the fastest
		// reachable one wins. Bounded by the dialer timeout + ctx; losers closed.
		tcpStart := time.Now()
		rawConn, err = staggeredRace(ctx, len(ips), 250*time.Millisecond,
			func(rctx context.Context, idx int) (net.Conn, error) {
				network := "tcp4"
				if ips[idx].To4() == nil {
					network = "tcp6"
				}
				return dialer.DialContext(rctx, network, net.JoinHostPort(ips[idx].String(), port))
			},
			func(c net.Conn) { c.Close() },
		)
		if err != nil {
			return nil, fmt.Errorf("TCP connect failed: %w", err)
		}
		if rawConn == nil {
			return nil, fmt.Errorf("TCP connect failed: all connection attempts failed")
		}
		tcpElapsed = float64(time.Since(tcpStart).Microseconds()) / 1000
		dnsMs = dnsElapsed
	}

	// Set TCP keepalive
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// Generate fresh spec for this connection to avoid race condition
	// utls's ApplyPreset mutates the spec (clears KeyShares.Data, etc.), so each
	// connection needs its own copy. Use same shuffleSeed for consistent ordering.
	// One resolver for every TLS source, shared with the H1 transport. This used
	// to be an inline if/else chain whose first arm was `if ja3String != ""`,
	// taken unconditionally, which made the PSK arm below it unreachable for any
	// JA3 preset. Adding raw hellos as a fourth source to that shape would have
	// reproduced the same bug, so the decision lives in fingerprint now.
	customJA3, customJA3Extras := "", (*fingerprint.JA3Extras)(nil)
	if t.config != nil {
		customJA3, customJA3Extras = t.config.CustomJA3, t.config.CustomJA3Extras
	}
	specToUse, specSource, specErr := fingerprint.ResolveClientHelloSpec(
		t.preset, customJA3, customJA3Extras, t.hasPSKSpec, t.shuffleSeed)
	if specErr != nil {
		rawConn.Close()
		return nil, fmt.Errorf("resolve client hello: %w", specErr)
	}
	// The preset's TCP signature_algorithms override (Chrome 150's ML-DSA
	// codepoints, for instance) layers on top of a ClientHelloID base only. JA3
	// carries its own via JA3Extras, and a captured raw hello already contains
	// the client's real list, so overwriting it there would undo the capture.
	if specSource == fingerprint.SourceClientHelloID {
		fingerprint.ApplySignatureAlgorithms(specToUse.Extensions, t.preset.SignatureAlgorithms)
		fingerprint.ApplyTrustAnchors(&specToUse.Extensions, t.preset.TrustAnchors)
	}

	// Fetch ECH config if needed. skipECH forces a no-ECH handshake, used by the
	// graceful-degradation retry (issue #74) after a first attempt whose ECH
	// config was rejected or mis-served.
	var echConfigList []byte
	if !skipECH && t.config != nil {
		if len(t.config.ECHConfig) > 0 {
			echConfigList = t.config.ECHConfig
		} else if t.config.ECHConfigDomain != "" {
			// Fetch ECH config from DNS
			echConfigList, _ = dns.FetchECHConfigs(ctx, t.config.ECHConfigDomain)
			// ECH fetch failed - continue without ECH (SNI will be visible)
		}
	}

	// Determine MinVersion based on ECH usage
	// ECH requires TLS 1.3, so set MinVersion accordingly
	minVersion := uint16(tls.VersionTLS12)
	if len(echConfigList) > 0 {
		minVersion = tls.VersionTLS13
	}

	// Determine key log writer - config override or global
	var keyLogWriter io.Writer
	if t.config != nil && t.config.KeyLogWriter != nil {
		keyLogWriter = t.config.KeyLogWriter
	} else {
		keyLogWriter = GetKeyLogWriter()
	}

	// Wrap with uTLS for fingerprinting
	tlsConfig := &utls.Config{
		// Go ramps its TLS record sizes (1186*N until 128KB) to trade latency for
		// throughput. No browser does that, and the ramp is arithmetic, so a
		// server reading the cleartext record lengths can identify the TLS stack
		// lineage rather than merely noting "not a browser". Disable it so every
		// record is full-size, as BoringSSL's are.
		//
		// This MUST ship with the DATA frame cap. On its own, measured, it makes
		// the profile worse: the short trailing records go from four to nine over
		// eight frames and land in a clean alternating pattern instead of hiding
		// inside the ramp.
		DynamicRecordSizingDisabled:        true,
		ServerName:                         host,
		InsecureSkipVerify:                 t.insecureSkipVerify,
		MinVersion:                         minVersion,
		MaxVersion:                         tls.VersionTLS13,
		OmitEmptyPsk:                       true,          // Chrome doesn't send empty PSK on first connection
		PreferSkipResumptionOnNilExtension: true,          // Skip resumption if spec has no PSK extension instead of panicking
		EncryptedClientHelloConfigList:     echConfigList, // ECH configuration (if available)
		KeyLogWriter:                       keyLogWriter,
	}
	t.tlsVerify.Apply(tlsConfig)

	// Only enable session cache if we have PSK spec - prevents panic when session
	// is cached but spec doesn't have PSK extension (TOCTOU race mitigation)
	if t.hasPSKSpec {
		tlsConfig.ClientSessionCache = t.sessionCache
	}

	// Create UClient with HelloCustom and apply our fresh spec
	// This ensures the TLS extension order is consistent across all connections (same seed)
	var tlsConn *utls.UConn
	if specToUse != nil {
		// Use fresh spec - extension order is consistent from shuffle seed
		tlsConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
		if err := tlsConn.ApplyPreset(specToUse); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to apply TLS preset: %w", err)
		}
	} else {
		// Fallback to ClientHelloID if spec generation failed
		tlsConn = utls.UClient(rawConn, tlsConfig, t.preset.ClientHelloID)
	}

	// Set session cache for TLS resumption (only if PSK spec available)
	if t.hasPSKSpec {
		tlsConn.SetSessionCache(t.sessionCache)
	}

	// Perform TLS handshake
	tlsStart := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()

		// Speculative TLS fallback: if the handshake failed because the proxy can't
		// handle combined CONNECT+ClientHello, re-dial with blocking CONNECT flow.
		// This is transparent to the caller and doesn't consume a retry attempt.
		if IsSpeculativeTLSError(err) && t.proxy != nil && t.proxy.URL != "" {
			// Remember this proxy doesn't support speculative TLS
			MarkProxyNoSpeculative(t.proxy.URL)

			// Re-dial with fresh TCP connection using blocking CONNECT
			rawConn, dialErr := t.dialHTTPProxyBlockingFresh(ctx, connectHost, port)
			if dialErr != nil {
				return nil, fmt.Errorf("speculative TLS fallback dial failed: %w", dialErr)
			}

			// Regenerate fresh TLS spec (the previous one was consumed)
			var fallbackSpec *utls.ClientHelloSpec
			// Reuse same JA3 resolution logic as primary path
			fallbackJA3 := ""
			var fallbackJA3Extras *fingerprint.JA3Extras
			if t.config != nil && t.config.CustomJA3 != "" {
				fallbackJA3 = t.config.CustomJA3
				fallbackJA3Extras = t.config.CustomJA3Extras
			} else if t.preset.JA3 != "" {
				fallbackJA3 = t.preset.JA3
				fallbackJA3Extras = t.preset.JA3Extras
			}
			if fallbackJA3 != "" {
				spec, parseErr := fingerprint.ParseJA3(fallbackJA3, fallbackJA3Extras)
				if parseErr != nil {
					rawConn.Close()
					return nil, fmt.Errorf("speculative TLS fallback: failed to parse JA3: %w", parseErr)
				}
				fallbackSpec = spec
			} else if t.hasPSKSpec {
				if spec, specErr := utls.UTLSIdToSpecWithSeed(t.preset.PSKClientHelloID, t.shuffleSeed); specErr == nil {
					fallbackSpec = &spec
				}
			}
			if fallbackSpec == nil {
				if spec, specErr := utls.UTLSIdToSpecWithSeed(t.preset.ClientHelloID, t.shuffleSeed); specErr == nil {
					fallbackSpec = &spec
				}
			}
			// Keep the same TCP signature_algorithms override on the fallback spec.
			if fallbackJA3 == "" && fallbackSpec != nil {
				fingerprint.ApplySignatureAlgorithms(fallbackSpec.Extensions, t.preset.SignatureAlgorithms)
				fingerprint.ApplyTrustAnchors(&fallbackSpec.Extensions, t.preset.TrustAnchors)
			}

			// Redo TLS handshake on the clean connection
			if fallbackSpec != nil {
				tlsConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
				if applyErr := tlsConn.ApplyPreset(fallbackSpec); applyErr != nil {
					rawConn.Close()
					return nil, fmt.Errorf("speculative TLS fallback preset failed: %w", applyErr)
				}
			} else {
				tlsConn = utls.UClient(rawConn, tlsConfig, t.preset.ClientHelloID)
			}
			if t.hasPSKSpec {
				tlsConn.SetSessionCache(t.sessionCache)
			}

			if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
				rawConn.Close()
				return nil, fmt.Errorf("TLS handshake failed (after speculative fallback): %w", hsErr)
			}
			// Fall through to ALPN check below
			goto alpnCheck
		}

		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
alpnCheck:
	// Measured here rather than after the handshake call, because the
	// speculative-TLS fallback re-dials and jumps straight to this label, and
	// that path's handshake has to be counted too.
	tlsElapsed = float64(time.Since(tlsStart).Microseconds()) / 1000

	// Check ALPN negotiation result
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		// Return ALPNMismatchError with the TLS connection so caller can reuse it for H1
		// DO NOT close the connection - caller is responsible for closing or reusing
		return nil, &ALPNMismatchError{
			Expected:   "h2",
			Negotiated: state.NegotiatedProtocol,
			TLSConn:    tlsConn,
			Host:       host,
			Port:       port,
		}
	}

	// Check TLSOnly mode: no automatic Accept-Encoding, no default User-Agent.
	tlsOnly := t.config != nil && t.config.TLSOnly

	// One builder for both entrypoints. The transport path and the pool path
	// used to construct this literal independently and had drifted; see
	// internal/h2build.
	h2Transport := h2build.Transport(h2build.Options{
		Preset:  t.preset,
		TLSOnly: tlsOnly,
		PseudoHeaderOrder: func() []string {
			if t.config != nil && len(t.config.CustomPseudoOrder) > 0 {
				return t.config.CustomPseudoOrder
			}
			return nil
		}(),
	})

	h2Conn, err := h2Transport.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("HTTP/2 setup failed: %w", err)
	}

	_ = targetAddr // Used in proxy connection

	// Check if session was resumed (faster TLS handshake)
	connState := tlsConn.ConnectionState()
	sessionResumed := connState.DidResume

	return &persistentConn{
		host:           host,
		tlsConn:        tlsConn,
		h2Conn:         h2Conn,
		createdAt:      time.Now(),
		lastUsedAt:     time.Now(),
		useCount:       0,
		sessionResumed: sessionResumed,
		tlsVersion:     connState.Version,
		cipherSuite:    connState.CipherSuite,
		dnsMs:          dnsMs,
		tcpMs:          tcpElapsed,
		tlsMs:          tlsElapsed,
	}, nil
}

// dialThroughProxy establishes a connection through a proxy using CONNECT
// Supports both HTTP proxies (HTTP CONNECT) and SOCKS5 proxies (SOCKS5 CONNECT)
func (t *HTTP2Transport) dialThroughProxy(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	// Check if it's a SOCKS5 proxy
	if proxy.IsSOCKS5URL(t.proxy.URL) {
		return t.dialThroughSOCKS5(ctx, targetHost, targetPort)
	}

	// HTTP proxy - use HTTP CONNECT
	return t.dialThroughHTTPProxy(ctx, targetHost, targetPort)
}

// dialThroughSOCKS5 establishes a connection through a SOCKS5 proxy
func (t *HTTP2Transport) dialThroughSOCKS5(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	socks5Dialer, err := proxy.NewSOCKS5Dialer(t.proxy.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}
	if t.localAddr != "" {
		socks5Dialer.SetLocalAddr(t.localAddr)
	}
	socks5Dialer.Control = BuildDialControl(&t.preset.TCPFingerprint, t.localAddr)

	targetAddr := net.JoinHostPort(targetHost, targetPort)
	conn, err := socks5Dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 CONNECT failed: %w", err)
	}

	return conn, nil
}

// dialThroughHTTPProxy establishes a connection through an HTTP proxy using CONNECT.
// By default, uses the traditional blocking CONNECT flow. Speculative TLS (sending
// CONNECT + ClientHello together) can be enabled via TransportConfig.EnableSpeculativeTLS.
func (t *HTTP2Transport) dialThroughHTTPProxy(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	// Parse proxy URL
	proxyURL, err := url.Parse(t.proxy.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	// Determine proxy address
	proxyHost := proxyURL.Hostname()
	proxyPort := proxyURL.Port()
	if proxyPort == "" {
		if proxyURL.Scheme == "https" {
			proxyPort = "443"
		} else {
			proxyPort = "8080"
		}
	}

	// Resolve the proxy hostname via the shared DNS cache (cached, honors the
	// configured IP-family preference, stale fallback on transient errors).
	proxyIPObjs, err := t.dnsCache.ResolveAllSorted(ctx, proxyHost)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxyHost, err)
	}
	proxyIPs := ipsToStrings(proxyIPObjs)
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxyHost)
	}

	// Connect to proxy using resolved IP
	dialer := &net.Dialer{
		Timeout:   t.connectTimeout,
		KeepAlive: 30 * time.Second,
	}
	SetDialerControl(dialer, &t.preset.TCPFingerprint)
	ApplyLocalAddrControl(dialer, t.localAddr)
	if t.localAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(t.localAddr)}
	}

	conn, err := dialProxyAddrs(ctx, dialer, proxyIPs, proxyPort, t.connectTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	// Build CONNECT request
	targetAddr := net.JoinHostPort(targetHost, targetPort)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	// Add proxy authentication if provided
	proxyAuth := t.getProxyAuth(proxyURL)
	if proxyAuth != "" {
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", proxyAuth)
	}

	connectReq += "Connection: keep-alive\r\n\r\n"

	// Use speculative TLS only when explicitly enabled and not on the blocklist
	if t.config != nil && t.config.EnableSpeculativeTLS && !IsProxyNoSpeculative(t.proxy.URL) {
		// Speculative TLS: send CONNECT + ClientHello together to save one round-trip
		return NewSpeculativeConn(conn, connectReq), nil
	}

	// Traditional flow: send CONNECT, wait for 200 OK, then return conn for TLS
	return t.dialHTTPProxyBlocking(ctx, conn, connectReq)
}

// dialHTTPProxyBlockingFresh opens a new TCP connection to the proxy and performs
// the traditional blocking CONNECT flow. Used as fallback when speculative TLS fails
// and the original connection is corrupted.
func (t *HTTP2Transport) dialHTTPProxyBlockingFresh(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	proxyURL, err := url.Parse(t.proxy.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	proxyHost := proxyURL.Hostname()
	proxyPort := proxyURL.Port()
	if proxyPort == "" {
		if proxyURL.Scheme == "https" {
			proxyPort = "443"
		} else {
			proxyPort = "8080"
		}
	}

	proxyIPObjs, err := t.dnsCache.ResolveAllSorted(ctx, proxyHost)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxyHost, err)
	}
	proxyIPs := ipsToStrings(proxyIPObjs)
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxyHost)
	}

	dialer := &net.Dialer{
		Timeout:   t.connectTimeout,
		KeepAlive: 30 * time.Second,
	}
	SetDialerControl(dialer, &t.preset.TCPFingerprint)
	ApplyLocalAddrControl(dialer, t.localAddr)
	if t.localAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(t.localAddr)}
	}

	conn, err := dialProxyAddrs(ctx, dialer, proxyIPs, proxyPort, t.connectTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	targetAddr := net.JoinHostPort(targetHost, targetPort)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	proxyAuth := t.getProxyAuth(proxyURL)
	if proxyAuth != "" {
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", proxyAuth)
	}
	connectReq += "Connection: keep-alive\r\n\r\n"

	return t.dialHTTPProxyBlocking(ctx, conn, connectReq)
}

// dialHTTPProxyBlocking performs the traditional blocking CONNECT flow.
// Used when speculative TLS is disabled or as a fallback.
func (t *HTTP2Transport) dialHTTPProxyBlocking(ctx context.Context, conn net.Conn, connectReq string) (net.Conn, error) {
	// Send CONNECT request
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	// Set deadline for proxy response — respect context deadline if sooner than 30s
	deadline := time.Now().Add(30 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.SetReadDeadline(deadline)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	conn.SetReadDeadline(time.Time{}) // Clear deadline after response
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed with status %d: %s", resp.StatusCode, resp.Status)
	}

	// Connection established - tunnel is now open
	// If the bufio.Reader read ahead past the HTTP response (e.g., start of
	// TLS ServerHello arrived in same TCP segment), wrap the conn so those
	// buffered bytes are returned first.
	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: io.MultiReader(reader, conn)}, nil
	}
	return conn, nil
}

// getProxyAuth returns base64-encoded proxy authentication credentials
func (t *HTTP2Transport) getProxyAuth(proxyURL *url.URL) string {
	// First check struct fields
	username := t.proxy.Username
	password := t.proxy.Password

	// Override with URL credentials if present
	if proxyURL.User != nil {
		if u := proxyURL.User.Username(); u != "" {
			username = u
		}
		if p, ok := proxyURL.User.Password(); ok {
			password = p
		}
	}

	if username == "" {
		return ""
	}

	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// removeConn removes a connection from the pool
func (t *HTTP2Transport) removeConn(key string) {
	t.connsMu.Lock()
	conn, exists := t.conns[key]
	if exists {
		delete(t.conns, key)
	}
	t.connsMu.Unlock()

	if exists && conn != nil {
		// Deferred: another request may still be streaming on this connection
		// even though the caller that triggered the removal hit an error.
		go t.retire(conn)
	}
}

// close closes the persistent connection.
// Closes h2Conn first (graceful GOAWAY + stream teardown) then tlsConn.
func (c *persistentConn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	if c.h2Conn != nil {
		c.h2Conn.Close()
	}
	if c.tlsConn != nil {
		c.tlsConn.Close()
	}
}

// cleanupLoop periodically cleans up stale connections
func (t *HTTP2Transport) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCleanup:
			return
		case <-ticker.C:
			t.cleanup()
		}
	}
}

// cleanup removes stale connections
func (t *HTTP2Transport) cleanup() {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	for key, conn := range t.conns {
		// Note: destroyable, not "not usable". A connection that is merely too
		// old to take new requests may still be streaming a response body.
		if t.isConnDestroyable(conn) {
			delete(t.conns, key)
			go conn.close()
		}
	}

	// Evicted-but-draining connections live outside t.conns; they need the same
	// bound applied or they would never be revisited.
	t.sweepRetired()
}

// Close shuts down the transport
func (t *HTTP2Transport) Close() {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.closed {
		return
	}
	t.closed = true

	close(t.stopCleanup)

	for _, conn := range t.conns {
		go conn.close()
	}
	t.conns = nil

	// Connections evicted while still streaming are not in t.conns. Shutdown is
	// unconditional, so close them here too rather than leaving their sockets
	// behind after the transport is gone.
	t.retiredMu.Lock()
	for _, conn := range t.retired {
		go conn.close()
	}
	t.retired = nil
	t.retiredMu.Unlock()
}

// Refresh closes all connections but keeps the TLS session cache intact.
// This simulates a browser page refresh - new TCP connections but TLS resumption.
func (t *HTTP2Transport) Refresh() {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.closed {
		return
	}

	// Close all connections
	for _, conn := range t.conns {
		go conn.close()
	}
	// Reset the map but keep session cache
	t.conns = make(map[string]*persistentConn)
}

// GetSessionCache returns the TLS session cache
func (t *HTTP2Transport) GetSessionCache() utls.ClientSessionCache {
	return t.sessionCache
}

// SetSessionCache sets the TLS session cache
func (t *HTTP2Transport) SetSessionCache(cache utls.ClientSessionCache) {
	t.sessionCache = cache
}

// SetInsecureSkipVerify sets whether to skip TLS certificate verification
// SetTLSVerify installs caller-supplied certificate verification hooks.
// Only verification is configurable; nothing here affects the ClientHello.
func (t *HTTP2Transport) SetTLSVerify(v *TLSVerify) {
	t.tlsVerify = v
}

func (t *HTTP2Transport) SetInsecureSkipVerify(skip bool) {
	t.insecureSkipVerify = skip
}

// SetLocalAddr sets the local IP address for outgoing connections
func (t *HTTP2Transport) SetLocalAddr(addr string) {
	t.localAddr = addr
	narrowDNSToLocalFamily(t.dnsCache, addr)
}

// Stats returns transport statistics
func (t *HTTP2Transport) Stats() map[string]ConnStats {
	t.connsMu.RLock()
	defer t.connsMu.RUnlock()

	stats := make(map[string]ConnStats)
	for key, conn := range t.conns {
		conn.mu.Lock()
		stats[key] = ConnStats{
			Host:           conn.host,
			CreatedAt:      conn.createdAt,
			LastUsedAt:     conn.lastUsedAt,
			UseCount:       conn.useCount,
			Age:            time.Since(conn.createdAt),
			IdleTime:       time.Since(conn.lastUsedAt),
			IsReused:       conn.useCount > 1,
			SessionResumed: conn.sessionResumed,
			TLSVersion:     conn.tlsVersion,
			CipherSuite:    conn.cipherSuite,
		}
		conn.mu.Unlock()
	}

	return stats
}

// IsConnectionReused checks if the connection for a host will be reused
// Returns true if a usable connection already exists in the pool
func (t *HTTP2Transport) IsConnectionReused(host, port string) bool {
	key := net.JoinHostPort(host, port)
	t.connsMu.RLock()
	conn, exists := t.conns[key]
	t.connsMu.RUnlock()

	if !exists {
		return false
	}
	// If connection exists and is usable, it will be reused
	return t.isConnUsable(conn)
}

// ConnectionSetupTiming reports the measured DNS, TCP and TLS phases for the
// pooled connection serving host:port, in milliseconds.
//
// It exists so the response path can report real numbers instead of the
// fabricated breakdown it used to compute: DNSLookup, TCPConnect and
// TLSHandshake were fixed fractions of FirstByte (0.2, 0.3 and 0.5 of 70% of
// it), which are invented values in a public API field.
//
// ok is false when there is no such connection. A phase that was not separable
// on the path taken, the proxy dial in particular, reports zero, which is the
// value the Timing struct already documents for a phase that did not happen.
func (t *HTTP2Transport) ConnectionSetupTiming(host, port string) (dnsMs, tcpMs, tlsMs float64, ok bool) {
	key := net.JoinHostPort(host, port)
	t.connsMu.RLock()
	conn, exists := t.conns[key]
	t.connsMu.RUnlock()
	if !exists || conn == nil {
		return 0, 0, 0, false
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.dnsMs, conn.tcpMs, conn.tlsMs, true
}

// GetConnectionUseCount returns how many times a connection has been used
func (t *HTTP2Transport) GetConnectionUseCount(host, port string) int64 {
	key := net.JoinHostPort(host, port)
	t.connsMu.RLock()
	conn, exists := t.conns[key]
	t.connsMu.RUnlock()

	if !exists {
		return 0
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.useCount
}

// ConnStats contains connection statistics
type ConnStats struct {
	Host           string
	CreatedAt      time.Time
	LastUsedAt     time.Time
	UseCount       int64
	Age            time.Duration
	IdleTime       time.Duration
	IsReused       bool
	SessionResumed bool   // True if TLS session was resumed
	TLSVersion     uint16 // TLS version (e.g., 0x0304 for TLS 1.3)
	CipherSuite    uint16 // Negotiated cipher suite
}

// GetDNSCache returns the DNS cache
func (t *HTTP2Transport) GetDNSCache() *dns.Cache {
	return t.dnsCache
}

// SetConnectTo sets a host mapping for domain fronting
func (t *HTTP2Transport) SetConnectTo(requestHost, connectHost string) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	if t.config.ConnectTo == nil {
		t.config.ConnectTo = make(map[string]string)
	}
	t.config.ConnectTo[requestHost] = connectHost
}

// SetECHConfigDomain sets a domain to fetch ECH config from
func (t *HTTP2Transport) SetECHConfigDomain(domain string) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfigDomain = domain
}

// SetECHConfig sets a custom ECH configuration
func (t *HTTP2Transport) SetECHConfig(echConfig []byte) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfig = echConfig
}

// getConnectHost returns the connection host for DNS resolution
func (t *HTTP2Transport) getConnectHost(requestHost string) string {
	if t.config == nil || t.config.ConnectTo == nil {
		return requestHost
	}
	if connectHost, ok := t.config.ConnectTo[requestHost]; ok {
		return connectHost
	}
	return requestHost
}

// Connect establishes a connection to the host without making a request.
// This is used for protocol racing - the first protocol to connect wins.
func (t *HTTP2Transport) Connect(ctx context.Context, host, port string) error {
	// Use connect host for pool key (domain fronting: multiple request hosts share one connection)
	connectHost := t.getConnectHost(host)
	key := net.JoinHostPort(connectHost, port)

	// Check if we already have a usable connection
	t.connsMu.RLock()
	if t.closed {
		t.connsMu.RUnlock()
		return fmt.Errorf("http2: transport closed")
	}
	existingConn, exists := t.conns[key]
	t.connsMu.RUnlock()

	if exists && t.isConnUsable(existingConn) {
		return nil // Already connected
	}

	// Create new connection
	conn, err := t.createConn(ctx, host, port)
	if err != nil {
		return err
	}

	// Store connection for reuse
	t.connsMu.Lock()
	if t.closed {
		t.connsMu.Unlock()
		go conn.close()
		return fmt.Errorf("http2: transport closed")
	}
	// Check again in case another goroutine created one
	if oldConn, exists := t.conns[key]; exists {
		// Close the old one if not usable. Deferred, because "not usable for a
		// new request" does not mean nothing is streaming on it.
		if !t.isConnUsable(oldConn) {
			go t.retire(oldConn)
		} else {
			// Old one is still good, close the new one we just created
			go conn.close()
			t.connsMu.Unlock()
			return nil
		}
	}
	t.conns[key] = conn
	t.connsMu.Unlock()

	return nil
}
