package transport

import (
	"bufio"
	"context"
	tls "github.com/sardanioss/utls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	http "github.com/sardanioss/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/proxy"
	utls "github.com/sardanioss/utls"
)

// HTTP1Transport is a custom HTTP/1.1 transport with uTLS fingerprinting
// and connection pooling with keep-alive support
type HTTP1Transport struct {
	preset   *fingerprint.Preset
	dnsCache *dns.Cache
	proxy    *ProxyConfig
	config   *TransportConfig

	// Connection pool
	idleConns   map[string][]*http1Conn
	idleConnsMu sync.Mutex

	// TLS session cache for resumption
	sessionCache utls.ClientSessionCache

	// Configuration
	maxIdleConnsPerHost int
	maxIdleTime         time.Duration
	connectTimeout      time.Duration
	responseTimeout     time.Duration
	insecureSkipVerify  bool
	localAddr           string // Local IP to bind outgoing connections

	// Cleanup
	stopCleanup chan struct{}
	closed      bool
	closedMu    sync.RWMutex
}

// http1Conn represents a persistent HTTP/1.1 connection
type http1Conn struct {
	host       string
	port       string
	conn       net.Conn
	tlsConn    *utls.UConn
	br         *bufio.Reader
	bw         *bufio.Writer
	createdAt  time.Time
	lastUsedAt time.Time
	useCount   int64
	mu         sync.Mutex
	closed     bool
}

// NewHTTP1Transport creates a new HTTP/1.1 transport with uTLS
func NewHTTP1Transport(preset *fingerprint.Preset, dnsCache *dns.Cache) *HTTP1Transport {
	return NewHTTP1TransportWithConfig(preset, dnsCache, nil, nil)
}

// NewHTTP1TransportWithProxy creates a new HTTP/1.1 transport with optional proxy
func NewHTTP1TransportWithProxy(preset *fingerprint.Preset, dnsCache *dns.Cache, proxy *ProxyConfig) *HTTP1Transport {
	return NewHTTP1TransportWithConfig(preset, dnsCache, proxy, nil)
}

// NewHTTP1TransportWithConfig creates a new HTTP/1.1 transport with proxy and config
func NewHTTP1TransportWithConfig(preset *fingerprint.Preset, dnsCache *dns.Cache, proxy *ProxyConfig, config *TransportConfig) *HTTP1Transport {
	// Create session cache - with optional distributed backend
	var sessionCache *PersistableSessionCache
	if config != nil && config.SessionCacheBackend != nil {
		sessionCache = NewPersistableSessionCacheWithBackend(
			config.SessionCacheBackend,
			preset.Name,
			"h1",
			config.SessionCacheErrorCallback,
		)
	} else {
		sessionCache = NewPersistableSessionCache()
	}

	t := &HTTP1Transport{
		preset:              preset,
		dnsCache:            dnsCache,
		proxy:               proxy,
		config:              config,
		idleConns:           make(map[string][]*http1Conn),
		sessionCache:        sessionCache,
		maxIdleConnsPerHost: 6, // Browser-like limit
		maxIdleTime:         90 * time.Second,
		connectTimeout:      30 * time.Second,
		responseTimeout:     60 * time.Second,
		stopCleanup:         make(chan struct{}),
	}

	// Apply localAddr from config
	if config != nil && config.LocalAddr != "" {
		t.localAddr = config.LocalAddr
	}

	go t.cleanupLoop()

	return t
}

// SetConnectTo sets a host mapping for domain fronting
func (t *HTTP1Transport) SetConnectTo(requestHost, connectHost string) {
	if t.config == nil {
		t.config = &TransportConfig{}
	}
	if t.config.ConnectTo == nil {
		t.config.ConnectTo = make(map[string]string)
	}
	t.config.ConnectTo[requestHost] = connectHost
}

// getConnectHost returns the connection host for DNS resolution
func (t *HTTP1Transport) getConnectHost(requestHost string) string {
	if t.config == nil || t.config.ConnectTo == nil {
		return requestHost
	}
	if connectHost, ok := t.config.ConnectTo[requestHost]; ok {
		return connectHost
	}
	return requestHost
}

// SetInsecureSkipVerify sets whether to skip TLS verification
func (t *HTTP1Transport) SetInsecureSkipVerify(skip bool) {
	t.insecureSkipVerify = skip
}

// SetLocalAddr sets the local IP address for outgoing connections
func (t *HTTP1Transport) SetLocalAddr(addr string) {
	t.localAddr = addr
}

// RoundTrip implements http.RoundTripper
func (t *HTTP1Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		return nil, &TransportError{
			Op:       "roundtrip",
			Host:     req.URL.Hostname(),
			Protocol: "h1",
			Cause:    ErrClosed,
			Category: ErrClosed,
		}
	}
	t.closedMu.RUnlock()

	host := req.URL.Hostname()
	port := req.URL.Port()
	scheme := req.URL.Scheme

	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Use connect host for pool key (domain fronting: multiple request hosts share one connection)
	connectHost := t.getConnectHost(host)
	key := fmt.Sprintf("%s://%s:%s", scheme, connectHost, port)

	// Try to get an idle connection
	conn, err := t.getIdleConn(key)
	if err == nil && conn != nil {
		resp, err := t.doRequest(conn, req)
		if err == nil {
			// Wrap the body to handle connection lifecycle
			// Connection will be returned to pool or closed when body is fully read
			resp.Body = &pooledBodyWrapper{
				body:        resp.Body,
				conn:        conn,
				key:         key,
				transport:   t,
				keepAlive:   t.shouldKeepAlive(req, resp),
			}
			return resp, nil
		}
		// Connection failed, close it and try new one
		conn.close()
	}

	// Create new connection (pass request host for SNI, connectHost used internally for DNS)
	conn, err = t.createConn(req.Context(), host, port, scheme)
	if err != nil {
		return nil, err
	}

	resp, err := t.doRequest(conn, req)
	if err != nil {
		conn.close()
		return nil, WrapError("request", host, port, "h1", err)
	}

	// Wrap the body to handle connection lifecycle
	resp.Body = &pooledBodyWrapper{
		body:        resp.Body,
		conn:        conn,
		key:         key,
		transport:   t,
		keepAlive:   t.shouldKeepAlive(req, resp),
	}

	return resp, nil
}

// RoundTripWithTLSConn performs an HTTP/1.1 request using an existing TLS connection.
// This is used when ALPN negotiation results in HTTP/1.1 instead of HTTP/2,
// allowing the TLS connection to be reused instead of creating a new one.
// The connection will be closed after the request (not pooled) since it came from H2 transport.
func (t *HTTP1Transport) RoundTripWithTLSConn(req *http.Request, tlsConn *utls.UConn, host, port string) (*http.Response, error) {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		tlsConn.Close()
		return nil, &TransportError{
			Op:       "roundtrip_with_conn",
			Host:     host,
			Protocol: "h1",
			Cause:    ErrClosed,
			Category: ErrClosed,
		}
	}
	t.closedMu.RUnlock()

	// Wrap the existing TLS connection into an http1Conn
	conn := &http1Conn{
		host:       host,
		port:       port,
		conn:       tlsConn,
		tlsConn:    tlsConn,
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
		br:         bufio.NewReaderSize(tlsConn, 64*1024),  // 64KB read buffer
		bw:         bufio.NewWriterSize(tlsConn, 256*1024), // 256KB write buffer
	}

	resp, err := t.doRequest(conn, req)
	if err != nil {
		conn.close()
		return nil, WrapError("request", host, port, "h1", err)
	}

	// Wrap the body to close connection when done (not pooled since it came from H2 attempt)
	resp.Body = &streamBodyWrapper{
		body: resp.Body,
		conn: conn,
	}

	return resp, nil
}

// pooledBodyWrapper wraps response body to return connection to pool when done.
// Uses sync.Once to safely handle concurrent Read(EOF) and Close().
type pooledBodyWrapper struct {
	body      io.ReadCloser
	conn      *http1Conn
	key       string
	transport *HTTP1Transport
	keepAlive bool
	once      sync.Once
}

func (w *pooledBodyWrapper) Read(p []byte) (n int, err error) {
	n, err = w.body.Read(p)
	if err == io.EOF {
		w.handleClose()
	}
	return n, err
}

func (w *pooledBodyWrapper) Close() error {
	// Close body first to drain remaining data, THEN return conn to pool.
	// Reversing this order causes a race: conn goes back to pool while
	// body.Close() is still draining from the same underlying bufio.Reader.
	err := w.body.Close()
	if err != nil {
		// Body drain failed (e.g., deadline hit on large response).
		// Connection's bufio.Reader is mid-body — don't pool it.
		w.once.Do(func() { w.conn.close() })
		return err
	}
	w.handleClose()
	return nil
}

func (w *pooledBodyWrapper) handleClose() {
	w.once.Do(func() {
		// Clear deadline before returning conn to pool — the next request
		// will set its own deadline. Without this, the stale deadline from
		// the previous request would fire during the next request's I/O.
		w.conn.conn.SetDeadline(time.Time{})
		if w.keepAlive {
			w.transport.putIdleConn(w.key, w.conn)
		} else {
			w.conn.close()
		}
	})
}

// streamBodyWrapper wraps response body to close connection when body is closed
type streamBodyWrapper struct {
	body io.ReadCloser
	conn *http1Conn
}

func (w *streamBodyWrapper) Read(p []byte) (n int, err error) {
	return w.body.Read(p)
}

func (w *streamBodyWrapper) Close() error {
	err := w.body.Close()
	w.conn.close()
	return err
}

// StreamRoundTrip performs an HTTP request for streaming - connection is NOT pooled
// The connection will be closed when the response body is closed
func (t *HTTP1Transport) StreamRoundTrip(req *http.Request) (*http.Response, error) {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		return nil, &TransportError{
			Op:       "stream_roundtrip",
			Host:     req.URL.Hostname(),
			Protocol: "h1",
			Cause:    ErrClosed,
			Category: ErrClosed,
		}
	}
	t.closedMu.RUnlock()

	host := req.URL.Hostname()
	port := req.URL.Port()
	scheme := req.URL.Scheme

	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Create new connection (don't use pool for streaming)
	conn, err := t.createConn(req.Context(), host, port, scheme)
	if err != nil {
		return nil, err
	}

	resp, err := t.doRequest(conn, req)
	if err != nil {
		conn.close()
		return nil, WrapError("stream_request", host, port, "h1", err)
	}

	// Wrap the response body to close connection when body is closed
	resp.Body = &streamBodyWrapper{
		body: resp.Body,
		conn: conn,
	}

	return resp, nil
}

// createConn creates a new HTTP/1.1 connection
// host is the request host (used for TLS SNI), DNS resolution uses getConnectHost
func (t *HTTP1Transport) createConn(ctx context.Context, host, port, scheme string) (*http1Conn, error) {
	var rawConn net.Conn
	var err error

	// Use connect host for DNS resolution and proxy CONNECT (may differ for domain fronting)
	connectHost := t.getConnectHost(host)
	targetAddr := net.JoinHostPort(connectHost, port)

	if t.proxy != nil && t.proxy.URL != "" {
		rawConn, err = t.dialThroughProxy(ctx, connectHost, port)
		if err != nil {
			return nil, NewProxyError("dial_proxy", host, port, err)
		}
	} else {
		// Direct connection with DNS resolution and IPv4/IPv6 fallback
		// Resolve connectHost (may be different from request host for domain fronting)
		ips, err := t.dnsCache.ResolveAllSorted(ctx, connectHost)
		if err != nil {
			return nil, NewDNSError(host, err)
		}
		if len(ips) == 0 {
			return nil, NewDNSError(host, fmt.Errorf("no IP addresses found"))
		}

		dialer := &net.Dialer{
			Timeout:   t.connectTimeout,
			KeepAlive: 30 * time.Second,
		}
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
					return nil, NewDNSError(host, fmt.Errorf("no %s addresses found for host (local address is %s)", family, t.localAddr))
				}
			}
		}

		// Try each IP address in order (preferred first based on PreferIPv4 setting)
		var lastErr error
		for _, ip := range ips {
			network := "tcp4"
			if ip.To4() == nil {
				network = "tcp6"
			}
			addr := net.JoinHostPort(ip.String(), port)

			rawConn, err = dialer.DialContext(ctx, network, addr)
			if err == nil {
				break // Connection successful
			}
			lastErr = err
		}

		if rawConn == nil {
			if lastErr != nil {
				return nil, NewConnectionError("dial", host, port, "h1", lastErr)
			}
			return nil, NewConnectionError("dial", host, port, "h1", fmt.Errorf("all connection attempts failed"))
		}
	}

	// Set TCP options
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
	}

	conn := &http1Conn{
		host:       host,
		port:       port,
		conn:       rawConn,
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
	}

	// For HTTPS, wrap with uTLS
	if scheme == "https" {
		// Determine key log writer - config override or global
		var keyLogWriter io.Writer
		if t.config != nil && t.config.KeyLogWriter != nil {
			keyLogWriter = t.config.KeyLogWriter
		} else {
			keyLogWriter = GetKeyLogWriter()
		}

		tlsConfig := &utls.Config{
			ServerName:                         host,
			InsecureSkipVerify:                 t.insecureSkipVerify,
			MinVersion:                         tls.VersionTLS12,
			MaxVersion:                         tls.VersionTLS13,
			NextProtos:                         []string{"http/1.1"}, // Force HTTP/1.1 only
			PreferSkipResumptionOnNilExtension: true,                 // Skip resumption if spec has no PSK extension
			KeyLogWriter:                       keyLogWriter,
		}
		// Only set session cache when not using custom JA3 without PSK extension
		if t.config == nil || t.config.CustomJA3 == "" || ja3HasExtension(t.config.CustomJA3, "41") {
			tlsConfig.ClientSessionCache = t.sessionCache
		}

		// Create TLS connection with appropriate fingerprint
		var tlsConn *utls.UConn
		if t.config != nil && t.config.CustomJA3 != "" {
			// Custom JA3: parse to spec and apply with HelloCustom
			spec, parseErr := fingerprint.ParseJA3(t.config.CustomJA3, t.config.CustomJA3Extras)
			if parseErr != nil {
				rawConn.Close()
				return nil, NewTLSError("parse_ja3", host, port, "h1", parseErr)
			}
			// Force HTTP/1.1 ALPN in the spec
			for _, ext := range spec.Extensions {
				if alpn, ok := ext.(*utls.ALPNExtension); ok {
					alpn.AlpnProtocols = []string{"http/1.1"}
					break
				}
			}
			tlsConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
			if err := tlsConn.ApplyPreset(spec); err != nil {
				rawConn.Close()
				return nil, NewTLSError("apply_ja3_preset", host, port, "h1", err)
			}
		} else {
			// Use preset's ClientHelloID directly
			// Note: ClientHelloID includes ALPN with [h2, http/1.1], so we must modify it
			tlsConn = utls.UClient(rawConn, tlsConfig, t.preset.ClientHelloID)
			tlsConn.SetSessionCache(t.sessionCache)

			// Build handshake state first - this populates Extensions from ClientHelloID
			if err := tlsConn.BuildHandshakeState(); err != nil {
				rawConn.Close()
				return nil, NewTLSError("build_handshake", host, port, "h1", err)
			}

			// Force HTTP/1.1 only ALPN to prevent h2 negotiation
			// Must be done AFTER BuildHandshakeState() which generates the extensions
			for _, ext := range tlsConn.Extensions {
				if alpn, ok := ext.(*utls.ALPNExtension); ok {
					alpn.AlpnProtocols = []string{"http/1.1"}
					break
				}
			}
		}
		// Only set session cache for preset path or custom JA3 with PSK extension.
		// Setting session cache on a spec without PSK extension can cause handshake failures.
		if t.config == nil || t.config.CustomJA3 == "" || ja3HasExtension(t.config.CustomJA3, "41") {
			tlsConn.SetSessionCache(t.sessionCache)
		}

		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()

			// Speculative TLS fallback: if the proxy can't handle combined
			// CONNECT+ClientHello, re-dial with blocking CONNECT flow.
			if IsSpeculativeTLSError(err) && t.proxy != nil && t.proxy.URL != "" {
				MarkProxyNoSpeculative(t.proxy.URL)

				rawConn, dialErr := t.dialHTTPProxyBlockingFresh(ctx, connectHost, port)
				if dialErr != nil {
					return nil, NewTLSError("speculative_fallback_dial", host, port, "h1", dialErr)
				}

				// Redo TLS setup on the clean connection
				if t.config != nil && t.config.CustomJA3 != "" {
					spec, parseErr := fingerprint.ParseJA3(t.config.CustomJA3, t.config.CustomJA3Extras)
					if parseErr != nil {
						rawConn.Close()
						return nil, NewTLSError("parse_ja3", host, port, "h1", parseErr)
					}
					for _, ext := range spec.Extensions {
						if alpn, ok := ext.(*utls.ALPNExtension); ok {
							alpn.AlpnProtocols = []string{"http/1.1"}
							break
						}
					}
					tlsConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
					if applyErr := tlsConn.ApplyPreset(spec); applyErr != nil {
						rawConn.Close()
						return nil, NewTLSError("apply_ja3_preset", host, port, "h1", applyErr)
					}
				} else {
					tlsConn = utls.UClient(rawConn, tlsConfig, t.preset.ClientHelloID)
					if buildErr := tlsConn.BuildHandshakeState(); buildErr != nil {
						rawConn.Close()
						return nil, NewTLSError("build_handshake", host, port, "h1", buildErr)
					}
					for _, ext := range tlsConn.Extensions {
						if alpn, ok := ext.(*utls.ALPNExtension); ok {
							alpn.AlpnProtocols = []string{"http/1.1"}
							break
						}
					}
				}
				tlsConn.SetSessionCache(t.sessionCache)
				if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
					rawConn.Close()
					return nil, NewTLSError("tls_handshake", host, port, "h1", hsErr)
				}

				// Update conn to use new rawConn
				conn.conn = rawConn
			} else {
				return nil, NewTLSError("tls_handshake", host, port, "h1", err)
			}
		}

		conn.tlsConn = tlsConn
		conn.conn = tlsConn
	}

	conn.br = bufio.NewReaderSize(conn.conn, 64*1024)  // 64KB read buffer
	conn.bw = bufio.NewWriterSize(conn.conn, 256*1024) // 256KB write buffer for fast uploads

	_ = targetAddr // suppress unused warning

	return conn, nil
}

// dialThroughProxy establishes a connection through a proxy
// Supports both HTTP proxies (HTTP CONNECT) and SOCKS5 proxies (SOCKS5 CONNECT)
func (t *HTTP1Transport) dialThroughProxy(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	// Check if it's a SOCKS5 proxy
	if proxy.IsSOCKS5URL(t.proxy.URL) {
		return t.dialThroughSOCKS5(ctx, targetHost, targetPort)
	}

	// HTTP proxy - use HTTP CONNECT
	return t.dialThroughHTTPProxy(ctx, targetHost, targetPort)
}

// dialThroughSOCKS5 establishes a connection through a SOCKS5 proxy
func (t *HTTP1Transport) dialThroughSOCKS5(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	socks5Dialer, err := proxy.NewSOCKS5Dialer(t.proxy.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}
	if t.localAddr != "" {
		socks5Dialer.SetLocalAddr(t.localAddr)
	}

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
func (t *HTTP1Transport) dialThroughHTTPProxy(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
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

	// Pre-resolve proxy hostname using CGO-compatible resolver
	// Required for shared library usage where Go's pure-Go resolver doesn't work
	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, proxyHost)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxyHost, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxyHost)
	}

	dialer := &net.Dialer{
		Timeout:   t.connectTimeout,
		KeepAlive: 30 * time.Second,
	}
	if t.localAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(t.localAddr)}
	}

	// Dial using resolved IP to avoid DNS lookup in net.Dialer
	proxyAddr := net.JoinHostPort(proxyIPs[0], proxyPort)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	// Build CONNECT request
	targetAddr := net.JoinHostPort(targetHost, targetPort)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	// Add proxy authentication if needed
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
func (t *HTTP1Transport) dialHTTPProxyBlockingFresh(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
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

	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, proxyHost)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxyHost, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxyHost)
	}

	dialer := &net.Dialer{
		Timeout:   t.connectTimeout,
		KeepAlive: 30 * time.Second,
	}
	if t.localAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(t.localAddr)}
	}

	proxyAddr := net.JoinHostPort(proxyIPs[0], proxyPort)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
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
func (t *HTTP1Transport) dialHTTPProxyBlocking(ctx context.Context, conn net.Conn, connectReq string) (net.Conn, error) {
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
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	conn.SetReadDeadline(time.Time{}) // Clear deadline after response
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	// If the bufio.Reader read ahead past the HTTP response (e.g., start of
	// TLS ServerHello arrived in same TCP segment), wrap the conn so those
	// buffered bytes are returned first. Without this, the TLS handshake
	// would miss the beginning of the server's response.
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: io.MultiReader(br, conn)}, nil
	}
	return conn, nil
}

// bufferedConn wraps a net.Conn to first drain any bytes buffered by a
// bufio.Reader before reading from the underlying connection.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// getProxyAuth returns base64-encoded proxy credentials
func (t *HTTP1Transport) getProxyAuth(proxyURL *url.URL) string {
	username := t.proxy.Username
	password := t.proxy.Password

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

// doRequest performs the HTTP request on the connection
func (t *HTTP1Transport) doRequest(conn *http1Conn, req *http.Request) (*http.Response, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.closed {
		return nil, fmt.Errorf("connection closed")
	}

	conn.lastUsedAt = time.Now()
	conn.useCount++

	// Set deadline - use the earlier of context deadline and response timeout
	deadline := time.Now().Add(t.responseTimeout)
	if ctxDeadline, ok := req.Context().Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.conn.SetDeadline(deadline)
	// NOTE: We intentionally do NOT defer clearing the deadline here.
	// The deadline must remain active while the response body is being read
	// (body is returned to caller via pooledBodyWrapper). The deadline is
	// cleared in handleClose() when the body is done and conn returns to pool.

	// Write request
	if err := t.writeRequest(conn, req); err != nil {
		return nil, err
	}

	// Read response
	resp, err := http.ReadResponse(conn.br, req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// writeRequest writes an HTTP/1.1 request with browser-like header ordering
func (t *HTTP1Transport) writeRequest(conn *http1Conn, req *http.Request) error {
	// Request line
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	fmt.Fprintf(conn.bw, "%s %s HTTP/1.1\r\n", req.Method, uri)

	// Host header first (browser behavior)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	fmt.Fprintf(conn.bw, "Host: %s\r\n", host)

	// Determine if we need chunked encoding (unknown content length with body)
	// http.NoBody is an explicit "no body" sentinel — don't use chunked for it
	useChunked := req.Body != nil && req.Body != http.NoBody && req.ContentLength <= 0 && req.Header.Get("Content-Length") == ""

	// Write headers in browser-like order
	t.writeHeadersInOrder(conn.bw, req, useChunked)

	// End headers
	conn.bw.WriteString("\r\n")

	// Flush headers
	if err := conn.bw.Flush(); err != nil {
		return err
	}

	// Write body if present
	if req.Body != nil {
		defer req.Body.Close()
		if useChunked {
			// Write body in chunked encoding
			if err := t.writeChunkedBody(conn.bw, req.Body); err != nil {
				return err
			}
		} else {
			_, err := io.Copy(conn.bw, req.Body)
			if err != nil {
				return err
			}
		}
		if err := conn.bw.Flush(); err != nil {
			return err
		}
	}

	return nil
}

// writeChunkedBody writes the body using chunked transfer encoding
func (t *HTTP1Transport) writeChunkedBody(w *bufio.Writer, body io.Reader) error {
	buf := make([]byte, 32*1024) // 32KB chunks
	for {
		n, err := body.Read(buf)
		if n > 0 {
			// Write chunk size in hex
			fmt.Fprintf(w, "%x\r\n", n)
			// Write chunk data
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			// Write chunk terminator
			if _, werr := w.WriteString("\r\n"); werr != nil {
				return werr
			}
			// Flush each chunk to ensure it's sent
			if ferr := w.Flush(); ferr != nil {
				return ferr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	// Write final chunk (0-length)
	if _, err := w.WriteString("0\r\n\r\n"); err != nil {
		return err
	}
	return nil
}

// canonicalHeaderKey converts a header key to canonical form (e.g., "sec-ch-ua" -> "Sec-Ch-Ua").
// Uses Go's standard textproto.CanonicalMIMEHeaderKey for exact compatibility with http.Header.
func canonicalHeaderKey(s string) string {
	return textproto.CanonicalMIMEHeaderKey(s)
}

// writeHeadersInOrder writes headers in a browser-like order
func (t *HTTP1Transport) writeHeadersInOrder(w *bufio.Writer, req *http.Request, useChunked bool) {
	// Check if custom header order is specified (from preset or user)
	// This allows HTTP/1.1 to respect the same header ordering as H2/H3
	var headerOrder []string
	if customOrder, ok := req.Header[http.HeaderOrderKey]; ok && len(customOrder) > 0 {
		// Use custom/preset header order
		headerOrder = customOrder
	} else {
		// Fallback to browser-like header order for HTTP/1.1
		headerOrder = []string{
			"Connection",
			"Cache-Control",
			"Upgrade-Insecure-Requests",
			"User-Agent",
			"Accept",
			"Accept-Encoding",
			"Accept-Language",
			"Cookie",
			"Referer",
			"Origin",
			"Sec-Fetch-Dest",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Site",
			"Sec-Fetch-User",
			"Content-Type",
			"Content-Length",
			"Transfer-Encoding",
		}
	}

	written := make(map[string]bool)

	// Write headers in preferred order
	for _, key := range headerOrder {
		// Convert to canonical form for map lookup (Go's http.Header uses canonical keys)
		canonicalKey := canonicalHeaderKey(key)

		// Special handling for Content-Length
		if strings.EqualFold(key, "Content-Length") {
			if useChunked {
				// Skip Content-Length when using chunked encoding
				continue
			}
			// First check if header is set
			if values, ok := req.Header[canonicalKey]; ok {
				for _, v := range values {
					fmt.Fprintf(w, "%s: %s\r\n", canonicalKey, v)
				}
				written[canonicalKey] = true
			} else if req.ContentLength > 0 {
				// Fallback to ContentLength field
				fmt.Fprintf(w, "Content-Length: %d\r\n", req.ContentLength)
				written[canonicalKey] = true
			} else if req.ContentLength == 0 && req.Body != nil && !useChunked {
				// Empty body but Body is set (POST/PUT/PATCH with empty body)
				fmt.Fprintf(w, "Content-Length: 0\r\n")
				written[canonicalKey] = true
			}
			continue
		}

		// Special handling for Transfer-Encoding
		if strings.EqualFold(key, "Transfer-Encoding") {
			if useChunked {
				fmt.Fprintf(w, "Transfer-Encoding: chunked\r\n")
				written[canonicalKey] = true
			}
			continue
		}

		// Skip Host - already written before this function is called
		if strings.EqualFold(key, "Host") {
			continue
		}

		// Look up header using canonical key
		if values, ok := req.Header[canonicalKey]; ok {
			for _, v := range values {
				fmt.Fprintf(w, "%s: %s\r\n", canonicalKey, v)
			}
			written[canonicalKey] = true
		}
	}

	// Write remaining headers (not in specified order)
	for key, values := range req.Header {
		// Key from map iteration is already canonical
		if written[key] {
			continue
		}
		// Skip Host (already written) and certain headers
		if strings.EqualFold(key, "Host") {
			continue
		}
		// Skip internal header ordering keys - these are used internally to control
		// header order but MUST NOT be sent to the server
		if key == http.HeaderOrderKey || key == http.PHeaderOrderKey {
			continue
		}
		// Skip Transfer-Encoding and Content-Length if we're handling them specially
		if useChunked && (strings.EqualFold(key, "Transfer-Encoding") || strings.EqualFold(key, "Content-Length")) {
			continue
		}
		for _, v := range values {
			fmt.Fprintf(w, "%s: %s\r\n", key, v)
		}
	}

	// Ensure Content-Length is written when body is present
	// This handles the case where the preset's header order doesn't include content-length
	if !written["Content-Length"] && !useChunked {
		if values, ok := req.Header["Content-Length"]; ok {
			for _, v := range values {
				fmt.Fprintf(w, "Content-Length: %s\r\n", v)
			}
		} else if req.ContentLength > 0 {
			fmt.Fprintf(w, "Content-Length: %d\r\n", req.ContentLength)
		} else if req.ContentLength == 0 && req.Body != nil {
			fmt.Fprintf(w, "Content-Length: 0\r\n")
		}
	}

	// Ensure Transfer-Encoding is written for chunked
	if !written["Transfer-Encoding"] && useChunked {
		fmt.Fprintf(w, "Transfer-Encoding: chunked\r\n")
	}

	// Ensure Connection header
	if _, ok := req.Header["Connection"]; !ok {
		fmt.Fprintf(w, "Connection: keep-alive\r\n")
	}
}

// shouldKeepAlive determines if connection should be reused
func (t *HTTP1Transport) shouldKeepAlive(req *http.Request, resp *http.Response) bool {
	// Check response Connection header
	if strings.EqualFold(resp.Header.Get("Connection"), "close") {
		return false
	}

	// Check request Connection header
	if strings.EqualFold(req.Header.Get("Connection"), "close") {
		return false
	}

	// HTTP/1.1 defaults to keep-alive
	if resp.ProtoMajor == 1 && resp.ProtoMinor >= 1 {
		return true
	}

	// HTTP/1.0 with explicit keep-alive
	if strings.ToLower(resp.Header.Get("Connection")) == "keep-alive" {
		return true
	}

	return false
}

// getIdleConn retrieves an idle connection from the pool
func (t *HTTP1Transport) getIdleConn(key string) (*http1Conn, error) {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	conns := t.idleConns[key]
	if len(conns) == 0 {
		return nil, nil
	}

	// Get the most recently used connection
	conn := conns[len(conns)-1]
	t.idleConns[key] = conns[:len(conns)-1]

	// Check if connection is still valid
	if time.Since(conn.lastUsedAt) > t.maxIdleTime {
		conn.close()
		return nil, nil
	}

	return conn, nil
}

// putIdleConn returns a connection to the pool
func (t *HTTP1Transport) putIdleConn(key string, conn *http1Conn) {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		conn.close()
		return
	}
	t.closedMu.RUnlock()

	conns := t.idleConns[key]
	if len(conns) >= t.maxIdleConnsPerHost {
		// Pool is full, close oldest connection
		oldConn := conns[0]
		conns = conns[1:]
		go oldConn.close()
	}

	conn.lastUsedAt = time.Now()
	t.idleConns[key] = append(conns, conn)
}

// close closes an http1Conn
func (c *http1Conn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	c.closed = true

	if c.tlsConn != nil {
		c.tlsConn.Close()
	} else if c.conn != nil {
		c.conn.Close()
	}
}

// cleanupLoop periodically removes stale connections
func (t *HTTP1Transport) cleanupLoop() {
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
func (t *HTTP1Transport) cleanup() {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	for key, conns := range t.idleConns {
		var active []*http1Conn
		for _, conn := range conns {
			if time.Since(conn.lastUsedAt) > t.maxIdleTime {
				go conn.close()
			} else {
				active = append(active, conn)
			}
		}
		if len(active) > 0 {
			t.idleConns[key] = active
		} else {
			delete(t.idleConns, key)
		}
	}
}

// Close shuts down the transport
func (t *HTTP1Transport) Close() {
	t.closedMu.Lock()
	if t.closed {
		t.closedMu.Unlock()
		return
	}
	t.closed = true
	t.closedMu.Unlock()

	close(t.stopCleanup)

	t.idleConnsMu.Lock()
	for _, conns := range t.idleConns {
		for _, conn := range conns {
			go conn.close()
		}
	}
	t.idleConns = nil
	t.idleConnsMu.Unlock()
}

// Refresh closes all connections but keeps the TLS session cache intact.
// This simulates a browser page refresh - new TCP connections but TLS resumption.
func (t *HTTP1Transport) Refresh() {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		return
	}
	t.closedMu.RUnlock()

	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	// Close all idle connections
	for _, conns := range t.idleConns {
		for _, conn := range conns {
			go conn.close()
		}
	}
	// Reset the map but keep session cache
	t.idleConns = make(map[string][]*http1Conn)
}

// SetProxy changes the proxy configuration and closes all existing connections
// HTTP/1.1 connections are short-lived, but we close idle ones for cleanliness
func (t *HTTP1Transport) SetProxy(proxy *ProxyConfig) {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	// Close all idle connections - they're using the old proxy
	for _, conns := range t.idleConns {
		for _, conn := range conns {
			go conn.close()
		}
	}
	t.idleConns = make(map[string][]*http1Conn)

	// Update proxy configuration
	t.proxy = proxy
}

// GetProxy returns the current proxy configuration
func (t *HTTP1Transport) GetProxy() *ProxyConfig {
	return t.proxy
}

// GetSessionCache returns the TLS session cache
func (t *HTTP1Transport) GetSessionCache() utls.ClientSessionCache {
	return t.sessionCache
}

// SetSessionCache sets the TLS session cache
func (t *HTTP1Transport) SetSessionCache(cache utls.ClientSessionCache) {
	t.sessionCache = cache
}

// Stats returns transport statistics
func (t *HTTP1Transport) Stats() map[string]HTTP1ConnStats {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	stats := make(map[string]HTTP1ConnStats)
	for key, conns := range t.idleConns {
		var totalUseCount int64
		var oldestCreated time.Time
		var newestUsed time.Time

		for _, conn := range conns {
			conn.mu.Lock()
			totalUseCount += conn.useCount
			if oldestCreated.IsZero() || conn.createdAt.Before(oldestCreated) {
				oldestCreated = conn.createdAt
			}
			if conn.lastUsedAt.After(newestUsed) {
				newestUsed = conn.lastUsedAt
			}
			conn.mu.Unlock()
		}

		stats[key] = HTTP1ConnStats{
			IdleConns:      len(conns),
			TotalUseCount:  totalUseCount,
			OldestCreated:  oldestCreated,
			NewestLastUsed: newestUsed,
		}
	}

	return stats
}

// HTTP1ConnStats contains HTTP/1.1 connection statistics
type HTTP1ConnStats struct {
	IdleConns      int
	TotalUseCount  int64
	OldestCreated  time.Time
	NewestLastUsed time.Time
}

// GetDNSCache returns the DNS cache
func (t *HTTP1Transport) GetDNSCache() *dns.Cache {
	return t.dnsCache
}
