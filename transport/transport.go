package transport

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	http "github.com/sardanioss/http"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
)

// Protocol represents the HTTP protocol version
type Protocol int

const (
	// ProtocolAuto automatically selects the best protocol (H3 -> H2 -> H1)
	ProtocolAuto Protocol = iota
	// ProtocolHTTP1 forces HTTP/1.1 over TCP
	ProtocolHTTP1
	// ProtocolHTTP2 forces HTTP/2 over TCP
	ProtocolHTTP2
	// ProtocolHTTP3 forces HTTP/3 over QUIC
	ProtocolHTTP3
)

// Buffer pools for high-performance body reading
// Tiered pools minimize memory waste for different response sizes
var (
	// Pool for bodies up to 1MB
	bodyPool1MB = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 1*1024*1024)
			return &buf
		},
	}
	// Pool for bodies up to 10MB
	bodyPool10MB = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 10*1024*1024)
			return &buf
		},
	}
	// Pool for bodies up to 100MB
	bodyPool100MB = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 100*1024*1024)
			return &buf
		},
	}
)

// getPooledBuffer gets a buffer from the appropriate pool based on size
func getPooledBuffer(size int64) (*[]byte, func()) {
	if size <= 1*1024*1024 {
		buf := bodyPool1MB.Get().(*[]byte)
		return buf, func() { bodyPool1MB.Put(buf) }
	}
	if size <= 10*1024*1024 {
		buf := bodyPool10MB.Get().(*[]byte)
		return buf, func() { bodyPool10MB.Put(buf) }
	}
	if size <= 100*1024*1024 {
		buf := bodyPool100MB.Get().(*[]byte)
		return buf, func() { bodyPool100MB.Put(buf) }
	}
	// For very large bodies, allocate directly (rare case)
	buf := make([]byte, size)
	return &buf, func() {} // No-op release for non-pooled buffers
}

// String returns the string representation of the protocol
func (p Protocol) String() string {
	switch p {
	case ProtocolAuto:
		return "auto"
	case ProtocolHTTP1:
		return "h1"
	case ProtocolHTTP2:
		return "h2"
	case ProtocolHTTP3:
		return "h3"
	default:
		return "unknown"
	}
}

// ProxyConfig contains proxy server configuration
type ProxyConfig struct {
	URL      string // Proxy URL (e.g., "http://proxy:8080" or "http://user:pass@proxy:8080")
	Username string // Proxy username (optional, can also be in URL)
	Password string // Proxy password (optional, can also be in URL)

	// TCPProxy is the proxy URL for TCP-based protocols (HTTP/1.1 and HTTP/2)
	// When set, overrides URL for TCP transports
	TCPProxy string

	// UDPProxy is the proxy URL for UDP-based protocols (HTTP/3 via MASQUE)
	// When set, overrides URL for UDP transports
	UDPProxy string
}

// TransportConfig contains advanced transport configuration
type TransportConfig struct {
	// ConnectTo maps request hosts to connection hosts (domain fronting).
	// Key: request host, Value: connection host for DNS resolution
	ConnectTo map[string]string

	// ECHConfig is a custom ECH configuration (overrides DNS fetch)
	ECHConfig []byte

	// ECHConfigDomain is a domain to fetch ECH config from instead of target
	ECHConfigDomain string

	// TLSOnly mode: use TLS fingerprint but skip preset HTTP headers
	// User sets all headers manually
	TLSOnly bool

	// QuicIdleTimeout is the idle timeout for QUIC connections (default: 30s)
	QuicIdleTimeout time.Duration

	// LocalAddr is the local IP address to bind outgoing connections to.
	// Used for IPv6 rotation with IP_FREEBIND on Linux.
	LocalAddr string

	// SessionCacheBackend is an optional distributed cache for TLS sessions.
	// When set, TLS session tickets will be stored/retrieved from this backend,
	// enabling session sharing across multiple instances.
	SessionCacheBackend SessionCacheBackend

	// SessionCacheErrorCallback is called when backend operations fail.
	// This is optional but recommended for monitoring backend health.
	SessionCacheErrorCallback ErrorCallback

	// KeyLogWriter is an optional writer for TLS key logging.
	// When set, TLS master secrets are written in NSS key log format
	// for traffic decryption in Wireshark.
	// If nil, falls back to GetKeyLogWriter() (SSLKEYLOGFILE env var).
	KeyLogWriter io.Writer

	// EnableSpeculativeTLS enables the speculative TLS optimization for proxy connections.
	// When true, CONNECT request and TLS ClientHello are sent together, saving one
	// round-trip. Disabled by default due to compatibility issues with some proxies.
	EnableSpeculativeTLS bool

	// CustomJA3 is a JA3 fingerprint string to use instead of the preset's TLS fingerprint.
	// Format: TLSVersion,CipherSuites,Extensions,EllipticCurves,PointFormats
	// When set, the preset's ClientHelloID is overridden with HelloCustom.
	// Not applied to H3 (QUIC TLS uses different extensions).
	CustomJA3 string

	// CustomJA3Extras provides extension data that JA3 cannot capture (e.g., signature
	// algorithms, ALPN). If nil, sensible Chrome-like defaults are used.
	CustomJA3Extras *fingerprint.JA3Extras

	// CustomH2Settings overrides the preset's HTTP/2 settings (from Akamai fingerprint).
	CustomH2Settings *fingerprint.HTTP2Settings

	// CustomPseudoOrder overrides the pseudo-header order (from Akamai fingerprint).
	// Values: [":method", ":authority", ":scheme", ":path"]
	CustomPseudoOrder []string

	// CustomTCPFingerprint overrides individual TCP/IP fingerprint fields from the preset.
	// Only non-zero fields are applied; zero fields keep the preset default.
	CustomTCPFingerprint *fingerprint.TCPFingerprint
}

// Request represents an HTTP request
type Request struct {
	Method     string
	URL        string
	Headers    map[string][]string // Multi-value headers (matches http.Header)
	Body       []byte
	BodyReader io.Reader // For streaming uploads - used instead of Body if set

	// GetBody returns a fresh reader over the same body for a request that has
	// to go on the wire more than once: a 307/308 redirect hop, or a retried
	// attempt. Nil means the body cannot be re-opened.
	//
	// Mirrors net/http.Request.GetBody with one deliberate difference: it
	// returns io.Reader, not io.ReadCloser. The value is handed straight to
	// http.NewRequestWithContext, and it is that function's in-memory type
	// switch (*bytes.Reader, *bytes.Buffer, *strings.Reader) that sets
	// ContentLength. An io.NopCloser wrapper hides the concrete type, so
	// ContentLength stays 0, outgoingLength maps that to -1, and the request
	// goes out chunked — a wire shape no browser produces for a form POST, and
	// one the first hop of the same chain did not use.
	//
	// Body []byte needs no GetBody: the transport builds a fresh bytes.Reader
	// over it on every Do. For BodyReader, the session derives one at the first
	// hop via DeriveGetBody for the in-memory reader types; set it yourself for
	// anything else (an *os.File, a multipart pipe) if the request may be
	// replayed.
	GetBody func() (io.Reader, error)

	Timeout time.Duration

	// ExactHeaders, when non-empty, replaces the whole header pipeline for this
	// request. The pairs go on the wire in the order and the casing given, a
	// name may repeat, and nothing else is added: no preset header block, no
	// client hints, no Sec-Fetch inference, no alphabetical tail for names the
	// preset does not know.
	//
	// It exists because the normal path is opinionated in three ways that a
	// mirror cannot live with. It always injects the preset block, it appends
	// unknown caller headers sorted alphabetically at the end, and it
	// canonicalises casing through http.Header.Set. On top of that a
	// map[string][]string cannot express two headers of the same name in a
	// chosen position relative to other names.
	//
	// This is a deliberate escape hatch, not the default. A caller using it
	// takes on responsibility for the entire request shape, including the
	// headers a browser would always send.
	//
	// Two things are still written for you, because they are protocol framing
	// rather than caller headers: Host and Connection on HTTP/1.1, and the
	// pseudo-header block on HTTP/2 and HTTP/3. Suppressing Connection would
	// break keep-alive, and Chrome sends it on every H1 request anyway.
	ExactHeaders []fingerprint.HeaderPair

	// TLSOnly is a per-request override for TLS-only mode.
	// When set to true, preset HTTP headers are NOT applied - only TLS fingerprinting is used.
	// When nil, the transport's TLSOnly setting is used.
	// This is useful for LocalProxy where each request can have different TLS-only settings
	// via the X-HTTPCloak-TlsOnly header.
	TLSOnly *bool

	// FollowRedirects, when non-nil, overrides the session's follow-redirects
	// policy for this single request. Session-layer concept; the transport
	// itself does not consult this field.
	FollowRedirects *bool

	// DisableConditionalCache, when true, instructs the session layer to skip
	// injection of If-None-Match / If-Modified-Since headers from the session's
	// per-URL cache for this request AND to skip storing any ETag / Last-Modified
	// from the response. Session-layer concept; the transport itself does not
	// consult this field.
	DisableConditionalCache bool

	// DisableClientHints, when true, strips ALL preset UA client hints for this
	// request: the always-on sec-ch-ua / sec-ch-ua-mobile / sec-ch-ua-platform
	// trio is not applied by the transport, and the session layer skips the
	// high-entropy hints too. Headers the caller sets explicitly still pass
	// through (the user-override loop runs after the preset headers). The session
	// also sets this when client hints are disabled session-wide.
	DisableClientHints bool

	// DisableHighEntropyClientHints, when true, keeps the always-on sec-ch-ua
	// trio but tells the session layer to skip the high-entropy hints for this
	// request. Session-layer concept; the transport does not consult this field.
	DisableHighEntropyClientHints bool

	// HeaderOrder, when non-empty, is the header order for THIS request only and
	// fully replaces any order installed session-wide with SetHeaderOrder. It is
	// read from the request, never from shared state, so concurrent requests can
	// each carry their own order without locking the transport.
	//
	// Same semantics as SetHeaderOrder: the list is a prefix, not a whole-request
	// replacement. Names you list are emitted first, in this order; every header
	// you leave out still falls back to the preset's position table and then to a
	// stable sorted tail — see CompleteHeaderOrder. Naming every header you send
	// therefore gives you the exact wire order. Names are case-insensitive.
	//
	// An empty or nil slice means "no per-request order": the session-wide order
	// applies. There is no per-request way to say "ignore the session order and
	// use the bare preset"; pass the preset's own order (Session.GetHeaderOrder
	// with no custom order set) if you need that.
	//
	// The transport applies this to exactly the request it is set on; it has no
	// concept of a redirect. The session layer, which does, copies it onto the
	// follow-up request it builds for each hop, matching how it replays the
	// caller's headers.
	HeaderOrder []string

	// OnRedirect, when non-nil, is called once per redirect hop before the
	// follow-up request is built. Returning nil follows the hop; returning
	// ErrUseLastResponse stops the chain and returns the 3xx itself with a nil
	// error; any other error fails the request with that error unwrapped, so
	// errors.Is against your own sentinel matches.
	//
	// This exists because both alternatives lose something. Turning redirects
	// off hands you the entire chain to re-implement, cookie jar and header
	// scrubbing included. Reading Response.History afterwards is too late: the
	// request to the host you meant to block has already gone out.
	//
	// The hop is deliberately read-only. A callback able to rewrite the target
	// would sit upstream of the scheme and origin scrubbing, which is the part
	// that keeps Authorization from following a hop off-origin.
	//
	// Not called for a 3xx with no Location (there is no hop to veto), nor for
	// the hop that would exceed the redirect cap, nor from the streaming path,
	// which does not follow redirects at all. It runs on the calling goroutine
	// between hops, so it must not block and must not re-enter the same session.
	//
	// Session-layer concept; the transport itself does not consult this field.
	OnRedirect func(*Redirect) error
}

// ErrUseLastResponse, returned from a Request.OnRedirect callback, stops the
// redirect chain and hands the 3xx back to the caller with a nil error, exactly
// as if redirects had been off for that hop. Any other non-nil error from the
// callback fails the request instead.
//
// Shaped after net/http.ErrUseLastResponse so the semantics transfer. The
// response body is buffered and still yours to read.
var ErrUseLastResponse = errors.New("httpcloak/transport: use last response")

// Redirect describes one hop the chain is about to take. It is passed to
// Request.OnRedirect before the follow-up request is built.
//
// Read-only in both directions: mutating a field does not retarget the hop, and
// Headers aliases the 3xx response's own header map, so writing to it corrupts
// the redirect history the caller gets back. The value is valid only for the
// duration of the callback; copy anything you keep.
type Redirect struct {
	// Hop counts this redirect in the chain, starting at 1. It never exceeds the
	// redirect cap: the cap is checked before the callback runs, so a chain about
	// to be rejected for length fails with ErrTooManyRedirects rather than asking
	// first — otherwise a veto could quietly turn that error into a success.
	Hop int

	// StatusCode is the 3xx that triggered this hop.
	StatusCode int

	// Headers are the 3xx response's headers. This is the only place to read a
	// Set-Cookie or a routing header that the final response will not carry.
	//
	// Keys are lowercase, matching Response.Headers, so index it as
	// Headers["set-cookie"] or use GetHeader / GetHeaders, which lowercase for
	// you. Headers["Set-Cookie"] returns nothing.
	Headers map[string][]string

	// From is the absolute URL of the request that produced the 3xx.
	From string

	// To is the Location header resolved against From. Use ToURL rather than
	// substring-matching this: strings.Contains(To, "example.com") also passes
	// for https://example.com.attacker.test, which is the exact hop a veto is
	// usually written to stop.
	To string

	// Method is the method the next hop will use, after the 301/302/303
	// POST-to-GET rewrite. Compare it against your own to catch a hop that
	// silently drops the body.
	Method string

	// CrossOrigin reports a change of scheme, host or port, using the same
	// comparison the library itself uses to decide whether to strip
	// Authorization on this hop.
	CrossOrigin bool

	// SchemeDowngrade reports an https -> http hop. It always implies CrossOrigin.
	SchemeDowngrade bool
}

// ToURL parses To. A method rather than a *url.URL field because parsing costs
// an allocation on every hop and almost no request installs a callback at all.
func (r *Redirect) ToURL() (*url.URL, error) {
	return url.Parse(r.To)
}

// GetHeader returns the first value of the named 3xx response header, or "".
// Case-insensitive, so GetHeader("Set-Cookie") works where the raw map needs
// the lowercase key. Same shape as Response.GetHeader.
func (r *Redirect) GetHeader(key string) string {
	if values := r.Headers[strings.ToLower(key)]; len(values) > 0 {
		return values[0]
	}
	return ""
}

// GetHeaders returns every value of the named 3xx response header.
// Case-insensitive. Use this one for Set-Cookie, which legitimately repeats.
func (r *Redirect) GetHeaders(key string) []string {
	return r.Headers[strings.ToLower(key)]
}

// RedirectInfo contains information about a redirect response
type RedirectInfo struct {
	StatusCode int
	URL        string
	Headers    map[string][]string // Multi-value headers
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Headers    map[string][]string // Multi-value headers (matches http.Header)
	Body       io.ReadCloser       // Streaming body - call Close() when done
	FinalURL   string
	Timing     *protocol.Timing
	Protocol   string // "h1", "h2", or "h3"
	History    []*RedirectInfo

	// bodyBytes caches the body after reading for multiple access
	bodyBytes []byte
	bodyRead  bool
}

// Close closes the response body.
// Should be called when done reading the body.
func (r *Response) Close() error {
	if r.Body != nil {
		return r.Body.Close()
	}
	return nil
}

// GetHeader returns the first value for the given header key (case-insensitive).
// Use GetHeaders() for multi-value headers like Set-Cookie.
func (r *Response) GetHeader(key string) string {
	if values := r.Headers[strings.ToLower(key)]; len(values) > 0 {
		return values[0]
	}
	return ""
}

// GetHeaders returns all values for the given header key (case-insensitive).
func (r *Response) GetHeaders(key string) []string {
	return r.Headers[strings.ToLower(key)]
}

// ErrNoLocation is returned by Response.Location when the response has no
// Location header.
var ErrNoLocation = errors.New("httpcloak/transport: no Location header in response")

// ErrBodyNotReplayable is returned when a request has to be sent again — a
// 307/308 hop — but its body is a one-shot stream with no Request.GetBody to
// re-open it. Sending the hop anyway would put an empty body on the wire under
// the caller's Content-Type, which is silent data loss, so the hop is refused
// instead. The 3xx is returned alongside the error, so a caller can read its
// Location and drive the rest of the chain itself.
var ErrBodyNotReplayable = errors.New("httpcloak/transport: request body is not replayable (set Request.GetBody)")

// ErrTooManyRedirects is returned when a chain exceeds the configured cap. The
// response carrying the last Location is returned alongside it, so a caller can
// see where the chain ended up rather than only that it was too long.
var ErrTooManyRedirects = errors.New("httpcloak/transport: too many redirects")

// DeriveGetBody returns a GetBody for the in-memory reader types, and nil for
// anything else. The three cases are exactly net/http.NewRequestWithContext's:
// a value copy of *bytes.Reader / *strings.Reader snapshots the current read
// offset without copying the data, and *bytes.Buffer snapshots the remaining
// bytes. Call it before anything reads r.
//
// There is deliberately no io.Seeker case, matching net/http: seeking a reader
// you do not own is not safe, and the concrete type would still fall outside
// NewRequestWithContext's ContentLength switch, so the replayed hop would go out
// chunked while the first one did not.
func DeriveGetBody(r io.Reader) func() (io.Reader, error) {
	switch v := r.(type) {
	case *bytes.Buffer:
		buf := v.Bytes()
		return func() (io.Reader, error) { return bytes.NewReader(buf), nil }
	case *bytes.Reader:
		snapshot := *v
		return func() (io.Reader, error) { r := snapshot; return &r, nil }
	case *strings.Reader:
		snapshot := *v
		return func() (io.Reader, error) { r := snapshot; return &r, nil }
	}
	return nil
}

// Location returns the URL of the response's "Location" header, if present.
// A relative Location is resolved against the URL of the request that produced
// the response (FinalURL), mirroring net/http's Response.Location.
// ErrNoLocation is returned when no Location header is present.
func (r *Response) Location() (*url.URL, error) {
	lv := r.GetHeader("Location")
	if lv == "" {
		return nil, ErrNoLocation
	}
	if r.FinalURL != "" {
		if base, err := url.Parse(r.FinalURL); err == nil {
			return base.Parse(lv)
		}
	}
	return url.Parse(lv)
}

// Bytes returns the response body as a byte slice.
// If the body has already been read, returns the cached bytes.
// Otherwise reads the body and caches it.
func (r *Response) Bytes() ([]byte, error) {
	if r.bodyRead {
		return r.bodyBytes, nil
	}
	if r.Body == nil {
		return nil, nil
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body.Close()
	r.bodyBytes = data
	r.bodyRead = true
	return data, nil
}

// Text returns the response body as a string.
func (r *Response) Text() (string, error) {
	data, err := r.Bytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Transport is a unified HTTP transport supporting HTTP/1.1, HTTP/2, and HTTP/3
type Transport struct {
	h1Transport *HTTP1Transport
	h2Transport *HTTP2Transport
	h3Transport *HTTP3Transport
	dnsCache    *dns.Cache
	preset      *fingerprint.Preset
	timeout     time.Duration
	protocol    Protocol
	proxy       *ProxyConfig
	config      *TransportConfig

	// fieldsMu guards the mutable fields that SetProxy/SetPreset/SetProtocol
	// reassign while Do/doAuto/DoStream (and the Get*Transport getters) read
	// them: h1Transport, h2Transport, h3Transport, preset, protocol, proxy,
	// h3ProxyError, tcpProxyError. The session releases its own lock before
	// calling Do, so a concurrent SetProxy raced these pointer reads/writes.
	// Readers snapshot under an RLock (never held across network I/O); the three
	// mutators publish under the write lock.
	fieldsMu sync.RWMutex

	// Track protocol support per host
	protocolSupport   map[string]Protocol // Best known protocol per host
	protocolSupportMu sync.RWMutex

	// Configuration
	insecureSkipVerify bool
	tlsVerify          *TLSVerify

	// H3 proxy initialization error - if set, H3 requests will fail with this error
	// instead of silently bypassing the proxy
	h3ProxyError error

	// tcpProxyError is set when a proxy IS configured but cannot carry TCP — a
	// UDP-only MASQUE proxy (e.g. via SetUDPProxy, which clears Proxy/TCPProxy).
	// H1/H2 dispatch then refuses with this error rather than silently dialing
	// the target directly, which would leak the real client IP + SNI. nil means
	// TCP dispatch is allowed (direct, or through a real TCP/SOCKS5 proxy).
	tcpProxyError error

	// Custom header order (nil = use preset's order)
	customHeaderOrder   []string
	customHeaderOrderMu sync.RWMutex

	// Custom pseudo-header order (nil = use preset's browser-type heuristic)
	customPseudoOrder []string

	// TLS-only mode: skip preset HTTP headers, use TLS fingerprint only
	tlsOnly bool
}

// NewTransport creates a new unified transport
func NewTransport(presetName string) *Transport {
	return NewTransportWithConfig(presetName, nil, nil)
}

// NewTransportWithProxy creates a new unified transport with optional proxy
func NewTransportWithProxy(presetName string, proxy *ProxyConfig) *Transport {
	return NewTransportWithConfig(presetName, proxy, nil)
}

// proxyRouting resolves how each protocol family reaches the network for a given
// ProxyConfig. Split TCPProxy/UDPProxy fields take precedence over the unified
// URL; struct-level Username/Password are carried through so they reach the
// H1/H2 CONNECT auth (getProxyAuth) and SOCKS5 even when the URL has no userinfo.
type proxyRouting struct {
	// tcpProxy is what H1/H2 dial through. A nil tcpProxy means "no proxy for
	// TCP". When a proxy IS configured but cannot carry TCP (a UDP-only MASQUE
	// proxy), tcpProxy is nil AND tcpProxyErr is set, so the caller refuses the
	// TCP path instead of falling through to a DIRECT (real-IP + SNI) dial.
	tcpProxy    *ProxyConfig
	udpProxyURL string
	username    string
	password    string
	tcpProxyErr error
}

// deriveProxyRouting computes the per-protocol proxy split from an incoming
// (possibly split) ProxyConfig. Central so the constructor, SetProxy and
// SetPreset share identical rules — including the anti-leak guarantee that a
// configured proxy never degrades into a direct dial.
func deriveProxyRouting(proxy *ProxyConfig) proxyRouting {
	var r proxyRouting
	if proxy == nil {
		return r
	}
	r.username = proxy.Username
	r.password = proxy.Password

	tcpProxyURL := proxy.TCPProxy
	if tcpProxyURL == "" {
		tcpProxyURL = proxy.URL
	}
	r.udpProxyURL = proxy.UDPProxy
	if r.udpProxyURL == "" {
		r.udpProxyURL = proxy.URL
	}

	// UDP-only configs (SetUDPProxy clears Proxy/TCPProxy) must never let H1/H2
	// fall through to a DIRECT dial — that leaks the real client IP + SNI to the
	// target on every H1/H2 request (and on the H2 probe of an Auto race).
	// SOCKS5 also speaks TCP CONNECT, so reuse it for H1/H2. A UDP-only MASQUE
	// proxy cannot carry TCP: flag it so the TCP path refuses rather than dials.
	if tcpProxyURL == "" && r.udpProxyURL != "" {
		if isSOCKS5Proxy(r.udpProxyURL) {
			tcpProxyURL = r.udpProxyURL
		} else {
			r.tcpProxyErr = fmt.Errorf("HTTP/3-only proxy: no TCP proxy configured for HTTP/1.1 or HTTP/2")
		}
	}

	if tcpProxyURL != "" {
		r.tcpProxy = &ProxyConfig{
			URL:      proxyURLWithCreds(tcpProxyURL, proxy.Username, proxy.Password),
			Username: proxy.Username,
			Password: proxy.Password,
		}
	}
	return r
}

// udpProxyConfig builds the ProxyConfig H3 should use, or nil when no UDP proxy
// is configured. Carries the struct credentials alongside the URL.
func (r proxyRouting) udpProxyConfig() *ProxyConfig {
	if r.udpProxyURL == "" {
		return nil
	}
	return &ProxyConfig{
		URL:      proxyURLWithCreds(r.udpProxyURL, r.username, r.password),
		Username: r.username,
		Password: r.password,
	}
}

// proxyURLWithCreds returns rawURL with username/password injected as userinfo
// when rawURL has none. This makes credentials supplied via the ProxyConfig
// struct fields reach BOTH consumers: the H1/H2 CONNECT auth (getProxyAuth,
// which also reads the struct fields) AND the SOCKS5 dialer, which authenticates
// from the URL userinfo ONLY (proxy/socks5_*). URL-embedded creds are never
// overwritten; on parse failure rawURL is returned unchanged (the struct fields
// are still carried separately for the CONNECT path).
func proxyURLWithCreds(rawURL, username, password string) string {
	if rawURL == "" || username == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.User != nil {
		return rawURL // keep existing userinfo / unparseable URL as-is
	}
	u.User = url.UserPassword(username, password)
	return u.String()
}

// NewTransportWithConfig creates a new unified transport with proxy and config
func NewTransportWithConfig(presetName string, proxy *ProxyConfig, config *TransportConfig) *Transport {
	preset := fingerprint.Get(presetName)
	dnsCache := dns.NewCache()

	// Determine TLS-only mode from config
	tlsOnly := false
	if config != nil {
		tlsOnly = config.TLSOnly

		// Override preset HTTP/2 settings with custom Akamai fingerprint
		if config.CustomH2Settings != nil {
			preset.HTTP2Settings = *config.CustomH2Settings
		}
		// Override individual TCP/IP fingerprint fields
		if config.CustomTCPFingerprint != nil {
			fp := config.CustomTCPFingerprint
			if fp.TTL > 0 {
				preset.TCPFingerprint.TTL = fp.TTL
			}
			if fp.MSS > 0 {
				preset.TCPFingerprint.MSS = fp.MSS
			}
			if fp.WindowSize > 0 {
				preset.TCPFingerprint.WindowSize = fp.WindowSize
			}
			if fp.WindowScale > 0 {
				preset.TCPFingerprint.WindowScale = fp.WindowScale
			}
			if fp.DFBit {
				preset.TCPFingerprint.DFBit = fp.DFBit
			}
		}
	}

	// Capture custom pseudo-header order from config
	var customPseudoOrder []string
	if config != nil && len(config.CustomPseudoOrder) > 0 {
		customPseudoOrder = config.CustomPseudoOrder
	}

	t := &Transport{
		dnsCache:          dnsCache,
		preset:            preset,
		timeout:           30 * time.Second,
		protocol:          ProtocolAuto,
		protocolSupport:   make(map[string]Protocol),
		proxy:             proxy,
		config:            config,
		customPseudoOrder: customPseudoOrder,
		tlsOnly:           tlsOnly,
	}

	// Resolve how each protocol family reaches the network (split fields + struct
	// credentials, plus the anti-leak guard for UDP-only proxies — see
	// deriveProxyRouting).
	routing := deriveProxyRouting(proxy)
	t.tcpProxyError = routing.tcpProxyErr

	// Create HTTP/1.1 and HTTP/2 transports with the TCP proxy (nil = direct).
	t.h1Transport = NewHTTP1TransportWithConfig(preset, dnsCache, routing.tcpProxy, config)
	t.h2Transport = NewHTTP2TransportWithConfig(preset, dnsCache, routing.tcpProxy, config)

	// Create HTTP/3 transport - with UDP proxy support if applicable
	if udpProxy := routing.udpProxyConfig(); udpProxy != nil {
		udpProxyURL := routing.udpProxyURL
		if isSOCKS5Proxy(udpProxyURL) {
			// SOCKS5 supports UDP relay for HTTP/3
			h3Transport, err := NewHTTP3TransportWithConfig(preset, dnsCache, udpProxy, config)
			if err != nil {
				// Store the error - don't silently fallback to direct connection!
				// H3 requests will fail with explicit error instead of bypassing proxy
				t.h3ProxyError = fmt.Errorf("SOCKS5 UDP proxy initialization failed: %w", err)
				// Still create a basic H3 transport for non-proxied use cases
				// but h3ProxyError will prevent it from being used when proxy is expected
				t.h3Transport, _ = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
			} else {
				t.h3Transport = h3Transport
			}
		} else if isMASQUEProxy(udpProxyURL) {
			// MASQUE supports HTTP/3 through HTTP/3 proxy
			h3Transport, err := NewHTTP3TransportWithMASQUE(preset, dnsCache, udpProxy, config)
			if err != nil {
				// Store the error - don't silently fallback to direct connection!
				t.h3ProxyError = fmt.Errorf("MASQUE proxy initialization failed: %w", err)
				t.h3Transport, _ = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
			} else {
				t.h3Transport = h3Transport
			}
		} else {
			// HTTP proxy - HTTP/3 doesn't work through HTTP proxies
			// Store error so H3 requests fail explicitly
			t.h3ProxyError = fmt.Errorf("HTTP proxy does not support HTTP/3 (QUIC requires UDP)")
			t.h3Transport, _ = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
		}
	} else {
		// No proxy - HTTP/3 works directly
		t.h3Transport, _ = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
	}

	return t
}

// SetProtocol sets the preferred protocol
func (t *Transport) SetProtocol(p Protocol) {
	t.fieldsMu.Lock()
	t.protocol = p
	t.fieldsMu.Unlock()
}

// SetInsecureSkipVerify sets whether to skip TLS certificate verification
func (t *Transport) SetInsecureSkipVerify(skip bool) {
	t.insecureSkipVerify = skip
	t.h1Transport.SetInsecureSkipVerify(skip)
	if t.h2Transport != nil {
		t.h2Transport.SetInsecureSkipVerify(skip)
	}
	if t.h3Transport != nil {
		t.h3Transport.SetInsecureSkipVerify(skip)
	}
}

// SetTLSVerify installs caller-supplied certificate verification hooks on every
// protocol transport. Verification only; nothing here alters the ClientHello.
func (t *Transport) SetTLSVerify(v *TLSVerify) {
	t.tlsVerify = v
	t.h1Transport.SetTLSVerify(v)
	if t.h2Transport != nil {
		t.h2Transport.SetTLSVerify(v)
	}
	if t.h3Transport != nil {
		t.h3Transport.SetTLSVerify(v)
	}
}

// SetDisableECH disables ECH lookup for faster first request
func (t *Transport) SetDisableECH(disable bool) {
	if t.h3Transport != nil {
		t.h3Transport.SetDisableECH(disable)
	}
}

// SetProxy sets or updates the proxy configuration
// Note: This recreates the underlying transports
func (t *Transport) SetProxy(proxy *ProxyConfig) {
	preset := t.getPreset()

	// Resolve routing (split fields + credentials + the UDP-only anti-leak guard).
	routing := deriveProxyRouting(proxy)

	// Build the replacement transports OUTSIDE the fields lock. Construction — and
	// the Close() of the superseded transports below — can block (QUIC), and we
	// must not stall concurrent Do readers on either; only the pointer swap is
	// locked. Preserve the transport config (custom JA3, H2 settings, speculative
	// TLS, etc.) on H1/H2.
	newH1 := NewHTTP1TransportWithConfig(preset, t.dnsCache, routing.tcpProxy, t.config)
	newH2 := NewHTTP2TransportWithConfig(preset, t.dnsCache, routing.tcpProxy, t.config)

	// Recreate HTTP/3 - with proxy support if applicable. Keyed off the UDP proxy
	// (UDPProxy, else the unified URL), so a split TCP/UDP config still gets H3.
	var newH3 *HTTP3Transport
	var newH3Err error
	if h3Proxy := routing.udpProxyConfig(); h3Proxy != nil {
		udpProxyURL := routing.udpProxyURL
		if isSOCKS5Proxy(udpProxyURL) {
			h3Transport, err := NewHTTP3TransportWithProxy(preset, t.dnsCache, h3Proxy)
			if err != nil {
				newH3Err = fmt.Errorf("SOCKS5 UDP proxy initialization failed: %w", err)
				newH3, _ = NewHTTP3Transport(preset, t.dnsCache)
			} else {
				newH3 = h3Transport
			}
		} else if isMASQUEProxy(udpProxyURL) {
			h3Transport, err := NewHTTP3TransportWithMASQUE(preset, t.dnsCache, h3Proxy, nil)
			if err != nil {
				newH3Err = fmt.Errorf("MASQUE proxy initialization failed: %w", err)
				newH3, _ = NewHTTP3Transport(preset, t.dnsCache)
			} else {
				newH3 = h3Transport
			}
		} else {
			// HTTP proxy does not support HTTP/3 (QUIC requires UDP)
			newH3Err = fmt.Errorf("HTTP proxy does not support HTTP/3 (QUIC requires UDP)")
			newH3, _ = NewHTTP3Transport(preset, t.dnsCache)
		}
	} else {
		newH3, _ = NewHTTP3Transport(preset, t.dnsCache)
	}

	// Re-apply insecureSkipVerify to the fresh transports before publishing them.
	if t.insecureSkipVerify {
		newH1.SetInsecureSkipVerify(true)
		newH2.SetInsecureSkipVerify(true)
		if newH3 != nil {
			newH3.SetInsecureSkipVerify(true)
		}
	}

	// Same for the caller's certificate verification hooks. Rebuilding the
	// transports must not quietly drop them: a caller that installed pinning and
	// then rotated proxy or preset would go back to default verification with no
	// error and no way to notice.
	if t.tlsVerify != nil {
		newH1.SetTLSVerify(t.tlsVerify)
		newH2.SetTLSVerify(t.tlsVerify)
		if newH3 != nil {
			newH3.SetTLSVerify(t.tlsVerify)
		}
	}

	// Publish atomically; capture the old transports to close after unlocking.
	t.fieldsMu.Lock()
	oldH1, oldH2, oldH3 := t.h1Transport, t.h2Transport, t.h3Transport
	t.proxy = proxy
	t.h3ProxyError = newH3Err
	t.tcpProxyError = routing.tcpProxyErr
	t.h1Transport = newH1
	t.h2Transport = newH2
	t.h3Transport = newH3
	t.fieldsMu.Unlock()

	// Close the superseded transports outside the lock (QUIC Close can block).
	if oldH1 != nil {
		oldH1.Close()
	}
	if oldH2 != nil {
		oldH2.Close()
	}
	if oldH3 != nil {
		oldH3.Close()
	}
}

// SetPreset changes the fingerprint preset
func (t *Transport) SetPreset(presetName string) {
	preset := fingerprint.Get(presetName)

	// Re-apply custom H2 settings to the fresh preset (if any)
	if t.config != nil && t.config.CustomH2Settings != nil {
		preset.HTTP2Settings = *t.config.CustomH2Settings
	}

	// Snapshot the current proxy so the rebuilt transports keep routing through it.
	t.fieldsMu.RLock()
	proxy := t.proxy
	t.fieldsMu.RUnlock()

	// Same routing rules as the constructor/SetProxy — including credential
	// carry-over and the UDP-only anti-leak guard.
	routing := deriveProxyRouting(proxy)

	// Build outside the lock (construction + old-transport Close can block).
	newH1 := NewHTTP1TransportWithConfig(preset, t.dnsCache, routing.tcpProxy, t.config)
	newH2 := NewHTTP2TransportWithConfig(preset, t.dnsCache, routing.tcpProxy, t.config)

	// Recreate HTTP/3 - with proxy support if applicable.
	var newH3 *HTTP3Transport
	var newH3Err error
	if h3Proxy := routing.udpProxyConfig(); h3Proxy != nil {
		udpProxyURL := routing.udpProxyURL
		if isSOCKS5Proxy(udpProxyURL) {
			h3Transport, err := NewHTTP3TransportWithProxy(preset, t.dnsCache, h3Proxy)
			if err != nil {
				newH3Err = fmt.Errorf("SOCKS5 UDP proxy initialization failed: %w", err)
				newH3, _ = NewHTTP3Transport(preset, t.dnsCache)
			} else {
				newH3 = h3Transport
			}
		} else if isMASQUEProxy(udpProxyURL) {
			h3Transport, err := NewHTTP3TransportWithMASQUE(preset, t.dnsCache, h3Proxy, nil)
			if err != nil {
				newH3Err = fmt.Errorf("MASQUE proxy initialization failed: %w", err)
				newH3, _ = NewHTTP3Transport(preset, t.dnsCache)
			} else {
				newH3 = h3Transport
			}
		} else {
			newH3Err = fmt.Errorf("HTTP proxy does not support HTTP/3 (QUIC requires UDP)")
			newH3, _ = NewHTTP3Transport(preset, t.dnsCache)
		}
	} else {
		newH3, _ = NewHTTP3Transport(preset, t.dnsCache)
	}

	// Re-apply insecureSkipVerify to the fresh transports before publishing them.
	if t.insecureSkipVerify {
		newH1.SetInsecureSkipVerify(true)
		newH2.SetInsecureSkipVerify(true)
		if newH3 != nil {
			newH3.SetInsecureSkipVerify(true)
		}
	}

	// Same for the caller's certificate verification hooks. Rebuilding the
	// transports must not quietly drop them: a caller that installed pinning and
	// then rotated proxy or preset would go back to default verification with no
	// error and no way to notice.
	if t.tlsVerify != nil {
		newH1.SetTLSVerify(t.tlsVerify)
		newH2.SetTLSVerify(t.tlsVerify)
		if newH3 != nil {
			newH3.SetTLSVerify(t.tlsVerify)
		}
	}

	// Publish atomically; capture the old transports to close after unlocking.
	t.fieldsMu.Lock()
	oldH1, oldH2, oldH3 := t.h1Transport, t.h2Transport, t.h3Transport
	t.preset = preset
	t.h3ProxyError = newH3Err
	t.tcpProxyError = routing.tcpProxyErr
	t.h1Transport = newH1
	t.h2Transport = newH2
	t.h3Transport = newH3
	t.fieldsMu.Unlock()

	if oldH1 != nil {
		oldH1.Close()
	}
	if oldH2 != nil {
		oldH2.Close()
	}
	if oldH3 != nil {
		oldH3.Close()
	}
}

// isSOCKS5Proxy checks if the proxy URL is a SOCKS5 proxy
func isSOCKS5Proxy(proxyURL string) bool {
	return IsSOCKS5Proxy(proxyURL)
}

// IsSOCKS5Proxy checks if the proxy URL is a SOCKS5 proxy (exported version)
func IsSOCKS5Proxy(proxyURL string) bool {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}
	return parsed.Scheme == "socks5" || parsed.Scheme == "socks5h"
}

// isMASQUEProxy checks if the proxy URL should use MASQUE protocol.
// Returns true for masque:// scheme or known MASQUE providers with https://
func isMASQUEProxy(proxyURL string) bool {
	return IsMASQUEProxy(proxyURL)
}

// IsMASQUEProxy checks if the proxy URL should use MASQUE protocol (exported version).
// Returns true for masque:// scheme or known MASQUE providers with https://
func IsMASQUEProxy(proxyURL string) bool {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}

	// Explicit masque:// scheme
	if parsed.Scheme == "masque" {
		return true
	}

	// Auto-detect MASQUE based on URL path containing MASQUE endpoints
	// MASQUE proxies use specific paths like /.well-known/masque/ or /connect-udp/
	// Don't auto-detect based on hostname alone - providers use different ports for different protocols
	if parsed.Scheme == "https" {
		path := strings.ToLower(parsed.Path)
		if strings.Contains(path, "masque") || strings.Contains(path, "connect-udp") {
			return true
		}
	}

	return false
}

// SupportsQUIC checks if the proxy URL supports QUIC/HTTP3 tunneling.
// Returns true for SOCKS5 (UDP relay) or MASQUE (CONNECT-UDP) proxies.
func SupportsQUIC(proxyURL string) bool {
	return IsSOCKS5Proxy(proxyURL) || IsMASQUEProxy(proxyURL)
}

// SetTimeout sets the request timeout
func (t *Transport) SetTimeout(timeout time.Duration) {
	t.timeout = timeout
}

// Timeout returns the transport's configured request timeout (the session-level
// default; 0 means unbounded). Callers use it to derive a single overall
// deadline that bounds a whole logical request across redirect hops and retries,
// so a per-hop budget can't be multiplied by the number of hops.
func (t *Transport) Timeout() time.Duration {
	return t.timeout
}

// SetConnectTo sets a host mapping for domain fronting
func (t *Transport) SetConnectTo(requestHost, connectHost string) {
	if t.config == nil {
		t.config = &TransportConfig{}
	}
	if t.config.ConnectTo == nil {
		t.config.ConnectTo = make(map[string]string)
	}
	t.config.ConnectTo[requestHost] = connectHost

	// Update all transports
	if t.h1Transport != nil {
		t.h1Transport.SetConnectTo(requestHost, connectHost)
	}
	if t.h2Transport != nil {
		t.h2Transport.SetConnectTo(requestHost, connectHost)
	}
	if t.h3Transport != nil {
		t.h3Transport.SetConnectTo(requestHost, connectHost)
	}
}

// SetECHConfig sets a custom ECH configuration
func (t *Transport) SetECHConfig(echConfig []byte) {
	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfig = echConfig

	// Update HTTP/2 transport
	if t.h2Transport != nil {
		t.h2Transport.SetECHConfig(echConfig)
	}
	// Update HTTP/3 transport
	if t.h3Transport != nil {
		t.h3Transport.SetECHConfig(echConfig)
	}
}

// SetECHConfigDomain sets a domain to fetch ECH config from
func (t *Transport) SetECHConfigDomain(domain string) {
	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfigDomain = domain

	// Update HTTP/2 transport
	if t.h2Transport != nil {
		t.h2Transport.SetECHConfigDomain(domain)
	}
	// Update HTTP/3 transport
	if t.h3Transport != nil {
		t.h3Transport.SetECHConfigDomain(domain)
	}
}

// SetHeaderOrder sets a custom header order for all requests.
// Pass nil or empty slice to reset to preset's default order.
// Order should contain lowercase header names.
//
// The list is a prefix, not a replacement — see CompleteHeaderOrder, which does
// the assembly.
//
// This is session-wide state. To vary the order per request without serializing
// concurrent callers on it, set Request.HeaderOrder instead; a request that
// carries one ignores whatever is installed here.
func (t *Transport) SetHeaderOrder(order []string) {
	t.customHeaderOrderMu.Lock()
	defer t.customHeaderOrderMu.Unlock()

	if len(order) == 0 {
		t.customHeaderOrder = nil
		return
	}

	// Normalize to lowercase
	t.customHeaderOrder = make([]string, len(order))
	for i, h := range order {
		t.customHeaderOrder[i] = strings.ToLower(h)
	}
}

// GetHeaderOrder returns the current header order.
// Returns preset's default order if no custom order is set.
func (t *Transport) GetHeaderOrder() []string {
	// Snapshot the preset first (its own lock, released here) so we never nest
	// fieldsMu under customHeaderOrderMu.
	preset := t.getPreset()

	t.customHeaderOrderMu.RLock()
	defer t.customHeaderOrderMu.RUnlock()

	if len(t.customHeaderOrder) > 0 {
		result := make([]string, len(t.customHeaderOrder))
		copy(result, t.customHeaderOrder)
		return result
	}

	// Return preset's order
	if preset != nil && len(preset.HeaderOrder) > 0 {
		result := make([]string, len(preset.HeaderOrder))
		for i, hp := range preset.HeaderOrder {
			result[i] = hp.Key
		}
		return result
	}

	return nil
}

// getHeaderOrder returns the current header order for internal use (no copy).
func (t *Transport) getHeaderOrder() []string {
	t.customHeaderOrderMu.RLock()
	defer t.customHeaderOrderMu.RUnlock()
	return t.customHeaderOrder
}

// effectiveHeaderOrder returns the header order to use for a single request:
// the request's own HeaderOrder when it sets one, otherwise the session-wide
// order from SetHeaderOrder.
//
// The per-request list wins outright rather than merging with the session list —
// two prefixes cannot be combined without one silently reordering the other, and
// a caller who names an order for a request means that order. Normalizing to
// lowercase is left to CompleteHeaderOrder, which lowercases every name it
// places, so the request field needs no copy and no lock.
func (t *Transport) effectiveHeaderOrder(req *Request) []string {
	if req != nil && len(req.HeaderOrder) > 0 {
		return req.HeaderOrder
	}
	return t.getHeaderOrder()
}

// getCustomPseudoOrder returns the custom pseudo-header order (from Akamai fingerprint).
func (t *Transport) getCustomPseudoOrder() []string {
	return t.customPseudoOrder
}

// GetConnectHost returns the connection host for a request host.
// If there's a ConnectTo mapping, returns the mapped host.
// Otherwise returns the original host.
func (c *TransportConfig) GetConnectHost(requestHost string) string {
	if c == nil || c.ConnectTo == nil {
		return requestHost
	}
	if connectHost, ok := c.ConnectTo[requestHost]; ok {
		return connectHost
	}
	return requestHost
}

// GetECHConfig returns the ECH config to use for a host.
// Returns custom config if set, otherwise fetches from ECHConfigDomain or target host.
func (c *TransportConfig) GetECHConfig(ctx context.Context, targetHost string) []byte {
	if c == nil {
		// No config - fetch from target host
		echConfig, _ := dns.FetchECHConfigs(ctx, targetHost)
		return echConfig
	}

	// Custom ECH config takes priority
	if len(c.ECHConfig) > 0 {
		return c.ECHConfig
	}

	// ECH from different domain
	if c.ECHConfigDomain != "" {
		echConfig, _ := dns.FetchECHConfigs(ctx, c.ECHConfigDomain)
		return echConfig
	}

	// Default: fetch from target host
	echConfig, _ := dns.FetchECHConfigs(ctx, targetHost)
	return echConfig
}

// transportSnapshot is a consistent read of the mutable transport fields, taken
// once at the top of a request. SetProxy/SetPreset/SetProtocol swap these under
// fieldsMu; snapshotting avoids a data race with those mutators and gives the
// whole dispatch a stable view (e.g. the proxy and its matching sub-transports).
type transportSnapshot struct {
	h1            *HTTP1Transport
	h2            *HTTP2Transport
	h3            *HTTP3Transport
	proxy         *ProxyConfig
	preset        *fingerprint.Preset
	protocol      Protocol
	h3ProxyError  error
	tcpProxyError error
}

// snapshot reads the mutable fields under the read lock. The lock is released
// before the caller does any network I/O.
func (t *Transport) snapshot() transportSnapshot {
	t.fieldsMu.RLock()
	defer t.fieldsMu.RUnlock()
	return transportSnapshot{
		h1:            t.h1Transport,
		h2:            t.h2Transport,
		h3:            t.h3Transport,
		proxy:         t.proxy,
		preset:        t.preset,
		protocol:      t.protocol,
		h3ProxyError:  t.h3ProxyError,
		tcpProxyError: t.tcpProxyError,
	}
}

// getPreset returns the current preset under the read lock (grabbed and released
// so callers can safely take other locks afterwards).
func (t *Transport) getPreset() *fingerprint.Preset {
	t.fieldsMu.RLock()
	p := t.preset
	t.fieldsMu.RUnlock()
	return p
}

// Do executes an HTTP request
func (t *Transport) Do(ctx context.Context, req *Request) (*Response, error) {
	// Parse URL to determine scheme
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "", err)
	}

	// Snapshot the mutable fields once so a concurrent SetProxy/SetPreset/
	// SetProtocol can't race the dispatch below (see transportSnapshot).
	snap := t.snapshot()

	// Establish ONE overall deadline for the whole request, covering any protocol
	// fallback (H3 -> H2 -> H1). Each doHTTPx otherwise derives its own fresh
	// WithTimeout(ctx, timeout), so without a shared parent deadline the per-attempt
	// budgets ADD UP: a 4s timeout could ride to 8s (H2->H1) or 12s (H3->H2->H1).
	// The per-request timeout wins over the session default; both are honored
	// because context.WithTimeout takes the sooner of the parent deadline and this.
	effectiveTimeout := t.timeout
	if req.Timeout > 0 {
		effectiveTimeout = req.Timeout
	}
	if effectiveTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, effectiveTimeout)
		defer cancel()
	}

	// tcpBlocked is non-nil only when a proxy IS configured but cannot carry TCP
	// (a UDP-only MASQUE proxy). Any H1/H2 dispatch must then refuse rather than
	// dial the target directly, which would leak the real client IP + SNI.
	tcpBlocked := snap.tcpProxyError

	// For HTTP (non-TLS), only HTTP/1.1 is supported
	if parsedURL.Scheme == "http" {
		if tcpBlocked != nil {
			return nil, tcpBlocked
		}
		return t.doHTTP1(ctx, req)
	}

	// When proxy is configured, respect user's protocol choice
	// Check for any proxy (URL, TCPProxy, or UDPProxy)
	if snap.proxy != nil && (snap.proxy.URL != "" || snap.proxy.TCPProxy != "" || snap.proxy.UDPProxy != "") {
		// QUIC capability is decided by the UDP-side proxy, matching how the H3
		// transport is built (UDPProxy, else the unified URL). A TCP-only proxy
		// never relays QUIC, and for a split config (TCPProxy=http,
		// UDPProxy=socks5) keying off the TCP proxy would hide a perfectly good
		// H3-over-proxy transport.
		udpEffectiveProxyURL := snap.proxy.UDPProxy
		if udpEffectiveProxyURL == "" {
			udpEffectiveProxyURL = snap.proxy.URL
		}

		// Respect user's explicit protocol choice
		switch snap.protocol {
		case ProtocolHTTP1:
			if tcpBlocked != nil {
				return nil, tcpBlocked
			}
			return t.doHTTP1(ctx, req)

		case ProtocolHTTP2:
			if tcpBlocked != nil {
				return nil, tcpBlocked
			}
			return t.doHTTP2(ctx, req)

		case ProtocolHTTP3:
			// Check if H3 is possible with this proxy
			if snap.h3ProxyError != nil {
				return nil, snap.h3ProxyError
			}
			if !SupportsQUIC(udpEffectiveProxyURL) {
				return nil, fmt.Errorf("HTTP/3 requires a SOCKS5 or MASQUE proxy (current proxy does not support UDP)")
			}
			return t.doHTTP3(ctx, req)

		case ProtocolAuto:
			// Auto-select based on proxy capabilities
			if snap.h3ProxyError != nil {
				// H3 proxy failed during init - fall back to H2/H1, but only when
				// TCP can actually reach the target through a proxy. With a UDP-only
				// proxy there is no non-leaking TCP path, so surface the H3 error.
				if tcpBlocked != nil {
					return nil, snap.h3ProxyError
				}
				resp, err := t.doHTTP2(ctx, req)
				if err == nil {
					return resp, nil
				}
				// Reuse TLS conn if proxy negotiated h1.1 instead of h2 (e.g. Charles, mitmproxy)
				var alpnErr *ALPNMismatchError
				if errors.As(err, &alpnErr) {
					return t.doHTTP1WithTLSConn(ctx, req, alpnErr)
				}
				return t.doHTTP1(ctx, req)
			}

			if SupportsQUIC(udpEffectiveProxyURL) {
				if tcpBlocked != nil {
					// UDP-only proxy (MASQUE): only H3 can reach the target. Racing
					// would fire an H2 probe that dials direct and leaks the real
					// IP + SNI, so go straight to H3 with no TCP fallback.
					return t.doHTTP3(ctx, req)
				}
				// SOCKS5 or MASQUE proxy. Race H3 and H2 instead of trying H3
				// first: when QUIC cannot actually relay through the proxy, the
				// sequential path idles ~5s on the QUIC handshake before falling
				// back. doAuto's racer (proxy-aware Connect probes) picks the
				// first protocol to connect and caches the decision per host.
				return t.doAuto(ctx, req)
			}
			// HTTP proxy - only supports H2/H1
			if tcpBlocked != nil {
				return nil, tcpBlocked
			}
			resp, err := t.doHTTP2(ctx, req)
			if err == nil {
				return resp, nil
			}
			// Reuse TLS conn if proxy negotiated h1.1 instead of h2 (e.g. Charles, mitmproxy)
			var alpnErr *ALPNMismatchError
			if errors.As(err, &alpnErr) {
				return t.doHTTP1WithTLSConn(ctx, req, alpnErr)
			}
			return t.doHTTP1(ctx, req)

		default:
			if tcpBlocked != nil {
				return nil, tcpBlocked
			}
			return t.doHTTP2(ctx, req)
		}
	}

	switch snap.protocol {
	case ProtocolHTTP1:
		return t.doHTTP1(ctx, req)
	case ProtocolHTTP2:
		return t.doHTTP2(ctx, req)
	case ProtocolHTTP3:
		return t.doHTTP3(ctx, req)
	case ProtocolAuto:
		return t.doAuto(ctx, req)
	default:
		return t.doHTTP2(ctx, req)
	}
}

// doAuto races HTTP/3 and HTTP/2 in parallel, using whichever succeeds first.
// This avoids the 5-second HTTP/3 timeout delay when QUIC is blocked.
// When ALPN negotiates HTTP/1.1 instead of HTTP/2, the TLS connection is reused.
func (t *Transport) doAuto(ctx context.Context, req *Request) (*Response, error) {
	host := extractHost(req.URL)

	// Snapshot preset + h3 once so SetPreset/SetProxy can't race these reads.
	snap := t.snapshot()

	// Check if we already know the best protocol for this host
	t.protocolSupportMu.RLock()
	knownProtocol, known := t.protocolSupport[host]
	t.protocolSupportMu.RUnlock()

	if known {
		switch knownProtocol {
		case ProtocolHTTP3:
			return t.doHTTP3(ctx, req)
		case ProtocolHTTP2:
			resp, err := t.doHTTP2(ctx, req)
			if err == nil {
				return resp, nil
			}
			// Check if ALPN mismatch - reuse connection for H1
			var alpnErr *ALPNMismatchError
			if errors.As(err, &alpnErr) {
				return t.doHTTP1WithTLSConn(ctx, req, alpnErr)
			}
			// H2 failed for other reason, try H1 with new connection
			return t.doHTTP1(ctx, req)
		case ProtocolHTTP1:
			return t.doHTTP1(ctx, req)
		}
	}

	// Preset explicitly disables HTTP/2 (e.g. a custom JA3 preset with
	// protocols.h2=false / ALPN http/1.1): skip the H2 attempt entirely and go
	// straight to HTTP/1.1 rather than negotiating H2 then ALPN-downgrading.
	if snap.preset.DisableHTTP2 && !snap.preset.SupportHTTP3 {
		resp, err := t.doHTTP1(ctx, req)
		if err == nil {
			t.protocolSupportMu.Lock()
			t.protocolSupport[host] = ProtocolHTTP1
			t.protocolSupportMu.Unlock()
		}
		return resp, err
	}

	// Race HTTP/3 and HTTP/2 in parallel if H3 is supported
	if snap.preset.SupportHTTP3 && snap.h3 != nil {
		resp, protocol, err := t.raceH3H2(ctx, req)
		if err == nil {
			t.protocolSupportMu.Lock()
			t.protocolSupport[host] = protocol
			t.protocolSupportMu.Unlock()
			return resp, nil
		}
		// Check if ALPN mismatch from H2 - reuse connection
		var alpnErr *ALPNMismatchError
		if errors.As(err, &alpnErr) {
			resp, err := t.doHTTP1WithTLSConn(ctx, req, alpnErr)
			if err == nil {
				t.protocolSupportMu.Lock()
				t.protocolSupport[host] = ProtocolHTTP1
				t.protocolSupportMu.Unlock()
			}
			return resp, err
		}
		// Both failed, try HTTP/1.1 with new connection
	} else {
		// No H3 support, just try H2
		resp, err := t.doHTTP2(ctx, req)
		if err == nil {
			t.protocolSupportMu.Lock()
			t.protocolSupport[host] = ProtocolHTTP2
			t.protocolSupportMu.Unlock()
			return resp, nil
		}
		// Check if ALPN mismatch - reuse connection for H1
		var alpnErr *ALPNMismatchError
		if errors.As(err, &alpnErr) {
			resp, err := t.doHTTP1WithTLSConn(ctx, req, alpnErr)
			if err == nil {
				t.protocolSupportMu.Lock()
				t.protocolSupport[host] = ProtocolHTTP1
				t.protocolSupportMu.Unlock()
			}
			return resp, err
		}
	}

	// Fallback to HTTP/1.1 with new connection
	resp, err := t.doHTTP1(ctx, req)
	if err == nil {
		t.protocolSupportMu.Lock()
		t.protocolSupport[host] = ProtocolHTTP1
		t.protocolSupportMu.Unlock()
		return resp, nil
	}

	return nil, err
}

// connectResult holds the result of a connection race
type connectResult struct {
	protocol Protocol
	err      error
}

// cacheProtocol records the best-known protocol for a host so subsequent
// requests skip the connection race.
func (t *Transport) cacheProtocol(host string, p Protocol) {
	t.protocolSupportMu.Lock()
	t.protocolSupport[host] = p
	t.protocolSupportMu.Unlock()
}

// connectDecision is the outcome of racing H3 and H2 connection probes. Exactly
// one of the fields is meaningful: err (context cancelled before any result),
// alpnErr (the H2 attempt negotiated HTTP/1.1; the live TLS conn is held for
// reuse), or protocol (H3 or H2 connected first; H2 is also the default when
// neither wins so the caller falls back through H2 -> H1).
type connectDecision struct {
	protocol Protocol
	alpnErr  *ALPNMismatchError
	err      error
}

// raceConnectProtocol races H3 and H2 connection probes and reports which
// established first, performing no application request. Keeping the request out
// of the race means it is safe for both buffered and streaming dispatch (the
// request is sent exactly once, on the winner) and for non-idempotent methods.
//
// Both Connect() probes tunnel through the configured proxy when one is set, so
// this never makes a direct (real-IP) dial. It eliminates the multi-second
// stall that a sequential "try H3 first" path pays whenever QUIC is blocked or
// the proxy cannot relay UDP: H2 simply wins the race in well under a second.
func (t *Transport) raceConnectProtocol(ctx context.Context, host, port string) connectDecision {
	// Snapshot the sub-transports so a concurrent SetProxy/SetPreset swap can't
	// race the pointer reads inside the probe closures.
	snap := t.snapshot()
	return raceTwoProbes(ctx, 6*time.Second,
		func(c context.Context) error { return snap.h3.Connect(c, host, port) },
		func(c context.Context) error { return snap.h2.Connect(c, host, port) },
	)
}

// raceTwoProbes runs the H3 and H2 connection probes concurrently under a
// shared cancellable context and returns as soon as one connects, when the H2
// probe reports an ALPN downgrade to HTTP/1.1, when BOTH probes have failed, or
// when the budget elapses (default to H2 then). The losing probe is cancelled.
// budget bounds the wait so a blocked H3 probe cannot stall the caller. Split
// out from raceConnectProtocol so the race/timeout logic is unit-testable with
// injected probes.
//
// The both-failed case matters more than it looks. Each goroutine used to
// signal only on success, so a plain error from either was dropped on the
// floor and the race sat out the entire budget even when both probes had
// already given up. Measured against a host that does not resolve: every
// forced protocol reported "no such host" in 20 to 130ms, while auto mode took
// 6005ms, the budget almost exactly. Any request with a timeout under the
// budget therefore died as "context deadline exceeded" and the real reason
// never reached the caller. That applies to every fast failure, not just
// NXDOMAIN: connection refused, no route to host, a rejected handshake.
func raceTwoProbes(ctx context.Context, budget time.Duration, h3Probe, h2Probe func(context.Context) error) connectDecision {
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	winnerCh := make(chan Protocol, 1)
	alpnErrCh := make(chan *ALPNMismatchError, 1)
	doneCh := make(chan struct{})
	// bothFailedCh closes once each probe has reported a failure that is not an
	// ALPN downgrade, so a race nobody can win ends now instead of at the
	// budget. An ALPN mismatch is not a failure here: it resolves the race on
	// alpnErrCh and hands the caller a live connection.
	bothFailedCh := make(chan struct{})
	var failures atomic.Int32
	noteFailure := func() {
		if failures.Add(1) == 2 {
			close(bothFailedCh)
		}
	}
	// h2Done closes when the H2 probe goroutine has fully returned. The drainer
	// (see drainLateALPN) waits on it so a late ALPN downgrade — an *ALPNMismatchError
	// carrying a live *utls.UConn that the probe emits AFTER the race resolved —
	// is read from alpnErrCh and its TLS conn closed, instead of leaking there.
	h2Done := make(chan struct{})

	// Race HTTP/3 connection
	go func() {
		if err := h3Probe(raceCtx); err == nil {
			select {
			case winnerCh <- ProtocolHTTP3:
			default:
			}
			return
		}
		noteFailure()
	}()

	// Race HTTP/2 connection
	go func() {
		defer close(h2Done)
		err := h2Probe(raceCtx)
		if err == nil {
			select {
			case winnerCh <- ProtocolHTTP2:
			default:
			}
		} else {
			// ALPN negotiated HTTP/1.1 - preserve the connection for reuse
			var alpnErr *ALPNMismatchError
			if errors.As(err, &alpnErr) {
				select {
				case alpnErrCh <- alpnErr:
				default:
				}
			} else {
				noteFailure()
			}
		}
	}()

	// Bound the race: H3 typically idles out in ~5s when blocked, H2 connects
	// in <1s. Context-aware so we never outlive the parent.
	go func() {
		select {
		case <-time.After(budget):
		case <-raceCtx.Done():
		}
		close(doneCh)
	}()

	select {
	case p := <-winnerCh:
		cancel() // stop the other attempt
		// The H2 probe may still be mid-handshake and downgrade to HTTP/1.1 after
		// this point; drain any such conn so its TLS socket can't leak.
		drainLateALPN(h2Done, alpnErrCh)
		return connectDecision{protocol: p}
	case alpnErr := <-alpnErrCh:
		cancel()
		// This alpnErr's conn is handed to the caller to reuse; do NOT close it
		// and do NOT drain (the probe emits exactly one alpnErr).
		return connectDecision{alpnErr: alpnErr}
	case <-bothFailedCh:
		cancel()
		// Same outcome as the budget path, just without the wait: the caller
		// falls back to H2 then H1, which fail fast now that DNS or the dial
		// has already answered, and produces the real error instead of a
		// deadline.
		select {
		case alpnErr := <-alpnErrCh:
			return connectDecision{alpnErr: alpnErr}
		default:
		}
		drainLateALPN(h2Done, alpnErrCh)
		return connectDecision{protocol: ProtocolHTTP2}
	case <-doneCh:
		cancel()
		select {
		case alpnErr := <-alpnErrCh:
			// Downgrade conn already available — hand it to the caller.
			return connectDecision{alpnErr: alpnErr}
		default:
		}
		// No winner and no ALPN mismatch yet: default to H2 (caller tries H2 -> H1),
		// but drain a late downgrade the still-running H2 probe may emit.
		drainLateALPN(h2Done, alpnErrCh)
		return connectDecision{protocol: ProtocolHTTP2}
	case <-ctx.Done():
		cancel()
		drainLateALPN(h2Done, alpnErrCh)
		return connectDecision{err: ctx.Err()}
	}
}

// drainLateALPN closes the TLS connection carried by a late ALPN-downgrade error
// that the H2 probe may still emit AFTER the race has resolved. It blocks (in a
// fresh goroutine) until the probe has certainly finished — h2Done closed, so any
// buffered send has already landed in alpnErrCh — then closes the conn exactly
// once. The race is already cancelled by the time this is called, so the probe
// unblocks promptly and this goroutine cannot leak. Only used on paths where the
// alpnErr was NOT handed to the caller, so this is the sole owner of that conn.
func drainLateALPN(h2Done <-chan struct{}, alpnErrCh <-chan *ALPNMismatchError) {
	go func() {
		<-h2Done
		select {
		case alpnErr := <-alpnErrCh:
			if alpnErr != nil && alpnErr.TLSConn != nil {
				alpnErr.TLSConn.Close()
			}
		default:
		}
	}()
}

// raceH3H2 races HTTP/3 and HTTP/2 connections in parallel, then makes the request
// on whichever protocol connects first. This eliminates the 5-second delay when
// HTTP/3 (QUIC) is blocked by firewalls or VPNs.
func (t *Transport) raceH3H2(ctx context.Context, req *Request) (*Response, Protocol, error) {
	// Parse URL to get host:port
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, ProtocolHTTP2, err
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	// Race the connection probes (proxy-aware), then send the request once on
	// whichever protocol established first.
	decision := t.raceConnectProtocol(ctx, host, port)
	if decision.err != nil {
		return nil, ProtocolHTTP2, decision.err
	}
	if decision.alpnErr != nil {
		// ALPN negotiated HTTP/1.1 instead of H2 - reuse the live connection.
		resp, err := t.doHTTP1WithTLSConn(ctx, req, decision.alpnErr)
		return resp, ProtocolHTTP1, err
	}

	switch decision.protocol {
	case ProtocolHTTP3:
		resp, err := t.doHTTP3(ctx, req)
		return resp, ProtocolHTTP3, err
	default: // ProtocolHTTP2 (also the no-winner default)
		resp, err := t.doHTTP2(ctx, req)
		if err != nil {
			// Check for ALPN mismatch - reuse connection
			var alpnErr *ALPNMismatchError
			if errors.As(err, &alpnErr) {
				resp, err := t.doHTTP1WithTLSConn(ctx, req, alpnErr)
				return resp, ProtocolHTTP1, err
			}
			// H2 failed for other reason, try H1 with new connection
			resp, err = t.doHTTP1(ctx, req)
			return resp, ProtocolHTTP1, err
		}
		return resp, ProtocolHTTP2, nil
	}
}

// isProtocolError checks if the error indicates protocol negotiation failure
func isProtocolError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "protocol") ||
		strings.Contains(errStr, "alpn") ||
		strings.Contains(errStr, "http2") ||
		strings.Contains(errStr, "does not support")
}

// doHTTP1 executes the request over HTTP/1.1
func (t *Transport) doHTTP1(ctx context.Context, req *Request) (*Response, error) {
	snap := t.snapshot()
	startTime := time.Now()
	timing := &protocol.Timing{}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "h1", err)
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Set timeout
	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build HTTP request
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, "h1", err)
	}

	// Determine effective TLS-only mode: per-request override takes precedence
	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	// Set preset headers (with ordering for fingerprinting)
	// Pass "h1" protocol so Chrome presets don't send Priority header on HTTP/1.1
	applyPresetHeaders(httpReq, snap.preset, t.effectiveHeaderOrder(req), t.getCustomPseudoOrder(), effectiveTLSOnly, "h1", req.Headers, req.DisableClientHints, req.ExactHeaders)

	// Override with custom headers (multi-value support)
	// Use Set for first value to replace preset headers, Add for additional values
	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	// Record timing before request
	reqStart := time.Now()

	// Make request
	resp, err := snap.h1.RoundTrip(httpReq)
	if err != nil {
		return nil, WrapError("roundtrip", host, port, "h1", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	// Read response body with pre-allocation for known content length
	body, err := readBodyOptimized(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h1", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" {
		decompressed, err := decompress(body, contentEncoding)
		if err != nil {
			return nil, NewRequestError("decompress", host, port, "h1", err)
		}
		body = decompressed
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   req.URL,
		Timing:     timing,
		Protocol:   "h1",
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

// doHTTP1WithTLSConn executes an HTTP/1.1 request using an existing TLS connection.
// This is used when ALPN negotiation results in HTTP/1.1 instead of HTTP/2,
// allowing the TLS connection to be reused instead of creating a new one.
func (t *Transport) doHTTP1WithTLSConn(ctx context.Context, req *Request, alpnErr *ALPNMismatchError) (*Response, error) {
	snap := t.snapshot()
	startTime := time.Now()
	timing := &protocol.Timing{}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		alpnErr.TLSConn.Close()
		return nil, NewRequestError("parse_url", "", "", "h1", err)
	}

	host := alpnErr.Host
	port := alpnErr.Port

	// Set timeout
	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build HTTP request
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		alpnErr.TLSConn.Close()
		return nil, NewRequestError("create_request", host, port, "h1", err)
	}

	// Determine effective TLS-only mode: per-request override takes precedence
	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	// Set preset headers - pass "h1" protocol so Chrome presets don't send Priority header
	applyPresetHeaders(httpReq, snap.preset, t.effectiveHeaderOrder(req), t.getCustomPseudoOrder(), effectiveTLSOnly, "h1", req.Headers, req.DisableClientHints, req.ExactHeaders)

	// Override with custom headers (multi-value support)
	// Use Set for first value to replace preset headers, Add for additional values
	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	// Record timing before request
	reqStart := time.Now()

	// Use the existing TLS connection for the HTTP/1.1 request
	resp, err := snap.h1.RoundTripWithTLSConn(httpReq, alpnErr.TLSConn, host, port)
	if err != nil {
		return nil, WrapError("roundtrip", host, port, "h1", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	// Read response body with pre-allocation for known content length
	body, err := readBodyOptimized(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h1", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" {
		decompressed, err := decompress(body, contentEncoding)
		if err != nil {
			return nil, NewRequestError("decompress", host, port, "h1", err)
		}
		body = decompressed
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   parsedURL.String(),
		Timing:     timing,
		Protocol:   "h1",
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

// doHTTP2 executes the request over HTTP/2
func (t *Transport) doHTTP2(ctx context.Context, req *Request) (*Response, error) {
	snap := t.snapshot()
	startTime := time.Now()
	timing := &protocol.Timing{}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "h2", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, NewProtocolError("", "", "h2",
			&TransportError{Op: "scheme_check", Cause: ErrProtocol, Category: ErrProtocol})
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	// Get connection use count BEFORE the request
	useCountBefore := snap.h2.GetConnectionUseCount(host, port)

	// Set timeout
	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build HTTP request
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, "h2", err)
	}

	// Determine effective TLS-only mode: per-request override takes precedence
	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	// Set preset headers (with ordering for fingerprinting)
	applyPresetHeaders(httpReq, snap.preset, t.effectiveHeaderOrder(req), t.getCustomPseudoOrder(), effectiveTLSOnly, "h2", req.Headers, req.DisableClientHints, req.ExactHeaders)

	// Override with custom headers (multi-value support)
	// Use Set for first value to replace preset headers, Add for additional values
	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	// Record timing before request
	reqStart := time.Now()

	// Make request
	resp, err := snap.h2.RoundTrip(httpReq)
	if err != nil {
		return nil, WrapError("roundtrip", host, port, "h2", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	// Read response body with pre-allocation for known content length
	body, err := readBodyOptimized(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h2", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" {
		decompressed, err := decompress(body, contentEncoding)
		if err != nil {
			return nil, NewRequestError("decompress", host, port, "h2", err)
		}
		body = decompressed
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Calculate timing breakdown
	wasReused := useCountBefore >= 1
	if wasReused {
		timing.DNSLookup = 0
		timing.TCPConnect = 0
		timing.TLSHandshake = 0
	} else {
		connectionOverhead := timing.FirstByte * 0.7
		if connectionOverhead > 10 {
			timing.DNSLookup = connectionOverhead * 0.2
			timing.TCPConnect = connectionOverhead * 0.3
			timing.TLSHandshake = connectionOverhead * 0.5
		}
	}

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   req.URL,
		Timing:     timing,
		Protocol:   "h2",
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

// doHTTP3 executes the request over HTTP/3
func (t *Transport) doHTTP3(ctx context.Context, req *Request) (*Response, error) {
	snap := t.snapshot()
	startTime := time.Now()
	timing := &protocol.Timing{}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "h3", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, NewProtocolError("", "", "h3",
			&TransportError{Op: "scheme_check", Cause: ErrProtocol, Category: ErrProtocol})
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	// Get dial count BEFORE the request
	dialCountBefore := snap.h3.GetDialCount()

	// Set timeout
	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build HTTP request
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, "h3", err)
	}

	// Determine effective TLS-only mode: per-request override takes precedence
	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	// Set preset headers (with ordering for fingerprinting)
	applyPresetHeaders(httpReq, snap.preset, t.effectiveHeaderOrder(req), t.getCustomPseudoOrder(), effectiveTLSOnly, "h3", req.Headers, req.DisableClientHints, req.ExactHeaders)

	// Override with custom headers (multi-value support)
	// Use Set for first value to replace preset headers, Add for additional values
	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	// Record timing before request
	reqStart := time.Now()

	// Make request. In forced-H3 (H3-only) mode there is no protocol fallback, so a
	// QUIC path that completes its handshake but then stalls the roundtrip — an
	// IPv6 PMTU black hole keeps the connection alive via keepalives while the
	// response never arrives — would otherwise hang until the full deadline.
	// roundTripHTTP3 bounds the first attempt and, on a stall, redials once biased
	// to the other address family.
	resp, cleanup, err := t.roundTripHTTP3(ctx, snap.h3, httpReq, req)
	if err != nil {
		cleanup()
		return nil, WrapError("roundtrip", host, port, "h3", err)
	}
	// cleanup releases the first-attempt context (if one was armed) only after the
	// body has been read below, so lazy body streaming is not cancelled early.
	defer cleanup()
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	// Read response body with pre-allocation for known content length
	body, err := readBodyOptimized(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h3", err)
	}

	// Decompress if needed
	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" {
		decompressed, err := decompress(body, contentEncoding)
		if err != nil {
			return nil, NewRequestError("decompress", host, port, "h3", err)
		}
		body = decompressed
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Calculate timing breakdown (HTTP/3 uses QUIC, no TCP)
	dialCountAfter := t.h3Transport.GetDialCount()
	wasReused := dialCountAfter == dialCountBefore
	timing.TCPConnect = 0

	if wasReused {
		timing.DNSLookup = 0
		timing.TLSHandshake = 0
	} else {
		connectionOverhead := timing.FirstByte * 0.7
		if connectionOverhead > 10 {
			timing.DNSLookup = connectionOverhead * 0.3
			timing.TLSHandshake = connectionOverhead * 0.7
		}
	}

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   req.URL,
		Timing:     timing,
		Protocol:   "h3",
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

// h3StallWindow bounds how long doHTTP3 waits for the first HTTP/3 response
// before treating the winning QUIC path as dead. The default QUIC MaxIdleTimeout
// is 30s with 15s keepalives, so a path that answers keepalives yet blackholes the
// response (an IPv6 PMTU black hole) stays "alive" and would otherwise hang until
// the request deadline. Five seconds sits well above normal first-byte latency but
// recovers fast; a fully idle path already errors around here on its own. Only
// applied when a retry is actually possible (see roundTripHTTP3).
const h3StallWindow = 5 * time.Second

// roundTripHTTP3 runs the HTTP/3 roundtrip with a bounded first attempt and, on a
// stall over a still-alive-but-useless QUIC connection, drops that connection and
// retries once biased to the other address family. This is the only fallback
// available in H3-only mode — auto mode races H2 and never gets stuck here. When a
// retry cannot help (a non-replayable streaming body, or a budget too small to
// carve out a stall window) it runs a single unbounded attempt, preserving the
// original behavior exactly.
func (t *Transport) roundTripHTTP3(ctx context.Context, h3 *HTTP3Transport, httpReq *http.Request, req *Request) (*http.Response, func(), error) {
	noop := func() {}
	deadline, hasDeadline := ctx.Deadline()
	// A streaming body cannot be re-read on retry; only in-memory []byte bodies
	// replay. Skip the bounded/retry dance unless the budget clears one stall
	// window with room to spare, so a tight deadline keeps its single full attempt.
	replayable := req.BodyReader == nil
	if !replayable || !hasDeadline || time.Until(deadline) <= h3StallWindow+time.Second {
		resp, err := h3.RoundTrip(httpReq)
		return resp, noop, err
	}

	// First attempt on a stall-abortable child context. The stall window only
	// bounds time-to-response-headers: RoundTrip returns once headers arrive and
	// the body streams lazily afterward, so we must NOT cancel the context on
	// success or the body read fails with H3_REQUEST_CANCELLED. On success we hand
	// cancelAttempt back as the cleanup func, which doHTTP3 defers until after the
	// body has been read.
	type rtResult struct {
		resp *http.Response
		err  error
	}
	attemptCtx, cancelAttempt := context.WithCancel(ctx)
	done := make(chan rtResult, 1)
	go func() {
		resp, err := h3.RoundTrip(httpReq.WithContext(attemptCtx))
		done <- rtResult{resp, err}
	}()

	select {
	case res := <-done:
		if res.err == nil {
			return res.resp, cancelAttempt, nil
		}
		cancelAttempt()
		// Retry only a stall, and only while the overall request budget survives.
		// A definitive transport error (not a stall) or an exhausted parent
		// deadline returns as-is.
		if ctx.Err() != nil || !isH3Stall(res.err) {
			return res.resp, noop, res.err
		}
	case <-time.After(h3StallWindow):
		// Headers never arrived within the window: abort this attempt. The
		// goroutine observes the cancel and drains into the buffered channel.
		cancelAttempt()
		if ctx.Err() != nil {
			return nil, noop, ctx.Err()
		}
	}

	// The leading family handshook but stalled. Drop the dead connection and bias
	// the redial to IPv4 (IPv6 black holes are the common trigger). Refresh is a
	// broad hammer — it resets this session's H3 connections — but a stall is rare
	// and forced-H3 sessions are single-purpose, so the cost is acceptable.
	h3.SetIPv4FirstOverride(true)
	defer h3.SetIPv4FirstOverride(false)
	_ = h3.Refresh()

	retryReq := httpReq.WithContext(ctx)
	if req.BodyReader == nil && len(req.Body) > 0 {
		retryReq.Body = io.NopCloser(bytes.NewReader(req.Body))
	}
	resp, err := h3.RoundTrip(retryReq)
	return resp, noop, err
}

// isH3Stall reports whether an HTTP/3 roundtrip error looks like a stalled or dead
// QUIC path (a bounded-attempt deadline, or QUIC's idle "no recent network
// activity") rather than a definitive transport failure worth surfacing directly.
func isH3Stall(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no recent network activity") ||
		strings.Contains(s, "timeout") ||
		strings.Contains(s, "deadline exceeded")
}

// Close shuts down the transport
func (t *Transport) Close() {
	t.h1Transport.Close()
	t.h2Transport.Close()
	t.h3Transport.Close()
}

// Refresh closes all connections but keeps TLS session caches intact.
// This simulates a browser page refresh - new TCP/QUIC connections but TLS resumption.
// Useful for resetting connection state without losing session tickets.
func (t *Transport) Refresh() {
	t.h1Transport.Refresh()
	t.h2Transport.Refresh()
	t.h3Transport.Refresh()
}

// RefreshWithProtocol closes all connections and switches to a new protocol.
// TLS session caches are preserved for 0-RTT resumption on the new protocol.
// This enables warming up TLS tickets on one protocol (e.g. H3) then serving
// requests on another (e.g. H2) with session resumption.
func (t *Transport) RefreshWithProtocol(p Protocol) {
	t.h1Transport.Refresh()
	t.h2Transport.Refresh()
	t.h3Transport.Refresh()
	t.SetProtocol(p)
	t.ClearProtocolCache()
}

// Stats returns transport statistics
func (t *Transport) Stats() map[string]interface{} {
	return map[string]interface{}{
		"http1": t.h1Transport.Stats(),
		"http2": t.h2Transport.Stats(),
		"http3": t.h3Transport.Stats(),
	}
}

// GetDNSCache returns the DNS cache
func (t *Transport) GetDNSCache() *dns.Cache {
	return t.dnsCache
}

// ClearProtocolCache clears the learned protocol support cache
func (t *Transport) ClearProtocolCache() {
	t.protocolSupportMu.Lock()
	t.protocolSupport = make(map[string]Protocol)
	t.protocolSupportMu.Unlock()
}

// GetHTTP1Transport returns the HTTP/1.1 transport for TLS session cache access
func (t *Transport) GetHTTP1Transport() *HTTP1Transport {
	t.fieldsMu.RLock()
	defer t.fieldsMu.RUnlock()
	return t.h1Transport
}

// GetHTTP2Transport returns the HTTP/2 transport for TLS session cache access
func (t *Transport) GetHTTP2Transport() *HTTP2Transport {
	t.fieldsMu.RLock()
	defer t.fieldsMu.RUnlock()
	return t.h2Transport
}

// GetHTTP3Transport returns the HTTP/3 transport for TLS session cache access
func (t *Transport) GetHTTP3Transport() *HTTP3Transport {
	t.fieldsMu.RLock()
	defer t.fieldsMu.RUnlock()
	return t.h3Transport
}

// GetConfig returns the transport's configuration.
func (t *Transport) GetConfig() *TransportConfig {
	return t.config
}

// SetSessionIdentifier sets a session identifier on all TLS session caches.
// This is used to isolate TLS sessions when the same host is accessed through
// different proxies or with different session configurations.
// The identifier is included in distributed cache keys to prevent session sharing.
func (t *Transport) SetSessionIdentifier(sessionId string) {
	if t.h1Transport != nil {
		if cache := t.h1Transport.GetSessionCache(); cache != nil {
			if pCache, ok := cache.(*PersistableSessionCache); ok {
				pCache.SetSessionIdentifier(sessionId)
			}
		}
	}
	if t.h2Transport != nil {
		if cache := t.h2Transport.GetSessionCache(); cache != nil {
			if pCache, ok := cache.(*PersistableSessionCache); ok {
				pCache.SetSessionIdentifier(sessionId)
			}
		}
	}
	if t.h3Transport != nil {
		if cache := t.h3Transport.GetSessionCache(); cache != nil {
			if pCache, ok := cache.(*PersistableSessionCache); ok {
				pCache.SetSessionIdentifier(sessionId)
			}
		}
	}
}

// Helper functions

// applyPresetHeaders applies headers from the preset to the request.
// Uses ordered headers (HeaderOrder) if available, otherwise falls back to the map.
// customHeaderOrder overrides preset's default order if provided.
// customPseudoOrder overrides the preset's pseudo-header order if provided.
// If tlsOnly is true, skips applying preset headers but still sets header order for fingerprinting.
// The protocol parameter ("h1", "h2", "h3") is used for protocol-specific header handling.
// userHeaders are the user-provided request headers, used for auto-detecting CORS mode.
// isClientHintHeader reports whether a header key is a UA client hint
// (sec-ch-ua and the sec-ch-ua-* family). Case-insensitive.
func isClientHintHeader(key string) bool {
	return len(key) >= 7 && strings.EqualFold(key[:7], "sec-ch-")
}

// CompleteHeaderOrder builds a header-order list that names every header the
// request carries, so none is left to an encoder's map-iteration fallback.
//
// The list is assembled in three passes: explicitOrder (the caller's order for
// this request — Request.HeaderOrder if it names one, else SetHeaderOrder, and
// empty when there is neither); then presetOrder, so a partial
// custom list does not cost the caller the preset's ordering for the headers
// they did not name; then everything still unplaced, sorted by name. An empty
// explicitOrder needs no special case — pass one falls through and pass two
// lays down the preset table on its own. Names are lowercased and
// de-duplicated. userHeaders may be nil when the caller has already merged
// them into header.
//
// Both remainders were previously emitted in Go map order, which is randomised
// on every range. A header order that differs per request is itself a
// fingerprint, and a strong one — no browser produces one. Sorted is not what a
// browser sends either, but it is stable, which is the detectable part.
func CompleteHeaderOrder(explicitOrder, presetOrder []string, header http.Header, userHeaders map[string][]string) []string {
	seen := make(map[string]bool, len(explicitOrder)+len(presetOrder)+len(header)+len(userHeaders))
	order := make([]string, 0, len(explicitOrder)+len(presetOrder)+len(header)+len(userHeaders))

	place := func(name string) {
		lower := strings.ToLower(name)
		if lower == "" || seen[lower] {
			return
		}
		seen[lower] = true
		order = append(order, lower)
	}
	for _, name := range explicitOrder {
		place(name)
	}
	for _, name := range presetOrder {
		place(name)
	}

	rest := make([]string, 0, len(header)+len(userHeaders))
	collect := func(name string) {
		// The ordering keys are internal control entries, not headers, and must
		// never reach the wire.
		if strings.EqualFold(name, http.HeaderOrderKey) || strings.EqualFold(name, http.PHeaderOrderKey) {
			return
		}
		lower := strings.ToLower(name)
		if lower == "" || seen[lower] {
			return
		}
		seen[lower] = true
		rest = append(rest, lower)
	}
	for name := range header {
		collect(name)
	}
	for name := range userHeaders {
		collect(name)
	}
	sort.Strings(rest)

	return append(order, rest...)
}

// presetSendsSecFetch reports whether a preset describes a client that sends
// Sec-Fetch-* metadata at all.
//
// The XHR coercion below rewrites Sec-Fetch-* and Accept to keep a *browser*
// coherent on API-shaped calls. A preset for a non-browser client - okhttp,
// curl, a native mobile SDK - has no navigation headers to correct, so running
// the coercion on one does not fix an incoherence, it invents headers that
// client never sends.
//
// The signal is the preset's EMIT SET, not its HPACK position table. The table
// only says where a header goes if it is sent; the emit set says what is
// actually sent, which is the thing being suppressed. Reading the table instead
// leaves a hole: a custom preset that drops Sec-Fetch-* from its emit set while
// inheriting a browser's position table would still have all of them injected,
// so the opt-out would silently fail for exactly the preset that asked for it.
//
// Every built-in today lists the family in both places, so this changes nothing
// for any shipped fingerprint. Matching is case-insensitive: HTTP/2 field names
// are lowercase by definition (RFC 9113 8.2.1) and the built-in tables follow
// that, but a hand-written custom preset need not.
func presetSendsSecFetch(preset *fingerprint.Preset) bool {
	if len(preset.HeaderOrder) > 0 {
		// The ordered list IS the emit set when it is populated, so it alone
		// decides. Falling through to the Headers map here would reopen the hole
		// this gate exists to close: a custom preset built with based_on drops
		// Sec-Fetch-* from its own HeaderOrder but still inherits the base's
		// Headers map, so the map would answer true and the headers would be
		// injected anyway - the opt-out failing for exactly the preset that
		// asked for it, one field over from where it failed before.
		for _, h := range preset.HeaderOrder {
			if len(h.Key) >= 10 && strings.EqualFold(h.Key[:10], "sec-fetch-") {
				return true
			}
		}
		return false
	}
	// Only for presets that carry the backward-compatible map and no ordered list.
	for name := range preset.Headers {
		if len(name) >= 10 && strings.EqualFold(name[:10], "sec-fetch-") {
			return true
		}
	}
	return false
}

// applyExactHeaders writes the caller's headers verbatim and returns true when
// it has taken over. Direct map assignment rather than Header.Set is the point:
// Set canonicalises the key, and a map entry holding several values is how a
// repeated header name survives to the wire.
func applyExactHeaders(httpReq *http.Request, exact []fingerprint.HeaderPair, preset *fingerprint.Preset, customPseudoOrder []string, protocol string) bool {
	if len(exact) == 0 {
		return false
	}
	for k := range httpReq.Header {
		delete(httpReq.Header, k)
	}
	order := make([]string, 0, len(exact))
	seen := make(map[string]bool, len(exact))
	for _, hp := range exact {
		httpReq.Header[hp.Key] = append(httpReq.Header[hp.Key], hp.Value)
		if !seen[hp.Key] {
			seen[hp.Key] = true
			order = append(order, hp.Key)
		}
	}
	// One order entry per name. A repeated name emits all of its values at that
	// one position, which is what a browser does with Cookie on HTTP/1.1.
	httpReq.Header[http.HeaderOrderKey] = order

	// Pseudo-header order is still the preset's. It is part of the protocol
	// framing rather than something the caller listed, and a caller who wants
	// it different sets it on the preset.
	switch {
	case len(customPseudoOrder) > 0:
		httpReq.Header[http.PHeaderOrderKey] = customPseudoOrder
	case preset != nil && preset.H2PseudoHeaderOrder() != nil:
		httpReq.Header[http.PHeaderOrderKey] = preset.H2PseudoHeaderOrder()
	case protocol == "h3":
		httpReq.Header[http.PHeaderOrderKey] = []string{":method", ":scheme", ":path", ":authority"}
	default:
		httpReq.Header[http.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
	}
	return true
}

func applyPresetHeaders(httpReq *http.Request, preset *fingerprint.Preset, customHeaderOrder []string, customPseudoOrder []string, tlsOnly bool, protocol string, userHeaders map[string][]string, stripClientHints bool, exactHeaders []fingerprint.HeaderPair) {
	if applyExactHeaders(httpReq, exactHeaders, preset, customPseudoOrder, protocol) {
		return
	}
	// In TLS-only mode, skip applying preset headers but still set header order
	if !tlsOnly {
		if len(preset.HeaderOrder) > 0 {
			// Use ordered headers for HTTP/2 and HTTP/3 fingerprinting
			for _, hp := range preset.HeaderOrder {
				if stripClientHints && isClientHintHeader(hp.Key) {
					continue // full opt-out: don't apply the preset sec-ch-* trio
				}
				httpReq.Header.Set(hp.Key, hp.Value)
			}
		} else {
			// Fallback to unordered headers map
			for key, value := range preset.Headers {
				if stripClientHints && isClientHintHeader(key) {
					continue
				}
				httpReq.Header.Set(key, value)
			}
		}
		httpReq.Header.Set("User-Agent", preset.UserAgent)

		// Auto-detect CORS mode from the request shape. Real browsers use
		// cors/empty Sec-Fetch-* for fetch()/XHR and navigate/document for
		// top-level navigations + classic <form> POSTs; infer which one this
		// request is from method, Content-Type, Accept, and any user-supplied
		// Sec-Fetch-* headers. WAFs like Akamai flag navigation headers on
		// API endpoints as bot behavior.
		//
		// Skipped for presets that describe a client sending no Sec-Fetch-* at
		// all; see presetSendsSecFetch for why inferring that from the preset
		// leaves every browser preset untouched.
		if presetSendsSecFetch(preset) && sniffXHRMode(httpReq.Method, userHeaders) {
			// Preserve any explicitly user-supplied Sec-Fetch-Mode/Dest/Site;
			// the sniff coercion is for "user said nothing, infer XHR" — once
			// they pin a value (e.g. mode=no-cors, dest=image, site=same-origin)
			// the request shape is intentional and our preset header defaults
			// (which assume navigation) should yield. Without this, callers
			// can't request browser sub-resource fetches like preload-as=image.
			userMode := headerVal(userHeaders, "Sec-Fetch-Mode")
			userDest := headerVal(userHeaders, "Sec-Fetch-Dest")
			userSite := headerVal(userHeaders, "Sec-Fetch-Site")
			if userMode != "" {
				httpReq.Header.Set("Sec-Fetch-Mode", userMode)
			} else {
				httpReq.Header.Set("Sec-Fetch-Mode", "cors")
			}
			if userDest != "" {
				httpReq.Header.Set("Sec-Fetch-Dest", userDest)
			} else {
				httpReq.Header.Set("Sec-Fetch-Dest", "empty")
			}
			if userSite != "" {
				httpReq.Header.Set("Sec-Fetch-Site", userSite)
			} else {
				httpReq.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			httpReq.Header.Del("Sec-Fetch-User")
			httpReq.Header.Del("sec-fetch-user")
			httpReq.Header.Del("Upgrade-Insecure-Requests")
			httpReq.Header.Del("upgrade-insecure-requests")
			// Real browsers send Accept: */* on fetch()/XHR unless the user
			// explicitly asked for something else — no user Accept means swap
			// the navigation Accept (text/html,...) for the CORS default.
			if headerVal(userHeaders, "Accept") == "" {
				httpReq.Header.Set("Accept", "*/*")
			}
			// CORS uses u=1,i priority (lower urgency than navigation's u=0,i)
			// — used as the static fallback when the preset has no per-dest
			// PriorityTable. Presets that ship a PriorityTable (Chrome 147+)
			// override this below.
			if httpReq.Header.Get("Priority") != "" {
				httpReq.Header.Set("Priority", "u=1, i")
			}
			if httpReq.Header.Get("priority") != "" {
				httpReq.Header.Set("priority", "u=1, i")
			}
		}

		// Per-resource-type priority: HTTP header. Chrome 147+ desktop emits
		// a distinct urgency per sec-fetch-dest (style→u=0, script→u=1,
		// manifest→u=2, image→u=2/i, fetch→u=1/i, prefetch→u=4/i, …). Presets
		// that ship a PriorityTable apply that mapping here AFTER the XHR
		// detector runs (so Sec-Fetch-Dest is final). Presets without a table
		// retain the static priority set by HeaderOrder / sniffXHRMode above.
		//
		// Skip on HTTP/1.1 — Chrome never sends the priority: header on H1;
		// the H1 strip below handles cleanup either way.
		if (protocol == "h2" || protocol == "h3") && preset.H2HasPriorityTable() {
			dest := httpReq.Header.Get("Sec-Fetch-Dest")
			if _, _, hv, ok := preset.H2PriorityFor(dest); ok {
				if hv == "" {
					// Chrome omits the header for this dest (e.g. async/defer scripts).
					httpReq.Header.Del("Priority")
					httpReq.Header.Del("priority")
				} else {
					httpReq.Header.Set("Priority", hv)
					// Mirror the lowercase form for callers that bypassed Set's
					// canonicalization when constructing the request.
					if _, hasLower := httpReq.Header["priority"]; hasLower {
						httpReq.Header["priority"] = []string{hv}
					}
				}
			}
		}

		// Chrome does NOT send Priority header on HTTP/1.1, only on HTTP/2 and HTTP/3.
		// Some anti-bots (Cloudflare, Datadome, Akamai) check for this and flag requests
		// that send Priority on H1 as bots.
		if protocol == "h1" && isChromePreset(preset.Name) {
			httpReq.Header.Del("Priority")
			httpReq.Header.Del("priority")
		}
	} else {
		// TLS-only mode: set empty User-Agent to prevent Go's default "Go-http-client/2.0"
		// This marks didUA=true in httpcommon.EncodeHeaders but skips writing the value
		httpReq.Header.Set("User-Agent", "")
	}

	// Set header order for HTTP/2 and HTTP/3 fingerprinting
	// Chrome uses the same header order for both H2 and H3 (same request_->extra_headers vector)
	//
	// Important: use H2HeaderOrder() (the full HPACK position table) — NOT
	// preset.HeaderOrder (the default emit set). The two differ: HeaderOrder
	// only lists headers Chrome sends on every request, while H2HeaderOrder
	// also reserves slots for situational headers (cache-control on F5,
	// content-type/content-length on POST, origin/referer on cross-origin,
	// cookie on subsequent requests). Using HeaderOrder here was a real
	// fingerprinting bug — when callers added cache-control/content-type/
	// cookie, the fork couldn't slot them and appended them after `priority`
	// instead of placing them where real Chrome does.
	httpReq.Header[http.HeaderOrderKey] = CompleteHeaderOrder(customHeaderOrder, preset.H2HeaderOrder(), httpReq.Header, userHeaders)

	// Set pseudo-header order: custom (Akamai) > preset H2Config > heuristic
	if len(customPseudoOrder) > 0 {
		httpReq.Header[http.PHeaderOrderKey] = customPseudoOrder
	} else if order := preset.H2PseudoHeaderOrder(); order != nil {
		httpReq.Header[http.PHeaderOrderKey] = order
	} else if preset.HTTP2Settings.NoRFC7540Priorities {
		httpReq.Header[http.PHeaderOrderKey] = []string{":method", ":scheme", ":path", ":authority"}
	} else {
		httpReq.Header[http.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
	}
}

// sniffXHRMode decides whether a request should send CORS-mode Sec-Fetch-*
// instead of navigation-mode, based on the request method and user headers.
// Browsers send cors/empty for fetch()/XHR and navigate/document for top-level
// navigations + classic <form> POSTs. Libraries that don't know the user's
// intent (session.post / httpcloak_post) have to infer it from the request
// shape.
func sniffXHRMode(method string, userHeaders map[string][]string) bool {
	method = strings.ToUpper(method)

	// Explicit user override on Sec-Fetch-Mode / Sec-Fetch-Dest wins — the
	// caller knows what intent they want to project. "navigate" explicitly
	// asks for navigation mode even for a POST that would otherwise sniff
	// as CORS.
	if v := headerVal(userHeaders, "Sec-Fetch-Mode"); v != "" {
		switch strings.ToLower(v) {
		case "cors", "no-cors", "websocket":
			return true
		case "navigate":
			return false
		}
	}
	if v := headerVal(userHeaders, "Sec-Fetch-Dest"); v != "" {
		// "document" is the only dest compatible with navigate mode — treat
		// an explicit "document" as a nav signal, anything else as API.
		if strings.ToLower(v) == "document" {
			return false
		}
		return true
	}

	// API-style Accept flags any method (also keeps prior GET behavior).
	if v := headerVal(userHeaders, "Accept"); v != "" && isAPIAcceptValue(v) {
		return true
	}

	switch method {
	case "GET", "HEAD", "OPTIONS", "":
		// Bodyless methods stay navigate unless Accept hinted API (above).
		return false
	case "DELETE":
		// DELETE is never a navigation.
		return true
	}

	// Body-carrying methods (POST/PUT/PATCH/...). Use Content-Type to
	// distinguish form submissions (navigate) from programmatic calls (cors).
	if ct := headerVal(userHeaders, "Content-Type"); ct != "" {
		if isFormContentTypeValue(ct) {
			return false
		}
		if isAPIContentTypeValue(ct) {
			return true
		}
	}

	// Unknown Content-Type on a body-carrying method: lean CORS. Real-world
	// POSTs from scrapers are overwhelmingly API calls; form submissions
	// always carry one of the form Content-Types handled above.
	return true
}

func headerVal(h map[string][]string, name string) string {
	if h == nil {
		return ""
	}
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func isAPIAcceptValue(accept string) bool {
	lower := strings.ToLower(accept)
	return strings.Contains(lower, "application/json") ||
		strings.Contains(lower, "application/xml") ||
		strings.Contains(lower, "text/plain") ||
		strings.Contains(lower, "application/octet-stream") ||
		lower == "*/*"
}

func isFormContentTypeValue(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.HasPrefix(lower, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(lower, "multipart/form-data")
}

func isAPIContentTypeValue(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.HasPrefix(lower, "application/json") ||
		strings.HasPrefix(lower, "application/xml") ||
		strings.HasPrefix(lower, "application/octet-stream") ||
		strings.HasPrefix(lower, "application/grpc") ||
		strings.HasPrefix(lower, "application/x-protobuf") ||
		strings.HasPrefix(lower, "text/plain") ||
		// Any other application/* that isn't a form type is API-ish.
		(strings.HasPrefix(lower, "application/") && !isFormContentTypeValue(lower))
}

// isChromePreset returns true if the preset name indicates a Chrome fingerprint.
func isChromePreset(name string) bool {
	return strings.HasPrefix(name, "chrome-") || strings.HasPrefix(name, "Chrome")
}

func extractHost(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// buildHeadersMap converts http.Header to map[string][]string.
// Preserves all values for multi-value headers (Set-Cookie, etc.)
func buildHeadersMap(h http.Header) map[string][]string {
	headers := make(map[string][]string)
	for key, values := range h {
		lowerKey := strings.ToLower(key)
		// Copy values to avoid sharing underlying array
		headerValues := make([]string, len(values))
		copy(headerValues, values)
		headers[lowerKey] = headerValues
	}
	return headers
}

// readBodyOptimized reads a response body and returns a buffer owned solely by
// the caller.
//
// The returned slice never aliases a pooled buffer. It used to, when
// Content-Length was known: the pooled buffer was handed straight to the caller
// and escaped into the Response. Nothing ever returned it to the pool on the
// common path, and on the Content-Encoding path it was returned to the pool
// while the Response still pointed into it, so a later request could overwrite
// a body that had already been given to the caller.
//
// Pooling bought nothing there in any case. The caller needs a stable buffer for
// the lifetime of the Response, so an allocation of the final size is required
// either way, and reading straight into it is one allocation with no copy.
//
// The chunked path still uses a pooled scratch buffer, where it genuinely helps:
// it avoids the repeated grow-and-copy that io.ReadAll does starting from 512
// bytes. That buffer is copied out of and released before returning.
func readBodyOptimized(body io.Reader, contentLength int64) ([]byte, error) {
	if contentLength > 0 {
		buf := make([]byte, contentLength)
		n, err := io.ReadFull(body, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		return buf[:n], nil
	}

	// Unknown/chunked length: read into a pooled scratch buffer, then copy out.
	bufPtr, release := getPooledBuffer(1 * 1024 * 1024)
	buf := *bufPtr
	n := 0
	for {
		if n == len(buf) {
			// Buffer full — grow by doubling (rare: response > 1MB with no Content-Length).
			// Copy before releasing: once the buffer is back in the pool another
			// goroutine can take it and start writing over what we are reading.
			newBuf := make([]byte, len(buf)*2)
			copy(newBuf, buf[:n])
			release()
			release = func() {}
			buf = newBuf
		}
		nn, err := body.Read(buf[n:])
		n += nn
		if err == io.EOF {
			break
		}
		if err != nil {
			release()
			return nil, err
		}
	}
	// Copy to a right-sized slice so the caller does not hold the scratch buffer
	result := make([]byte, n)
	copy(result, buf[:n])
	release()
	return result, nil
}

func decompress(data []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)

	case "br":
		reader := brotli.NewReader(bytes.NewReader(data))
		return io.ReadAll(reader)

	case "zstd":
		decoder, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer decoder.Close()
		return io.ReadAll(decoder)

	case "deflate":
		reader := flate.NewReader(bytes.NewReader(data))
		defer reader.Close()
		return io.ReadAll(reader)

	case "", "identity":
		return data, nil

	default:
		return data, nil
	}
}
