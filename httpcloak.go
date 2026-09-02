// Package httpcloak provides an HTTP client with perfect browser TLS/HTTP fingerprinting.
//
// httpcloak allows you to make HTTP requests that are indistinguishable from real browsers,
// bypassing TLS fingerprinting, HTTP/2 fingerprinting, and header-based bot detection.
//
// Basic usage:
//
//	client := httpcloak.New("chrome-146")
//	defer client.Close()
//
//	resp, err := client.Get(ctx, "https://example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(string(resp.Body))
//
// With options:
//
//	client := httpcloak.New("chrome-146",
//	    httpcloak.WithTimeout(30*time.Second),
//	    httpcloak.WithProxy("http://user:pass@proxy:8080"),
//	)
package httpcloak

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/textproto"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak/client"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/session"
	"github.com/sardanioss/httpcloak/transport"
	tls "github.com/sardanioss/utls"
)

// systemRoots is pre-loaded at init time to avoid ~40ms delay on first TLS connection
var systemRoots *x509.CertPool

func init() {
	// Pre-load system root CA certificates at package init time.
	// This normally takes ~40ms on first TLS connection, so we do it eagerly.
	// The result is cached by the Go runtime, so subsequent calls are instant.
	systemRoots, _ = x509.SystemCertPool()
}

// Client is an HTTP client with browser fingerprint spoofing
type Client struct {
	inner   *client.Client
	timeout time.Duration
}

// Option configures the Client
type Option func(*clientConfig)

type clientConfig struct {
	timeout time.Duration
	proxy   string
}

// WithTimeout sets the request timeout
func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) {
		c.timeout = d
	}
}

// WithProxy sets an HTTP/HTTPS/SOCKS5 proxy
func WithProxy(proxyURL string) Option {
	return func(c *clientConfig) {
		c.proxy = proxyURL
	}
}

// New creates a new HTTP client with the specified browser fingerprint.
//
// Available presets:
//   - "chrome-latest" (recommended), "chrome-latest-windows", "chrome-latest-linux", "chrome-latest-macos"
//   - "chrome-146", "chrome-145", "chrome-144", "chrome-143", "chrome-141", "chrome-133"
//   - "firefox-latest", "firefox-133"
//   - "safari-latest", "safari-18"
//   - "chrome-latest-ios", "safari-latest-ios"
//   - "chrome-latest-android"
//
// The -latest aliases always resolve to the newest version in the library.
//
// Example:
//
//	client := httpcloak.New("chrome-latest")
//	defer client.Close()
func New(preset string, opts ...Option) *Client {
	cfg := &clientConfig{
		timeout: 30 * time.Second,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Build client options
	var clientOpts []client.Option
	if cfg.proxy != "" {
		clientOpts = append(clientOpts, client.WithProxy(cfg.proxy))
	}

	return &Client{
		inner:   client.NewClient(preset, clientOpts...),
		timeout: cfg.timeout,
	}
}

// MultipartField represents a single field in a multipart/form-data body.
// For text fields, set Name and Value. For file uploads, set Name, Filename,
// Content, and optionally ContentType (defaults to application/octet-stream).
type MultipartField struct {
	Name        string // Form field name
	Value       string // Text value (used when Filename is empty)
	Filename    string // If set, this field is a file upload
	Content     []byte // File content (used when Filename is set)
	ContentType string // MIME type for file uploads (default: application/octet-stream)
}

// BuildMultipart encodes fields into a multipart/form-data body.
// Returns the encoded body bytes and the Content-Type header value (including boundary).
func BuildMultipart(fields []MultipartField) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	// Chrome-shaped boundary. Without this, Go emits 60 lowercase hex
	// characters with no leading dashes, which no browser produces and which
	// travels in cleartext in the content-type request header.
	if err := w.SetBoundary(fingerprint.MultipartBoundary()); err != nil {
		return nil, "", err
	}
	for _, f := range fields {
		if f.Filename != "" {
			ct := f.ContentType
			if ct == "" {
				ct = "application/octet-stream"
			}
			part, err := w.CreatePart(textproto.MIMEHeader{
				"Content-Disposition": {fmt.Sprintf(`form-data; name="%s"; filename="%s"`, f.Name, f.Filename)},
				"Content-Type":        {ct},
			})
			if err != nil {
				return nil, "", err
			}
			if _, err := part.Write(f.Content); err != nil {
				return nil, "", err
			}
		} else {
			if err := w.WriteField(f.Name, f.Value); err != nil {
				return nil, "", err
			}
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

// Request represents an HTTP request
type Request struct {
	Method  string
	URL     string
	Headers map[string][]string // Multi-value headers (matches http.Header)

	// ExactHeaders, when non-empty, replaces the whole header pipeline for this
	// request. The pairs go on the wire in the order and casing given, and
	// nothing is added: no preset block, no client hints, no Sec-Fetch
	// inference, and no alphabetical tail for names the preset does not know.
	//
	// A name may repeat, and each occurrence keeps its own position. Listing
	// cookie, accept, cookie puts the accept between the two cookies on all
	// three protocols, which a map of name to values cannot express and is the
	// shape a captured request routinely has.
	//
	// Use it to reproduce a captured request exactly. It is an escape hatch:
	// the caller takes on the entire request shape, including headers a browser
	// would always send. Headers is ignored when this is set, and so is the
	// session cookie jar, which would otherwise append a Cookie of its own.
	//
	// Host on HTTP/1.1 and the pseudo-header block on HTTP/2 and HTTP/3 are
	// still written for you, because they are protocol framing rather than
	// caller headers. Connection is not: a capture that carries none cannot
	// have one added back, and HTTP/1.1 keeps the connection alive by default
	// anyway. List it yourself to send it.
	ExactHeaders []fingerprint.HeaderPair
	Body         io.Reader // Streaming body for uploads
	Timeout      time.Duration

	// GetBody returns a fresh reader over the same body for a request that has
	// to go on the wire more than once: a 307 or 308 redirect hop, or a retried
	// attempt.
	//
	// You rarely need to set this. When Body is one of the in-memory reader
	// types — *bytes.Reader, *bytes.Buffer, *strings.Reader — a GetBody is
	// derived automatically, which costs nothing because the bytes are already
	// resident. Set it yourself when Body is a genuine stream (an *os.File, a
	// pipe, a live multipart writer) and the request might be replayed;
	// otherwise a 307 fails with ErrBodyNotReplayable rather than sending the
	// hop with an empty body, and a retry is skipped rather than corrupted.
	//
	// It returns io.Reader rather than net/http's io.ReadCloser deliberately: an
	// io.NopCloser wrapper would hide the concrete type from the type switch
	// that sets Content-Length, and the replayed hop would go out chunked while
	// the first one did not — a wire difference mid-chain that no browser
	// produces.
	GetBody func() (io.Reader, error)

	// TLSOnly is a per-request override for TLS-only mode.
	// When set to true, preset HTTP headers are NOT applied - only TLS fingerprinting is used.
	// When nil, the session's TLSOnly setting is used.
	// This is useful for LocalProxy where each request can have different TLS-only settings
	// via the X-HTTPCloak-TlsOnly header.
	TLSOnly *bool

	// FollowRedirects, when non-nil, overrides the session's follow-redirects
	// policy for this single request. Set to &true to follow redirects on this
	// request, &false to surface the 3xx response back to the caller. When nil,
	// the session-level setting is used.
	FollowRedirects *bool

	// DisableConditionalCache, when true, skips ETag / If-Modified-Since handling
	// for this single request: no cache validators are injected on the way out
	// and any ETag / Last-Modified on the response is not stored in the session
	// cache. Useful for forcing a fresh fetch without touching the session-wide
	// setting.
	DisableConditionalCache bool

	// DisableClientHints, when true, strips ALL UA client hints for this request:
	// the always-on sec-ch-ua / sec-ch-ua-mobile / sec-ch-ua-platform trio and the
	// high-entropy hints. Headers you set explicitly still pass through.
	DisableClientHints bool

	// DisableHighEntropyClientHints, when true, keeps the always-on sec-ch-ua trio
	// but suppresses the high-entropy hints (full-version-list, arch,
	// platform-version, bitness, model, wow64) for this single request.
	DisableHighEntropyClientHints bool

	// DisableRedirectReferer, when true, stops a Referer being added on redirect
	// hops. By default httpcloak synthesises one per Chrome's default
	// strict-origin-when-cross-origin policy: the full previous URL same-origin,
	// the origin alone cross-origin, and nothing at all on an https to http
	// downgrade. That is what a browser does, so leave this off unless you are
	// mirroring a client that sends no Referer.
	//
	// When set, no Referer reaches the next hop at all, including one you set on
	// the original request, since forwarding that would leak the pre-redirect URL
	// to the new host.
	DisableRedirectReferer bool

	// HeaderOrder, when non-empty, sets the header order for this single request
	// and overrides whatever SetHeaderOrder installed on the session. Nothing is
	// stored on the session and no lock is taken, so concurrent requests can each
	// carry a different order — which is the point: use this instead of calling
	// SetHeaderOrder around a request when one endpoint needs a header a browser
	// never sends slotted in a specific place.
	//
	// The list is a prefix, not a whole-request replacement. Headers you name are
	// emitted first, in this order; everything you leave out keeps the preset's
	// own position (then a stable alphabetical tail for anything the preset does
	// not know). Name every header you send and you get exactly that wire order.
	// Names are case-insensitive. Empty or nil means "no per-request order" — the
	// session-wide order applies.
	//
	// The order carries across followed redirects, because the headers it orders
	// do: the session replays your request headers onto each hop, so a header you
	// slotted explicitly here keeps that slot for the whole chain instead of being
	// re-placed by the preset table on hop two.
	//
	//	resp, err := s.Do(ctx, &httpcloak.Request{
	//	    Method:  "POST",
	//	    URL:     "https://api.example.com/v1/checkout",
	//	    Headers: map[string][]string{"x-api-token": {tok}},
	//	    HeaderOrder: []string{
	//	        "content-length", "sec-ch-ua", "x-api-token",
	//	        "content-type", "user-agent", "accept",
	//	    },
	//	})
	HeaderOrder []string

	// OnRedirect, when non-nil, is called once per redirect hop before the
	// follow-up request is built. Return nil to follow the hop,
	// ErrUseLastResponse to stop the chain and get the 3xx back as the response
	// with a nil error, or any other error to fail the request — that error
	// reaches you unwrapped, so errors.Is against your own sentinel matches.
	//
	// This is the seam for a decision that has to be made per hop. Turning
	// redirects off instead hands you the whole chain to re-implement, cookie
	// jar and browser-parity header scrubbing included, and reading
	// Response.History afterwards is too late: the request to the host you
	// meant to block has already gone out. The callback also sees each hop's
	// own headers, which is the only place to read a Set-Cookie or a routing
	// header that the final response will not carry.
	//
	// The hop is read-only. Writing to it does not retarget the redirect: a
	// callback able to rewrite the target would sit upstream of the scheme and
	// origin scrubbing, which is what keeps Authorization from following a hop
	// off-origin.
	//
	//	resp, err := s.Do(ctx, &httpcloak.Request{
	//	    Method: "POST", URL: checkout, Body: body,
	//	    OnRedirect: func(r *httpcloak.Redirect) error {
	//	        if r.CrossOrigin {
	//	            return httpcloak.ErrUseLastResponse // hand me the 3xx
	//	        }
	//	        return nil
	//	    },
	//	})
	//
	// It is not called for a 3xx with no Location, because there is no hop to
	// veto, nor for the hop that would exceed the redirect cap, which fails with
	// ErrTooManyRedirects instead. DoStream does not follow redirects at all, so
	// it never fires there. It runs on the calling goroutine between hops, so it
	// must not block and must not re-enter the same session.
	OnRedirect func(*Redirect) error
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

	// HeaderOrder is the order the server sent its headers in, lowercase, one
	// entry per occurrence. Headers is a map and cannot carry order, so code
	// that relays this response onward would otherwise emit a different
	// sequence than the origin did.
	//
	// Nil when the protocol path did not record one: HTTP/2 and HTTP/3 decode
	// an ordered field list and record it for free, while HTTP/1.1 reads
	// through textproto, which canonicalises the names and drops the order.
	HeaderOrder []string

	// HeaderCasing is the response header names as the server spelled them, in
	// arrival order. HTTP/1.1 only: HTTP/2 and HTTP/3 require lowercase on the
	// wire, so there is no casing to report and this is nil. Also nil when the
	// header block was not fully buffered when the response was read. Headers is
	// populated either way.
	HeaderCasing []string

	// Trailer is the trailing header block sent after the body, lowercase-keyed,
	// nil when there was none. gRPC puts the call's real status here rather than
	// in the response headers, so a client that ignores it reports every failed
	// call as a 200.
	Trailer map[string][]string

	Body     io.ReadCloser // Streaming body - call Close() when done
	FinalURL string
	Protocol string
	History  []*RedirectInfo

	// bodyBytes caches the body after reading
	bodyBytes []byte
	bodyRead  bool
}

// Close closes the response body.
func (r *Response) Close() error {
	if r.Body != nil {
		return r.Body.Close()
	}
	return nil
}

// Bytes reads and returns the entire response body.
// The body can only be read once unless cached.
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

// Text reads and returns the response body as a string.
func (r *Response) Text() (string, error) {
	data, err := r.Bytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// JSON decodes the response body into the given interface.
func (r *Response) JSON(v interface{}) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// GetHeader returns the first value for the given header key.
func (r *Response) GetHeader(key string) string {
	if values := r.Headers[strings.ToLower(key)]; len(values) > 0 {
		return values[0]
	}
	return ""
}

// GetHeaders returns all values for the given header key.
func (r *Response) GetHeaders(key string) []string {
	return r.Headers[strings.ToLower(key)]
}

// ErrNoLocation is returned by Response.Location when the response has no
// Location header.
//
// Deliberately the same error value as transport.ErrNoLocation rather than a
// separate sentinel with the same text: a caller doing
// errors.Is(err, ErrNoLocation) must match regardless of which layer produced
// the response.
var ErrNoLocation = transport.ErrNoLocation

// Redirect describes one hop a redirect chain is about to take. See
// Request.OnRedirect.
//
// An alias rather than a copy of transport.Redirect: OnRedirect is a func value
// travelling inward through the layers, so an alias makes
// func(*httpcloak.Redirect) error and func(*transport.Redirect) error the
// identical type and the field assigns straight through with no per-hop
// conversion.
type Redirect = transport.Redirect

// ErrUseLastResponse, returned from a Request.OnRedirect callback, stops the
// redirect chain and returns the 3xx itself with a nil error. Shaped after
// net/http.ErrUseLastResponse.
//
// Deliberately the same error value as transport.ErrUseLastResponse, for the
// same reason as ErrNoLocation above.
var ErrUseLastResponse = transport.ErrUseLastResponse

// ErrBodyNotReplayable is returned when a 307 or 308 needs the request body a
// second time but Body was a one-shot stream and no GetBody was set to re-open
// it. The 3xx is returned alongside the error, so you can read its Location and
// drive the rest of the chain yourself. Set Request.GetBody to follow it
// automatically.
var ErrBodyNotReplayable = transport.ErrBodyNotReplayable

// ErrTooManyRedirects is returned when a chain exceeds the configured cap. The
// response carrying the last Location is returned alongside it, so you can see
// where the chain ended up rather than only that it was too long.
var ErrTooManyRedirects = transport.ErrTooManyRedirects

// Location returns the URL of the response's "Location" header, if present.
// A relative Location is resolved against the URL of the request that produced
// the response (FinalURL), mirroring net/http's Response.Location. Useful for
// inspecting 3xx responses when redirects are disabled via WithoutRedirects or
// Request.FollowRedirects. ErrNoLocation is returned when no Location header
// is present.
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

// Do executes an HTTP request
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	timeout := req.Timeout
	if timeout == 0 {
		timeout = c.timeout
	}

	cReq := &client.Request{
		Method:  req.Method,
		URL:     req.URL,
		Headers: req.Headers,
		Body:    req.Body,
		Timeout: timeout,
		// A veto that silently did not apply would be worse than no veto at
		// all, so this one field is carried even though this literal drops most
		// of Request (see the type's docs for what the Client path supports).
		OnRedirect: req.OnRedirect,
	}

	resp, err := c.inner.Do(ctx, cReq)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
		FinalURL:   resp.FinalURL,
		Protocol:   resp.Protocol,
	}, nil
}

// Get performs a GET request
func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method: "GET",
		URL:    url,
	})
}

// GetWithHeaders performs a GET request with custom headers
func (c *Client) GetWithHeaders(ctx context.Context, url string, headers map[string][]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, url string, body io.Reader, contentType string) (*Response, error) {
	headers := map[string][]string{}
	if contentType != "" {
		headers["Content-Type"] = []string{contentType}
	}
	return c.Do(ctx, &Request{
		Method:  "POST",
		URL:     url,
		Headers: headers,
		Body:    body,
	})
}

// PostJSON performs a POST request with JSON body
func (c *Client) PostJSON(ctx context.Context, url string, body []byte) (*Response, error) {
	return c.Post(ctx, url, bytes.NewReader(body), "application/json")
}

// PostForm performs a POST request with form data
func (c *Client) PostForm(ctx context.Context, url string, body []byte) (*Response, error) {
	return c.Post(ctx, url, bytes.NewReader(body), "application/x-www-form-urlencoded")
}

// PostMultipart performs a POST request with multipart/form-data body.
func (c *Client) PostMultipart(ctx context.Context, url string, fields []MultipartField) (*Response, error) {
	body, contentType, err := BuildMultipart(fields)
	if err != nil {
		return nil, err
	}
	return c.Post(ctx, url, bytes.NewReader(body), contentType)
}

// Close releases all resources held by the client
func (c *Client) Close() {
	c.inner.Close()
}

// Session represents a persistent HTTP session with cookie management
type Session struct {
	inner     *session.Session
	configErr error // deferred config error (e.g. invalid Akamai string)
}

// SessionOption configures a session
type SessionOption func(*sessionConfig)

type sessionConfig struct {
	preset                        string
	proxy                         string
	tcpProxy                      string // Proxy for TCP-based protocols (HTTP/1.1, HTTP/2)
	udpProxy                      string // Proxy for UDP-based protocols (HTTP/3 via MASQUE)
	timeout                       time.Duration
	forceHTTP1                    bool
	forceHTTP2                    bool
	forceHTTP3                    bool
	disableHTTP3                  bool
	insecureSkipVerify            bool
	tlsVerifyPeerCertificate      func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	tlsVerifyConnection           func(cs stdtls.ConnectionState) error
	tlsRootCAs                    *x509.CertPool
	disableRedirects              bool
	maxRedirects                  int
	retryCount                    int
	retryWaitMin                  time.Duration
	retryWaitMax                  time.Duration
	retryOnStatus                 []int
	preferIPv4                    bool
	connectTo                     map[string]string // Domain fronting: request_host -> connect_host
	echConfigDomain               string            // Domain to fetch ECH config from
	tlsOnly                       bool              // TLS-only mode: skip preset headers, set all manually
	quicIdleTimeout               time.Duration     // QUIC idle timeout (default: 30s)
	localAddr                     string            // Local IP address to bind outgoing connections
	keyLogFile                    string            // Path to write TLS key log for Wireshark decryption
	disableECH                    bool              // Disable ECH lookup for faster first request
	enableSpeculativeTLS          bool              // Enable speculative TLS optimization for proxy connections
	switchProtocol                string            // Protocol to switch to after Refresh() (e.g. "h1", "h2", "h3")
	withoutCookieJar              bool              // Disable internal cookie jar entirely (caller manages cookies via headers)
	withoutConditionalCache       bool              // Disable ETag / If-Modified-Since handling entirely
	withoutClientHints            bool              // Disable all UA client hints (trio + high-entropy)
	withoutHighEntropyClientHints bool              // Disable only the high-entropy UA client hints

	// Distributed session cache
	sessionCacheBackend       transport.SessionCacheBackend
	sessionCacheErrorCallback transport.ErrorCallback

	// Custom fingerprint
	customJA3            string
	customJA3Extras      *fingerprint.JA3Extras
	customH2Settings     *fingerprint.HTTP2Settings
	customPseudoOrder    []string
	customTCPFingerprint *fingerprint.TCPFingerprint

	configErr error // deferred error from option parsing
}

// WithSessionProxy sets a proxy for the session
func WithSessionProxy(proxyURL string) SessionOption {
	return func(c *sessionConfig) {
		c.proxy = proxyURL
	}
}

// WithSessionTCPProxy sets a proxy for TCP-based protocols (HTTP/1.1 and HTTP/2).
// Use this with WithSessionUDPProxy for split proxy configuration.
func WithSessionTCPProxy(proxyURL string) SessionOption {
	return func(c *sessionConfig) {
		c.tcpProxy = proxyURL
	}
}

// WithSessionUDPProxy sets a proxy for UDP-based protocols (HTTP/3 via MASQUE).
// Use this with WithSessionTCPProxy for split proxy configuration.
func WithSessionUDPProxy(proxyURL string) SessionOption {
	return func(c *sessionConfig) {
		c.udpProxy = proxyURL
	}
}

// WithSessionTimeout sets the timeout for session requests
func WithSessionTimeout(d time.Duration) SessionOption {
	return func(c *sessionConfig) {
		c.timeout = d
	}
}

// WithForceHTTP1 forces HTTP/1.1 protocol
func WithForceHTTP1() SessionOption {
	return func(c *sessionConfig) {
		c.forceHTTP1 = true
	}
}

// WithForceHTTP2 forces HTTP/2 protocol
func WithForceHTTP2() SessionOption {
	return func(c *sessionConfig) {
		c.forceHTTP2 = true
	}
}

// WithForceHTTP3 forces HTTP/3 protocol (QUIC)
func WithForceHTTP3() SessionOption {
	return func(c *sessionConfig) {
		c.forceHTTP3 = true
	}
}

// WithDisableHTTP3 disables HTTP/3 (QUIC) while keeping H1/H2 auto-negotiation.
// Use this when QUIC is unreliable on your network or when binding to a local
// address that doesn't support UDP.
func WithDisableHTTP3() SessionOption {
	return func(c *sessionConfig) {
		c.disableHTTP3 = true
	}
}

// WithInsecureSkipVerify disables SSL certificate verification
func WithInsecureSkipVerify() SessionOption {
	return func(c *sessionConfig) {
		c.insecureSkipVerify = true
	}
}

// WithVerifyPeerCertificate installs a certificate verification callback,
// mirroring crypto/tls.Config.VerifyPeerCertificate.
//
// It runs after the normal certificate checks, with the raw certificates and
// any chains the default verifier built; returning an error aborts the
// handshake. This is the hook for certificate pinning. Pair it with
// WithInsecureSkipVerify to replace the default verification rather than add
// to it.
func WithVerifyPeerCertificate(fn func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error) SessionOption {
	return func(c *sessionConfig) {
		c.tlsVerifyPeerCertificate = fn
	}
}

// WithVerifyConnection installs a connection verification callback, mirroring
// crypto/tls.Config.VerifyConnection. It runs after WithVerifyPeerCertificate,
// on every handshake including resumptions.
//
// The state is the standard library type, translated from the underlying uTLS
// connection state. Everything a verification callback normally reads is
// populated; ExportKeyingMaterial on it is not usable, because that plumbing
// cannot be reconstructed from outside crypto/tls.
func WithVerifyConnection(fn func(cs stdtls.ConnectionState) error) SessionOption {
	return func(c *sessionConfig) {
		c.tlsVerifyConnection = fn
	}
}

// WithTLSConfig takes the verification settings from a standard *tls.Config.
//
// Reaching for a tls.Config is the reflex, so this accepts one, but be clear on
// what it reads. Honoured: VerifyPeerCertificate, VerifyConnection and
// InsecureSkipVerify. Ignored: everything that shapes the ClientHello, which is
// CipherSuites, MinVersion, MaxVersion, CurvePreferences, NextProtos,
// ServerName and the rest. Those come from the browser preset. Letting a caller
// override them would quietly destroy the fingerprint the library exists to
// reproduce, and the damage would only be visible to whoever is fingerprinting
// at the other end.
//
// Prefer WithVerifyPeerCertificate and WithVerifyConnection, which make the
// supported surface obvious. A nil config is ignored.
func WithTLSConfig(cfg *stdtls.Config) SessionOption {
	return func(c *sessionConfig) {
		if cfg == nil {
			return
		}
		if cfg.VerifyPeerCertificate != nil {
			c.tlsVerifyPeerCertificate = cfg.VerifyPeerCertificate
		}
		if cfg.VerifyConnection != nil {
			c.tlsVerifyConnection = cfg.VerifyConnection
		}
		if cfg.RootCAs != nil {
			c.tlsRootCAs = cfg.RootCAs
		}
		if cfg.InsecureSkipVerify {
			c.insecureSkipVerify = true
		}
	}
}

// WithoutRedirects disables automatic redirect following
func WithoutRedirects() SessionOption {
	return func(c *sessionConfig) {
		c.disableRedirects = true
	}
}

// WithRedirects configures redirect behavior
func WithRedirects(follow bool, maxRedirects int) SessionOption {
	return func(c *sessionConfig) {
		c.disableRedirects = !follow
		c.maxRedirects = maxRedirects
	}
}

// WithRetry enables retry with default settings
func WithRetry(count int) SessionOption {
	return func(c *sessionConfig) {
		c.retryCount = count
	}
}

// WithoutRetry explicitly disables retry
func WithoutRetry() SessionOption {
	return func(c *sessionConfig) {
		c.retryCount = 0
	}
}

// WithRetryConfig configures retry behavior
func WithRetryConfig(count int, waitMin, waitMax time.Duration, retryOnStatus []int) SessionOption {
	return func(c *sessionConfig) {
		c.retryCount = count
		c.retryWaitMin = waitMin
		c.retryWaitMax = waitMax
		c.retryOnStatus = retryOnStatus
	}
}

// WithSessionPreferIPv4 makes the session prefer IPv4 addresses over IPv6.
// Use this on networks with poor IPv6 connectivity.
func WithSessionPreferIPv4() SessionOption {
	return func(c *sessionConfig) {
		c.preferIPv4 = true
	}
}

// WithLocalAddress binds outgoing connections to a specific local IP address.
// Useful for IPv6 rotation when you have a large IPv6 prefix and want to
// rotate source IPs per session. On Linux, freebind is automatically applied
// so you can bind to any address from a routed prefix without configuring
// each one on the interface.
// Supports both IPv4 and IPv6 addresses (e.g., "192.168.1.100" or "2001:db8::1").
func WithLocalAddress(addr string) SessionOption {
	return func(c *sessionConfig) {
		c.localAddr = addr
	}
}

// WithLocalAddrIP is the net.IP-typed equivalent of WithLocalAddress. Pass
// the parsed IP directly when you already have a net.IP value (e.g. when
// rotating from a precomputed pool). Same semantics: nil is a no-op so
// callers building options conditionally don't accidentally clobber a
// previously-set address.
func WithLocalAddrIP(ip net.IP) SessionOption {
	return func(c *sessionConfig) {
		if ip == nil {
			return
		}
		c.localAddr = ip.String()
	}
}

// WithKeyLogFile sets the path to write TLS key log for Wireshark decryption.
// This overrides the global SSLKEYLOGFILE environment variable for this session.
func WithKeyLogFile(path string) SessionOption {
	return func(c *sessionConfig) {
		c.keyLogFile = path
	}
}

// WithDisableECH disables ECH (Encrypted Client Hello) lookup for faster first request.
// ECH is an optional privacy feature that adds ~15-20ms to first connection.
// Disabling it has no security impact, only privacy implications.
func WithDisableECH() SessionOption {
	return func(c *sessionConfig) {
		c.disableECH = true
	}
}

// WithEnableSpeculativeTLS enables the speculative TLS optimization for proxy connections.
// When enabled, the CONNECT request and TLS ClientHello are sent together, saving one
// round-trip (~25% faster). Disabled by default due to compatibility issues with some proxies.
func WithEnableSpeculativeTLS() SessionOption {
	return func(c *sessionConfig) {
		c.enableSpeculativeTLS = true
	}
}

// WithSwitchProtocol sets the protocol to switch to after Refresh().
// This enables warming up TLS tickets on one protocol (e.g. H3) then serving
// requests on another (e.g. H2) with TLS session resumption.
// Valid values: "h1", "h2", "h3".
func WithSwitchProtocol(protocol string) SessionOption {
	return func(c *sessionConfig) {
		c.switchProtocol = protocol
	}
}

// WithoutCookieJar disables the session's internal cookie jar entirely.
// When set, Set-Cookie headers from responses are NOT stored and the jar's
// contents are NOT injected as Cookie headers on subsequent requests —
// cookie management is left fully to the caller via per-request headers.
//
// Useful when an application maintains its own cookie store (database,
// shared cache across sessions) and wants the lib to be byte-transparent
// about cookies. Combine with the regular `headers={"Cookie": "..."}`
// kwarg to inject your own jar's contents per request.
//
// Caller-provided Cookie headers always pass through regardless of this
// option — only the auto-injection from the internal jar is suppressed.
func WithoutCookieJar() SessionOption {
	return func(c *sessionConfig) {
		c.withoutCookieJar = true
	}
}

// WithoutConditionalCache disables the session's ETag / If-Modified-Since
// handling for the lifetime of the session. When set, the session never
// injects If-None-Match or If-Modified-Since headers and never stores those
// validators from responses.
//
// Useful for benchmarking, fingerprint testing, or any workflow that needs
// every request to hit the origin fresh regardless of prior responses.
// Toggle the same state at runtime with Session.SetConditionalCacheEnabled,
// or skip the cache for a single request via Request.DisableConditionalCache.
func WithoutConditionalCache() SessionOption {
	return func(c *sessionConfig) {
		c.withoutConditionalCache = true
	}
}

// WithoutClientHints disables ALL UA client hints for the session: the always-on
// sec-ch-ua / sec-ch-ua-mobile / sec-ch-ua-platform trio AND the high-entropy
// hints. Only sec-ch-* headers you set explicitly are sent. Toggle at runtime
// with Session.SetClientHintsEnabled, or for a single request via
// Request.DisableClientHints. Note that real Chrome always sends the trio over
// HTTPS, so this trades fidelity for control.
func WithoutClientHints() SessionOption {
	return func(c *sessionConfig) {
		c.withoutClientHints = true
	}
}

// WithoutHighEntropyClientHints keeps the always-on sec-ch-ua trio but suppresses
// the high-entropy hints (sec-ch-ua-full-version-list, -arch, -platform-version,
// -bitness, -model, -wow64) that Chrome only sends after a host advertises
// Accept-CH. Toggle at runtime with Session.SetHighEntropyClientHintsEnabled, or
// for a single request via Request.DisableHighEntropyClientHints.
func WithoutHighEntropyClientHints() SessionOption {
	return func(c *sessionConfig) {
		c.withoutHighEntropyClientHints = true
	}
}

// WithConnectTo sets a host mapping for domain fronting.
// Requests to requestHost will connect to connectHost instead.
// The TLS SNI and Host header will still use requestHost.
func WithConnectTo(requestHost, connectHost string) SessionOption {
	return func(c *sessionConfig) {
		if c.connectTo == nil {
			c.connectTo = make(map[string]string)
		}
		c.connectTo[requestHost] = connectHost
	}
}

// WithECHFrom sets a domain to fetch ECH config from.
// Instead of fetching ECH from the target domain's DNS,
// the config will be fetched from this domain.
// Useful for Cloudflare domains - use "cloudflare-ech.com" to get
// ECH config that works for any Cloudflare-proxied domain.
func WithECHFrom(domain string) SessionOption {
	return func(c *sessionConfig) {
		c.echConfigDomain = domain
	}
}

// WithTLSOnly enables TLS-only mode.
// In this mode, the preset's TLS fingerprint is used but its default HTTP headers
// are NOT applied. You must set all headers manually per-request.
// Useful when you need full control over HTTP headers while keeping the TLS fingerprint.
func WithTLSOnly() SessionOption {
	return func(c *sessionConfig) {
		c.tlsOnly = true
	}
}

// WithQuicIdleTimeout sets the QUIC connection idle timeout.
// Default is 30 seconds (matches Chrome). Connections are closed after
// this duration of inactivity. Set higher values if you need longer-lived
// HTTP/3 connections with gaps between requests.
func WithQuicIdleTimeout(d time.Duration) SessionOption {
	return func(c *sessionConfig) {
		c.quicIdleTimeout = d
	}
}

// WithSessionCache sets a distributed TLS session cache backend.
// This enables TLS session ticket sharing across multiple instances (e.g., via Redis).
// The errorCallback is optional and will be called when backend operations fail.
func WithSessionCache(backend transport.SessionCacheBackend, errorCallback transport.ErrorCallback) SessionOption {
	return func(c *sessionConfig) {
		c.sessionCacheBackend = backend
		c.sessionCacheErrorCallback = errorCallback
	}
}

// CustomFingerprint configures custom TLS (JA3) and HTTP/2 (Akamai) fingerprints.
// This overrides the preset's fingerprint for fine-grained control.
type CustomFingerprint struct {
	// JA3 is a JA3 fingerprint string.
	// Format: TLSVersion,CipherSuites,Extensions,EllipticCurves,PointFormats
	// Example: "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
	JA3 string

	// Akamai is an Akamai HTTP/2 fingerprint string.
	// Format: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
	// Example: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	Akamai string

	// SignatureAlgorithms overrides the default signature algorithms for the JA3 spec.
	// Valid values: "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256",
	// "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384",
	// "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512"
	SignatureAlgorithms []string

	// ALPN overrides the default ALPN protocols. Default: ["h2", "http/1.1"]
	ALPN []string

	// CertCompression overrides the cert compression algorithms.
	// Valid values: "brotli", "zlib", "zstd"
	CertCompression []string

	// PermuteExtensions randomly permutes the TLS extension order.
	PermuteExtensions bool

	// DelegatedCredentialAlgorithms sets extension 34. Same value vocabulary as
	// SignatureAlgorithms. Empty keeps the Chrome defaults.
	DelegatedCredentialAlgorithms []string

	// RecordSizeLimit sets extension 28. Zero keeps the Chrome default of
	// 0x4001. Firefox is the client that differs here.
	RecordSizeLimit uint16

	// KeyShareCurves is how many curves to send key shares for. Zero means one,
	// which is the Chrome default; a client offering both X25519MLKEM768 and
	// x25519 shares sends two.
	KeyShareCurves int
}

// WithCustomFingerprint sets a custom TLS/HTTP2 fingerprint for the session.
// When JA3 is set, TLS-only mode is automatically enabled (preset HTTP headers are skipped).
// WithTCPFingerprint overrides individual TCP/IP fingerprint fields from the preset.
// Only non-zero fields are applied; zero fields keep the preset default.
func WithTCPFingerprint(fp fingerprint.TCPFingerprint) SessionOption {
	return func(c *sessionConfig) {
		c.customTCPFingerprint = &fp
	}
}

func WithCustomFingerprint(fp CustomFingerprint) SessionOption {
	return func(c *sessionConfig) {
		c.customJA3 = fp.JA3

		// Build JA3Extras from user-friendly string-based fields
		if fp.JA3 != "" {
			extras := &fingerprint.JA3Extras{
				PermuteExtensions: fp.PermuteExtensions,
				RecordSizeLimit:   0x4001,
				KeyShareCurves:    fp.KeyShareCurves,
			}
			if fp.RecordSizeLimit != 0 {
				extras.RecordSizeLimit = fp.RecordSizeLimit
			}
			if len(fp.DelegatedCredentialAlgorithms) > 0 {
				algs, err := parseSignatureAlgorithmsStrict(fp.DelegatedCredentialAlgorithms)
				if err != nil {
					c.configErr = fmt.Errorf("delegated_credential_algorithms: %w", err)
				}
				extras.DelegatedCredentialAlgorithms = algs
			}
			if len(fp.ALPN) > 0 {
				extras.ALPN = fp.ALPN
			}
			if len(fp.SignatureAlgorithms) > 0 {
				algs, err := parseSignatureAlgorithmsStrict(fp.SignatureAlgorithms)
				if err != nil {
					c.configErr = fmt.Errorf("signature_algorithms: %w", err)
				}
				extras.SignatureAlgorithms = algs
			}
			if len(fp.CertCompression) > 0 {
				extras.CertCompAlgs = parseCertCompression(fp.CertCompression)
			}
			c.customJA3Extras = extras
			// Auto-enable TLS-only mode when custom JA3 is set
			c.tlsOnly = true
		}

		// Parse Akamai fingerprint
		if fp.Akamai != "" {
			h2Settings, pseudoOrder, err := fingerprint.ParseAkamai(fp.Akamai)
			if err != nil {
				c.configErr = fmt.Errorf("invalid Akamai fingerprint: %w", err)
			} else {
				c.customH2Settings = h2Settings
				c.customPseudoOrder = pseudoOrder
			}
		}
	}
}

// NewSession creates a new persistent session with cookie management
func NewSession(preset string, opts ...SessionOption) *Session {
	cfg := &sessionConfig{
		preset:  preset,
		timeout: 30 * time.Second,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	sessionCfg := &protocol.SessionConfig{
		Preset:                        cfg.preset,
		Proxy:                         cfg.proxy,
		TCPProxy:                      cfg.tcpProxy,
		UDPProxy:                      cfg.udpProxy,
		Timeout:                       int(cfg.timeout.Seconds()),
		InsecureSkipVerify:            cfg.insecureSkipVerify,
		TLSVerifyPeerCertificate:      cfg.tlsVerifyPeerCertificate,
		TLSVerifyConnection:           cfg.tlsVerifyConnection,
		TLSRootCAs:                    cfg.tlsRootCAs,
		FollowRedirects:               !cfg.disableRedirects,
		MaxRedirects:                  cfg.maxRedirects,
		PreferIPv4:                    cfg.preferIPv4,
		ConnectTo:                     cfg.connectTo,
		ECHConfigDomain:               cfg.echConfigDomain,
		TLSOnly:                       cfg.tlsOnly,
		QuicIdleTimeout:               int(cfg.quicIdleTimeout.Seconds()),
		LocalAddress:                  cfg.localAddr,
		KeyLogFile:                    cfg.keyLogFile,
		DisableECH:                    cfg.disableECH,
		EnableSpeculativeTLS:          cfg.enableSpeculativeTLS,
		SwitchProtocol:                cfg.switchProtocol,
		WithoutCookieJar:              cfg.withoutCookieJar,
		WithoutConditionalCache:       cfg.withoutConditionalCache,
		WithoutClientHints:            cfg.withoutClientHints,
		WithoutHighEntropyClientHints: cfg.withoutHighEntropyClientHints,
	}

	// Retry configuration
	if cfg.retryCount > 0 {
		sessionCfg.RetryEnabled = true
		sessionCfg.MaxRetries = cfg.retryCount
		if cfg.retryWaitMin > 0 {
			sessionCfg.RetryWaitMin = int(cfg.retryWaitMin.Milliseconds())
		}
		if cfg.retryWaitMax > 0 {
			sessionCfg.RetryWaitMax = int(cfg.retryWaitMax.Milliseconds())
		}
		if len(cfg.retryOnStatus) > 0 {
			sessionCfg.RetryOnStatus = cfg.retryOnStatus
		}
	}

	// Protocol forcing
	if cfg.forceHTTP1 {
		sessionCfg.ForceHTTP1 = true
		sessionCfg.DisableHTTP3 = true
	}
	if cfg.forceHTTP2 {
		sessionCfg.ForceHTTP2 = true
		sessionCfg.DisableHTTP3 = true
	}
	if cfg.forceHTTP3 {
		sessionCfg.ForceHTTP3 = true
	}
	if cfg.disableHTTP3 {
		sessionCfg.DisableHTTP3 = true
	}

	// Create session with optional distributed cache and custom fingerprint
	var s *session.Session
	needsOpts := cfg.sessionCacheBackend != nil || cfg.customJA3 != "" || cfg.customH2Settings != nil || len(cfg.customPseudoOrder) > 0 || cfg.customTCPFingerprint != nil
	if needsOpts {
		opts := &session.SessionOptions{
			SessionCacheBackend:       cfg.sessionCacheBackend,
			SessionCacheErrorCallback: cfg.sessionCacheErrorCallback,
			CustomJA3:                 cfg.customJA3,
			CustomJA3Extras:           cfg.customJA3Extras,
			CustomH2Settings:          cfg.customH2Settings,
			CustomPseudoOrder:         cfg.customPseudoOrder,
			CustomTCPFingerprint:      cfg.customTCPFingerprint,
		}
		s = session.NewSessionWithOptions("", sessionCfg, opts)
	} else {
		s = session.NewSession("", sessionCfg)
	}
	// An unrecognised preset name is a config error, not something to paper
	// over. Get() answers it with chrome-146, so a single mistyped character
	// used to put a three-version-old fingerprint on the wire with nothing said
	// about it, which is the one failure this library exists to prevent.
	//
	// Deferred like the other config errors: NewSession has no error return, so
	// it surfaces on the first request rather than at construction.
	configErr := cfg.configErr
	if configErr == nil && cfg.preset != "" && fingerprint.GetStrict(cfg.preset) == nil {
		configErr = fingerprint.UnknownPresetError(cfg.preset)
	}
	return &Session{inner: s, configErr: configErr}
}

// toResponse converts a transport response, including its redirect history.
// A nil input gives a nil output, because the session may return a response
// alongside an error (ErrTooManyRedirects, ErrBodyNotReplayable) and may return
// neither.
func toResponse(resp *transport.Response) *Response {
	if resp == nil {
		return nil
	}

	var history []*RedirectInfo
	if len(resp.History) > 0 {
		history = make([]*RedirectInfo, len(resp.History))
		for i, h := range resp.History {
			history[i] = &RedirectInfo{
				StatusCode: h.StatusCode,
				URL:        h.URL,
				Headers:    h.Headers,
			}
		}
	}

	return &Response{
		StatusCode:  resp.StatusCode,
		Headers:     resp.Headers,
		HeaderOrder: resp.HeaderOrder,
		Trailer:     resp.Trailer,
		HeaderCasing: resp.HeaderCasing,
		Body:        resp.Body,
		FinalURL:    resp.FinalURL,
		Protocol:    resp.Protocol,
		History:     history,
	}
}

// Do executes a request within the session, maintaining cookies.
//
// A non-nil response can accompany a non-nil error: ErrTooManyRedirects and
// ErrBodyNotReplayable both hand back the 3xx that ended the chain, so a caller
// can read its Location and decide what to do. The body is buffered, so
// ignoring that response leaks nothing.
func (s *Session) Do(ctx context.Context, req *Request) (*Response, error) {
	if s.configErr != nil {
		return nil, s.configErr
	}
	sReq := &transport.Request{
		Method:                        req.Method,
		URL:                           req.URL,
		Headers:                       req.Headers,
		ExactHeaders:                  req.ExactHeaders,
		BodyReader:                    req.Body,
		GetBody:                       req.GetBody,
		TLSOnly:                       req.TLSOnly,
		FollowRedirects:               req.FollowRedirects,
		DisableConditionalCache:       req.DisableConditionalCache,
		DisableClientHints:            req.DisableClientHints,
		DisableHighEntropyClientHints: req.DisableHighEntropyClientHints,
		DisableRedirectReferer:        req.DisableRedirectReferer,
		HeaderOrder:                   req.HeaderOrder,
		OnRedirect:                    req.OnRedirect,
		Timeout:                       req.Timeout,
	}

	resp, err := s.inner.Request(ctx, sReq)
	if err != nil {
		return toResponse(resp), err
	}
	return toResponse(resp), nil
}

// DoWithBody executes a request with an io.Reader as the body for streaming
// uploads. The reader replaces Request.Body; Request.GetBody, if set, still
// applies and must re-open the same content.
//
// As with Do, a non-nil response can accompany a non-nil error.
func (s *Session) DoWithBody(ctx context.Context, req *Request, bodyReader io.Reader) (*Response, error) {
	if s.configErr != nil {
		return nil, s.configErr
	}
	sReq := &transport.Request{
		Method:                        req.Method,
		URL:                           req.URL,
		Headers:                       req.Headers,
		ExactHeaders:                  req.ExactHeaders,
		BodyReader:                    bodyReader,
		GetBody:                       req.GetBody,
		TLSOnly:                       req.TLSOnly,
		FollowRedirects:               req.FollowRedirects,
		DisableConditionalCache:       req.DisableConditionalCache,
		DisableClientHints:            req.DisableClientHints,
		DisableHighEntropyClientHints: req.DisableHighEntropyClientHints,
		DisableRedirectReferer:        req.DisableRedirectReferer,
		HeaderOrder:                   req.HeaderOrder,
		OnRedirect:                    req.OnRedirect,
		Timeout:                       req.Timeout,
	}

	resp, err := s.inner.Request(ctx, sReq)
	if err != nil {
		return toResponse(resp), err
	}
	return toResponse(resp), nil
}

// Get performs a GET request within the session
func (s *Session) Get(ctx context.Context, url string) (*Response, error) {
	return s.Do(ctx, &Request{Method: "GET", URL: url})
}

// CookieInfo represents a cookie with full metadata (domain, path, expiry, etc.)
type CookieInfo = session.CookieState

// GetCookies returns all cookies stored in the session with full metadata.
//
// Note: In bindings (Node.js, Python, .NET), GetCookies currently returns a
// flat name-value map for backward compatibility, with a deprecation warning.
// In a future release, all bindings will change to return the same []CookieInfo
// format as this Go method. GetCookiesDetailed already returns this format in
// all bindings.
func (s *Session) GetCookies() []CookieInfo {
	return s.inner.GetCookies()
}

// GetCookiesDetailed returns all cookies with full metadata (domain, path, expiry, etc.)
func (s *Session) GetCookiesDetailed() []CookieInfo {
	return s.inner.GetCookies()
}

// SetCookie sets a cookie in the session with full metadata
func (s *Session) SetCookie(cookie CookieInfo) {
	s.inner.SetCookie(cookie.Name, cookie.Value, cookie.Domain, cookie.Path, cookie.Secure, cookie.HttpOnly, cookie.SameSite, cookie.MaxAge, cookie.Expires)
}

// DeleteCookie removes cookies by name. If domain is empty, removes from all domains.
func (s *Session) DeleteCookie(name, domain string) {
	s.inner.DeleteCookie(name, domain)
}

// ClearCookies removes all cookies from the session
func (s *Session) ClearCookies() {
	s.inner.ClearCookies()
}

// SetProxy sets or updates the proxy for all protocols (HTTP/1.1, HTTP/2, HTTP/3)
// This closes existing connections and recreates transports with the new proxy
// Pass empty string to switch to direct connection
func (s *Session) SetProxy(proxyURL string) {
	s.inner.SetProxy(proxyURL)
}

// SetTCPProxy sets the proxy for TCP protocols (HTTP/1.1, HTTP/2)
func (s *Session) SetTCPProxy(proxyURL string) {
	s.inner.SetTCPProxy(proxyURL)
}

// SetUDPProxy sets the proxy for UDP protocols (HTTP/3 via SOCKS5 or MASQUE)
func (s *Session) SetUDPProxy(proxyURL string) {
	s.inner.SetUDPProxy(proxyURL)
}

// GetProxy returns the current proxy URL (unified proxy or TCP proxy)
func (s *Session) GetProxy() string {
	return s.inner.GetProxy()
}

// GetTCPProxy returns the current TCP proxy URL
func (s *Session) GetTCPProxy() string {
	return s.inner.GetTCPProxy()
}

// GetUDPProxy returns the current UDP proxy URL
func (s *Session) GetUDPProxy() string {
	return s.inner.GetUDPProxy()
}

// SetHeaderOrder sets a custom header order for all requests.
// Pass nil or empty slice to reset to preset's default order.
// Order should contain lowercase header names.
//
// The list is a prefix, not a replacement: the headers named here lead in the
// order given, the preset's own table then covers whatever they did not name,
// and anything still unplaced follows sorted by name. A partial list therefore
// costs nothing for the headers it leaves out.
//
// This mutates shared session state, so it is the wrong tool when only one
// request needs a different order — callers would have to serialize around it.
// Set Request.HeaderOrder instead: it applies to that request alone and ignores
// whatever is installed here.
func (s *Session) SetHeaderOrder(order []string) {
	s.inner.SetHeaderOrder(order)
}

// GetHeaderOrder returns the current header order.
// Returns preset's default order if no custom order is set.
func (s *Session) GetHeaderOrder() []string {
	return s.inner.GetHeaderOrder()
}

// SetSessionIdentifier sets a session identifier for TLS cache key isolation.
// This is used when the session is registered with a LocalProxy to ensure
// TLS sessions are isolated per proxy/session configuration in distributed caches.
func (s *Session) SetSessionIdentifier(sessionId string) {
	s.inner.SetSessionIdentifier(sessionId)
}

// Stats returns a snapshot of session counters and timestamps.
func (s *Session) Stats() session.SessionStats {
	return s.inner.Stats()
}

// IdleTime returns time since the session last serviced a request.
func (s *Session) IdleTime() time.Duration {
	return s.inner.IdleTime()
}

// IsActive reports whether the session is still usable. False once Close has run.
func (s *Session) IsActive() bool {
	return s.inner.IsActive()
}

// Touch resets the idle timer to now without issuing a request.
func (s *Session) Touch() {
	s.inner.Touch()
}

// ClearCache drops the conditional-request cache (ETag / Last-Modified entries).
// Cookies and TLS tickets are not affected.
func (s *Session) ClearCache() {
	s.inner.ClearCache()
}

// SetConditionalCacheEnabled toggles the session's ETag / If-Modified-Since
// handling at runtime. When false, the session stops injecting cache
// validators on outgoing requests and stops storing them from responses.
// Pair with ClearCache to also wipe any previously-stored validators.
func (s *Session) SetConditionalCacheEnabled(enabled bool) {
	s.inner.SetConditionalCacheEnabled(enabled)
}

// ConditionalCacheEnabled reports whether the session is currently injecting
// and storing ETag / If-Modified-Since validators.
func (s *Session) ConditionalCacheEnabled() bool {
	return s.inner.ConditionalCacheEnabled()
}

// SetClientHintsEnabled toggles ALL UA client hints (the sec-ch-ua trio plus the
// high-entropy hints) at runtime. When false, only sec-ch-* headers the caller
// sets explicitly are sent.
func (s *Session) SetClientHintsEnabled(enabled bool) {
	s.inner.SetClientHintsEnabled(enabled)
}

// ClientHintsEnabled reports whether UA client hints are currently enabled.
func (s *Session) ClientHintsEnabled() bool {
	return s.inner.ClientHintsEnabled()
}

// SetHighEntropyClientHintsEnabled toggles only the high-entropy UA client hints
// at runtime; the always-on sec-ch-ua trio is unaffected.
func (s *Session) SetHighEntropyClientHintsEnabled(enabled bool) {
	s.inner.SetHighEntropyClientHintsEnabled(enabled)
}

// HighEntropyClientHintsEnabled reports whether the high-entropy UA client hints
// are currently enabled.
func (s *Session) HighEntropyClientHintsEnabled() bool {
	return s.inner.HighEntropyClientHintsEnabled()
}

// SetFollowRedirects toggles the session's redirect-following policy at
// runtime. A per-request Request.FollowRedirects override still wins over
// this value for that one request.
func (s *Session) SetFollowRedirects(enabled bool) {
	s.inner.SetFollowRedirects(enabled)
}

// SetMaxRedirects updates the session's redirect cap at runtime. Values
// of zero or below are ignored, leaving the prior cap (or the default
// of 10) in place.
func (s *Session) SetMaxRedirects(max int) {
	s.inner.SetMaxRedirects(max)
}

// FollowRedirects reports the session's current redirect-following policy.
// Per-request overrides via Request.FollowRedirects don't change this value.
func (s *Session) FollowRedirects() bool {
	return s.inner.FollowRedirects()
}

// MaxRedirects reports the session's current redirect cap.
func (s *Session) MaxRedirects() int {
	return s.inner.MaxRedirects()
}

// GetTransport returns the underlying transport. Escape hatch for advanced
// transport-level access; the lib reserves the right to evolve the transport
// surface between releases.
func (s *Session) GetTransport() *transport.Transport {
	return s.inner.GetTransport()
}

// Warmup simulates a real browser page load to warm TLS sessions, cookies,
// and cache state. Fetches the HTML page and its subresources (CSS, JS, images)
// with realistic headers, priorities, and timing.
func (s *Session) Warmup(ctx context.Context, url string) error {
	return s.inner.Warmup(ctx, url)
}

// Fork creates n new sessions that share cookies and TLS session caches with
// the parent, but have independent connections. This simulates multiple browser
// tabs — same cookies, same TLS resumption tickets, same fingerprint, but
// independent TCP/QUIC connections for parallel requests.
func (s *Session) Fork(n int) []*Session {
	innerForks := s.inner.Fork(n)
	if innerForks == nil {
		return nil
	}
	forks := make([]*Session, len(innerForks))
	for i, inner := range innerForks {
		forks[i] = &Session{inner: inner}
	}
	return forks
}

// Close closes the session and releases resources immediately. Any request
// still in flight, including a body still being read, is interrupted.
func (s *Session) Close() {
	s.inner.Close()
}

// CloseGraceful closes the session without interrupting requests that are in
// flight. The session stops accepting new requests at once; idle connections
// close now, and a connection still delivering a response body closes when that
// body is finished. It returns immediately, and calling Close afterwards forces
// anything still draining. This is the right call when retiring a long-lived
// session that other goroutines may still be reading responses from.
//
// HTTP/1.1 and HTTP/2 connections drain as described. HTTP/3 connections are
// closed immediately, as by Close.
func (s *Session) CloseGraceful() {
	s.inner.CloseGraceful()
}

// Refresh closes all connections but keeps TLS session caches and cookies intact.
// This simulates a browser page refresh - new TCP/QUIC connections but TLS resumption.
// If a switchProtocol was configured, the session switches to that protocol.
func (s *Session) Refresh() {
	s.inner.Refresh()
}

// RefreshWithProtocol closes all connections and switches to a new protocol.
// The protocol change persists for future Refresh() calls as well.
// Valid protocols: "h1", "h2", "h3", "auto".
func (s *Session) RefreshWithProtocol(protocol string) error {
	return s.inner.RefreshWithProtocol(protocol)
}

// Save exports session state (cookies, TLS sessions) to a file
func (s *Session) Save(path string) error {
	return s.inner.Save(path)
}

// Marshal exports session state to JSON bytes
func (s *Session) Marshal() ([]byte, error) {
	return s.inner.Marshal()
}

// SessionLoadOptions supplies the parts of a saved session's configuration that
// JSON cannot carry: the certificate verification hooks installed with
// WithVerifyPeerCertificate and WithVerifyConnection, and the trust store
// installed with WithTLSConfig.
//
// Those are Go functions and a *x509.CertPool, so Save can only record THAT
// they were configured, never what they did. The fields here take exactly what
// those options take.
type SessionLoadOptions = session.SessionLoadOptions

// LoadSession loads a session from a file.
//
// Fails if the saved session had certificate verification hooks configured.
// They cannot be serialised, and restoring without them would hand back a
// session that accepts certificates the saved one would have rejected, with
// nothing to say so. Use LoadSessionWithOptions to pass them back in.
func LoadSession(path string) (*Session, error) {
	return LoadSessionWithOptions(path, nil)
}

// LoadSessionWithOptions loads a session from a file, re-supplying the
// verification hooks it was saved with.
func LoadSessionWithOptions(path string, opts *SessionLoadOptions) (*Session, error) {
	inner, err := session.LoadSessionWithOptions(path, opts)
	if err != nil {
		return nil, err
	}
	return &Session{inner: inner}, nil
}

// UnmarshalSession loads a session from JSON bytes.
//
// Fails if the saved session had certificate verification hooks configured. See
// LoadSession.
func UnmarshalSession(data []byte) (*Session, error) {
	return UnmarshalSessionWithOptions(data, nil)
}

// UnmarshalSessionWithOptions loads a session from JSON bytes, re-supplying the
// verification hooks it was saved with.
func UnmarshalSessionWithOptions(data []byte, opts *SessionLoadOptions) (*Session, error) {
	inner, err := session.UnmarshalSessionWithOptions(data, opts)
	if err != nil {
		return nil, err
	}
	return &Session{inner: inner}, nil
}

// StreamResponse represents a streaming HTTP response where the body
// is read incrementally. Use this for large file downloads.
type StreamResponse struct {
	StatusCode int
	Headers    map[string][]string

	// HeaderOrder is the order the server sent its headers in, lowercase. See
	// Response.HeaderOrder; nil on HTTP/1.1.
	HeaderOrder []string

	FinalURL      string
	Protocol      string
	ContentLength int64 // -1 if unknown (chunked encoding)

	inner *transport.StreamResponse
}

// Trailer returns the trailing header block, lowercase-keyed, or nil when there
// was none.
//
// Call it after the body has been read to EOF. On a streamed response the
// trailers have not arrived before then, which is why this is a method rather
// than the plain field it is on the buffered Response. gRPC is the case that
// needs it: the call's real status arrives in the trailers, not the headers.
func (r *StreamResponse) Trailer() map[string][]string {
	if r == nil || r.inner == nil {
		return nil
	}
	return r.inner.Trailer()
}

// Read reads data from the response body
func (r *StreamResponse) Read(p []byte) (n int, err error) {
	return r.inner.Read(p)
}

// Close closes the response body - must be called when done
func (r *StreamResponse) Close() error {
	return r.inner.Close()
}

// ReadAll reads the entire response body into memory
// This defeats the purpose of streaming but is useful for small responses
func (r *StreamResponse) ReadAll() ([]byte, error) {
	return r.inner.ReadAll()
}

// ReadChunk reads up to size bytes from the response
func (r *StreamResponse) ReadChunk(size int) ([]byte, error) {
	return r.inner.ReadChunk(size)
}

// DoStream executes an HTTP request and returns a streaming response
// The caller is responsible for closing the response when done
// Note: Streaming does NOT support redirects - use Do() for redirect handling.
// Request.OnRedirect is therefore not carried here: it would never fire, and
// wiring it would suggest otherwise.
func (s *Session) DoStream(ctx context.Context, req *Request) (*StreamResponse, error) {
	if s.configErr != nil {
		return nil, s.configErr
	}
	sReq := &transport.Request{
		Method:                        req.Method,
		URL:                           req.URL,
		Headers:                       req.Headers,
		ExactHeaders:                  req.ExactHeaders,
		BodyReader:                    req.Body,
		GetBody:                       req.GetBody,
		TLSOnly:                       req.TLSOnly,
		FollowRedirects:               req.FollowRedirects,
		DisableConditionalCache:       req.DisableConditionalCache,
		DisableClientHints:            req.DisableClientHints,
		DisableHighEntropyClientHints: req.DisableHighEntropyClientHints,
		DisableRedirectReferer:        req.DisableRedirectReferer,
		HeaderOrder:                   req.HeaderOrder,
		Timeout:                       req.Timeout,
	}

	resp, err := s.inner.RequestStream(ctx, sReq)
	if err != nil {
		return nil, err
	}

	return &StreamResponse{
		StatusCode:    resp.StatusCode,
		Headers:       resp.Headers,
		HeaderOrder:   resp.HeaderOrder,
		FinalURL:      resp.FinalURL,
		Protocol:      resp.Protocol,
		ContentLength: resp.ContentLength,
		inner:         resp,
	}, nil
}

// GetStream performs a streaming GET request
func (s *Session) GetStream(ctx context.Context, url string) (*StreamResponse, error) {
	return s.DoStream(ctx, &Request{Method: "GET", URL: url})
}

// GetStreamWithHeaders performs a streaming GET request with custom headers
func (s *Session) GetStreamWithHeaders(ctx context.Context, url string, headers map[string][]string) (*StreamResponse, error) {
	return s.DoStream(ctx, &Request{Method: "GET", URL: url, Headers: headers})
}

// Presets returns available fingerprint presets
func Presets() []string {
	return fingerprint.Available()
}

// ValidateSessionFile validates a session file without loading it.
// Returns nil if the file at path is a valid httpcloak session blob,
// or a descriptive error otherwise. Useful for pre-flight checks before
// LoadSession on user-supplied paths.
func ValidateSessionFile(path string) error {
	return session.ValidateSessionFile(path)
}

// SetKeyLogWriter installs a process-global writer that the lib uses to
// emit TLS keylog lines (NSS keylog format). Pass nil to disable.
//
// This is the io.Writer-flavoured sibling of WithSessionKeyLogFile, which
// takes a file path. Use SetKeyLogWriter when the destination is something
// other than a file: a ring buffer, an S3 multipart uploader, a syslog
// pipe, etc. Setting a writer affects every TLS handshake the binary
// performs from the moment it's set.
func SetKeyLogWriter(w io.Writer) {
	transport.SetKeyLogWriter(w)
}

// Manager is an in-process registry for many sessions at once. It's the
// right tool for worker pools, multi-tenant scrapers, or any service that
// needs to look up sessions by external ID with bounded concurrency and
// idle eviction. Re-exported from the session subpackage so callers don't
// have to import it directly. See the connection-lifecycle/session-manager
// chapter for usage.
type Manager = session.Manager

// NewManager constructs a fresh session Manager with the package defaults
// (max 100 concurrent sessions, 30-minute idle timeout, 1-minute cleanup
// interval). Override the bounds with Manager.SetMaxSessions and
// Manager.SetSessionTimeout.
func NewManager() *Manager {
	return session.NewManager()
}

// signatureSchemeNames is the spelling vocabulary for signature algorithms.
//
// It is not exhaustive and cannot be: TLS gains codepoints faster than a name
// table gets updated, and this library's job is to reproduce whatever a real
// client sent. parseSignatureAlgorithmsStrict therefore also accepts a raw
// codepoint, so a caller is never blocked on a name being added here.
var signatureSchemeNames = map[string]tls.SignatureScheme{
	"ecdsa_secp256r1_sha256": tls.ECDSAWithP256AndSHA256,
	"ecdsa_secp384r1_sha384": tls.ECDSAWithP384AndSHA384,
	"ecdsa_secp521r1_sha512": tls.ECDSAWithP521AndSHA512,
	"rsa_pss_rsae_sha256":    tls.PSSWithSHA256,
	"rsa_pss_rsae_sha384":    tls.PSSWithSHA384,
	"rsa_pss_rsae_sha512":    tls.PSSWithSHA512,
	"rsa_pkcs1_sha256":       tls.PKCS1WithSHA256,
	"rsa_pkcs1_sha384":       tls.PKCS1WithSHA384,
	"rsa_pkcs1_sha512":       tls.PKCS1WithSHA512,
	// Present in real captures and previously unspellable.
	"rsa_pkcs1_sha1": 0x0201,
	"ecdsa_sha1":     0x0203,
	"ed25519":        0x0807,
	"ed448":          0x0808,
	// draft-ietf-tls-mldsa. Chrome 150+ sends these on TCP but not on QUIC,
	// which is why presets carry separate TCP and QUIC sig-alg lists.
	"mldsa44": 0x0904,
	"mldsa65": 0x0905,
	"mldsa87": 0x0906,
}

// parseSignatureAlgorithmsStrict converts names or raw codepoints to schemes,
// reporting anything it does not understand.
//
// The previous version silently dropped unknown names, which is the worst
// failure mode for a fingerprinting library: the request succeeds, the
// extension is short, and nothing says why. A caller asking for ML-DSA got an
// empty list and a Chrome 146 signature_algorithms extension.
//
// A codepoint may be written "0x0904" or "2308"; both reach the same value.
func parseSignatureAlgorithmsStrict(names []string) ([]tls.SignatureScheme, error) {
	var result []tls.SignatureScheme
	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		if scheme, ok := signatureSchemeNames[key]; ok {
			result = append(result, scheme)
			continue
		}
		if n, err := strconv.ParseUint(key, 0, 16); err == nil {
			result = append(result, tls.SignatureScheme(n))
			continue
		}
		return nil, fmt.Errorf("unknown signature algorithm %q: use a known name or a "+
			"codepoint such as 0x0904", name)
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

// parseSignatureAlgorithms is the lenient form kept for callers that cannot
// report an error. Prefer parseSignatureAlgorithmsStrict.
func parseSignatureAlgorithms(names []string) []tls.SignatureScheme {
	result, _ := parseSignatureAlgorithmsStrict(names)
	return result
}

// parseCertCompression converts string names to tls.CertCompressionAlgo values.
func parseCertCompression(names []string) []tls.CertCompressionAlgo {
	m := map[string]tls.CertCompressionAlgo{
		"brotli": tls.CertCompressionBrotli,
		"zlib":   tls.CertCompressionZlib,
		"zstd":   tls.CertCompressionZstd,
	}
	var result []tls.CertCompressionAlgo
	for _, name := range names {
		if algo, ok := m[strings.ToLower(name)]; ok {
			result = append(result, algo)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// TrimMemory returns freed memory to the operating system and blocks until it
// has.
//
// Closing a session makes its memory collectable, which is a different thing
// from giving it back. Go's scavenger releases pages lazily and on Linux it
// does so with MADV_FREE, which lets the kernel reclaim the pages under
// pressure but leaves them counted against the process until it does. So RSS
// stays flat, or drifts slightly up, long after the sessions are gone. Measured
// over 150 sessions each doing a real TLS request: 85MB resident, and closing
// every one of them then forcing a garbage collection moved it by less than
// three megabytes, in the wrong direction.
//
// This is a ceiling rather than a leak. It is bounded by how many sessions are
// alive at once, and a long-running process reuses those pages for the next
// batch instead of growing without limit. Reach for this when the ceiling
// itself is the problem: a worker that has just finished a large batch and will
// now sit idle, a process sharing a memory-capped container with something
// else, or a fork-per-job model measuring RSS.
//
// It is deliberately NOT called by Close, and that is worth saying plainly
// because it looks like the obvious home for it. This stops the world for the
// length of a full collection, so a pool closing sessions steadily would pay
// that on every single one, and the cost lands on exactly the workloads that
// close sessions most. Calling it once between batches costs the same one
// collection and gives back the same memory.
//
// It is process-wide, not per session, which is why it is a package function
// and not a method: the runtime has one heap and this hands back all of the
// free part of it, whoever allocated it.
func TrimMemory() {
	debug.FreeOSMemory()
}
