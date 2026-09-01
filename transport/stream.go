package transport

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/protocol"
)

// StreamResponse represents a streaming HTTP response where the body
// is read incrementally rather than all at once.
type StreamResponse struct {
	StatusCode int
	Headers    map[string][]string // Multi-value headers

	// HeaderOrder is the order the peer sent its headers in, lowercase. See
	// Response.HeaderOrder; nil on HTTP/1.1.
	HeaderOrder []string

	FinalURL string
	Timing   *protocol.Timing
	Protocol string // "h1", "h2", or "h3"

	// ContentLength is the expected total size (-1 if unknown/chunked)
	ContentLength int64

	// The underlying response body reader
	reader       io.ReadCloser
	decompressor io.Closer
	rawReader    io.ReadCloser

	// Context cancel function - called when response is closed
	cancel context.CancelFunc

	// done is the stream context's Done channel (cancelled by Close()). Lines()
	// selects on it so its goroutine unblocks instead of leaking when a caller
	// abandons iteration and closes the response.
	done <-chan struct{}

	// httpResp is kept only so Trailer() can read the trailing block. On a
	// streamed response the trailers are not known when the header block
	// arrives, so they cannot be a plain field the way they are on a buffered
	// Response; they have to be read back after the body reaches EOF.
	httpResp *http.Response
}

// Trailer returns the trailing header block, lowercase-keyed, or nil when the
// response carried none.
//
// Call it only after the body has been read to EOF. Before that the trailing
// block has not arrived and this returns nil, or on HTTP/1.1 the declared names
// with no values, which is what the protocol makes available at that point.
// This is the streaming counterpart of Response.Trailer, which can be a plain
// field because that path buffers the body first.
//
// gRPC is the case that needs it: the call's real status arrives here, not in
// the response headers, so a streamed gRPC call read without this reports every
// failure as a 200.
func (r *StreamResponse) Trailer() map[string][]string {
	if r == nil || r.httpResp == nil {
		return nil
	}
	return buildTrailerMap(r.httpResp.Trailer)
}

// Read reads data from the response body
func (r *StreamResponse) Read(p []byte) (n int, err error) {
	return r.reader.Read(p)
}

// Close closes the response body and cancels the context
func (r *StreamResponse) Close() error {
	if r.cancel != nil {
		r.cancel()
	}
	if r.decompressor != nil {
		r.decompressor.Close()
	}
	if r.rawReader != nil {
		return r.rawReader.Close()
	}
	return nil
}

// ReadAll reads the entire response body into memory
// This defeats the purpose of streaming but is useful for small responses
func (r *StreamResponse) ReadAll() ([]byte, error) {
	defer r.Close()
	return io.ReadAll(r.reader)
}

// ReadChunk reads up to size bytes from the response
func (r *StreamResponse) ReadChunk(size int) ([]byte, error) {
	buf := make([]byte, size)
	n, err := r.reader.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], err
}

// Scanner returns a bufio.Scanner for line-by-line reading
func (r *StreamResponse) Scanner() *bufio.Scanner {
	return bufio.NewScanner(r.reader)
}

// Lines returns a channel that yields lines from the response
// Close the response when done to stop iteration
func (r *StreamResponse) Lines() <-chan string {
	ch := make(chan string)
	done := r.done
	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(r.reader)
		for scanner.Scan() {
			// Select on done so an abandoned iteration (caller stopped ranging
			// and called Close(), which cancels the stream context) unblocks this
			// send instead of pinning the goroutine + body/conn forever.
			select {
			case ch <- scanner.Text():
			case <-done:
				return
			}
		}
	}()
	return ch
}

// IsSuccess returns true if the status code is 2xx
func (r *StreamResponse) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// DoStream executes an HTTP request and returns a streaming response
// The caller is responsible for closing the response when done
func (t *Transport) DoStream(ctx context.Context, req *Request) (*StreamResponse, error) {
	// Parse URL to determine scheme
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "", err)
	}

	// Snapshot the mutable fields once so a concurrent SetProxy/SetPreset/
	// SetProtocol can't race the dispatch below (see transportSnapshot).
	snap := t.snapshot()

	// tcpBlocked is non-nil only when a proxy IS configured but cannot carry TCP
	// (a UDP-only MASQUE proxy). Any H1/H2 dispatch must then refuse rather than
	// dial the target directly, which would leak the real client IP + SNI.
	tcpBlocked := snap.tcpProxyError

	// For HTTP (non-TLS), only HTTP/1.1 is supported
	if parsedURL.Scheme == "http" {
		if tcpBlocked != nil {
			return nil, tcpBlocked
		}
		return t.doStreamHTTP1(ctx, req)
	}

	// When proxy is configured, select protocol based on proxy capabilities.
	// QUIC capability is decided by the UDP-side proxy (UDPProxy, else the unified
	// URL) — matching how the H3 transport is built and the buffered Do path — so
	// a split config (TCPProxy=http, UDPProxy=socks5) still gets H3.
	if snap.proxy != nil && (snap.proxy.URL != "" || snap.proxy.TCPProxy != "" || snap.proxy.UDPProxy != "") {
		udpEffectiveProxyURL := snap.proxy.UDPProxy
		if udpEffectiveProxyURL == "" {
			udpEffectiveProxyURL = snap.proxy.URL
		}
		if SupportsQUIC(udpEffectiveProxyURL) {
			if tcpBlocked != nil {
				// UDP-only proxy (MASQUE): only H3 can reach the target. Racing
				// would fire an H2 probe that dials direct and leaks the real
				// IP + SNI, so stream over H3 with no TCP fallback.
				return t.doStreamHTTP3(ctx, req)
			}
			// Race H3/H2 rather than trying H3 first: a proxy that cannot relay
			// QUIC would otherwise stall ~5s on the H3 handshake before falling
			// back. doStreamAuto probes both (proxy-aware) and dispatches once.
			return t.doStreamAuto(ctx, req)
		}
		// HTTP/HTTPS proxy - use HTTP/2
		if tcpBlocked != nil {
			return nil, tcpBlocked
		}
		return t.doStreamHTTP2(ctx, req)
	}

	// Default HTTPS: Try HTTP/3 first, fallback to HTTP/2
	switch snap.protocol {
	case ProtocolHTTP1:
		return t.doStreamHTTP1(ctx, req)
	case ProtocolHTTP2:
		return t.doStreamHTTP2(ctx, req)
	case ProtocolHTTP3:
		return t.doStreamHTTP3(ctx, req)
	default:
		// Auto mode: race H3 and H2 connection probes, dispatch on the winner.
		return t.doStreamAuto(ctx, req)
	}
}

// streamEffectiveTimeout returns the timeout that bounds ONLY connection
// establishment for a streaming request: the per-request Timeout wins, else the
// transport/session timeout. Zero means "no establishment bound" (the parent
// context still applies). It intentionally does not cap total stream duration.
func (t *Transport) streamEffectiveTimeout(req *Request) time.Duration {
	if req.Timeout > 0 {
		return req.Timeout
	}
	return t.timeout
}

// boundStreamEstablishment installs a watchdog that cancels the stream context
// if connection establishment (dial + TLS handshake + proxy CONNECT, all of
// which run inside the RoundTrip) overruns timeout. It returns a finish func to
// call once RoundTrip has returned; finish stops the watchdog so it never bounds
// the body read that follows. A zero/negative timeout installs nothing.
//
// A microsecond-wide window remains: if establishment completes at the exact
// instant the deadline fires, the watchdog may cancel a stream that just became
// ready. That only happens when establishment consumed essentially the whole
// timeout, i.e. the request was already at its deadline.
func boundStreamEstablishment(timeout time.Duration, cancel context.CancelFunc) (finish func()) {
	if timeout <= 0 {
		return func() {}
	}
	var established atomic.Bool
	timer := time.AfterFunc(timeout, func() {
		if !established.Load() {
			cancel()
		}
	})
	return func() {
		established.Store(true)
		timer.Stop()
	}
}

// doStreamAuto selects a protocol for a streaming request without paying the
// sequential "try H3 first" stall. It reuses any cached per-host protocol
// decision (shared with the buffered doAuto path); otherwise it races proxy-
// aware connection probes and dispatches the single stream on the winner.
// Only the probe is raced, never the request, so the body is sent exactly once
// (safe for non-idempotent methods).
func (t *Transport) doStreamAuto(ctx context.Context, req *Request) (*StreamResponse, error) {
	host := extractHost(req.URL)

	// Snapshot preset + h3 once so SetPreset/SetProxy can't race these reads.
	snap := t.snapshot()

	// Reuse a prior decision for this host.
	t.protocolSupportMu.RLock()
	known, ok := t.protocolSupport[host]
	t.protocolSupportMu.RUnlock()
	if ok {
		switch known {
		case ProtocolHTTP3:
			resp, err := t.doStreamHTTP3(ctx, req)
			if err == nil {
				return resp, nil
			}
			if req.BodyReader != nil {
				// A one-shot BodyReader may have been partially drained by the
				// H3 attempt; re-sending it on H2 would corrupt the body. Surface
				// the H3 error instead of silently sending a truncated request.
				return nil, err
			}
			return t.doStreamHTTP2OrHTTP1(ctx, req)
		case ProtocolHTTP1:
			return t.doStreamHTTP1(ctx, req)
		case ProtocolHTTP2:
			return t.doStreamHTTP2OrHTTP1(ctx, req)
		}
	}

	// No cached decision yet: race a connection probe when H3 is viable.
	if snap.preset.SupportHTTP3 && snap.h3 != nil {
		port := "443"
		if u, err := url.Parse(req.URL); err == nil && u.Port() != "" {
			port = u.Port()
		}
		// Bound the connection-probe race with the effective timeout so a stalled
		// host/proxy fails fast instead of riding the internal probe budget. Only
		// the probe is bounded here; the stream body dispatched below runs
		// unbounded (its own establishment is watchdog-bounded in doStreamHTTPx).
		probeCtx := ctx
		if to := t.streamEffectiveTimeout(req); to > 0 {
			var probeCancel context.CancelFunc
			probeCtx, probeCancel = context.WithTimeout(ctx, to)
			defer probeCancel()
		}
		decision := t.raceConnectProtocol(probeCtx, host, port)
		switch {
		case decision.err != nil:
			return nil, decision.err
		case decision.alpnErr != nil:
			// The probe negotiated http/1.1: the server is H1-only. Drop the probe
			// conn and stream over HTTP/1.1 directly (issue #75) instead of retrying
			// H2, which would just mismatch again and fail the stream.
			decision.alpnErr.TLSConn.Close()
			resp, err := t.doStreamHTTP1(ctx, req)
			if err == nil {
				t.cacheProtocol(host, ProtocolHTTP1)
			}
			return resp, err
		case decision.protocol == ProtocolHTTP3:
			resp, err := t.doStreamHTTP3(ctx, req)
			if err == nil {
				t.cacheProtocol(host, ProtocolHTTP3)
				return resp, nil
			}
			if req.BodyReader != nil {
				// One-shot body may be drained; do not re-send on H2 (see above).
				return nil, err
			}
			// Replayable body (or none): fall through to H2.
		}
	}

	resp, err := t.doStreamHTTP2OrHTTP1(ctx, req)
	if err == nil {
		if resp.Protocol == "h1" {
			t.cacheProtocol(host, ProtocolHTTP1)
		} else {
			t.cacheProtocol(host, ProtocolHTTP2)
		}
	}
	return resp, err
}

// doStreamHTTP2OrHTTP1 streams over HTTP/2 and, when the server negotiates
// http/1.1 (ALPN mismatch), transparently falls back to HTTP/1.1 instead of
// failing. This mirrors the buffered doAuto path so streaming works against
// H1-only servers (issue #75: request_stream failed with "Failed to start
// streaming request" on any host that speaks only http/1.1). Forced HTTP/2 does
// NOT route through here, so an explicit H2 choice still surfaces the mismatch.
func (t *Transport) doStreamHTTP2OrHTTP1(ctx context.Context, req *Request) (*StreamResponse, error) {
	resp, err := t.doStreamHTTP2(ctx, req)
	if err == nil {
		return resp, nil
	}
	var alpnErr *ALPNMismatchError
	if errors.As(err, &alpnErr) {
		// Server offered only http/1.1. Streaming has no H1-conn-reuse path, so
		// drop the mismatched TLS conn and re-establish over HTTP/1.1.
		alpnErr.TLSConn.Close()
		return t.doStreamHTTP1(ctx, req)
	}
	return nil, err
}

// doStreamHTTP1 executes a streaming request over HTTP/1.1
func (t *Transport) doStreamHTTP1(ctx context.Context, req *Request) (*StreamResponse, error) {
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

	// For streaming, we use a cancellable context without timeout
	// The timeout from the parent context (if any) will still apply
	// But we don't add an additional timeout that would cut off reading
	ctx, cancel := context.WithCancel(ctx)

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
		cancel()
		return nil, NewRequestError("create_request", host, port, "h1", err)
	}

	// Determine effective TLS-only mode: per-request override takes precedence
	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	// Set preset headers
	applyPresetHeaders(httpReq, t.wireHeaders(snap.preset), t.effectiveHeaderOrder(req), t.getCustomPseudoOrder(), effectiveTLSOnly, "h1", req.Headers, req.DisableClientHints, req.ExactHeaders)

	mergeCallerHeaders(httpReq, req)

	// Record timing before request
	reqStart := time.Now()

	// Bound ONLY connection establishment (dial + TLS + proxy CONNECT, all inside
	// StreamRoundTrip) with the effective timeout; the body stream then runs
	// unbounded. Without this a stalled host/proxy rides the internal connect
	// timeout regardless of the configured timeout.
	finishEstablishment := boundStreamEstablishment(t.streamEffectiveTimeout(req), cancel)

	// Make request - use StreamRoundTrip to avoid connection pooling issues
	resp, err := snap.h1.StreamRoundTrip(httpReq)
	finishEstablishment()
	if err != nil {
		cancel()
		return nil, WrapError("stream_roundtrip", host, port, "h1", err)
	}

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())
	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	// Setup decompression reader
	reader, decompressor := setupStreamDecompressor(resp.Body, resp.Header.Get("Content-Encoding"))

	return &StreamResponse{
		StatusCode:    resp.StatusCode,
		Headers:       headers,
		HeaderOrder:   responseHeaderOrder(resp.Header),
		httpResp:      resp,
		FinalURL:      req.URL,
		Timing:        timing,
		Protocol:      "h1",
		ContentLength: resp.ContentLength,
		reader:        reader,
		decompressor:  decompressor,
		rawReader:     resp.Body,
		cancel:        cancel,
		done:          ctx.Done(),
	}, nil
}

// doStreamHTTP2 executes a streaming request over HTTP/2
func (t *Transport) doStreamHTTP2(ctx context.Context, req *Request) (*StreamResponse, error) {
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

	// For streaming, use cancellable context without additional timeout
	ctx, cancel := context.WithCancel(ctx)

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
		cancel()
		return nil, NewRequestError("create_request", host, port, "h2", err)
	}

	// Determine effective TLS-only mode: per-request override takes precedence
	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	// Set preset headers
	applyPresetHeaders(httpReq, t.wireHeaders(snap.preset), t.effectiveHeaderOrder(req), t.getCustomPseudoOrder(), effectiveTLSOnly, "h2", req.Headers, req.DisableClientHints, req.ExactHeaders)

	mergeCallerHeaders(httpReq, req)

	// Record timing before request
	reqStart := time.Now()

	// Bound ONLY connection establishment with the effective timeout; the body
	// stream then runs unbounded (see doStreamHTTP1).
	finishEstablishment := boundStreamEstablishment(t.streamEffectiveTimeout(req), cancel)

	// Make request
	resp, err := snap.h2.RoundTrip(httpReq)
	finishEstablishment()
	if err != nil {
		cancel()
		return nil, WrapError("roundtrip", host, port, "h2", err)
	}

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())
	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	// Setup decompression reader
	reader, decompressor := setupStreamDecompressor(resp.Body, resp.Header.Get("Content-Encoding"))

	return &StreamResponse{
		StatusCode:    resp.StatusCode,
		Headers:       headers,
		HeaderOrder:   responseHeaderOrder(resp.Header),
		httpResp:      resp,
		FinalURL:      req.URL,
		Timing:        timing,
		Protocol:      "h2",
		ContentLength: resp.ContentLength,
		reader:        reader,
		decompressor:  decompressor,
		rawReader:     resp.Body,
		cancel:        cancel,
		done:          ctx.Done(),
	}, nil
}

// doStreamHTTP3 executes a streaming request over HTTP/3
func (t *Transport) doStreamHTTP3(ctx context.Context, req *Request) (*StreamResponse, error) {
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

	// For streaming, use cancellable context without additional timeout
	ctx, cancel := context.WithCancel(ctx)

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
		cancel()
		return nil, NewRequestError("create_request", host, port, "h3", err)
	}

	// Determine effective TLS-only mode: per-request override takes precedence
	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	// Set preset headers
	applyPresetHeaders(httpReq, t.wireHeaders(snap.preset), t.effectiveHeaderOrder(req), t.getCustomPseudoOrder(), effectiveTLSOnly, "h3", req.Headers, req.DisableClientHints, req.ExactHeaders)

	mergeCallerHeaders(httpReq, req)

	// Record timing before request
	reqStart := time.Now()

	// Bound ONLY connection establishment with the effective timeout; the body
	// stream then runs unbounded (see doStreamHTTP1).
	finishEstablishment := boundStreamEstablishment(t.streamEffectiveTimeout(req), cancel)

	// Make request
	resp, err := snap.h3.RoundTrip(httpReq)
	finishEstablishment()
	if err != nil {
		cancel()
		return nil, WrapError("roundtrip", host, port, "h3", err)
	}

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())
	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Build response headers map
	headers := buildHeadersMap(resp.Header)

	// Setup decompression reader
	reader, decompressor := setupStreamDecompressor(resp.Body, resp.Header.Get("Content-Encoding"))

	return &StreamResponse{
		StatusCode:    resp.StatusCode,
		Headers:       headers,
		HeaderOrder:   responseHeaderOrder(resp.Header),
		httpResp:      resp,
		FinalURL:      req.URL,
		Timing:        timing,
		Protocol:      "h3",
		ContentLength: resp.ContentLength,
		reader:        reader,
		decompressor:  decompressor,
		rawReader:     resp.Body,
		cancel:        cancel,
		done:          ctx.Done(),
	}, nil
}

// setupStreamDecompressor creates a decompression reader based on Content-Encoding
func setupStreamDecompressor(body io.ReadCloser, encoding string) (io.ReadCloser, io.Closer) {
	switch strings.ToLower(encoding) {
	case "gzip":
		reader, err := gzip.NewReader(body)
		if err != nil {
			return body, nil
		}
		return reader, reader
	case "br":
		return &brotliStreamReader{brotli.NewReader(body)}, nil
	case "deflate":
		return &deflateStreamReader{flate.NewReader(body)}, nil
	case "zstd":
		decoder, err := zstd.NewReader(body)
		if err != nil {
			return body, nil
		}
		return &zstdStreamReader{decoder: decoder, body: body}, nil
	default:
		return body, nil
	}
}

// brotliStreamReader wraps brotli.Reader to implement io.ReadCloser
type brotliStreamReader struct {
	reader *brotli.Reader
}

func (b *brotliStreamReader) Read(p []byte) (n int, err error) {
	return b.reader.Read(p)
}

func (b *brotliStreamReader) Close() error {
	return nil // brotli.Reader doesn't need closing
}

// deflateStreamReader wraps flate.Reader to implement io.ReadCloser
type deflateStreamReader struct {
	reader io.ReadCloser
}

func (d *deflateStreamReader) Read(p []byte) (n int, err error) {
	return d.reader.Read(p)
}

func (d *deflateStreamReader) Close() error {
	return d.reader.Close()
}

// zstdStreamReader wraps zstd.Decoder to implement io.ReadCloser
type zstdStreamReader struct {
	decoder *zstd.Decoder
	body    io.ReadCloser
}

func (z *zstdStreamReader) Read(p []byte) (n int, err error) {
	return z.decoder.Read(p)
}

func (z *zstdStreamReader) Close() error {
	z.decoder.Close()
	return z.body.Close()
}
