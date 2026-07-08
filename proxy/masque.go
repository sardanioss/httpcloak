package proxy

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	http "github.com/sardanioss/http"
	tls "github.com/sardanioss/utls"

	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
)

const (
	// requestProtocol is the :protocol pseudo-header for CONNECT-UDP
	requestProtocol = "connect-udp"
	// capsuleProtocolHeaderValue indicates capsule protocol support (RFC 9297)
	capsuleProtocolHeaderValue = "?1"
	// defaultInitialPacketSize for MASQUE connections (allows tunneling QUIC with 1200 MTU)
	defaultInitialPacketSize = 1350
)

// MASQUEConn implements net.PacketConn for MASQUE CONNECT-UDP tunneling.
// This allows QUIC connections to be tunneled through an HTTP/3 MASQUE proxy.
//
// MASQUE (Multiplexed Application Substrate over QUIC Encryption) uses:
// - RFC 9298: CONNECT-UDP method for UDP proxying
// - RFC 9297: HTTP/3 Datagrams for carrying UDP packets
// - RFC 9484: MASQUE protocol specification
type MASQUEConn struct {
	// QUIC connection to the MASQUE proxy
	quicConn *quic.Conn

	// Underlying UDP socket the QUIC conn runs over. quic-go does NOT close this
	// when the QUIC conn closes, so we track it to close it ourselves (otherwise
	// the socket + its read goroutine leak on every Close/Reset).
	udpConn *net.UDPConn

	// quic.Transport that owns udpConn. Each dial attempt gets its own Transport
	// (quic-go allows only one Transport per socket); we retain the winning one
	// so Close/Reset can stop its read goroutine before releasing the socket.
	quicTransport *quic.Transport

	// HTTP/3 client connection for Extended CONNECT
	clientConn *http3.ClientConn

	// Request stream for the CONNECT-UDP tunnel
	requestStream *http3.RequestStream

	// Target address (host:port) being proxied
	targetHost string
	targetPort int

	// Resolved target address (for proper net.PacketConn behavior)
	resolvedTarget *net.UDPAddr

	// State management
	mu          sync.RWMutex
	established bool
	closed      bool

	// Deadline management
	readDeadline  time.Time
	writeDeadline time.Time

	// Proxy configuration
	proxyHost string
	proxyPort string
	username  string
	password  string

	// Local address simulation (for net.PacketConn interface)
	localAddr net.Addr

	// Datagram receive channel - datagrams from QUIC connection
	datagramCh chan []byte
	// Context for background goroutine
	ctx    context.Context
	cancel context.CancelFunc
}

// NewMASQUEConn creates a new MASQUE connection to the specified proxy URL.
// URL format: masque://[user:pass@]host:port or https://[user:pass@]host:port
func NewMASQUEConn(proxyURL string) (*MASQUEConn, error) {
	// Normalize masque:// to https://
	normalizedURL, err := NormalizeMASQUEURL(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	parsed, err := url.Parse(normalizedURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443" // Default HTTPS port
	}

	conn := &MASQUEConn{
		proxyHost:  host,
		proxyPort:  port,
		datagramCh: make(chan []byte, 100),
	}

	// Extract credentials if present
	if parsed.User != nil {
		conn.username = parsed.User.Username()
		conn.password, _ = parsed.User.Password()
	}

	// Create a simulated local address
	conn.localAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}

	return conn, nil
}

// EstablishWithQUICConfig establishes the MASQUE tunnel with custom QUIC config.
// This allows maintaining browser fingerprinting on the proxy connection.
func (c *MASQUEConn) EstablishWithQUICConfig(ctx context.Context, targetHost string, targetPort int, tlsConfig *tls.Config, quicConfig *quic.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.established {
		// A MASQUEConn is a single UDP tunnel bound to one target. Silently
		// reusing it for a different target would send traffic to the wrong
		// host (the target is baked into the CONNECT-UDP path). Fail loudly
		// instead — the caller should open a tunnel per target.
		if c.targetHost != targetHost || c.targetPort != targetPort {
			return fmt.Errorf("MASQUE tunnel already bound to %s:%d, cannot reuse for %s:%d",
				c.targetHost, c.targetPort, targetHost, targetPort)
		}
		return nil
	}

	if c.closed {
		return net.ErrClosed
	}

	c.targetHost = targetHost
	c.targetPort = targetPort

	// Step 1: Dial QUIC connection to proxy
	// Pre-resolve proxy hostname using CGO-compatible resolver
	// (required for shared library usage where Go's pure-Go resolver doesn't work)
	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, c.proxyHost)
	if err != nil {
		return fmt.Errorf("failed to resolve proxy host %s: %w", c.proxyHost, err)
	}
	if len(proxyIPs) == 0 {
		return fmt.Errorf("no IP addresses found for proxy host %s", c.proxyHost)
	}

	// Parse port
	port, err := strconv.Atoi(c.proxyPort)
	if err != nil {
		return fmt.Errorf("invalid proxy port %s: %w", c.proxyPort, err)
	}

	// The winning attempt's socket + Transport (retained below) and a guard so
	// every error path after this point closes the QUIC conn, its Transport, and
	// the socket — otherwise the socket and its receive goroutine leak on every
	// failed establish.
	var udpConn *net.UDPConn
	var quicTransport *quic.Transport
	established := false
	defer func() {
		if established {
			return
		}
		if c.quicConn != nil {
			c.quicConn.CloseWithError(0, "establish failed")
		}
		if quicTransport != nil {
			quicTransport.Close()
		}
		if udpConn != nil {
			udpConn.Close()
		}
	}()

	// Create TLS config for proxy connection
	proxyTLSConfig := tlsConfig.Clone()
	proxyTLSConfig.ServerName = c.proxyHost
	proxyTLSConfig.NextProtos = []string{http3.NextProtoH3}

	// Ensure datagrams are enabled and use larger packet size for tunneling
	proxyCfg := quicConfig.Clone()
	proxyCfg.EnableDatagrams = true
	if proxyCfg.InitialPacketSize == 0 {
		proxyCfg.InitialPacketSize = defaultInitialPacketSize
	}

	// Try every resolved proxy address (IPv4 first) so an unreachable address
	// (e.g. a dead IPv6 listed first) doesn't fail the tunnel outright. Each
	// attempt MUST get its own UDP socket + quic.Transport: quic-go allows only
	// one Transport per socket and keeps a read goroutine running on it, so
	// reusing a single socket across attempts lets a failed dial's Transport
	// swallow the next attempt's handshake packets — the IPv4 fallback would then
	// stall until the ctx deadline instead of connecting. We open a fresh socket
	// per address and fully tear down every loser (Transport + socket) before
	// moving on; only the winning pair is retained.
	var quicConn *quic.Conn
	var dialErr error
	for _, ipStr := range orderIPv4First(proxyIPs) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		sock, sockErr := net.ListenUDP("udp", nil)
		if sockErr != nil {
			dialErr = fmt.Errorf("failed to create UDP socket: %w", sockErr)
			continue
		}
		tr := &quic.Transport{Conn: sock}
		conn, err := tr.Dial(ctx, &net.UDPAddr{IP: ip, Port: port}, proxyTLSConfig, proxyCfg)
		if err != nil {
			dialErr = err
			// Tear down the failed attempt fully: stop the Transport's read
			// goroutine on this socket, then release the fd, before the next addr.
			tr.Close()
			sock.Close()
			continue
		}
		udpConn = sock
		quicTransport = tr
		quicConn = conn
		break
	}
	if quicConn == nil {
		if dialErr == nil {
			dialErr = fmt.Errorf("no usable proxy address")
		}
		return fmt.Errorf("failed to dial QUIC to proxy: %w", dialErr)
	}
	c.quicConn = quicConn

	// Step 2: Create HTTP/3 client connection
	tr := &http3.Transport{EnableDatagrams: true}
	c.clientConn = tr.NewClientConn(quicConn)

	// Wait for server settings to confirm Extended CONNECT support
	select {
	case <-ctx.Done():
		c.quicConn.CloseWithError(0, "context cancelled")
		return ctx.Err()
	case <-c.clientConn.Context().Done():
		return fmt.Errorf("connection closed: %w", c.clientConn.Context().Err())
	case <-c.clientConn.ReceivedSettings():
	}

	settings := c.clientConn.Settings()
	if !settings.EnableExtendedConnect {
		c.quicConn.CloseWithError(0, "no extended connect")
		return errors.New("proxy doesn't support Extended CONNECT")
	}
	if !settings.EnableDatagrams {
		c.quicConn.CloseWithError(0, "no datagrams")
		return errors.New("proxy doesn't support HTTP/3 Datagrams")
	}

	// Step 3: Send Extended CONNECT request for CONNECT-UDP
	if err := c.sendConnectUDP(ctx); err != nil {
		c.quicConn.CloseWithError(0, "connect-udp failed")
		return fmt.Errorf("CONNECT-UDP request failed: %w", err)
	}

	// Step 4: Start datagram receiver goroutine. Hand the receiver its own
	// stable copies of ctx and the request stream (captured here under c.mu) so
	// a concurrent Reset()/re-Establish that reassigns c.ctx or nils
	// c.requestStream can't mutate what the running receiver is reading — the
	// old receiver drains on its snapshotted ctx and exits cleanly when that
	// snapshot's cancel fires.
	c.ctx, c.cancel = context.WithCancel(context.Background())
	go c.receiveDatagrams(c.ctx, c.requestStream)

	c.established = true
	c.udpConn = udpConn             // track so Close/Reset can release the socket
	c.quicTransport = quicTransport // track so Close/Reset can stop its read goroutine
	established = true              // tunnel owns udpConn now; skip the cleanup defer
	return nil
}

// Establish performs the MASQUE CONNECT-UDP handshake with default config.
// For browser fingerprinting, use EstablishWithQUICConfig instead.
func (c *MASQUEConn) Establish(ctx context.Context, targetHost string, targetPort int) error {
	tlsConfig := &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:    30 * time.Second,
		EnableDatagrams:   true,
		InitialPacketSize: defaultInitialPacketSize,
	}

	return c.EstablishWithQUICConfig(ctx, targetHost, targetPort, tlsConfig, quicConfig)
}

// sendConnectUDP sends the Extended CONNECT request to establish the UDP tunnel.
// Uses proper HTTP/3 framing via OpenRequestStream and SendRequestHeader.
func (c *MASQUEConn) sendConnectUDP(ctx context.Context) error {
	// Open a request stream for Extended CONNECT
	rstr, err := c.clientConn.OpenRequestStream(ctx)
	if err != nil {
		return fmt.Errorf("failed to open request stream: %w", err)
	}
	c.requestStream = rstr

	// Build the request URL with well-known MASQUE path
	// Format: /.well-known/masque/udp/{target_host}/{target_port}/
	path := fmt.Sprintf("/.well-known/masque/udp/%s/%d/", c.targetHost, c.targetPort)
	reqURL, _ := url.Parse(fmt.Sprintf("https://%s:%s%s", c.proxyHost, c.proxyPort, path))

	// Build headers
	headers := http.Header{
		http3.CapsuleProtocolHeader: []string{capsuleProtocolHeaderValue},
	}

	// Add Proxy-Authorization if credentials are provided
	if c.username != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.username + ":" + c.password))
		headers.Set("Proxy-Authorization", "Basic "+auth)
	}

	// Create Extended CONNECT request
	// The Proto field sets the :protocol pseudo-header for Extended CONNECT
	req := &http.Request{
		Method: http.MethodConnect,
		Proto:  requestProtocol, // This becomes :protocol = connect-udp
		Host:   reqURL.Host,
		Header: headers,
		URL:    reqURL,
	}

	// Send the request headers
	if err := rstr.SendRequestHeader(req); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Read the response — bounded by the caller's ctx. Without this the read
	// blocks until the QUIC MaxIdleTimeout (~30s, extendable by keepalives) when
	// the proxy completes the handshake but never answers the Extended CONNECT,
	// ignoring the dial ctx's shorter deadline. Same class as the SOCKS5
	// ReadResponse bug fixed elsewhere. We push the ctx deadline onto the stream
	// so a blocking read wakes, and also watch ctx.Done() so a deadline-less
	// cancellation still tears the stream down and fails fast.
	if dl, ok := ctx.Deadline(); ok {
		rstr.SetReadDeadline(dl)
		defer rstr.SetReadDeadline(time.Time{})
	}
	type connectUDPResult struct {
		rsp *http.Response
		err error
	}
	respCh := make(chan connectUDPResult, 1)
	go func() {
		rsp, err := rstr.ReadResponse()
		respCh <- connectUDPResult{rsp: rsp, err: err}
	}()

	var rsp *http.Response
	select {
	case <-ctx.Done():
		// Abandon the parked read so ReadResponse unblocks, then fail fast.
		rstr.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		rstr.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		return fmt.Errorf("CONNECT-UDP response timed out: %w", ctx.Err())
	case res := <-respCh:
		if res.err != nil {
			return fmt.Errorf("failed to read response: %w", res.err)
		}
		rsp = res.rsp
	}

	// Check for success (2xx status code)
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		switch rsp.StatusCode {
		case 407:
			return errors.New("proxy authentication required")
		case 403:
			return errors.New("proxy connection forbidden")
		case 502, 503:
			return errors.New("proxy could not reach target")
		default:
			return fmt.Errorf("proxy responded with %d", rsp.StatusCode)
		}
	}

	// Update local address from response if available
	if rsp.Header.Get("X-Brd-Ip") != "" {
		// Bright Data provides exit IP in header
		c.localAddr = &net.UDPAddr{IP: net.ParseIP(rsp.Header.Get("X-Brd-Ip")), Port: 0}
	}

	return nil
}

// receiveDatagrams runs in a goroutine to receive datagrams from the QUIC
// connection. It takes ctx and rstr as parameters (snapshotted under c.mu by the
// launcher) rather than reading c.ctx/c.requestStream directly, so a concurrent
// Reset()/re-Establish that reassigns those fields can't race with — or nil out
// from under — the running receiver.
func (c *MASQUEConn) receiveDatagrams(ctx context.Context, rstr *http3.RequestStream) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Receive datagram from RequestStream (handles quarter stream ID)
		// The datagram may include a context ID prefix per RFC 9298
		data, err := rstr.ReceiveDatagram(ctx)
		if err != nil {
			// Connection closed or context cancelled
			return
		}

		// Process the datagram - strip context ID prefix
		// Context ID 0 is used for CONNECT-UDP (per RFC 9298)
		payload := c.unwrapDatagram(data)
		if payload == nil {
			continue
		}

		// Send to channel (non-blocking)
		select {
		case c.datagramCh <- payload:
		default:
			// Channel full, drop packet
		}
	}
}

// unwrapDatagram removes the HTTP/3 datagram context ID prefix if present
func (c *MASQUEConn) unwrapDatagram(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	// RFC 9297: Datagrams start with a variable-length integer context ID
	// Context ID 0 is used for CONNECT-UDP
	// We need to read the varint and skip it

	contextID, bytesRead := readVarInt(data)
	if bytesRead == 0 || bytesRead >= len(data) {
		// Invalid or no payload
		return nil
	}

	// Verify context ID is 0 (for CONNECT-UDP)
	if contextID != 0 {
		// Different context, might be control frame - ignore for UDP
		return nil
	}

	return data[bytesRead:]
}

// wrapDatagram adds the HTTP/3 datagram context ID prefix
func (c *MASQUEConn) wrapDatagram(data []byte) []byte {
	// RFC 9297: Prepend context ID 0 for CONNECT-UDP
	// Context ID 0 encodes as single byte 0x00
	result := make([]byte, 1+len(data))
	result[0] = 0x00 // Context ID 0
	copy(result[1:], data)
	return result
}

// WriteTo implements net.PacketConn - writes a UDP datagram through the MASQUE tunnel
func (c *MASQUEConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return 0, net.ErrClosed
	}
	if !c.established {
		c.mu.RUnlock()
		return 0, errors.New("MASQUE connection not established")
	}
	rstr := c.requestStream
	c.mu.RUnlock()

	// Wrap with context ID (RFC 9298)
	wrappedData := c.wrapDatagram(b)

	// Send as HTTP/3 datagram via the RequestStream
	// The stream handles the quarter stream ID prefix (RFC 9297)
	err := rstr.SendDatagram(wrappedData)
	if err != nil {
		return 0, fmt.Errorf("failed to send datagram: %w", err)
	}

	return len(b), nil
}

// ReadFrom implements net.PacketConn - reads a UDP datagram from the MASQUE tunnel
func (c *MASQUEConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return 0, nil, net.ErrClosed
	}
	if !c.established {
		c.mu.RUnlock()
		return 0, nil, errors.New("MASQUE connection not established")
	}
	c.mu.RUnlock()

	// Check deadline
	var deadline <-chan time.Time
	c.mu.RLock()
	if !c.readDeadline.IsZero() {
		timer := time.NewTimer(time.Until(c.readDeadline))
		defer timer.Stop()
		deadline = timer.C
	}
	c.mu.RUnlock()

	select {
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-deadline:
		return 0, nil, &net.OpError{Op: "read", Err: errors.New("i/o timeout")}
	case data := <-c.datagramCh:
		n := copy(b, data)
		// Return the resolved target address (set by SetResolvedTarget)
		c.mu.RLock()
		targetAddr := c.resolvedTarget
		c.mu.RUnlock()
		if targetAddr == nil {
			// Fallback if not set
			targetAddr = &net.UDPAddr{
				IP:   net.ParseIP(c.targetHost),
				Port: c.targetPort,
			}
			if targetAddr.IP == nil {
				targetAddr.IP = net.IPv4zero
			}
		}
		return n, targetAddr, nil
	}
}

// Close closes the MASQUE connection and all underlying resources
func (c *MASQUEConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	// Cancel background goroutine
	if c.cancel != nil {
		c.cancel()
	}

	var errs []error

	// Close the request stream
	if c.requestStream != nil {
		if err := c.requestStream.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// Close the QUIC connection
	if c.quicConn != nil {
		if err := c.quicConn.CloseWithError(0, "closed"); err != nil {
			errs = append(errs, err)
		}
	}

	// Stop the Transport's read goroutine, then close the underlying UDP socket —
	// quic-go won't do either, so skipping this leaks the socket and its goroutine.
	if c.quicTransport != nil {
		c.quicTransport.Close()
		c.quicTransport = nil
	}
	if c.udpConn != nil {
		c.udpConn.Close()
		c.udpConn = nil
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Reset tears down the current tunnel so the next Establish dials a fresh one.
// Used by a transport Refresh: without it the stale tunnel (established == true
// over an already-closed QUIC connection, plus a leaked datagram-receive
// goroutine and UDP socket) would be reused after refresh.
func (c *MASQUEConn) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if c.cancel != nil {
		c.cancel()
	}
	if c.quicConn != nil {
		c.quicConn.CloseWithError(0, "reset")
		c.quicConn = nil
	}
	if c.quicTransport != nil {
		c.quicTransport.Close()
		c.quicTransport = nil
	}
	if c.udpConn != nil {
		c.udpConn.Close()
		c.udpConn = nil
	}
	c.clientConn = nil
	c.requestStream = nil
	c.established = false
}

// LocalAddr returns the local address (simulated for net.PacketConn interface)
func (c *MASQUEConn) LocalAddr() net.Addr {
	return c.localAddr
}

// SetResolvedTarget sets the resolved target address for proper PacketConn behavior.
// This should be called after DNS resolution to ensure ReadFrom returns the correct
// source address that matches what QUIC dialed to.
func (c *MASQUEConn) SetResolvedTarget(addr *net.UDPAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resolvedTarget = addr
}

// SetDeadline sets read and write deadlines
func (c *MASQUEConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

// SetReadDeadline sets the read deadline
func (c *MASQUEConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

// SetWriteDeadline sets the write deadline
func (c *MASQUEConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

// readVarInt reads a QUIC variable-length integer from the beginning of data
// Returns the value and number of bytes read (0 if error)
func readVarInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	// Get the 2-bit length prefix
	prefix := data[0] >> 6
	length := 1 << prefix // 1, 2, 4, or 8 bytes

	if len(data) < length {
		return 0, 0
	}

	var value uint64
	switch length {
	case 1:
		value = uint64(data[0] & 0x3f)
	case 2:
		value = uint64(data[0]&0x3f)<<8 | uint64(data[1])
	case 4:
		value = uint64(data[0]&0x3f)<<24 | uint64(data[1])<<16 | uint64(data[2])<<8 | uint64(data[3])
	case 8:
		value = uint64(data[0]&0x3f)<<56 | uint64(data[1])<<48 | uint64(data[2])<<40 | uint64(data[3])<<32 |
			uint64(data[4])<<24 | uint64(data[5])<<16 | uint64(data[6])<<8 | uint64(data[7])
	}

	return value, length
}

// writeVarInt encodes a value as a QUIC variable-length integer
func writeVarInt(value uint64) []byte {
	if value <= 63 {
		return []byte{byte(value)}
	}
	if value <= 16383 {
		buf := make([]byte, 2)
		buf[0] = byte(value>>8) | 0x40
		buf[1] = byte(value)
		return buf
	}
	if value <= 1073741823 {
		buf := make([]byte, 4)
		buf[0] = byte(value>>24) | 0x80
		buf[1] = byte(value >> 16)
		buf[2] = byte(value >> 8)
		buf[3] = byte(value)
		return buf
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value|0xC000000000000000)
	return buf
}

// ParseMASQUETarget parses a target address string into host and port
func ParseMASQUETarget(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}
