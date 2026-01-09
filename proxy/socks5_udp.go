package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"
)

// SOCKS5 constants
const (
	socks5Version = 0x05

	// Authentication methods
	authNone     = 0x00
	authPassword = 0x02
	authNoAccept = 0xFF

	// Commands
	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	// Address types
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	// Reply codes
	replySuccess          = 0x00
	replyGeneralFailure   = 0x01
	replyConnNotAllowed   = 0x02
	replyNetworkUnreach   = 0x03
	replyHostUnreach      = 0x04
	replyConnRefused      = 0x05
	replyTTLExpired       = 0x06
	replyCmdNotSupported  = 0x07
	replyAddrNotSupported = 0x08
)

// SOCKS5UDPConn implements net.PacketConn for SOCKS5 UDP relay
// This allows QUIC to send UDP packets through a SOCKS5 proxy
type SOCKS5UDPConn struct {
	// TCP connection for SOCKS5 control channel
	// Must stay open for UDP relay to work
	tcpConn net.Conn

	// UDP connection to send/receive through relay
	udpConn *net.UDPConn

	// Relay address returned by proxy after UDP ASSOCIATE
	relayAddr *net.UDPAddr

	// Original proxy address
	proxyHost string
	proxyPort string

	// Authentication credentials
	username string
	password string

	// State management
	mu           sync.RWMutex
	established  bool
	closed       bool
	lastActivity time.Time
	writeCount   int64
	readCount    int64

	// Read buffer for receiving packets
	readBuf []byte

	// Deadline management
	readDeadline  time.Time
	writeDeadline time.Time
}

// NewSOCKS5UDPConn creates a new SOCKS5 UDP connection from a proxy URL
// URL format: socks5://[user:pass@]host:port
func NewSOCKS5UDPConn(proxyURL string) (*SOCKS5UDPConn, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	if parsed.Scheme != "socks5" && parsed.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported proxy scheme: %s (need socks5)", parsed.Scheme)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "1080" // Default SOCKS5 port
	}

	conn := &SOCKS5UDPConn{
		proxyHost: host,
		proxyPort: port,
		readBuf:   make([]byte, 65535), // Max UDP datagram size
	}

	// Extract credentials if present
	if parsed.User != nil {
		conn.username = parsed.User.Username()
		conn.password, _ = parsed.User.Password()
	}

	return conn, nil
}

// Establish performs the SOCKS5 UDP ASSOCIATE handshake
// This must be called before using the connection
// It will retry up to 5 times if the proxy returns "general failure"
// (common with load-balanced proxies where some servers don't support UDP)
func (c *SOCKS5UDPConn) Establish(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.established {
		return nil
	}

	if c.closed {
		return net.ErrClosed
	}

	var lastErr error
	maxRetries := 5

	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := c.tryEstablish(ctx)
		if err == nil {
			c.established = true
			c.lastActivity = time.Now()

			// Start TCP keepalive goroutine to detect proxy disconnect
			go c.tcpKeepalive()

			return nil
		}

		lastErr = err

		// Clean up failed attempt
		if c.udpConn != nil {
			c.udpConn.Close()
			c.udpConn = nil
		}
		if c.tcpConn != nil {
			c.tcpConn.Close()
			c.tcpConn = nil
		}

		// Only retry on "general failure" (reply=1) - indicates load-balanced server issue
		if !isRetryableError(err) {
			return err
		}

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Small delay before retry (except on last attempt)
		if attempt < maxRetries {
			time.Sleep(500 * time.Millisecond)
		}
	}

	return fmt.Errorf("UDP ASSOCIATE failed after %d attempts: %w", maxRetries, lastErr)
}

// isRetryableError checks if the error is a "general SOCKS server failure"
// which often indicates hitting a load-balanced server that doesn't support UDP
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	// Reply code 1 = "general SOCKS server failure"
	return contains(err.Error(), "reply=1") || contains(err.Error(), "general")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// tryEstablish attempts a single UDP ASSOCIATE handshake
func (c *SOCKS5UDPConn) tryEstablish(ctx context.Context) error {
	// Step 1: Pre-resolve proxy hostname using CGO-compatible resolver
	// Required for shared library usage where Go's pure-Go resolver doesn't work
	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, c.proxyHost)
	if err != nil {
		return fmt.Errorf("failed to resolve proxy host %s: %w", c.proxyHost, err)
	}
	if len(proxyIPs) == 0 {
		return fmt.Errorf("no IP addresses found for proxy host %s", c.proxyHost)
	}

	// Connect to SOCKS5 proxy via TCP using resolved IP
	proxyAddr := net.JoinHostPort(proxyIPs[0], c.proxyPort)
	dialer := &net.Dialer{}
	tcpConn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
	}
	c.tcpConn = tcpConn

	// Set deadline for handshake
	deadline, ok := ctx.Deadline()
	if ok {
		c.tcpConn.SetDeadline(deadline)
	}

	// Step 2: SOCKS5 greeting and authentication
	if err := c.socks5Handshake(); err != nil {
		return fmt.Errorf("SOCKS5 handshake failed: %w", err)
	}

	// Step 3: Create local UDP socket (force IPv4 for better compatibility)
	udpConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}
	c.udpConn = udpConn

	// Step 4: Send UDP ASSOCIATE request
	if err := c.sendUDPAssociate(); err != nil {
		return err
	}

	// Clear deadline after successful handshake
	c.tcpConn.SetDeadline(time.Time{})

	return nil
}

// socks5Handshake performs version negotiation and authentication
func (c *SOCKS5UDPConn) socks5Handshake() error {
	// Build greeting message
	var greeting []byte
	if c.username != "" {
		// Offer both no-auth and username/password
		greeting = []byte{socks5Version, 0x02, authNone, authPassword}
	} else {
		// Only offer no-auth
		greeting = []byte{socks5Version, 0x01, authNone}
	}

	if _, err := c.tcpConn.Write(greeting); err != nil {
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	// Read server's chosen method
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c.tcpConn, resp); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp[0] != socks5Version {
		return fmt.Errorf("invalid SOCKS version: %d", resp[0])
	}

	switch resp[1] {
	case authNone:
		// No authentication required
		return nil
	case authPassword:
		// Username/password authentication required
		return c.socks5PasswordAuth()
	case authNoAccept:
		return errors.New("proxy rejected all authentication methods")
	default:
		return fmt.Errorf("unsupported authentication method: %d", resp[1])
	}
}

// socks5PasswordAuth performs username/password authentication (RFC 1929)
func (c *SOCKS5UDPConn) socks5PasswordAuth() error {
	if c.username == "" {
		return errors.New("proxy requires authentication but no credentials provided")
	}

	// Build auth request: VER(1) + ULEN(1) + UNAME(1-255) + PLEN(1) + PASSWD(1-255)
	authReq := make([]byte, 0, 3+len(c.username)+len(c.password))
	authReq = append(authReq, 0x01) // Auth sub-negotiation version
	authReq = append(authReq, byte(len(c.username)))
	authReq = append(authReq, []byte(c.username)...)
	authReq = append(authReq, byte(len(c.password)))
	authReq = append(authReq, []byte(c.password)...)

	if _, err := c.tcpConn.Write(authReq); err != nil {
		return fmt.Errorf("failed to send auth request: %w", err)
	}

	// Read auth response: VER(1) + STATUS(1)
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c.tcpConn, resp); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp[1] != 0x00 {
		return errors.New("authentication failed: invalid credentials")
	}

	return nil
}

// sendUDPAssociate sends UDP ASSOCIATE request and parses the reply
func (c *SOCKS5UDPConn) sendUDPAssociate() error {
	// Build UDP ASSOCIATE request
	// VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2)
	//
	// Per RFC 1928: "If the client is not in possession of the information at
	// the time of the UDP ASSOCIATE, the client MUST use a port number and
	// address of all zeros."
	//
	// We always send 0.0.0.0:0 because:
	// 1. Many proxies don't support IPv6 address type in UDP ASSOCIATE
	// 2. The local UDP socket address (e.g., ::) may be rejected
	// 3. Most proxies ignore this field anyway and accept from any address
	request := []byte{
		socks5Version,  // VER
		cmdUDPAssociate, // CMD
		0x00,           // RSV
		atypIPv4,       // ATYP: IPv4
		0, 0, 0, 0,     // DST.ADDR: 0.0.0.0
		0, 0,           // DST.PORT: 0
	}

	if _, err := c.tcpConn.Write(request); err != nil {
		return fmt.Errorf("failed to send UDP ASSOCIATE: %w", err)
	}

	// Parse reply
	return c.parseUDPAssociateReply()
}

// parseUDPAssociateReply parses the server's UDP ASSOCIATE response
func (c *SOCKS5UDPConn) parseUDPAssociateReply() error {
	// Read header: VER(1) + REP(1) + RSV(1) + ATYP(1)
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.tcpConn, header); err != nil {
		return fmt.Errorf("failed to read reply header: %w", err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("invalid SOCKS version in reply: %d", header[0])
	}

	if header[1] != replySuccess {
		return fmt.Errorf("UDP ASSOCIATE failed: %s", socks5ReplyString(header[1]))
	}

	// Parse bound address based on ATYP
	var relayIP net.IP
	var relayPort uint16

	switch header[3] {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(c.tcpConn, addr); err != nil {
			return fmt.Errorf("failed to read IPv4 address: %w", err)
		}
		relayIP = net.IP(addr)

	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(c.tcpConn, lenByte); err != nil {
			return fmt.Errorf("failed to read domain length: %w", err)
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(c.tcpConn, domain); err != nil {
			return fmt.Errorf("failed to read domain: %w", err)
		}
		// Resolve domain to IP
		ips, err := net.LookupIP(string(domain))
		if err != nil || len(ips) == 0 {
			return fmt.Errorf("failed to resolve relay domain %s: %w", domain, err)
		}
		relayIP = ips[0]

	case atypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(c.tcpConn, addr); err != nil {
			return fmt.Errorf("failed to read IPv6 address: %w", err)
		}
		relayIP = net.IP(addr)

	default:
		return fmt.Errorf("unsupported address type in reply: %d", header[3])
	}

	// Read port (2 bytes, big-endian)
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(c.tcpConn, portBytes); err != nil {
		return fmt.Errorf("failed to read port: %w", err)
	}
	relayPort = binary.BigEndian.Uint16(portBytes)

	// Handle 0.0.0.0 - proxy wants us to use its own IP
	if relayIP.IsUnspecified() {
		// Use the proxy's IP address
		proxyIP := net.ParseIP(c.proxyHost)
		if proxyIP == nil {
			// Proxy host is a domain, resolve it
			ips, err := net.LookupIP(c.proxyHost)
			if err != nil || len(ips) == 0 {
				return fmt.Errorf("failed to resolve proxy host %s: %w", c.proxyHost, err)
			}
			proxyIP = ips[0]
		}
		relayIP = proxyIP
	}

	c.relayAddr = &net.UDPAddr{IP: relayIP, Port: int(relayPort)}
	return nil
}

// tcpKeepalive monitors the TCP control channel
// If it closes, the UDP relay stops working
func (c *SOCKS5UDPConn) tcpKeepalive() {
	buf := make([]byte, 1)
	for {
		c.mu.RLock()
		if c.closed {
			c.mu.RUnlock()
			return
		}
		tcpConn := c.tcpConn
		c.mu.RUnlock()

		if tcpConn == nil {
			return
		}

		// Set a read deadline to check periodically
		tcpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err := tcpConn.Read(buf)

		if err != nil {
			// Check if it's just a timeout (expected) or actual error
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Normal timeout, continue
				continue
			}

			// Connection closed or error - close everything
			c.Close()
			return
		}
	}
}

// WriteTo implements net.PacketConn - writes a UDP datagram through the proxy
func (c *SOCKS5UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return 0, net.ErrClosed
	}
	if !c.established {
		c.mu.RUnlock()
		return 0, errors.New("SOCKS5 UDP connection not established")
	}
	udpConn := c.udpConn
	relayAddr := c.relayAddr
	c.mu.RUnlock()

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("invalid address type: %T (expected *net.UDPAddr)", addr)
	}

	// Build SOCKS5 UDP header
	header := buildSOCKS5UDPHeader(udpAddr)

	// Combine header + data
	packet := make([]byte, len(header)+len(b))
	copy(packet, header)
	copy(packet[len(header):], b)

	// Apply write deadline if set
	c.mu.RLock()
	deadline := c.writeDeadline
	c.mu.RUnlock()
	if !deadline.IsZero() {
		udpConn.SetWriteDeadline(deadline)
	}

	// Send to relay address
	n, err := udpConn.WriteTo(packet, relayAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to write to relay: %w", err)
	}

	c.mu.Lock()
	c.lastActivity = time.Now()
	c.writeCount++
	c.mu.Unlock()

	// Return original data length (not including header)
	dataLen := n - len(header)
	if dataLen < 0 {
		dataLen = 0
	}
	return dataLen, nil
}

// ReadFrom implements net.PacketConn - reads a UDP datagram from the proxy
func (c *SOCKS5UDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return 0, nil, net.ErrClosed
	}
	if !c.established {
		c.mu.RUnlock()
		return 0, nil, errors.New("SOCKS5 UDP connection not established")
	}
	udpConn := c.udpConn
	c.mu.RUnlock()

	// Apply read deadline if set
	c.mu.RLock()
	deadline := c.readDeadline
	c.mu.RUnlock()
	if !deadline.IsZero() {
		udpConn.SetReadDeadline(deadline)
	}

	// Read into buffer
	n, _, err := udpConn.ReadFrom(c.readBuf)
	if err != nil {
		return 0, nil, err
	}

	// Parse SOCKS5 UDP header and extract data
	dataOffset, srcAddr, err := parseSOCKS5UDPHeader(c.readBuf[:n])
	if err != nil {
		return 0, nil, fmt.Errorf("invalid SOCKS5 UDP header: %w", err)
	}

	// Copy data to output buffer
	dataLen := n - dataOffset
	if dataLen > len(b) {
		dataLen = len(b)
	}
	copy(b, c.readBuf[dataOffset:dataOffset+dataLen])

	// Update activity time
	c.mu.Lock()
	c.lastActivity = time.Now()
	c.mu.Unlock()

	return dataLen, srcAddr, nil
}

// Close closes both TCP and UDP connections
func (c *SOCKS5UDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	var errs []error

	if c.udpConn != nil {
		if err := c.udpConn.Close(); err != nil {
			errs = append(errs, err)
		}
		c.udpConn = nil
	}

	if c.tcpConn != nil {
		if err := c.tcpConn.Close(); err != nil {
			errs = append(errs, err)
		}
		c.tcpConn = nil
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// LocalAddr returns the local UDP address
func (c *SOCKS5UDPConn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.udpConn != nil {
		return c.udpConn.LocalAddr()
	}
	return nil
}

// SetDeadline sets both read and write deadlines
func (c *SOCKS5UDPConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

// SetReadDeadline sets the read deadline
func (c *SOCKS5UDPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline sets the write deadline
func (c *SOCKS5UDPConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

// RelayAddr returns the UDP relay address from the proxy
func (c *SOCKS5UDPConn) RelayAddr() *net.UDPAddr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.relayAddr
}

// IsEstablished returns true if UDP ASSOCIATE was successful
func (c *SOCKS5UDPConn) IsEstablished() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.established
}

// buildSOCKS5UDPHeader builds the SOCKS5 UDP request header
// Format: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2)
func buildSOCKS5UDPHeader(addr *net.UDPAddr) []byte {
	var header []byte

	// RSV (2 bytes) + FRAG (1 byte) - all zeros for non-fragmented
	header = append(header, 0x00, 0x00, 0x00)

	// Address type and address
	ip := addr.IP
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		header = append(header, atypIPv4)
		header = append(header, ip4...)
	} else if ip16 := ip.To16(); ip16 != nil {
		// IPv6
		header = append(header, atypIPv6)
		header = append(header, ip16...)
	} else {
		// Fallback to IPv4 zeros (shouldn't happen)
		header = append(header, atypIPv4, 0, 0, 0, 0)
	}

	// Port (big-endian)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(addr.Port))
	header = append(header, port...)

	return header
}

// parseSOCKS5UDPHeader parses the SOCKS5 UDP header from a received packet
// Returns the data offset and source address
func parseSOCKS5UDPHeader(packet []byte) (dataOffset int, srcAddr net.Addr, err error) {
	if len(packet) < 10 { // Minimum: RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + Port(2)
		return 0, nil, errors.New("packet too small")
	}

	// Check RSV (should be 0x0000)
	// Some proxies don't zero this, so we'll be lenient

	// Check FRAG - we don't support fragmentation
	if packet[2] != 0x00 {
		return 0, nil, fmt.Errorf("fragmented packets not supported (frag=%d)", packet[2])
	}

	// Parse address based on ATYP
	atyp := packet[3]
	var ip net.IP
	var port uint16
	var addrEnd int

	switch atyp {
	case atypIPv4:
		if len(packet) < 10 {
			return 0, nil, errors.New("packet too small for IPv4 address")
		}
		ip = net.IP(packet[4:8])
		port = binary.BigEndian.Uint16(packet[8:10])
		addrEnd = 10

	case atypDomain:
		if len(packet) < 5 {
			return 0, nil, errors.New("packet too small for domain length")
		}
		domainLen := int(packet[4])
		if len(packet) < 7+domainLen {
			return 0, nil, errors.New("packet too small for domain")
		}
		// For domain names, we'll resolve them
		domain := string(packet[5 : 5+domainLen])
		ips, resolveErr := net.LookupIP(domain)
		if resolveErr != nil || len(ips) == 0 {
			// Can't resolve, use placeholder
			ip = net.IPv4zero
		} else {
			ip = ips[0]
		}
		port = binary.BigEndian.Uint16(packet[5+domainLen : 7+domainLen])
		addrEnd = 7 + domainLen

	case atypIPv6:
		if len(packet) < 22 {
			return 0, nil, errors.New("packet too small for IPv6 address")
		}
		ip = net.IP(packet[4:20])
		port = binary.BigEndian.Uint16(packet[20:22])
		addrEnd = 22

	default:
		return 0, nil, fmt.Errorf("unsupported address type: %d", atyp)
	}

	srcAddr = &net.UDPAddr{IP: ip, Port: int(port)}
	return addrEnd, srcAddr, nil
}

// socks5ReplyString returns a human-readable error for SOCKS5 reply codes
func socks5ReplyString(code byte) string {
	switch code {
	case replySuccess:
		return "success"
	case replyGeneralFailure:
		return "general SOCKS server failure"
	case replyConnNotAllowed:
		return "connection not allowed by ruleset"
	case replyNetworkUnreach:
		return "network unreachable"
	case replyHostUnreach:
		return "host unreachable"
	case replyConnRefused:
		return "connection refused"
	case replyTTLExpired:
		return "TTL expired"
	case replyCmdNotSupported:
		return "command not supported"
	case replyAddrNotSupported:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown error (code %d)", code)
	}
}
