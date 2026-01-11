package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"
)

// SOCKS5Dialer provides SOCKS5 TCP CONNECT functionality for HTTP/1.1 and HTTP/2
type SOCKS5Dialer struct {
	// Proxy address
	proxyHost string
	proxyPort string

	// Authentication
	username string
	password string

	// Connection timeout
	timeout time.Duration
}

// NewSOCKS5Dialer creates a new SOCKS5 dialer from a proxy URL
// URL format: socks5://[user:pass@]host:port or socks5h://[user:pass@]host:port
func NewSOCKS5Dialer(proxyURL string) (*SOCKS5Dialer, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	if parsed.Scheme != "socks5" && parsed.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported proxy scheme: %s (need socks5 or socks5h)", parsed.Scheme)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "1080" // Default SOCKS5 port
	}

	dialer := &SOCKS5Dialer{
		proxyHost: host,
		proxyPort: port,
		timeout:   30 * time.Second,
	}

	// Extract credentials if present
	if parsed.User != nil {
		dialer.username = parsed.User.Username()
		dialer.password, _ = parsed.User.Password()
	}

	return dialer, nil
}

// DialContext connects to the target through the SOCKS5 proxy using TCP CONNECT
func (d *SOCKS5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Parse target address
	targetHost, targetPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	// Resolve proxy hostname using CGO-compatible resolver
	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, d.proxyHost)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", d.proxyHost, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", d.proxyHost)
	}

	// Connect to proxy
	proxyAddr := net.JoinHostPort(proxyIPs[0], d.proxyPort)
	dialer := &net.Dialer{Timeout: d.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
	}

	// Set deadline for handshake
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	// Perform SOCKS5 handshake
	if err := d.socks5Handshake(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
	}

	// Send CONNECT request
	if err := d.socks5Connect(conn, targetHost, targetPort); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT failed: %w", err)
	}

	// Clear deadline after successful handshake
	conn.SetDeadline(time.Time{})

	return conn, nil
}

// socks5Handshake performs version negotiation and authentication
func (d *SOCKS5Dialer) socks5Handshake(conn net.Conn) error {
	// Build greeting message
	var greeting []byte
	if d.username != "" {
		// Offer both no-auth and username/password
		greeting = []byte{socks5Version, 0x02, authNone, authPassword}
	} else {
		// Only offer no-auth
		greeting = []byte{socks5Version, 0x01, authNone}
	}

	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	// Read server's chosen method
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
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
		return d.socks5PasswordAuth(conn)
	case authNoAccept:
		return errors.New("proxy rejected all authentication methods")
	default:
		return fmt.Errorf("unsupported authentication method: %d", resp[1])
	}
}

// socks5PasswordAuth performs username/password authentication (RFC 1929)
func (d *SOCKS5Dialer) socks5PasswordAuth(conn net.Conn) error {
	if d.username == "" {
		return errors.New("proxy requires authentication but no credentials provided")
	}

	// Build auth request: VER(1) + ULEN(1) + UNAME(1-255) + PLEN(1) + PASSWD(1-255)
	authReq := make([]byte, 0, 3+len(d.username)+len(d.password))
	authReq = append(authReq, 0x01) // Auth sub-negotiation version
	authReq = append(authReq, byte(len(d.username)))
	authReq = append(authReq, []byte(d.username)...)
	authReq = append(authReq, byte(len(d.password)))
	authReq = append(authReq, []byte(d.password)...)

	if _, err := conn.Write(authReq); err != nil {
		return fmt.Errorf("failed to send auth request: %w", err)
	}

	// Read auth response: VER(1) + STATUS(1)
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp[1] != 0x00 {
		return errors.New("authentication failed: invalid credentials")
	}

	return nil
}

// socks5Connect sends a CONNECT request and reads the reply
func (d *SOCKS5Dialer) socks5Connect(conn net.Conn, host, port string) error {
	// Parse port
	portNum, err := net.LookupPort("tcp", port)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	// Build CONNECT request
	// VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2)
	request := []byte{socks5Version, cmdConnect, 0x00}

	// Try to parse as IP first
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			request = append(request, atypIPv4)
			request = append(request, ip4...)
		} else {
			// IPv6
			request = append(request, atypIPv6)
			request = append(request, ip.To16()...)
		}
	} else {
		// Domain name
		if len(host) > 255 {
			return errors.New("domain name too long")
		}
		request = append(request, atypDomain)
		request = append(request, byte(len(host)))
		request = append(request, []byte(host)...)
	}

	// Add port (big-endian)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portNum))
	request = append(request, portBytes...)

	// Send request
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	// Read reply header: VER(1) + REP(1) + RSV(1) + ATYP(1)
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read reply header: %w", err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("invalid SOCKS version in reply: %d", header[0])
	}

	if header[1] != replySuccess {
		return fmt.Errorf("CONNECT failed: %s (reply=%d)", socks5ReplyString(header[1]), header[1])
	}

	// Read and discard bound address (we don't need it for TCP CONNECT)
	switch header[3] {
	case atypIPv4:
		// 4 bytes IP + 2 bytes port
		if _, err := io.ReadFull(conn, make([]byte, 6)); err != nil {
			return fmt.Errorf("failed to read bound address: %w", err)
		}
	case atypDomain:
		// 1 byte length + domain + 2 bytes port
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return fmt.Errorf("failed to read domain length: %w", err)
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lenByte[0])+2)); err != nil {
			return fmt.Errorf("failed to read domain and port: %w", err)
		}
	case atypIPv6:
		// 16 bytes IP + 2 bytes port
		if _, err := io.ReadFull(conn, make([]byte, 18)); err != nil {
			return fmt.Errorf("failed to read bound address: %w", err)
		}
	default:
		return fmt.Errorf("unsupported address type in reply: %d", header[3])
	}

	// Connection established - tunnel is now open
	return nil
}

// IsSOCKS5URL checks if the URL is a SOCKS5 proxy URL
func IsSOCKS5URL(proxyURL string) bool {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}
	return parsed.Scheme == "socks5" || parsed.Scheme == "socks5h"
}
