//go:build windows

package transport

import (
	"fmt"
	"syscall"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// IP_DONTFRAGMENT is Windows-specific (not in Go's syscall package).
// See winsock2.h: #define IP_DONTFRAGMENT 14
const ipDontFragment = 14

// Winsock IPv6 constants (ws2ipdef.h), defined locally for portability across
// Go's Windows syscall package: IPPROTO_IPV6 = 41, IPV6_UNICAST_HOPS = 4.
const (
	ipprotoIPv6     = 41
	ipv6UnicastHops = 4
)

// applyTCPFingerprint sets TCP/IP stack parameters on a raw socket via setsockopt.
// Called from Dialer.Control BEFORE connect(), so the SYN packet carries the
// spoofed values (TTL, window size, DF bit).
// Note: TCP_MAXSEG is not reliably settable on Windows.
func applyTCPFingerprint(conn syscall.RawConn, fp *fingerprint.TCPFingerprint) error {
	var sysErr error
	err := conn.Control(func(fd uintptr) {
		s := syscall.Handle(fd)

		// TTL / IPv6 hop limit. Set both the IPv4 (IP_TTL) and IPv6
		// (IPV6_UNICAST_HOPS) options since the socket family is not known here;
		// the mismatched one fails harmlessly. Only a failure of both is a real
		// error. Previously only IP_TTL was set, so IPv6 SYNs kept the kernel
		// default hop limit (issue #81).
		if fp.TTL > 0 {
			e4 := syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_TTL, fp.TTL)
			e6 := syscall.SetsockoptInt(s, ipprotoIPv6, ipv6UnicastHops, fp.TTL)
			if e4 != nil && e6 != nil {
				sysErr = fmt.Errorf("set TTL/hop-limit (IP_TTL: %v; IPV6_UNICAST_HOPS: %v)", e4, e6)
				return
			}
		}

		// TCP Window Size via SO_RCVBUF
		if fp.WindowSize > 0 {
			if e := syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_RCVBUF, fp.WindowSize); e != nil {
				sysErr = fmt.Errorf("SO_RCVBUF: %w", e)
				return
			}
		}

		// IPv4 Don't Fragment flag (Windows-specific socket option). IPv6 has no DF
		// bit, so this is IPv4-only and best-effort: on a pure-IPv6 socket it fails
		// harmlessly and must not abort the dial (issue #81).
		if fp.DFBit {
			_ = syscall.SetsockoptInt(s, syscall.IPPROTO_IP, ipDontFragment, 1)
		}
	})
	if err != nil {
		return err
	}
	return sysErr
}
