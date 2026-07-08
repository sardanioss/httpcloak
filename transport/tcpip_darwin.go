//go:build darwin

package transport

import (
	"fmt"
	"syscall"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// IP_DONTFRAG is macOS-specific (not in Go's syscall package).
// See /usr/include/netinet/in.h: #define IP_DONTFRAG 28
const ipDontFrag = 28

// applyTCPFingerprint sets TCP/IP stack parameters on a raw socket via setsockopt.
// Called from Dialer.Control BEFORE connect(), so the SYN packet carries the
// spoofed values (TTL, MSS, window size, DF bit).
func applyTCPFingerprint(conn syscall.RawConn, fp *fingerprint.TCPFingerprint) error {
	var sysErr error
	err := conn.Control(func(fd uintptr) {
		s := int(fd)

		// TTL / IPv6 hop limit. Set both the IPv4 (IP_TTL) and IPv6
		// (IPV6_UNICAST_HOPS) options since the socket family is not known here;
		// the mismatched one is a harmless ENOPROTOOPT. Only a failure of both is
		// a real error. Previously only IP_TTL was set, so IPv6 SYNs kept the
		// kernel default hop limit (issue #81).
		if fp.TTL > 0 {
			e4 := syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_TTL, fp.TTL)
			e6 := syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, fp.TTL)
			if e4 != nil && e6 != nil {
				sysErr = fmt.Errorf("set TTL/hop-limit (IP_TTL: %v; IPV6_UNICAST_HOPS: %v)", e4, e6)
				return
			}
		}

		// TCP Maximum Segment Size
		if fp.MSS > 0 {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, fp.MSS); e != nil {
				sysErr = fmt.Errorf("TCP_MAXSEG: %w", e)
				return
			}
		}

		// TCP Window Size via SO_RCVBUF (macOS does NOT double this like Linux)
		if fp.WindowSize > 0 {
			if e := syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_RCVBUF, fp.WindowSize); e != nil {
				sysErr = fmt.Errorf("SO_RCVBUF: %w", e)
				return
			}
		}

		// IPv4 Don't Fragment flag (macOS-specific socket option). IPv6 has no DF
		// bit in the header, so this is IPv4-only and best-effort: on a pure-IPv6
		// socket IP_DONTFRAG is ENOPROTOOPT and must not abort the dial (issue #81).
		if fp.DFBit {
			_ = syscall.SetsockoptInt(s, syscall.IPPROTO_IP, ipDontFrag, 1)
		}
	})
	if err != nil {
		return err
	}
	return sysErr
}
