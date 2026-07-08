//go:build linux

package transport

import (
	"fmt"
	"syscall"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// TCP_WINDOW_CLAMP limits the announced TCP window size.
// Not exported by Go's syscall package on Linux.
const tcpWindowClamp = 10

// applyTCPFingerprint sets TCP/IP stack parameters on a raw socket via setsockopt.
// Called from Dialer.Control BEFORE connect(), so the SYN packet carries the
// spoofed values (TTL, MSS, window size, DF bit).
func applyTCPFingerprint(conn syscall.RawConn, fp *fingerprint.TCPFingerprint) error {
	var sysErr error
	err := conn.Control(func(fd uintptr) {
		s := int(fd)

		// TTL / IPv6 hop limit — determines the hop count seen by the remote
		// (128=Windows, 64=Linux/macOS). The socket family is not known here: a
		// dual-stack "tcp" dial resolves it only at connect(), so set BOTH the IPv4
		// (IP_TTL) and IPv6 (IPV6_UNICAST_HOPS) options. Setting the one that does
		// not match the family is a harmless ENOPROTOOPT; only a failure of BOTH is
		// a real error. Previously only IP_TTL was set, so IPv6 SYNs carried the
		// kernel default hop limit (64) regardless of the fingerprint (issue #81).
		if fp.TTL > 0 {
			e4 := syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_TTL, fp.TTL)
			e6 := syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, fp.TTL)
			if e4 != nil && e6 != nil {
				sysErr = fmt.Errorf("set TTL/hop-limit (IP_TTL: %v; IPV6_UNICAST_HOPS: %v)", e4, e6)
				return
			}
		}

		// TCP Maximum Segment Size — 1460 for standard Ethernet
		if fp.MSS > 0 {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, fp.MSS); e != nil {
				sysErr = fmt.Errorf("TCP_MAXSEG: %w", e)
				return
			}
		}

		// TCP window size. The advertised initial receive window is derived from
		// the socket receive buffer, so request a buffer comfortably larger than
		// WindowSize; the previous WindowSize/2 produced an advertised window of
		// only ~WindowSize/2 (issue #73). TCP_WINDOW_CLAMP below caps the window at
		// WindowSize, so over-requesting the buffer is safe. SO_RCVBUF is bounded
		// by net.core.rmem_max; the clamp still holds the window at WindowSize as
		// long as the (rmem_max-limited) buffer covers it, which the ~208KB default
		// does for browser-sized windows.
		//
		// LIMITATION (window scale): the SYN window scale is chosen by the kernel
		// from the receive buffer and is forced to 0 by the window clamp, and
		// net.core.rmem_max caps the buffer far below what a large scale (Windows'
		// wscale 8 needs ~16MB) requires. So the window SIZE is matched here but the
		// window SCALE cannot be set to an arbitrary browser value via setsockopt on
		// Linux (fp.WindowScale is advisory); matching it exactly needs kernel-level
		// packet rewriting (nftables/eBPF) or a raised net.core.rmem_max.
		if fp.WindowSize > 0 {
			if e := syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_RCVBUF, fp.WindowSize*4); e != nil {
				sysErr = fmt.Errorf("SO_RCVBUF: %w", e)
				return
			}
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_TCP, tcpWindowClamp, fp.WindowSize); e != nil {
				sysErr = fmt.Errorf("TCP_WINDOW_CLAMP: %w", e)
				return
			}
		}

		// IPv4 Don't Fragment flag via IP_MTU_DISCOVER. IPv6 has no DF bit in the
		// header (routers never fragment; PMTUD is end-to-end), so this is IPv4-only
		// and best-effort: on a pure-IPv6 socket IP_MTU_DISCOVER is ENOPROTOOPT and
		// must NOT abort the dial. Previously it returned the error, so a Windows
		// fingerprint (DFBit set) failed every IPv6 connection (issue #81).
		if fp.DFBit {
			_ = syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)
		}
	})
	if err != nil {
		return err
	}
	return sysErr
}
