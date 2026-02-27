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

		// IP TTL — determines hop count seen by remote (128=Windows, 64=Linux/macOS)
		if fp.TTL > 0 {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_TTL, fp.TTL); e != nil {
				sysErr = fmt.Errorf("IP_TTL: %w", e)
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

		// TCP Window Size via SO_RCVBUF.
		// Linux kernel doubles SO_RCVBUF internally (man 7 socket), so request half.
		// Bounded by /proc/sys/net/core/rmem_max — if too low the kernel silently
		// clamps, which is acceptable (window will just be smaller than intended).
		if fp.WindowSize > 0 {
			if e := syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_RCVBUF, fp.WindowSize/2); e != nil {
				sysErr = fmt.Errorf("SO_RCVBUF: %w", e)
				return
			}
		}

		// TCP_WINDOW_CLAMP constrains the advertised window. Combined with
		// SO_RCVBUF this controls the window scale factor in the SYN.
		if fp.WindowSize > 0 {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_TCP, tcpWindowClamp, fp.WindowSize); e != nil {
				sysErr = fmt.Errorf("TCP_WINDOW_CLAMP: %w", e)
				return
			}
		}

		// IP Don't Fragment flag via IP_MTU_DISCOVER
		if fp.DFBit {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO); e != nil {
				sysErr = fmt.Errorf("IP_MTU_DISCOVER: %w", e)
				return
			}
		}
	})
	if err != nil {
		return err
	}
	return sysErr
}
