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

		// IP TTL
		if fp.TTL > 0 {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_TTL, fp.TTL); e != nil {
				sysErr = fmt.Errorf("IP_TTL: %w", e)
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

		// IP Don't Fragment flag (macOS-specific socket option)
		if fp.DFBit {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_IP, ipDontFrag, 1); e != nil {
				sysErr = fmt.Errorf("IP_DONTFRAG: %w", e)
				return
			}
		}
	})
	if err != nil {
		return err
	}
	return sysErr
}
