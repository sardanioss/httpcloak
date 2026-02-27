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

// applyTCPFingerprint sets TCP/IP stack parameters on a raw socket via setsockopt.
// Called from Dialer.Control BEFORE connect(), so the SYN packet carries the
// spoofed values (TTL, window size, DF bit).
// Note: TCP_MAXSEG is not reliably settable on Windows.
func applyTCPFingerprint(conn syscall.RawConn, fp *fingerprint.TCPFingerprint) error {
	var sysErr error
	err := conn.Control(func(fd uintptr) {
		s := syscall.Handle(fd)

		// IP TTL
		if fp.TTL > 0 {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_TTL, fp.TTL); e != nil {
				sysErr = fmt.Errorf("IP_TTL: %w", e)
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

		// IP Don't Fragment flag (Windows-specific socket option)
		if fp.DFBit {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_IP, ipDontFragment, 1); e != nil {
				sysErr = fmt.Errorf("IP_DONTFRAGMENT: %w", e)
				return
			}
		}
	})
	if err != nil {
		return err
	}
	return sysErr
}
