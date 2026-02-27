//go:build !linux && !darwin && !windows

package transport

import (
	"syscall"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// applyTCPFingerprint is a no-op on unsupported platforms.
// TCP/IP fingerprint spoofing requires platform-specific setsockopt calls.
func applyTCPFingerprint(_ syscall.RawConn, _ *fingerprint.TCPFingerprint) error {
	return nil
}
