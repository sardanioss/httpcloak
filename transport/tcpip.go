package transport

import (
	"net"
	"syscall"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// BuildDialerControl returns a Dialer.Control function that applies TCP/IP
// fingerprint settings to the raw socket before connect(). This sets TTL,
// MSS, window size, and DF bit in the SYN packet to match the target OS.
// Returns nil if no fingerprint is configured (zero TTL = no-op).
func BuildDialerControl(fp *fingerprint.TCPFingerprint) func(network, address string, conn syscall.RawConn) error {
	if fp == nil || fp.TTL == 0 {
		return nil
	}
	return func(network, address string, conn syscall.RawConn) error {
		return applyTCPFingerprint(conn, fp)
	}
}

// SetDialerControl configures a net.Dialer to apply TCP/IP fingerprint
// settings on every new connection. Safe to call with a nil or zero-value
// fingerprint (no-op in that case).
func SetDialerControl(dialer *net.Dialer, fp *fingerprint.TCPFingerprint) {
	if ctrl := BuildDialerControl(fp); ctrl != nil {
		dialer.Control = ctrl
	}
}
