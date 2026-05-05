package transport

import (
	"context"
	"fmt"
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

// ApplyLocalAddrControl wires freebind onto a net.Dialer that's binding to
// localAddr. Composes with any pre-existing dialer.Control (e.g. TCP
// fingerprint) so callers don't have to think about ordering. localAddr ==
// "" is a no-op so the same wiring is safe to call unconditionally.
//
// Why we only freebind when localAddr is set: most users never touch
// LocalAddr, and silently turning freebind on for them would be surprising
// (it changes the failure semantics of bind() — without it you'd see
// EADDRNOTAVAIL early; with it the kernel happily accepts non-local
// addresses and you only discover the misconfig later when packets vanish).
// Opt-in via LocalAddr keeps the principle of least surprise.
func ApplyLocalAddrControl(dialer *net.Dialer, localAddr string) {
	if localAddr == "" {
		return
	}
	prev := dialer.Control
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		applyFreebind(c)
		if prev != nil {
			return prev(network, address, c)
		}
		return nil
	}
}

// BuildLocalAddrListenControl returns a ListenConfig.Control callback that
// applies freebind to a UDP socket about to bind to localAddr. Returns nil
// when localAddr is empty so callers can plug it straight into a
// net.ListenConfig literal without conditional code.
func BuildLocalAddrListenControl(localAddr string) func(network, address string, c syscall.RawConn) error {
	if localAddr == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		applyFreebind(c)
		return nil
	}
}

// ListenUDPWithLocalAddr opens a UDP socket on network bound to localUDPAddr.
// When localAddr is non-empty, freebind is applied first so the bind succeeds
// for addresses that aren't configured on any local interface (the IPv6
// prefix rotation case). When localAddr is empty this degrades to a plain
// net.ListenUDP — no behaviour change for callers that don't use the
// feature.
//
// Returns *net.UDPConn (not net.PacketConn) so the H3 path can plug it
// straight into quic.Transport without an extra type assertion at the
// call site.
func ListenUDPWithLocalAddr(network string, localUDPAddr *net.UDPAddr, localAddr string) (*net.UDPConn, error) {
	ctrl := BuildLocalAddrListenControl(localAddr)
	if ctrl == nil {
		return net.ListenUDP(network, localUDPAddr)
	}
	lc := &net.ListenConfig{Control: ctrl}
	pc, err := lc.ListenPacket(context.Background(), network, localUDPAddr.String())
	if err != nil {
		return nil, err
	}
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("ListenPacket returned %T, want *net.UDPConn", pc)
	}
	return udp, nil
}

// BuildDialControl returns a Dialer.Control callback that chains TCP
// fingerprint sockopts with freebind (when localAddr is set). Useful when
// the dialer is owned by another package (proxy/socks5_tcp) that cannot
// import this package — pass the result via that package's Control field.
// Returns nil if neither concern applies (no fingerprint, no localAddr).
func BuildDialControl(fp *fingerprint.TCPFingerprint, localAddr string) func(network, address string, c syscall.RawConn) error {
	fpCtrl := BuildDialerControl(fp)
	if fpCtrl == nil && localAddr == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		if localAddr != "" {
			applyFreebind(c)
		}
		if fpCtrl != nil {
			return fpCtrl(network, address, c)
		}
		return nil
	}
}
