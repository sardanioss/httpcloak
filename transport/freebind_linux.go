//go:build linux

package transport

import (
	"syscall"
)

// IP_FREEBIND lets a socket bind to a non-local IP address — useful when
// rotating outgoing connections across an entire routed IPv6 prefix without
// having to add every address to the interface.
//
// Not exported by Go's syscall package on Linux, but stable in the kernel:
//
//	IP_FREEBIND   = 15  // include/uapi/linux/in.h
//	IPV6_FREEBIND = 78  // include/uapi/linux/in6.h
//
// Setting both is harmless — the kernel ignores the wrong-family one.
const (
	ipFreebind   = 15
	ipv6Freebind = 78
)

// applyFreebind sets IP_FREEBIND + IPV6_FREEBIND on the raw socket. Failures
// are silently ignored: freebind is a privilege feature (CAP_NET_ADMIN or
// net.ipv4.ip_nonlocal_bind=1), and on a kernel where it's blocked the bind
// would have failed anyway with EADDRNOTAVAIL — we don't want to *also* fail
// the unprivileged-but-locally-configured case (where freebind is unneeded).
func applyFreebind(conn syscall.RawConn) {
	_ = conn.Control(func(fd uintptr) {
		s := int(fd)
		_ = syscall.SetsockoptInt(s, syscall.IPPROTO_IP, ipFreebind, 1)
		_ = syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, ipv6Freebind, 1)
	})
}
