package transport

import (
	"net"
	"runtime"
	"testing"
)

// BuildLocalAddrListenControl returns nil when localAddr is empty so callers
// can plug it into a net.ListenConfig literal without conditional code.
func TestBuildLocalAddrListenControl_EmptyIsNil(t *testing.T) {
	if got := BuildLocalAddrListenControl(""); got != nil {
		t.Errorf("empty localAddr should return nil callback, got non-nil")
		_ = got
	}
}

func TestBuildLocalAddrListenControl_SetReturnsCallback(t *testing.T) {
	if got := BuildLocalAddrListenControl("2001:db8::1"); got == nil {
		t.Error("non-empty localAddr should return a callback, got nil")
	}
}

// BuildDialControl returns nil when neither fingerprint sockopts nor freebind
// apply, so callers don't pay the indirect-call cost on the hot dial path.
func TestBuildDialControl_NothingToDoMeansNil(t *testing.T) {
	if got := BuildDialControl(nil, ""); got != nil {
		t.Errorf("nil fingerprint + empty localAddr should return nil, got non-nil")
		_ = got
	}
}

// ListenUDPWithLocalAddr falls back to plain net.ListenUDP when localAddr is
// empty (no freebind needed) — this is the path every caller hits when the
// user never set WithLocalAddress.
func TestListenUDPWithLocalAddr_EmptyLocalAddrUsesPlainListen(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	conn, err := ListenUDPWithLocalAddr("udp", addr, "")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	if conn.LocalAddr() == nil {
		t.Error("expected a bound local address, got nil")
	}
}

// ListenUDPWithLocalAddr with a configured local IP also returns a bound
// socket. We use 127.0.0.1 so the test passes without freebind privilege.
func TestListenUDPWithLocalAddr_ConfiguredLocalAddrBinds(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDPWithLocalAddr("udp", addr, "127.0.0.1")
	if err != nil {
		t.Fatalf("listen 127.0.0.1: %v", err)
	}
	defer conn.Close()
	if conn.LocalAddr() == nil {
		t.Error("expected a bound local address, got nil")
	}
}

// On Linux, freebind should let us bind a UDP socket to an IPv6 address
// that's not configured on any local interface. On other platforms the
// freebind helper is a no-op and this bind would fail with EADDRNOTAVAIL,
// so we skip elsewhere. If the test runs without CAP_NET_ADMIN /
// net.ipv6.ip_nonlocal_bind=1, the bind also legitimately fails — we
// downgrade that to a skip so CI without the privilege isn't a hard fail.
func TestListenUDPWithLocalAddr_FreebindNonLocalIPv6(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("freebind is Linux-only (running on %s)", runtime.GOOS)
	}
	// Documentation prefix 2001:db8::/32 — guaranteed not routed locally.
	const nonLocal = "2001:db8::dead:beef"
	addr := &net.UDPAddr{IP: net.ParseIP(nonLocal), Port: 0}
	conn, err := ListenUDPWithLocalAddr("udp6", addr, nonLocal)
	if err != nil {
		t.Skipf("freebind unprivileged or kernel disallows (skipping): %v", err)
	}
	defer conn.Close()
	bound := conn.LocalAddr().(*net.UDPAddr)
	if !bound.IP.Equal(net.ParseIP(nonLocal)) {
		t.Errorf("bound to %v, want %v", bound.IP, nonLocal)
	}
}
