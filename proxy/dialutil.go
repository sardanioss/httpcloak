package proxy

import (
	"context"
	"fmt"
	"net"
	"time"
)

// orderIPv4First reorders resolved address strings so IPv4 is attempted before
// IPv6 (then any unparseable entries last). Proxy providers commonly route IPv4
// more reliably than IPv6, and a dual-stack DNS answer that lists an unreachable
// IPv6 address first was the cause of proxy dials that got stuck on the first
// address instead of falling through to a reachable one.
func orderIPv4First(ips []string) []string {
	out := make([]string, 0, len(ips))
	var v6, other []string
	for _, s := range ips {
		ip := net.ParseIP(s)
		switch {
		case ip == nil:
			other = append(other, s)
		case ip.To4() != nil:
			out = append(out, s)
		default:
			v6 = append(v6, s)
		}
	}
	out = append(out, v6...)
	out = append(out, other...)
	return out
}

// dialTCPFirstReachable dials each candidate proxy address in turn (IPv4 first)
// and returns the first connection that establishes. Trying every resolved
// address — rather than only the first — means a proxy whose DNS lists an
// unreachable address ahead of a reachable one still connects. Each attempt
// gets an even slice of connectTimeout, capped at 10s.
func dialTCPFirstReachable(ctx context.Context, dialer *net.Dialer, proxyIPs []string, proxyPort string, connectTimeout time.Duration) (net.Conn, error) {
	ordered := orderIPv4First(proxyIPs)
	if len(ordered) == 0 {
		return nil, fmt.Errorf("no proxy addresses to dial")
	}
	var lastErr error
	remaining := len(ordered)
	for _, ipStr := range ordered {
		network := "tcp"
		if ip := net.ParseIP(ipStr); ip != nil {
			if ip.To4() != nil {
				network = "tcp4"
			} else {
				network = "tcp6"
			}
		}
		perAddr := connectTimeout
		if connectTimeout > 0 && remaining > 0 {
			perAddr = connectTimeout / time.Duration(remaining)
		}
		if perAddr <= 0 || perAddr > 10*time.Second {
			perAddr = 10 * time.Second
		}
		dialCtx, cancel := context.WithTimeout(ctx, perAddr)
		conn, err := dialer.DialContext(dialCtx, network, net.JoinHostPort(ipStr, proxyPort))
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
		remaining--
	}
	return nil, fmt.Errorf("failed to connect to proxy (tried %d address(es)): %w", len(ordered), lastErr)
}
