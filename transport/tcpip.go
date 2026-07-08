package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

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

// proxyDialAttempts is the total number of connection-establishment attempts
// made when a proxy is configured (1 initial + retries). Retrying here is safe
// for every HTTP method because it happens before any request bytes leave the
// client — unlike retrying on a 5xx response, it can never duplicate a
// non-idempotent request (the reason response-level retry defaults to 0). Kept
// small and proxy-scoped: it smooths transient proxy hiccups without changing
// direct-connection latency semantics.
const proxyDialAttempts = 2

// proxyDialBackoff is the pause between connection-establishment retries.
const proxyDialBackoff = 250 * time.Millisecond

// retryDial runs dial up to attempts times, giving each attempt its own
// attemptTimeout (derived from the parent context) and pausing proxyDialBackoff
// between tries. It aborts immediately if the parent context is done, never
// retrying a cancellation or deadline. attempts <= 1 means a single try with no
// retry overhead.
func retryDial[T any](parent context.Context, attempts int, attemptTimeout time.Duration, dial func(context.Context) (T, error)) (T, error) {
	var zero T
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := parent.Err(); err != nil {
			return zero, err
		}
		ctx := parent
		var cancel context.CancelFunc
		if attemptTimeout > 0 {
			ctx, cancel = context.WithTimeout(parent, attemptTimeout)
		}
		v, err := dial(ctx)
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return v, nil
		}
		// Never retry an ALPN downgrade: createConn returns ALPNMismatchError
		// carrying a LIVE TLS connection the caller must take ownership of (to
		// serve the request over HTTP/1.1). Retrying would both leak that
		// connection and pointlessly re-dial. Surface it immediately, conn intact.
		var alpnErr *ALPNMismatchError
		if errors.As(err, &alpnErr) {
			return zero, err
		}
		lastErr = err
		if attempt < attempts-1 {
			select {
			case <-time.After(proxyDialBackoff):
			case <-parent.Done():
				return zero, parent.Err()
			}
		}
	}
	return zero, lastErr
}

// staggeredRace implements RFC 8305 Happy Eyeballs v2 connection racing over n
// candidates. It dials candidate 0, then starts each subsequent candidate after
// attemptDelay — or immediately when an earlier attempt fails — and returns the
// first dial that succeeds, cancelling the rest. A dial that succeeds after the
// race is already won is handed to closeLoser so it isn't leaked. dial must
// honor the context it's given (it is cancelled for the losers).
func staggeredRace[T any](ctx context.Context, n int, attemptDelay time.Duration, dial func(ctx context.Context, idx int) (T, error), closeLoser func(T)) (T, error) {
	var zero T
	if n <= 0 {
		return zero, fmt.Errorf("no candidates to dial")
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		val T
		err error
	}
	results := make(chan result, n)

	launched, pending := 0, 0
	launchNext := func() {
		idx := launched
		go func() {
			v, err := dial(raceCtx, idx)
			results <- result{val: v, err: err}
		}()
		launched++
		pending++
	}

	timer := time.NewTimer(attemptDelay)
	defer timer.Stop()
	safeReset := func(d time.Duration) {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(d)
	}

	launchNext()

	var lastErr error
	for {
		select {
		case <-ctx.Done():
			// The parent cancelled the race. defer cancel() stops the losing
			// dials, but a dial that already succeeded (its result sitting in
			// the buffered channel, or landing right after cancellation) would
			// otherwise leak its *net.Conn / *quic.Conn. Drain the outstanding
			// results and close any that connected — mirror the winner-path
			// drain below. results is buffered to n, so this can't block forever.
			if pending > 0 {
				go func(rem int) {
					for i := 0; i < rem; i++ {
						lr := <-results
						if lr.err == nil {
							closeLoser(lr.val)
						}
					}
				}(pending)
			}
			return zero, ctx.Err()

		case <-timer.C:
			if launched < n {
				launchNext()
			}
			if launched < n {
				safeReset(attemptDelay)
			}

		case r := <-results:
			pending--
			if r.err == nil {
				cancel() // stop the losing dials
				if pending > 0 {
					go func(rem int) {
						for i := 0; i < rem; i++ {
							lr := <-results
							if lr.err == nil {
								closeLoser(lr.val)
							}
						}
					}(pending)
				}
				return r.val, nil
			}
			lastErr = r.err
			// Fail-fast: start the next candidate immediately rather than
			// waiting for the timer.
			if launched < n {
				launchNext()
				if launched < n {
					safeReset(attemptDelay)
				}
			} else if pending == 0 {
				if lastErr == nil {
					lastErr = fmt.Errorf("all dial attempts failed")
				}
				return zero, lastErr
			}
		}
	}
}

// ipsToStrings converts resolved net.IP values to their string form, preserving
// order (so a preference-sorted list from the DNS cache stays sorted).
func ipsToStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// orderIPv4First reorders resolved address strings so IPv4 is attempted before
// IPv6 (then any unparseable entries last). Many proxy providers route IPv4 far
// more reliably than IPv6, and a dual-stack DNS answer that lists an unreachable
// IPv6 address first was the root cause of proxy dials that got stuck on the
// first address and never fell through to a reachable one.
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

// dialProxyAddrs dials each candidate proxy address in turn (IPv4 first),
// returning the first connection that establishes. Trying every resolved
// address — rather than only the first — means a proxy whose DNS lists an
// unreachable address ahead of a reachable one (the classic dual-stack
// "IPv6 first but no IPv6 route" case) still connects instead of failing
// outright. Each attempt gets an even slice of the remaining time budget,
// capped at 10s, so one dead address can't burn the whole connectTimeout.
func dialProxyAddrs(ctx context.Context, dialer *net.Dialer, proxyIPs []string, proxyPort string, connectTimeout time.Duration) (net.Conn, error) {
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
		if remaining > 0 {
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
