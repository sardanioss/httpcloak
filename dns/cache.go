package dns

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// maxCacheEntries bounds the host->Entry map so a long-running client that
// touches many distinct hosts (and whose cache has no external cleanup driver,
// e.g. a standalone transport.Transport) can't grow it without limit. When the
// map crosses this size on a write, expired entries are swept inline — no
// background goroutine, so nothing leaks if the cache itself is dropped.
const maxCacheEntries = 4096

// resolveLookupTimeout bounds a single-flight resolver call. The underlying
// c.lookup runs under a context DETACHED from the leader caller (so one caller
// cancelling mid-flight can't abort the shared lookup for its peers), and
// context.WithoutCancel strips the parent deadline, so we re-apply this deadline
// to keep the detached lookup from running unbounded.
const resolveLookupTimeout = 15 * time.Second

// Entry represents a cached DNS entry. A negative entry (negative == true)
// caches a lookup failure for a short window so a genuinely missing/erroring
// name isn't re-resolved on every request.
type Entry struct {
	IPs       []net.IP
	ExpiresAt time.Time
	LookupAt  time.Time
	negative  bool
	err       error

	// network is the address family the entry was resolved under, stamped by
	// store. An entry is only valid while the cache is still on that family:
	// handing an AAAA-only result to a caller that has since rebound to IPv4
	// looks to it like a host with no usable address. Comparing here rather
	// than flushing on change makes that hold even against a lookup that was
	// already in flight when the family changed.
	network string
}

// IsExpired checks if the entry has expired
func (e *Entry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// Cache provides DNS caching with bounded entry lifetime, single-flight
// deduplication of concurrent lookups, and short negative caching.
type Cache struct {
	entries    map[string]*Entry
	mu         sync.RWMutex
	resolver   *net.Resolver
	defaultTTL time.Duration
	negTTL     time.Duration
	minTTL     time.Duration
	preferIPv4 bool // If true, prefer IPv4 over IPv6

	// network restricts lookups to one address family: "ip4", "ip6", or "" for
	// both. See SetNetwork.
	network string

	// sf collapses concurrent lookups of the same host into a single resolver
	// call (the others wait and share the result), preventing a thundering herd
	// when many requests start against a cold or just-expired name.
	sf singleflight.Group

	// lookupHook, when non-nil, replaces the system resolver call. It exists
	// purely as a test seam (nil in all production paths) so the caching,
	// single-flight, and negative-cache logic can be exercised deterministically.
	lookupHook func(ctx context.Context, host string) ([]net.IP, error)
}

// NewCache creates a new DNS cache
func NewCache() *Cache {
	// Use CGO resolver (PreferGo: false) for compatibility with shared library usage.
	// The pure-Go resolver doesn't work when Go runtime is loaded as a plugin/shared library
	// because the netpoller isn't properly initialized in that context.
	//
	// Note on TTL: getaddrinfo (the CGO resolver) does not expose record TTLs, and
	// we deliberately keep using it rather than issuing raw DNS queries — only the
	// system resolver honors /etc/hosts, nsswitch, and split-horizon/VPN DNS.
	// Instead of pinning entries for minutes, defaultTTL is kept short so CDN/GSLB
	// failovers are picked up quickly, with singleflight keeping the re-resolution
	// cost to one lookup per host per interval.
	resolver := &net.Resolver{
		PreferGo: false, // Force CGO resolver for shared library compatibility
	}
	return &Cache{
		entries:    make(map[string]*Entry),
		resolver:   resolver,
		defaultTTL: 60 * time.Second, // failover-responsive; getaddrinfo gives no wire TTL
		negTTL:     10 * time.Second, // short negative cache for NXDOMAIN / no-address
		minTTL:     5 * time.Second,  // floor for SetTTL
		preferIPv4: false,
	}
}

// SetPreferIPv4 sets whether to prefer IPv4 addresses over IPv6
func (c *Cache) SetPreferIPv4(prefer bool) {
	c.mu.Lock()
	c.preferIPv4 = prefer
	c.mu.Unlock()
}

// PreferIPv4 returns whether IPv4 is preferred over IPv6
func (c *Cache) PreferIPv4() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.preferIPv4
}

// SetNetwork restricts lookups to a single address family: "ip4" queries only
// A records, "ip6" only AAAA, and "" (the default) both. Anything else is
// ignored, so a bad value cannot silently turn every lookup into an error.
//
// This is a narrower knob than SetPreferIPv4, which only orders a result set
// that still contains both families. Restricting is for the case where the
// other family cannot be dialled at all, so resolving it is work whose result
// is discarded; see NetworkForLocalAddr.
//
// Entries resolved under the previous family are not flushed; they are stamped
// with it and ignored while the cache is on another one, so a lookup already in
// flight when the family changes cannot land as a usable entry either. The next
// lookup for that host replaces the entry, since entries are keyed by host
// alone, and any that are not looked up again expire on the normal TTL.
func (c *Cache) SetNetwork(network string) {
	if network != "" && network != "ip4" && network != "ip6" {
		return
	}
	c.mu.Lock()
	c.network = network
	c.mu.Unlock()
}

// Network returns the address family lookups are restricted to, or "" when
// both are queried.
func (c *Cache) Network() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.network
}

// NetworkForLocalAddr returns the SetNetwork value matching the family of a
// local source address, or "" when addr is empty or not an IP.
//
// Binding a source address makes the other family undialable: a socket bound
// to an IPv6 source cannot reach an IPv4 peer, and the transports already drop
// those addresses after resolving them. Feeding this to SetNetwork moves that
// filter ahead of the resolver, so the addresses that were going to be
// discarded are never asked for.
func NetworkForLocalAddr(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "ip4"
	}
	return "ip6"
}

// Resolve looks up the IP addresses for a hostname
// Returns cached result if available and not expired
func (c *Cache) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	// Fast path: a fresh cached entry (positive or negative) for the family the
	// cache is currently on. Both are read under one lock so the pair cannot be
	// torn by a concurrent SetNetwork.
	c.mu.RLock()
	entry, exists := c.entries[host]
	network := c.network
	c.mu.RUnlock()
	if exists && entry.network == network && !entry.IsExpired() {
		if entry.negative {
			return nil, entry.err
		}
		return entry.IPs, nil
	}

	// Cache miss or expired: dedup concurrent lookups of this host so a burst of
	// requests triggers one resolver call, not N. Use DoChan (not Do) so each
	// caller waits on ITS OWN ctx below — a leader whose request ctx cancels
	// mid-flight must not poison healthy joined callers with context.Canceled.
	ch := c.sf.DoChan(host, func() (interface{}, error) {
		// Re-check: another goroutine may have populated a fresh entry while we
		// were waiting for the single-flight slot.
		c.mu.RLock()
		e, ok := c.entries[host]
		current := c.network
		c.mu.RUnlock()
		if ok && e.network == current && !e.IsExpired() {
			if e.negative {
				return nil, e.err
			}
			return e.IPs, nil
		}

		// Run the shared lookup under a context detached from the leader caller,
		// so a single cancelled caller can't abort the resolver call the other
		// joined callers are still waiting on. WithoutCancel drops the deadline,
		// so re-apply a bounded one.
		lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resolveLookupTimeout)
		defer cancel()

		ips, lerr := c.lookup(lookupCtx, host)
		if lerr != nil {
			if isTransientDNSErr(lerr) {
				// Transient (timeout/temporary/network): serve a stale positive
				// entry if we have one, and do NOT negative-cache — the name may
				// be fine, the resolver just hiccuped.
				// Only a stale entry from the family the cache is on: one
				// resolved under a different family is not a usable answer for
				// this caller, so serving it would turn a resolver hiccup into
				// a host with no dialable address.
				if ok && e.network == current && !e.negative && len(e.IPs) > 0 {
					return e.IPs, nil
				}
				return nil, lerr
			}
			// Permanent (NXDOMAIN / no such host): drop any stale entry and
			// negative-cache briefly so we don't re-resolve a dead name every
			// request, while still recovering quickly if it comes back.
			c.store(host, &Entry{negative: true, err: lerr, ExpiresAt: time.Now().Add(c.negTTL)})
			return nil, lerr
		}
		if len(ips) == 0 {
			noAddr := &net.DNSError{Err: "no addresses found", Name: host, IsNotFound: true}
			c.store(host, &Entry{negative: true, err: noAddr, ExpiresAt: time.Now().Add(c.negTTL)})
			return nil, noAddr
		}

		c.mu.RLock()
		ttl := c.defaultTTL
		c.mu.RUnlock()
		c.store(host, &Entry{IPs: ips, ExpiresAt: time.Now().Add(ttl), LookupAt: time.Now()})
		return ips, nil
	})

	// Wait on the CALLER's own ctx, not the leader's: a caller whose ctx is
	// still valid gets the shared result (or keeps waiting) even if the leader
	// bailed out. Only this caller's own cancellation aborts this caller.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.([]net.IP), nil
	}
}

// store writes an entry under the write lock, sweeping expired entries inline
// when the map has grown large so the cache stays bounded without a background
// goroutine.
func (c *Cache) store(host string, e *Entry) {
	c.mu.Lock()
	e.network = c.network
	if len(c.entries) >= maxCacheEntries {
		now := time.Now()
		for h, ent := range c.entries {
			if now.After(ent.ExpiresAt) {
				delete(c.entries, h)
			}
		}
	}
	c.entries[host] = e
	c.mu.Unlock()
}

// isTransientDNSErr reports whether a resolution error is likely temporary
// (timeout, temporary failure, context cancellation) versus a definitive
// "this name does not resolve" (NXDOMAIN). Only transient errors justify
// serving a stale positive entry.
func isTransientDNSErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return false // definitive NXDOMAIN
		}
		// Only genuinely transient failures (timeout/temporary) justify serving
		// a stale positive entry and skipping the negative cache. A permanent
		// error (e.g. a malformed/format error that is not IsNotFound) is treated
		// as definitive so it gets negative-cached instead of re-resolved forever.
		return dnsErr.IsTimeout || dnsErr.IsTemporary
	}
	return true
}

// lookup performs the actual DNS lookup
func (c *Cache) lookup(ctx context.Context, host string) ([]net.IP, error) {
	// Check if host is already an IP
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	if c.lookupHook != nil {
		return c.lookupHook(ctx, host)
	}

	// LookupIP asks the resolver for one family; LookupIPAddr asks for both.
	// getaddrinfo turns the unrestricted form into an A query and an AAAA query,
	// so when a family has been ruled out, going through LookupIP is what keeps
	// the query for it off the wire rather than filtering the answer afterwards.
	if network := c.Network(); network != "" {
		return c.resolver.LookupIP(ctx, network, host)
	}

	addrs, err := c.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, len(addrs))
	for i, addr := range addrs {
		ips[i] = addr.IP
	}

	return ips, nil
}

// ResolveOne returns a single IP address for the hostname
// By default prefers IPv6 over IPv4 (modern browser behavior)
// If PreferIPv4 is set, prefers IPv4 instead
func (c *Cache) ResolveOne(ctx context.Context, host string) (net.IP, error) {
	ips, err := c.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses found", Name: host}
	}

	if c.PreferIPv4() {
		// Prefer IPv4
		for _, ip := range ips {
			if ip.To4() != nil {
				return ip, nil
			}
		}
	} else {
		// Prefer IPv6 (default - modern browser behavior)
		for _, ip := range ips {
			if ip.To4() == nil && ip.To16() != nil {
				return ip, nil
			}
		}
	}
	return ips[0], nil
}

// ResolveAllSorted returns all IPs sorted for Happy Eyeballs (RFC 8305)
// By default IPv6 addresses first, interleaved with IPv4
// If PreferIPv4 is set, IPv4 addresses come first
func (c *Cache) ResolveAllSorted(ctx context.Context, host string) ([]net.IP, error) {
	ips, err := c.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses found", Name: host}
	}

	// Separate IPv4 and IPv6
	var ipv4, ipv6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip)
		} else {
			ipv6 = append(ipv6, ip)
		}
	}

	// Interleave based on preference
	result := make([]net.IP, 0, len(ips))
	i, j := 0, 0

	if c.PreferIPv4() {
		// IPv4 first: IPv4, IPv6, IPv4, IPv6, ...
		for i < len(ipv4) || j < len(ipv6) {
			if i < len(ipv4) {
				result = append(result, ipv4[i])
				i++
			}
			if j < len(ipv6) {
				result = append(result, ipv6[j])
				j++
			}
		}
	} else {
		// IPv6 first (default): IPv6, IPv4, IPv6, IPv4, ... (RFC 8305 recommendation)
		for i < len(ipv6) || j < len(ipv4) {
			if i < len(ipv6) {
				result = append(result, ipv6[i])
				i++
			}
			if j < len(ipv4) {
				result = append(result, ipv4[j])
				j++
			}
		}
	}

	return result, nil
}

// ResolveIPv6First returns IPv6 addresses first, then IPv4 addresses
// This is for strict IPv6 preference - try all IPv6 before falling back to IPv4
func (c *Cache) ResolveIPv6First(ctx context.Context, host string) (ipv6 []net.IP, ipv4 []net.IP, err error) {
	ips, err := c.Resolve(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	if len(ips) == 0 {
		return nil, nil, &net.DNSError{Err: "no addresses found", Name: host}
	}

	// Separate IPv4 and IPv6
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip)
		} else {
			ipv6 = append(ipv6, ip)
		}
	}

	return ipv6, ipv4, nil
}

// Invalidate removes a hostname from the cache
func (c *Cache) Invalidate(host string) {
	c.mu.Lock()
	delete(c.entries, host)
	c.mu.Unlock()
}

// Clear removes all entries from the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	c.entries = make(map[string]*Entry)
	c.mu.Unlock()
}

// SetTTL sets the default TTL for cached entries
func (c *Cache) SetTTL(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	c.defaultTTL = ttl
}

// Stats returns cache statistics
func (c *Cache) Stats() (total int, expired int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	for _, entry := range c.entries {
		total++
		if now.After(entry.ExpiresAt) {
			expired++
		}
	}
	return
}

// Cleanup removes expired entries from the cache
func (c *Cache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for host, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, host)
		}
	}
}

// StartCleanup starts a background goroutine that periodically cleans up expired entries
func (c *Cache) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.Cleanup()
			}
		}
	}()
}

// ECHEntry represents a cached ECH config entry. A negative entry has
// ConfigList == nil and records "this host advertises no ECH" for its TTL, so we
// don't re-fire public-DNS HTTPS queries on every H3 dial to a non-ECH host.
type ECHEntry struct {
	ConfigList []byte
	ExpiresAt  time.Time
}

// echStaleGrace bounds how long an expired ECH config may still be served when
// a fresh DNS re-query fails. Past this, FetchECHConfigs returns no ECH (the
// handshake proceeds without it) rather than risk a retired-key rejection.
const echStaleGrace = 5 * time.Minute

// echMaxEntries bounds the process-global ECH cache so a long-running client
// touching many distinct hosts can't grow it without limit. Mirrors the
// A-record cache's inline expired-sweep + hard cap — no background goroutine, so
// nothing leaks if the cache is never touched again.
const echMaxEntries = 4096

// echCache stores ECH configs separately. echSF collapses concurrent HTTPS-record
// fetches for the same host into a single query (the others wait and share the
// result), so a burst of H3 dials to one cold host doesn't thunder public DNS.
var (
	echCache   = make(map[string]*ECHEntry)
	echCacheMu sync.RWMutex
	echSF      singleflight.Group
)

// echIncompatTTL bounds how long a target that stalled or rejected a TLS
// handshake with ECH applied is remembered as ECH-incompatible. After the window
// ECH is retried, so a target that later adds ECH support self-heals.
const echIncompatTTL = 10 * time.Minute

// echIncompat maps a target host to the time until which ECH should be skipped
// for it. Populated by MarkECHIncompatible after a handshake fails with an ECH
// config applied (issue #74: an ECHConfigDomain that does not front this target,
// which some servers stall on rather than cleanly reject).
var (
	echIncompat   = make(map[string]time.Time)
	echIncompatMu sync.RWMutex
)

// MarkECHIncompatible records that a target host could not complete a TLS
// handshake with an ECH config applied, so callers skip ECH for it until the TTL
// expires. Sweeps expired entries inline once the map grows large so it stays
// bounded.
func MarkECHIncompatible(host string) {
	echIncompatMu.Lock()
	if len(echIncompat) >= echMaxEntries {
		now := time.Now()
		for h, exp := range echIncompat {
			if now.After(exp) {
				delete(echIncompat, h)
			}
		}
	}
	echIncompat[host] = time.Now().Add(echIncompatTTL)
	echIncompatMu.Unlock()
}

// IsECHIncompatible reports whether ECH should currently be skipped for host
// (it recently stalled or rejected an ECH handshake).
func IsECHIncompatible(host string) bool {
	echIncompatMu.RLock()
	exp, ok := echIncompat[host]
	echIncompatMu.RUnlock()
	return ok && time.Now().Before(exp)
}

// echStore writes an ECH entry under the write lock, sweeping expired entries
// inline once the map grows large so the cache stays bounded.
func echStore(hostname string, e *ECHEntry) {
	echCacheMu.Lock()
	if len(echCache) >= echMaxEntries {
		now := time.Now()
		for h, ent := range echCache {
			if now.After(ent.ExpiresAt) {
				delete(echCache, h)
			}
		}
	}
	echCache[hostname] = e
	echCacheMu.Unlock()
}

// InvalidateECHConfig drops the cached ECH config for a host so the next
// FetchECHConfigs re-queries DNS for a fresh one. Call this when a handshake is
// rejected in a way that suggests the cached config went stale (for example the
// CDN rotated its ECH keys).
func InvalidateECHConfig(hostname string) {
	echCacheMu.Lock()
	delete(echCache, hostname)
	echCacheMu.Unlock()
}

// Default DNS servers for ECH queries
var (
	echDNSServers   = []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}
	echDNSServersMu sync.RWMutex
)

// SetECHDNSServers sets the DNS servers to use for ECH config queries.
// Pass nil or empty slice to reset to defaults.
func SetECHDNSServers(servers []string) {
	echDNSServersMu.Lock()
	defer echDNSServersMu.Unlock()
	if len(servers) == 0 {
		echDNSServers = []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}
	} else {
		echDNSServers = make([]string, len(servers))
		copy(echDNSServers, servers)
	}
}

// GetECHDNSServers returns the current DNS servers used for ECH config queries.
func GetECHDNSServers() []string {
	echDNSServersMu.RLock()
	defer echDNSServersMu.RUnlock()
	result := make([]string, len(echDNSServers))
	copy(result, echDNSServers)
	return result
}

// FetchECHConfigs fetches ECH configs from DNS HTTPS records for the given hostname.
// Returns nil if no ECH configs are available (this is not an error).
func FetchECHConfigs(ctx context.Context, hostname string) ([]byte, error) {
	// Check cache first. A fresh entry may be POSITIVE (has an ECH config) or
	// NEGATIVE (ConfigList == nil, meaning "this host has no ECH"). Both short-
	// circuit here, so a no-ECH host is not re-queried on every dial.
	echCacheMu.RLock()
	entry, exists := echCache[hostname]
	echCacheMu.RUnlock()

	if exists && time.Now().Before(entry.ExpiresAt) {
		return entry.ConfigList, nil
	}

	// Collapse concurrent dials to the same host into one DNS query — the others
	// wait and share the result — so a burst of H3 connections doesn't fire N
	// parallel HTTPS lookups (each up to ~1.5s where UDP/53 is filtered).
	v, err, _ := echSF.Do(hostname, func() (interface{}, error) {
		// Re-check under the flight: another goroutine may have populated a fresh
		// entry while we waited for the single-flight slot.
		echCacheMu.RLock()
		e, ok := echCache[hostname]
		echCacheMu.RUnlock()
		if ok && time.Now().Before(e.ExpiresAt) {
			return e.ConfigList, nil
		}

		echConfigList, ttl, qerr := queryECHFromDNS(ctx, hostname)
		if qerr != nil {
			// On DNS failure (including all-servers-SERVFAIL, now surfaced as an
			// error rather than a bogus success) serve the expired config only
			// within a short grace window. Serving an indefinitely-stale config
			// strands us on a retired key after the CDN rotates ECH, which the
			// server then rejects with illegal_parameter on every handshake until
			// the process restarts.
			if ok && time.Now().Before(e.ExpiresAt.Add(echStaleGrace)) {
				return e.ConfigList, nil
			}
			return nil, qerr
		}

		// Cache the result — INCLUDING a nil config as a negative entry, so a host
		// that advertises no ECH is remembered for its TTL instead of re-queried.
		echStore(hostname, &ECHEntry{
			ConfigList: echConfigList,
			ExpiresAt:  time.Now().Add(time.Duration(ttl) * time.Second),
		})
		return echConfigList, nil
	})
	if err != nil {
		return nil, nil // No ECH available is not an error
	}
	if v == nil {
		return nil, nil
	}
	return v.([]byte), nil
}

// queryECHFromDNS queries HTTPS records and extracts ECH config
func queryECHFromDNS(ctx context.Context, hostname string) ([]byte, uint32, error) {
	// Create DNS client with short timeout - ECH is optional, shouldn't block connections
	client := &dns.Client{
		Timeout: 500 * time.Millisecond, // Short timeout - ECH is optional
	}

	// Create HTTPS query (type 65)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeHTTPS)
	msg.RecursionDesired = true

	// Use configured DNS servers (defaults to well-known public DNS)
	dnsServers := GetECHDNSServers()

	var lastErr error
	for _, server := range dnsServers {
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			// Record the failure so an all-servers non-success (e.g. every server
			// SERVFAILs) returns an error and triggers the stale-serve fallback,
			// instead of masquerading as a successful "no ECH" result.
			lastErr = fmt.Errorf("HTTPS query for %s returned rcode %s", hostname, dns.RcodeToString[resp.Rcode])
			continue
		}

		// Parse HTTPS records for ECH config
		for _, answer := range resp.Answer {
			if https, ok := answer.(*dns.HTTPS); ok {
				for _, kv := range https.Value {
					if kv.Key() == dns.SVCB_ECHCONFIG {
						// ECH config is base64 encoded in the SVCB record
						echParam, ok := kv.(*dns.SVCBECHConfig)
						if ok && len(echParam.ECH) > 0 {
							return echParam.ECH, https.Hdr.Ttl, nil
						}
					}
				}
			}
		}

		// No ECH found in this response, but query succeeded
		return nil, 300, nil
	}

	return nil, 0, lastErr
}

// FetchECHConfigsBase64 returns ECH configs as base64 string (for debugging)
func FetchECHConfigsBase64(ctx context.Context, hostname string) (string, error) {
	configs, err := FetchECHConfigs(ctx, hostname)
	if err != nil || configs == nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(configs), nil
}
