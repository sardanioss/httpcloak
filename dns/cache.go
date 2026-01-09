package dns

import (
	"context"
	"encoding/base64"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Entry represents a cached DNS entry
type Entry struct {
	IPs       []net.IP
	ExpiresAt time.Time
	LookupAt  time.Time
}

// IsExpired checks if the entry has expired
func (e *Entry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// Cache provides TTL-aware DNS caching
type Cache struct {
	entries    map[string]*Entry
	mu         sync.RWMutex
	resolver   *net.Resolver
	defaultTTL time.Duration
	minTTL     time.Duration
	preferIPv4 bool // If true, prefer IPv4 over IPv6
}

// NewCache creates a new DNS cache
func NewCache() *Cache {
	// Use CGO resolver (PreferGo: false) for compatibility with shared library usage.
	// The pure-Go resolver doesn't work when Go runtime is loaded as a plugin/shared library
	// because the netpoller isn't properly initialized in that context.
	resolver := &net.Resolver{
		PreferGo: false, // Force CGO resolver for shared library compatibility
	}
	return &Cache{
		entries:    make(map[string]*Entry),
		resolver:   resolver,
		defaultTTL: 5 * time.Minute,  // Default TTL if not specified
		minTTL:     30 * time.Second, // Minimum TTL to prevent hammering
		preferIPv4: false,
	}
}

// SetPreferIPv4 sets whether to prefer IPv4 addresses over IPv6
func (c *Cache) SetPreferIPv4(prefer bool) {
	c.preferIPv4 = prefer
}

// PreferIPv4 returns whether IPv4 is preferred over IPv6
func (c *Cache) PreferIPv4() bool {
	return c.preferIPv4
}

// Resolve looks up the IP addresses for a hostname
// Returns cached result if available and not expired
func (c *Cache) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	// Check cache first
	c.mu.RLock()
	entry, exists := c.entries[host]
	c.mu.RUnlock()

	if exists && !entry.IsExpired() {
		return entry.IPs, nil
	}

	// Cache miss or expired - do actual lookup
	ips, err := c.lookup(ctx, host)
	if err != nil {
		// If lookup fails but we have stale cache, use it
		if exists {
			return entry.IPs, nil
		}
		return nil, err
	}

	// Cache the result
	c.mu.Lock()
	c.entries[host] = &Entry{
		IPs:       ips,
		ExpiresAt: time.Now().Add(c.defaultTTL),
		LookupAt:  time.Now(),
	}
	c.mu.Unlock()

	return ips, nil
}

// lookup performs the actual DNS lookup
func (c *Cache) lookup(ctx context.Context, host string) ([]net.IP, error) {
	// Check if host is already an IP
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
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

	if c.preferIPv4 {
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

	if c.preferIPv4 {
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

// ECHEntry represents a cached ECH config entry
type ECHEntry struct {
	ConfigList []byte
	ExpiresAt  time.Time
}

// echCache stores ECH configs separately
var (
	echCache   = make(map[string]*ECHEntry)
	echCacheMu sync.RWMutex
)

// FetchECHConfigs fetches ECH configs from DNS HTTPS records for the given hostname.
// Returns nil if no ECH configs are available (this is not an error).
func FetchECHConfigs(ctx context.Context, hostname string) ([]byte, error) {
	// Check cache first
	echCacheMu.RLock()
	entry, exists := echCache[hostname]
	echCacheMu.RUnlock()

	if exists && time.Now().Before(entry.ExpiresAt) {
		return entry.ConfigList, nil
	}

	// Query DNS for HTTPS records
	echConfigList, ttl, err := queryECHFromDNS(ctx, hostname)
	if err != nil {
		// Return cached value if available, even if expired
		if exists {
			return entry.ConfigList, nil
		}
		return nil, nil // No ECH available is not an error
	}

	// Cache the result
	if echConfigList != nil {
		echCacheMu.Lock()
		echCache[hostname] = &ECHEntry{
			ConfigList: echConfigList,
			ExpiresAt:  time.Now().Add(time.Duration(ttl) * time.Second),
		}
		echCacheMu.Unlock()
	}

	return echConfigList, nil
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

	// Use system resolver or fallback to well-known DNS
	dnsServers := []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}

	var lastErr error
	for _, server := range dnsServers {
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
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
