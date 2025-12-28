package dns

import (
	"context"
	"net"
	"sync"
	"time"
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
}

// NewCache creates a new DNS cache
func NewCache() *Cache {
	return &Cache{
		entries:    make(map[string]*Entry),
		resolver:   net.DefaultResolver,
		defaultTTL: 5 * time.Minute,  // Default TTL if not specified
		minTTL:     30 * time.Second, // Minimum TTL to prevent hammering
	}
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
// Prefers IPv6 over IPv4 (modern browser behavior)
func (c *Cache) ResolveOne(ctx context.Context, host string) (net.IP, error) {
	ips, err := c.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses found", Name: host}
	}
	// Return first IP (prefer IPv6 if available - modern browser behavior)
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() != nil {
			return ip, nil
		}
	}
	return ips[0], nil
}

// ResolveAllSorted returns all IPs sorted for Happy Eyeballs (RFC 8305)
// IPv6 addresses first, interleaved with IPv4
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

	// Interleave: IPv6, IPv4, IPv6, IPv4, ... (RFC 8305 recommendation)
	result := make([]net.IP, 0, len(ips))
	i, j := 0, 0
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
