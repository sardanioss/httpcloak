package dns

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestNetworkForLocalAddr(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string
	}{
		{"unset", "", ""},
		{"not an ip", "eth0", ""},
		{"host and port is not an ip", "192.0.2.1:0", ""},
		{"ipv4", "192.0.2.1", "ip4"},
		{"ipv4 unspecified", "0.0.0.0", "ip4"},
		{"ipv4 mapped to v6 is still v4", "::ffff:192.0.2.1", "ip4"},
		{"ipv6", "2001:db8::1", "ip6"},
		{"ipv6 unspecified", "::", "ip6"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NetworkForLocalAddr(c.addr); got != c.want {
				t.Errorf("NetworkForLocalAddr(%q) = %q, want %q", c.addr, got, c.want)
			}
		})
	}
}

// A value outside the three the resolver accepts must be ignored rather than
// stored: net.Resolver.LookupIP errors on an unknown network, so storing one
// would turn every lookup on this cache into a failure.
func TestSetNetworkRejectsUnknownValues(t *testing.T) {
	c := NewCache()
	c.SetNetwork("ip6")

	for _, bad := range []string{"ipv6", "tcp6", "udp", "6"} {
		c.SetNetwork(bad)
		if got := c.Network(); got != "ip6" {
			t.Fatalf("SetNetwork(%q) changed the network to %q, want it left at \"ip6\"", bad, got)
		}
	}

	c.SetNetwork("")
	if got := c.Network(); got != "" {
		t.Errorf(`SetNetwork("") = %q, want ""`, got)
	}
}

// An IP literal never reaches the resolver, so restricting the family must not
// start rejecting one. The transports hand hostnames and literals to the same
// cache, and a literal of the bound family is exactly what a caller pinning a
// connection target passes.
func TestNetworkDoesNotAffectIPLiterals(t *testing.T) {
	c := NewCache()
	c.SetNetwork("ip6")

	ips, err := c.Resolve(context.Background(), "2001:db8::1")
	if err != nil {
		t.Fatalf("Resolve of an IPv6 literal: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("Resolve returned %v, want [2001:db8::1]", ips)
	}
}

// A cache that was never told a family must query both, which is what every
// caller that does not bind a source address relies on.
func TestNewCacheQueriesBothFamilies(t *testing.T) {
	if got := NewCache().Network(); got != "" {
		t.Errorf("a new cache reported network %q, want \"\"", got)
	}
}

// The three values SetNetwork accepts are the three net.Resolver.LookupIP
// accepts. If that ever stops being true, a restricted cache fails every
// lookup with "unknown network", so pin it here rather than discovering it
// against a live resolver.
func TestAcceptedNetworksAreResolverNetworks(t *testing.T) {
	for _, network := range []string{"ip4", "ip6"} {
		// A literal short-circuits before any I/O, so this reaches LookupIP's
		// network validation without needing a resolver or a name to look up.
		_, err := (&net.Resolver{}).LookupIP(context.Background(), network, "not a host")
		var unknown net.UnknownNetworkError
		if errors.As(err, &unknown) {
			t.Errorf("SetNetwork accepts %q but net.Resolver.LookupIP rejects it: %v", network, err)
		}
	}
}

// Entries hold what the previous family resolved to, so changing the family
// has to stop them being served. This asserts on what Resolve hands back rather than on the
// entry count: the failure this guards against is a caller that has rebound to
// IPv4 being given the AAAA set the cache resolved while it was on IPv6, which
// it filters down to nothing and reports as a host with no usable address, for
// as long as the TTL has left to run.
func TestSetNetworkDoesNotServeEntriesFromTheOldFamily(t *testing.T) {
	const host = "family-switch.example"
	v6 := net.ParseIP("2001:db8::1")
	v4 := net.ParseIP("192.0.2.1")

	c := NewCache()
	c.SetNetwork("ip6")
	c.lookupHook = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{v6}, nil
	}

	got, err := c.Resolve(context.Background(), host)
	if err != nil {
		t.Fatalf("Resolve under ip6: %v", err)
	}
	if len(got) != 1 || !got[0].Equal(v6) {
		t.Fatalf("Resolve under ip6 = %v, want [%v]", got, v6)
	}

	// Rebind to IPv4. The entry above is still well inside its TTL.
	c.SetNetwork("ip4")
	c.lookupHook = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{v4}, nil
	}

	got, err = c.Resolve(context.Background(), host)
	if err != nil {
		t.Fatalf("Resolve after rebinding to ip4: %v", err)
	}
	if len(got) != 1 || !got[0].Equal(v4) {
		t.Fatalf("Resolve after rebinding to ip4 = %v, want [%v]; the entry resolved under the previous family was served instead", got, v4)
	}
}

// An entry stays usable when the family is set back to the one it was resolved
// under, and stays hidden while the cache is on the other. Tagging rather than
// flushing is what makes that true, and is also what makes a lookup that was
// already in flight when the family changed unable to land as a usable entry.
func TestEntriesAreScopedToTheFamilyTheyWereResolvedUnder(t *testing.T) {
	const host = "family-scope.example"
	v6 := net.ParseIP("2001:db8::1")

	c := NewCache()
	c.SetNetwork("ip6")

	var lookups int
	c.lookupHook = func(context.Context, string) ([]net.IP, error) {
		lookups++
		return []net.IP{v6}, nil
	}

	if _, err := c.Resolve(context.Background(), host); err != nil {
		t.Fatalf("Resolve under ip6: %v", err)
	}
	if lookups != 1 {
		t.Fatalf("first Resolve did %d lookups, want 1", lookups)
	}

	// Cached: no second lookup while the family is unchanged.
	if _, err := c.Resolve(context.Background(), host); err != nil {
		t.Fatalf("second Resolve under ip6: %v", err)
	}
	if lookups != 1 {
		t.Fatalf("a cached hit did %d lookups, want 1", lookups)
	}

	// On another family the entry must not be served, so this has to re-look-up.
	c.SetNetwork("ip4")
	c.lookupHook = func(context.Context, string) ([]net.IP, error) {
		lookups++
		return []net.IP{net.ParseIP("192.0.2.1")}, nil
	}
	if _, err := c.Resolve(context.Background(), host); err != nil {
		t.Fatalf("Resolve under ip4: %v", err)
	}
	if lookups != 2 {
		t.Fatalf("after the family changed, lookups = %d, want 2", lookups)
	}

	// Entries are keyed by host alone, so the ip4 lookup replaced the ip6 one
	// rather than sitting beside it. Going back therefore re-resolves as well,
	// and must not hand back what was resolved while the cache was on ip4.
	c.SetNetwork("ip6")
	c.lookupHook = func(context.Context, string) ([]net.IP, error) {
		lookups++
		return []net.IP{v6}, nil
	}
	got, err := c.Resolve(context.Background(), host)
	if err != nil {
		t.Fatalf("Resolve back on ip6: %v", err)
	}
	if lookups != 3 {
		t.Errorf("returning to the original family did %d lookups in total, want 3", lookups)
	}
	if len(got) != 1 || !got[0].Equal(v6) {
		t.Errorf("Resolve back on ip6 = %v, want [%v]", got, v6)
	}
}

// A transient resolver failure falls back to a stale entry. That fallback has
// to respect the family too, or a hiccup hands back addresses the caller
// cannot dial.
func TestTransientFailureDoesNotServeAnotherFamilysStaleEntry(t *testing.T) {
	const host = "family-transient.example"
	c := NewCache()
	c.SetNetwork("ip6")
	c.lookupHook = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2001:db8::1")}, nil
	}
	if _, err := c.Resolve(context.Background(), host); err != nil {
		t.Fatalf("seeding the ip6 entry: %v", err)
	}

	// Rebind, then make the ip4 lookup fail transiently.
	c.SetNetwork("ip4")
	timeout := &net.DNSError{Err: "timeout", Name: host, IsTimeout: true, IsTemporary: true}
	c.lookupHook = func(context.Context, string) ([]net.IP, error) {
		return nil, timeout
	}

	got, err := c.Resolve(context.Background(), host)
	if err == nil {
		t.Fatalf("Resolve returned %v and no error; the ip6 entry was served as a stale fallback under ip4", got)
	}
}
