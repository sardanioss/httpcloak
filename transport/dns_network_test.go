package transport

import "testing"

// A bound source address must reach the DNS cache, because that is the whole
// mechanism: the transports already discard the other family after resolving
// it, and this is what stops it being resolved. Without the wiring the change
// is invisible, so assert on the cache the transport actually uses.
func TestTransportRestrictsLookupsToTheBoundFamily(t *testing.T) {
	cases := []struct {
		name      string
		localAddr string
		want      string
	}{
		{"no local address queries both families", "", ""},
		{"ipv6 source", "2001:db8::1", "ip6"},
		{"ipv4 source", "192.0.2.1", "ip4"},
		{"unparseable source is left alone", "not-an-ip", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := NewTransportWithConfig("chrome-latest", nil, &TransportConfig{LocalAddr: c.localAddr})
			cache := tr.GetDNSCache()
			if cache == nil {
				t.Fatal("transport has no DNS cache")
			}
			if got := cache.Network(); got != c.want {
				t.Errorf("LocalAddr %q gave cache network %q, want %q", c.localAddr, got, c.want)
			}
		})
	}
}

// A transport built without a config must behave as it did before, querying
// both families.
func TestTransportWithoutConfigQueriesBothFamilies(t *testing.T) {
	tr := NewTransport("chrome-latest")
	if got := tr.GetDNSCache().Network(); got != "" {
		t.Errorf("cache network = %q, want \"\"", got)
	}
}

// The transports expose SetLocalAddr, so a source address can be changed after
// construction. The three of them share one DNS cache but keep their own
// localAddr, and only the constructor ever sees an address that all three
// agree on. So a rebind must never leave the cache restricted to a family a
// sibling is not bound to: it either stays inside the family it already has,
// or the restriction is lifted and both families are resolved again, which is
// what this library did before the restriction existed.
func TestSetLocalAddrNeverLeavesTheCacheAheadOfASibling(t *testing.T) {
	cases := []struct {
		name  string
		built string
		then  string
		want  string
	}{
		{"rebind inside the same family keeps the restriction", "2001:db8::1", "2001:db8::2", "ip6"},
		{"rebind inside the same family keeps it for v4 too", "192.0.2.1", "192.0.2.2", "ip4"},
		{"crossing families lifts it", "2001:db8::1", "192.0.2.1", ""},
		{"crossing the other way lifts it", "192.0.2.1", "2001:db8::1", ""},
		{"clearing the address lifts it", "2001:db8::1", "", ""},
		{"an unparseable address lifts it", "2001:db8::1", "not-an-ip", ""},
		{"binding on an unrestricted transport stays unrestricted", "", "2001:db8::1", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := NewTransportWithConfig("chrome-latest", nil, &TransportConfig{LocalAddr: c.built})
			tr.GetHTTP2Transport().SetLocalAddr(c.then)
			if got := tr.GetDNSCache().Network(); got != c.want {
				t.Errorf("built with %q then rebound to %q: cache network = %q, want %q", c.built, c.then, got, c.want)
			}
		})
	}
}

// Every protocol transport shares the one cache, so the guarantee above has to
// hold whichever of them is rebound.
//
// Each case reaches for its own transport and skips only if that one is
// absent. HTTP/3 construction can fail on a host with no usable UDP socket,
// and a single shared guard would then have skipped HTTP/1.1 and HTTP/2 too,
// quietly reporting a pass for cases that never ran.
func TestSetLocalAddrGuardAppliesToEveryProtocol(t *testing.T) {
	for _, name := range []string{"http1", "http2", "http3"} {
		t.Run(name, func(t *testing.T) {
			tr := NewTransportWithConfig("chrome-latest", nil, &TransportConfig{LocalAddr: "2001:db8::1"})
			if got := tr.GetDNSCache().Network(); got != "ip6" {
				t.Fatalf("cache network before the rebind = %q, want \"ip6\"", got)
			}

			switch name {
			case "http1":
				h := tr.GetHTTP1Transport()
				if h == nil {
					t.Skip("no HTTP/1.1 transport on this build")
				}
				h.SetLocalAddr("192.0.2.1")
			case "http2":
				h := tr.GetHTTP2Transport()
				if h == nil {
					t.Skip("no HTTP/2 transport on this build")
				}
				h.SetLocalAddr("192.0.2.1")
			case "http3":
				h := tr.GetHTTP3Transport()
				if h == nil {
					t.Skip("no HTTP/3 transport on this build")
				}
				h.SetLocalAddr("192.0.2.1")
			}

			if got := tr.GetDNSCache().Network(); got != "" {
				t.Errorf("%s rebound across families left cache network %q, want \"\"", name, got)
			}
		})
	}
}
