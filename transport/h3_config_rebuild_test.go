package transport

import "testing"

// SetProxy and SetPreset rebuild all three transports. HTTP/1.1 and HTTP/2
// were rebuilt with the session's TransportConfig, HTTP/3 without it, so after
// either call HTTP/3 quietly lost the custom JA3, the ECH config domain,
// DisableECH, the local address, the QUIC idle timeout and the session cache
// backend.
func TestHTTP3KeepsItsConfigWhenRebuilt(t *testing.T) {
	cfg := &TransportConfig{ECHConfigDomain: "cloudflare-ech.com"}
	tr := NewTransportWithConfig("chrome-146", nil, cfg)
	t.Cleanup(tr.Close)

	check := func(after string) {
		t.Helper()
		tr.fieldsMu.RLock()
		h3 := tr.h3Transport
		tr.fieldsMu.RUnlock()
		if h3 == nil {
			t.Fatalf("after %s: no HTTP/3 transport", after)
		}
		if h3.config != cfg {
			t.Errorf("after %s: the HTTP/3 transport lost the session's config", after)
		}
	}

	check("construction")
	tr.SetProxy(&ProxyConfig{URL: "http://127.0.0.1:1"}) // HTTP/3 cannot use it
	check("SetProxy(http)")
	if tr.h3ProxyError == nil {
		t.Error("an HTTP proxy left HTTP/3 without its refusal")
	}
	tr.SetProxy(&ProxyConfig{URL: "masque://127.0.0.1:1"})
	check("SetProxy(masque)")
	tr.SetProxy(nil)
	check("SetProxy(nil)")
	if tr.h3ProxyError != nil {
		t.Errorf("a direct connection kept the proxy error %v", tr.h3ProxyError)
	}
	tr.SetPreset("chrome-146-windows")
	check("SetPreset")
}
