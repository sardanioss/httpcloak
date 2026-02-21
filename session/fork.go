package session

import (
	"time"

	"github.com/sardanioss/httpcloak/transport"
)

// Fork creates n new sessions that share cookies and TLS session caches with
// the parent, but have independent connections. This simulates multiple browser
// tabs from the same browser instance — same cookies, same TLS resumption
// tickets, same fingerprint, but independent TCP/QUIC connections for parallel
// requests.
func (s *Session) Fork(n int) []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.active || n <= 0 {
		return nil
	}

	forks := make([]*Session, n)
	for i := range forks {
		forks[i] = s.forkOne()
	}
	return forks
}

// forkOne creates a single forked session. Must be called with s.mu held (at least RLock).
func (s *Session) forkOne() *Session {
	// Deep-copy config (struct copy — SetProxy mutates it)
	cfgCopy := *s.Config

	// Determine preset
	presetName := "chrome-latest"
	if cfgCopy.Preset != "" {
		presetName = cfgCopy.Preset
	}

	// Build proxy config (same logic as NewSessionWithOptions)
	var proxy *transport.ProxyConfig
	if cfgCopy.Proxy != "" || cfgCopy.TCPProxy != "" || cfgCopy.UDPProxy != "" {
		proxy = &transport.ProxyConfig{
			URL:      cfgCopy.Proxy,
			TCPProxy: cfgCopy.TCPProxy,
			UDPProxy: cfgCopy.UDPProxy,
		}
	}

	// Build transport config (same logic as NewSessionWithOptions, but no keyLogWriter)
	var transportConfig *transport.TransportConfig
	needsConfig := len(cfgCopy.ConnectTo) > 0 || cfgCopy.ECHConfigDomain != "" ||
		cfgCopy.TLSOnly || cfgCopy.QuicIdleTimeout > 0 || cfgCopy.LocalAddress != "" ||
		cfgCopy.EnableSpeculativeTLS
	if needsConfig {
		transportConfig = &transport.TransportConfig{
			ConnectTo:             cfgCopy.ConnectTo,
			ECHConfigDomain:       cfgCopy.ECHConfigDomain,
			TLSOnly:              cfgCopy.TLSOnly,
			QuicIdleTimeout:      time.Duration(cfgCopy.QuicIdleTimeout) * time.Second,
			LocalAddr:            cfgCopy.LocalAddress,
			EnableSpeculativeTLS: cfgCopy.EnableSpeculativeTLS,
		}
	}

	// Create new transport
	t := transport.NewTransportWithConfig(presetName, proxy, transportConfig)

	// Apply protocol settings
	if cfgCopy.InsecureSkipVerify {
		t.SetInsecureSkipVerify(true)
	}
	if cfgCopy.ForceHTTP1 {
		t.SetProtocol(transport.ProtocolHTTP1)
	} else if cfgCopy.ForceHTTP2 {
		t.SetProtocol(transport.ProtocolHTTP2)
	} else if cfgCopy.ForceHTTP3 {
		t.SetProtocol(transport.ProtocolHTTP3)
	} else if cfgCopy.DisableHTTP3 {
		t.SetProtocol(transport.ProtocolHTTP2)
	}

	if cfgCopy.PreferIPv4 {
		if dnsCache := t.GetDNSCache(); dnsCache != nil {
			dnsCache.SetPreferIPv4(true)
		}
	}

	if cfgCopy.DisableECH {
		t.SetDisableECH(true)
	}

	// Share TLS session caches (shared pointers for 0-RTT resumption)
	if parentH1 := s.transport.GetHTTP1Transport(); parentH1 != nil {
		if forkH1 := t.GetHTTP1Transport(); forkH1 != nil {
			forkH1.SetSessionCache(parentH1.GetSessionCache())
		}
	}
	if parentH2 := s.transport.GetHTTP2Transport(); parentH2 != nil {
		if forkH2 := t.GetHTTP2Transport(); forkH2 != nil {
			forkH2.SetSessionCache(parentH2.GetSessionCache())
		}
	}
	if parentH3 := s.transport.GetHTTP3Transport(); parentH3 != nil {
		if forkH3 := t.GetHTTP3Transport(); forkH3 != nil {
			forkH3.SetSessionCache(parentH3.GetSessionCache())
		}
	}

	// Snapshot-copy cacheEntries
	cacheEntries := make(map[string]*cacheEntry, len(s.cacheEntries))
	for k, v := range s.cacheEntries {
		entryCopy := *v
		cacheEntries[k] = &entryCopy
	}

	// Snapshot-copy clientHints
	clientHints := make(map[string]map[string]bool, len(s.clientHints))
	for host, hints := range s.clientHints {
		hintsCopy := make(map[string]bool, len(hints))
		for k, v := range hints {
			hintsCopy[k] = v
		}
		clientHints[host] = hintsCopy
	}

	// Parse switch protocol
	switchProto := transport.ProtocolAuto
	if cfgCopy.SwitchProtocol != "" {
		p, err := parseProtocol(cfgCopy.SwitchProtocol)
		if err == nil {
			switchProto = p
		}
	}

	return &Session{
		ID:             generateID(),
		CreatedAt:      time.Now(),
		LastUsed:       time.Now(),
		RequestCount:   0,
		Config:         &cfgCopy,
		transport:      t,
		cookies:        s.cookies, // shared pointer — thread-safe CookieJar
		cacheEntries:   cacheEntries,
		clientHints:    clientHints,
		keyLogWriter:   nil, // no key log on fork to avoid double-close
		switchProtocol: switchProto,
		active:         true,
	}
}
