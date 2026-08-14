package transport

import (
	stdtls "crypto/tls"
	"crypto/x509"
	"testing"
)

// Regression lock: certificate verification hooks must reach the HTTP/3
// transport's cached TLS config.
//
// HTTP/1.1 and HTTP/2 build a fresh utls.Config for every connection, so they
// pick up whatever SetTLSVerify recorded by the time they dial. HTTP/3 does not:
// it builds t.tlsConfig ONCE, in the constructor, which runs before any setter
// can be called. So recording the field without re-applying it to that cached
// config left QUIC with no hooks at all.
//
// That failure is silent and fails OPEN. A verification callback that is never
// consulted can never reject, so a caller pinning a certificate believes they
// are pinned while the QUIC path accepts anything the system roots accept - and
// on a client that prefers HTTP/3, that is the connection the request uses.
//
// Verified end to end against a live HTTP/3 endpoint at the time of the fix:
// before, the callbacks fired 0 times and a rejecting callback still produced a
// successful response; after, both fire and the rejection aborts the handshake.
func TestH3VerifyHooksReachCachedTLSConfig(t *testing.T) {
	preset := testPreset(t)

	tr, err := NewHTTP3Transport(preset, nil)
	if err != nil {
		t.Skipf("HTTP/3 transport unavailable: %v", err)
	}
	defer tr.Close()

	if tr.tlsConfig == nil {
		t.Fatal("expected the HTTP/3 transport to build its TLS config in the constructor")
	}
	if tr.tlsConfig.VerifyPeerCertificate != nil || tr.tlsConfig.VerifyConnection != nil {
		t.Fatal("no hooks installed yet, so the cached config should carry none")
	}

	tr.SetTLSVerify(&TLSVerify{
		VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error { return nil },
		VerifyConnection:      func(_ stdtls.ConnectionState) error { return nil },
	})

	if tr.tlsConfig.VerifyPeerCertificate == nil {
		t.Error("SetTLSVerify did not reach the cached TLS config: VerifyPeerCertificate is nil, " +
			"so certificate verification would silently never run on QUIC")
	}
	if tr.tlsConfig.VerifyConnection == nil {
		t.Error("SetTLSVerify did not reach the cached TLS config: VerifyConnection is nil")
	}
}

// RootCAs must reach it too. Dropping a caller's restricted trust store also
// fails open: they narrow trust to their own CA and silently get the full
// system store back.
func TestH3RootCAsReachCachedTLSConfig(t *testing.T) {
	preset := testPreset(t)

	tr, err := NewHTTP3Transport(preset, nil)
	if err != nil {
		t.Skipf("HTTP/3 transport unavailable: %v", err)
	}
	defer tr.Close()

	pool := x509.NewCertPool()
	tr.SetTLSVerify(&TLSVerify{RootCAs: pool})

	if tr.tlsConfig.RootCAs == nil {
		t.Error("a restricted RootCAs pool did not reach the HTTP/3 TLS config, so the caller " +
			"would keep verifying against the full system trust store")
	}
}
