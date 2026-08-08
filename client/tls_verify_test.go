package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// Regression tests for issue #85.
//
// WithTLSConfig existed and stored the config, but nothing ever read it, so
// VerifyPeerCertificate and VerifyConnection silently never fired. Code using
// them compiled and appeared to work while performing no verification at all,
// which is the worst possible failure mode for a security hook.

func startTLSServer(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok"))
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	return "https://" + ln.Addr().String() + "/"
}

// The callbacks supplied through WithTLSConfig must actually be invoked. This
// is the exact scenario from the issue.
func TestWithTLSConfigVerifyCallbacksFire(t *testing.T) {
	url := startTLSServer(t)

	var peerCalls, connCalls atomic.Int32

	c := NewClient("chrome-latest",
		WithTimeout(15*time.Second),
		WithTLSConfig(&tls.Config{
			// Self-signed server, so skip the default chain check and do our own.
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("no certificates presented")
				}
				peerCalls.Add(1)
				return nil
			},
			VerifyConnection: func(cs tls.ConnectionState) error {
				if cs.Version == 0 {
					return errors.New("connection state not populated")
				}
				connCalls.Add(1)
				return nil
			},
		}),
	)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := c.Get(ctx, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Close()

	if peerCalls.Load() == 0 {
		t.Error("VerifyPeerCertificate was never called (issue #85: the config was stored but never read)")
	}
	if connCalls.Load() == 0 {
		t.Error("VerifyConnection was never called (issue #85: the config was stored but never read)")
	}
}

// Returning an error from VerifyPeerCertificate must abort the handshake. If
// the hook is wired up but its error is ignored, pinning would silently pass
// everything, so this is the assertion that actually matters for security.
func TestVerifyPeerCertificateRejectionAbortsHandshake(t *testing.T) {
	url := startTLSServer(t)

	wantErr := errors.New("pinned certificate mismatch")

	c := NewClient("chrome-latest",
		WithTimeout(15*time.Second),
		WithInsecureSkipVerify(),
		WithVerifyPeerCertificate(func(_ [][]byte, _ [][]*x509.Certificate) error {
			return wantErr
		}),
	)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := c.Get(ctx, url, nil)
	if err == nil {
		if resp != nil {
			resp.Close()
		}
		t.Fatal("request succeeded even though VerifyPeerCertificate rejected the certificate")
	}
}

// The connection state handed to VerifyConnection is translated out of uTLS,
// so check the fields a caller would realistically read are populated.
func TestVerifyConnectionStateIsPopulated(t *testing.T) {
	url := startTLSServer(t)

	var gotVersion atomic.Uint32
	var gotCerts atomic.Int32
	var gotALPN atomic.Value

	c := NewClient("chrome-latest",
		WithTimeout(15*time.Second),
		WithInsecureSkipVerify(),
		WithVerifyConnection(func(cs tls.ConnectionState) error {
			gotVersion.Store(uint32(cs.Version))
			gotCerts.Store(int32(len(cs.PeerCertificates)))
			gotALPN.Store(cs.NegotiatedProtocol)
			return nil
		}),
	)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := c.Get(ctx, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Close()

	if v := gotVersion.Load(); v != uint32(tls.VersionTLS13) && v != uint32(tls.VersionTLS12) {
		t.Errorf("ConnectionState.Version = 0x%04x, want a TLS 1.2/1.3 version", v)
	}
	if n := gotCerts.Load(); n == 0 {
		t.Error("ConnectionState.PeerCertificates was empty")
	}
	if p, _ := gotALPN.Load().(string); p == "" {
		t.Error("ConnectionState.NegotiatedProtocol was empty, expected an ALPN result")
	}
}

// A nil config must not panic or clobber existing settings.
func TestWithTLSConfigNilIsIgnored(t *testing.T) {
	cfg := DefaultConfig()
	WithTLSConfig(nil)(cfg)
	if cfg.TLSConfig != nil || cfg.VerifyPeerCertificate != nil || cfg.VerifyConnection != nil {
		t.Error("WithTLSConfig(nil) should be a no-op")
	}
}

// Fields that shape the ClientHello must be ignored: honouring them would
// silently break the browser fingerprint the library exists to reproduce.
func TestWithTLSConfigIgnoresFingerprintFields(t *testing.T) {
	cfg := DefaultConfig()
	WithTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		NextProtos:   []string{"http/1.1"},
		ServerName:   "not-the-real-host",
	})(cfg)

	// Stored for reference, but nothing downstream reads these fields.
	if cfg.VerifyPeerCertificate != nil || cfg.VerifyConnection != nil {
		t.Error("no verification hooks were supplied, none should have been set")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should stay false when the supplied config does not set it")
	}
}
