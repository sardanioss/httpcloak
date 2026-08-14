package httpcloak

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// Regression lock for the root API's RootCAs threading.
//
// WithTLSConfig accepted a restricted trust store and NewSession never copied it
// into the session config, so it was stored and never read. An EMPTY pool -
// trusting nothing at all - still returned 200 on HTTP/1.1 and HTTP/2 and a real
// response over HTTP/3. That fails OPEN: a caller who narrows trust to their own
// CA keeps the entire system trust store while believing they are pinned.
//
// This lock exists because that is the second time the same value was lost. The
// first fix did not apply at all - a text edit whose anchor no longer matched
// after a reformat, failing silently - and nothing caught it, because deleting
// the line breaks no other test in the repository.
//
// Note the root package is covered by a blanket /*_test.go ignore, so this file
// needs an explicit exception in .gitignore to exist in the tree at all. If you
// are moving it, move the exception with it.
//
// The assertion is three-way on purpose. "Empty pool fails" alone would also
// pass if the pool were merely merged into the system store, so a pool that
// DOES contain the server's CA must succeed, and the system store must fail.
// Together those three prove the supplied pool replaced the default.
func TestRootAPIRootCAsIsHonoured(t *testing.T) {
	addr, caPool := startLocalCATLSServer(t)
	url := "https://" + addr + "/"

	protocols := []struct {
		name string
		opt  SessionOption
	}{
		{"h1", WithForceHTTP1()},
		{"h2", WithForceHTTP2()},
	}

	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			t.Run("pool with the CA succeeds", func(t *testing.T) {
				if err := get(t, url, proto.opt, WithTLSConfig(&tls.Config{RootCAs: caPool})); err != nil {
					t.Fatalf("a pool containing the server's CA should verify, got: %v", err)
				}
			})
			t.Run("empty pool fails", func(t *testing.T) {
				if err := get(t, url, proto.opt, WithTLSConfig(&tls.Config{RootCAs: x509.NewCertPool()})); err == nil {
					t.Error("FAIL-OPEN: an empty trust store accepted the certificate, so RootCAs was ignored")
				}
			})
			t.Run("system roots fail", func(t *testing.T) {
				if err := get(t, url, proto.opt); err == nil {
					t.Error("the system trust store should not accept this private CA")
				}
			})
		})
	}
}

func get(t *testing.T, url string, opts ...SessionOption) error {
	t.Helper()
	s := NewSession("chrome-latest", append(opts, WithSessionTimeout(10*time.Second))...)
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := s.Get(ctx, url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// startLocalCATLSServer serves HTTPS from a private CA and returns its address
// plus a pool containing that CA.
func startLocalCATLSServer(t *testing.T) (string, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "httpcloak-rootcas-lock"},
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
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })

	return ln.Addr().String(), pool
}
