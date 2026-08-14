package httpcloak

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// Regression test: the local proxy decompresses a response body before writing
// it to the client, and must not forward the origin's Content-Length.
//
// That header counts the COMPRESSED bytes. Forwarding it alongside a
// decompressed body makes the client stop reading that many bytes in and treat
// the response as complete, so a 68 KB page compressed to a few hundred bytes
// arrived as its first few hundred bytes of plaintext. No short-read, no decode
// failure, no error at any layer: just quietly wrong data. Content-Encoding was
// already stripped for the same reason; Content-Length was missed.
//
// It went unnoticed because the endpoints normally used to exercise this path
// happen not to trigger it - one serves identity, the other serves chunked -
// so neither carries a compressed body alongside a Content-Length.
func TestLocalProxyDoesNotTruncateCompressedBody(t *testing.T) {
	// Body large enough that truncation is unmistakable and compresses well.
	want := bytes.Repeat([]byte("hello gzip world "), 4096) // ~68 KB

	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	if _, err := zw.Write(want); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	zw.Close()
	compressed := gzBuf.Bytes()

	if len(compressed) >= len(want)/4 {
		t.Fatalf("test body did not compress enough to be a meaningful check: %d -> %d", len(want), len(compressed))
	}

	// Origin serving gzip WITH an explicit Content-Length: the exact shape that
	// triggers the bug.
	origin := newTLSOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(compressed)))
		w.WriteHeader(http.StatusOK)
		w.Write(compressed)
	})

	proxy, err := StartLocalProxy(0, WithProxyPreset("chrome-latest"), WithProxyTimeout(30*time.Second))
	if err != nil {
		t.Skipf("could not start local proxy: %v", err)
	}
	defer proxy.Stop()

	// The origin uses a self-signed certificate, so route through a registered
	// session that accepts it.
	sess := NewSession("chrome-latest", WithInsecureSkipVerify(), WithSessionTimeout(30*time.Second))
	defer sess.Close()
	if err := proxy.RegisterSession("gziptest", sess); err != nil {
		t.Skipf("could not register session: %v", err)
	}

	// Route through the proxy the way the documented pattern does: plain http://
	// URL plus the scheme header, so the proxy performs the TLS itself.
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxy.Port()))
	hc := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableCompression: true},
		Timeout:   30 * time.Second,
	}

	req, _ := http.NewRequest("GET", "http://"+origin+"/gz", nil)
	req.Header.Set(HeaderScheme, "https")
	req.Header.Set(HeaderSession, "gziptest")

	resp, err := hc.Do(req)
	if err != nil {
		t.Skipf("request through proxy failed (environment): %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if len(got) == len(compressed) {
		t.Fatalf("body truncated to the COMPRESSED length: got %d bytes, want %d. "+
			"The proxy forwarded the origin's Content-Length (%d) alongside a decompressed body.",
			len(got), len(want), len(compressed))
	}
	if len(got) != len(want) {
		t.Fatalf("body length = %d, want %d (Content-Length header was %q)",
			len(got), len(want), resp.Header.Get("Content-Length"))
	}
	if !bytes.Equal(got, want) {
		t.Fatal("body content differs from what the origin sent")
	}
}

// newTLSOrigin starts an HTTPS server with a self-signed cert and returns its
// host:port.
func newTLSOrigin(t *testing.T, h http.HandlerFunc) string {
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

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:   h,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })

	return ln.Addr().String()
}
