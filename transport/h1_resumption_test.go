package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	http "github.com/sardanioss/http"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// h1TicketServer is a TLS 1.3 server that issues session tickets, which is what
// a resumption test needs and what a plain httptest server does not guarantee
// once the cipher and version are pinned.
func h1TicketServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &stdtls.Config{
		Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   stdtls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() { _ = srv.Close(); _ = ln.Close() }
}

// HTTP/1.1 never resumed a TLS session. Two things were wrong, and each alone
// is enough to break it:
//
//   - the ClientHelloID branch hardcoded preset.ClientHelloID, whose spec has
//     no pre_shared_key extension, so no ticket was ever offered. H2 has always
//     used PSKClientHelloID when the preset has one.
//   - the H1 tls.Config was missing OmitEmptyPsk, which H2 sets. Without it,
//     using the PSK hello on a first connection (no ticket yet) fails outright
//     with "tls: empty psk detected".
//
// It stayed invisible because HTTP1ConnStats carried no TLS state at all, so
// there was nothing to look at. Measured before the fix, four refreshes on a
// chrome-latest session: SessionResumed false every time, while H2 and H3 both
// resumed on the first refresh.
//
// The cost was not only the extra round trip. A client that never resumes emits
// a first-connection-shaped ClientHello on every connection forever, which is
// itself a tell, because a real browser resumes.
func TestHTTP1ResumesTLSSessions(t *testing.T) {
	addr, stop := h1TicketServer(t)
	defer stop()

	preset := fingerprint.Get("chrome-latest")
	if preset == nil {
		t.Fatal("chrome-latest preset missing")
	}
	if preset.PSKClientHelloID.Client == "" {
		t.Skip("preset carries no PSK ClientHelloID, nothing to resume with")
	}

	tr := NewHTTP1Transport(preset, dns.NewCache())
	tr.insecureSkipVerify = true
	defer tr.Close()

	host, port, _ := net.SplitHostPort(addr)
	url := "https://" + net.JoinHostPort(host, port) + "/"

	resumed := func() bool {
		req, _ := http.NewRequest("GET", url, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := tr.RoundTrip(req.WithContext(ctx))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		for _, s := range tr.Stats() {
			return s.SessionResumed
		}
		t.Fatal("no connection in stats; HTTP1ConnStats is not reporting TLS state")
		return false
	}

	if resumed() {
		t.Error("first connection reported a resumed session; there was no ticket yet")
	}
	// Refresh drops connections but keeps the ticket cache. That is the whole
	// point of Refresh, and it is what a browser F5 does.
	tr.Refresh()
	if !resumed() {
		t.Error("second connection did not resume. Either the PSK ClientHelloID is not " +
			"being selected, or OmitEmptyPsk is missing from the H1 tls.Config")
	}
}
