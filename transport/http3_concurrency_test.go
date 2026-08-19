package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/quic-go/http3"
	utls "github.com/sardanioss/utls"
)

func h3RaceTestTLS(t *testing.T) *utls.Config {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyB, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyB})
	cert, err := utls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &utls.Config{Certificates: []utls.Certificate{cert}, NextProtos: []string{"h3"}}
}

// TestHTTP3ConnectConcurrentNoRace concurrently establishes many QUIC connections
// through HTTP3Transport.Connect against a local HTTP/3 server. The H3 transport
// used to share one *utls.ClientHelloSpec across dials, which utls ApplyPreset
// mutates in place; under `-race` this caught dozens of data races. Each dial now
// regenerates its own spec from the stored ClientHelloID + shuffleSeed, so the
// extension order (JA3/JA4) stays identical while each connection mutates a
// private spec. CI-safe (loopback only); the lock is the -race detector.
func TestHTTP3ConnectConcurrentNoRace(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	port := udpConn.LocalAddr().(*net.UDPAddr).Port

	srv := &http3.Server{
		TLSConfig: h3RaceTestTLS(t),
		Handler: shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
			w.WriteHeader(200)
		}),
	}
	go func() { _ = srv.Serve(udpConn) }()
	defer srv.Close()
	time.Sleep(300 * time.Millisecond)

	tr, err := NewHTTP3Transport(fingerprint.Chrome146(), dns.NewCache())
	if err != nil {
		t.Fatal(err)
	}
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = tr.Connect(ctx, "127.0.0.1", strconv.Itoa(port))
		}()
	}
	wg.Wait()
}
