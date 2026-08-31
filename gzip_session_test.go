package httpcloak

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/quic-go/http3"
	utls "github.com/sardanioss/utls"
)

// TestSessionGzipResponses drives the public Session API, the path the
// bindings and most callers use, against local servers on each protocol, so
// gzip bodies are checked end to end through Session.Do and Session.DoStream
// rather than only at the transport underneath.
func TestSessionGzipResponses(t *testing.T) {
	var text bytes.Buffer
	for i := range 4096 {
		fmt.Fprintf(&text, `{"id":%d,"text":"hello, httpcloak session"}`+"\n", i)
	}
	body := text.Bytes()
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		zw := gzip.NewWriter(w)
		for chunk := range slices.Chunk(body, 16<<10) {
			zw.Write(chunk)
			zw.Flush()
			w.(http.Flusher).Flush()
		}
		zw.Close()
	}

	h1 := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer h1.Close()
	h2 := httptest.NewUnstartedServer(http.HandlerFunc(handler))
	h2.EnableHTTP2 = true
	h2.StartTLS()
	defer h2.Close()
	h3URL := gzipSessionH3Server(t, body)

	for _, tt := range []struct {
		name  string
		url   string
		force SessionOption
	}{
		{name: "h1", url: h1.URL, force: WithForceHTTP1()},
		{name: "h2", url: h2.URL, force: WithForceHTTP2()},
		{name: "h3", url: h3URL, force: WithForceHTTP3()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSession("chrome-latest", tt.force, WithInsecureSkipVerify())
			defer s.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			for i := range 3 {
				resp, err := s.Do(ctx, &Request{Method: "GET", URL: tt.url})
				if err != nil {
					t.Fatalf("Do %d: %v", i, err)
				}
				got, err := resp.Bytes()
				if err != nil {
					t.Fatalf("Do %d: Bytes: %v", i, err)
				}
				if !bytes.Equal(got, body) {
					t.Fatalf("Do %d: body is %d bytes, want %d", i, len(got), len(body))
				}
				if resp.Protocol != tt.name {
					t.Fatalf("Do %d: protocol = %q, want %q", i, resp.Protocol, tt.name)
				}

				stream, err := s.DoStream(ctx, &Request{Method: "GET", URL: tt.url})
				if err != nil {
					t.Fatalf("DoStream %d: %v", i, err)
				}
				got, err = stream.ReadAll()
				if err != nil {
					t.Fatalf("DoStream %d: ReadAll: %v", i, err)
				}
				if !bytes.Equal(got, body) {
					t.Fatalf("DoStream %d: body is %d bytes, want %d", i, len(got), len(body))
				}
			}
		})
	}
}

func gzipSessionH3Server(t *testing.T, body []byte) string {
	t.Helper()
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
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyB, _ := x509.MarshalECPrivateKey(priv)
	cert, err := utls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyB}))
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		TLSConfig: &utls.Config{Certificates: []utls.Certificate{cert}, NextProtos: []string{"h3"}},
		Handler: shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(200)
			zw := gzip.NewWriter(w)
			zw.Write(body)
			zw.Close()
		}),
	}
	go func() { _ = srv.Serve(udpConn) }()
	t.Cleanup(func() { srv.Close(); udpConn.Close() })
	time.Sleep(200 * time.Millisecond)
	return "https://" + udpConn.LocalAddr().String() + "/"
}
