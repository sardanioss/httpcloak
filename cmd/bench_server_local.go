package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func main() {
	cert, _ := generateCert()

	mux := http.NewServeMux()

	// Stream endpoint: /stream/100 = 100MB
	mux.HandleFunc("/stream/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		sizeMB := 100
		if len(parts) >= 3 {
			if s, _ := strconv.Atoi(parts[2]); s > 0 {
				sizeMB = s
			}
		}
		sizeBytes := sizeMB * 1024 * 1024
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(sizeBytes))

		chunk := make([]byte, 64*1024)
		for i := range chunk {
			chunk[i] = byte(i % 256)
		}
		written := 0
		for written < sizeBytes {
			toWrite := len(chunk)
			if written+toWrite > sizeBytes {
				toWrite = sizeBytes - written
			}
			w.Write(chunk[:toWrite])
			written += toWrite
		}
	})

	// Upload endpoint
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		total := 0
		buf := make([]byte, 64*1024)
		for {
			n, err := r.Body.Read(buf)
			total += n
			if err != nil {
				break
			}
		}
		fmt.Fprintf(w, `{"received": %d}`, total)
	})

	server := &http.Server{
		Addr:    "127.0.0.1:8443",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	fmt.Println("Local HTTPS benchmark server on https://127.0.0.1:8443")
	fmt.Println("Endpoints: /stream/{mb} /upload")
	server.ListenAndServeTLS("", "")
}

func generateCert() (tls.Certificate, error) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Bench"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: priv}, nil
}
