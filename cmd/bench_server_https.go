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
	"net/http"
	"strconv"
	"strings"
	"time"
)

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Benchmark"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []byte{127, 0, 0, 1},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

func main() {
	cert, err := generateSelfSignedCert()
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()

	// Serve random bytes
	mux.HandleFunc("/stream/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		sizeMB := 100
		if len(parts) >= 3 {
			if s, err := strconv.Atoi(parts[2]); err == nil {
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
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"received": %d}`, total)
	})

	server := &http.Server{
		Addr:    "127.0.0.1:8766",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	fmt.Println("HTTPS Benchmark server running on https://127.0.0.1:8766")
	fmt.Println("Note: Using self-signed certificate")
	server.ListenAndServeTLS("", "")
}
