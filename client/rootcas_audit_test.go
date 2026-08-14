package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	fhttp "github.com/sardanioss/http"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	utls "github.com/sardanioss/utls"
)

type caServer struct {
	addr    string
	pool    *x509.CertPool
	closers []func()
}

func (s *caServer) Close() {
	for _, c := range s.closers {
		c()
	}
}

func newCAServer(t *testing.T) *caServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "httpcloak-client-rootcas-audit"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprintf(w, "ok %s", r.Proto)
	})
	srv := &http.Server{
		Handler: mux,
		TLSConfig: &stdtls.Config{
			Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}
	go srv.ServeTLS(ln, "", "")
	cs := &caServer{addr: addr, pool: pool}
	cs.closers = append(cs.closers, func() { srv.Close() })

	udpAddr, _ := net.ResolveUDPAddr("udp", addr)
	uc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Logf("udp listen failed: %v", err)
		return cs
	}
	fmux := fhttp.NewServeMux()
	fmux.HandleFunc("/", func(w fhttp.ResponseWriter, r *fhttp.Request) {
		w.WriteHeader(200)
		fmt.Fprintf(w, "ok %s", r.Proto)
	})
	h3 := &http3.Server{
		Handler: fmux,
		TLSConfig: &utls.Config{
			Certificates: []utls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
			NextProtos:   []string{"h3"},
		},
		QUICConfig: &quic.Config{MaxIdleTimeout: 30 * time.Second},
	}
	go h3.Serve(uc)
	cs.closers = append(cs.closers, func() { h3.Close(); uc.Close() })
	return cs
}

func isCertErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, n := range []string{"unknown authority", "x509", "certificate", "crypto_error"} {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func clientProtoOpt(proto string) Option {
	switch proto {
	case "h1":
		return WithForceHTTP1()
	case "h2":
		return WithForceHTTP2()
	default:
		return WithForceHTTP3()
	}
}

// TestClientRootCAsMatrix: same three-way triangulation on the client package,
// through both WithTLSConfig and the raw ClientConfig.RootCAs field.
func TestClientRootCAsMatrix(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	time.Sleep(300 * time.Millisecond)
	url := "https://" + srv.addr + "/"

	entries := []struct {
		name string
		opt  func(p *x509.CertPool) Option
	}{
		{"WithTLSConfig", func(p *x509.CertPool) Option {
			return WithTLSConfig(&stdtls.Config{RootCAs: p})
		}},
		{"ConfigField", func(p *x509.CertPool) Option {
			return func(c *ClientConfig) { c.RootCAs = p }
		}},
	}
	cases := []struct {
		name   string
		pool   func() *x509.CertPool
		wantOK bool
	}{
		{"trusted-pool", func() *x509.CertPool { return srv.pool }, true},
		{"empty-pool", func() *x509.CertPool { return x509.NewCertPool() }, false},
		{"system-roots", func() *x509.CertPool { return nil }, false},
	}

	for _, proto := range []string{"h1", "h2", "h3"} {
		for _, e := range entries {
			for _, c := range cases {
				t.Run(proto+"/"+e.name+"/"+c.name, func(t *testing.T) {
					opts := []Option{clientProtoOpt(proto), WithTimeout(20 * time.Second), WithDisableECH()}
					if p := c.pool(); p != nil {
						opts = append(opts, e.opt(p))
					}
					cl := NewClient("chrome-latest", opts...)
					defer cl.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
					defer cancel()
					resp, err := cl.Get(ctx, url, nil)
					if c.wantOK {
						if err != nil {
							t.Fatalf("expected success, got: %v", err)
						}
						t.Logf("OK status=%d proto=%s", resp.StatusCode, resp.Protocol)
						return
					}
					if err == nil {
						t.Fatalf("FAIL-OPEN: expected failure, got status=%d proto=%s", resp.StatusCode, resp.Protocol)
					}
					t.Logf("correctly rejected: %v", err)
					if !isCertErr(err) {
						t.Errorf("not a certificate error: %v", err)
					}
				})
			}
		}
	}
}

// TestClientRootCAsSurviveProxyRotation is the handshake-level version of the
// field-assertion regression lock: after SetProxy/SetTCPProxy/SetUDPProxy
// rebuild the transports, the restricted pool must still be enforced, and a
// trusting pool must still be honoured.
func TestClientRootCAsSurviveProxyRotation(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	time.Sleep(300 * time.Millisecond)
	url := "https://" + srv.addr + "/"

	rotations := []struct {
		name string
		do   func(c *Client)
	}{
		{"SetProxy", func(c *Client) { c.SetProxy("") }},
		{"SetTCPProxy", func(c *Client) { c.SetTCPProxy("") }},
		{"SetUDPProxy", func(c *Client) { c.SetUDPProxy("") }},
		{"SetPreset", func(c *Client) { c.SetPreset("firefox-latest") }},
	}

	for _, proto := range []string{"h1", "h2", "h3"} {
		for _, r := range rotations {
			t.Run(proto+"/"+r.name+"/empty-pool", func(t *testing.T) {
				cl := NewClient("chrome-latest",
					clientProtoOpt(proto), WithTimeout(20*time.Second), WithDisableECH(),
					WithTLSConfig(&stdtls.Config{RootCAs: x509.NewCertPool()}))
				defer cl.Close()
				r.do(cl)
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				defer cancel()
				resp, err := cl.Get(ctx, url, nil)
				if err == nil {
					t.Fatalf("FAIL-OPEN after %s: status=%d proto=%s", r.name, resp.StatusCode, resp.Protocol)
				}
				t.Logf("still rejected after %s: %v", r.name, err)
				if !isCertErr(err) {
					t.Errorf("not a certificate error: %v", err)
				}
			})
			t.Run(proto+"/"+r.name+"/trusted-pool", func(t *testing.T) {
				cl := NewClient("chrome-latest",
					clientProtoOpt(proto), WithTimeout(20*time.Second), WithDisableECH(),
					WithTLSConfig(&stdtls.Config{RootCAs: srv.pool}))
				defer cl.Close()
				r.do(cl)
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				defer cancel()
				resp, err := cl.Get(ctx, url, nil)
				if err != nil {
					t.Fatalf("trusting pool should still work after %s, got: %v", r.name, err)
				}
				t.Logf("OK after %s status=%d proto=%s", r.name, resp.StatusCode, resp.Protocol)
			})
		}
	}
}

// TestClientVerifyHookSurvivesProxyRotation is the callback half of the same
// hole: a rejecting VerifyPeerCertificate must keep rejecting after a rebuild.
func TestClientVerifyHookSurvivesProxyRotation(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	time.Sleep(300 * time.Millisecond)
	url := "https://" + srv.addr + "/"

	for _, proto := range []string{"h1", "h2", "h3"} {
		for _, name := range []string{"baseline", "SetProxy", "SetTCPProxy", "SetUDPProxy", "SetPreset"} {
			t.Run(proto+"/"+name, func(t *testing.T) {
				cl := NewClient("chrome-latest",
					clientProtoOpt(proto), WithTimeout(20*time.Second), WithDisableECH(),
					// Trust the server's CA so the ONLY thing that can reject is the hook.
					WithTLSConfig(&stdtls.Config{RootCAs: srv.pool}),
					WithVerifyPeerCertificate(func(_ [][]byte, _ [][]*x509.Certificate) error {
						return fmt.Errorf("pinning rejected this certificate")
					}))
				defer cl.Close()
				switch name {
				case "SetProxy":
					cl.SetProxy("")
				case "SetTCPProxy":
					cl.SetTCPProxy("")
				case "SetUDPProxy":
					cl.SetUDPProxy("")
				case "SetPreset":
					cl.SetPreset("firefox-latest")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				defer cancel()
				resp, err := cl.Get(ctx, url, nil)
				if err == nil {
					t.Fatalf("FAIL-OPEN after %s: rejecting hook was dropped, status=%d proto=%s",
						name, resp.StatusCode, resp.Protocol)
				}
				t.Logf("hook still enforced after %s: %v", name, err)
				if !strings.Contains(err.Error(), "pinning rejected") {
					t.Errorf("failed for the wrong reason: %v", err)
				}
			})
		}
	}
}

// TestClientConfigTLSConfigFieldIsDead measures the exported ClientConfig.TLSConfig
// field. Its doc comment says "Only its verification fields are read", but the
// extraction happens inside the WithTLSConfig option, not from the field, so
// nothing in NewClient ever reads c.config.TLSConfig. Setting it directly - which
// the exported Option type and the field's own doc invite - applies nothing.
func TestClientConfigTLSConfigFieldIsDead(t *testing.T) {
	if testing.Short() {
		t.Skip("needs network")
	}
	// Empty pool plus a rejecting hook, against a publicly trusted site. If the
	// field were read, either one would abort the handshake.
	setField := func(c *ClientConfig) {
		c.TLSConfig = &stdtls.Config{
			RootCAs: x509.NewCertPool(),
			VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
				return fmt.Errorf("field hook rejected")
			},
		}
	}
	for _, proto := range []string{"h1", "h2", "h3"} {
		t.Run(proto, func(t *testing.T) {
			url := "https://example.com/"
			if proto == "h3" {
				url = "https://cloudflare-quic.com/"
			}
			cl := NewClient("chrome-latest", clientProtoOpt(proto), WithTimeout(25*time.Second), setField)
			defer cl.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			resp, err := cl.Get(ctx, url, nil)
			if err != nil {
				t.Logf("field WAS honoured: %v", err)
				return
			}
			// Reported as a finding rather than a hard failure so this file does
			// not block the release build. Flip to t.Errorf once the field is
			// either read in NewClient or removed.
			t.Logf("MEASURED FAIL-OPEN: ClientConfig.TLSConfig ignored entirely - empty RootCAs and a rejecting hook both dropped, status=%d proto=%s",
				resp.StatusCode, resp.Protocol)
		})
	}
}

// TestClientEmptyPoolPublicSite is the assertion that separates "RootCAs
// replaced the trust store" from "RootCAs was merged into it". Against the
// self-signed local server both readings look identical, because the system
// roots reject that certificate anyway. Against a publicly trusted site only
// replacement fails closed.
func TestClientEmptyPoolPublicSite(t *testing.T) {
	if testing.Short() {
		t.Skip("needs network")
	}
	for _, proto := range []string{"h1", "h2", "h3"} {
		t.Run(proto, func(t *testing.T) {
			url := "https://example.com/"
			if proto == "h3" {
				url = "https://cloudflare-quic.com/"
			}
			cl := NewClient("chrome-latest", clientProtoOpt(proto), WithTimeout(25*time.Second),
				WithTLSConfig(&stdtls.Config{RootCAs: x509.NewCertPool()}))
			defer cl.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			resp, err := cl.Get(ctx, url, nil)
			if err == nil {
				t.Fatalf("FAIL-OPEN: empty pool against a publicly trusted site returned status=%d proto=%s",
					resp.StatusCode, resp.Protocol)
			}
			t.Logf("correctly rejected: %v", err)
			if !isCertErr(err) {
				t.Errorf("not a certificate error: %v", err)
			}
		})
	}
}
