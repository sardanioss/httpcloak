package client

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	fhttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	utls "github.com/sardanioss/utls"
)

// rawQUICHello builds a captured-shape QUIC hello from a parrot.
func rawQUICHello(t *testing.T, id utls.ClientHelloID) []byte {
	t.Helper()
	spec, err := utls.UTLSIdToSpecWithSeed(id, 1)
	if err != nil {
		t.Fatalf("build %s spec: %v", id.Str(), err)
	}
	conn := utls.UClient(nil, &utls.Config{ServerName: "example.com", OmitEmptyPsk: true}, utls.HelloCustom)
	if err := conn.ApplyPreset(&spec); err != nil {
		t.Fatalf("apply %s spec: %v", id.Str(), err)
	}
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatalf("build handshake state: %v", err)
	}
	hello := conn.HandshakeState.Hello.Raw
	return append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)
}

// observedQUICHello starts an HTTP/3 server, sends one request through a
// client.Client on the given preset, and returns the extension types of the
// ClientHello the server saw, GREASE folded to 0x0a0a.
func observedQUICHello(t *testing.T, preset string) []uint16 {
	t.Helper()
	var mu sync.Mutex
	var hello []uint16
	tlsCfg := h3GzipTestTLS(t)
	tlsCfg.GetConfigForClient = func(chi *utls.ClientHelloInfo) (*utls.Config, error) {
		mu.Lock()
		defer mu.Unlock()
		hello = hello[:0]
		for _, e := range chi.Extensions {
			if e&0x0f0f == 0x0a0a && e>>8 == e&0xff {
				e = 0x0a0a
			}
			hello = append(hello, e)
		}
		return nil, nil
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		TLSConfig:  tlsCfg,
		QUICConfig: &quic.Config{},
		Handler:    fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) { w.WriteHeader(200) }),
	}
	go func() { _ = srv.Serve(udpConn) }()
	defer func() { srv.Close(); udpConn.Close() }()
	time.Sleep(100 * time.Millisecond)

	c := NewClient(preset, WithForceHTTP3(), WithInsecureSkipVerify(), WithoutRetry())
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.Get(ctx, "https://"+udpConn.LocalAddr().String()+"/", nil)
	if err != nil {
		t.Fatalf("%s: %v", preset, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	out := slices.Clone(hello)
	slices.Sort(out)
	return out
}

// client.Client's HTTP/3 pool picked its hello by QUICClientHelloID only. A
// preset built from a captured QUIC hello has none, so the pool found nothing
// and quic-go sent its own stock hello: the request worked and carried a
// fingerprint nobody chose. It now resolves the hello the way the HTTP/3
// transport does, so the server sees the capture.
func TestHTTP3PoolSendsTheCapturedQUICHello(t *testing.T) {
	capture := rawQUICHello(t, utls.HelloIOS_18_QUIC)
	p, err := fingerprint.LoadAndBuildPresetFromJSON([]byte(`{"preset":{"name":"client-raw-quic",` +
		`"based_on":"chrome-latest","tls":{"raw_quic_client_hello":"` +
		base64.StdEncoding.EncodeToString(capture) + `"}}}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	fingerprint.Register(p.Name, p)

	got := observedQUICHello(t, p.Name)
	chrome := observedQUICHello(t, "chrome-latest")
	t.Logf("capture preset: %v", got)
	t.Logf("chrome-latest:  %v", chrome)
	if slices.Equal(got, chrome) {
		t.Fatalf("the capture preset sent chrome-latest's hello: %v", got)
	}
	// Safari's QUIC hello carries no application_settings; Chrome's does.
	const alpsOld, alpsNew = 17513, 17613
	if slices.Contains(got, alpsOld) || slices.Contains(got, alpsNew) {
		t.Errorf("the hello carries ALPS, so it is not the Safari capture: %v", got)
	}
	// quic-go's stock hello carries no GREASE and no compress_certificate.
	const grease, compressCertificate = 0x0a0a, 27
	if !slices.Contains(got, grease) || !slices.Contains(got, compressCertificate) {
		t.Errorf("the hello has no GREASE or compress_certificate, so it is quic-go's stock one: %v", got)
	}
}
