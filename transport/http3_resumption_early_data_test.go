package transport

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	utls "github.com/sardanioss/utls"
)

// resumeOrigin records the extensions of every ClientHello an HTTP/3 server
// receives, one per handshake, and every connection it accepts.
type resumeOrigin struct {
	mu     sync.Mutex
	hellos [][]uint16
	conns  []*quic.Conn
}

func startResumeOrigin(t *testing.T, allow0RTT bool) (url string, rec *resumeOrigin) {
	t.Helper()
	rec = &resumeOrigin{}
	tlsCfg := h3RaceTestTLS(t)
	tlsCfg.GetConfigForClient = func(chi *utls.ClientHelloInfo) (*utls.Config, error) {
		rec.mu.Lock()
		rec.hellos = append(rec.hellos, slices.Clone(chi.Extensions))
		rec.mu.Unlock()
		return nil, nil
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		TLSConfig:  tlsCfg,
		QUICConfig: &quic.Config{Allow0RTT: allow0RTT},
		Handler:    shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) { w.WriteHeader(200) }),
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			rec.mu.Lock()
			rec.conns = append(rec.conns, conn)
			rec.mu.Unlock()
			return ctx
		},
	}
	go func() { _ = srv.Serve(c) }()
	t.Cleanup(func() { srv.Close(); c.Close() })
	time.Sleep(100 * time.Millisecond)
	return fmt.Sprintf("https://127.0.0.1:%d/", c.LocalAddr().(*net.UDPAddr).Port), rec
}

func (r *resumeOrigin) snapshot() ([][]uint16, []*quic.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.hellos), slices.Clone(r.conns)
}

// checkResumption asserts that the second of two connections resumed in one
// handshake, offering early_data and using 0-RTT exactly when the server's
// tickets allow it.
func checkResumption(t *testing.T, rec *resumeOrigin, allow0RTT bool) {
	t.Helper()
	hellos, conns := rec.snapshot()
	if len(hellos) != 2 || len(conns) != 2 {
		t.Fatalf("%d handshakes and %d connections, want 2 of each: one per connection", len(hellos), len(conns))
	}
	const preSharedKey, earlyData = 41, 42
	if !slices.Contains(hellos[1], preSharedKey) {
		t.Fatalf("the second connection offered no pre_shared_key: %v", hellos[1])
	}
	if got := slices.Contains(hellos[1], earlyData); got != allow0RTT {
		t.Errorf("the resuming hello offers early_data: %v, want %v (extensions %v)", got, allow0RTT, hellos[1])
	}
	cs := conns[1].ConnectionState()
	if !cs.TLS.DidResume {
		t.Error("the second connection did not resume")
	}
	if cs.Used0RTT != allow0RTT {
		t.Errorf("0-RTT used: %v, want %v", cs.Used0RTT, allow0RTT)
	}
}

// A resuming connection offers early_data only when its ticket allows 0-RTT,
// which is what Chrome 156 and Firefox 159 sent when captured against tickets
// with and without early data. It used to be offered on every ticket. A server
// whose tickets do not allow early data rejected the 0-RTT, the http3 layer
// abandoned the connection with H3_INTERNAL_ERROR, twice, and the next dial
// dropped the ticket for a full handshake: a Refresh cost three handshakes
// and lost the resumption it is for.
func TestHTTP3ResumptionOffersEarlyDataOnlyWhenTheTicketAllows(t *testing.T) {
	for _, allow0RTT := range []bool{false, true} {
		t.Run(fmt.Sprintf("server allows 0-RTT %v", allow0RTT), func(t *testing.T) {
			url, rec := startResumeOrigin(t, allow0RTT)
			tr, err := NewHTTP3Transport(fingerprint.Get("chrome-155-windows"), dns.NewCache())
			if err != nil {
				t.Fatal(err)
			}
			tr.SetInsecureSkipVerify(true)
			defer tr.Close()

			if err := h3Fetch(tr, url); err != nil {
				t.Fatal(err)
			}
			time.Sleep(200 * time.Millisecond) // the ticket arrives after the response
			tr.Refresh()
			if err := h3Fetch(tr, url); err != nil {
				t.Fatal(err)
			}
			checkResumption(t, rec, allow0RTT)
		})
	}
}
