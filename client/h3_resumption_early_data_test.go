package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	fhttp "github.com/sardanioss/http"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	utls "github.com/sardanioss/utls"
)

// client.Client's HTTP/3 pool resumes the way the Session does: early_data
// only on a ticket that allows 0-RTT, one handshake per connection. It used to
// offer early_data on every ticket, so against a server whose tickets do not
// allow it the resumed connection was abandoned with H3_INTERNAL_ERROR twice
// before a full handshake.
func TestHTTP3PoolResumptionOffersEarlyDataOnlyWhenTheTicketAllows(t *testing.T) {
	for _, allow0RTT := range []bool{false, true} {
		t.Run(fmt.Sprintf("server allows 0-RTT %v", allow0RTT), func(t *testing.T) {
			var mu sync.Mutex
			var hellos [][]uint16
			var conns []*quic.Conn
			tlsCfg := h3GzipTestTLS(t)
			tlsCfg.GetConfigForClient = func(chi *utls.ClientHelloInfo) (*utls.Config, error) {
				mu.Lock()
				hellos = append(hellos, slices.Clone(chi.Extensions))
				mu.Unlock()
				return nil, nil
			}
			udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			srv := &http3.Server{
				TLSConfig:  tlsCfg,
				QUICConfig: &quic.Config{Allow0RTT: allow0RTT},
				Handler:    fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) { w.WriteHeader(200) }),
				ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
					mu.Lock()
					conns = append(conns, c)
					mu.Unlock()
					return ctx
				},
			}
			go func() { _ = srv.Serve(udpConn) }()
			t.Cleanup(func() { srv.Close(); udpConn.Close() })
			time.Sleep(100 * time.Millisecond)
			url := "https://" + udpConn.LocalAddr().String() + "/"

			c := NewClient("chrome-155-windows", WithForceHTTP3(), WithInsecureSkipVerify(), WithoutRetry())
			defer c.Close()
			get := func() {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				resp, err := c.Get(ctx, url, nil)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			get()
			time.Sleep(200 * time.Millisecond) // the ticket arrives after the response
			c.CloseQUICConnections()           // keeps the session cache
			get()

			mu.Lock()
			defer mu.Unlock()
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
			if cs := conns[1].ConnectionState(); cs.Used0RTT != allow0RTT || !cs.TLS.DidResume {
				t.Errorf("resumed %v, 0-RTT used %v; want resumed, 0-RTT %v", cs.TLS.DidResume, cs.Used0RTT, allow0RTT)
			}
		})
	}
}
