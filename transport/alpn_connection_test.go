package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestALPNConnectionClosedOnForcedHTTP2Error(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, negotiated := range []string{"http/1.1", ""} {
			alpnName := negotiated
			if alpnName == "" {
				alpnName = "no_alpn"
			}
			name := "buffered/" + alpnName
			if streaming {
				name = "streaming/" + alpnName
			}
			t.Run(name, func(t *testing.T) {
				var requests, connections atomic.Int64
				closed := make(chan struct{}, 1)
				srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					_, _ = io.WriteString(w, "unexpected request")
				}))
				srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					switch state {
					case http.StateNew:
						connections.Add(1)
					case http.StateClosed:
						select {
						case closed <- struct{}{}:
						default:
						}
					}
				}
				nextProtos := []string{}
				if negotiated != "" {
					nextProtos = append(nextProtos, negotiated)
				}
				srv.TLS = &tls.Config{NextProtos: nextProtos}
				srv.StartTLS()
				defer srv.Close()

				tr := NewTransport("chrome-latest")
				defer tr.Close()
				tr.SetInsecureSkipVerify(true)
				tr.SetProtocol(ProtocolHTTP2)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				req := &Request{Method: "GET", URL: srv.URL}
				var err error
				if streaming {
					_, err = tr.DoStream(ctx, req)
				} else {
					_, err = tr.Do(ctx, req)
				}
				var mismatch *ALPNMismatchError
				if !errors.Is(err, ErrALPNMismatch) || !errors.As(err, &mismatch) {
					t.Fatalf("error = %v, want ALPNMismatchError", err)
				}
				defer mismatch.TLSConn.Close()
				if mismatch.Expected != "h2" || mismatch.Negotiated != negotiated {
					t.Fatalf("ALPN mismatch = %q -> %q, want h2 -> %q", mismatch.Expected, mismatch.Negotiated, negotiated)
				}
				// The request must release the unpooled TLS connection itself;
				// neither transport shutdown nor the request deadline should be needed.
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("ALPN connection remains open after the request returned")
				}
				if got := requests.Load(); got != 0 {
					t.Fatalf("HTTP requests = %d, want 0", got)
				}
				if got := connections.Load(); got != 1 {
					t.Fatalf("TCP connections = %d, want 1", got)
				}
			})
		}
	}
}

func TestALPNConnectionAutoFallbackStillWorks(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		name := "buffered_reuses_connection"
		if streaming {
			name = "streaming_reconnects"
		}
		t.Run(name, func(t *testing.T) {
			var requests, connections atomic.Int64
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				_, _ = io.WriteString(w, "ok")
			}))
			srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			srv.StartTLS()
			defer srv.Close()

			tr := NewTransport("chrome-latest")
			defer tr.Close()
			tr.SetInsecureSkipVerify(true)
			// A cached H2 choice exercises the actual request fallback without
			// involving a separate H3 connection-probe race.
			tr.cacheProtocol(extractHost(srv.URL), ProtocolHTTP2)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req := &Request{Method: "GET", URL: srv.URL}
			var body []byte
			var protocol string
			if streaming {
				resp, err := tr.DoStream(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Close()
				protocol = resp.Protocol
				body, err = io.ReadAll(resp)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				resp, err := tr.Do(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Close()
				protocol = resp.Protocol
				body, err = io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
			}
			if protocol != "h1" || string(body) != "ok" {
				t.Fatalf("response = %s %q, want h1 ok", protocol, body)
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("HTTP requests = %d, want 1", got)
			}
			wantConnections := int64(1)
			if streaming {
				wantConnections = 2
			}
			if got := connections.Load(); got != wantConnections {
				t.Fatalf("TCP connections = %d, want %d", got, wantConnections)
			}
		})
	}
}
