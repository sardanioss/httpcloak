package httpcloak

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionHTTP2MaxConnAgeOption(t *testing.T) {
	for _, tt := range []struct {
		name string
		opts []SessionOption
		want time.Duration
	}{
		{name: "omitted"},
		{name: "zero", opts: []SessionOption{WithHTTP2MaxConnAge(0)}},
		{name: "custom", opts: []SessionOption{WithHTTP2MaxConnAge(123456789 * time.Nanosecond)}, want: 123456789 * time.Nanosecond},
		{name: "disabled", opts: []SessionOption{WithHTTP2MaxConnAge(-1)}, want: -1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSession("chrome-latest", tt.opts...)
			defer s.Close()
			if got := s.inner.Config.HTTP2MaxConnAge; got != tt.want {
				t.Fatalf("session maximum age = %v, want %v", got, tt.want)
			}
			cfg := s.GetTransport().GetConfig()
			if cfg == nil {
				if tt.want != 0 {
					t.Fatal("nonzero maximum age did not create a transport configuration")
				}
				return
			}
			if got := cfg.HTTP2MaxConnAge; got != tt.want {
				t.Fatalf("transport maximum age = %v, want %v", got, tt.want)
			}
		})
	}
}

// Exercise the public streaming API so option propagation is checked against
// actual TCP reuse, rather than only inspecting the stored configuration.
func TestSessionHTTP2MaxConnAgeControlsReuse(t *testing.T) {
	for _, tt := range []struct {
		name      string
		age       time.Duration
		wantConns int32
	}{
		{name: "default", wantConns: 1},
		{name: "expired", age: time.Nanosecond, wantConns: 2},
		{name: "disabled", age: -1, wantConns: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var connections atomic.Int32
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 {
					t.Errorf("request protocol = %s, want HTTP/2", r.Proto)
				}
				_, _ = io.WriteString(w, "ok")
			}))
			srv.EnableHTTP2 = true
			srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			srv.StartTLS()
			defer srv.Close()

			s := NewSession("chrome-latest", WithForceHTTP2(), WithInsecureSkipVerify(), WithDisableECH(), WithHTTP2MaxConnAge(tt.age))
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for i := range 2 {
				resp, err := s.GetStream(ctx, srv.URL)
				if err != nil {
					t.Fatalf("request %d: %v", i+1, err)
				}
				body, err := io.ReadAll(resp)
				closeErr := resp.Close()
				if err != nil || closeErr != nil {
					t.Fatalf("request %d: read = %v, close = %v", i+1, err, closeErr)
				}
				if resp.StatusCode != http.StatusOK || string(body) != "ok" {
					t.Fatalf("request %d: status = %d, body = %q", i+1, resp.StatusCode, body)
				}
			}
			if got := connections.Load(); got != tt.wantConns {
				t.Fatalf("TCP connections = %d, want %d", got, tt.wantConns)
			}
		})
	}
}
