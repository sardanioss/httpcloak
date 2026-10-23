package httpcloak

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/transport"
	"github.com/sardanioss/net/http2"
)

// Refuse every stream, so a lost opt-out becomes an observable extra request
// rather than a different error or a successful request on a later stream.
type retryOptionH2Server struct {
	url     string
	headers atomic.Int64
}

func newRetryOptionH2Server(t *testing.T) *retryOptionH2Server {
	t.Helper()
	s := &retryOptionH2Server{}
	var mu sync.Mutex
	connections := make(map[*tls.Conn]struct{})
	closing := false
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected HTTP/1 request: %s", r.URL)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	ts.EnableHTTP2 = true
	ts.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
			mu.Lock()
			if closing {
				mu.Unlock()
				conn.Close()
				return
			}
			connections[conn] = struct{}{}
			mu.Unlock()
			defer func() {
				conn.Close()
				mu.Lock()
				delete(connections, conn)
				mu.Unlock()
			}()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			preface := make([]byte, len(http2.ClientPreface))
			if _, err := io.ReadFull(conn, preface); err != nil {
				return
			}
			if string(preface) != http2.ClientPreface {
				t.Errorf("unexpected HTTP/2 preface: %q", preface)
				return
			}
			fr := http2.NewFramer(conn, conn)
			if err := fr.WriteSettings(); err != nil {
				return
			}
			for {
				frame, err := fr.ReadFrame()
				if err != nil {
					return
				}
				switch f := frame.(type) {
				case *http2.SettingsFrame:
					if !f.IsAck() {
						err = fr.WriteSettingsAck()
					}
				case *http2.PingFrame:
					if !f.IsAck() {
						err = fr.WritePing(true, f.Data)
					}
				case *http2.HeadersFrame:
					s.headers.Add(1)
					if f.HeadersEnded() {
						err = fr.WriteRSTStream(f.StreamID, http2.ErrCodeRefusedStream)
					}
				case *http2.ContinuationFrame:
					if f.HeadersEnded() {
						err = fr.WriteRSTStream(f.StreamID, http2.ErrCodeRefusedStream)
					}
				}
				if err != nil {
					return
				}
			}
		},
	}
	ts.StartTLS()
	s.url = ts.URL
	t.Cleanup(func() {
		mu.Lock()
		closing = true
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
		ts.Close()
	})
	return s
}

func newRetryOptionSession(t *testing.T, opts ...SessionOption) *Session {
	t.Helper()
	base := []SessionOption{WithForceHTTP2(), WithInsecureSkipVerify(), WithDisableECH(), WithoutRetry()}
	s := NewSession("chrome-latest", append(base, opts...)...)
	t.Cleanup(s.Close)
	return s
}

func assertRetryOptionRequest(t *testing.T, s *Session, server *retryOptionH2Server, streaming bool, want int64) {
	t.Helper()
	before := server.headers.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := &Request{Method: "GET", URL: server.url}
	var err error
	if streaming {
		var resp *StreamResponse
		resp, err = s.DoStream(ctx, req)
		if resp != nil {
			resp.Close()
		}
	} else {
		_, err = s.Do(ctx, req)
	}
	var streamErr http2.StreamError
	if !errors.As(err, &streamErr) || streamErr.Code != http2.ErrCodeRefusedStream {
		t.Fatalf("request error = %v, want an unwrap-able REFUSED_STREAM", err)
	}
	var transportErr *transport.TransportError
	if !errors.As(err, &transportErr) || transportErr.Protocol != "h2" {
		t.Fatalf("request error = %v, want an unwrap-able HTTP/2 TransportError", err)
	}
	if got := server.headers.Load() - before; got != want {
		t.Fatalf("HEADERS arrivals = %d, want %d", got, want)
	}
}

func TestSessionHTTP2RetryOption(t *testing.T) {
	for _, api := range []string{"Do", "DoStream"} {
		for _, disabled := range []bool{false, true} {
			name := "default"
			if disabled {
				name = "disabled"
			}
			t.Run(api+"/"+name, func(t *testing.T) {
				server := newRetryOptionH2Server(t)
				var opts []SessionOption
				want := int64(3)
				if disabled {
					opts = append(opts, WithDisableHTTP2Retries())
					want = 1
				}
				s := newRetryOptionSession(t, opts...)
				assertRetryOptionRequest(t, s, server, api == "DoStream", want)
			})
		}
	}
}

// Application retries remain a separate policy. Streaming never applies that
// policy, while Do can explicitly send again after the transport returns.
func TestSessionHTTP2RetryOptionDoesNotDisableApplicationRetries(t *testing.T) {
	for _, api := range []string{"Do", "DoStream"} {
		t.Run(api, func(t *testing.T) {
			server := newRetryOptionH2Server(t)
			s := newRetryOptionSession(t, WithDisableHTTP2Retries(), WithRetryConfig(1, time.Millisecond, time.Millisecond, nil))
			want := int64(2)
			if api == "DoStream" {
				want = 1
			}
			assertRetryOptionRequest(t, s, server, api == "DoStream", want)
		})
	}
}

func TestSessionHTTP2RetryOptionSurvivesLifecycle(t *testing.T) {
	for _, api := range []string{"Do", "DoStream"} {
		for _, operation := range []string{"fork", "refresh", "refresh-with-protocol", "proxy-rebuild", "preset-rebuild"} {
			t.Run(api+"/"+operation, func(t *testing.T) {
				server := newRetryOptionH2Server(t)
				s := newRetryOptionSession(t, WithDisableHTTP2Retries())
				assertRetryOptionRequest(t, s, server, api == "DoStream", 1)
				switch operation {
				case "fork":
					forks := s.Fork(1)
					if len(forks) != 1 {
						t.Fatalf("Fork returned %d sessions, want 1", len(forks))
					}
					s = forks[0]
					t.Cleanup(s.Close)
				case "refresh":
					s.Refresh()
				case "refresh-with-protocol":
					if err := s.RefreshWithProtocol("h2"); err != nil {
						t.Fatal(err)
					}
				case "proxy-rebuild":
					// Removing a proxy rebuilds transports without needing a
					// remote proxy or any network access outside loopback.
					s.SetProxy("")
				case "preset-rebuild":
					s.GetTransport().SetPreset("chrome-146")
				}
				assertRetryOptionRequest(t, s, server, api == "DoStream", 1)
			})
		}
	}
}

func TestSessionHTTP2RetryOptionSaveLoad(t *testing.T) {
	for _, api := range []string{"Do", "DoStream"} {
		for _, legacy := range []bool{false, true} {
			name := "disabled"
			if legacy {
				name = "legacy-missing-field"
			}
			t.Run(api+"/"+name, func(t *testing.T) {
				server := newRetryOptionH2Server(t)
				source := newRetryOptionSession(t, WithDisableHTTP2Retries())
				path := filepath.Join(t.TempDir(), "session.json")
				if err := source.Save(path); err != nil {
					t.Fatal(err)
				}
				source.Close()
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var state map[string]json.RawMessage
				if err := json.Unmarshal(data, &state); err != nil {
					t.Fatal(err)
				}
				var config map[string]json.RawMessage
				if err := json.Unmarshal(state["config"], &config); err != nil {
					t.Fatal(err)
				}
				if string(config["disableHttp2Retries"]) != "true" {
					t.Fatalf("saved disableHttp2Retries = %s, want true", config["disableHttp2Retries"])
				}
				want := int64(1)
				if legacy {
					// Files written before this option existed must retain
					// the existing retry policy when the field is absent.
					delete(config, "disableHttp2Retries")
					state["config"], err = json.Marshal(config)
					if err != nil {
						t.Fatal(err)
					}
					data, err = json.Marshal(state)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
					want = 3
				}
				restored, err := LoadSession(path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(restored.Close)
				assertRetryOptionRequest(t, restored, server, api == "DoStream", want)
			})
		}
	}
}
