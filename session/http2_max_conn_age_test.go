package session

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

func requireHTTP2MaxConnAge(t *testing.T, s *Session, want time.Duration) {
	t.Helper()
	if got := s.Config.HTTP2MaxConnAge; got != want {
		t.Fatalf("session maximum age = %v, want %v", got, want)
	}
	cfg := s.transport.GetConfig()
	if cfg == nil {
		if want != 0 {
			t.Fatal("nonzero maximum age did not create a transport configuration")
		}
		return
	}
	if got := cfg.HTTP2MaxConnAge; got != want {
		t.Fatalf("transport maximum age = %v, want %v", got, want)
	}
}

func TestHTTP2MaxConnAgeSurvivesSessionLifecycle(t *testing.T) {
	for _, age := range []time.Duration{0, 123456789 * time.Nanosecond, -1} {
		t.Run(age.String(), func(t *testing.T) {
			s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest", HTTP2MaxConnAge: age})
			defer s.Close()
			requireHTTP2MaxConnAge(t, s, age)

			forks := s.Fork(1)
			if len(forks) != 1 {
				t.Fatalf("Fork returned %d sessions, want 1", len(forks))
			}
			defer forks[0].Close()
			requireHTTP2MaxConnAge(t, forks[0], age)

			s.Refresh()
			requireHTTP2MaxConnAge(t, s, age)
			if err := s.RefreshWithProtocol("h2"); err != nil {
				t.Fatalf("RefreshWithProtocol: %v", err)
			}
			requireHTTP2MaxConnAge(t, s, age)

			s.SetProxy("http://127.0.0.1:12345")
			requireHTTP2MaxConnAge(t, s, age)
			s.SetProxy("")
			requireHTTP2MaxConnAge(t, s, age)
			s.transport.SetPreset("firefox-latest")
			requireHTTP2MaxConnAge(t, s, age)
		})
	}
}

func TestHTTP2MaxConnAgeForkWithoutParentTransportConfig(t *testing.T) {
	for _, age := range []time.Duration{time.Minute, -1} {
		t.Run(age.String(), func(t *testing.T) {
			s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest", HTTP2MaxConnAge: age})
			defer s.Close()
			// Exercise the fallback that reconstructs the transport config from
			// SessionConfig when no parent transport configuration is available.
			s.transport.Close()
			s.transport = transport.NewTransport("chrome-latest")
			if s.transport.GetConfig() != nil {
				t.Fatal("test requires a parent transport without configuration")
			}
			forks := s.Fork(1)
			if len(forks) != 1 {
				t.Fatalf("Fork returned %d sessions, want 1", len(forks))
			}
			defer forks[0].Close()
			requireHTTP2MaxConnAge(t, forks[0], age)
		})
	}
}

func TestHTTP2MaxConnAgePersistence(t *testing.T) {
	for _, age := range []time.Duration{time.Nanosecond, 123456 * time.Nanosecond, 17 * time.Minute, -1, -time.Second} {
		t.Run(age.String(), func(t *testing.T) {
			s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest", HTTP2MaxConnAge: age})
			defer s.Close()
			data, err := s.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var state map[string]json.RawMessage
			if err := json.Unmarshal(data, &state); err != nil {
				t.Fatalf("decode state: %v", err)
			}
			var config map[string]json.RawMessage
			if err := json.Unmarshal(state["config"], &config); err != nil {
				t.Fatalf("decode config: %v", err)
			}
			if got, want := string(config["http2MaxConnAge"]), strconv.FormatInt(int64(age), 10); got != want {
				t.Fatalf("serialized maximum age = %q, want nanoseconds %q", got, want)
			}
			for _, version := range []int{4, 5} {
				t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
					state["version"] = json.RawMessage(strconv.Itoa(version))
					state["cookies"] = json.RawMessage("null")
					encoded, err := json.Marshal(state)
					if err != nil {
						t.Fatalf("encode state: %v", err)
					}
					restored, err := UnmarshalSession(encoded)
					if err != nil {
						t.Fatalf("UnmarshalSession: %v", err)
					}
					defer restored.Close()
					requireHTTP2MaxConnAge(t, restored, age)
				})
			}
		})
	}
}

func TestHTTP2MaxConnAgeOldStateKeepsDefault(t *testing.T) {
	for _, version := range []int{4, 5} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			data := []byte(fmt.Sprintf(`{"version":%d,"config":{"preset":"chrome-latest"}}`, version))
			s, err := UnmarshalSession(data)
			if err != nil {
				t.Fatalf("UnmarshalSession: %v", err)
			}
			defer s.Close()
			requireHTTP2MaxConnAge(t, s, 0)
			encoded, err := s.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var state struct {
				Config map[string]json.RawMessage `json:"config"`
			}
			if err := json.Unmarshal(encoded, &state); err != nil {
				t.Fatalf("decode saved state: %v", err)
			}
			if value, ok := state.Config["http2MaxConnAge"]; ok {
				t.Fatalf("default maximum age should be omitted, got %s", value)
			}
		})
	}
}
