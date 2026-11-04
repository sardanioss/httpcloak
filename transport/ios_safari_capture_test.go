package transport

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/net/http2"
)

// Compare emitted frames and HPACK field order with the sanitized phone capture,
// including the HEADERS priority bit that the Akamai shorthand does not cover.
func TestIOSSafari26MatchesPhoneCapture(t *testing.T) {
	var capture struct {
		Headers []string `json:"headers"`
	}
	data, err := os.ReadFile("../fingerprint/testdata/safari-26-ios-capture.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	wantOrder := make([]string, 0, len(capture.Headers))
	wantValues := map[string]string{}
	for _, field := range capture.Headers {
		name, value, ok := strings.Cut(field, ": ")
		if !ok {
			t.Fatalf("invalid captured field %q", field)
		}
		wantOrder = append(wantOrder, name)
		wantValues[name] = value
	}
	for _, name := range []string{"safari-26-ios", "ios-safari-26", "safari-latest-ios", "ios-safari-latest"} {
		t.Run(name, func(t *testing.T) {
			srv := startH2CaptureServer(t)
			tr := NewTransport(name)
			tr.SetProtocol(ProtocolHTTP2)
			tr.SetInsecureSkipVerify(true) // Self-signed loopback server only.
			defer tr.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + srv.addr + "/api/all", Headers: map[string][]string{"Accept-Language": {wantValues["accept-language"]}}})
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			select {
			case got := <-srv.captures:
				wantSettings := []http2.Setting{{ID: 2, Val: 0}, {ID: 3, Val: 100}, {ID: 4, Val: 2097152}, {ID: 9, Val: 1}}
				if !reflect.DeepEqual(got.Settings, wantSettings) {
					t.Errorf("SETTINGS=%v, want %v", got.Settings, wantSettings)
				}
				if got.WindowUpdate != 10420225 {
					t.Errorf("WINDOW_UPDATE=%d", got.WindowUpdate)
				}
				if got.HasPriority {
					t.Error("phone sends no legacy HEADERS priority")
				}
				if !reflect.DeepEqual(got.HeaderOrder, wantOrder) {
					t.Errorf("header order=%v, want %v", got.HeaderOrder, wantOrder)
				}
				for key, want := range wantValues {
					if key != ":authority" && got.Headers[key] != want {
						t.Errorf("%s=%q, want %q", key, got.Headers[key], want)
					}
				}
			case <-ctx.Done():
				t.Fatal("no HTTP/2 capture")
			}
		})
	}
}
