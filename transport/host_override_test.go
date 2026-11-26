package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// A caller-supplied Host header must reach the server, for example for domain
// fronting. https://github.com/sardanioss/httpcloak/issues/158
func TestCallerHostHeaderIsSent(t *testing.T) {
	hosts := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		hosts <- r.Host
	}))
	defer server.Close()

	tr := NewTransport("chrome-latest")
	defer tr.Close()

	requests := map[string]*Request{
		"Headers":      {Method: "GET", URL: server.URL, Headers: map[string][]string{"Host": {"real.example.com"}}},
		"lowercase":    {Method: "GET", URL: server.URL, Headers: map[string][]string{"host": {"real.example.com"}}},
		"ExactHeaders": {Method: "GET", URL: server.URL, ExactHeaders: []fingerprint.HeaderPair{{Key: "Host", Value: "real.example.com"}}},
	}
	for name, req := range requests {
		t.Run(name, func(t *testing.T) {
			resp, err := tr.Do(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			if got := <-hosts; got != "real.example.com" {
				t.Fatalf("server received Host %q, want %q", got, "real.example.com")
			}
		})
	}
}
