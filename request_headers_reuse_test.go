package httpcloak

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

// Client.Do hands its caller's Headers map to client.Client as it is, and
// client.Client used to write every header it sent into that map. So a map
// reused for a second request sent it the first one's built headers. After a
// POST, a GET to another host went out with the POST's Content-Length,
// Content-Type and Origin, as a cors request, and over HTTP/1.1 the server
// waited for a body that never came.
func TestClientDoReusedHeaderMap(t *testing.T) {
	presets := []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}
	protocols := []struct {
		name  string
		force client.Option
	}{
		{"h1", client.WithForceHTTP1()},
		{"h2", client.WithForceHTTP2()},
	}
	for _, preset := range presets {
		for _, p := range protocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				var mu sync.Mutex
				seen := map[string]http.Header{}
				srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.Copy(io.Discard, r.Body)
					mu.Lock()
					seen[r.URL.Path] = r.Header.Clone()
					mu.Unlock()
					io.WriteString(w, "ok")
				}))
				srv.EnableHTTP2 = true
				srv.StartTLS()
				t.Cleanup(srv.Close)

				// The root package has no option to trust httptest's
				// certificate, so the Client is built around one that does.
				c := &Client{
					inner: client.NewClient(preset,
						client.WithInsecureSkipVerify(),
						client.WithPreferIPv4(), // the server listens on 127.0.0.1 only
						client.WithTimeout(10*time.Second),
						p.force),
					timeout: 10 * time.Second,
				}
				t.Cleanup(c.Close)

				headers := map[string][]string{"X-Probe": {"1"}}
				ctx := context.Background()
				if _, err := c.Do(ctx, &Request{Method: "POST", URL: srv.URL + "/api", Headers: headers,
					Body: strings.NewReader(`{"a":1}`)}); err != nil {
					t.Fatalf("POST: %v", err)
				}
				other := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
				if _, err := c.Do(ctx, &Request{Method: "GET", URL: other + "/next", Headers: headers}); err != nil {
					t.Fatalf("GET: %v", err)
				}

				mu.Lock()
				post, get := seen["/api"], seen["/next"]
				mu.Unlock()
				if got := post.Get("Sec-Fetch-Mode"); got != "cors" {
					t.Fatalf("the POST went out as Sec-Fetch-Mode %q, want cors", got)
				}
				for _, name := range []string{"Content-Length", "Content-Type", "Origin"} {
					if v := get.Values(name); len(v) != 0 {
						t.Errorf("the GET sent %s %q", name, v)
					}
				}
				if got := get.Get("Sec-Fetch-Mode"); got != "navigate" {
					t.Errorf("the GET went out as Sec-Fetch-Mode %q, want navigate", got)
				}
				if len(headers) != 1 {
					t.Errorf("the caller's map is now %v, want only X-Probe", headers)
				}
			})
		}
	}
}
