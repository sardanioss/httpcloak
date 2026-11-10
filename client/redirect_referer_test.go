package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// refererOnHop sends one GET that the server redirects once, with the given
// referrer ("{server}" stands for the server's origin), and returns the Referer
// of the redirected request.
func refererOnHop(t *testing.T, referer string) string {
	t.Helper()
	var mu sync.Mutex
	var referers []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		referers = append(referers, r.Header.Get("Referer"))
		mu.Unlock()
		if r.URL.Path == "/hop0" {
			http.Redirect(w, r, "/land", http.StatusFound)
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	c := newVetoClient(t)
	if _, err := c.Do(context.Background(), &Request{
		Method:  "GET",
		URL:     srv.URL + "/hop0",
		Referer: strings.ReplaceAll(referer, "{server}", srv.URL),
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(referers) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(referers))
	}
	return strings.ReplaceAll(referers[1], srv.URL, "{server}")
}

// The client follows redirects in its own loop, and a hop there carries the
// referrer its request had, as a session's does: the page, never the URL that
// redirected, cut down to its origin for a hop on another, and none when the
// request had none.
func TestClientRedirectKeepsTheReferrerOfItsRequest(t *testing.T) {
	cases := []struct{ name, referer, want string }{
		{"a page on the hop's origin", "{server}/page?q=1", "{server}/page?q=1"},
		{"a page on another origin", "https://caller.example/secret?token=abc", "https://caller.example/"},
		{"no referrer", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := refererOnHop(t, c.referer); got != c.want {
				t.Errorf("the hop's Referer = %q, want %q", got, c.want)
			}
		})
	}
}
