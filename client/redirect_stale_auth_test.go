package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	fhttp "github.com/sardanioss/http"
)

// onceAuth writes an Authorization on the first request only, as a Digest
// auth does once a refusal has cleared its nonce.
type onceAuth struct {
	mu   sync.Mutex
	used bool
}

func (a *onceAuth) Apply(req *fhttp.Request) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.used {
		a.used = true
		req.Header.Set("Authorization", "Answer for-the-first-request")
	}
	return nil
}

func (a *onceAuth) HandleChallenge(*fhttp.Response, *fhttp.Request) (bool, error) {
	return false, nil
}

// A same-origin redirect hop gets its Authorization from Auth, never the one
// Auth wrote for the request before it. Only a caller's own Authorization
// is carried.
func TestRedirectHopDoesNotCarryAuthsAnswer(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		if r.URL.Path == "/a" || r.URL.Path == "/own" {
			w.Header().Set("Location", r.URL.Path+"-next")
			w.WriteHeader(302)
			return
		}
		io.WriteString(w, "ok")
	}))
	srv.StartTLS()
	defer srv.Close()

	c := NewClient("chrome-latest", WithInsecureSkipVerify(), WithPreferIPv4(), WithTimeout(10*time.Second), WithForceHTTP1())
	defer c.Close()
	c.SetAuth(&onceAuth{})
	ctx := context.Background()
	if _, err := c.Do(ctx, &Request{Method: "GET", URL: srv.URL + "/a"}); err != nil {
		t.Fatal(err)
	}
	// A caller's own Authorization still follows a same-origin hop.
	if _, err := c.Do(ctx, &Request{Method: "GET", URL: srv.URL + "/own",
		Headers: map[string][]string{"Authorization": {"Bearer mine"}}}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if seen["/a"] != "Answer for-the-first-request" {
		t.Fatalf("/a got Authorization %q", seen["/a"])
	}
	if got := seen["/a-next"]; got != "" {
		t.Errorf("same-origin hop re-sent Auth's answer for the previous request: %q", got)
	}
	if got := seen["/own-next"]; got != "Bearer mine" {
		t.Errorf("caller's own Authorization on the hop = %q, want Bearer mine", got)
	}
}
