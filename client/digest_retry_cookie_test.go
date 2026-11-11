package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The Digest retry must start from the caller's request. Started from the
// copy that holds the jar's Cookie as sent, it took that Cookie for the
// caller's own, and a cookie a later redirect deleted went out again.
func TestDigestRetryThenRedirectDropsDeletedCookie(t *testing.T) {
	var mu sync.Mutex
	seen := map[string][]string{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		seen[r.URL.Path] = append(seen[r.URL.Path], r.Header.Get("Cookie"))
		mu.Unlock()
		switch r.URL.Path {
		case "/set":
			w.Header().Add("Set-Cookie", "sid=old; Path=/")
			io.WriteString(w, "ok")
		case "/a":
			if r.Header.Get("Authorization") == "" {
				w.Header().Set("WWW-Authenticate", `Digest realm="r", nonce="n1", qop="auth"`)
				w.WriteHeader(401)
				return
			}
			w.Header().Add("Set-Cookie", "sid=; Path=/; Max-Age=0")
			w.Header().Set("Location", "/b")
			w.WriteHeader(302)
		default:
			io.WriteString(w, "ok")
		}
	}))
	srv.StartTLS()
	defer srv.Close()

	c := NewClient("chrome-latest", WithInsecureSkipVerify(), WithPreferIPv4(), WithTimeout(10*time.Second), WithForceHTTP1())
	defer c.Close()
	c.EnableCookies()
	c.SetAuth(NewDigestAuth("u", "p"))
	ctx := context.Background()
	if _, err := c.Do(ctx, &Request{Method: "GET", URL: srv.URL + "/set"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(ctx, &Request{Method: "GET", URL: srv.URL + "/a"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Logf("/a cookies: %q, /b cookies: %q", seen["/a"], seen["/b"])
	if got := seen["/b"]; len(got) != 1 || got[0] != "" {
		t.Errorf("/b got Cookie %q after the 302 deleted sid", got)
	}
}

// The same without a redirect: a 401 that deletes a cookie, then the retry.
func TestDigestRetryDropsCookieThe401Deleted(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.URL.Path == "/a" {
			seen = append(seen, r.Header.Get("Cookie"))
		}
		mu.Unlock()
		switch r.URL.Path {
		case "/set":
			w.Header().Add("Set-Cookie", "sid=old; Path=/")
		case "/a":
			if r.Header.Get("Authorization") == "" {
				w.Header().Add("Set-Cookie", "sid=; Path=/; Max-Age=0")
				w.Header().Set("WWW-Authenticate", `Digest realm="r", nonce="n1", qop="auth"`)
				w.WriteHeader(401)
				return
			}
		}
		io.WriteString(w, "ok")
	}))
	srv.StartTLS()
	defer srv.Close()
	c := NewClient("chrome-latest", WithInsecureSkipVerify(), WithPreferIPv4(), WithTimeout(10*time.Second), WithForceHTTP1())
	defer c.Close()
	c.EnableCookies()
	c.SetAuth(NewDigestAuth("u", "p"))
	ctx := context.Background()
	c.Do(ctx, &Request{Method: "GET", URL: srv.URL + "/set"})
	if _, err := c.Do(ctx, &Request{Method: "GET", URL: srv.URL + "/a"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Logf("/a cookies per attempt: %q", seen)
	if len(seen) == 2 && strings.Contains(seen[1], "sid=old") {
		t.Errorf("Digest retry resent the cookie the 401 deleted")
	}
}

// A Digest server without qop sends no nonce count, so a refused answer can't
// be told from one sent up front by its count. This one accepts an answer and
// then moves to a new nonce without stale=true: the next request's up-front
// answer is refused, and must be answered once more rather than returned.
func TestDigestWithoutQopAnswersANewNonce(t *testing.T) {
	var mu sync.Mutex
	nonce := "n1"
	var log []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		a := r.Header.Get("Authorization")
		log = append(log, a)
		if a != "" && strings.Contains(a, `nonce="`+nonce+`"`) {
			nonce = nonce + "x" // rotate after each accepted answer
			io.WriteString(w, "ok")
			return
		}
		w.Header().Set("WWW-Authenticate", `Digest realm="r", nonce="`+nonce+`"`)
		w.WriteHeader(401)
	}))
	srv.StartTLS()
	defer srv.Close()
	c := NewClient("chrome-latest", WithInsecureSkipVerify(), WithPreferIPv4(), WithTimeout(10*time.Second), WithForceHTTP1())
	defer c.Close()
	c.SetAuth(NewDigestAuth("u", "p"))
	for i := 0; i < 2; i++ {
		resp, err := c.Do(context.Background(), &Request{Method: "GET", URL: srv.URL + "/a"})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("request %d: status %d", i+1, resp.StatusCode)
		if resp.StatusCode != 200 {
			t.Errorf("request %d got %d", i+1, resp.StatusCode)
		}
	}
	t.Logf("server saw %d requests", len(log))
}
