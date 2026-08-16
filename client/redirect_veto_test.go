package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// The client layer follows redirects in its own loop, so the callback needs its
// own coverage. Two things here are client-specific and easy to get wrong: the
// deferred close on the underlying *http.Response body, and the retry loop.

// vetoServer answers each request with the next status from its list. The
// redirect bodies are non-empty on purpose: a halted 3xx must still hand its
// body to the caller.
type vetoServer struct {
	url      string
	statuses []int

	mu    sync.Mutex
	count int
}

func newVetoServer(t *testing.T, statuses ...int) *vetoServer {
	t.Helper()
	s := &vetoServer{statuses: statuses}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.count++
		n := s.count
		s.mu.Unlock()

		status := 200
		if n <= len(s.statuses) {
			status = s.statuses[n-1]
		}
		if status >= 300 && status < 400 {
			w.Header().Set("Location", fmt.Sprintf("%s/hop%d", s.url, n))
			w.Header().Set("X-Hop", fmt.Sprint(n))
			w.WriteHeader(status)
			io.WriteString(w, "redirect")
			return
		}
		w.WriteHeader(status)
		io.WriteString(w, "final")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	s.url = srv.URL
	return s
}

func (s *vetoServer) requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func newVetoClient(t *testing.T, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{WithForceHTTP2(), WithInsecureSkipVerify(), WithTimeout(20 * time.Second)}, opts...)
	c := NewClient("chrome-latest", opts...)
	t.Cleanup(func() { c.Close() })
	return c
}

// TestClientOnRedirect_HaltBodyStillReadable is the regression guard for the
// deferred close. doOnce closes the underlying *http.Response body on the way
// out, and only the ReadAll near the end detaches the bytes into the Response
// the caller receives. A halt that returned from inside the redirect branch
// would hand back a body about to be closed, so the halt has to fall through.
func TestClientOnRedirect_HaltBodyStillReadable(t *testing.T) {
	srv := newVetoServer(t, 302, 200)
	c := newVetoClient(t)

	resp, err := c.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.url + "/hop0",
		OnRedirect: func(r *Redirect) error {
			return ErrUseLastResponse
		},
	})
	if err != nil {
		t.Fatalf("halting must not be an error: %v", err)
	}
	if resp.StatusCode != 302 {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("halted response body not readable: %v", err)
	}
	if string(body) != "redirect" {
		t.Errorf("body = %q, want %q", body, "redirect")
	}
	if got := resp.GetHeader("X-Hop"); got != "1" {
		t.Errorf("X-Hop = %q, want 1: the halted 3xx's own headers must survive", got)
	}
	if len(resp.RedirectHistory) != 0 {
		t.Errorf("RedirectHistory has %d entries, want 0", len(resp.RedirectHistory))
	}
	if n := srv.requests(); n != 1 {
		t.Errorf("%d requests reached the server, want 1", n)
	}
}

var errClientRefused = errors.New("refused by policy")

// TestClientOnRedirect_ErrorIsNotRetried covers the retry loop, which treats any
// error as a transient fault worth replaying. A vetoed request must not be sent
// again, and the callback must not be invoked once per attempt.
func TestClientOnRedirect_ErrorIsNotRetried(t *testing.T) {
	srv := newVetoServer(t, 302, 302, 302, 302, 302, 200)
	c := newVetoClient(t, WithRetry(3))

	calls := 0
	resp, err := c.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.url + "/hop0",
		OnRedirect: func(r *Redirect) error {
			calls++
			return errClientRefused
		},
	})
	if !errors.Is(err, errClientRefused) {
		t.Fatalf("err = %v, want the callback's own error unwrapped", err)
	}
	if resp != nil {
		t.Error("a refused chain returns no response")
	}
	if calls != 1 {
		t.Errorf("callback fired %d times, want 1: a vetoed request must not be replayed", calls)
	}
	if n := srv.requests(); n != 1 {
		t.Errorf("%d requests reached the server, want 1", n)
	}
}

func TestClientOnRedirect_SeesTheHopAndSurvives(t *testing.T) {
	srv := newVetoServer(t, 302, 302, 200)
	c := newVetoClient(t)

	var hops []int
	var first *Redirect
	if _, err := c.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.url + "/hop0",
		OnRedirect: func(r *Redirect) error {
			if first == nil {
				first = r
			}
			hops = append(hops, r.Hop)
			return nil
		},
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if len(hops) != 2 || hops[0] != 1 || hops[1] != 2 {
		t.Errorf("hops = %v, want [1 2]", hops)
	}
	if first == nil {
		t.Fatal("callback never fired")
	}
	if first.StatusCode != 302 {
		t.Errorf("StatusCode = %d, want 302", first.StatusCode)
	}
	if first.To != srv.url+"/hop1" {
		t.Errorf("To = %q, want %q", first.To, srv.url+"/hop1")
	}
	if first.Method != "GET" {
		t.Errorf("Method = %q, want GET", first.Method)
	}
	if first.CrossOrigin {
		t.Error("CrossOrigin = true for a same-host hop")
	}
}

func TestClientTooManyRedirects_Sentinel(t *testing.T) {
	srv := newVetoServer(t, 302, 302, 302, 302, 302)
	c := newVetoClient(t, WithRedirects(true, 2))

	_, err := c.Do(context.Background(), &Request{Method: "GET", URL: srv.url + "/hop0"})
	if !errors.Is(err, ErrTooManyRedirects) {
		t.Fatalf("err = %v, want ErrTooManyRedirects", err)
	}
}
