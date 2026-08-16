package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// newNoLocationServer answers every request with a 302 that carries no Location,
// which the session treats as the end of the chain rather than an error.
func newNoLocationServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				conn.Read(buf)
				fmt.Fprint(conn, "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}()
		}
	}()
	return "http://" + ln.Addr().String() + "/no-location"
}

// OnRedirect is the seam that lets a caller stop a chain on one specific hop
// without giving up the browser-parity method, Referer, cookie and credential
// rules that following a redirect correctly depends on.

func TestOnRedirect_HaltReturnsTheRedirect(t *testing.T) {
	srv := newBodyCapture(t, 302, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	var seen []*transport.Redirect
	resp, err := s.Request(context.Background(), &transport.Request{
		Method: "GET",
		URL:    srv.url + "hop0",
		OnRedirect: func(r *transport.Redirect) error {
			seen = append(seen, r)
			return transport.ErrUseLastResponse
		},
	})
	if err != nil {
		t.Fatalf("halting must not be an error: %v", err)
	}
	if resp.StatusCode != 302 {
		t.Errorf("status = %d, want the 302 handed back", resp.StatusCode)
	}
	if len(seen) != 1 {
		t.Fatalf("callback fired %d times, want 1", len(seen))
	}
	if len(resp.History) != 0 {
		t.Errorf("History has %d entries, want 0: a halted response must not appear in its own history",
			len(resp.History))
	}
	if n := len(srv.recorded()); n != 1 {
		t.Errorf("%d requests reached the server, want 1", n)
	}
}

func TestOnRedirect_SeesTheHop(t *testing.T) {
	srv := newBodyCapture(t, 307, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	var got *transport.Redirect
	if _, err := s.Request(context.Background(), &transport.Request{
		Method:  "GET",
		URL:     srv.url + "hop0",
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		OnRedirect: func(r *transport.Redirect) error {
			got = r
			return nil
		},
	}); err != nil {
		t.Fatalf("Request: %v", err)
	}

	if got == nil {
		t.Fatal("callback never fired")
	}
	if got.Hop != 1 {
		t.Errorf("Hop = %d, want 1", got.Hop)
	}
	if got.StatusCode != 307 {
		t.Errorf("StatusCode = %d, want 307", got.StatusCode)
	}
	if got.From != srv.url+"hop0" {
		t.Errorf("From = %q, want %q", got.From, srv.url+"hop0")
	}
	if got.To != srv.url+"hop1" {
		t.Errorf("To = %q, want %q", got.To, srv.url+"hop1")
	}
	if got.Method != "GET" {
		t.Errorf("Method = %q, want GET", got.Method)
	}
	if got.CrossOrigin {
		t.Error("CrossOrigin = true for a same-host hop")
	}
	if got.SchemeDowngrade {
		t.Error("SchemeDowngrade = true for an http -> http hop")
	}
	if len(got.Headers) == 0 {
		t.Error("Headers is empty: the 3xx's own headers are the point of the callback")
	}
	u, err := got.ToURL()
	if err != nil {
		t.Fatalf("ToURL: %v", err)
	}
	if u.Path != "/hop1" {
		t.Errorf("ToURL().Path = %q, want /hop1", u.Path)
	}
}

// errRefused stands in for a caller's own sentinel: it must survive the trip
// out unwrapped, or errors.Is at the call site stops working.
var errRefused = errors.New("refused by policy")

func TestOnRedirect_ErrorPropagatesUnwrapped(t *testing.T) {
	srv := newBodyCapture(t, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	resp, err := s.Request(context.Background(), &transport.Request{
		Method: "GET",
		URL:    srv.url + "hop0",
		OnRedirect: func(r *transport.Redirect) error {
			return errRefused
		},
	})
	if !errors.Is(err, errRefused) {
		t.Fatalf("err = %v, want the callback's own error", err)
	}
	if resp != nil {
		t.Error("a refused chain returns no response")
	}
	if n := len(srv.recorded()); n != 1 {
		t.Errorf("%d requests reached the server, want 1", n)
	}
}

// TestOnRedirect_SurvivesToLaterHops catches forgetting to carry OnRedirect onto
// the hop request, which would fire the callback once and then follow the rest
// of the chain unsupervised.
func TestOnRedirect_SurvivesToLaterHops(t *testing.T) {
	srv := newBodyCapture(t, 302, 302, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	var hops []int
	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET",
		URL:    srv.url + "hop0",
		OnRedirect: func(r *transport.Redirect) error {
			hops = append(hops, r.Hop)
			return nil
		},
	}); err != nil {
		t.Fatalf("Request: %v", err)
	}

	want := []int{1, 2, 3}
	if len(hops) != len(want) {
		t.Fatalf("callback fired for hops %v, want %v", hops, want)
	}
	for i := range want {
		if hops[i] != want[i] {
			t.Errorf("hops = %v, want %v", hops, want)
			break
		}
	}
}

// A 3xx with no Location ends the chain rather than continuing it, so there is
// no hop to veto and the callback must not fire.
func TestOnRedirect_NotCalledWithoutLocation(t *testing.T) {
	srv := newNoLocationServer(t)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	called := false
	resp, err := s.Request(context.Background(), &transport.Request{
		Method: "GET",
		URL:    srv,
		OnRedirect: func(r *transport.Redirect) error {
			called = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if resp.StatusCode != 302 {
		t.Errorf("status = %d, want the 302 returned as-is", resp.StatusCode)
	}
	if called {
		t.Error("callback fired for a 3xx with no Location: there is no hop to veto")
	}
}

// The cap is a resource bound, not a policy question. Letting the callback see
// the hop that busts it would let a veto turn ErrTooManyRedirects into a success.
func TestOnRedirect_NotCalledForTheOverCapHop(t *testing.T) {
	srv := newBodyCapture(t, 302, 302, 302, 302)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true, MaxRedirects: 2})

	var hops []int
	_, err := s.Request(context.Background(), &transport.Request{
		Method: "GET",
		URL:    srv.url + "hop0",
		OnRedirect: func(r *transport.Redirect) error {
			hops = append(hops, r.Hop)
			return transport.ErrUseLastResponse
		},
	})
	// The first hop halts, so the cap is never reached here; the assertion that
	// matters is that no callback ever sees Hop > MaxRedirects.
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	for _, h := range hops {
		if h > 2 {
			t.Errorf("callback saw hop %d, above the cap of 2", h)
		}
	}

	// Now without a veto: the chain must die on the cap, and the callback must
	// have been asked exactly twice.
	srv2 := newBodyCapture(t, 302, 302, 302, 302)
	hops = nil
	_, err = s.Request(context.Background(), &transport.Request{
		Method: "GET",
		URL:    srv2.url + "hop0",
		OnRedirect: func(r *transport.Redirect) error {
			hops = append(hops, r.Hop)
			return nil
		},
	})
	if !errors.Is(err, transport.ErrTooManyRedirects) {
		t.Fatalf("err = %v, want ErrTooManyRedirects", err)
	}
	if len(hops) != 2 {
		t.Errorf("callback fired %d times (%v), want 2 — never for the hop that busts the cap", len(hops), hops)
	}
}
