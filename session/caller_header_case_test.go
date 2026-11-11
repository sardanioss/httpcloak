package session

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// The transport sends one spelling of a header name and prefers the
// canonical one. Wherever the session adds a header of its own beside the
// caller's, a caller's lowercase spelling must not be the one that loses:
// a "cookie" copied from DevTools has to reach the server once the jar has
// cookies of its own, and a caller's validator beats the cached one.
func TestCallerLowercaseHeadersSurviveSessionHeaders(t *testing.T) {
	var mu sync.Mutex
	var cookies, inm []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookies = append(cookies, strings.Join(r.Header.Values("Cookie"), " | "))
		inm = append(inm, r.Header.Get("If-None-Match"))
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "jar", Value: "1", Path: "/"})
		w.Header().Set("ETag", `"cached"`)
		io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	for _, proto := range []struct {
		name string
		cfg  protocol.SessionConfig
	}{
		{"h1", protocol.SessionConfig{Preset: "chrome-latest", ForceHTTP1: true, InsecureSkipVerify: true}},
		{"h2", protocol.SessionConfig{Preset: "chrome-latest", ForceHTTP2: true, InsecureSkipVerify: true}},
	} {
		t.Run(proto.name, func(t *testing.T) {
			mu.Lock()
			cookies, inm = nil, nil
			mu.Unlock()
			cfg := proto.cfg
			s := NewSession("", &cfg)
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			headers := map[string][]string{"cookie": {"mine=1"}, "if-none-match": {`"mine"`}}
			for i := range 2 {
				resp, err := s.Request(ctx, &transport.Request{Method: "GET", URL: srv.URL + "/", Headers: headers})
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				resp.Close()
			}
			stream, err := s.RequestStream(ctx, &transport.Request{Method: "GET", URL: srv.URL + "/", Headers: headers})
			if err != nil {
				t.Fatalf("stream: %v", err)
			}
			io.Copy(io.Discard, stream)
			stream.Close()

			mu.Lock()
			defer mu.Unlock()
			// Requests 2 and 3 go out with the jar holding jar=1.
			for i, got := range cookies[1:] {
				if !strings.Contains(got, "mine=1") || !strings.Contains(got, "jar=1") {
					t.Errorf("request %d sent Cookie %q, want both mine=1 and jar=1", i+2, got)
				}
			}
			for i, got := range inm {
				if got != `"mine"` {
					t.Errorf("request %d sent If-None-Match %q, want the caller's", i+1, got)
				}
			}
		})
	}
}

// RequestStream folds every spelling of the caller's Cookie into one even
// when the jar has nothing to add, as the buffered path does. It used to fold
// only when it was adding the jar's, so a fresh session, or one without a
// jar, sent two spellings and the transport kept only the canonical one.
func TestStreamFoldsCallerCookieSpellingsWithAnEmptyJar(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, strings.Join(r.Header.Values("Cookie"), " | "))
		mu.Unlock()
		io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	for _, tc := range []struct {
		name string
		cfg  protocol.SessionConfig
	}{
		{"h1 empty jar", protocol.SessionConfig{Preset: "chrome-latest", ForceHTTP1: true, InsecureSkipVerify: true}},
		{"h2 empty jar", protocol.SessionConfig{Preset: "chrome-latest", ForceHTTP2: true, InsecureSkipVerify: true}},
		{"h2 without jar", protocol.SessionConfig{Preset: "chrome-latest", ForceHTTP2: true, InsecureSkipVerify: true, WithoutCookieJar: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			got = nil
			mu.Unlock()
			cfg := tc.cfg
			s := NewSession("", &cfg)
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			headers := map[string][]string{"cookie": {"a=1"}, "Cookie": {"b=2"}}
			stream, err := s.RequestStream(ctx, &transport.Request{Method: "GET", URL: srv.URL + "/", Headers: headers})
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, stream)
			stream.Close()
			mu.Lock()
			defer mu.Unlock()
			if len(got) != 1 || !strings.Contains(got[0], "a=1") || !strings.Contains(got[0], "b=2") {
				t.Errorf("server saw Cookie %q, want both a=1 and b=2", got)
			}
		})
	}
}
