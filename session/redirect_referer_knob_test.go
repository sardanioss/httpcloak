package session

import (
	"context"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// By default a redirect hop carries a Referer, because that is what Chrome does.
// This is the control for the two tests below: without it, a knob that silently
// did nothing and a knob that worked would look identical.
func TestRedirectRefererOnByDefault(t *testing.T) {
	srv := newBodyCapture(t, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "hop0",
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.hops) != 2 {
		t.Fatalf("server saw %d hops, want 2", len(srv.hops))
	}
	if !hasHeader(srv.hops[1], "referer") {
		t.Fatal("hop 2 carried no Referer by default; Chrome sends one on every " +
			"hop except an https->http downgrade")
	}
	if got := srv.hops[1].values["referer"]; !strings.Contains(got, "hop0") {
		t.Errorf("hop 2 Referer = %q, want it to name the URL that issued the 302", got)
	}
}

// DisableRedirectReferer suppresses it.
func TestDisableRedirectRefererSuppressesIt(t *testing.T) {
	srv := newBodyCapture(t, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "hop0",
		DisableRedirectReferer: true,
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.hops) != 2 {
		t.Fatalf("server saw %d hops, want 2", len(srv.hops))
	}
	if hasHeader(srv.hops[1], "referer") {
		t.Errorf("hop 2 carried Referer %q despite DisableRedirectReferer",
			srv.hops[1].values["referer"])
	}
}

// And a Referer the caller set on the ORIGINAL request must not be forwarded
// either. Suppressing only the synthesis would leave the caller's own value in
// place, which names the pre-redirect URL and so leaks to the new host exactly
// what the caller asked us not to send.
func TestDisableRedirectRefererDropsACallerSuppliedOne(t *testing.T) {
	srv := newBodyCapture(t, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "hop0",
		Headers:                map[string][]string{"Referer": {"https://caller.example/secret?token=abc"}},
		DisableRedirectReferer: true,
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.hops) != 2 {
		t.Fatalf("server saw %d hops, want 2", len(srv.hops))
	}
	if got := srv.hops[1].values["referer"]; got != "" {
		t.Errorf("hop 2 forwarded the caller's Referer %q; it names the "+
			"pre-redirect URL and must not reach the new host", got)
	}
}

// ExactHeaders has to survive a redirect. Its contract is that nothing else is
// added, and the hop used to rebuild the request without it, so a caller
// mirroring a captured request got their exact bytes on the first request and
// the full preset pipeline on every hop after it, with no error and no warning.
func TestExactHeadersSurviveARedirect(t *testing.T) {
	srv := newBodyCapture(t, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	exact := []fingerprint.HeaderPair{
		{Key: "user-agent", Value: "mirror/1"},
		{Key: "accept", Value: "*/*"},
		{Key: "x-mirror", Value: "1"},
	}

	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "hop0",
		ExactHeaders:           exact,
		DisableRedirectReferer: true, // Referer is the one thing the hop may still add
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.hops) != 2 {
		t.Fatalf("server saw %d hops, want 2", len(srv.hops))
	}

	// Assert the hop matches the FIRST request rather than a literal order.
	// Whatever shape the caller's exact headers produce, the redirect hop has to
	// reproduce it; that is the fix. Pinning a literal order here would also
	// pin an unrelated HTTP/1.1 write-path behaviour that reorders these
	// alphabetically, which hop 1 shows too and which this change does not touch.
	hop1, hop2 := srv.hops[0].headers, srv.hops[1].headers
	if len(hop1) != len(exact) {
		t.Fatalf("hop 1 sent %d headers %v, want exactly the %d given; the preset "+
			"pipeline leaked into the original request", len(hop1), hop1, len(exact))
	}
	if len(hop2) != len(hop1) {
		t.Fatalf("hop 1 sent %v but hop 2 sent %v; ExactHeaders did not survive "+
			"the redirect and the preset pipeline rebuilt the request", hop1, hop2)
	}
	for i := range hop1 {
		if hop2[i] != hop1[i] {
			t.Errorf("header %d is %q on hop 1 and %q on hop 2; the hop must "+
				"reproduce the caller's exact shape", i, hop1[i], hop2[i])
		}
	}
	for _, name := range hop2 {
		if srv.hops[1].values[name] != srv.hops[0].values[name] {
			t.Errorf("header %q is %q on hop 1 and %q on hop 2", name,
				srv.hops[0].values[name], srv.hops[1].values[name])
		}
	}
}
