package session

import (
	"context"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// refererOnHop sends one GET that the server redirects once and returns what
// the redirected request carried as its Referer, and whether it carried one.
func refererOnHop(t *testing.T, referer string, disable bool) (string, bool) {
	t.Helper()
	srv := newBodyCapture(t, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	req := &transport.Request{Method: "GET", URL: srv.url + "hop0", DisableRedirectReferer: disable}
	if referer != "" {
		req.Headers = map[string][]string{"Referer": {strings.ReplaceAll(referer, "{server}", srv.url)}}
	}
	if _, err := s.Request(context.Background(), req); err != nil {
		t.Fatalf("request: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.hops) != 2 {
		t.Fatalf("server saw %d hops, want 2", len(srv.hops))
	}
	return strings.ReplaceAll(srv.hops[1].values["referer"], srv.url, "{server}"), hasHeader(srv.hops[1], "referer")
}

// A redirect does not change who made the request, so the hop carries the
// referrer the request had: the page, never the URL that redirected. Chrome
// 156 sends the page's whole URL to a hop on the page's origin.
func TestARedirectKeepsTheReferrerOfItsRequest(t *testing.T) {
	if got, _ := refererOnHop(t, "{server}page?q=1", false); got != "{server}page?q=1" {
		t.Errorf("the hop's Referer = %q, want the request's own, {server}page?q=1", got)
	}
}

// And the page's origin alone to a hop on another: a referrer on another
// origin than the server is cut down to its origin.
func TestARedirectToAnotherOriginCarriesTheReferrersOrigin(t *testing.T) {
	if got, _ := refererOnHop(t, "http://caller.example/secret?token=abc", false); got != "http://caller.example/" {
		t.Errorf("the hop's Referer = %q, want the referrer's origin, http://caller.example/", got)
	}
}

// A request that had no referrer (an address typed, a bookmark opened) is
// followed with none: the URL that redirected is nobody's referrer.
func TestARedirectAddsNoRefererOfItsOwn(t *testing.T) {
	if got, sent := refererOnHop(t, "", false); sent {
		t.Errorf("the hop carried Referer %q though the request had none", got)
	}
}

// DisableRedirectReferer keeps the request's Referer off every hop.
func TestDisableRedirectRefererDropsTheRequestsOwn(t *testing.T) {
	if got, sent := refererOnHop(t, "{server}page", true); sent {
		t.Errorf("the hop carried Referer %q despite DisableRedirectReferer", got)
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
		ExactHeaders: exact,
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.hops) != 2 {
		t.Fatalf("server saw %d hops, want 2", len(srv.hops))
	}

	// Both hops must carry exactly the given names, in the given order. The
	// order half is not incidental: these are deliberately not alphabetical
	// (user-agent before accept), so a writer that sorts its output fails here.
	want := []string{"user-agent", "accept", "x-mirror"}
	hop1, hop2 := srv.hops[0].headers, srv.hops[1].headers
	if len(hop1) != len(exact) {
		t.Fatalf("hop 1 sent %d headers %v, want exactly the %d given; the preset "+
			"pipeline leaked into the original request", len(hop1), hop1, len(exact))
	}
	for i := range want {
		if hop1[i] != want[i] {
			t.Errorf("hop 1 header %d is %q, want %q; ExactHeaders puts the pairs "+
				"on the wire in the order given", i, hop1[i], want[i])
		}
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
