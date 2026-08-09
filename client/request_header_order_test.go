package client

import (
	"net/url"
	"strings"
	"testing"

	customhttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// SetHeaderOrder is client-wide state behind a mutex, so a caller who needs one
// request ordered differently has to install the order, send, and restore it —
// serializing every concurrent request in the process. Request.HeaderOrder is
// the per-request alternative: it wins over the client order and touches nothing
// shared.

func TestClientEffectiveHeaderOrder_RequestOverridesClient(t *testing.T) {
	c := &Client{}
	c.SetHeaderOrder([]string{"accept", "user-agent"})

	got := c.effectiveHeaderOrder(&Request{HeaderOrder: []string{"x-alpha", "cookie"}})
	if strings.Join(got, ",") != "x-alpha,cookie" {
		t.Errorf("per-request order not used: got %v", got)
	}

	// The client order is read, never written, by a per-request override.
	if strings.Join(c.getHeaderOrder(), ",") != "accept,user-agent" {
		t.Errorf("client order was mutated: got %v", c.getHeaderOrder())
	}
}

func TestClientEffectiveHeaderOrder_FallsBackToClientOrder(t *testing.T) {
	c := &Client{}
	c.SetHeaderOrder([]string{"accept", "user-agent"})

	for name, req := range map[string]*Request{
		"nil request":    nil,
		"unset field":    {},
		"empty, non-nil": {HeaderOrder: []string{}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := c.effectiveHeaderOrder(req); strings.Join(got, ",") != "accept,user-agent" {
				t.Errorf("expected the client order, got %v", got)
			}
		})
	}
}

// applyModeHeaders is where the resolved order reaches the request. This pins
// that a per-request order lands in the ordering key as a prefix, with the
// preset's table still covering the headers it did not name.
func TestClientRequestHeaderOrder_ReachesTheOrderingKey(t *testing.T) {
	preset := fingerprint.Get("chrome-latest")
	if preset == nil {
		t.Skip("chrome-latest preset unavailable")
	}
	c := &Client{preset: preset}
	c.SetHeaderOrder([]string{"user-agent", "accept"})

	target, _ := url.Parse("https://example.com/")
	req := &Request{
		Method:      "GET",
		URL:         target.String(),
		Headers:     map[string][]string{"x-alpha": {"1"}},
		HeaderOrder: []string{"x-alpha", "accept", "user-agent"},
	}
	httpReq, err := customhttp.NewRequest("GET", req.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	applyModeHeaders(httpReq, preset, req, target, c.effectiveHeaderOrder(req))

	order := httpReq.Header[customhttp.HeaderOrderKey]
	want := []string{"x-alpha", "accept", "user-agent"}
	if len(order) < len(want) || strings.Join(order[:len(want)], ",") != strings.Join(want, ",") {
		t.Fatalf("per-request order did not lead the ordering key\n got: %s\nwant prefix: %s",
			strings.Join(order, " → "), strings.Join(want, " → "))
	}
	// Prefix, not replacement: the preset's own headers are still named.
	if len(order) <= len(want) {
		t.Errorf("ordering key was truncated to the caller's list: %v", order)
	}
}
