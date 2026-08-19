package transport

import (
	"context"
	"testing"
	"time"
)

// Response.Headers is a map, so the order the server sent its headers in was
// gone by the time anyone could read it, and buildHeadersMap lowercased the
// names on the way. Code relaying the response onward, a MITM addon handing it
// back to a real browser for instance, therefore emitted a different header
// sequence than the origin did.
//
// HTTP/2 decodes an ordered field list, so recording the order costs one
// append. This runs against the local TLS+ALPN h2 server, so it is offline.
func TestResponseHeaderOrderIsPreservedOnH2(t *testing.T) {
	// The server emits these in this order, which is deliberately not
	// alphabetical: a map-backed reader would hand them back in any order at
	// all, so a lexical result proves nothing.
	h := startHPACKWireServer(t, 0, []string{"z=1", "a=2", "m=3"})

	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + h.addr + "/order"})
	if err != nil {
		t.Skipf("environment did not complete the exchange: %v", err)
	}

	if len(resp.HeaderOrder) == 0 {
		t.Fatal("HeaderOrder is empty on an HTTP/2 response; the arrival order is not " +
			"being recorded")
	}
	// Every recorded name must correspond to a header actually present, or the
	// order describes something the caller cannot look up.
	for _, name := range resp.HeaderOrder {
		if _, ok := resp.Headers[name]; !ok {
			t.Errorf("HeaderOrder names %q, which is not in Headers", name)
		}
	}
	// Three set-cookie fields arrived, so three entries must be recorded: one
	// per occurrence, not one per distinct name.
	n := 0
	for _, name := range resp.HeaderOrder {
		if name == "set-cookie" {
			n++
		}
	}
	if n != 3 {
		t.Errorf("HeaderOrder has %d set-cookie entries, want 3 (one per occurrence): %v",
			n, resp.HeaderOrder)
	}
	// The bookkeeping key must never reach the caller as a header.
	for _, leaked := range []string{"header-order:", "Header-Order:", "pheader-order:"} {
		if _, ok := resp.Headers[leaked]; ok {
			t.Errorf("internal key %q leaked into the response headers", leaked)
		}
	}
}
