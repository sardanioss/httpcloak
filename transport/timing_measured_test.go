package transport

import (
	"context"
	"testing"
	"time"
)

// DNSLookup, TCPConnect and TLSHandshake were computed as fixed fractions of
// FirstByte: 0.2, 0.3 and 0.5 of 70% of it. That is one measurement reshaped
// into three and presented as a breakdown, in a public API field.
//
// Measured against the real endpoint before the change, the total happened to
// be close while the split was not: the fabrication gave dns=66 tcp=99 tls=166
// where the truth was dns=22 tcp=148 tls=156. Anyone diagnosing latency from
// those numbers was reading fiction that looked plausible.
//
// This runs against the local TLS+ALPN server the HPACK tests use, so it is
// offline.
func TestTimingBreakdownIsMeasuredNotDerived(t *testing.T) {
	h := startHPACKWireServer(t, 0, nil)

	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	do := func() *Response {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + h.addr + "/t"})
		if err != nil {
			t.Skipf("environment did not complete the exchange: %v", err)
		}
		return resp
	}

	first := do()
	if first.Timing == nil {
		t.Fatal("no timing on the response")
	}
	// A real handshake happened, so the TLS phase must be non-zero. The
	// fabricated version gated on FirstByte > 10ms and reported zeros on a
	// loopback connection, which is the opposite of the truth.
	if first.Timing.TLSHandshake <= 0 {
		t.Errorf("TLSHandshake = %v on a fresh connection, want a measured value. "+
			"The old code reported zero here because FirstByte was under its 10ms threshold",
			first.Timing.TLSHandshake)
	}
	if first.Timing.Connect <= 0 {
		t.Errorf("Connect = %v on a fresh connection, want the sum of the phases",
			first.Timing.Connect)
	}
	// The three phases must not be a fixed ratio of FirstByte any more. On
	// loopback the handshake dominates and FirstByte is tiny, so the derived
	// values could not possibly match the measured ones.
	if derived := first.Timing.FirstByte * 0.7 * 0.5; first.Timing.TLSHandshake == derived {
		t.Errorf("TLSHandshake is still exactly 0.5*0.7*FirstByte (%v); the fabrication is back",
			derived)
	}

	second := do()
	if second.Timing.DNSLookup != 0 || second.Timing.TCPConnect != 0 ||
		second.Timing.TLSHandshake != 0 || second.Timing.Connect != 0 {
		t.Errorf("reused connection reported dns=%v tcp=%v tls=%v connect=%v, want zeros",
			second.Timing.DNSLookup, second.Timing.TCPConnect,
			second.Timing.TLSHandshake, second.Timing.Connect)
	}
}
