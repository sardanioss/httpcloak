package transport

import (
	"context"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/sardanioss/net/http2"
)

func transportWithHTTP2RetriesDisabled(t *testing.T) *Transport {
	t.Helper()
	tr := NewTransportWithConfig("chrome-latest", nil, &TransportConfig{DisableHTTP2Retries: true})
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(tr.Close)
	return tr
}

// A refusal must reach the caller without consuming a second stream. A healthy
// connection remains reusable if the caller explicitly submits another request.
func TestDisableHTTP2RetriesRefusedStream(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, refuseBoth := range []bool{false, true} {
			name := "buffered"
			if streaming {
				name = "streaming"
			}
			if refuseBoth {
				name += "/two_refusals"
			} else {
				name += "/explicit_recovery"
			}
			t.Run(name, func(t *testing.T) {
				resets := map[int]uint32{1: errCodeRefusedStream}
				if refuseBoth {
					resets[2] = errCodeRefusedStream
				}
				s := startH2Server(t, h2Config{ResetStreams: resets})
				tr := transportWithHTTP2RetriesDisabled(t)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				for call := 1; call <= 2; call++ {
					err := callerHTTP2Request(ctx, tr, s.url("/refused"), streaming)
					if call == 1 || refuseBoth {
						assertRefusedStream(t, err)
					} else if err != nil {
						t.Fatal(err)
					}
					assertOneConnection(t, s, call)
					assertHTTP2NoInFlight(t, tr)
				}
			})
		}
	}
}

// Opting out must not discard a healthy connection or retain a failed one.
// GOAWAY and an abrupt close both require a new connection on the next call.
func TestDisableHTTP2RetriesConnectionRecovery(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, reason := range []string{"goaway", "close"} {
			name := "buffered/" + reason
			if streaming {
				name = "streaming/" + reason
			}
			t.Run(name, func(t *testing.T) {
				cfg := h2Config{GoAwayRequests: map[int]uint32{1: 0}}
				if reason == "close" {
					cfg = h2Config{CloseRequests: map[int]bool{1: true}}
				}
				s := startH2Server(t, cfg)
				tr := transportWithHTTP2RetriesDisabled(t)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				err := callerHTTP2Request(ctx, tr, s.url("/recover"), streaming)
				var wrapped *TransportError
				if !errors.As(err, &wrapped) || wrapped.Protocol != "h2" {
					t.Fatalf("HTTP/2 error lost: %v", err)
				}
				assertOneConnection(t, s, 1)
				h2 := tr.snapshot().h2
				h2.connsMu.RLock()
				remaining := len(h2.conns)
				h2.connsMu.RUnlock()
				if remaining != 0 {
					t.Fatal("failed connection still in the pool")
				}
				if err := callerHTTP2Request(ctx, tr, s.url("/recover"), streaming); err != nil {
					t.Fatal(err)
				}
				arrivals := s.attempts()
				if len(arrivals) != 2 || s.connCount() != 2 || arrivals[0].Conn == arrivals[1].Conn {
					t.Fatalf("explicit recovery did not replace the connection: %v\n%s", arrivals, s.dump())
				}
				assertHTTP2NoInFlight(t, tr)
			})
		}
	}
}

func TestDisableHTTP2RetriesCancellationAfterDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := startH2Server(t, h2Config{
		OnRequest:    func(uint32, int) { cancel() },
		ResetStreams: map[int]uint32{1: errCodeRefusedStream},
	})
	tr := transportWithHTTP2RetriesDisabled(t)
	if err := callerHTTP2Request(ctx, tr, s.url("/cancel"), true); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	assertOneConnection(t, s, 1)
	assertHTTP2NoInFlight(t, tr)
}

func TestDisableHTTP2RetriesExplicitPOSTKeepsBody(t *testing.T) {
	body := []byte("0123456789abcdef0123456789abcdef")
	s := startH2Server(t, h2Config{
		ReadToEndStream: true,
		GrantCredit:     true,
		ResetStreams:    map[int]uint32{1: errCodeRefusedStream},
	})
	tr := transportWithHTTP2RetriesDisabled(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for call := 1; call <= 2; call++ {
		response, err := tr.Do(ctx, &Request{Method: "POST", URL: s.url("/upload"), Body: body})
		if call == 1 {
			assertRefusedStream(t, err)
		} else if err != nil || response.StatusCode != 200 {
			t.Fatalf("explicit POST: response=%v error=%v", response, err)
		}
		if response != nil {
			response.Close()
		}
		assertOneConnection(t, s, call)
	}
	streams, headers := s.attempts(), s.decoded()
	if len(headers) != 2 {
		t.Fatalf("got %d header blocks, want 2", len(headers))
	}
	for i, h := range headers {
		declared, err := strconv.Atoi(h["content-length"])
		if err != nil || declared != len(body) || s.dataBytes(streams[i]) != len(body) {
			t.Fatalf("call %d: content-length=%q sent=%d error=%v", i+1, h["content-length"], s.dataBytes(streams[i]), err)
		}
	}
}

// A refused stream must leave the priority chain before the caller retries it.
func TestDisableHTTP2RetriesRefusedStreamLeavesDependencyChain(t *testing.T) {
	s := startDepServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	c := &depClient{t: t, tr: transportWithHTTP2RetriesDisabled(t), s: s, ctx: ctx}
	t.Cleanup(c.done)
	c.send("/doc", "document", 1)
	_, err := c.tr.Do(ctx, &Request{Method: "GET", URL: "https://" + s.addr + "/img-refuse",
		Headers: map[string][]string{"Sec-Fetch-Dest": {"image"}}})
	assertRefusedStream(t, err)
	c.n++
	if caps := s.byPath("/img-refuse"); len(caps) != 1 {
		t.Fatalf("got %d arrivals for one refused request, want 1", len(caps))
	}
	c.send("/img-refuse", "image", 1)
	caps := s.byPath("/img-refuse")
	if len(caps) != 2 || caps[1].dep != 1 {
		t.Fatalf("explicit retry depends on a refused stream: %+v", caps)
	}
	c.send("/after", "image", 1)
	c.expect("/after", caps[1].stream, 183, true)
}

func callerHTTP2Request(ctx context.Context, tr *Transport, url string, streaming bool) error {
	request := &Request{Method: "GET", URL: url}
	if streaming {
		response, err := tr.DoStream(ctx, request)
		if err != nil {
			return err
		}
		defer response.Close()
		_, err = io.Copy(io.Discard, response)
		return err
	}
	response, err := tr.Do(ctx, request)
	if response != nil {
		response.Close()
	}
	return err
}

func assertRefusedStream(t *testing.T, err error) {
	t.Helper()
	var streamErr http2.StreamError
	if !errors.As(err, &streamErr) || streamErr.Code != http2.ErrCodeRefusedStream {
		t.Fatalf("REFUSED_STREAM not preserved: %v", err)
	}
}

func assertHTTP2NoInFlight(t *testing.T, tr *Transport) {
	t.Helper()
	h2 := tr.snapshot().h2
	h2.connsMu.RLock()
	defer h2.connsMu.RUnlock()
	for _, conn := range h2.conns {
		conn.mu.Lock()
		inFlight := conn.inFlight
		conn.mu.Unlock()
		if inFlight != 0 {
			t.Fatalf("connection still has %d requests in flight", inFlight)
		}
	}
}
