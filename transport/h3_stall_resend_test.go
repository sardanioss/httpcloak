package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
)

// When an HTTP/3 request whose answer is slow goes out again. roundTripHTTP3
// gives the first attempt h3StallWindow (5 s) to get its answer's headers and
// then sends the request again on a new connection, for a QUIC path that keeps
// its connection alive but carries nothing. It did that for any request whose
// body was not a stream, so a POST whose answer took more than 5 s (a payment
// being processed) went out twice, and the caller got the second answer as an
// ordinary success. It now goes again only when the first attempt never had a
// connection to write it on, or when it is idempotent; a POST that went out
// waits for its answer within its own deadline.

// slowH3Origin answers each request after delay, and counts each method.
func slowH3Origin(t *testing.T, delay func(method string, n int32) time.Duration) (url string, seen func(method string) int32) {
	t.Helper()
	var mu sync.Mutex
	counts := map[string]int32{}
	url = startH3Origin(t, shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		counts[r.Method]++
		n := counts[r.Method]
		mu.Unlock()
		select {
		case <-time.After(delay(r.Method, n)):
		case <-r.Context().Done():
			return
		}
		w.Write([]byte("ok"))
	}))
	return url, func(method string) int32 {
		mu.Lock()
		defer mu.Unlock()
		return counts[method]
	}
}

func h3Transport(t *testing.T, proto Protocol) *Transport {
	t.Helper()
	tr := NewTransport("chrome-146")
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(proto)
	t.Cleanup(tr.Close)
	return tr
}

func TestASlowPostOverHTTP3GoesOnce(t *testing.T) {
	cases := []struct {
		name   string
		proto  Protocol
		cached bool
		body   []byte
	}{
		{"forced, body", ProtocolHTTP3, false, []byte("charge=100")},
		{"forced, no body (as the C library passes an empty one)", ProtocolHTTP3, false, nil},
		{"auto, host cached as HTTP/3", ProtocolAuto, true, []byte("charge=100")},
		{"auto, HTTP/3 wins the race", ProtocolAuto, false, []byte("charge=100")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			const answerAfter = h3StallWindow + 2*time.Second
			url, seen := slowH3Origin(t, func(string, int32) time.Duration { return answerAfter })
			tr := h3Transport(t, c.proto)
			if c.cached {
				tr.cacheProtocol(extractHost(url), ProtocolHTTP3)
			}

			start := time.Now()
			resp, err := tr.Do(context.Background(), &Request{Method: "POST", URL: url + "pay", Body: c.body, Timeout: 20 * time.Second})
			if err != nil {
				t.Fatalf("the POST should have waited for its answer: %v", err)
			}
			if resp.StatusCode != 200 || resp.Protocol != "h3" {
				t.Fatalf("got %d over %s, want 200 over h3", resp.StatusCode, resp.Protocol)
			}
			if took := time.Since(start); took < answerAfter {
				t.Fatalf("answered after %v, before the server answered the first attempt", took)
			}
			if n := seen("POST"); n != 1 {
				t.Fatalf("server read the POST %d times, want once", n)
			}
		})
	}
}

// A GET may be sent again, and still is: the first attempt's answer is held
// past the window, the second comes at once.
func TestASlowGetOverHTTP3IsSentAgain(t *testing.T) {
	url, seen := slowH3Origin(t, func(_ string, n int32) time.Duration {
		if n == 1 {
			return time.Minute
		}
		return 0
	})
	tr := h3Transport(t, ProtocolHTTP3)

	start := time.Now()
	resp, err := tr.Do(context.Background(), &Request{Method: "GET", URL: url, Timeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("the GET should have gone again after the stall: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if took := time.Since(start); took > h3StallWindow+3*time.Second {
		t.Fatalf("answered after %v: the GET waited out the first attempt", took)
	}
	if n := seen("GET"); n != 2 {
		t.Fatalf("server read the GET %d times, want twice", n)
	}
}

// stallFirstQUICConn relays datagrams between clients and target, but drops
// every packet of the first QUIC connection a client starts: its handshake
// stalls and never completes, while a later connection goes through. A
// connection is told by the destination connection ID of its long-header
// packets, which until the server answers stays the one the client chose.
func stallFirstQUICConn(t *testing.T, target string) (addr string) {
	t.Helper()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	up, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	var first []byte
	relays := map[string]*net.UDPConn{}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, client, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			p := buf[:n]
			if len(p) > 6 && p[0]&0x80 != 0 && len(p) >= 6+int(p[5]) {
				dcid := p[6 : 6+int(p[5])]
				if first == nil {
					first = append([]byte(nil), dcid...)
				}
				if bytes.Equal(dcid, first) {
					continue
				}
			}
			relay, ok := relays[client.String()]
			if !ok {
				relay, err = net.DialUDP("udp", nil, up)
				if err != nil {
					return
				}
				relays[client.String()] = relay
				t.Cleanup(func() { relay.Close() })
				go func(relay *net.UDPConn, client *net.UDPAddr) {
					b := make([]byte, 65535)
					for {
						n, err := relay.Read(b)
						if err != nil {
							return
						}
						ln.WriteToUDP(b[:n], client)
					}
				}(relay, client)
			}
			relay.Write(p)
		}
	}()
	return ln.LocalAddr().String()
}

// A POST whose QUIC handshake stalls never had a connection to be written on,
// so it may still go again on a new connection once the window is out.
func TestAPostWhoseHTTP3HandshakeStalledGoesAgain(t *testing.T) {
	url, seen := slowH3Origin(t, func(string, int32) time.Duration { return 0 })
	addr := stallFirstQUICConn(t, url[len("https://"):len(url)-1])

	tr := h3Transport(t, ProtocolHTTP3)
	resp, err := tr.Do(context.Background(), &Request{Method: "POST", URL: "https://" + addr + "/pay", Body: []byte("charge=100"), Timeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("the POST should have gone on a new connection: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if n := seen("POST"); n != 1 {
		t.Fatalf("server read the POST %d times, want once", n)
	}
}
