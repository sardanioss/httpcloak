package session

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// A 307 or 308 must arrive at the next hop with the body the caller gave, and
// the only formulation that catches the loss is asserting what the SERVER
// received: the client-side request object looks correct either way, and the
// hop that lost its body still came back 200.

// hopRecord is one request as it arrived on the wire.
type hopRecord struct {
	method           string
	contentLength    string
	transferEncoding string
	contentType      string
	headers          []string
	values           map[string]string // lowercased name -> value, for tests that assert content
	body             []byte
}

// bodyCapture answers each request with the next status from its list, reading
// the full request body first. Reading the body matters twice over: it is what
// the assertions are about, and a server that replies without draining gets the
// client a reset mid-write.
type bodyCapture struct {
	url      string
	statuses []int // one per hop; the last is the terminal response

	mu   sync.Mutex
	hops []hopRecord
}

func newBodyCapture(t *testing.T, statuses ...int) *bodyCapture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &bodyCapture{url: "http://" + ln.Addr().String() + "/", statuses: statuses}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *bodyCapture) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	rec := hopRecord{method: strings.Fields(strings.TrimSpace(line))[0], values: map[string]string{}}

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		switch name {
		case "content-length":
			rec.contentLength = value
		case "transfer-encoding":
			rec.transferEncoding = value
		case "content-type":
			rec.contentType = value
		}
		if name != "host" && name != "connection" {
			rec.headers = append(rec.headers, name)
			rec.values[name] = value
		}
	}

	// Drain the body before answering, by whichever framing was used.
	switch {
	case rec.transferEncoding == "chunked":
		rec.body = readChunked(br)
	case rec.contentLength != "":
		n, _ := strconv.Atoi(rec.contentLength)
		if n > 0 {
			buf := make([]byte, n)
			if _, err := io.ReadFull(br, buf); err != nil {
				return
			}
			rec.body = buf
		}
	}

	s.mu.Lock()
	s.hops = append(s.hops, rec)
	n := len(s.hops)
	s.mu.Unlock()

	status := 200
	if n <= len(s.statuses) {
		status = s.statuses[n-1]
	}

	if status >= 300 && status < 400 {
		fmt.Fprintf(conn, "HTTP/1.1 %d Redirect\r\nLocation: %shop%d\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, s.url, n)
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 %d OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", status)
}

func readChunked(br *bufio.Reader) []byte {
	var out []byte
	for {
		sizeLine, err := br.ReadString('\n')
		if err != nil {
			return out
		}
		n, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
		if err != nil || n == 0 {
			return out
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return out
		}
		out = append(out, buf...)
		br.ReadString('\n') // trailing CRLF
	}
}

func (s *bodyCapture) recorded() []hopRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]hopRecord, len(s.hops))
	copy(out, s.hops)
	return out
}

func newBodyTestSession(t *testing.T, cfg *protocol.SessionConfig) *Session {
	t.Helper()
	if cfg.Preset == "" {
		cfg.Preset = "chrome-latest"
	}
	cfg.ForceHTTP1 = true
	s := NewSession("", cfg)
	t.Cleanup(func() { s.Close() })
	return s
}

func hasHeader(rec hopRecord, name string) bool {
	for _, h := range rec.headers {
		if h == name {
			return true
		}
	}
	return false
}

// TestRedirect307_PreservesStreamingBody is the regression lock. Before the fix
// the second hop arrived with zero bytes, because Session.Do populates
// BodyReader while the redirect path copied only Body.
//
// The Transfer-Encoding assertion is not incidental: replaying through an
// io.ReadCloser would hide the concrete reader type from the Content-Length
// switch in NewRequestWithContext, and hop 1 would go out chunked while hop 0
// went out with a length — a wire difference mid-chain that no browser produces.
func TestRedirect307_PreservesStreamingBody(t *testing.T) {
	const payload = `{"amount":4200,"currency":"eur"}`

	readers := map[string]func() io.Reader{
		"bytes.Reader":   func() io.Reader { return bytes.NewReader([]byte(payload)) },
		"bytes.Buffer":   func() io.Reader { return bytes.NewBufferString(payload) },
		"strings.Reader": func() io.Reader { return strings.NewReader(payload) },
	}

	for _, status := range []int{307, 308} {
		for name, mk := range readers {
			t.Run(fmt.Sprintf("%d/%s", status, name), func(t *testing.T) {
				srv := newBodyCapture(t, status, 200)
				s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

				resp, err := s.Request(context.Background(), &transport.Request{
					Method:     "POST",
					URL:        srv.url + "hop0",
					Headers:    map[string][]string{"Content-Type": {"application/json"}},
					BodyReader: mk(),
				})
				if err != nil {
					t.Fatalf("Request: %v", err)
				}
				if resp.StatusCode != 200 {
					t.Fatalf("final status = %d, want 200", resp.StatusCode)
				}

				hops := srv.recorded()
				if len(hops) != 2 {
					t.Fatalf("got %d hops, want 2", len(hops))
				}
				if got := string(hops[0].body); got != payload {
					t.Fatalf("hop 0 body = %q, want %q", got, payload)
				}
				if got := string(hops[1].body); got != payload {
					t.Errorf("hop 1 body = %q, want %q — the %d hop lost the body", got, payload, status)
				}
				if hops[1].method != "POST" {
					t.Errorf("hop 1 method = %q, want POST", hops[1].method)
				}
				if want := strconv.Itoa(len(payload)); hops[1].contentLength != want {
					t.Errorf("hop 1 Content-Length = %q, want %q", hops[1].contentLength, want)
				}
				if hops[1].transferEncoding != "" {
					t.Errorf("hop 1 Transfer-Encoding = %q, want none: the replayed hop must be framed "+
						"the same way as hop 0, which used Content-Length", hops[1].transferEncoding)
				}
			})
		}
	}
}

// TestRedirect307_TwiceKeepsBody catches forgetting to carry GetBody onto the
// hop: the first replay would work and the second would find nothing to re-open.
func TestRedirect307_TwiceKeepsBody(t *testing.T) {
	const payload = "one=1&two=2"
	srv := newBodyCapture(t, 307, 307, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	if _, err := s.Request(context.Background(), &transport.Request{
		Method:     "POST",
		URL:        srv.url + "hop0",
		Headers:    map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
		BodyReader: strings.NewReader(payload),
	}); err != nil {
		t.Fatalf("Request: %v", err)
	}

	hops := srv.recorded()
	if len(hops) != 3 {
		t.Fatalf("got %d hops, want 3", len(hops))
	}
	for i, hop := range hops {
		if got := string(hop.body); got != payload {
			t.Errorf("hop %d body = %q, want %q", i, got, payload)
		}
	}
}

// oneShot defeats DeriveGetBody's type switch, standing in for an *os.File or a
// pipe: a body that genuinely cannot be re-read.
type oneShot struct{ io.Reader }

func TestRedirect307_NonReplayableBodyErrors(t *testing.T) {
	srv := newBodyCapture(t, 307, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	resp, err := s.Request(context.Background(), &transport.Request{
		Method:     "POST",
		URL:        srv.url + "hop0",
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		BodyReader: oneShot{strings.NewReader(`{"a":1}`)},
	})

	if !errors.Is(err, transport.ErrBodyNotReplayable) {
		t.Fatalf("err = %v, want ErrBodyNotReplayable", err)
	}
	if resp == nil {
		t.Fatal("want the 3xx returned alongside the error, got nil response")
	}
	if resp.StatusCode != 307 {
		t.Errorf("resp.StatusCode = %d, want 307", resp.StatusCode)
	}
	if n := len(srv.recorded()); n != 1 {
		t.Errorf("%d requests reached the server, want 1: the hop must not be sent bodiless", n)
	}
}

// TestRedirect307_CallerSuppliedGetBody locks the escape hatch for a body the
// type switch cannot see.
func TestRedirect307_CallerSuppliedGetBody(t *testing.T) {
	const payload = `{"a":1}`
	srv := newBodyCapture(t, 307, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	resp, err := s.Request(context.Background(), &transport.Request{
		Method:     "POST",
		URL:        srv.url + "hop0",
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		BodyReader: oneShot{strings.NewReader(payload)},
		GetBody:    func() (io.Reader, error) { return strings.NewReader(payload), nil },
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("final status = %d, want 200", resp.StatusCode)
	}

	hops := srv.recorded()
	if len(hops) != 2 {
		t.Fatalf("got %d hops, want 2", len(hops))
	}
	if got := string(hops[1].body); got != payload {
		t.Errorf("hop 1 body = %q, want %q", got, payload)
	}
}

// TestRedirect302POST_DropsBody guards the other direction: a careless fix that
// carries the body everywhere would break the 301/302/303 POST-to-GET rewrite.
func TestRedirect302POST_DropsBody(t *testing.T) {
	srv := newBodyCapture(t, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	if _, err := s.Request(context.Background(), &transport.Request{
		Method:     "POST",
		URL:        srv.url + "hop0",
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		BodyReader: strings.NewReader(`{"a":1}`),
	}); err != nil {
		t.Fatalf("Request: %v", err)
	}

	hops := srv.recorded()
	if len(hops) != 2 {
		t.Fatalf("got %d hops, want 2", len(hops))
	}
	if hops[1].method != "GET" {
		t.Errorf("hop 1 method = %q, want GET", hops[1].method)
	}
	if len(hops[1].body) != 0 {
		t.Errorf("hop 1 body = %q, want empty", hops[1].body)
	}
	if hops[1].contentType != "" {
		t.Errorf("hop 1 Content-Type = %q, want none: the body is gone, so the header describing it is a lie",
			hops[1].contentType)
	}
}

// TestRedirect307_CarriesRequestFlags locks the per-request options onto the
// hop. They used to be dropped, so a request opting out of client hints got the
// opt-out on the first hop only.
func TestRedirect307_CarriesRequestFlags(t *testing.T) {
	srv := newBodyCapture(t, 307, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	if _, err := s.Request(context.Background(), &transport.Request{
		Method:             "POST",
		URL:                srv.url + "hop0",
		BodyReader:         strings.NewReader("x=1"),
		DisableClientHints: true,
	}); err != nil {
		t.Fatalf("Request: %v", err)
	}

	hops := srv.recorded()
	if len(hops) != 2 {
		t.Fatalf("got %d hops, want 2", len(hops))
	}
	for i, hop := range hops {
		if hasHeader(hop, "sec-ch-ua") {
			t.Errorf("hop %d carries sec-ch-ua despite DisableClientHints", i)
		}
	}
}

func TestTooManyRedirects_SentinelAndResponse(t *testing.T) {
	srv := newBodyCapture(t, 302, 302, 302, 302, 302, 302)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true, MaxRedirects: 2})

	resp, err := s.Request(context.Background(), &transport.Request{
		Method: "GET",
		URL:    srv.url + "hop0",
	})

	if !errors.Is(err, transport.ErrTooManyRedirects) {
		t.Fatalf("err = %v, want ErrTooManyRedirects", err)
	}
	if resp == nil {
		t.Fatal("want the last response returned alongside the error, got nil")
	}
	if resp.StatusCode != 302 {
		t.Errorf("resp.StatusCode = %d, want 302", resp.StatusCode)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Errorf("last response body not readable: %v", err)
	}
}

// TestRetry_ReplaysBodyOnSecondAttempt covers the other half of the same root
// cause: the retry loop re-sends the same request, so a streaming body used to
// arrive empty on attempt two.
func TestRetry_ReplaysBodyOnSecondAttempt(t *testing.T) {
	const payload = "retry-me"
	srv := newBodyCapture(t, 503, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{
		FollowRedirects: true,
		RetryEnabled:    true,
		MaxRetries:      1,
		RetryWaitMin:    1,
		RetryWaitMax:    5,
		RetryOnStatus:   []int{503},
	})

	resp, err := s.Request(context.Background(), &transport.Request{
		Method:     "POST",
		URL:        srv.url + "hop0",
		Headers:    map[string][]string{"Content-Type": {"text/plain"}},
		BodyReader: strings.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("final status = %d, want 200", resp.StatusCode)
	}

	hops := srv.recorded()
	if len(hops) != 2 {
		t.Fatalf("got %d attempts, want 2", len(hops))
	}
	if got := string(hops[1].body); got != payload {
		t.Errorf("attempt 2 body = %q, want %q", got, payload)
	}
	if want := strconv.Itoa(len(payload)); hops[1].contentLength != want {
		t.Errorf("attempt 2 Content-Length = %q, want %q", hops[1].contentLength, want)
	}
}

// TestRetry_NonReplayableBodySkipsRetry locks the deliberate asymmetry with the
// redirect case: a retry is optional, so a body that cannot be replayed disables
// it rather than failing the request.
func TestRetry_NonReplayableBodySkipsRetry(t *testing.T) {
	srv := newBodyCapture(t, 503, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{
		FollowRedirects: true,
		RetryEnabled:    true,
		MaxRetries:      1,
		RetryWaitMin:    1,
		RetryWaitMax:    5,
		RetryOnStatus:   []int{503},
	})

	resp, err := s.Request(context.Background(), &transport.Request{
		Method:     "POST",
		URL:        srv.url + "hop0",
		BodyReader: oneShot{strings.NewReader("nope")},
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if resp.StatusCode != 503 {
		t.Errorf("status = %d, want the 503 handed back unretried", resp.StatusCode)
	}
	if n := len(srv.recorded()); n != 1 {
		t.Errorf("%d attempts reached the server, want 1", n)
	}
}
