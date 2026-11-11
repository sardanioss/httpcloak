package client

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	customhttp "github.com/sardanioss/http"
)

// The client answers a Digest challenge by sending the request again. These
// tests pin down when it does, against what Chrome 156, Firefox 159 and curl
// 8.11.0 were measured doing:
//
//   - The first answer to a challenge carries nc=00000001.
//   - An answer refused with a new challenge is not sent again. The browsers
//     ask the user instead, and curl returns the 401; here the 401 goes back
//     to the caller. An answer sent up front, to an earlier request's
//     challenge, is answered once more first, which is what Chrome sends when
//     the same credentials are given again.
//   - A challenge with stale=true is answered again, with its new nonce and
//     nc=00000001.
//   - One hop's request goes out at most 32 times, Chrome's bound, whatever
//     the Auth.
//
// Each test asserts what the server saw, through a real send.

// The auth code is the same for every preset, but each preset builds its own
// header block, so every browser family the library mimics is covered.
var digestRetryPresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

var digestRetryProtocols = []struct {
	name  string // as Response.Protocol names it
	force Option
}{
	{"h1", WithForceHTTP1()},
	{"h2", WithForceHTTP2()},
}

// digestRetryRunaway is how many requests a server answers before it gives up
// with a 500, so that a client that never stops fails its test at once rather
// than at its timeout.
const digestRetryRunaway = 100

// digestRetryRequest is one request as the server saw it.
type digestRetryRequest struct {
	path   string
	authz  string            // the Authorization header, "" for none
	params map[string]string // its Digest parameters, nil when it is not Digest
	valid  bool              // the Digest response hashes right for user:pass
	body   string
}

// String gives the request's path, then "none" when it carried no
// Authorization, or the nonce and nc of the Digest answer it carried, marked
// "(wrong)" when the answer does not hash right for user:pass.
func (r digestRetryRequest) String() string {
	switch {
	case r.authz == "":
		return r.path + " none"
	case r.params == nil:
		return r.path + " " + r.authz
	case !r.valid:
		return fmt.Sprintf("%s %s nc=%s (wrong)", r.path, r.params["nonce"], r.params["nc"])
	}
	return fmt.Sprintf("%s %s nc=%s", r.path, r.params["nonce"], r.params["nc"])
}

// digestRetryServer records every request it gets and answers each one with
// respond, which runs with mu held and may set response headers on h.
type digestRetryServer struct {
	url string // https://127.0.0.1:port, no trailing slash

	mu       sync.Mutex
	nonces   int
	requests []digestRetryRequest
	respond  func(s *digestRetryServer, r digestRetryRequest, h http.Header) int
}

func newDigestRetryServer(t *testing.T, respond func(s *digestRetryServer, r digestRetryRequest, h http.Header) int) *digestRetryServer {
	t.Helper()
	s := &digestRetryServer{respond: respond}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req := digestRetryRequest{path: r.URL.Path, authz: r.Header.Get("Authorization"), body: string(body)}
		req.params = parseDigestRetryAnswer(req.authz)
		req.valid = req.params != nil && digestRetryHashesRight(req.params, r.Method)

		s.mu.Lock()
		s.requests = append(s.requests, req)
		status := http.StatusInternalServerError
		if len(s.requests) <= digestRetryRunaway {
			status = s.respond(s, req, w.Header())
		}
		s.mu.Unlock()

		w.WriteHeader(status)
		io.WriteString(w, http.StatusText(status))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

// challenge sets a Digest challenge in realm "r" with a new nonce, n1, n2 and
// so on in the order issued, and returns the nonce. It runs with mu held.
func (s *digestRetryServer) challenge(h http.Header, stale bool) string {
	s.nonces++
	nonce := fmt.Sprintf("n%d", s.nonces)
	s.challengeWith(h, nonce, stale)
	return nonce
}

func (s *digestRetryServer) challengeWith(h http.Header, nonce string, stale bool) {
	c := fmt.Sprintf(`Digest realm="r", nonce="%s", qop="auth"`, nonce)
	if stale {
		c += ", stale=true"
	}
	h.Set("WWW-Authenticate", c)
}

func (s *digestRetryServer) sent() []digestRetryRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]digestRetryRequest(nil), s.requests...)
}

// wantSent fails unless the server saw exactly want, one String per request
// in arrival order.
func (s *digestRetryServer) wantSent(t *testing.T, want ...string) {
	t.Helper()
	sent := s.sent()
	got := make([]string, len(sent))
	for i, r := range sent {
		got[i] = r.String()
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the server saw %d requests:\n  %s\nwant %d:\n  %s",
			len(got), strings.Join(got, "\n  "), len(want), strings.Join(want, "\n  "))
	}
}

// parseDigestRetryAnswer returns the parameters of a Digest Authorization
// header, or nil when it is not one.
func parseDigestRetryAnswer(h string) map[string]string {
	if !strings.HasPrefix(h, "Digest ") {
		return nil
	}
	params := map[string]string{}
	rest := h[len("Digest "):]
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			break
		}
		key := rest[:eq]
		rest = rest[eq+1:]
		var value string
		if strings.HasPrefix(rest, `"`) {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				return nil
			}
			value, rest = rest[1:1+end], rest[2+end:]
		} else if end := strings.IndexByte(rest, ','); end >= 0 {
			value, rest = rest[:end], rest[end:]
		} else {
			value, rest = rest, ""
		}
		params[key] = value
	}
	return params
}

// digestRetryHashesRight reports whether a qop=auth answer's response is the
// one RFC 7616 gives for user:pass in realm "r".
func digestRetryHashesRight(p map[string]string, method string) bool {
	md5hex := func(s string) string {
		sum := md5.Sum([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	ha1 := md5hex("user:r:pass")
	ha2 := md5hex(method + ":" + p["uri"])
	want := md5hex(ha1 + ":" + p["nonce"] + ":" + p["nc"] + ":" + p["cnonce"] + ":" + p["qop"] + ":" + ha2)
	return p["username"] == "user" && p["realm"] == "r" && p["qop"] == "auth" && p["response"] == want
}

// digestRetryClient is a client for one preset, forced onto one protocol.
type digestRetryClient struct {
	c     *Client
	proto string
}

// digestRetryEach runs f once per preset and protocol, with a function that
// makes a client for them using auth.
func digestRetryEach(t *testing.T, f func(t *testing.T, newClient func(auth Auth) digestRetryClient)) {
	for _, preset := range digestRetryPresets {
		for _, proto := range digestRetryProtocols {
			t.Run(preset+"/"+proto.name, func(t *testing.T) {
				f(t, func(auth Auth) digestRetryClient {
					c := NewClient(preset,
						proto.force,
						WithInsecureSkipVerify(), // httptest's certificate
						WithPreferIPv4(),         // the server listens on 127.0.0.1 only
						WithTimeout(10*time.Second),
					)
					t.Cleanup(func() { c.Close() })
					c.SetAuth(auth)
					return digestRetryClient{c: c, proto: proto.name}
				})
			})
		}
	}
}

// do sends one request and fails the test unless it comes back with
// wantStatus over the protocol the client is forced onto.
func (dc digestRetryClient) do(t *testing.T, method, url, body string, wantStatus int) *Response {
	t.Helper()
	req := &Request{Method: method, URL: url}
	if body != "" {
		req.Body = strings.NewReader(body)
	}
	resp, err := dc.c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	if resp.Protocol != dc.proto {
		t.Fatalf("%s %s went over %s, want %s", method, url, resp.Protocol, dc.proto)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s %s: status %d, want %d", method, url, resp.StatusCode, wantStatus)
	}
	return resp
}

// TestDigestRetryFirstAnswerCountsFromOne covers a challenge that is answered
// and accepted. The answer counts from 00000001, and is otherwise what it has
// always been. The next request answers the same challenge at once, counting
// on, as Chrome and Firefox sent 00000002 there.
func TestDigestRetryFirstAnswerCountsFromOne(t *testing.T) {
	answer := regexp.MustCompile(`^Digest username="user", realm="r", nonce="abc", uri="/x", response="[0-9a-f]{32}", qop=auth, nc=00000001, cnonce="[0-9a-f]{16}", opaque="op", algorithm=MD5$`)
	digestRetryEach(t, func(t *testing.T, newClient func(Auth) digestRetryClient) {
		s := newDigestRetryServer(t, func(s *digestRetryServer, r digestRetryRequest, h http.Header) int {
			if r.valid {
				return http.StatusOK
			}
			h.Set("WWW-Authenticate", `Digest realm="r", nonce="abc", qop="auth", opaque="op", algorithm=MD5`)
			return http.StatusUnauthorized
		})
		c := newClient(NewDigestAuth("user", "pass"))

		c.do(t, "GET", s.url+"/x", "", http.StatusOK)
		s.wantSent(t, "/x none", "/x abc nc=00000001")
		if sent := s.sent(); len(sent) == 2 && !answer.MatchString(sent[1].authz) {
			t.Errorf("the answer was\n  %s\nwant it to match\n  %s", sent[1].authz, answer)
		}

		c.do(t, "GET", s.url+"/x", "", http.StatusOK)
		s.wantSent(t, "/x none", "/x abc nc=00000001", "/x abc nc=00000002")
	})
}

// TestDigestRetryRefusedAnswerIsReturned covers wrong credentials: the answer
// gets another challenge without stale=true. The client used to answer that
// one too, and the next, until its timeout ran out. Now the 401 goes back to
// the caller after one answer, and the refused challenge is forgotten: the
// next request carries no answer, as the browsers dropped theirs.
func TestDigestRetryRefusedAnswerIsReturned(t *testing.T) {
	cases := []struct {
		name string
		// sameNonce makes the server send nonce "abc" in every challenge.
		sameNonce bool
		// answered are the nonces the two answers go out with, and refusal is
		// the one in the challenge that refuses the first.
		answered [2]string
		refusal  string
	}{
		{"fresh nonce", false, [2]string{"n1", "n3"}, "n2"},
		{"same nonce", true, [2]string{"abc", "abc"}, "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			digestRetryEach(t, func(t *testing.T, newClient func(Auth) digestRetryClient) {
				s := newDigestRetryServer(t, func(s *digestRetryServer, r digestRetryRequest, h http.Header) int {
					if tc.sameNonce {
						s.challengeWith(h, "abc", false)
					} else {
						s.challenge(h, false)
					}
					return http.StatusUnauthorized
				})
				c := newClient(NewDigestAuth("user", "wrong"))

				resp := c.do(t, "GET", s.url+"/x", "", http.StatusUnauthorized)
				s.wantSent(t, "/x none", "/x "+tc.answered[0]+" nc=00000001 (wrong)")
				if got := resp.GetHeader("WWW-Authenticate"); !strings.Contains(got, `nonce="`+tc.refusal+`"`) {
					t.Errorf("the 401 came back with WWW-Authenticate %q, want the refusal's own challenge", got)
				}

				c.do(t, "GET", s.url+"/x", "", http.StatusUnauthorized)
				s.wantSent(t, "/x none", "/x "+tc.answered[0]+" nc=00000001 (wrong)",
					"/x none", "/x "+tc.answered[1]+" nc=00000001 (wrong)")
			})
		})
	}
}

// TestDigestRetryStaleAnswerIsResent covers an answer refused only because its
// nonce had expired. The new challenge's nonce is answered from 00000001,
// and the body goes out again with it.
func TestDigestRetryStaleAnswerIsResent(t *testing.T) {
	digestRetryEach(t, func(t *testing.T, newClient func(Auth) digestRetryClient) {
		var first, second string
		s := newDigestRetryServer(t, func(s *digestRetryServer, r digestRetryRequest, h http.Header) int {
			switch {
			case r.params == nil:
				first = s.challenge(h, false)
			case r.valid && r.params["nonce"] == first:
				second = s.challenge(h, true)
			case r.valid && r.params["nonce"] == second:
				return http.StatusOK
			default:
				s.challenge(h, false)
			}
			return http.StatusUnauthorized
		})
		c := newClient(NewDigestAuth("user", "pass"))

		c.do(t, "POST", s.url+"/x", "payload", http.StatusOK)
		s.wantSent(t, "/x none", "/x n1 nc=00000001", "/x n2 nc=00000001")
		for i, r := range s.sent() {
			if r.body != "payload" {
				t.Errorf("request %d had body %q, want %q", i+1, r.body, "payload")
			}
		}
	})
}

// TestDigestRetryStaleResendsStopAtChromesBound covers a server that answers
// every answer with stale=true. Chrome resent the request with each new nonce
// until it had gone out 32 times, then failed it. The client sends it as many
// times, and then returns the last 401.
func TestDigestRetryStaleResendsStopAtChromesBound(t *testing.T) {
	digestRetryEach(t, func(t *testing.T, newClient func(Auth) digestRetryClient) {
		s := newDigestRetryServer(t, func(s *digestRetryServer, r digestRetryRequest, h http.Header) int {
			s.challenge(h, r.params != nil)
			return http.StatusUnauthorized
		})
		c := newClient(NewDigestAuth("user", "pass"))

		c.do(t, "GET", s.url+"/x", "", http.StatusUnauthorized)
		want := []string{"/x none"}
		for i := 1; i <= 31; i++ {
			want = append(want, fmt.Sprintf("/x n%d nc=00000001", i))
		}
		s.wantSent(t, want...)
	})
}

// digestRetryAlwaysAuth is an Auth whose HandleChallenge asks to answer every
// 401, as a custom one may. Its header numbers each Apply.
type digestRetryAlwaysAuth struct {
	mu      sync.Mutex
	applies int
}

func (a *digestRetryAlwaysAuth) Apply(req *customhttp.Request) error {
	a.mu.Lock()
	a.applies++
	n := a.applies
	a.mu.Unlock()
	req.Header.Set("Authorization", fmt.Sprintf("Custom %d", n))
	return nil
}

func (a *digestRetryAlwaysAuth) HandleChallenge(*customhttp.Response, *customhttp.Request) (bool, error) {
	return true, nil
}

// TestDigestRetryBoundCoversCustomAuth covers the bound for an Auth that never
// stops asking for a resend. The request goes out 32 times and the last 401
// comes back. Apply runs once per send: it also used to run once more on each
// request that was about to be dropped.
func TestDigestRetryBoundCoversCustomAuth(t *testing.T) {
	digestRetryEach(t, func(t *testing.T, newClient func(Auth) digestRetryClient) {
		s := newDigestRetryServer(t, func(*digestRetryServer, digestRetryRequest, http.Header) int {
			return http.StatusUnauthorized
		})
		auth := &digestRetryAlwaysAuth{}
		c := newClient(auth)

		c.do(t, "GET", s.url+"/x", "", http.StatusUnauthorized)
		want := make([]string, 32)
		for i := range want {
			want[i] = fmt.Sprintf("/x Custom %d", i+1)
		}
		s.wantSent(t, want...)
	})
}

// TestDigestRetryPreemptiveAnswerRefused covers a request that answers the
// last challenge at once, when the server has since expired its nonce. Such
// an answer, refused without stale=true, is answered once more with the new
// nonce from 00000001: the server may have changed nonces without saying so,
// and that is what Chrome sends when the same credentials are given again.
// With stale=true the request is resent the same way. If the fresh answer is
// refused in turn, its 401 is returned and the challenge forgotten, so the
// request after it starts over with no answer.
func TestDigestRetryPreemptiveAnswerRefused(t *testing.T) {
	cases := []struct {
		name  string
		stale bool
		// lock refuses every answer once the first has been accepted.
		lock bool
		// second and third are the statuses the second and third requests come
		// back with; third is 0 when there is no third request.
		second, third int
		want          []string
	}{
		{"fresh challenge", false, false, http.StatusOK, 0, []string{
			"/x none", "/x n1 nc=00000001", // accepted, after which n1 expires
			"/x n1 nc=00000002", // refused with n2
			"/x n2 nc=00000001", // answered once more, accepted
		}},
		{"stale challenge", true, false, http.StatusOK, 0, []string{
			"/x none", "/x n1 nc=00000001",
			"/x n1 nc=00000002", // refused with n2, stale
			"/x n2 nc=00000001",
		}},
		{"refused again", false, true, http.StatusUnauthorized, http.StatusUnauthorized, []string{
			"/x none", "/x n1 nc=00000001", // accepted, after which nothing is
			"/x n1 nc=00000002",            // refused with n2
			"/x n2 nc=00000001",            // answered once more, refused with n3: returned
			"/x none", "/x n4 nc=00000001", // n3 forgotten; refused with n5: returned
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			digestRetryEach(t, func(t *testing.T, newClient func(Auth) digestRetryClient) {
				// Each nonce is good for one request.
				var current string
				used := map[string]bool{}
				locked := false
				s := newDigestRetryServer(t, func(s *digestRetryServer, r digestRetryRequest, h http.Header) int {
					switch {
					case r.valid && r.params["nonce"] == current && !used[current] && !locked:
						used[current] = true
						locked = tc.lock
						return http.StatusOK
					case r.valid && used[r.params["nonce"]]:
						current = s.challenge(h, tc.stale)
					default:
						current = s.challenge(h, false)
					}
					return http.StatusUnauthorized
				})
				c := newClient(NewDigestAuth("user", "pass"))

				c.do(t, "GET", s.url+"/x", "", http.StatusOK)
				c.do(t, "GET", s.url+"/x", "", tc.second)
				if tc.third != 0 {
					c.do(t, "GET", s.url+"/x", "", tc.third)
				}
				s.wantSent(t, tc.want...)
			})
		})
	}
}

// TestDigestRetryBoundIsPerHop covers a redirect. Chrome follows each hop with
// a new transaction, so the hop gets the whole bound of its own, whatever
// the hop before it used.
func TestDigestRetryBoundIsPerHop(t *testing.T) {
	digestRetryEach(t, func(t *testing.T, newClient func(Auth) digestRetryClient) {
		var start string
		s := newDigestRetryServer(t, func(s *digestRetryServer, r digestRetryRequest, h http.Header) int {
			if r.path == "/start" {
				if r.valid && r.params["nonce"] == start {
					h.Set("Location", "/next")
					return http.StatusFound
				}
				start = s.challenge(h, false)
				return http.StatusUnauthorized
			}
			s.challenge(h, r.params != nil)
			return http.StatusUnauthorized
		})
		c := newClient(NewDigestAuth("user", "pass"))

		resp := c.do(t, "GET", s.url+"/start", "", http.StatusUnauthorized)
		if len(resp.RedirectHistory) != 1 {
			t.Errorf("the chain took %d hops, want 1", len(resp.RedirectHistory))
		}
		// /start is resent once with its answer. /next first answers n1 at
		// once, then is resent 31 times, with n2 to n32.
		want := []string{"/start none", "/start n1 nc=00000001", "/next n1 nc=00000002"}
		for i := 2; i <= 32; i++ {
			want = append(want, fmt.Sprintf("/next n%d nc=00000001", i))
		}
		s.wantSent(t, want...)
	})
}

// TestDigestAuthSharedAcrossRequests sends requests at once through one
// client, which all share its DigestAuth. Each answer counts nc up and each
// challenge replaces the stored one, and nothing guarded either, so under
// go test -race they raced. Every answer hashes right here, so every request
// should come back 200.
func TestDigestAuthSharedAcrossRequests(t *testing.T) {
	for _, proto := range digestRetryProtocols {
		t.Run(proto.name, func(t *testing.T) {
			s := newDigestRetryServer(t, func(s *digestRetryServer, r digestRetryRequest, h http.Header) int {
				if r.valid {
					return http.StatusOK
				}
				s.challenge(h, false)
				return http.StatusUnauthorized
			})
			c := NewClient("chrome-latest", proto.force,
				WithInsecureSkipVerify(), // httptest's certificate
				WithPreferIPv4(),         // the server listens on 127.0.0.1 only
				WithTimeout(10*time.Second),
			)
			t.Cleanup(func() { c.Close() })
			c.SetAuth(NewDigestAuth("user", "pass"))

			const n = 16
			var wg sync.WaitGroup
			errs := make(chan error, n)
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					resp, err := c.Do(context.Background(), &Request{Method: "GET", URL: s.url + "/x"})
					switch {
					case err != nil:
						errs <- err
					case resp.StatusCode != http.StatusOK:
						errs <- fmt.Errorf("status %d, want 200", resp.StatusCode)
					}
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
		})
	}
}
