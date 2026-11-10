//go:build hctest

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// A failure crosses to a binding with what its types say about it beside its
// message: the kind (code), whether the request is known never to have reached
// the server (not_sent), and the status a proxy refused the tunnel with. Each
// case here is a real request through httpcloak_request.
//
// Run with: go test -tags hctest -run FailuresCross .

// listen serves each connection with handle until the test ends.
func listen(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	return ln.Addr().String()
}

func nothingListens(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// answering reads a request and writes answer, or holds the connection for
// hold first when answer is empty.
func answering(answer string, hold time.Duration) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		io.Copy(io.Discard, req.Body)
		time.Sleep(hold)
		io.WriteString(c, answer)
	}
}

func TestFailuresCrossWithWhatTheirTypesSay(t *testing.T) {
	closed := nothingListens(t)
	proxy407 := listen(t, answering("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 0\r\n\r\n", 0))
	silent := listen(t, answering("", 3*time.Second))
	hangsUp := listen(t, answering("", 0))
	var loop string
	loop = listen(t, func(c net.Conn) {
		answering(fmt.Sprintf("HTTP/1.1 302 Found\r\nLocation: http://%s/again\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", loop), 0)(c)
	})

	cases := []struct {
		name    string
		session string
		request string
		want    ErrorResponse
	}{
		{"refused connection", `{"preset":"chrome-latest"}`,
			`{"method":"POST","url":"http://` + closed + `/pay","body":"x"}`,
			ErrorResponse{Code: "connect", NotSent: true}},
		{"refused proxy", `{"preset":"chrome-latest","proxy":"http://` + closed + `"}`,
			`{"method":"POST","url":"https://pay.test/pay","body":"x"}`,
			ErrorResponse{Code: "proxy", NotSent: true}},
		{"proxy credentials refused", `{"preset":"chrome-latest","proxy":"http://u:p@` + proxy407 + `"}`,
			`{"method":"POST","url":"https://pay.test/pay","body":"x"}`,
			ErrorResponse{Code: "proxy", NotSent: true, ProxyStatus: 407}},
		{"proxy credentials refused over HTTP/1.1", `{"preset":"chrome-latest","http_version":"h1","proxy":"http://` + proxy407 + `"}`,
			`{"method":"POST","url":"https://pay.test/pay","body":"x"}`,
			ErrorResponse{Code: "proxy", NotSent: true, ProxyStatus: 407}},
		{"no answer in time", `{"preset":"chrome-latest"}`,
			`{"method":"POST","url":"http://` + silent + `/pay","body":"x","timeout":1}`,
			ErrorResponse{Code: "timeout"}},
		// The kind of a hang-up is not in its types; the binding reads the message.
		{"hung up after the request", `{"preset":"chrome-latest"}`,
			`{"method":"POST","url":"http://` + hangsUp + `/pay","body":"x"}`,
			ErrorResponse{}},
		{"too many redirects", `{"preset":"chrome-latest","max_redirects":2}`,
			`{"method":"GET","url":"http://` + loop + `/"}`,
			ErrorResponse{Code: "redirect"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := hcTestSessionNew(c.session)
			defer hcTestSessionFree(h)
			out := hcTestRequest(h, c.request)
			var got ErrorResponse
			if err := json.Unmarshal([]byte(out), &got); err != nil || got.Error == "" {
				t.Fatalf("not an error object: %s", out)
			}
			c.want.Error = got.Error
			if got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}
