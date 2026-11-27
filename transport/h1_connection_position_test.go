package transport

import (
	"bufio"
	"context"
	"io"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// The HTTP/1.1 writer put Connection second, right after Host, for every
// preset, which is where Chrome puts it. Firefox 159 writes it after
// Accept-Encoding for the page and for every stylesheet, script, image and
// frame it loads, so a Firefox preset went out with Chrome's placement. An exact-headers request fared worse: a
// Connection the caller listed later still went out second, and one spelled
// in lowercase did not go out at all. The Chrome cases pin what must not move,
// including a caller's own value, which CompleteHeaderOrder's sorted tail
// would otherwise carry to the end.
func TestConnectionPositionOverHTTP1(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	reqs := make(chan []string, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					if _, err := br.ReadString('\n'); err != nil { // request line
						return
					}
					var lines []string
					for {
						l, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if l = strings.TrimRight(l, "\r\n"); l == "" {
							break
						}
						lines = append(lines, l)
					}
					reqs <- lines
					io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
				}
			}(c)
		}
	}()
	url := "http://" + ln.Addr().String() + "/"
	closing := map[string][]string{"Connection": {"close"}}
	exact := func(name string) []fingerprint.HeaderPair {
		return []fingerprint.HeaderPair{{Key: "accept", Value: "*/*"}, {Key: name, Value: "close"}, {Key: "user-agent", Value: "probe"}}
	}

	for _, c := range []struct {
		name   string
		preset string
		req    *Request
		after  string // the header Connection must follow
		line   string // the Connection line itself
	}{
		{"firefox", "firefox-148-windows", &Request{Method: "GET", URL: url}, "Accept-Encoding", "Connection: keep-alive"},
		{"firefox, caller's value", "firefox-148-windows", &Request{Method: "GET", URL: url, Headers: closing}, "Accept-Encoding", "Connection: close"},
		{"chrome", "chrome-155-windows", &Request{Method: "GET", URL: url}, "Host", "Connection: keep-alive"},
		{"chrome, caller's value", "chrome-155-windows", &Request{Method: "GET", URL: url, Headers: closing}, "Host", "Connection: close"},
		{"exact headers", "chrome-155-windows", &Request{Method: "GET", URL: url, ExactHeaders: exact("Connection")}, "accept", "Connection: close"},
		{"exact headers, lowercase", "chrome-155-windows", &Request{Method: "GET", URL: url, ExactHeaders: exact("connection")}, "accept", "connection: close"},
	} {
		tr := NewTransport(c.preset)
		resp, err := tr.Do(context.Background(), c.req)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		resp.Close()
		tr.Close()
		lines := <-reqs
		i := slices.IndexFunc(lines, func(l string) bool { return strings.EqualFold(lineName(l), "Connection") })
		if i < 1 || lines[i] != c.line || lineName(lines[i-1]) != c.after {
			t.Errorf("%s: got %q, want %q right after %s", c.name, lines, c.line, c.after)
		}
	}
}

func lineName(l string) string {
	name, _, _ := strings.Cut(l, ":")
	return name
}
