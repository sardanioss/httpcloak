package session

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/transport"
)

// acceptCHServer is a plain HTTP/1.1 server for the client hint tests. It
// answers a request with Accept-CH when the test asks it to, and hands back the
// request's header lines as they arrived, so a test reads what went on the wire
// rather than a header map.
type acceptCHServer struct {
	url, host string
	acceptCH  string
	reqs      chan []string
	advert    chan bool
}

func newAcceptCHServer(t *testing.T, acceptCH string) *acceptCHServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &acceptCHServer{
		url:      "http://" + ln.Addr().String() + "/",
		host:     "127.0.0.1",
		acceptCH: acceptCH,
		reqs:     make(chan []string, 4),
		advert:   make(chan bool, 4),
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *acceptCHServer) serve(c net.Conn) {
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
		s.reqs <- lines
		extra := ""
		if <-s.advert {
			extra = "Accept-CH: " + s.acceptCH + "\r\n"
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\n"+extra+"Content-Length: 2\r\n\r\nok")
	}
}

// send makes one GET through sess, with the caller's headers if any, and
// returns the header lines the server read for it. advertise says whether the
// response carries Accept-CH.
func (s *acceptCHServer) send(t *testing.T, sess *Session, headers map[string][]string, advertise bool) []string {
	t.Helper()
	s.advert <- advertise
	resp, err := sess.Request(context.Background(), &transport.Request{Method: "GET", URL: s.url, Headers: headers})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Close()
	return <-s.reqs
}
