package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/sardanioss/net/http2/hpack"
)

// Firefox 159's header order, captured on 2026-10-28 for every request shape
// below: over HTTP/1.1 through powhttp, over HTTP/1.1 with TLS, and over
// HTTP/2, decoded on the wire and read from Firefox's own encoder log. Each
// case sends that shape through a real transport with a Firefox preset.
//
// The HTTP/1.1 head must name its headers in the order Firefox did. The HTTP/2
// block must hold the same names without Host and Connection, after the
// pseudo-headers and followed by te: trailers. That is what Firefox's HTTP/2
// encoder makes of the HTTP/1.1 head (Http2Compressor::EncodeHeaderBlock), and
// every captured request agreed with it.
//
// Firefox sends Referer in one of two places. A fetch() and a redirect hop
// carry it right after Accept-Encoding; a navigation or a no-cors subresource
// from a page that set no Referrer-Policy carries it after Connection. The
// headers a page set on a fetch() follow the early slot; a caller's arrive in a
// map, so they go there sorted. The captured navigation and form submission
// were started by script and sent no Sec-Fetch-User; the preset sends one, in
// the place the typed navigation put it.
func TestFirefoxHeaderOrder(t *testing.T) {
	const ref = "https://example.test/page"
	cookie := map[string][]string{"Cookie": {"sid=abc123; pref=dark"}}
	with := func(base map[string][]string, kv ...string) map[string][]string {
		h := map[string][]string{}
		for k, v := range base {
			h[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			h[kv[i]] = []string{kv[i+1]}
		}
		return h
	}
	fetch := func(kv ...string) map[string][]string {
		return with(cookie, append([]string{"Referer", ref,
			"Sec-Fetch-Dest", "empty", "Sec-Fetch-Mode", "cors", "Sec-Fetch-Site", "same-origin"}, kv...)...)
	}

	cases := []struct {
		name string
		req  Request
		want []string // the HTTP/1.1 head as Firefox 159 sent it
	}{
		{"navigation", Request{Method: "GET"}, []string{
			"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection",
			"Upgrade-Insecure-Requests", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User",
			"Priority"}},
		{"navigation revalidation", Request{Method: "GET", Headers: with(cookie,
			"If-None-Match", `"p1"`, "If-Modified-Since", "Wed, 21 Oct 2026 07:28:00 GMT")}, []string{
			"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection", "Cookie",
			"Upgrade-Insecure-Requests", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User",
			"If-Modified-Since", "If-None-Match", "Priority"}},
		{"stylesheet", Request{Method: "GET", Headers: with(cookie, "Referer", ref, "Accept", "text/css,*/*;q=0.1",
			"Sec-Fetch-Dest", "style", "Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Site", "same-origin")}, []string{
			"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection", "Referer", "Cookie",
			"Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Priority"}},
		{"fetch with a header of its own", Request{Method: "GET", Headers: fetch("X-Requested-With", "XMLHttpRequest")}, []string{
			"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Referer", "X-Requested-With",
			"Connection", "Cookie", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Priority"}},
		{"fetch JSON POST", Request{Method: "POST", Body: []byte(`{"a":1}`), Headers: fetch(
			"Content-Type", "application/json", "X-Custom", "1", "Origin", "https://example.test")}, []string{
			"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Referer", "Content-Type", "X-Custom",
			"Content-Length", "Origin", "Connection", "Cookie", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
			"Priority"}},
		{"fetch revalidation", Request{Method: "GET", Headers: fetch(
			"If-None-Match", `"cf1"`, "If-Modified-Since", "Wed, 21 Oct 2026 07:28:00 GMT")}, []string{
			"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Referer", "Connection", "Cookie",
			"Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "If-Modified-Since", "If-None-Match", "Priority"}},
		{"form POST", Request{Method: "POST", Body: []byte("b=2"), Headers: with(cookie, "Referer", ref,
			"Content-Type", "application/x-www-form-urlencoded", "Origin", "https://example.test",
			"Sec-Fetch-Site", "same-origin")}, []string{
			"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Content-Type", "Content-Length",
			"Origin", "Connection", "Referer", "Cookie", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest",
			"Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User", "Priority"}},
		{"redirect hop", Request{Method: "GET", RedirectHop: true, Headers: with(cookie, "Referer", ref)}, []string{
			"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Referer", "Connection", "Cookie",
			"Upgrade-Insecure-Requests", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User",
			"Priority"}},
	}

	h1URL, h1Heads := serveH1HeaderNames(t)
	h2URL, h2Blocks := serveH2HeaderNames(t)
	for _, preset := range []string{"firefox-148-windows", "firefox-133-linux"} {
		for _, c := range cases {
			t.Run(preset+"/"+c.name, func(t *testing.T) {
				// firefox-133 sends no Upgrade-Insecure-Requests and no TE; the
				// order of everything else is the same.
				want := c.want
				if preset == "firefox-133-linux" {
					want = without(want, "Upgrade-Insecure-Requests")
				}

				req := c.req
				req.URL = h1URL
				tr := NewTransport(preset)
				resp, err := tr.Do(context.Background(), &req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Close()
				tr.Close()
				if got := <-h1Heads; !equalFoldAll(got, want) {
					t.Errorf("HTTP/1.1:\n got  %q\n want %q", got, want)
				}

				// Cookie goes out one field per pair, in its own slot, as
				// Firefox's encoder sends it.
				h2want := []string{":method", ":path", ":authority", ":scheme"}
				for _, n := range without(want, "Host", "Connection") {
					crumbs := 1
					if n == "Cookie" {
						crumbs = strings.Count(c.req.Headers["Cookie"][0], "; ") + 1
					}
					for range crumbs {
						h2want = append(h2want, strings.ToLower(n))
					}
				}
				if preset != "firefox-133-linux" {
					h2want = append(h2want, "te")
				}
				req = c.req
				req.URL = h2URL
				tr = NewTransport(preset)
				tr.SetProtocol(ProtocolHTTP2)
				tr.SetInsecureSkipVerify(true)
				resp, err = tr.Do(context.Background(), &req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Close()
				tr.Close()
				if got := <-h2Blocks; !reflect.DeepEqual(got, h2want) {
					t.Errorf("HTTP/2:\n got  %q\n want %q", got, h2want)
				}
			})
		}
	}
}

// The marker is read from the preset's order only, and takes every header the
// orders do not name, sorted, where it stands.
func TestCompleteHeaderOrderOtherHeaders(t *testing.T) {
	header := map[string][]string{"A": {"1"}, "B": {"1"}, "C": {"1"}, "D": {"1"}, "E": {"1"}}
	for _, c := range []struct {
		explicit, preset, want []string
	}{
		{nil, []string{"a", "*", "c"}, []string{"a", "b", "d", "e", "c"}},
		{nil, []string{"*", "a"}, []string{"b", "c", "d", "e", "a"}},
		{nil, []string{"a", "c", "*"}, []string{"a", "c", "b", "d", "e"}},
		{[]string{"e"}, []string{"a", "*", "c"}, []string{"e", "a", "b", "d", "c"}},
		{[]string{"*", "e"}, []string{"a", "c"}, []string{"e", "a", "c", "b", "d"}},
		{nil, []string{"a", "*", "b", "c", "d", "e"}, []string{"a", "b", "c", "d", "e"}},
	} {
		if got := CompleteHeaderOrder(c.explicit, c.preset, header, nil); !reflect.DeepEqual(got, c.want) {
			t.Errorf("CompleteHeaderOrder(%q, %q) = %q, want %q", c.explicit, c.preset, got, c.want)
		}
	}
}

func equalFoldAll(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

// serveH1HeaderNames answers plain HTTP/1.1 and sends each request's header
// names, in the order they arrived, down the channel.
func serveH1HeaderNames(t *testing.T) (string, <-chan []string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	heads := make(chan []string, 1)
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
					var names []string
					length := 0
					for {
						l, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if l = strings.TrimRight(l, "\r\n"); l == "" {
							break
						}
						name, value, _ := strings.Cut(l, ":")
						names = append(names, name)
						if strings.EqualFold(name, "Content-Length") {
							length, _ = strconv.Atoi(strings.TrimSpace(value))
						}
					}
					if _, err := io.CopyN(io.Discard, br, int64(length)); err != nil {
						return
					}
					heads <- names
					io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
				}
			}(c)
		}
	}()
	return "http://" + ln.Addr().String() + "/", heads
}

// serveH2HeaderNames answers HTTP/2 over TLS and sends the field names of each
// request's header block, pseudo-headers included, down the channel.
func serveH2HeaderNames(t *testing.T) (string, <-chan []string) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{wireCert(t)}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	blocks := make(chan []string, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := io.ReadFull(c, make([]byte, 24)); err != nil { // preface
					return
				}
				write := func(typ, flags byte, sid uint32, p []byte) {
					h := []byte{byte(len(p) >> 16), byte(len(p) >> 8), byte(len(p)), typ, flags, 0, 0, 0, 0}
					binary.BigEndian.PutUint32(h[5:], sid)
					c.Write(append(h, p...))
				}
				write(0x4, 0, 0, nil) // SETTINGS, empty
				dec := hpack.NewDecoder(65536, nil)
				hdr := make([]byte, 9)
				for {
					if _, err := io.ReadFull(c, hdr); err != nil {
						return
					}
					typ, flags := hdr[3], hdr[4]
					sid := binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
					p := make([]byte, int(hdr[0])<<16|int(hdr[1])<<8|int(hdr[2]))
					if _, err := io.ReadFull(c, p); err != nil {
						return
					}
					switch typ {
					case 0x0: // DATA
						if flags&0x1 != 0 {
							write(0x1, 0x5, sid, []byte{0x88}) // :status 200, END_STREAM
						}
					case 0x1: // HEADERS; a preset's block fits one frame
						if flags&0x8 != 0 { // PADDED
							p = p[1 : len(p)-int(p[0])]
						}
						if flags&0x20 != 0 { // PRIORITY
							p = p[5:]
						}
						fields, err := dec.DecodeFull(p)
						if err != nil {
							return
						}
						names := make([]string, len(fields))
						for i, f := range fields {
							names[i] = f.Name
						}
						blocks <- names
						if flags&0x1 != 0 {
							write(0x1, 0x5, sid, []byte{0x88})
						}
					case 0x4: // SETTINGS
						if flags&0x1 == 0 {
							write(0x4, 0x1, 0, nil)
						}
					case 0x6: // PING
						if flags&0x1 == 0 {
							write(0x6, 0x1, 0, p)
						}
					}
				}
			}(c)
		}
	}()
	return "https://" + ln.Addr().String() + "/", blocks
}
