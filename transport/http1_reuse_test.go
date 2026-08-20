package transport

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	http "github.com/sardanioss/http"
)

func TestHTTP1ShouldKeepAliveHonorsParsedClose(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(
		"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !resp.Close {
		t.Fatal("parsed response did not record Connection: close")
	}
	if (&HTTP1Transport{}).shouldKeepAlive(req, resp) {
		t.Fatal("Connection: close response was marked reusable")
	}
}

func TestHTTP1ShouldKeepAliveHonorsRequestClose(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Close = true
	resp := &http.Response{ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header)}
	if (&HTTP1Transport{}).shouldKeepAlive(req, resp) {
		t.Fatal("request with Close set was marked reusable")
	}
}

func TestRewindRequestBody(t *testing.T) {
	want := []byte("sensor-payload")
	req, err := http.NewRequest("POST", "http://example.test/", bytes.NewReader(want))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(req.Body); err != nil {
		t.Fatal(err)
	}
	if err := req.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rewindRequestBody(req); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("rewound body = %q, want %q", got, want)
	}
}

func TestRewindRequestBodyRejectsNonReplayableBody(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.test/", io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	if req.GetBody != nil {
		t.Fatal("test body unexpectedly replayable")
	}
	if err := rewindRequestBody(req); err == nil {
		t.Fatal("non-replayable body was accepted")
	}
}
