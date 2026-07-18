package client

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDoStreamSurvivesAgedConnectionRetirement(t *testing.T) {
	writeSecondEvent := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()

		select {
		case <-writeSecondEvent:
			_, _ = fmt.Fprint(w, "data: second\n\n")
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	client := NewClient(
		"chrome-149",
		WithForceHTTP2(),
		WithInsecureSkipVerify(),
		WithTimeout(5*time.Second),
	)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	responses := make([]*StreamResponse, 2)
	readers := make([]*bufio.Reader, len(responses))
	for i := range responses {
		resp, err := client.DoStream(ctx, &Request{Method: http.MethodGet, URL: server.URL})
		if err != nil {
			t.Fatalf("DoStream %d: %v", i, err)
		}
		responses[i] = resp
		defer responses[i].Close()

		readers[i] = bufio.NewReader(responses[i])
		if event := readTestSSEEvent(t, readers[i]); event != "data: first\n\n" {
			t.Fatalf("stream %d first event = %q", i, event)
		}
	}

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	host, port, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatalf("split server host: %v", err)
	}
	hostPool, err := client.poolManager.GetPool(host, port)
	if err != nil {
		t.Fatalf("get host pool: %v", err)
	}
	streamConn, err := hostPool.GetConn(ctx)
	if err != nil {
		t.Fatalf("get stream connection: %v", err)
	}

	streamConn.CreatedAt = time.Now().Add(-6 * time.Minute)
	hostPool.CloseIdle()

	replacementConn, err := hostPool.GetConn(ctx)
	if err != nil {
		t.Fatalf("get replacement connection: %v", err)
	}
	if replacementConn == streamConn {
		t.Fatal("aged connection remained eligible for new requests")
	}

	close(writeSecondEvent)
	for i := range readers {
		if event := readTestSSEEvent(t, readers[i]); event != "data: second\n\n" {
			t.Fatalf("stream %d second event = %q", i, event)
		}
	}
}

func readTestSSEEvent(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	var event strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE event: %v", err)
		}
		event.WriteString(line)
		if line == "\n" {
			return event.String()
		}
	}
}
