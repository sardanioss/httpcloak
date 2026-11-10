package transport

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// A page script's JSON POST to another site goes out in the order Chrome 156
// sends it (its network log, the same for every such POST of a dozen origins):
// content-length first, the script's content-type inside the client hints, and
// origin after accept.
func TestFetchPostLeavesInChromesOrder(t *testing.T) {
	srv := startH2CaptureServer(t)
	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := tr.Do(ctx, &Request{
		Method: "POST",
		URL:    "https://" + srv.addr + "/v1/events",
		Body:   []byte(`{"k":1}`),
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
			"Referer":      {"https://www.example.com/products/x"},
		},
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var c h2Capture
	select {
	case c = <-srv.captures:
	case <-time.After(5 * time.Second):
		t.Fatal("no HEADERS frame captured")
	}
	var got []string
	for _, name := range c.HeaderOrder {
		if name[0] != ':' {
			got = append(got, name)
		}
	}
	want := []string{
		"content-length", "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "content-type", "sec-ch-ua-mobile",
		"accept", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
		"accept-encoding", "accept-language", "priority",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fetch() POST header order\n got %v\nwant %v", got, want)
	}
}
