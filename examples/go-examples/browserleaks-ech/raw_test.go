package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

func main() {
	ctx := context.Background()

	echConfig, _ := base64.StdEncoding.DecodeString("AFb+DQBSCQAgACCv9VgyhBjSIX5QZS44OkBQC8H5c4+b2u20pF/4sbkEUgAMAAEAAQABAAIAAQADABtxdWljLW91dGVyLmJyb3dzZXJsZWFrcy5jb20AAA==")

	c := client.NewClient("chrome-latest",
		client.WithTimeout(30*time.Second),
		client.WithECHConfig(echConfig),
	)
	defer c.Close()

	// Request 1
	fmt.Println("=== Request 1 (Initial) - RAW JSON ===")
	start := time.Now()
	resp, _ := c.Do(ctx, &client.Request{
		Method:        "GET",
		URL:           "https://quic.browserleaks.com/?minify=1",
		ForceProtocol: client.ProtocolHTTP3,
	})
	text, _ := resp.Text()
	fmt.Println(text)
	fmt.Printf("RTT: %.2f ms\n\n", float64(time.Since(start).Microseconds())/1000.0)

	time.Sleep(1 * time.Second)
	c.CloseQUICConnections()
	time.Sleep(500 * time.Millisecond)

	// Request 2
	fmt.Println("=== Request 2 (0-RTT Resumption) - RAW JSON ===")
	start = time.Now()
	resp, _ = c.Do(ctx, &client.Request{
		Method:        "GET",
		URL:           "https://quic.browserleaks.com/?minify=1",
		ForceProtocol: client.ProtocolHTTP3,
	})
	text, _ = resp.Text()
	fmt.Println(text)
	fmt.Printf("RTT: %.2f ms\n\n", float64(time.Since(start).Microseconds())/1000.0)

	c.CloseQUICConnections()
	time.Sleep(500 * time.Millisecond)

	// Request 3
	fmt.Println("=== Request 3 (0-RTT Resumption) - RAW JSON ===")
	start = time.Now()
	resp, _ = c.Do(ctx, &client.Request{
		Method:        "GET",
		URL:           "https://quic.browserleaks.com/?minify=1",
		ForceProtocol: client.ProtocolHTTP3,
	})
	text, _ = resp.Text()
	fmt.Println(text)
	fmt.Printf("RTT: %.2f ms\n", float64(time.Since(start).Microseconds())/1000.0)
}
