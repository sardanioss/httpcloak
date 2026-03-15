package main

import (
	"context"
	"fmt"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

func main() {
	ctx := context.Background()
	
	c := client.NewClient("chrome-latest-windows",
		client.WithTimeout(30*time.Second),
	)
	defer c.Close()

	// Fetch browserleaks - print raw JSON
	resp, _ := c.Do(ctx, &client.Request{
		Method:        "GET",
		URL:           "https://quic.browserleaks.com/?minify=1",
		ForceProtocol: client.ProtocolHTTP3,
	})
	text, _ := resp.Text()
	fmt.Println(text)
}
