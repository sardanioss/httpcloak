package main

import (
	"context"
	"fmt"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

func main() {
	// Create client with Chrome 143 Windows preset
	c := client.NewClient("chrome-143-windows",
		client.WithTimeout(30*time.Second),
	)
	defer c.Close()

	ctx := context.Background()

	// Send request to TLS fingerprint checker
	resp, err := c.Get(ctx, "https://tls.peet.ws/api/all", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Protocol: %s\n", resp.Protocol)
	fmt.Println("---RAW RESPONSE---")
	fmt.Println(string(resp.Body))
}
