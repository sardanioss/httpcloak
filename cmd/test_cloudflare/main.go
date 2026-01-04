package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("How many requests to send? ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	count, err := strconv.Atoi(input)
	if err != nil || count < 1 {
		fmt.Println("Invalid number, defaulting to 1")
		count = 1
	}

	fmt.Print("Use HTTP/3? (y/n, default n): ")
	protoInput, _ := reader.ReadString('\n')
	protoInput = strings.TrimSpace(strings.ToLower(protoInput))
	useHTTP3 := protoInput == "y" || protoInput == "yes"

	var c *client.Client
	if useHTTP3 {
		// Default behavior tries HTTP/3 first if server supports it
		c = client.NewClient("chrome-143-windows",
			client.WithTimeout(30*time.Second),
		)
		fmt.Printf("\nUsing HTTP/3 (QUIC) if supported - connection reuse enabled\n")
	} else {
		c = client.NewClient("chrome-143-windows",
			client.WithTimeout(30*time.Second),
			client.WithForceHTTP2(),
		)
		fmt.Printf("\nUsing HTTP/2 - connection reuse enabled\n")
	}
	defer c.Close()

	ctx := context.Background()

	for i := 1; i <= count; i++ {
		fmt.Printf("\n=== Request %d/%d ===\n", i, count)

		resp, err := c.Get(ctx, "https://www.cloudflare.com/cdn-cgi/trace", nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		fmt.Printf("Status: %d\n", resp.StatusCode)
		fmt.Printf("Protocol: %s\n", resp.Protocol)
		fmt.Printf("Body:\n%s\n", string(resp.Body))

		if i < count {
			time.Sleep(500 * time.Millisecond)
		}
	}

	fmt.Printf("\n=== Session Info ===\n")
	if useHTTP3 {
		fmt.Printf("All %d requests used the same QUIC connection\n", count)
	} else {
		fmt.Printf("All %d requests used the same HTTP/2 connection\n", count)
	}
}
