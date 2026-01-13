package main

import (
	"context"
	"fmt"
	// "os"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

func main() {
	// Disable ECH debug for cleaner output
	// os.Setenv("UTLS_ECH_DEBUG", "1")
	// Test ECH + PSK (0-RTT) with browserleaks
	url := "https://quic.browserleaks.com/?minify=1"
	ctx := context.Background()

	c := client.NewClient("chrome-143", client.WithForceHTTP3())
	defer c.Close()

	fmt.Println("=== Testing 5 Requests with Session Resumption ===")
	fmt.Println("Target:", url)
	fmt.Println(strings.Repeat("-", 60))

	for i := 1; i <= 5; i++ {
		if i > 1 {
			// Close QUIC connections but keep session cache
			c.CloseQUICConnections()
			time.Sleep(100 * time.Millisecond)
		}

		fmt.Printf("\n=== Request %d ===\n", i)
		startTime := time.Now()
		resp, err := c.Get(ctx, url, nil)
		elapsed := time.Since(startTime)

		if err != nil {
			fmt.Printf("Error: %v\n", err)
			fmt.Printf("Elapsed: %v\n", elapsed)
			// Wait and try again
			time.Sleep(500 * time.Millisecond)
			continue
		}

		body, _ := resp.Bytes()
		bodyStr := string(body)

		// Extract 0-rtt value
		zeroRTT := "UNKNOWN"
		if strings.Contains(bodyStr, `"0-rtt":true`) {
			zeroRTT = "TRUE"
		} else if strings.Contains(bodyStr, `"0-rtt":false`) {
			zeroRTT = "FALSE"
		}

		fmt.Printf("0-RTT: %s | Status: %d | Protocol: %s | Time: %v\n",
			zeroRTT, resp.StatusCode, resp.Protocol, elapsed)

		// Wait for session ticket processing
		if i == 1 {
			fmt.Println("Waiting 500ms for session ticket processing...")
			time.Sleep(500 * time.Millisecond)
		}
	}

	fmt.Println("\n" + strings.Repeat("-", 60))
	fmt.Println("Test Complete")
}
