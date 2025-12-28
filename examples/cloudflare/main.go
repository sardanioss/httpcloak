// Example: Multiple requests to Cloudflare trace endpoint
//
// This example demonstrates:
// - Making multiple requests to the same endpoint
// - Comparing httpcloak vs Go's standard library
// - Verifying TLS fingerprint consistency
// - Protocol detection (HTTP/2 vs HTTP/3)
//
// The Cloudflare trace endpoint returns connection info including:
// - IP address
// - Location (colo)
// - HTTP protocol version
// - TLS version
//
// Run: go run main.go
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

const (
	traceURL    = "https://www.cloudflare.com/cdn-cgi/trace"
	numRequests = 5
)

func main() {
	ctx := context.Background()

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("httpcloak vs Go stdlib - Cloudflare Trace Comparison")
	fmt.Println(strings.Repeat("=", 70))

	// =========================================================================
	// Part 1: Multiple requests with httpcloak
	// =========================================================================
	fmt.Println("\n[httpcloak] Making", numRequests, "requests to Cloudflare trace")
	fmt.Println(strings.Repeat("-", 50))

	c := client.NewClient("chrome-143",
		client.WithTimeout(30*time.Second),
	)
	defer c.Close()

	for i := 1; i <= numRequests; i++ {
		start := time.Now()
		resp, err := c.Get(ctx, traceURL, nil)
		elapsed := time.Since(start)

		if err != nil {
			fmt.Printf("[%d] Error: %v\n", i, err)
			continue
		}

		// Parse trace response
		trace := parseTrace(resp.Text())

		fmt.Printf("[%d] %s | %s | Protocol: %s | h=%s | loc=%s | %v\n",
			i,
			resp.Protocol,
			trace["http"],
			trace["visit_scheme"],
			trace["h"],
			trace["colo"],
			elapsed.Round(time.Millisecond),
		)

		// Small delay between requests
		if i < numRequests {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// =========================================================================
	// Part 2: Multiple requests with Go's standard library
	// =========================================================================
	fmt.Println("\n[Go stdlib] Making", numRequests, "requests to Cloudflare trace")
	fmt.Println(strings.Repeat("-", 50))

	stdClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	for i := 1; i <= numRequests; i++ {
		start := time.Now()
		resp, err := stdClient.Get(traceURL)
		elapsed := time.Since(start)

		if err != nil {
			fmt.Printf("[%d] Error: %v\n", i, err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Parse trace response
		trace := parseTrace(string(body))

		fmt.Printf("[%d] %s | %s | Protocol: %s | h=%s | loc=%s | %v\n",
			i,
			resp.Proto,
			trace["http"],
			trace["visit_scheme"],
			trace["h"],
			trace["colo"],
			elapsed.Round(time.Millisecond),
		)

		// Small delay between requests
		if i < numRequests {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// =========================================================================
	// Part 3: Compare different browser presets
	// =========================================================================
	fmt.Println("\n[Preset Comparison] Different browser fingerprints")
	fmt.Println(strings.Repeat("-", 50))

	presets := []string{"chrome-143", "chrome-131", "firefox-133", "safari-18"}

	for _, preset := range presets {
		pc := client.NewClient(preset, client.WithTimeout(30*time.Second))

		resp, err := pc.Get(ctx, traceURL, nil)
		if err != nil {
			fmt.Printf("%-15s Error: %v\n", preset, err)
			pc.Close()
			continue
		}

		trace := parseTrace(resp.Text())
		fmt.Printf("%-15s | Protocol: %s | http=%s | tls=%s\n",
			preset,
			resp.Protocol,
			trace["http"],
			trace["tls"],
		)
		pc.Close()

		time.Sleep(300 * time.Millisecond)
	}

	// =========================================================================
	// Part 4: Force HTTP/2 vs HTTP/3
	// =========================================================================
	fmt.Println("\n[Protocol Comparison] HTTP/2 vs HTTP/3")
	fmt.Println(strings.Repeat("-", 50))

	// Force HTTP/2
	resp, err := c.Do(ctx, &client.Request{
		Method:        "GET",
		URL:           traceURL,
		ForceProtocol: client.ProtocolHTTP2,
	})
	if err != nil {
		fmt.Printf("HTTP/2: Error - %v\n", err)
	} else {
		trace := parseTrace(resp.Text())
		fmt.Printf("Force HTTP/2:  Protocol=%s | http=%s\n", resp.Protocol, trace["http"])
	}

	// Force HTTP/3 (may fail if server doesn't support it)
	resp, err = c.Do(ctx, &client.Request{
		Method:        "GET",
		URL:           traceURL,
		ForceProtocol: client.ProtocolHTTP3,
	})
	if err != nil {
		fmt.Printf("HTTP/3: Error - %v (expected if H3 not supported)\n", err)
	} else {
		trace := parseTrace(resp.Text())
		fmt.Printf("Force HTTP/3:  Protocol=%s | http=%s\n", resp.Protocol, trace["http"])
	}

	// =========================================================================
	// Part 5: With session (cookies enabled)
	// =========================================================================
	fmt.Println("\n[Session] Requests with cookie persistence")
	fmt.Println(strings.Repeat("-", 50))

	session := client.NewSession("chrome-143")
	defer session.Close()

	for i := 1; i <= 3; i++ {
		resp, err := session.Get(ctx, traceURL, nil)
		if err != nil {
			fmt.Printf("[%d] Error: %v\n", i, err)
			continue
		}

		trace := parseTrace(resp.Text())
		cookieCount := 0
		if session.Cookies() != nil {
			cookieCount = session.Cookies().Count()
		}

		fmt.Printf("[%d] %s | http=%s | cookies=%d\n",
			i, resp.Protocol, trace["http"], cookieCount)

		time.Sleep(300 * time.Millisecond)
	}

	// =========================================================================
	// Part 6: Full trace output
	// =========================================================================
	fmt.Println("\n[Full Trace] Complete Cloudflare trace response")
	fmt.Println(strings.Repeat("-", 50))

	resp, err = c.Get(ctx, traceURL, nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Protocol: %s\n\n", resp.Protocol)
		fmt.Println(resp.Text())
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("Cloudflare trace comparison completed!")
	fmt.Println(strings.Repeat("=", 70))
}

// parseTrace parses the Cloudflare trace response into a map
func parseTrace(body string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(strings.TrimSpace(body), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}
