// Example: Basic HTTP requests with httpcloak
//
// This example demonstrates:
// - Simple GET request
// - Custom headers
// - POST with JSON body
// - Timeout configuration
// - Proxy usage
// - SSL verification skip
// - Redirect handling
// - Retry configuration
// - Force HTTP/2 or HTTP/3
// - Navigate vs CORS fetch modes
//
// Run: go run main.go
package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

func main() {
	ctx := context.Background()

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("httpcloak - Basic Examples")
	fmt.Println(strings.Repeat("=", 70))

	// =========================================================================
	// Example 1: Simple GET request
	// =========================================================================
	fmt.Println("\n[1] Simple GET Request")
	fmt.Println(strings.Repeat("-", 50))

	c := client.NewClient("chrome-143")
	defer c.Close()

	resp, err := c.Get(ctx, "https://httpbin.org/get", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Status: %d | Protocol: %s | Size: %d bytes\n",
			resp.StatusCode, resp.Protocol, len(resp.Body))
	}

	// =========================================================================
	// Example 2: GET with custom headers
	// =========================================================================
	fmt.Println("\n[2] GET with Custom Headers")
	fmt.Println(strings.Repeat("-", 50))

	resp, err = c.Get(ctx, "https://httpbin.org/headers", map[string]string{
		"X-Custom-Header": "my-value",
		"X-Request-ID":    "12345",
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Status: %d\n", resp.StatusCode)
		// Response will show our custom headers
	}

	// =========================================================================
	// Example 3: POST with JSON body
	// =========================================================================
	fmt.Println("\n[3] POST with JSON Body")
	fmt.Println(strings.Repeat("-", 50))

	jsonBody := []byte(`{"name": "httpcloak", "version": "1.0"}`)
	resp, err = c.Post(ctx, "https://httpbin.org/post", jsonBody, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Status: %d | Protocol: %s\n", resp.StatusCode, resp.Protocol)
	}

	// =========================================================================
	// Example 4: With timeout
	// =========================================================================
	fmt.Println("\n[4] Request with Timeout")
	fmt.Println(strings.Repeat("-", 50))

	clientWithTimeout := client.NewClient("chrome-143",
		client.WithTimeout(5*time.Second),
	)
	defer clientWithTimeout.Close()

	resp, err = clientWithTimeout.Get(ctx, "https://httpbin.org/delay/2", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Status: %d (completed within timeout)\n", resp.StatusCode)
	}

	// =========================================================================
	// Example 5: Disable redirect following
	// =========================================================================
	fmt.Println("\n[5] Disable Redirect Following")
	fmt.Println(strings.Repeat("-", 50))

	clientNoRedirect := client.NewClient("chrome-143",
		client.WithoutRedirects(),
	)
	defer clientNoRedirect.Close()

	resp, err = clientNoRedirect.Get(ctx, "https://httpbin.org/redirect/3", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Status: %d (redirect not followed)\n", resp.StatusCode)
		fmt.Printf("Location: %s\n", resp.Headers["location"])
	}

	// =========================================================================
	// Example 6: With retry on failure
	// =========================================================================
	fmt.Println("\n[6] Retry Configuration")
	fmt.Println(strings.Repeat("-", 50))

	clientWithRetry := client.NewClient("chrome-143",
		client.WithRetry(3), // Retry up to 3 times on 429, 500, 502, 503, 504
	)
	defer clientWithRetry.Close()

	// This won't actually retry since httpbin returns 200
	resp, err = clientWithRetry.Get(ctx, "https://httpbin.org/get", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Status: %d (retry enabled for transient failures)\n", resp.StatusCode)
	}

	// =========================================================================
	// Example 7: Advanced retry configuration
	// =========================================================================
	fmt.Println("\n[7] Advanced Retry Configuration")
	fmt.Println(strings.Repeat("-", 50))

	clientAdvancedRetry := client.NewClient("chrome-143",
		client.WithRetryConfig(
			5,                    // Max 5 retries
			500*time.Millisecond, // Min wait 500ms
			10*time.Second,       // Max wait 10s
			[]int{429, 503},      // Only retry on these status codes
		),
	)
	defer clientAdvancedRetry.Close()

	fmt.Println("Configured: 5 retries, 500ms-10s backoff, retry on 429/503")

	// =========================================================================
	// Example 8: Skip SSL verification (for testing only!)
	// =========================================================================
	fmt.Println("\n[8] Skip SSL Verification (testing only!)")
	fmt.Println(strings.Repeat("-", 50))

	clientInsecure := client.NewClient("chrome-143",
		client.WithInsecureSkipVerify(),
	)
	defer clientInsecure.Close()

	resp, err = clientInsecure.Get(ctx, "https://httpbin.org/get", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Status: %d (SSL verification skipped)\n", resp.StatusCode)
	}

	// =========================================================================
	// Example 9: Force HTTP/2 (skip HTTP/3 attempt)
	// =========================================================================
	fmt.Println("\n[9] Force HTTP/2 Protocol")
	fmt.Println(strings.Repeat("-", 50))

	resp, err = c.Do(ctx, &client.Request{
		Method:        "GET",
		URL:           "https://httpbin.org/get",
		ForceProtocol: client.ProtocolHTTP2,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Status: %d | Protocol: %s (forced H2)\n", resp.StatusCode, resp.Protocol)
	}

	// =========================================================================
	// Example 10: CORS mode (simulates JavaScript fetch)
	// =========================================================================
	fmt.Println("\n[10] CORS Mode (JavaScript fetch simulation)")
	fmt.Println(strings.Repeat("-", 50))

	resp, err = c.Do(ctx, &client.Request{
		Method:    "GET",
		URL:       "https://httpbin.org/get",
		FetchMode: client.FetchModeCORS, // Sec-Fetch-Mode: cors
		Referer:   "https://example.com/app",
		Headers: map[string]string{
			"Accept": "application/json",
		},
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Status: %d | Protocol: %s (CORS mode)\n", resp.StatusCode, resp.Protocol)
	}

	// =========================================================================
	// Example 11: Navigate mode (simulates user clicking link)
	// =========================================================================
	fmt.Println("\n[11] Navigate Mode (user clicking link simulation)")
	fmt.Println(strings.Repeat("-", 50))

	resp, err = c.Do(ctx, &client.Request{
		Method:    "GET",
		URL:       "https://httpbin.org/html",
		FetchMode: client.FetchModeNavigate, // Sec-Fetch-Mode: navigate
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Status: %d | Protocol: %s (Navigate mode)\n", resp.StatusCode, resp.Protocol)
	}

	// =========================================================================
	// Example 12: With query parameters
	// =========================================================================
	fmt.Println("\n[12] Request with Query Parameters")
	fmt.Println(strings.Repeat("-", 50))

	resp, err = c.Do(ctx, &client.Request{
		Method: "GET",
		URL:    "https://httpbin.org/get",
		Params: map[string]string{
			"search": "httpcloak",
			"page":   "1",
			"limit":  "10",
		},
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Status: %d | Final URL includes query params\n", resp.StatusCode)
	}

	// =========================================================================
	// Example 13: Response helpers
	// =========================================================================
	fmt.Println("\n[13] Response Helpers")
	fmt.Println(strings.Repeat("-", 50))

	resp, err = c.Get(ctx, "https://httpbin.org/json", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("IsSuccess: %v\n", resp.IsSuccess())
		fmt.Printf("IsRedirect: %v\n", resp.IsRedirect())
		fmt.Printf("IsClientError: %v\n", resp.IsClientError())
		fmt.Printf("IsServerError: %v\n", resp.IsServerError())

		// Parse JSON response
		var data map[string]interface{}
		if err := resp.JSON(&data); err == nil {
			fmt.Printf("JSON parsed successfully\n")
		}
	}

	// =========================================================================
	// Example 14: Different browser presets
	// =========================================================================
	fmt.Println("\n[14] Different Browser Presets")
	fmt.Println(strings.Repeat("-", 50))

	presets := []string{"chrome-143", "chrome-131", "firefox-133", "safari-18"}
	for _, preset := range presets {
		pc := client.NewClient(preset)
		resp, err := pc.Get(ctx, "https://httpbin.org/user-agent", nil)
		if err != nil {
			fmt.Printf("%s: Error - %v\n", preset, err)
		} else {
			// Extract just the browser name from response
			ua := resp.Text()
			if len(ua) > 60 {
				ua = ua[:60] + "..."
			}
			fmt.Printf("%s: %s\n", preset, ua)
		}
		pc.Close()
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("All examples completed!")
	fmt.Println(strings.Repeat("=", 70))
}
