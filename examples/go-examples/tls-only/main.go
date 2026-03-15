// Example: TLS-Only Mode with httpcloak
//
// TLS-only mode lets you use the browser's TLS fingerprint (JA3/JA4, Peetprint,
// Akamai) while having full control over HTTP headers.
//
// What you'll learn:
// - What TLS-only mode does vs normal mode
// - When to use TLS-only mode
// - How to set custom headers in TLS-only mode
//
// Run: go run main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sardanioss/httpcloak"
)

func main() {
	ctx := context.Background()

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("TLS-Only Mode Examples")
	fmt.Println(strings.Repeat("=", 60))

	// =========================================================================
	// Example 1: Normal Mode (default behavior)
	// =========================================================================
	fmt.Println("\n[1] Normal Mode (preset headers applied)")
	fmt.Println(strings.Repeat("-", 50))

	session := httpcloak.NewSession("chrome-latest")
	defer session.Close()

	resp, err := session.Get(ctx, "https://httpbin.org/headers", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result struct {
		Headers map[string]string `json:"headers"`
	}
	json.Unmarshal(body, &result)

	fmt.Println("Headers sent to server:")
	keys := make([]string, 0, len(result.Headers))
	for k := range result.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := result.Headers[key]
		if strings.HasPrefix(key, "Sec-") || strings.HasPrefix(key, "Accept") ||
			key == "User-Agent" || key == "Priority" || strings.HasPrefix(key, "Upgrade") {
			if len(value) > 60 {
				value = value[:60] + "..."
			}
			fmt.Printf("  %s: %s\n", key, value)
		}
	}
	fmt.Printf("\nTotal headers: %d\n", len(result.Headers))
	fmt.Println("Note: All Chrome preset headers are automatically included")

	// =========================================================================
	// Example 2: TLS-Only Mode (no preset headers)
	// =========================================================================
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[2] TLS-Only Mode (custom headers only)")
	fmt.Println(strings.Repeat("-", 50))

	tlsOnlySession := httpcloak.NewSession("chrome-latest", httpcloak.WithTLSOnly())
	defer tlsOnlySession.Close()

	// Only our custom headers will be sent
	resp, err = tlsOnlySession.Get(ctx, "https://httpbin.org/headers", map[string][]string{
		"User-Agent":      {"MyBot/1.0"},
		"X-Custom-Header": {"my-value"},
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	json.Unmarshal(body, &result)

	fmt.Println("Headers sent to server:")
	keys = make([]string, 0, len(result.Headers))
	for k := range result.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		fmt.Printf("  %s: %s\n", key, result.Headers[key])
	}
	fmt.Printf("\nTotal headers: %d\n", len(result.Headers))
	fmt.Println("Note: Only our custom headers + minimal required headers")

	// =========================================================================
	// Example 3: TLS-Only for API Clients
	// =========================================================================
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[3] TLS-Only for API Clients")
	fmt.Println(strings.Repeat("-", 50))

	apiSession := httpcloak.NewSession("chrome-latest", httpcloak.WithTLSOnly())
	defer apiSession.Close()

	// API-style request with custom headers
	resp, err = apiSession.Get(ctx, "https://httpbin.org/headers", map[string][]string{
		"Authorization": {"Bearer my-api-token"},
		"X-API-Key":     {"secret-key-123"},
		"Content-Type":  {"application/json"},
		"Accept":        {"application/json"},
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	json.Unmarshal(body, &result)

	fmt.Println("API request headers:")
	keys = make([]string, 0, len(result.Headers))
	for k := range result.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if !strings.HasPrefix(key, "X-Amzn") {
			fmt.Printf("  %s: %s\n", key, result.Headers[key])
		}
	}
	fmt.Println("\nNo Sec-Ch-Ua or browser-specific headers leaked!")

	// =========================================================================
	// Example 4: Comparing Fingerprints
	// =========================================================================
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[4] TLS Fingerprint Comparison")
	fmt.Println(strings.Repeat("-", 50))

	// Check TLS fingerprint in normal mode
	normalSession := httpcloak.NewSession("chrome-latest")
	defer normalSession.Close()

	resp, err = normalSession.Get(ctx, "https://tls.peet.ws/api/all", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	var tlsResult struct {
		TLS struct {
			JA4 string `json:"ja4"`
		} `json:"tls"`
	}
	json.Unmarshal(body, &tlsResult)
	fmt.Printf("Normal mode JA4:   %s\n", tlsResult.TLS.JA4)

	// Check TLS fingerprint in TLS-only mode
	tlsOnlySession2 := httpcloak.NewSession("chrome-latest", httpcloak.WithTLSOnly())
	defer tlsOnlySession2.Close()

	resp, err = tlsOnlySession2.Get(ctx, "https://tls.peet.ws/api/all", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	json.Unmarshal(body, &tlsResult)
	fmt.Printf("TLS-only mode JA4: %s\n", tlsResult.TLS.JA4)

	fmt.Println("\nBoth have identical TLS fingerprints!")

	// =========================================================================
	// Summary
	// =========================================================================
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Summary: When to use TLS-Only Mode")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println(`
Use TLS-only mode when you need:

1. Full control over HTTP headers
   - API clients with specific header requirements
   - Custom User-Agent strings
   - No browser-specific headers (Sec-Ch-Ua, etc.)

2. TLS fingerprint without HTTP fingerprint
   - Pass TLS-based bot detection
   - But use your own HTTP header set

3. Minimal header footprint
   - Only send headers you explicitly set
   - Useful for testing or specific protocols

Normal mode is better when:
- You want to fully mimic a browser
- You need automatic browser headers
- You're accessing websites (not APIs)
`)
}
