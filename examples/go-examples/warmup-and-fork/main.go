// Warmup & Fork: Browser-Like Page Load and Parallel Tab Simulation
//
// This example demonstrates:
// - Warmup() - simulate a real browser page load (HTML + subresources)
// - Fork(n)  - create parallel sessions sharing cookies and TLS cache (like browser tabs)
//
// Run: go run main.go
package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak"
)

const TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"

func parseTrace(body string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if idx := strings.Index(line, "="); idx != -1 {
			result[line[:idx]] = line[idx+1:]
		}
	}
	return result
}

func main() {
	ctx := context.Background()

	// ==========================================================
	// Example 1: Warmup (Full Browser Page Load Simulation)
	// ==========================================================
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Example 1: Warmup (Browser Page Load)")
	fmt.Println(strings.Repeat("-", 60))

	session := httpcloak.NewSession("chrome-latest", httpcloak.WithSessionTimeout(30*time.Second))

	// Warmup fetches the page + its CSS, JS, images with realistic
	// headers, priorities, and timing. After this, the session has:
	// - TLS session tickets for 0-RTT resumption
	// - Cookies from the page and its subresources
	// - Cache headers (ETag, Last-Modified)
	if err := session.Warmup(ctx, "https://www.cloudflare.com"); err != nil {
		fmt.Printf("Warmup error: %v\n", err)
		return
	}
	fmt.Println("Warmup complete - TLS tickets, cookies, and cache populated")

	// Subsequent requests look like follow-up navigation from a real user
	resp, err := session.Get(ctx, TEST_URL)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	body, _ := resp.Text()
	trace := parseTrace(body)
	fmt.Printf("Follow-up request: Protocol=%s, IP=%s\n", resp.Protocol, trace["ip"])

	session.Close()

	// ==========================================================
	// Example 2: Fork (Parallel Browser Tabs)
	// ==========================================================
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 2: Fork (Parallel Browser Tabs)")
	fmt.Println(strings.Repeat("-", 60))

	// Create a session, warm it up, then fork into parallel tabs
	session = httpcloak.NewSession("chrome-latest", httpcloak.WithSessionTimeout(30*time.Second))

	// Warmup once to populate TLS tickets and cookies
	if err := session.Warmup(ctx, "https://www.cloudflare.com"); err != nil {
		fmt.Printf("Warmup error: %v\n", err)
		return
	}
	fmt.Println("Parent session warmed up")

	// Fork into 3 tabs - each shares cookies and TLS cache
	// but has independent connections for parallel requests
	tabs := session.Fork(3)
	fmt.Printf("Forked into %d tabs\n", len(tabs))

	// Make parallel requests from each tab
	type result struct {
		index    int
		protocol string
		ip       string
	}
	results := make([]result, len(tabs))
	var wg sync.WaitGroup

	for i, tab := range tabs {
		wg.Add(1)
		go func(t *httpcloak.Session, idx int) {
			defer wg.Done()
			r, err := t.Get(ctx, TEST_URL)
			if err != nil {
				fmt.Printf("Tab %d error: %v\n", idx, err)
				return
			}
			b, _ := r.Text()
			tr := parseTrace(b)
			results[idx] = result{idx, r.Protocol, tr["ip"]}
		}(tab, i)
	}
	wg.Wait()

	for _, r := range results {
		fmt.Printf("  Tab %d: Protocol=%s, IP=%s\n", r.index, r.protocol, r.ip)
	}

	// Clean up
	for _, tab := range tabs {
		tab.Close()
	}
	session.Close()

	// ==========================================================
	// Example 3: Warmup + Fork Pattern (Recommended)
	// ==========================================================
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 3: Warmup + Fork (Recommended Pattern)")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Println(`
The recommended pattern for parallel scraping:

1. Create one session
2. Warmup to establish TLS tickets and cookies
3. Fork into N parallel sessions
4. Use each fork for independent requests

    session := httpcloak.NewSession("chrome-latest")
    session.Warmup(ctx, "https://example.com")

    tabs := session.Fork(10)
    var wg sync.WaitGroup
    for i, tab := range tabs {
        wg.Add(1)
        go func(t *httpcloak.Session, n int) {
            defer wg.Done()
            t.Get(ctx, fmt.Sprintf("https://example.com/page/%d", n))
        }(tab, i)
    }
    wg.Wait()

All forks share the same TLS fingerprint, cookies, and TLS session
cache (for 0-RTT resumption), but have independent TCP/QUIC connections.
This looks exactly like a single browser with multiple tabs.
`)

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Warmup & Fork examples completed!")
	fmt.Println(strings.Repeat("=", 60))
}
