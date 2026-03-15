// Runtime Proxy Switching
//
// This example demonstrates:
// - Switching proxies mid-session without creating new clients
// - Split proxy configuration (different proxies for TCP and UDP)
// - Getting current proxy configuration
// - H2 and H3 proxy switching

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

// Test URL that shows your IP
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

	// Basic proxy switching
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Example 1: Basic Proxy Switching")
	fmt.Println(strings.Repeat("-", 60))

	// Create client without proxy (direct connection)
	c := client.NewClient("chrome-latest", client.WithTimeout(30*time.Second))
	defer c.Close()

	// Make request with direct connection
	resp, err := c.Get(ctx, TEST_URL, nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	body, _ := resp.Text()
	trace := parseTrace(body)
	fmt.Println("Direct connection:")
	fmt.Printf("  Protocol: %s, IP: %s, Colo: %s\n", resp.Protocol, trace["ip"], trace["colo"])

	// Switch to a proxy (replace with your actual proxy)
	// c.SetProxy("http://user:pass@proxy.example.com:8080")
	// resp, _ = c.Get(ctx, TEST_URL, nil)
	// body, _ = resp.Text()
	// trace = parseTrace(body)
	// fmt.Println("\nAfter switching to HTTP proxy:")
	// fmt.Printf("  Protocol: %s, IP: %s\n", resp.Protocol, trace["ip"])

	// Switch back to direct connection
	// c.SetProxy("")
	// fmt.Printf("\nSwitched back to direct: %s\n", c.GetProxy())

	// Getting current proxy
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 2: Getting Current Proxy Configuration")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Printf("Current proxy: '%s' (empty = direct)\n", c.GetProxy())
	fmt.Printf("TCP proxy: '%s'\n", c.GetTCPProxy())
	fmt.Printf("UDP proxy: '%s'\n", c.GetUDPProxy())

	// Split proxy configuration
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 3: Split Proxy Configuration (TCP vs UDP)")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Println(`
// Use different proxies for HTTP/1.1+HTTP/2 (TCP) and HTTP/3 (UDP):

c := client.NewClient("chrome-latest")
defer c.Close()

// Set TCP proxy for HTTP/1.1 and HTTP/2
c.SetTCPProxy("http://tcp-proxy.example.com:8080")

// Set UDP proxy for HTTP/3 (requires SOCKS5 with UDP ASSOCIATE or MASQUE)
c.SetUDPProxy("socks5://udp-proxy.example.com:1080")

// Now HTTP/2 requests go through TCP proxy
// and HTTP/3 requests go through UDP proxy

fmt.Printf("TCP proxy: %s\n", c.GetTCPProxy())
fmt.Printf("UDP proxy: %s\n", c.GetUDPProxy())
`)

	// HTTP/3 proxy switching
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 4: HTTP/3 Proxy Switching")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Println(`
// HTTP/3 requires special proxy support:
// - SOCKS5 with UDP ASSOCIATE (most residential proxies)
// - MASQUE (CONNECT-UDP) - premium providers like Bright Data, Oxylabs

c := client.NewClient("chrome-latest", client.WithForceHTTP3())
defer c.Close()

// Direct H3 connection
resp, _ := c.Get(ctx, "https://example.com", nil)
fmt.Printf("Direct: %s\n", resp.Protocol)

// Switch to SOCKS5 proxy with UDP support
c.SetUDPProxy("socks5://user:pass@proxy.example.com:1080")
resp, _ = c.Get(ctx, "https://example.com", nil)
fmt.Printf("Via SOCKS5: %s\n", resp.Protocol)

// Switch to MASQUE proxy
c.SetUDPProxy("https://user:pass@brd.superproxy.io:10001")
resp, _ = c.Get(ctx, "https://example.com", nil)
fmt.Printf("Via MASQUE: %s\n", resp.Protocol)
`)

	// Proxy rotation pattern
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 5: Proxy Rotation Pattern")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Println(`
// Rotate through multiple proxies without recreating clients:

proxies := []string{
    "http://proxy1.example.com:8080",
    "http://proxy2.example.com:8080",
    "http://proxy3.example.com:8080",
}

c := client.NewClient("chrome-latest")
defer c.Close()

for i, proxy := range proxies {
    c.SetProxy(proxy)
    resp, _ := c.Get(ctx, "https://api.ipify.org", nil)
    body, _ := resp.Text()
    fmt.Printf("Request %d via %s: IP = %s\n", i+1, proxy, body)
}
`)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Proxy switching examples completed!")
	fmt.Println(strings.Repeat("=", 60))
}
