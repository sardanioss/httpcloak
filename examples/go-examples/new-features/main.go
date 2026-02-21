// New Features: Refresh, Local Address Binding, TLS Key Logging
//
// This example demonstrates:
// - Refresh() - simulate browser page refresh (close connections, keep TLS cache)
// - Local Address Binding - bind to specific local IP (IPv4 or IPv6)
// - TLS Key Logging - write TLS keys for Wireshark decryption

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
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
	// Example 1: Refresh (Browser Page Refresh Simulation)
	// ==========================================================
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Example 1: Refresh (Browser Page Refresh)")
	fmt.Println(strings.Repeat("-", 60))

	session := httpcloak.NewSession("chrome-144", httpcloak.WithSessionTimeout(30*time.Second))

	// Make initial request - establishes TLS session
	resp, err := session.Get(ctx, TEST_URL)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	body, _ := resp.Text()
	trace := parseTrace(body)
	fmt.Printf("First request: Protocol=%s, IP=%s\n", resp.Protocol, trace["ip"])

	// Simulate browser refresh (F5)
	// This closes TCP/QUIC connections but keeps TLS session cache
	session.Refresh()
	fmt.Println("Called Refresh() - connections closed, TLS cache kept")

	// Next request uses TLS resumption (faster handshake)
	resp, err = session.Get(ctx, TEST_URL)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	body, _ = resp.Text()
	trace = parseTrace(body)
	fmt.Printf("After refresh: Protocol=%s, IP=%s (TLS resumption)\n", resp.Protocol, trace["ip"])

	session.Close()

	// ==========================================================
	// Example 2: TLS Key Logging
	// ==========================================================
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 2: TLS Key Logging")
	fmt.Println(strings.Repeat("-", 60))

	keylogPath := "/tmp/go_keylog_example.txt"

	// Remove old keylog file
	os.Remove(keylogPath)

	// Create session with key logging enabled
	session2 := httpcloak.NewSession("chrome-144",
		httpcloak.WithSessionTimeout(30*time.Second),
		httpcloak.WithKeyLogFile(keylogPath),
	)

	// Make requests - TLS keys written to file
	resp, err = session2.Get(ctx, TEST_URL)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Request completed: Protocol=%s\n", resp.Protocol)

	session2.Close()

	// Check if keylog file was created
	if info, err := os.Stat(keylogPath); err == nil {
		fmt.Printf("Key log file created: %s (%d bytes)\n", keylogPath, info.Size())
		fmt.Println("Use in Wireshark: Edit -> Preferences -> Protocols -> TLS -> Pre-Master-Secret log filename")
	} else {
		fmt.Println("Key log file not found")
	}

	// ==========================================================
	// Example 3: Local Address Binding
	// ==========================================================
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 3: Local Address Binding")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Println(`
Local address binding allows you to specify which local IP to use
for outgoing connections. This is essential for IPv6 rotation scenarios.

Usage:

// Bind to specific IPv6 address
session, _ := httpcloak.NewSession("chrome-144",
    httpcloak.WithLocalAddress("2001:db8::1"),
)

// Bind to specific IPv4 address
session, _ := httpcloak.NewSession("chrome-144",
    httpcloak.WithLocalAddress("192.168.1.100"),
)

Note: When local address is set, target IPs are filtered to match
the address family (IPv6 local -> only connects to IPv6 targets).

Example with your machine's IPs:
`)

	// This is a demonstration - replace with actual local IP
	// Uncomment to test with your real IPv6/IPv4:
	//
	// session3 := httpcloak.NewSession("chrome-144",
	//     httpcloak.WithLocalAddress("YOUR_LOCAL_IP_HERE"),
	//     httpcloak.WithSessionTimeout(30*time.Second),
	// )
	// defer session3.Close()
	//
	// resp, err = session3.Get(ctx, "https://api.ipify.org", nil)
	// if err != nil {
	//     fmt.Printf("Error: %v\n", err)
	// } else {
	//     body, _ := resp.Text()
	//     fmt.Printf("Server saw IP: %s\n", body)
	// }

	// ==========================================================
	// Example 4: Speculative TLS for Proxy Connections
	// ==========================================================
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 4: Speculative TLS for Proxy Connections")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Println(`
Speculative TLS (disabled by default):
Sends CONNECT + TLS ClientHello together, saving one round-trip (~25% faster).
Enable it if your proxy supports it and you want the extra speed:

session := httpcloak.NewSession("chrome-144",
    httpcloak.WithProxy("http://user:pass@proxy.example.com:8080"),
    httpcloak.WithEnableSpeculativeTLS(),
)
`)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("New features examples completed!")
	fmt.Println(strings.Repeat("=", 60))
}
