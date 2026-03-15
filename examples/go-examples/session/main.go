// Example: Session management with cookies
//
// This example demonstrates:
// - Creating a persistent session
// - Automatic cookie handling
// - Login flow simulation
// - Cookie inspection
// - Manual cookie setting
// - Cookie clearing
// - Header order customization
//
// Run: go run main.go
package main

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

func main() {
	ctx := context.Background()

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("httpcloak - Session Examples")
	fmt.Println(strings.Repeat("=", 70))

	// =========================================================================
	// Example 1: Basic session with automatic cookie handling
	// =========================================================================
	fmt.Println("\n[1] Basic Session with Cookie Handling")
	fmt.Println(strings.Repeat("-", 50))

	// NewSession creates a client with cookie jar enabled
	session := client.NewSession("chrome-latest")
	defer session.Close()

	// First request - server sets cookies
	resp, err := session.Get(ctx, "https://httpbin.org/cookies/set/session_id/abc123", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Status: %d | Cookies set by server\n", resp.StatusCode)

	// Check cookies in jar
	cookies := session.Cookies()
	if cookies != nil {
		fmt.Printf("Cookies in jar: %d\n", cookies.Count())
	}

	// Second request - cookies are automatically sent
	resp, err = session.Get(ctx, "https://httpbin.org/cookies", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	respText, _ := resp.Text()
	fmt.Printf("Cookies sent with request: %s\n", respText)

	// =========================================================================
	// Example 2: Login flow simulation
	// =========================================================================
	fmt.Println("\n[2] Login Flow Simulation")
	fmt.Println(strings.Repeat("-", 50))

	loginSession := client.NewSession("chrome-latest",
		client.WithTimeout(30*time.Second),
	)
	defer loginSession.Close()

	// Step 1: Visit login page (may set CSRF cookie)
	fmt.Println("Step 1: Visiting login page...")
	resp, err = loginSession.Get(ctx, "https://httpbin.org/cookies/set/csrf_token/xyz789", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  Status: %d | CSRF cookie set\n", resp.StatusCode)

	// Step 2: Submit login (cookies sent automatically)
	fmt.Println("Step 2: Submitting login...")
	loginBody := []byte(`{"username": "testuser", "password": "testpass"}`)
	resp, err = loginSession.Post(ctx, "https://httpbin.org/post", bytes.NewReader(loginBody), map[string][]string{
		"Content-Type": {"application/json"},
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  Status: %d | Login submitted with cookies\n", resp.StatusCode)

	// Step 3: Access protected resource
	fmt.Println("Step 3: Accessing protected resource...")
	resp, err = loginSession.Get(ctx, "https://httpbin.org/cookies", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  Status: %d | Session maintained\n", resp.StatusCode)

	// =========================================================================
	// Example 3: Manual cookie management
	// =========================================================================
	fmt.Println("\n[3] Manual Cookie Management")
	fmt.Println(strings.Repeat("-", 50))

	manualSession := client.NewSession("chrome-latest")
	defer manualSession.Close()

	// Get the cookie jar and URL for the domain
	jar := manualSession.Cookies()
	httpbinURL, _ := url.Parse("https://httpbin.org/")

	// Manually set cookies
	jar.SetCookie(httpbinURL, "custom_cookie", "custom_value")
	jar.SetCookie(httpbinURL, "another_cookie", "another_value")
	fmt.Printf("Manually set 2 cookies\n")

	// Verify cookies are sent
	resp, err = manualSession.Get(ctx, "https://httpbin.org/cookies", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	respText, _ = resp.Text()
	fmt.Printf("Response shows cookies: %s\n", respText)

	// =========================================================================
	// Example 4: Cookie inspection
	// =========================================================================
	fmt.Println("\n[4] Cookie Inspection")
	fmt.Println(strings.Repeat("-", 50))

	inspectSession := client.NewSession("chrome-latest")
	defer inspectSession.Close()

	// Set multiple cookies
	inspectSession.Get(ctx, "https://httpbin.org/cookies/set/user_id/12345", nil)
	inspectSession.Get(ctx, "https://httpbin.org/cookies/set/theme/dark", nil)
	inspectSession.Get(ctx, "https://httpbin.org/cookies/set/lang/en", nil)

	jar = inspectSession.Cookies()
	fmt.Printf("Total cookies: %d\n", jar.Count())

	// Get all cookies for all domains
	allCookies := jar.AllCookies()
	for domain, cookies := range allCookies {
		fmt.Printf("\nDomain: %s\n", domain)
		for _, cookie := range cookies {
			fmt.Printf("  %s = %s\n", cookie.Name, cookie.Value)
		}
	}

	// =========================================================================
	// Example 5: Clear cookies
	// =========================================================================
	fmt.Println("\n[5] Clear Cookies")
	fmt.Println(strings.Repeat("-", 50))

	clearSession := client.NewSession("chrome-latest")
	defer clearSession.Close()

	// Set some cookies
	clearSession.Get(ctx, "https://httpbin.org/cookies/set/temp/data", nil)
	fmt.Printf("Before clear: %d cookies\n", clearSession.Cookies().Count())

	// Clear all cookies
	clearSession.ClearCookies()
	fmt.Printf("After clear: %d cookies\n", clearSession.Cookies().Count())

	// =========================================================================
	// Example 6: Enable cookies on existing client
	// =========================================================================
	fmt.Println("\n[6] Enable Cookies on Existing Client")
	fmt.Println(strings.Repeat("-", 50))

	// Start with regular client (no cookies)
	regularClient := client.NewClient("chrome-latest")
	defer regularClient.Close()

	fmt.Printf("Cookies enabled: %v\n", regularClient.Cookies() != nil)

	// Enable cookies
	regularClient.EnableCookies()
	fmt.Printf("Cookies enabled: %v\n", regularClient.Cookies() != nil)

	// Now cookies work
	regularClient.Get(ctx, "https://httpbin.org/cookies/set/enabled/true", nil)
	fmt.Printf("Cookie count: %d\n", regularClient.Cookies().Count())

	// =========================================================================
	// Example 7: Session with all options
	// =========================================================================
	fmt.Println("\n[7] Session with All Options")
	fmt.Println(strings.Repeat("-", 50))

	fullSession := client.NewSession("chrome-latest",
		client.WithTimeout(60*time.Second),
		client.WithRetry(3),
		client.WithRedirects(true, 5),
	)
	defer fullSession.Close()

	resp, err = fullSession.Get(ctx, "https://httpbin.org/get", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Status: %d | Full-featured session\n", resp.StatusCode)

	// =========================================================================
	// Example 8: Multiple sessions (isolated cookies)
	// =========================================================================
	fmt.Println("\n[8] Multiple Isolated Sessions")
	fmt.Println(strings.Repeat("-", 50))

	session1 := client.NewSession("chrome-latest")
	session2 := client.NewSession("chrome-latest")
	defer session1.Close()
	defer session2.Close()

	// Set different cookies in each session
	session1.Get(ctx, "https://httpbin.org/cookies/set/user/alice", nil)
	session2.Get(ctx, "https://httpbin.org/cookies/set/user/bob", nil)

	// Verify isolation
	resp1, _ := session1.Get(ctx, "https://httpbin.org/cookies", nil)
	resp2, _ := session2.Get(ctx, "https://httpbin.org/cookies", nil)

	resp1Text, _ := resp1.Text()
	resp2Text, _ := resp2.Text()
	fmt.Printf("Session 1 cookies: %s", resp1Text)
	fmt.Printf("Session 2 cookies: %s", resp2Text)

	// =========================================================================
	// Example 9: Header order customization
	// =========================================================================
	fmt.Println("\n[9] Header Order Customization")
	fmt.Println(strings.Repeat("-", 50))

	headerSession := client.NewClient("chrome-latest")
	defer headerSession.Close()

	// Get default header order from preset
	defaultOrder := headerSession.GetHeaderOrder()
	fmt.Printf("Default header order (%d headers):\n", len(defaultOrder))
	for i, h := range defaultOrder[:5] {
		fmt.Printf("  %d. %s\n", i+1, h)
	}
	fmt.Printf("  ... and %d more\n", len(defaultOrder)-5)

	// Set custom header order
	customOrder := []string{"accept", "user-agent", "sec-ch-ua", "accept-language", "accept-encoding"}
	headerSession.SetHeaderOrder(customOrder)
	fmt.Printf("\nCustom order set: %v\n", headerSession.GetHeaderOrder())

	// Make request with custom order
	resp, err = headerSession.Get(ctx, "https://httpbin.org/headers", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Request with custom order - Status: %d, Protocol: %s\n", resp.StatusCode, resp.Protocol)
	}

	// Reset to default
	headerSession.SetHeaderOrder(nil)
	resetOrder := headerSession.GetHeaderOrder()
	fmt.Printf("Reset to default (%d headers): %v...\n", len(resetOrder), resetOrder[:3])

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("All session examples completed!")
	fmt.Println(strings.Repeat("=", 70))
}
