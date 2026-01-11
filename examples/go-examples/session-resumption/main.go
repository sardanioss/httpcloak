// Example: Session Resumption (0-RTT)
//
// This example demonstrates TLS session resumption which dramatically
// improves bot detection scores by making connections look like
// returning visitors rather than new connections.
//
// Key concepts:
// - First connection: Bot score ~43 (new TLS handshake)
// - Resumed connection: Bot score ~99 (looks like returning visitor)
// - Cross-domain warming: Session tickets work across same-infrastructure sites
//
// Run: go run main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak"
)

const sessionFile = "session_state.json"

type CFResponse struct {
	BotManagement struct {
		Score int `json:"score"`
	} `json:"botManagement"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Session Resumption Examples")
	fmt.Println(strings.Repeat("=", 60))

	example1SaveLoad(ctx)
	example2MarshalUnmarshal(ctx)
	example3CrossDomainWarming(ctx)
	example4ProductionPattern(ctx)

	// Cleanup
	os.Remove(sessionFile)
	os.Remove("my_scraper.json")

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Session resumption examples completed!")
	fmt.Println(strings.Repeat("=", 60))
}

// =============================================================================
// Example 1: Basic Session Save/Load (File-based)
// =============================================================================
func example1SaveLoad(ctx context.Context) {
	fmt.Println("\n[1] Save and Load Session (File)")
	fmt.Println(strings.Repeat("-", 50))

	var session *httpcloak.Session

	// Check if we have a saved session
	if _, err := os.Stat(sessionFile); err == nil {
		fmt.Println("Loading existing session...")
		session, err = httpcloak.LoadSession(sessionFile)
		if err != nil {
			fmt.Printf("Failed to load: %v, creating new\n", err)
			session = httpcloak.NewSession("chrome-143")
		} else {
			fmt.Println("Session loaded with TLS tickets!")
		}
	} else {
		fmt.Println("Creating new session...")
		session = httpcloak.NewSession("chrome-143")

		// Warm up - this acquires TLS session tickets
		fmt.Println("Warming up session...")
		resp, _ := session.Get(ctx, "https://cloudflare.com/cdn-cgi/trace")
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			fmt.Printf("Warmup complete - Protocol: %s\n", resp.Protocol)
		}
	}
	defer session.Close()

	// Make request (will use 0-RTT if session was loaded)
	resp, _ := session.Get(ctx, "https://www.cloudflare.com/cdn-cgi/trace")
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Printf("Request - Protocol: %s\n", resp.Protocol)
	}

	// Save session for next run
	if err := session.Save(sessionFile); err != nil {
		fmt.Printf("Failed to save: %v\n", err)
	} else {
		fmt.Printf("Session saved to %s\n", sessionFile)
	}
}

// =============================================================================
// Example 2: Marshal/Unmarshal (For databases, Redis, etc.)
// =============================================================================
func example2MarshalUnmarshal(ctx context.Context) {
	fmt.Println("\n[2] Marshal/Unmarshal Session (Bytes)")
	fmt.Println(strings.Repeat("-", 50))

	// Create and warm up session
	session := httpcloak.NewSession("chrome-143")
	resp, _ := session.Get(ctx, "https://cloudflare.com/")
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Export to bytes (store in Redis, database, etc.)
	sessionData, err := session.Marshal()
	if err != nil {
		fmt.Printf("Marshal failed: %v\n", err)
		session.Close()
		return
	}
	fmt.Printf("Marshaled session: %d bytes\n", len(sessionData))
	session.Close()

	// Later: restore from bytes
	restored, err := httpcloak.UnmarshalSession(sessionData)
	if err != nil {
		fmt.Printf("Unmarshal failed: %v\n", err)
		return
	}
	defer restored.Close()

	resp, _ = restored.Get(ctx, "https://www.cloudflare.com/cdn-cgi/trace")
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Printf("Restored session request - Protocol: %s\n", resp.Protocol)
	}
}

// =============================================================================
// Example 3: Cross-Domain Session Warming (Cloudflare)
// =============================================================================
func example3CrossDomainWarming(ctx context.Context) {
	fmt.Println("\n[3] Cross-Domain Warming")
	fmt.Println(strings.Repeat("-", 50))

	session := httpcloak.NewSession("chrome-143")
	defer session.Close()

	// Warm up on cloudflare.com (safe, no bot detection)
	fmt.Println("Warming up on cloudflare.com...")
	resp, _ := session.Get(ctx, "https://cloudflare.com/cdn-cgi/trace")
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Printf("Warmup - Protocol: %s\n", resp.Protocol)
	}

	// The TLS session ticket works on OTHER Cloudflare sites!
	fmt.Println("\nUsing warmed session on cf.erisa.uk (CF-protected)...")
	resp, _ = session.Get(ctx, "https://cf.erisa.uk/")
	if resp != nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var cf CFResponse
		json.Unmarshal(body, &cf)
		fmt.Printf("Bot Score: %d\n", cf.BotManagement.Score)
		fmt.Printf("Protocol: %s\n", resp.Protocol)
	}
}

// =============================================================================
// Example 4: Production Pattern
// =============================================================================
func example4ProductionPattern(ctx context.Context) {
	fmt.Println("\n[4] Production Pattern")
	fmt.Println(strings.Repeat("-", 50))

	session := getOrCreateSession(ctx, "my_scraper")
	defer session.Close()

	resp, _ := session.Get(ctx, "https://cf.erisa.uk/")
	if resp != nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var cf CFResponse
		json.Unmarshal(body, &cf)
		fmt.Printf("Bot Score: %d\n", cf.BotManagement.Score)
	}
}

// getOrCreateSession gets an existing session or creates and warms up a new one.
// In production, you'd use Redis/database instead of files.
func getOrCreateSession(ctx context.Context, sessionKey string) *httpcloak.Session {
	sessionPath := sessionKey + ".json"

	if _, err := os.Stat(sessionPath); err == nil {
		session, err := httpcloak.LoadSession(sessionPath)
		if err == nil {
			return session
		}
	}

	// Create new session and warm it up
	session := httpcloak.NewSession("chrome-143")

	// Warm up on a neutral Cloudflare endpoint
	resp, _ := session.Get(ctx, "https://cloudflare.com/cdn-cgi/trace")
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Save for future use
	session.Save(sessionPath)

	return session
}
