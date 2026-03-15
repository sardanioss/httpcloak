// Example: High-Performance Downloads
//
// This example demonstrates:
// - Using Bytes() method to get response body
// - Benchmarking download speeds
// - Best practices for high-throughput scenarios
// - When to use streaming vs buffered downloads
//
// Run: go run main.go
package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak"
)

func main() {
	ctx := context.Background()

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("httpcloak - High-Performance Downloads")
	fmt.Println(strings.Repeat("=", 70))

	session := httpcloak.NewSession("chrome-latest")
	defer session.Close()

	// =========================================================================
	// Understanding Response Body Handling
	// =========================================================================
	fmt.Println("\n[INFO] Response Body Handling")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println(`
HTTPCloak uses io.ReadCloser for response bodies, enabling:
- Streaming large responses without loading into memory
- Efficient body handling with Bytes(), Text(), JSON() methods
- Automatic decompression (gzip, br, zstd)

Methods:
- resp.Bytes() - Read entire body as []byte (cached for reuse)
- resp.Text()  - Read body as string
- resp.JSON(&v) - Unmarshal body into struct
- resp.Body    - Raw io.ReadCloser for streaming`)

	// =========================================================================
	// Example 1: Basic usage with Bytes()
	// =========================================================================
	fmt.Println("\n[1] Basic Usage with Bytes()")
	fmt.Println(strings.Repeat("-", 50))

	resp, err := session.Get(ctx, "https://httpbin.org/bytes/1024")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Get the response body bytes
	body, err := resp.Bytes()
	if err != nil {
		fmt.Printf("Error reading body: %v\n", err)
		return
	}
	fmt.Printf("Downloaded %d bytes\n", len(body))

	// Bytes() caches the result - multiple calls return same data
	body2, _ := resp.Bytes()
	fmt.Printf("Second Bytes() call: %d bytes (cached)\n", len(body2))

	// =========================================================================
	// Example 2: Using Text() for string responses
	// =========================================================================
	fmt.Println("\n[2] Using Text() for String Responses")
	fmt.Println(strings.Repeat("-", 50))

	resp, err = session.Get(ctx, "https://httpbin.org/get")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	text, err := resp.Text()
	if err != nil {
		fmt.Printf("Error reading text: %v\n", err)
		return
	}
	fmt.Printf("Response text length: %d chars\n", len(text))

	// =========================================================================
	// Example 3: Using JSON() for structured responses
	// =========================================================================
	fmt.Println("\n[3] Using JSON() for Structured Responses")
	fmt.Println(strings.Repeat("-", 50))

	resp, err = session.Get(ctx, "https://httpbin.org/json")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Parse JSON directly from response
	var result map[string]interface{}
	if err := resp.JSON(&result); err == nil {
		fmt.Printf("Parsed JSON with %d top-level keys\n", len(result))
	}

	// =========================================================================
	// Example 4: High-throughput download loop
	// =========================================================================
	fmt.Println("\n[4] High-Throughput Download Loop")
	fmt.Println(strings.Repeat("-", 50))

	var totalBytes int64
	start := time.Now()
	iterations := 10

	for i := 0; i < iterations; i++ {
		resp, err := session.Get(ctx, "https://httpbin.org/bytes/102400")
		if err != nil {
			fmt.Printf("Error on iteration %d: %v\n", i, err)
			continue
		}
		body, err := resp.Bytes()
		if err != nil {
			fmt.Printf("Error reading body on iteration %d: %v\n", i, err)
			continue
		}
		totalBytes += int64(len(body))
	}

	elapsed := time.Since(start)
	speed := float64(totalBytes) / (1024 * 1024) / elapsed.Seconds()
	fmt.Printf("Downloaded %d requests, %.2f MB total\n", iterations, float64(totalBytes)/(1024*1024))
	fmt.Printf("Time: %v | Speed: %.1f MB/s\n", elapsed, speed)

	// =========================================================================
	// Example 5: Response Caching Behavior
	// =========================================================================
	fmt.Println("\n[5] Response Caching Behavior")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println(`
The Bytes(), Text(), and JSON() methods cache the body:
- First call: reads and caches the body
- Subsequent calls: return cached data

This allows safe multiple access to response data.`)

	resp, _ = session.Get(ctx, "https://httpbin.org/bytes/1024")
	bytes1, _ := resp.Bytes()
	bytes2, _ := resp.Bytes()
	fmt.Printf("First call: %d bytes, Second call: %d bytes\n", len(bytes1), len(bytes2))

	// =========================================================================
	// Example 6: Streaming for very large files
	// =========================================================================
	fmt.Println("\n[6] Use Streaming for Very Large Files")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println(`
For files larger than 100MB, use streaming instead:

    stream, _ := session.GetStream(ctx, url)
    defer stream.Close()

    buf := make([]byte, 1024*1024) // 1MB buffer
    for {
        n, err := stream.Read(buf)
        if n > 0 { processChunk(buf[:n]) }
        if err == io.EOF { break }
    }

Streaming doesn't load the entire file into memory.`)

	// =========================================================================
	// Best Practices Summary
	// =========================================================================
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("BEST PRACTICES SUMMARY")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println(`
1. Use Bytes()/Text()/JSON() for responses under 100MB
2. Use GetStream() for large files or when memory is constrained
3. Body is automatically decompressed (gzip, br, zstd)
4. Multiple reads from Bytes()/Text() return cached data
5. Connection pooling reduces latency for repeated requests
6. Use appropriate preset for your use case (chrome-latest, firefox-133, etc.)
`)
}
