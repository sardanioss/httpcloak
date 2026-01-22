// Example: Streaming Downloads with httpcloak
//
// This example demonstrates how to stream large files without loading
// them entirely into memory.
//
// What you'll learn:
// - Using GetStream() for memory-efficient downloads
// - Reading response data in chunks
// - Progress tracking during downloads
// - When to use streaming vs Get()
//
// Use Cases:
// - Downloading files larger than available memory
// - Progress bars for large downloads
// - Processing data as it arrives
// - Piping data to another destination
//
// Run: go run main.go
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak"
)

func main() {
	ctx := context.Background()

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("httpcloak - Streaming Downloads")
	fmt.Println(strings.Repeat("=", 70))

	// =========================================================================
	// Understanding Streaming
	// =========================================================================
	fmt.Println("\n[INFO] Understanding Streaming")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println(`
Streaming allows you to process response data as it arrives,
without loading the entire response into memory.

Use streaming when:
- File is larger than available memory
- You want to show download progress
- Processing data incrementally (parsing, transforming)
- Writing to disk as data arrives`)

	session := httpcloak.NewSession("chrome-143")
	defer session.Close()

	// =========================================================================
	// Example 1: Basic Streaming
	// =========================================================================
	fmt.Println("\n[1] Basic Streaming")
	fmt.Println(strings.Repeat("-", 50))

	stream, err := session.GetStream(ctx, "https://httpbin.org/bytes/102400")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Status Code: %d\n", stream.StatusCode)
	fmt.Printf("Protocol: %s\n", stream.Protocol)
	fmt.Printf("Content-Length: %d\n", stream.ContentLength)

	// Read data in chunks
	buf := make([]byte, 8192)
	totalBytes := 0
	chunkCount := 0

	for {
		n, err := stream.Read(buf)
		if n > 0 {
			totalBytes += n
			chunkCount++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Read error: %v\n", err)
			break
		}
	}
	stream.Close()

	fmt.Printf("Read %d bytes in %d chunks\n", totalBytes, chunkCount)

	// =========================================================================
	// Example 2: Download with Progress
	// =========================================================================
	fmt.Println("\n[2] Download with Progress")
	fmt.Println(strings.Repeat("-", 50))

	stream, err = session.GetStream(ctx, "https://httpbin.org/bytes/51200")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	contentLength := stream.ContentLength
	downloaded := 0

	fmt.Printf("Downloading %d bytes...\n", contentLength)
	startTime := time.Now()

	for {
		n, err := stream.Read(buf[:4096])
		if n > 0 {
			downloaded += n

			// Show progress
			if contentLength > 0 {
				percent := float64(downloaded) / float64(contentLength) * 100
				barWidth := 40
				filled := int(float64(barWidth) * float64(downloaded) / float64(contentLength))
				bar := strings.Repeat("=", filled) + strings.Repeat("-", barWidth-filled)
				fmt.Printf("\r[%s] %.1f%%", bar, percent)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}

	elapsed := time.Since(startTime)
	stream.Close()

	fmt.Printf("\nCompleted: %d bytes in %dms\n", downloaded, elapsed.Milliseconds())

	// =========================================================================
	// Example 3: Stream to File
	// =========================================================================
	fmt.Println("\n[3] Stream to File")
	fmt.Println(strings.Repeat("-", 50))

	stream, err = session.GetStream(ctx, "https://httpbin.org/bytes/102400")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	tmpFile, err := os.CreateTemp("", "httpcloak_stream_*.bin")
	if err != nil {
		fmt.Printf("Error creating temp file: %v\n", err)
		return
	}
	tempPath := tmpFile.Name()

	bytesWritten := int64(0)
	for {
		n, err := stream.Read(buf[:16384])
		if n > 0 {
			tmpFile.Write(buf[:n])
			bytesWritten += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}

	tmpFile.Close()
	stream.Close()

	fileInfo, _ := os.Stat(tempPath)
	fmt.Printf("Streamed %d bytes to file\n", bytesWritten)
	fmt.Printf("File size on disk: %d bytes\n", fileInfo.Size())
	os.Remove(tempPath)

	// =========================================================================
	// Example 4: io.Copy for Simple Streaming
	// =========================================================================
	fmt.Println("\n[4] Using io.Copy for Simple Streaming")
	fmt.Println(strings.Repeat("-", 50))

	stream, err = session.GetStream(ctx, "https://httpbin.org/bytes/32768")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// StreamResponse implements io.Reader, so io.Copy works
	bytesCopied, _ := io.Copy(io.Discard, stream)
	stream.Close()

	fmt.Printf("Copied %d bytes using io.Copy\n", bytesCopied)

	// =========================================================================
	// Example 5: Streaming with Different Protocols
	// =========================================================================
	fmt.Println("\n[5] Streaming with Different Protocols")
	fmt.Println(strings.Repeat("-", 50))

	// HTTP/2 streaming
	sessionH2 := httpcloak.NewSession("chrome-143", httpcloak.WithForceHTTP2())
	stream, err = sessionH2.GetStream(ctx, "https://cloudflare.com/cdn-cgi/trace")
	if err != nil {
		fmt.Printf("HTTP/2 stream error: %v\n", err)
	} else {
		data, err := io.ReadAll(stream)
		if err != nil {
			fmt.Printf("HTTP/2 read error: %v\n", err)
		} else {
			fmt.Printf("HTTP/2 stream: %d bytes, protocol: %s\n", len(data), stream.Protocol)
		}
		stream.Close()
	}
	sessionH2.Close()

	// HTTP/3 streaming
	sessionH3 := httpcloak.NewSession("chrome-143", httpcloak.WithForceHTTP3())
	stream, err = sessionH3.GetStream(ctx, "https://cloudflare.com/cdn-cgi/trace")
	if err != nil {
		fmt.Printf("HTTP/3 stream error: %v\n", err)
	} else {
		data, err := io.ReadAll(stream)
		if err != nil {
			fmt.Printf("HTTP/3 read error: %v\n", err)
		} else {
			fmt.Printf("HTTP/3 stream: %d bytes, protocol: %s\n", len(data), stream.Protocol)
		}
		stream.Close()
	}
	sessionH3.Close()

	// =========================================================================
	// Example 6: When to Use Streaming vs Get()
	// =========================================================================
	fmt.Println("\n[6] Streaming vs Get() Comparison")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println(`
STREAMING (GetStream):
- Memory efficient - only holds buffer at a time
- Good for files larger than RAM
- Enables progress tracking
- Implements io.Reader interface

GET with Release():
- Fastest download speed (~9000 MB/s)
- Loads entire response into memory
- Best for files that fit in memory
- Buffer pooling reduces allocations

RECOMMENDATIONS:
- Files < 100MB: Use Get() + Release()
- Files > 100MB or unknown size: Use streaming
- Need progress bar: Use streaming
- Memory constrained: Use streaming`)

	// =========================================================================
	// Summary
	// =========================================================================
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("SUMMARY")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println(`
Streaming methods:
- GetStream(ctx, url) - Start streaming GET request
- stream.Read(buf) - Read into buffer (io.Reader interface)
- io.ReadAll(stream) - Read all data
- io.Copy(dst, stream) - Copy to writer
- stream.Close() - Close the stream

Properties:
- stream.StatusCode - HTTP status
- stream.Headers - Response headers
- stream.ContentLength - Total size (if known)
- stream.Protocol - HTTP protocol used
`)
}
