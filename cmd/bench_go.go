package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

func main() {
	fmt.Println("=" + fmt.Sprintf("%59s", ""))
	fmt.Println("GO SPEED BENCHMARK (100MB)")
	fmt.Println("=" + fmt.Sprintf("%59s", ""))

	c := client.NewClient("chrome-143")
	defer c.Close()

	// Use speed.cloudflare.com for reliable large downloads
	url := "https://speed.cloudflare.com/__down?bytes=104857600" // 100MB
	ctx := context.Background()

	// Warmup
	fmt.Println("\nWarming up...")
	c.Get(ctx, "https://speed.cloudflare.com/__down?bytes=1024", nil)

	// 1. Buffered download (Bytes)
	fmt.Println("\n[1] Buffered Download (Bytes())")
	fmt.Println("-" + fmt.Sprintf("%49s", ""))
	for i := 0; i < 3; i++ {
		start := time.Now()
		resp, err := c.Get(ctx, url, nil)
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
			continue
		}
		data, _ := resp.Bytes()
		elapsed := time.Since(start)
		speed := float64(len(data)) / (1024 * 1024) / elapsed.Seconds()
		fmt.Printf("  Run %d: %.1f MB in %dms = %.1f MB/s\n", i+1, float64(len(data))/(1024*1024), elapsed.Milliseconds(), speed)
	}

	// 2. Streaming download (io.ReadAll on Body)
	fmt.Println("\n[2] Streaming Download (io.ReadAll)")
	fmt.Println("-" + fmt.Sprintf("%49s", ""))
	for i := 0; i < 3; i++ {
		start := time.Now()
		resp, err := c.Get(ctx, url, nil)
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
			continue
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		elapsed := time.Since(start)
		speed := float64(len(data)) / (1024 * 1024) / elapsed.Seconds()
		fmt.Printf("  Run %d: %.1f MB in %dms = %.1f MB/s\n", i+1, float64(len(data))/(1024*1024), elapsed.Milliseconds(), speed)
	}

	// 3. Chunked read from Body
	fmt.Println("\n[3] Chunked Read (64KB chunks)")
	fmt.Println("-" + fmt.Sprintf("%49s", ""))
	for i := 0; i < 3; i++ {
		start := time.Now()
		resp, err := c.Get(ctx, url, nil)
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
			continue
		}
		total := 0
		buf := make([]byte, 64*1024)
		for {
			n, err := resp.Body.Read(buf)
			total += n
			if err != nil {
				break
			}
		}
		resp.Body.Close()
		elapsed := time.Since(start)
		speed := float64(total) / (1024 * 1024) / elapsed.Seconds()
		fmt.Printf("  Run %d: %.1f MB in %dms = %.1f MB/s\n", i+1, float64(total)/(1024*1024), elapsed.Milliseconds(), speed)
	}

	fmt.Println("\n" + "=" + fmt.Sprintf("%59s", ""))
}
