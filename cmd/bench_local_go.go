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
	fmt.Println("GO LOCAL BENCHMARK (100MB)")
	fmt.Println("=" + fmt.Sprintf("%59s", ""))

	c := client.NewClient("chrome-143", client.WithInsecureSkipVerify())
	defer c.Close()

	url := "https://127.0.0.1:8443/stream/100"
	ctx := context.Background()

	// Warmup
	fmt.Println("\nWarming up...")
	c.Get(ctx, "https://127.0.0.1:8443/stream/1", nil)

	// 1. Buffered download
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
		fmt.Printf("  Run %d: %d MB in %dms = %.1f MB/s\n", i+1, len(data)/(1024*1024), elapsed.Milliseconds(), speed)
	}

	// 2. Streaming (io.ReadAll)
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
		fmt.Printf("  Run %d: %d MB in %dms = %.1f MB/s\n", i+1, len(data)/(1024*1024), elapsed.Milliseconds(), speed)
	}

	// 3. Chunked read
	fmt.Println("\n[3] Chunked Read (64KB)")
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
		fmt.Printf("  Run %d: %d MB in %dms = %.1f MB/s\n", i+1, total/(1024*1024), elapsed.Milliseconds(), speed)
	}

	fmt.Println("\n" + "=" + fmt.Sprintf("%59s", ""))
}
