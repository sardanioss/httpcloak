package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func main() {
	// Serve random bytes
	http.HandleFunc("/stream/", func(w http.ResponseWriter, r *http.Request) {
		// Parse size from URL: /stream/100 = 100MB
		parts := strings.Split(r.URL.Path, "/")
		sizeMB := 100
		if len(parts) >= 3 {
			if s, err := strconv.Atoi(parts[2]); err == nil {
				sizeMB = s
			}
		}

		sizeBytes := sizeMB * 1024 * 1024
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(sizeBytes))

		// Write in chunks
		chunk := make([]byte, 64*1024)
		for i := range chunk {
			chunk[i] = byte(i % 256)
		}

		written := 0
		for written < sizeBytes {
			toWrite := len(chunk)
			if written+toWrite > sizeBytes {
				toWrite = sizeBytes - written
			}
			w.Write(chunk[:toWrite])
			written += toWrite
		}
	})

	// Upload endpoint
	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		total := 0
		buf := make([]byte, 64*1024)
		for {
			n, err := r.Body.Read(buf)
			total += n
			if err != nil {
				break
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"received": %d}`, total)
	})

	fmt.Println("Benchmark server running on http://127.0.0.1:8765")
	http.ListenAndServe("127.0.0.1:8765", nil)
}
