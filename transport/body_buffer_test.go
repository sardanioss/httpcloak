package transport

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
)

// Regression tests for the response-body buffer aliasing bug.
//
// readBodyOptimized used to hand the caller a slice of a pooled buffer whenever
// Content-Length was known. That slice escaped into the Response. On the
// Content-Encoding path the buffer was then returned to the pool while the
// Response still pointed into it, so the next request could take the same
// buffer and overwrite a body that had already been handed to the caller -
// silent cross-request corruption rather than a crash.
//
// The invariant these lock: the returned body is owned solely by the caller and
// is never a window into a larger shared buffer.

func TestReadBodyDoesNotAliasPooledBuffer(t *testing.T) {
	// Sizes chosen to land in each of the pool size classes the old code used.
	for _, size := range []int{512 * 1024, 2 * 1024 * 1024, 12 * 1024 * 1024} {
		t.Run(fmt.Sprintf("%dKiB", size/1024), func(t *testing.T) {
			src := bytes.Repeat([]byte{'x'}, size)

			body, err := readBodyOptimized(bytes.NewReader(src), int64(size))
			if err != nil {
				t.Fatalf("readBodyOptimized: %v", err)
			}
			if len(body) != size {
				t.Fatalf("len(body) = %d, want %d", len(body), size)
			}

			// A pooled buffer is a fixed size class (1MB/10MB/100MB) sliced down
			// to the body length, so its capacity is much larger than its length.
			// An exclusively owned buffer is exactly sized.
			if cap(body) != len(body) {
				t.Fatalf("body has cap=%d for len=%d: it is a window into a shared "+
					"pooled buffer and can be overwritten by a later request",
					cap(body), len(body))
			}
		})
	}
}

// The chunked/unknown-length path uses a pooled scratch buffer internally. It
// must still copy out before handing anything back.
func TestReadBodyChunkedDoesNotAliasScratch(t *testing.T) {
	// Larger than the 1MB scratch so the grow-and-copy path runs too.
	src := bytes.Repeat([]byte{'y'}, 3*1024*1024)

	// contentLength <= 0 selects the chunked path.
	body, err := readBodyOptimized(bytes.NewReader(src), -1)
	if err != nil {
		t.Fatalf("readBodyOptimized: %v", err)
	}
	if !bytes.Equal(body, src) {
		t.Fatalf("chunked body mismatch: got %d bytes, want %d", len(body), len(src))
	}
	if cap(body) != len(body) {
		t.Fatalf("chunked body has cap=%d for len=%d: it still aliases the scratch buffer",
			cap(body), len(body))
	}
}

// Concurrent reads must not see each other's bytes. Run with -race.
func TestReadBodyConcurrentIntegrity(t *testing.T) {
	const (
		workers = 16
		rounds  = 8
		size    = 1500 * 1024 // over 1MB, so the old code used the 10MB pool
	)

	var wg sync.WaitGroup
	errs := make(chan error, workers*rounds)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Each worker uses a distinct fill byte, so any cross-contamination
			// between concurrently pooled buffers shows up immediately.
			fill := byte('A' + id)
			want := bytes.Repeat([]byte{fill}, size)

			for r := 0; r < rounds; r++ {
				body, err := readBodyOptimized(bytes.NewReader(want), int64(size))
				if err != nil {
					errs <- fmt.Errorf("worker %d round %d: %v", id, r, err)
					return
				}
				if !bytes.Equal(body, want) {
					bad := -1
					for i := range body {
						if body[i] != fill {
							bad = i
							break
						}
					}
					errs <- fmt.Errorf("worker %d round %d: body corrupted at offset %d", id, r, bad)
					return
				}
			}
		}(w)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// A short read (server closed early) must still return only the bytes actually
// received, and still own its buffer.
func TestReadBodyShortReadOwnsBuffer(t *testing.T) {
	const declared = 4 * 1024 * 1024
	actual := bytes.Repeat([]byte{'z'}, 1024)

	body, err := readBodyOptimized(io.LimitReader(bytes.NewReader(actual), int64(len(actual))), declared)
	if err != nil {
		t.Fatalf("readBodyOptimized: %v", err)
	}
	if len(body) != len(actual) {
		t.Fatalf("len(body) = %d, want %d", len(body), len(actual))
	}
	if !bytes.Equal(body, actual) {
		t.Fatal("short-read body contents differ from what was sent")
	}
}
