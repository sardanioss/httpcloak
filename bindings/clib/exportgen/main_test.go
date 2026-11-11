package main

import "testing"

// TestGeneratedFilesUpToDate is the same check as `go run ./exportgen -check`.
func TestGeneratedFilesUpToDate(t *testing.T) {
	files, err := generate("..")
	if err != nil {
		t.Fatal(err)
	}
	if names := stale("..", files); len(names) > 0 {
		t.Fatalf("%v out of date; run: go run ./exportgen (in bindings/clib)", names)
	}
}
