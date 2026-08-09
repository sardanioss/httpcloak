package transport

import (
	"errors"
	stdhttp "net/http"
	"net/url"
	"testing"
)

// locationCases drives both the direct tests and the net/http parity check.
// FinalURL is the URL of the request that produced the response; location is
// the raw Location header value as a server would send it.
var locationCases = []struct {
	name     string
	finalURL string
	location string
	want     string
}{
	{"absolute", "https://example.com/start", "https://other.example/next", "https://other.example/next"},
	{"root relative", "https://example.com/a/b?q=1", "/login", "https://example.com/login"},
	{"path relative", "https://example.com/a/b", "c/d", "https://example.com/a/c/d"},
	{"parent traversal", "https://example.com/a/b/c", "../up", "https://example.com/a/up"},
	{"query only", "https://example.com/a", "?page=2", "https://example.com/a?page=2"},
	{"fragment only", "https://example.com/a", "#section", "https://example.com/a#section"},
	{"protocol relative", "https://example.com/a", "//cdn.example/x", "https://cdn.example/x"},
	{"scheme downgrade", "https://example.com/a", "http://example.com/plain", "http://example.com/plain"},
	{"no base absolute", "", "https://example.com/abs", "https://example.com/abs"},
	{"no base relative", "", "/login", "/login"},
}

func TestResponseLocation(t *testing.T) {
	for _, tt := range locationCases {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{
				FinalURL: tt.finalURL,
				Headers:  map[string][]string{"location": {tt.location}},
			}
			got, err := resp.Location()
			if err != nil {
				t.Fatalf("Location() error = %v", err)
			}
			if got.String() != tt.want {
				t.Errorf("Location() = %q, want %q", got.String(), tt.want)
			}
		})
	}
}

// TestResponseLocationStdlibParity locks the resolution semantics to
// net/http's Response.Location: same header, same base URL, same result.
func TestResponseLocationStdlibParity(t *testing.T) {
	for _, tt := range locationCases {
		t.Run(tt.name, func(t *testing.T) {
			std := &stdhttp.Response{
				Header: stdhttp.Header{"Location": {tt.location}},
			}
			if tt.finalURL != "" {
				base, err := url.Parse(tt.finalURL)
				if err != nil {
					t.Fatalf("parse base: %v", err)
				}
				std.Request = &stdhttp.Request{URL: base}
			}
			want, err := std.Location()
			if err != nil {
				t.Fatalf("stdlib Location() error = %v", err)
			}

			resp := &Response{
				FinalURL: tt.finalURL,
				Headers:  map[string][]string{"location": {tt.location}},
			}
			got, err := resp.Location()
			if err != nil {
				t.Fatalf("Location() error = %v", err)
			}
			if got.String() != want.String() {
				t.Errorf("Location() = %q, stdlib = %q", got.String(), want.String())
			}
		})
	}
}

func TestResponseLocationMissing(t *testing.T) {
	for _, resp := range []*Response{
		{FinalURL: "https://example.com/", Headers: nil},
		{FinalURL: "https://example.com/", Headers: map[string][]string{}},
		{FinalURL: "https://example.com/", Headers: map[string][]string{"location": {""}}},
	} {
		if _, err := resp.Location(); !errors.Is(err, ErrNoLocation) {
			t.Errorf("Location() error = %v, want ErrNoLocation", err)
		}
	}
}

func TestResponseLocationFirstValueWins(t *testing.T) {
	resp := &Response{
		FinalURL: "https://example.com/",
		Headers:  map[string][]string{"location": {"/first", "/second"}},
	}
	got, err := resp.Location()
	if err != nil {
		t.Fatalf("Location() error = %v", err)
	}
	if got.String() != "https://example.com/first" {
		t.Errorf("Location() = %q, want %q", got.String(), "https://example.com/first")
	}
}
