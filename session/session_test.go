package session

import "testing"

func TestResolveURL(t *testing.T) {
	tests := []struct {
		name     string
		base     string
		ref      string
		expected string
	}{
		// Basic cases
		{
			name:     "absolute path",
			base:     "https://example.com/path",
			ref:      "/api/v1",
			expected: "https://example.com/api/v1",
		},
		{
			name:     "relative path without trailing slash",
			base:     "https://example.com/v1",
			ref:      "users",
			expected: "https://example.com/users",
		},
		{
			name:     "relative path with trailing slash",
			base:     "https://example.com/v1/",
			ref:      "users",
			expected: "https://example.com/v1/users",
		},
		{
			name:     "absolute URL",
			base:     "https://example.com",
			ref:      "https://other.com/path",
			expected: "https://other.com/path",
		},
		{
			name:     "protocol-relative URL",
			base:     "https://example.com",
			ref:      "//cdn.example.com/file",
			expected: "https://cdn.example.com/file",
		},

		// RFC 3986 edge cases - ./ normalization
		{
			name:     "current directory ./ normalization",
			base:     "https://example.com/app/",
			ref:      "./resource?foo=bar&id=12345",
			expected: "https://example.com/app/resource?foo=bar&id=12345",
		},
		{
			name:     "current directory ./ simple",
			base:     "https://example.com/path/",
			ref:      "./file",
			expected: "https://example.com/path/file",
		},
		{
			name:     "parent directory ../",
			base:     "https://example.com/a/b/c",
			ref:      "../d",
			expected: "https://example.com/a/d",
		},
		{
			name:     "parent directory ../ with trailing slash",
			base:     "https://example.com/a/b/c/",
			ref:      "../d",
			expected: "https://example.com/a/b/d",
		},
		{
			name:     "multiple parent directories",
			base:     "https://example.com/a/b/c",
			ref:      "../../d",
			expected: "https://example.com/d",
		},

		// Query strings and fragments
		{
			name:     "base with query, relative path",
			base:     "https://example.com/path?foo=bar",
			ref:      "newpath",
			expected: "https://example.com/newpath",
		},
		{
			name:     "relative query only",
			base:     "https://example.com/path",
			ref:      "?query=value",
			expected: "https://example.com/path?query=value",
		},
		{
			name:     "relative fragment only",
			base:     "https://example.com/path",
			ref:      "#fragment",
			expected: "https://example.com/path#fragment",
		},
		{
			name:     "query replaces base query",
			base:     "https://example.com/path?old=query",
			ref:      "?new=query",
			expected: "https://example.com/path?new=query",
		},

		// Empty and edge cases
		{
			name:     "empty reference",
			base:     "https://example.com/path",
			ref:      "",
			expected: "https://example.com/path",
		},
		{
			name:     "root-relative with query",
			base:     "https://example.com/old/path?query=1",
			ref:      "/new/path",
			expected: "https://example.com/new/path",
		},
		{
			name:     "percent-encoded path",
			base:     "https://example.com/path",
			ref:      "file%20name.txt",
			expected: "https://example.com/file%20name.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveURL(tt.base, tt.ref)
			if result != tt.expected {
				t.Errorf("resolveURL(%q, %q)\n  got:      %q\n  expected: %q",
					tt.base, tt.ref, result, tt.expected)
			}
		})
	}
}
