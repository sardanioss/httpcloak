package pool

import (
	"testing"
)

// TestProxyURLParsing tests proxy URL parsing
func TestProxyURLParsing(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		scheme   string
		host     string
		port     string
		username string
		password string
	}{
		{
			name:   "http proxy simple",
			url:    "http://proxy.example.com:8080",
			scheme: "http",
			host:   "proxy.example.com",
			port:   "8080",
		},
		{
			name:   "http proxy with auth",
			url:    "http://user:pass@proxy.example.com:8080",
			scheme: "http",
			host:   "proxy.example.com",
			port:   "8080",
			username: "user",
			password: "pass",
		},
		{
			name:   "socks5 proxy",
			url:    "socks5://localhost:1080",
			scheme: "socks5",
			host:   "localhost",
			port:   "1080",
		},
		{
			name:   "socks5 with auth",
			url:    "socks5://admin:secret@proxy.local:1080",
			scheme: "socks5",
			host:   "proxy.local",
			port:   "1080",
			username: "admin",
			password: "secret",
		},
		{
			name:   "no scheme defaults to http",
			url:    "proxy.example.com:3128",
			scheme: "http",
			host:   "proxy.example.com",
			port:   "3128",
		},
		{
			name:   "http default port",
			url:    "http://proxy.example.com",
			scheme: "http",
			host:   "proxy.example.com",
			port:   "80",
		},
		{
			name:   "socks5 default port",
			url:    "socks5://proxy.example.com",
			scheme: "socks5",
			host:   "proxy.example.com",
			port:   "1080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := parseProxyURL(tt.url)
			if err != nil {
				t.Fatalf("parseProxyURL failed: %v", err)
			}

			if config.Scheme != tt.scheme {
				t.Errorf("Scheme: expected %s, got %s", tt.scheme, config.Scheme)
			}
			if config.Host != tt.host {
				t.Errorf("Host: expected %s, got %s", tt.host, config.Host)
			}
			if config.Port != tt.port {
				t.Errorf("Port: expected %s, got %s", tt.port, config.Port)
			}
			if config.Username != tt.username {
				t.Errorf("Username: expected %s, got %s", tt.username, config.Username)
			}
			if config.Password != tt.password {
				t.Errorf("Password: expected %s, got %s", tt.password, config.Password)
			}
		})
	}
}

// TestProxyConfigAddr tests proxy address formatting
func TestProxyConfigAddr(t *testing.T) {
	config := &proxyConfig{
		Host: "proxy.example.com",
		Port: "8080",
	}

	addr := config.Addr()
	expected := "proxy.example.com:8080"
	if addr != expected {
		t.Errorf("Addr: expected %s, got %s", expected, addr)
	}
}

// TestBase64Encode tests base64 encoding
func TestBase64Encode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"f", "Zg=="},
		{"fo", "Zm8="},
		{"foo", "Zm9v"},
		{"foob", "Zm9vYg=="},
		{"fooba", "Zm9vYmE="},
		{"foobar", "Zm9vYmFy"},
		{"user:pass", "dXNlcjpwYXNz"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := base64Encode([]byte(tt.input))
			if result != tt.expected {
				t.Errorf("base64Encode(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIsHTTP200 tests HTTP 200 detection
func TestIsHTTP200(t *testing.T) {
	tests := []struct {
		response string
		expected bool
	}{
		{"HTTP/1.1 200 OK\r\n", true},
		{"HTTP/1.0 200 OK\r\n", true},
		{"HTTP/1.1 200 Connection Established\r\n", true},
		{"HTTP/1.1 407 Proxy Authentication Required\r\n", false},
		{"HTTP/1.1 403 Forbidden\r\n", false},
		{"HTTP/1.1 500 Internal Server Error\r\n", false},
		{"Short", false},
	}

	for _, tt := range tests {
		t.Run(tt.response[:min(20, len(tt.response))], func(t *testing.T) {
			result := isHTTP200(tt.response)
			if result != tt.expected {
				t.Errorf("isHTTP200(%q) = %v, expected %v", tt.response, result, tt.expected)
			}
		})
	}
}

// TestGetFirstLine tests first line extraction
func TestGetFirstLine(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n", "HTTP/1.1 200 OK"},
		{"HTTP/1.1 200 OK\nContent-Length: 0\n", "HTTP/1.1 200 OK"},
		{"Single line", "Single line"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := getFirstLine(tt.input)
			if result != tt.expected {
				t.Errorf("getFirstLine(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestParsePort tests port parsing
func TestParsePort(t *testing.T) {
	tests := []struct {
		port     string
		expected int
		hasError bool
	}{
		{"443", 443, false},
		{"80", 80, false},
		{"8080", 8080, false},
		{"1080", 1080, false},
		{"abc", 0, true},
		{"12a3", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.port, func(t *testing.T) {
			result, err := parsePort(tt.port)
			if tt.hasError {
				if err == nil {
					t.Errorf("parsePort(%q) expected error, got nil", tt.port)
				}
			} else {
				if err != nil {
					t.Errorf("parsePort(%q) unexpected error: %v", tt.port, err)
				}
				if result != tt.expected {
					t.Errorf("parsePort(%q) = %d, expected %d", tt.port, result, tt.expected)
				}
			}
		})
	}
}

// TestIndexOf tests string index finding
func TestIndexOf(t *testing.T) {
	tests := []struct {
		s        string
		substr   string
		expected int
	}{
		{"hello world", "world", 6},
		{"hello world", "hello", 0},
		{"hello world", "xyz", -1},
		{"http://example.com", "://", 4},
		{"", "test", -1},
		{"test", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			result := indexOf(tt.s, tt.substr)
			if result != tt.expected {
				t.Errorf("indexOf(%q, %q) = %d, expected %d", tt.s, tt.substr, result, tt.expected)
			}
		})
	}
}

// TestLastIndexOf tests last string index finding
func TestLastIndexOf(t *testing.T) {
	tests := []struct {
		s        string
		substr   string
		expected int
	}{
		{"host:8080", ":", 4},
		{"192.168.1.1:8080", ":", 11},
		{"no-colon", ":", -1},
		{"::1", ":", 1}, // IPv6 localhost
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			result := lastIndexOf(tt.s, tt.substr)
			if result != tt.expected {
				t.Errorf("lastIndexOf(%q, %q) = %d, expected %d", tt.s, tt.substr, result, tt.expected)
			}
		})
	}
}

// TestHasScheme tests URL scheme detection
func TestHasScheme(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"http://example.com", true},
		{"https://example.com", true},
		{"socks5://localhost:1080", true},
		{"example.com:8080", false},
		{"localhost:3128", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			result := hasScheme(tt.url)
			if result != tt.expected {
				t.Errorf("hasScheme(%q) = %v, expected %v", tt.url, result, tt.expected)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Benchmark tests
func BenchmarkProxyURLParsing(b *testing.B) {
	for i := 0; i < b.N; i++ {
		parseProxyURL("socks5://user:pass@proxy.example.com:1080")
	}
}

func BenchmarkBase64Encode(b *testing.B) {
	data := []byte("username:password")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		base64Encode(data)
	}
}
