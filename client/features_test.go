package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	customhttp "github.com/sardanioss/http"
)

// TestURLBuilder tests URL building and params encoding
func TestURLBuilder(t *testing.T) {
	tests := []struct {
		name     string
		base     string
		params   map[string]string
		expected string
	}{
		{
			name:     "simple params",
			base:     "https://example.com/api",
			params:   map[string]string{"q": "test", "page": "1"},
			expected: "https://example.com/api?page=1&q=test",
		},
		{
			name:     "params with special chars",
			base:     "https://example.com/search",
			params:   map[string]string{"q": "hello world", "filter": "a&b"},
			expected: "https://example.com/search?filter=a%26b&q=hello+world",
		},
		{
			name:     "base with existing params",
			base:     "https://example.com/api?existing=yes",
			params:   map[string]string{"new": "param"},
			expected: "https://example.com/api?existing=yes&new=param",
		},
		{
			name:     "no params",
			base:     "https://example.com/api",
			params:   map[string]string{},
			expected: "https://example.com/api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewURLBuilder(tt.base)
			for k, v := range tt.params {
				builder.Param(k, v)
			}
			result := builder.BuildSorted()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestJoinURL tests URL joining
func TestJoinURL(t *testing.T) {
	tests := []struct {
		base     string
		path     string
		expected string
	}{
		{"https://example.com", "/api/v1", "https://example.com/api/v1"},
		{"https://example.com/v1", "users", "https://example.com/users"},
		{"https://example.com/v1/", "users", "https://example.com/v1/users"},
		{"https://example.com", "https://other.com/path", "https://other.com/path"},
		{"https://example.com", "//cdn.example.com/file", "https://cdn.example.com/file"},
	}

	for _, tt := range tests {
		t.Run(tt.base+"_"+tt.path, func(t *testing.T) {
			result := JoinURL(tt.base, tt.path)
			if result != tt.expected {
				t.Errorf("JoinURL(%s, %s) = %s, expected %s", tt.base, tt.path, result, tt.expected)
			}
		})
	}
}

// TestEncodeDecodeParams tests params encoding/decoding
func TestEncodeDecodeParams(t *testing.T) {
	params := map[string]string{
		"name":  "John Doe",
		"email": "john@example.com",
		"age":   "30",
	}

	encoded := EncodeParams(params)
	if encoded == "" {
		t.Error("EncodeParams returned empty string")
	}

	decoded, err := DecodeParams(encoded)
	if err != nil {
		t.Fatalf("DecodeParams failed: %v", err)
	}

	for k, v := range params {
		if decoded[k] != v {
			t.Errorf("decoded[%s] = %s, expected %s", k, decoded[k], v)
		}
	}
}

// TestMultipartFormData tests multipart form building
func TestMultipartFormData(t *testing.T) {
	form := NewFormData()
	form.AddField("name", "test")
	form.AddField("description", "A test file")
	form.AddFile("file", "test.txt", []byte("Hello, World!"))

	body, contentType, err := form.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if !strings.Contains(contentType, "multipart/form-data") {
		t.Errorf("Content-Type should contain multipart/form-data, got %s", contentType)
	}

	if !strings.Contains(contentType, "boundary=") {
		t.Error("Content-Type should contain boundary")
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "name=\"name\"") {
		t.Error("Body should contain name field")
	}
	if !strings.Contains(bodyStr, "test") {
		t.Error("Body should contain field value")
	}
	if !strings.Contains(bodyStr, "filename=\"test.txt\"") {
		t.Error("Body should contain filename")
	}
	if !strings.Contains(bodyStr, "Hello, World!") {
		t.Error("Body should contain file content")
	}
}

// TestBasicAuth tests Basic authentication
func TestBasicAuth(t *testing.T) {
	auth := NewBasicAuth("user", "pass")
	req, _ := customhttp.NewRequest("GET", "https://example.com", nil)

	err := auth.Apply(req)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	header := req.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Basic ") {
		t.Errorf("Authorization header should start with 'Basic ', got %s", header)
	}

	// Base64 of "user:pass" is "dXNlcjpwYXNz"
	if header != "Basic dXNlcjpwYXNz" {
		t.Errorf("Unexpected Authorization header: %s", header)
	}
}

// TestBearerAuth tests Bearer authentication
func TestBearerAuth(t *testing.T) {
	auth := NewBearerAuth("my-token-123")
	req, _ := customhttp.NewRequest("GET", "https://example.com", nil)

	err := auth.Apply(req)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	header := req.Header.Get("Authorization")
	if header != "Bearer my-token-123" {
		t.Errorf("Unexpected Authorization header: %s", header)
	}
}

// TestDigestAuthParsing tests Digest auth challenge parsing
func TestDigestAuthParsing(t *testing.T) {
	auth := NewDigestAuth("user", "pass")

	// Simulate a 401 response with WWW-Authenticate header
	resp := &customhttp.Response{
		StatusCode: 401,
		Header:     make(customhttp.Header),
	}
	resp.Header.Set("WWW-Authenticate", `Digest realm="test@example.com", nonce="abc123", qop="auth", opaque="xyz"`)

	req, _ := customhttp.NewRequest("GET", "https://example.com/protected", nil)
	shouldRetry, err := auth.HandleChallenge(resp, req)
	if err != nil {
		t.Fatalf("HandleChallenge failed: %v", err)
	}

	if !shouldRetry {
		t.Error("HandleChallenge should return true for valid digest challenge")
	}

	// Now apply should add the digest header
	err = auth.Apply(req)
	if err != nil {
		t.Fatalf("Apply after challenge failed: %v", err)
	}

	header := req.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Digest ") {
		t.Errorf("Authorization header should start with 'Digest ', got %s", header)
	}

	// Check required fields are present
	requiredFields := []string{"username=", "realm=", "nonce=", "uri=", "response="}
	for _, field := range requiredFields {
		if !strings.Contains(header, field) {
			t.Errorf("Authorization header missing %s", field)
		}
	}
}

// TestClientConfig tests client configuration options
func TestClientConfig(t *testing.T) {
	config := DefaultConfig()

	// Check defaults
	if config.Timeout != 30*time.Second {
		t.Errorf("Default timeout should be 30s, got %v", config.Timeout)
	}
	if !config.FollowRedirects {
		t.Error("FollowRedirects should be true by default")
	}
	if config.MaxRedirects != 10 {
		t.Errorf("MaxRedirects should be 10, got %d", config.MaxRedirects)
	}
	if config.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}
	if config.RetryEnabled {
		t.Error("RetryEnabled should be false by default")
	}

	// Test options
	WithTimeout(60 * time.Second)(config)
	if config.Timeout != 60*time.Second {
		t.Errorf("Timeout should be 60s, got %v", config.Timeout)
	}

	WithProxy("http://proxy:8080")(config)
	if config.Proxy != "http://proxy:8080" {
		t.Errorf("Proxy should be set, got %s", config.Proxy)
	}

	WithInsecureSkipVerify()(config)
	if !config.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true after option")
	}

	WithRetry(5)(config)
	if !config.RetryEnabled || config.MaxRetries != 5 {
		t.Errorf("Retry should be enabled with 5 retries, got enabled=%v, max=%d", config.RetryEnabled, config.MaxRetries)
	}

	WithoutRedirects()(config)
	if config.FollowRedirects {
		t.Error("FollowRedirects should be false after WithoutRedirects")
	}
}

// TestResponseHelpers tests Response helper methods
func TestResponseHelpers(t *testing.T) {
	// Test JSON decoding
	jsonBody := `{"name": "John", "age": 30}`
	resp := &Response{
		StatusCode: 200,
		Body:       []byte(jsonBody),
	}

	var data map[string]interface{}
	err := resp.JSON(&data)
	if err != nil {
		t.Fatalf("JSON decode failed: %v", err)
	}
	if data["name"] != "John" {
		t.Errorf("Expected name=John, got %v", data["name"])
	}

	// Test Text
	if resp.Text() != jsonBody {
		t.Errorf("Text() should return body as string")
	}

	// Test status helpers
	tests := []struct {
		code      int
		isSuccess bool
		isRedirect bool
		isClient  bool
		isServer  bool
	}{
		{200, true, false, false, false},
		{201, true, false, false, false},
		{301, false, true, false, false},
		{302, false, true, false, false},
		{400, false, false, true, false},
		{404, false, false, true, false},
		{500, false, false, false, true},
		{503, false, false, false, true},
	}

	for _, tt := range tests {
		resp := &Response{StatusCode: tt.code}
		if resp.IsSuccess() != tt.isSuccess {
			t.Errorf("StatusCode %d: IsSuccess() = %v, expected %v", tt.code, resp.IsSuccess(), tt.isSuccess)
		}
		if resp.IsRedirect() != tt.isRedirect {
			t.Errorf("StatusCode %d: IsRedirect() = %v, expected %v", tt.code, resp.IsRedirect(), tt.isRedirect)
		}
		if resp.IsClientError() != tt.isClient {
			t.Errorf("StatusCode %d: IsClientError() = %v, expected %v", tt.code, resp.IsClientError(), tt.isClient)
		}
		if resp.IsServerError() != tt.isServer {
			t.Errorf("StatusCode %d: IsServerError() = %v, expected %v", tt.code, resp.IsServerError(), tt.isServer)
		}
	}
}

// TestRetryLogic tests retry wait calculation
func TestRetryLogic(t *testing.T) {
	config := DefaultConfig()
	config.RetryEnabled = true
	config.RetryWaitMin = 100 * time.Millisecond
	config.RetryWaitMax = 1 * time.Second

	client := &Client{config: config}

	// Test exponential backoff
	wait1 := client.calculateRetryWait(1)
	wait2 := client.calculateRetryWait(2)
	wait3 := client.calculateRetryWait(3)

	// wait2 should be roughly 2x wait1 (with jitter)
	if wait2 < wait1 {
		t.Errorf("wait2 (%v) should be >= wait1 (%v)", wait2, wait1)
	}

	// All waits should be <= max
	if wait1 > config.RetryWaitMax || wait2 > config.RetryWaitMax || wait3 > config.RetryWaitMax {
		t.Errorf("Wait times should not exceed max: wait1=%v, wait2=%v, wait3=%v", wait1, wait2, wait3)
	}

	// Test retry on status
	config.RetryOnStatus = []int{429, 500, 502, 503, 504}
	if !client.shouldRetryStatus(429) {
		t.Error("Should retry on 429")
	}
	if !client.shouldRetryStatus(503) {
		t.Error("Should retry on 503")
	}
	if client.shouldRetryStatus(404) {
		t.Error("Should not retry on 404")
	}
	if client.shouldRetryStatus(200) {
		t.Error("Should not retry on 200")
	}
}

// TestSSEParsing tests Server-Sent Events parsing
func TestSSEParsing(t *testing.T) {
	sseData := `event: message
data: Hello, World!
id: 1

event: update
data: line1
data: line2
id: 2

: this is a comment
data: simple data

`

	reader := strings.NewReader(sseData)
	resp := &StreamResponse{
		reader: io.NopCloser(reader),
	}

	sse := NewSSEReader(resp)

	// Event 1
	event1, err := sse.Next()
	if err != nil {
		t.Fatalf("Failed to read event 1: %v", err)
	}
	if event1.Event != "message" {
		t.Errorf("Event 1 type should be 'message', got '%s'", event1.Event)
	}
	if event1.Data != "Hello, World!" {
		t.Errorf("Event 1 data should be 'Hello, World!', got '%s'", event1.Data)
	}
	if event1.ID != "1" {
		t.Errorf("Event 1 ID should be '1', got '%s'", event1.ID)
	}

	// Event 2 (multiline data)
	event2, err := sse.Next()
	if err != nil {
		t.Fatalf("Failed to read event 2: %v", err)
	}
	if event2.Event != "update" {
		t.Errorf("Event 2 type should be 'update', got '%s'", event2.Event)
	}
	if event2.Data != "line1\nline2" {
		t.Errorf("Event 2 data should be 'line1\\nline2', got '%s'", event2.Data)
	}

	// Event 3 (simple, with comment before it)
	event3, err := sse.Next()
	if err != nil {
		t.Fatalf("Failed to read event 3: %v", err)
	}
	if event3.Data != "simple data" {
		t.Errorf("Event 3 data should be 'simple data', got '%s'", event3.Data)
	}

	// Should get EOF
	_, err = sse.Next()
	if err != io.EOF {
		t.Errorf("Expected EOF, got %v", err)
	}
}

// TestMIMETypeDetection tests MIME type detection from filename
func TestMIMETypeDetection(t *testing.T) {
	tests := []struct {
		filename string
		expected string
	}{
		{"test.html", "text/html"},
		{"style.css", "text/css"},
		{"script.js", "application/javascript"},
		{"data.json", "application/json"},
		{"image.png", "image/png"},
		{"photo.jpg", "image/jpeg"},
		{"photo.jpeg", "image/jpeg"},
		{"doc.pdf", "application/pdf"},
		{"archive.zip", "application/zip"},
		{"unknown.xyz", "application/octet-stream"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result := detectMIMEType(tt.filename)
			if result != tt.expected {
				t.Errorf("detectMIMEType(%s) = %s, expected %s", tt.filename, result, tt.expected)
			}
		})
	}
}

// TestRedirectDetection tests redirect status detection
func TestRedirectDetection(t *testing.T) {
	redirectCodes := []int{301, 302, 303, 307, 308}
	nonRedirectCodes := []int{200, 201, 400, 404, 500}

	for _, code := range redirectCodes {
		if !isRedirect(code) {
			t.Errorf("%d should be a redirect", code)
		}
	}

	for _, code := range nonRedirectCodes {
		if isRedirect(code) {
			t.Errorf("%d should not be a redirect", code)
		}
	}
}

// Integration test with mock server (tests actual HTTP flow)
func TestIntegrationWithMockServer(t *testing.T) {
	// Skip if running short tests
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	var requestCount int32

	// Create test server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		path := r.URL.Path

		switch path {
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

		case "/redirect":
			http.Redirect(w, r, "/final", http.StatusFound)

		case "/final":
			fmt.Fprint(w, "Redirected!")

		case "/retry":
			count := atomic.LoadInt32(&requestCount)
			if count < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			fmt.Fprint(w, "Success after retries")

		case "/auth":
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, "Authenticated")

		case "/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "Streaming not supported", http.StatusInternalServerError)
				return
			}
			for i := 1; i <= 3; i++ {
				fmt.Fprintf(w, "data: message %d\n\n", i)
				flusher.Flush()
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Logf("Test server running at %s", server.URL)
	t.Log("Note: Full integration tests require the actual Client with HTTPS support")
	t.Log("These tests verify the mock server works correctly")

	// Test the mock server directly
	client := server.Client()

	// Test JSON endpoint
	resp, err := client.Get(server.URL + "/json")
	if err != nil {
		t.Fatalf("GET /json failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}

	// Test redirect endpoint
	resp, err = client.Get(server.URL + "/redirect")
	if err != nil {
		t.Fatalf("GET /redirect failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Redirected!" {
		t.Errorf("Expected 'Redirected!', got '%s'", string(body))
	}

	// Test auth endpoint without auth
	resp, err = client.Get(server.URL + "/auth")
	if err != nil {
		t.Fatalf("GET /auth failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("Expected 401 without auth, got %d", resp.StatusCode)
	}

	// Test auth endpoint with auth
	req, _ := http.NewRequest("GET", server.URL+"/auth", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with auth failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200 with auth, got %d", resp.StatusCode)
	}
}

// Benchmark tests
func BenchmarkURLBuilder(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewURLBuilder("https://example.com/api").
			Param("q", "search term").
			Param("page", "1").
			Param("limit", "20").
			Build()
	}
}

func BenchmarkMultipartEncode(b *testing.B) {
	content := make([]byte, 1024) // 1KB file
	for i := 0; i < b.N; i++ {
		form := NewFormData()
		form.AddField("name", "test")
		form.AddFile("file", "test.bin", content)
		form.Encode()
	}
}

func BenchmarkBasicAuth(b *testing.B) {
	auth := NewBasicAuth("username", "password")
	req, _ := customhttp.NewRequest("GET", "https://example.com", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		auth.Apply(req)
	}
}

// Test that runs all feature tests
func TestAllFeatures(t *testing.T) {
	t.Run("URLBuilder", TestURLBuilder)
	t.Run("JoinURL", TestJoinURL)
	t.Run("EncodeDecodeParams", TestEncodeDecodeParams)
	t.Run("MultipartFormData", TestMultipartFormData)
	t.Run("BasicAuth", TestBasicAuth)
	t.Run("BearerAuth", TestBearerAuth)
	t.Run("DigestAuth", TestDigestAuthParsing)
	t.Run("ClientConfig", TestClientConfig)
	t.Run("ResponseHelpers", TestResponseHelpers)
	t.Run("RetryLogic", TestRetryLogic)
	t.Run("SSEParsing", TestSSEParsing)
	t.Run("MIMETypeDetection", TestMIMETypeDetection)
	t.Run("RedirectDetection", TestRedirectDetection)
}

// TLSFingerprint represents the response from tls.peet.ws
type TLSFingerprint struct {
	IP          string `json:"ip"`
	HTTPVersion string `json:"http_version"`
	TLS         struct {
		Ciphers []string `json:"ciphers"`
		Extensions []struct {
			Name string `json:"name"`
		} `json:"extensions"`
		TLSVersionRecord string `json:"tls_version_record"`
		TLSVersionNego   string `json:"tls_version_negotiated"`
		Ja3              string `json:"ja3"`
		Ja3Hash          string `json:"ja3_hash"`
		Ja4              string `json:"ja4"`
		Peetprint        string `json:"peetprint"`
		PeetprintHash    string `json:"peetprint_hash"`
	} `json:"tls"`
	HTTP2 struct {
		AkamaiFingerprint     string `json:"akamai_fingerprint"`
		AkamaiFingerprintHash string `json:"akamai_fingerprint_hash"`
		SentFrames            []struct {
			FrameType string `json:"frame_type"`
		} `json:"sent_frames"`
	} `json:"http2"`
}

// TestTLSFingerprint_Httpcloak tests that httpcloak produces a browser-like TLS fingerprint
func TestTLSFingerprint_Httpcloak(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TLS fingerprint test (requires network)")
	}

	c := NewClient("chrome-143", WithTimeout(30*time.Second))
	defer c.Close()

	ctx := context.Background()
	resp, err := c.Get(ctx, "https://tls.peet.ws/api/all", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	var fp TLSFingerprint
	if err := json.Unmarshal(resp.Body, &fp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify we got valid fingerprint data
	if fp.TLS.Ja3Hash == "" {
		t.Error("JA3 hash should not be empty")
	}
	if fp.TLS.Ja4 == "" {
		t.Error("JA4 should not be empty")
	}
	if len(fp.TLS.Ciphers) == 0 {
		t.Error("Should have cipher suites")
	}
	if len(fp.TLS.Extensions) == 0 {
		t.Error("Should have TLS extensions")
	}

	t.Logf("httpcloak Fingerprint:")
	t.Logf("  HTTP Version:   %s", fp.HTTPVersion)
	t.Logf("  TLS Version:    %s", fp.TLS.TLSVersionNego)
	t.Logf("  Cipher Suites:  %d", len(fp.TLS.Ciphers))
	t.Logf("  TLS Extensions: %d", len(fp.TLS.Extensions))
	t.Logf("  JA3 Hash:       %s", fp.TLS.Ja3Hash)
	t.Logf("  JA4:            %s", fp.TLS.Ja4)
	t.Logf("  Akamai FP Hash: %s", fp.HTTP2.AkamaiFingerprintHash)
}

// TestTLSFingerprint_GoStdlib tests Go's standard library TLS fingerprint for comparison
func TestTLSFingerprint_GoStdlib(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TLS fingerprint test (requires network)")
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	var fp TLSFingerprint
	if err := json.Unmarshal(body, &fp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	t.Logf("Go stdlib Fingerprint:")
	t.Logf("  HTTP Version:   %s", fp.HTTPVersion)
	t.Logf("  TLS Version:    %s", fp.TLS.TLSVersionNego)
	t.Logf("  Cipher Suites:  %d", len(fp.TLS.Ciphers))
	t.Logf("  TLS Extensions: %d", len(fp.TLS.Extensions))
	t.Logf("  JA3 Hash:       %s", fp.TLS.Ja3Hash)
	t.Logf("  JA4:            %s", fp.TLS.Ja4)
	t.Logf("  Akamai FP Hash: %s", fp.HTTP2.AkamaiFingerprintHash)
}

// TestTLSFingerprint_Comparison compares httpcloak vs Go stdlib fingerprints
func TestTLSFingerprint_Comparison(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TLS fingerprint comparison test (requires network)")
	}

	// Get httpcloak fingerprint
	c := NewClient("chrome-143", WithTimeout(30*time.Second))
	defer c.Close()

	ctx := context.Background()
	httpcloakResp, err := c.Get(ctx, "https://tls.peet.ws/api/all", nil)
	if err != nil {
		t.Fatalf("httpcloak request failed: %v", err)
	}

	var httpcloakFP TLSFingerprint
	if err := json.Unmarshal(httpcloakResp.Body, &httpcloakFP); err != nil {
		t.Fatalf("Failed to parse httpcloak response: %v", err)
	}

	// Get Go stdlib fingerprint
	stdClient := &http.Client{Timeout: 30 * time.Second}
	stdResp, err := stdClient.Get("https://tls.peet.ws/api/all")
	if err != nil {
		t.Fatalf("stdlib request failed: %v", err)
	}
	defer stdResp.Body.Close()

	stdBody, _ := io.ReadAll(stdResp.Body)
	var stdlibFP TLSFingerprint
	if err := json.Unmarshal(stdBody, &stdlibFP); err != nil {
		t.Fatalf("Failed to parse stdlib response: %v", err)
	}

	// Compare fingerprints - they MUST be different
	t.Logf("Comparison:")
	t.Logf("  %-20s %-35s %-35s", "Property", "Go stdlib", "httpcloak")
	t.Logf("  %-20s %-35s %-35s", strings.Repeat("-", 20), strings.Repeat("-", 35), strings.Repeat("-", 35))
	t.Logf("  %-20s %-35s %-35s", "HTTP Version", stdlibFP.HTTPVersion, httpcloakFP.HTTPVersion)
	t.Logf("  %-20s %-35s %-35s", "TLS Version", stdlibFP.TLS.TLSVersionNego, httpcloakFP.TLS.TLSVersionNego)
	t.Logf("  %-20s %-35d %-35d", "Cipher Suites", len(stdlibFP.TLS.Ciphers), len(httpcloakFP.TLS.Ciphers))
	t.Logf("  %-20s %-35d %-35d", "TLS Extensions", len(stdlibFP.TLS.Extensions), len(httpcloakFP.TLS.Extensions))
	t.Logf("  %-20s %-35s %-35s", "JA3 Hash", truncateStr(stdlibFP.TLS.Ja3Hash, 32), truncateStr(httpcloakFP.TLS.Ja3Hash, 32))
	t.Logf("  %-20s %-35s %-35s", "JA4", stdlibFP.TLS.Ja4, httpcloakFP.TLS.Ja4)

	// The core assertion: fingerprints must be different
	if stdlibFP.TLS.Ja3Hash == httpcloakFP.TLS.Ja3Hash {
		t.Error("FAIL: JA3 hashes are identical - httpcloak should produce a different fingerprint than Go stdlib")
	} else {
		t.Log("PASS: JA3 hashes are different - httpcloak is working correctly")
	}

	if stdlibFP.TLS.Ja4 == httpcloakFP.TLS.Ja4 {
		t.Error("FAIL: JA4 fingerprints are identical")
	} else {
		t.Log("PASS: JA4 fingerprints are different")
	}

	// HTTP/2 Akamai fingerprint should also differ
	if stdlibFP.HTTP2.AkamaiFingerprintHash != "" && httpcloakFP.HTTP2.AkamaiFingerprintHash != "" {
		if stdlibFP.HTTP2.AkamaiFingerprintHash == httpcloakFP.HTTP2.AkamaiFingerprintHash {
			t.Error("FAIL: Akamai fingerprint hashes are identical")
		} else {
			t.Log("PASS: Akamai fingerprint hashes are different")
		}
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
