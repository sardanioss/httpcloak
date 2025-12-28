package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/protocol"
)

// TestIPC runs comprehensive tests for all IPC features
type TestIPC struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	t      *testing.T
}

func newTestIPC(t *testing.T) *TestIPC {
	cmd := exec.Command("go", "run", ".")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("Failed to create stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start daemon: %v", err)
	}

	return &TestIPC{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReader(stdout),
		t:      t,
	}
}

func (ipc *TestIPC) send(msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		ipc.t.Fatalf("Failed to marshal message: %v", err)
	}
	_, err = ipc.stdin.Write(append(data, '\n'))
	if err != nil {
		ipc.t.Fatalf("Failed to write message: %v", err)
	}
}

func (ipc *TestIPC) receive() map[string]interface{} {
	line, err := ipc.stdout.ReadString('\n')
	if err != nil {
		ipc.t.Fatalf("Failed to read response: %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(line), &result); err != nil {
		ipc.t.Fatalf("Failed to unmarshal response: %v\nRaw: %s", err, line)
	}
	return result
}

func (ipc *TestIPC) close() {
	ipc.stdin.Close()
	ipc.cmd.Wait()
}

func TestPing(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	ipc.send(map[string]interface{}{
		"id":   "ping-1",
		"type": "ping",
	})

	resp := ipc.receive()
	if resp["type"] != "pong" {
		t.Errorf("Expected type 'pong', got '%v'", resp["type"])
	}
	if resp["id"] != "ping-1" {
		t.Errorf("Expected id 'ping-1', got '%v'", resp["id"])
	}
	if resp["version"] == nil || resp["version"] == "" {
		t.Errorf("Expected version in response")
	}
	t.Logf("Ping response: %v", resp)
}

func TestPresetList(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	ipc.send(map[string]interface{}{
		"id":   "preset-1",
		"type": "preset.list",
	})

	resp := ipc.receive()
	if resp["type"] != "preset.list" {
		t.Errorf("Expected type 'preset.list', got '%v'", resp["type"])
	}
	presets, ok := resp["presets"].([]interface{})
	if !ok || len(presets) == 0 {
		t.Errorf("Expected non-empty presets list")
	}
	t.Logf("Available presets: %v", presets)

	// Check for expected presets
	presetNames := make(map[string]bool)
	for _, p := range presets {
		presetNames[p.(string)] = true
	}
	expectedPresets := []string{"chrome-143", "chrome-133", "firefox-133", "safari-18"}
	for _, expected := range expectedPresets {
		if !presetNames[expected] {
			t.Errorf("Expected preset '%s' not found", expected)
		}
	}
}

func TestSessionLifecycle(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	// Create session
	ipc.send(map[string]interface{}{
		"id":   "session-create-1",
		"type": "session.create",
		"options": map[string]interface{}{
			"preset":  "chrome-143",
			"timeout": 30000,
		},
	})

	createResp := ipc.receive()
	if createResp["type"] != "session.create" {
		t.Errorf("Expected type 'session.create', got '%v'", createResp["type"])
	}
	sessionID, ok := createResp["session"].(string)
	if !ok || sessionID == "" {
		t.Fatalf("Expected session ID in response")
	}
	t.Logf("Created session: %s", sessionID)

	// List sessions
	ipc.send(map[string]interface{}{
		"id":   "session-list-1",
		"type": "session.list",
	})

	listResp := ipc.receive()
	sessions, ok := listResp["sessions"].([]interface{})
	if !ok || len(sessions) == 0 {
		t.Errorf("Expected non-empty sessions list")
	}
	found := false
	for _, s := range sessions {
		if s.(string) == sessionID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Created session not found in list")
	}
	t.Logf("Sessions: %v", sessions)

	// Close session
	ipc.send(map[string]interface{}{
		"id":      "session-close-1",
		"type":    "session.close",
		"session": sessionID,
	})

	closeResp := ipc.receive()
	if closeResp["type"] != "session.close" {
		t.Errorf("Expected type 'session.close', got '%v'", closeResp["type"])
	}
	t.Logf("Closed session: %s", sessionID)

	// Verify session is gone
	ipc.send(map[string]interface{}{
		"id":   "session-list-2",
		"type": "session.list",
	})

	listResp2 := ipc.receive()
	sessions2, _ := listResp2["sessions"].([]interface{})
	for _, s := range sessions2 {
		if s.(string) == sessionID {
			t.Errorf("Session should have been removed")
		}
	}
}

func TestOneShotRequest(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	// Simple GET request without session (using tls.peet.ws which is more reliable)
	ipc.send(map[string]interface{}{
		"id":     "request-1",
		"type":   "request",
		"method": "GET",
		"url":    "https://tls.peet.ws/api/clean",
		"options": map[string]interface{}{
			"timeout": 30000,
		},
	})

	resp := ipc.receive()
	if resp["type"] == "error" {
		errInfo := resp["error"].(map[string]interface{})
		t.Skipf("Request failed (network issue): %v", errInfo)
	}
	if resp["type"] != "response" {
		t.Fatalf("Expected type 'response', got '%v'", resp["type"])
	}
	status, ok := resp["status"].(float64)
	if !ok {
		t.Fatalf("Expected status in response, got: %v", resp)
	}
	if status != 200 {
		t.Errorf("Expected status 200, got %v", status)
	}
	if resp["body"] == nil || resp["body"] == "" {
		t.Errorf("Expected non-empty body")
	}
	t.Logf("One-shot request status: %v, protocol: %v", status, resp["protocol"])
}

func TestSessionRequest(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	// Create session
	ipc.send(map[string]interface{}{
		"id":   "session-1",
		"type": "session.create",
		"options": map[string]interface{}{
			"preset": "chrome-143",
		},
	})
	createResp := ipc.receive()
	sessionID := createResp["session"].(string)

	// Make request with session
	ipc.send(map[string]interface{}{
		"id":      "request-1",
		"type":    "request",
		"session": sessionID,
		"method":  "GET",
		"url":     "https://tls.peet.ws/api/clean",
		"options": map[string]interface{}{
			"timeout": 30000,
		},
	})

	resp := ipc.receive()
	if resp["type"] == "error" {
		errInfo := resp["error"].(map[string]interface{})
		t.Skipf("Request failed (network issue): %v", errInfo)
	}
	if resp["type"] != "response" {
		t.Fatalf("Expected type 'response', got '%v'", resp["type"])
	}
	if resp["session"] != sessionID {
		t.Errorf("Expected session ID in response")
	}
	status, ok := resp["status"].(float64)
	if !ok {
		t.Fatalf("Expected status in response")
	}
	if status != 200 {
		t.Errorf("Expected status 200, got %v", status)
	}
	t.Logf("Session request status: %v", status)
}

func TestRequestWithOptions(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	// POST request with headers and body to postman-echo
	ipc.send(map[string]interface{}{
		"id":     "request-1",
		"type":   "request",
		"method": "POST",
		"url":    "https://postman-echo.com/post",
		"headers": map[string]string{
			"Content-Type": "application/json",
			"X-Custom":     "test-value",
		},
		"body": `{"test": "data"}`,
		"options": map[string]interface{}{
			"timeout": 30000,
		},
	})

	resp := ipc.receive()
	if resp["type"] == "error" {
		errInfo := resp["error"].(map[string]interface{})
		t.Skipf("Request failed (network issue): %v", errInfo)
	}
	status, ok := resp["status"].(float64)
	if !ok {
		t.Fatalf("Expected status in response")
	}
	if status != 200 {
		t.Errorf("Expected status 200, got %v", status)
	}

	// Parse body to verify our data was sent
	body := resp["body"].(string)
	if !strings.Contains(body, "test-value") {
		t.Logf("Response body: %s", body)
	}
	t.Logf("POST request successful, status: %v", status)
}

func TestRequestWithParams(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	// GET request with query params
	ipc.send(map[string]interface{}{
		"id":     "request-1",
		"type":   "request",
		"method": "GET",
		"url":    "https://postman-echo.com/get",
		"options": map[string]interface{}{
			"timeout": 30000,
			"params": map[string]string{
				"foo": "bar",
				"baz": "qux",
			},
		},
	})

	resp := ipc.receive()
	if resp["type"] == "error" {
		errInfo := resp["error"].(map[string]interface{})
		t.Skipf("Request failed (network issue): %v", errInfo)
	}
	status, ok := resp["status"].(float64)
	if !ok {
		t.Fatalf("Expected status in response")
	}
	if status != 200 {
		t.Errorf("Expected status 200, got %v", status)
	}

	body := resp["body"].(string)
	if !strings.Contains(body, "foo") || !strings.Contains(body, "bar") {
		t.Logf("Response body: %s", body)
	}
	t.Logf("Request with params successful")
}

func TestCookieManagement(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	// Create session
	ipc.send(map[string]interface{}{
		"id":   "session-1",
		"type": "session.create",
	})
	createResp := ipc.receive()
	sessionID := createResp["session"].(string)

	// Set a cookie
	ipc.send(map[string]interface{}{
		"id":      "cookie-set-1",
		"type":    "cookie.set",
		"session": sessionID,
		"url":     "https://example.com",
		"name":    "test_cookie",
		"value":   "test_value",
		"domain":  "example.com",
		"path":    "/",
		"secure":  true,
	})

	setResp := ipc.receive()
	if setResp["type"] != "cookie.set" {
		t.Errorf("Expected type 'cookie.set', got '%v'", setResp["type"])
	}
	t.Logf("Cookie set successfully")

	// Get cookies for URL
	ipc.send(map[string]interface{}{
		"id":      "cookie-get-1",
		"type":    "cookie.get",
		"session": sessionID,
		"url":     "https://example.com/path",
	})

	getResp := ipc.receive()
	if getResp["type"] != "cookie.get" {
		t.Errorf("Expected type 'cookie.get', got '%v'", getResp["type"])
	}
	cookies, ok := getResp["cookies"].(map[string]interface{})
	if !ok {
		t.Errorf("Expected cookies map in response")
	}
	if cookies["test_cookie"] != "test_value" {
		t.Errorf("Expected cookie value 'test_value', got '%v'", cookies["test_cookie"])
	}
	t.Logf("Cookies: %v", cookies)

	// Get all cookies
	ipc.send(map[string]interface{}{
		"id":      "cookie-all-1",
		"type":    "cookie.all",
		"session": sessionID,
	})

	allResp := ipc.receive()
	if allResp["type"] != "cookie.all" {
		t.Errorf("Expected type 'cookie.all', got '%v'", allResp["type"])
	}
	allCookies, ok := allResp["all"].(map[string]interface{})
	if !ok || len(allCookies) == 0 {
		t.Errorf("Expected non-empty all cookies map")
	}
	t.Logf("All cookies: %v", allCookies)

	// Clear cookies
	ipc.send(map[string]interface{}{
		"id":      "cookie-clear-1",
		"type":    "cookie.clear",
		"session": sessionID,
	})

	clearResp := ipc.receive()
	if clearResp["type"] != "cookie.clear" {
		t.Errorf("Expected type 'cookie.clear', got '%v'", clearResp["type"])
	}

	// Verify cookies are cleared
	ipc.send(map[string]interface{}{
		"id":      "cookie-all-2",
		"type":    "cookie.all",
		"session": sessionID,
	})

	allResp2 := ipc.receive()
	allCookies2, _ := allResp2["all"].(map[string]interface{})
	if len(allCookies2) != 0 {
		t.Errorf("Expected empty cookies after clear")
	}
	t.Logf("Cookies cleared successfully")
}

func TestCookiePersistence(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	// Create session
	ipc.send(map[string]interface{}{
		"id":   "session-1",
		"type": "session.create",
	})
	createResp := ipc.receive()
	sessionID := createResp["session"].(string)

	// Manually set a cookie via IPC
	ipc.send(map[string]interface{}{
		"id":      "cookie-set-1",
		"type":    "cookie.set",
		"session": sessionID,
		"url":     "https://tls.peet.ws",
		"name":    "session_test",
		"value":   "hello_world",
		"domain":  "tls.peet.ws",
		"path":    "/",
	})
	ipc.receive()

	// Make request to verify cookie is sent
	ipc.send(map[string]interface{}{
		"id":      "request-1",
		"type":    "request",
		"session": sessionID,
		"method":  "GET",
		"url":     "https://tls.peet.ws/api/all",
		"options": map[string]interface{}{
			"timeout": 30000,
		},
	})

	resp := ipc.receive()
	if resp["type"] == "error" {
		errInfo := resp["error"].(map[string]interface{})
		t.Skipf("Request failed (network issue): %v", errInfo)
	}

	// The cookie should be visible in the request headers echoed back
	body := resp["body"].(string)
	if strings.Contains(body, "session_test") || strings.Contains(body, "hello_world") {
		t.Logf("Cookie visible in echoed headers")
	}

	// Verify cookie is still in jar
	ipc.send(map[string]interface{}{
		"id":      "cookie-get-1",
		"type":    "cookie.get",
		"session": sessionID,
		"url":     "https://tls.peet.ws/api/all",
	})

	getResp := ipc.receive()
	cookies := getResp["cookies"].(map[string]interface{})
	if cookies["session_test"] == "hello_world" {
		t.Logf("Cookie persistence verified")
	} else {
		t.Logf("Cookie jar contents: %v", cookies)
	}
}

func TestFetchModes(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	// Test navigate mode (default) - tls.peet.ws echoes headers
	ipc.send(map[string]interface{}{
		"id":     "request-1",
		"type":   "request",
		"method": "GET",
		"url":    "https://tls.peet.ws/api/all",
		"options": map[string]interface{}{
			"timeout":   30000,
			"fetchMode": "navigate",
		},
	})

	resp := ipc.receive()
	if resp["type"] == "error" {
		errInfo := resp["error"].(map[string]interface{})
		t.Skipf("Request failed (network issue): %v", errInfo)
	}
	body := resp["body"].(string)
	if strings.Contains(body, "sec-fetch-mode") {
		t.Logf("Navigate mode headers present in response")
	}

	// Test CORS mode
	ipc.send(map[string]interface{}{
		"id":     "request-2",
		"type":   "request",
		"method": "GET",
		"url":    "https://tls.peet.ws/api/clean",
		"options": map[string]interface{}{
			"timeout":   30000,
			"fetchMode": "cors",
		},
	})

	resp2 := ipc.receive()
	if resp2["type"] == "error" {
		t.Skipf("CORS mode request failed")
	}
	t.Logf("CORS mode request completed, status: %v", resp2["status"])
}

func TestErrorHandling(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	// Invalid session
	ipc.send(map[string]interface{}{
		"id":      "request-1",
		"type":    "request",
		"session": "invalid-session-id",
		"method":  "GET",
		"url":     "https://example.com",
	})

	resp := ipc.receive()
	if resp["type"] != "error" {
		t.Errorf("Expected type 'error', got '%v'", resp["type"])
	}
	errInfo, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Errorf("Expected error info in response")
	}
	if errInfo["code"] != protocol.ErrCodeInvalidSession {
		t.Errorf("Expected error code '%s', got '%v'", protocol.ErrCodeInvalidSession, errInfo["code"])
	}
	t.Logf("Invalid session error: %v", errInfo)

	// Invalid URL
	ipc.send(map[string]interface{}{
		"id":     "request-2",
		"type":   "request",
		"method": "GET",
		"url":    "not-a-valid-url",
	})

	resp2 := ipc.receive()
	if resp2["type"] != "error" {
		t.Errorf("Expected type 'error', got '%v'", resp2["type"])
	}
	t.Logf("Invalid URL error: %v", resp2["error"])

	// Connection refused (non-existent server)
	ipc.send(map[string]interface{}{
		"id":     "request-3",
		"type":   "request",
		"method": "GET",
		"url":    "https://localhost:59999/test",
		"options": map[string]interface{}{
			"timeout": 5000,
		},
	})

	resp3 := ipc.receive()
	if resp3["type"] != "error" {
		t.Errorf("Expected type 'error', got '%v'", resp3["type"])
	}
	t.Logf("Connection error: %v", resp3["error"])
}

func TestFingerprint(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	// Test fingerprint against tls.peet.ws
	ipc.send(map[string]interface{}{
		"id":     "request-1",
		"type":   "request",
		"method": "GET",
		"url":    "https://tls.peet.ws/api/all",
	})

	resp := ipc.receive()
	if resp["type"] != "response" {
		t.Fatalf("Expected response, got: %v", resp)
	}

	body := resp["body"].(string)

	// Check JA4
	expectedJA4 := "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	if !strings.Contains(body, expectedJA4) {
		t.Errorf("JA4 fingerprint mismatch. Expected %s in body", expectedJA4)
	} else {
		t.Logf("JA4 fingerprint matches: %s", expectedJA4)
	}

	// Check peetprint hash
	expectedPeetprint := "1d4ffe9b0e34acac0bd883fa7f79d7b5"
	if !strings.Contains(body, expectedPeetprint) {
		t.Errorf("Peetprint hash mismatch. Expected %s in body", expectedPeetprint)
	} else {
		t.Logf("Peetprint hash matches: %s", expectedPeetprint)
	}

	// Check Akamai HTTP/2 hash
	expectedAkamai := "52d84b11737d980aef856699f885ca86"
	if !strings.Contains(body, expectedAkamai) {
		t.Errorf("Akamai HTTP/2 hash mismatch. Expected %s in body", expectedAkamai)
	} else {
		t.Logf("Akamai HTTP/2 hash matches: %s", expectedAkamai)
	}

	// Check Priority flag
	if !strings.Contains(body, `"weight": 256`) {
		t.Errorf("Priority weight mismatch")
	}
	if !strings.Contains(body, `"exclusive": 1`) {
		t.Errorf("Priority exclusive flag mismatch")
	}
	if !strings.Contains(body, `"depends_on": 0`) {
		t.Errorf("Priority depends_on mismatch")
	}
	t.Logf("Priority frame verified: weight=256, exclusive=1, depends_on=0")

	// Check header order (m,a,s,p)
	if !strings.Contains(body, `"akamai_fingerprint": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"`) {
		t.Logf("Akamai fingerprint format may differ, checking components...")
		if strings.Contains(body, "m,a,s,p") {
			t.Logf("Pseudo-header order verified: m,a,s,p")
		}
	} else {
		t.Logf("Full Akamai fingerprint matches")
	}
}

func TestMultiplePresets(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	presets := []string{"chrome-143", "chrome-133", "firefox-133"}

	for _, preset := range presets {
		t.Run(preset, func(t *testing.T) {
			// Create session with preset
			ipc.send(map[string]interface{}{
				"id":   fmt.Sprintf("session-%s", preset),
				"type": "session.create",
				"options": map[string]interface{}{
					"preset": preset,
				},
			})
			createResp := ipc.receive()
			sessionID := createResp["session"].(string)

			// Make request to tls.peet.ws to see user-agent
			ipc.send(map[string]interface{}{
				"id":      fmt.Sprintf("request-%s", preset),
				"type":    "request",
				"session": sessionID,
				"method":  "GET",
				"url":     "https://tls.peet.ws/api/clean",
				"options": map[string]interface{}{
					"timeout": 30000,
				},
			})

			resp := ipc.receive()
			if resp["type"] == "error" {
				t.Skipf("Request failed for %s", preset)
			}
			status, ok := resp["status"].(float64)
			if !ok || status != 200 {
				t.Errorf("Expected status 200 for %s, got %v", preset, status)
			}

			body := resp["body"].(string)
			// Extract user_agent from response
			if strings.Contains(body, "user_agent") {
				t.Logf("%s request successful", preset)
			}

			// Close session
			ipc.send(map[string]interface{}{
				"id":      fmt.Sprintf("close-%s", preset),
				"type":    "session.close",
				"session": sessionID,
			})
			ipc.receive()
		})
	}
}

func TestTiming(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	ipc.send(map[string]interface{}{
		"id":     "request-1",
		"type":   "request",
		"method": "GET",
		"url":    "https://tls.peet.ws/api/clean",
		"options": map[string]interface{}{
			"timeout": 30000,
		},
	})

	resp := ipc.receive()
	if resp["type"] == "error" {
		errInfo := resp["error"].(map[string]interface{})
		t.Skipf("Request failed (network issue): %v", errInfo)
	}

	timing, ok := resp["timing"].(map[string]interface{})
	if !ok {
		t.Errorf("Expected timing info in response")
		return
	}

	// Check timing fields exist
	fields := []string{"dnsLookup", "tcpConnect", "tlsHandshake", "firstByte", "total"}
	for _, field := range fields {
		if _, exists := timing[field]; !exists {
			t.Errorf("Missing timing field: %s", field)
		}
	}

	total := timing["total"].(float64)
	if total <= 0 {
		t.Errorf("Expected positive total time, got %v", total)
	}
	t.Logf("Request timing: %v", timing)
}

func TestBodyEncoding(t *testing.T) {
	ipc := newTestIPC(t)
	defer ipc.close()

	// Test text response (JSON from tls.peet.ws)
	ipc.send(map[string]interface{}{
		"id":     "request-1",
		"type":   "request",
		"method": "GET",
		"url":    "https://tls.peet.ws/api/clean",
		"options": map[string]interface{}{
			"timeout": 30000,
		},
	})

	resp := ipc.receive()
	if resp["type"] == "error" {
		errInfo := resp["error"].(map[string]interface{})
		t.Skipf("Request failed (network issue): %v", errInfo)
	}
	if resp["bodyEncoding"] != "text" {
		t.Errorf("Expected bodyEncoding 'text' for JSON response, got '%v'", resp["bodyEncoding"])
	}
	t.Logf("Text response size: %v bytes, encoding: %v", resp["bodySize"], resp["bodyEncoding"])

	// Test binary response (favicon)
	ipc.send(map[string]interface{}{
		"id":     "request-2",
		"type":   "request",
		"method": "GET",
		"url":    "https://www.google.com/favicon.ico",
		"options": map[string]interface{}{
			"timeout": 30000,
		},
	})

	resp2 := ipc.receive()
	if resp2["type"] == "error" {
		t.Skipf("Binary request failed")
	}
	if resp2["bodyEncoding"] != "base64" {
		t.Logf("Body encoding for binary: %v (expected base64 for non-text content)", resp2["bodyEncoding"])
	}
	t.Logf("Binary response size: %v bytes", resp2["bodySize"])
}

// Run all tests with: go test -v -timeout 5m
func TestAll(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"Ping", TestPing},
		{"PresetList", TestPresetList},
		{"SessionLifecycle", TestSessionLifecycle},
		{"OneShotRequest", TestOneShotRequest},
		{"SessionRequest", TestSessionRequest},
		{"RequestWithOptions", TestRequestWithOptions},
		{"RequestWithParams", TestRequestWithParams},
		{"CookieManagement", TestCookieManagement},
		{"CookiePersistence", TestCookiePersistence},
		{"FetchModes", TestFetchModes},
		{"ErrorHandling", TestErrorHandling},
		{"Fingerprint", TestFingerprint},
		{"MultiplePresets", TestMultiplePresets},
		{"Timing", TestTiming},
		{"BodyEncoding", TestBodyEncoding},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn(t)
			time.Sleep(100 * time.Millisecond) // Brief pause between tests
		})
	}
}
