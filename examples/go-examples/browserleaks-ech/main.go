// Example: ECH + 0-RTT test with browserleaks using HTTP/3
//
// This example demonstrates:
// - Making HTTP/3 requests to browserleaks.com
// - Using ECH (Encrypted Client Hello) for privacy
// - Testing 0-RTT session resumption
// - Verifying ECH is working via JSON response
//
// Run: go run main.go
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

// ECHInfo holds ECH-specific data from browserleaks
type ECHInfo struct {
	ECHSuccess bool   `json:"ech_success"`
	OuterSNI   string `json:"outer_sni"`
}

// TLSInfo holds TLS data from browserleaks
type TLSInfo struct {
	ECH ECHInfo `json:"ech"`
}

// ServerResponse holds the JSON response from browserleaks
type ServerResponse struct {
	UserAgent string  `json:"user_agent,omitempty"`
	JA4       string  `json:"ja4,omitempty"`
	TLS       TLSInfo `json:"tls"`
}

// RequestResult holds the result of a single request
type RequestResult struct {
	RequestNum     int             `json:"request_num"`
	Success        bool            `json:"success"`
	Error          string          `json:"error,omitempty"`
	Protocol       string          `json:"protocol,omitempty"`
	ECHSuccess     bool            `json:"ech_success"`
	OuterSNI       string          `json:"outer_sni,omitempty"`
	JA4            string          `json:"ja4,omitempty"`
	JA4Extensions  string          `json:"ja4_extensions,omitempty"`
	NewConnection  bool            `json:"new_connection"`
	RTTMs          float64         `json:"rtt_ms"`
	ServerResponse *ServerResponse `json:"server_response,omitempty"`
}

// TestResults holds all test results
type TestResults struct {
	TestName   string          `json:"test_name"`
	Server     string          `json:"server"`
	Timestamp  string          `json:"timestamp"`
	Transport  string          `json:"transport"`
	Results    []RequestResult `json:"results"`
	AllPassed  bool            `json:"all_passed"`
	ECHWorking bool            `json:"ech_working"`
	ZeroRTT    bool            `json:"zero_rtt_working"`
	Summary    string          `json:"summary"`
}

func main() {
	ctx := context.Background()

	// ECH config for quic.browserleaks.com from DNS HTTPS record
	// Outer SNI: quic-outer.browserleaks.com
	echConfig, err := base64.StdEncoding.DecodeString("AFb+DQBSCQAgACCv9VgyhBjSIX5QZS44OkBQC8H5c4+b2u20pF/4sbkEUgAMAAEAAQABAAIAAQADABtxdWljLW91dGVyLmJyb3dzZXJsZWFrcy5jb20AAA==")
	if err != nil {
		fmt.Printf("Failed to decode ECH config: %v\n", err)
		return
	}

	// Create client with ECH config and force HTTP/3
	// Note: chrome-143 has QUICClientHelloID set, chrome-131 doesn't
	c := client.NewClient("chrome-143",
		client.WithTimeout(30*time.Second),
		client.WithECHConfig(echConfig),
	)
	defer c.Close()

	// Initialize test results
	testResults := TestResults{
		TestName:  "ECH + 0-RTT over QUIC/HTTP3 Test",
		Server:    "quic.browserleaks.com",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Transport: "QUIC/HTTP3",
		Results:   make([]RequestResult, 0, 3),
	}

	// Request 1: Initial connection (no session ticket yet)
	result1 := makeRequest(ctx, c, 1, true)
	testResults.Results = append(testResults.Results, result1)

	// Wait for session ticket to be received and processed
	time.Sleep(1 * time.Second)

	// Close QUIC connections but keep session cache
	// This forces new connections that should use 0-RTT
	c.CloseQUICConnections()
	time.Sleep(500 * time.Millisecond)

	// Request 2: Should use 0-RTT session resumption
	result2 := makeRequest(ctx, c, 2, true)
	testResults.Results = append(testResults.Results, result2)

	// Close again for third request
	c.CloseQUICConnections()
	time.Sleep(500 * time.Millisecond)

	// Request 3: Should also use 0-RTT
	result3 := makeRequest(ctx, c, 3, true)
	testResults.Results = append(testResults.Results, result3)

	// Determine if all tests passed
	allPassed := true
	echWorking := true
	for _, r := range testResults.Results {
		if !r.Success {
			allPassed = false
		}
		if !r.ECHSuccess {
			echWorking = false
		}
	}

	// Check 0-RTT by comparing RTT times and JA4 extensions
	// Request 1: 11 extensions (no PSK)
	// Request 2+: 13 extensions (with PSK) - indicates session resumption
	zeroRTTWorking := false
	if len(testResults.Results) >= 2 {
		// JA4 format: q13d0313h3_... where "13" after "d03" is the extension count
		ja4_1 := testResults.Results[0].JA4Extensions
		ja4_2 := testResults.Results[1].JA4Extensions
		// 11 -> 13 indicates PSK was added for session resumption
		if ja4_1 == "11" && ja4_2 == "13" {
			zeroRTTWorking = true
		}
	}

	testResults.AllPassed = allPassed && echWorking && zeroRTTWorking
	testResults.ECHWorking = echWorking
	testResults.ZeroRTT = zeroRTTWorking

	if echWorking && zeroRTTWorking {
		testResults.Summary = "ECH + 0-RTT working: ECH maintained on all requests, 0-RTT session resumption successful"
	} else if echWorking {
		testResults.Summary = "ECH working but 0-RTT not detected"
	} else if allPassed {
		testResults.Summary = "HTTP/3 working but ECH NOT accepted by server"
	} else {
		testResults.Summary = "Some requests failed"
	}

	// Output JSON results
	jsonOutput, err := json.MarshalIndent(testResults, "", "  ")
	if err != nil {
		fmt.Printf("Failed to marshal JSON: %v\n", err)
		return
	}
	fmt.Println(string(jsonOutput))
}

func makeRequest(ctx context.Context, c *client.Client, reqNum int, isNewConnection bool) RequestResult {
	result := RequestResult{
		RequestNum:    reqNum,
		NewConnection: isNewConnection,
	}

	start := time.Now()

	// Force HTTP/3 for browserleaks
	resp, err := c.Do(ctx, &client.Request{
		Method:        "GET",
		URL:           "https://quic.browserleaks.com/?minify=1",
		ForceProtocol: client.ProtocolHTTP3,
	})

	result.RTTMs = float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		result.Error = fmt.Sprintf("request error: %v", err)
		return result
	}

	result.Protocol = string(resp.Protocol)

	// Read response body
	text, err := resp.Text()
	if err != nil {
		result.Error = fmt.Sprintf("read body error: %v", err)
		return result
	}

	// Parse JSON response
	var serverResp ServerResponse
	if err := json.Unmarshal([]byte(text), &serverResp); err == nil {
		result.ServerResponse = &serverResp
		result.ECHSuccess = serverResp.TLS.ECH.ECHSuccess
		result.OuterSNI = serverResp.TLS.ECH.OuterSNI
		result.JA4 = serverResp.JA4

		// Extract extension count from JA4 (e.g., "q13d0311h3_..." -> "11")
		if len(serverResp.JA4) >= 9 {
			result.JA4Extensions = serverResp.JA4[6:8]
		}
	}

	result.Success = true
	return result
}
