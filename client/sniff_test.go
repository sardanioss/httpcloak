package client

import "testing"

// TestClientSniffXHRMode keeps the direct-Go-client sniffXHRMode in lockstep
// with the transport-layer one. If these ever diverge, a user switching
// between `client.Client` and the binding path would see different
// Sec-Fetch-* headers on otherwise identical requests.
func TestClientSniffXHRMode(t *testing.T) {
	cases := []struct {
		name    string
		req     *Request
		wantAPI bool
	}{
		{"explicit mode=cors", &Request{Method: "GET", Headers: map[string][]string{"Sec-Fetch-Mode": {"cors"}}}, true},
		{"explicit mode=navigate forces nav on POST json",
			&Request{Method: "POST", Headers: map[string][]string{
				"Sec-Fetch-Mode": {"navigate"},
				"Content-Type":   {"application/json"},
			}}, false},
		{"dest=document on POST stays nav",
			&Request{Method: "POST", Headers: map[string][]string{"Sec-Fetch-Dest": {"document"}}}, false},
		{"dest=empty on POST forces cors",
			&Request{Method: "POST", Headers: map[string][]string{"Sec-Fetch-Dest": {"empty"}}}, true},
		{"GET with Accept=json", &Request{Method: "GET", Headers: map[string][]string{"Accept": {"application/json"}}}, true},
		{"plain GET", &Request{Method: "GET"}, false},
		{"plain HEAD", &Request{Method: "HEAD"}, false},
		{"plain DELETE", &Request{Method: "DELETE"}, true},
		{"POST json — reporter Case A",
			&Request{Method: "POST", Headers: map[string][]string{"Content-Type": {"application/json"}}}, true},
		{"POST form-urlencoded stays nav",
			&Request{Method: "POST", Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}}, false},
		{"POST multipart stays nav",
			&Request{Method: "POST", Headers: map[string][]string{"Content-Type": {"multipart/form-data; boundary=x"}}}, false},
		{"PUT json", &Request{Method: "PUT", Headers: map[string][]string{"Content-Type": {"application/json"}}}, true},
		{"POST with no Content-Type leans cors", &Request{Method: "POST"}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sniffXHRMode(c.req); got != c.wantAPI {
				t.Errorf("sniffXHRMode(%+v) = %v, want %v", c.req, got, c.wantAPI)
			}
		})
	}
}
