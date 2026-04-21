package transport

import (
	"testing"
)

// TestSniffXHRMode exercises every decision branch of sniffXHRMode. The
// function drives the Sec-Fetch-* header pipeline in applyPresetHeaders, so a
// regression here silently changes user-visible headers on every POST/GET/etc.
func TestSniffXHRMode(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		headers map[string][]string
		wantAPI bool // true = cors/empty; false = navigate/document
	}{
		// --- Explicit Sec-Fetch-Mode override (user intent wins) ---
		{"explicit-mode-cors on POST", "POST", map[string][]string{"Sec-Fetch-Mode": {"cors"}}, true},
		{"explicit-mode-navigate on POST json", "POST",
			map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Content-Type": {"application/json"}}, false},
		{"explicit-mode-no-cors on GET", "GET", map[string][]string{"Sec-Fetch-Mode": {"no-cors"}}, true},
		{"explicit-mode-websocket upgrade", "GET", map[string][]string{"Sec-Fetch-Mode": {"websocket"}}, true},
		{"explicit-mode case-insensitive", "POST", map[string][]string{"Sec-Fetch-Mode": {"NAVIGATE"}}, false},

		// --- Sec-Fetch-Dest override (when Mode not set) ---
		{"dest=empty on POST (no CT)", "POST", map[string][]string{"Sec-Fetch-Dest": {"empty"}}, true},
		{"dest=document keeps nav on POST", "POST", map[string][]string{"Sec-Fetch-Dest": {"document"}}, false},
		{"dest=image forces cors", "GET", map[string][]string{"Sec-Fetch-Dest": {"image"}}, true},

		// --- Accept-based sniff (pre-fix behavior remains for GETs) ---
		{"GET with Accept: application/json", "GET",
			map[string][]string{"Accept": {"application/json"}}, true},
		{"GET with Accept: application/xml", "GET",
			map[string][]string{"Accept": {"application/xml"}}, true},
		{"GET with Accept: text/html stays nav", "GET",
			map[string][]string{"Accept": {"text/html,application/xhtml+xml"}}, false},
		{"GET with Accept: */* is API", "GET", map[string][]string{"Accept": {"*/*"}}, true},

		// --- Method-based defaults ---
		{"plain GET (no headers)", "GET", nil, false},
		{"plain HEAD", "HEAD", nil, false},
		{"plain OPTIONS", "OPTIONS", nil, false},
		{"plain DELETE", "DELETE", nil, true},

		// --- Body-method + Content-Type sniff (Case A fix lives here) ---
		{"POST json — reporter Case A", "POST",
			map[string][]string{"Content-Type": {"application/json"}}, true},
		{"POST json with charset", "POST",
			map[string][]string{"Content-Type": {"application/json; charset=utf-8"}}, true},
		{"POST form-urlencoded (classic form)", "POST",
			map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}, false},
		{"POST multipart (classic form)", "POST",
			map[string][]string{"Content-Type": {"multipart/form-data; boundary=---"}}, false},
		{"PUT json", "PUT", map[string][]string{"Content-Type": {"application/json"}}, true},
		{"PATCH json", "PATCH", map[string][]string{"Content-Type": {"application/json"}}, true},
		{"POST octet-stream", "POST",
			map[string][]string{"Content-Type": {"application/octet-stream"}}, true},
		{"POST grpc", "POST", map[string][]string{"Content-Type": {"application/grpc"}}, true},
		{"POST text/plain", "POST", map[string][]string{"Content-Type": {"text/plain"}}, true},
		{"POST unknown CT leans cors", "POST",
			map[string][]string{"Content-Type": {"application/vnd.custom"}}, true},
		{"POST no Content-Type leans cors", "POST", nil, true},

		// --- Method is case-normalized ---
		{"lowercase post json", "post", map[string][]string{"Content-Type": {"application/json"}}, true},

		// --- Precedence: explicit mode wins over Accept/CT ---
		{"mode=navigate beats Accept=json", "GET",
			map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Accept": {"application/json"}}, false},
		{"mode=cors beats form CT", "POST",
			map[string][]string{"Sec-Fetch-Mode": {"cors"}, "Content-Type": {"application/x-www-form-urlencoded"}}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sniffXHRMode(c.method, c.headers)
			if got != c.wantAPI {
				t.Errorf("sniffXHRMode(%q, %v) = %v, want %v", c.method, c.headers, got, c.wantAPI)
			}
		})
	}
}

func TestHeaderValCaseInsensitive(t *testing.T) {
	h := map[string][]string{
		"Sec-Fetch-Mode": {"cors"},
		"content-type":   {"application/json"},
		"ACCEPT":         {"*/*"},
	}
	if v := headerVal(h, "sec-fetch-mode"); v != "cors" {
		t.Errorf("want cors, got %q", v)
	}
	if v := headerVal(h, "Content-Type"); v != "application/json" {
		t.Errorf("want application/json, got %q", v)
	}
	if v := headerVal(h, "accept"); v != "*/*" {
		t.Errorf("want */*, got %q", v)
	}
	if v := headerVal(h, "missing"); v != "" {
		t.Errorf("want empty for missing header, got %q", v)
	}
	if v := headerVal(nil, "anything"); v != "" {
		t.Errorf("want empty for nil map, got %q", v)
	}
}

func TestIsAPIAcceptValue(t *testing.T) {
	cases := map[string]bool{
		"application/json":                 true,
		"application/json; charset=utf-8":  true,
		"application/xml":                  true,
		"text/plain":                       true,
		"application/octet-stream":         true,
		"*/*":                              true,
		"text/html":                        false,
		"text/html,application/xhtml+xml": false,
		"image/png":                        false,
		"":                                 false,
	}
	for input, want := range cases {
		if got := isAPIAcceptValue(input); got != want {
			t.Errorf("isAPIAcceptValue(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestIsFormContentTypeValue(t *testing.T) {
	cases := map[string]bool{
		"application/x-www-form-urlencoded":                true,
		"application/x-www-form-urlencoded; charset=utf-8": true,
		"multipart/form-data":                              true,
		"multipart/form-data; boundary=xyz":                true,
		"application/json":                                 false,
		"text/html":                                        false,
		"":                                                 false,
	}
	for input, want := range cases {
		if got := isFormContentTypeValue(input); got != want {
			t.Errorf("isFormContentTypeValue(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestIsAPIContentTypeValue(t *testing.T) {
	cases := map[string]bool{
		"application/json":                true,
		"application/xml":                 true,
		"application/octet-stream":        true,
		"application/grpc":                true,
		"application/grpc+proto":          true,
		"application/x-protobuf":          true,
		"application/vnd.custom.json":     true,  // any application/* that isn't a form type
		"text/plain":                      true,
		"application/x-www-form-urlencoded": false, // form — excluded
		"multipart/form-data":             false, // not application/*
		"text/html":                       false,
		"image/png":                       false,
		"":                                false,
	}
	for input, want := range cases {
		if got := isAPIContentTypeValue(input); got != want {
			t.Errorf("isAPIContentTypeValue(%q) = %v, want %v", input, got, want)
		}
	}
}
