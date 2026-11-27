package secfetch

import (
	"testing"
)

func TestIsAPIAcceptValue(t *testing.T) {
	cases := map[string]bool{
		"application/json":                true,
		"application/json; charset=utf-8": true,
		"application/xml":                 true,
		"text/plain":                      true,
		"application/octet-stream":        true,
		"*/*":                             true,
		"text/html":                       false,
		"text/html,application/xhtml+xml": false,
		"image/png":                       false,
		"":                                false,
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
		"application/json":                  true,
		"application/xml":                   true,
		"application/octet-stream":          true,
		"application/grpc":                  true,
		"application/grpc+proto":            true,
		"application/x-protobuf":            true,
		"application/vnd.custom.json":       true, // any application/* that isn't a form type
		"text/plain":                        true,
		"application/x-www-form-urlencoded": false, // form — excluded
		"multipart/form-data":               false, // not application/*
		"text/html":                         false,
		"image/png":                         false,
		"":                                  false,
	}
	for input, want := range cases {
		if got := isAPIContentTypeValue(input); got != want {
			t.Errorf("isAPIContentTypeValue(%q) = %v, want %v", input, got, want)
		}
	}
}
