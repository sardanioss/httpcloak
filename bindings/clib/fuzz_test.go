package main

import (
	"bytes"
	"encoding/base64"
	"math"
	"strconv"
	"strings"
	"testing"
)

// Fuzz targets for the clib's own parsers, the code every binding's input
// and output crosses. Where the standard library does the same job it is the
// oracle.
//
// Run one with: go test -run '^$' -fuzz FuzzBase64RoundTrip -fuzztime 60s .

func FuzzBase64RoundTrip(f *testing.F) {
	for _, s := range [][]byte{nil, {0}, {0xff, 0xfe}, []byte("hello"), bytes.Repeat([]byte{0x80}, 100)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		enc := encodeBase64(data)
		if want := base64.StdEncoding.EncodeToString(data); enc != want {
			t.Fatalf("encodeBase64(%x) = %q, want %q", data, enc, want)
		}
		dec, err := decodeBase64(enc)
		if err != nil || !bytes.Equal(dec, data) {
			t.Fatalf("decodeBase64(encodeBase64(%x)) = %x, %v", data, dec, err)
		}
	})
}

// decodeBase64 is what httpcloak_upload_write runs on a caller's chunk. On
// input the standard decoder accepts, it must agree with it; on anything else
// it must not panic.
func FuzzDecodeBase64(f *testing.F) {
	for _, s := range []string{"", "=", "QQ", "QQ==", "QUJD", "!!!!", "QUJD\n", "Q==Q"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := decodeBase64(s)
		if want, stdErr := base64.StdEncoding.DecodeString(s); stdErr == nil {
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("decodeBase64(%q) = %x, %v; the standard decoder gives %x", s, got, err, want)
			}
		}
	})
}

// parseSetCookieHeaders turns every Set-Cookie a server sends into the cookie
// list each response carries. Arbitrary server input must not panic it, and
// what it reports must be what the header said.
func FuzzParseSetCookie(f *testing.F) {
	for _, s := range []string{
		"a=1", "a=1; Path=/; HttpOnly", "b=2; Max-Age=3600; Secure; SameSite=lax",
		"=x", "noequals", "c=; Domain=.example.com", "d=1; Max-Age=99999999999999999999999",
		"e=1; Max-Age=-5", "f=\"q\"; Expires=Wed, 21 Oct 2015 07:28:00 GMT", ";;;", "g=1;;; ;Secure",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cookies := parseSetCookieHeaders(map[string][]string{"set-cookie": {line}})
		if len(cookies) > 1 {
			t.Fatalf("one Set-Cookie line gave %d cookies", len(cookies))
		}
		for _, c := range cookies {
			if c.Name == "" {
				t.Fatalf("%q gave a cookie with no name", line)
			}
			if strings.ContainsRune(c.Name, ';') || strings.ContainsRune(c.Value, ';') {
				t.Fatalf("%q gave a name or value with a ';' in it: %+v", line, c)
			}
			// The last valid Max-Age is the one that counts: RFC 6265 5.2.2
			// ignores one that is not an optional "-" and digits, and 5.3 lets
			// a later attribute replace an earlier one.
			maxAge := ""
			for _, attr := range strings.Split(line, ";")[1:] {
				if name, value, ok := strings.Cut(attr, "="); ok && strings.EqualFold(trim(name), "max-age") && isDecimal(trim(value)) {
					maxAge = value
				}
			}
			if value := trim(maxAge); value != "" {
				// One too large to hold saturates rather than wrap into a
				// negative (an instant delete) or some other number.
				var want int
				n, err := strconv.ParseInt(value, 10, 64)
				switch {
				case err == nil:
					want = int(n)
				case strings.HasPrefix(value, "-"):
					want = math.MinInt
				default:
					want = math.MaxInt
				}
				if c.MaxAge != want {
					t.Fatalf("Max-Age=%s parsed as %d, want %d", value, c.MaxAge, want)
				}
			}
		}
	})
}

// toUint16 reads tls_record_size_limit from a binding's extra_fp.
func FuzzToUint16(f *testing.F) {
	for _, s := range []string{"0x4001", "16385", "65535", "65536", "-1", "0x", "x", "0xffff", "ffff"} {
		f.Add(s, 0.0)
	}
	f.Add("", 16385.0)
	f.Add("", -1.0)
	f.Add("", 70000.0)
	f.Fuzz(func(t *testing.T, s string, n float64) {
		if v, ok := toUint16(n); ok && float64(v) != math.Trunc(n) {
			t.Fatalf("toUint16(%v) = %d", n, v)
		}
		if _, ok := toUint16(n); !ok && n >= 0 && n <= 65535 {
			t.Fatalf("toUint16(%v) refused a number in range", n)
		}
		toUint16(s)
	})
}

// buildHeaders and buildExactHeaders take a binding's request JSON as Go
// decoded it: any strings at all.
func FuzzBuildHeaders(f *testing.F) {
	f.Add("X-A", "1", "cors", "Sec-Fetch-Mode", "x")
	f.Fuzz(func(t *testing.T, k1, v1, mode, k2, v2 string) {
		h := buildHeaders(map[string]string{k1: v1, k2: v2}, mode)
		if m := strings.ToLower(strings.TrimSpace(mode)); m == "cors" || m == "navigate" || m == "no-cors" || m == "websocket" {
			found := false
			for k := range h {
				if strings.EqualFold(k, "Sec-Fetch-Mode") {
					found = true
				}
			}
			if !found {
				t.Fatalf("fetch mode %q set no Sec-Fetch-Mode: %v", mode, h)
			}
		}
		pairs := buildExactHeaders([][]string{{k1, v1}, {k2}, {k1, v1, v2}, {}, {"", v2}})
		for _, p := range pairs {
			if p.Key == "" {
				t.Fatalf("an exact header with no name got through: %+v", pairs)
			}
		}
	})
}
