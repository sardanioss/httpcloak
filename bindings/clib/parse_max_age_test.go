package main

import "testing"

// The cookies listed on a response must read Max-Age as the session's jar
// does (session.parseMaxAge), or a caller passing them back through
// set_cookie turns a deletion into a session cookie.
func TestParseMaxAgeMatchesTheJar(t *testing.T) {
	for in, want := range map[string]struct {
		n  int
		ok bool
	}{
		"3600": {3600, true}, "0": {-1, true}, "-5": {-1, true},
		"10abc": {0, false}, "": {0, false}, "-": {0, false},
		"99999999999999999999999": {maxCookieAgeSeconds, true}, "34560001": {maxCookieAgeSeconds, true}, "34560000": {34560000, true}, "-99999999999999999999999": {-1, true}, " 10": {0, false},
	} {
		n, ok := parseMaxAge(in)
		if n != want.n || ok != want.ok {
			t.Errorf("parseMaxAge(%q) = %d, %v; want %d, %v", in, n, ok, want.n, want.ok)
		}
	}
}
