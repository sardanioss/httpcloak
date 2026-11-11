package main

import (
	"encoding/json"
	"testing"
)

// Only a JSON false turns certificate checks off. Anything else, a string
// "false" included, leaves them on, in both configs that read verify.
func TestVerifyIsOffOnlyForJSONFalse(t *testing.T) {
	for raw, off := range map[string]bool{
		`{}`:                 false,
		`{"verify":true}`:    false,
		`{"verify":false}`:   true,
		`{"verify": false }`: true,
		`{"verify":"true"}`:  false,
		`{"verify":"false"}`: false,
		`{"verify":1}`:       false,
		`{"verify":0}`:       false,
		`{"verify":null}`:    false,
		`{"verify":[false]}`: false,
	} {
		var s SessionConfig
		json.Unmarshal([]byte(raw), &s)
		var p LocalProxyConfig
		json.Unmarshal([]byte(raw), &p)
		if verifyOff(s.Verify) != off || verifyOff(p.Verify) != off {
			t.Errorf("%s: session off=%v, proxy off=%v, want %v", raw, verifyOff(s.Verify), verifyOff(p.Verify), off)
		}
	}
}

// http2_max_conn_age takes a number of seconds, a fraction rounded up. A
// value that is not a number keeps the default rather than turning the
// limit off.
func TestHTTP2MaxConnAgeDecodes(t *testing.T) {
	for _, c := range []struct {
		raw string
		age int64
		set bool
	}{
		{`{}`, 0, false},
		{`{"http2_max_conn_age":90}`, 90, true},
		{`{"http2_max_conn_age":600.0}`, 600, true},
		{`{"http2_max_conn_age":1.5}`, 2, true},
		{`{"http2_max_conn_age":0}`, 0, true},
		{`{"http2_max_conn_age":-1}`, -1, true},
		{`{"http2_max_conn_age":"300"}`, 0, false},
		{`{"http2_max_conn_age":true}`, 0, false},
		{`{"http2_max_conn_age":null}`, 0, false},
		{`{"http2_max_conn_age":1e300}`, 9223372036, true},
	} {
		var s SessionConfig
		json.Unmarshal([]byte(c.raw), &s)
		age, set := connAgeSeconds(s.HTTP2MaxConnAge)
		if age != c.age || set != c.set {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", c.raw, age, set, c.age, c.set)
		}
	}
}
