package respheader

import (
	"context"
	"fmt"
	"net/textproto"
	"reflect"
	"testing"

	http "github.com/sardanioss/http"
)

// fields returns n distinct wire-case names and the same map keyed canonically.
func fields(n int) (wire, canonical http.Header) {
	wire, canonical = http.Header{}, http.Header{}
	for i := range n {
		name := fmt.Sprintf("x-name-%02d", i)
		v := []string{name}
		wire[name] = v
		canonical[http.CanonicalHeaderKey(name)] = v
	}
	return wire, canonical
}

// Canonical rekeys names in place and nothing else: the order entry keeps its
// spelling, values stay where they were, a map already canonical is left as
// it is, and the stack holds 32 entries before it spills to the heap.
func TestCanonical(t *testing.T) {
	order := []string{"set-cookie", "www-authenticate", "x-uncommon-name", "set-cookie"}
	wire32, canonical32 := fields(32)
	wire40, canonical40 := fields(40)
	for _, tc := range []struct {
		name     string
		in, want http.Header
	}{
		{
			name: "wire case",
			in: http.Header{
				"set-cookie":        {"a=1", "b=2"},
				"www-authenticate":  {"Basic"},
				"x-uncommon-name":   {"v"},
				http.HeaderOrderKey: order,
			},
			want: http.Header{
				"Set-Cookie":        {"a=1", "b=2"},
				"Www-Authenticate":  {"Basic"},
				"X-Uncommon-Name":   {"v"},
				http.HeaderOrderKey: order,
			},
		},
		{
			name: "mixed",
			in:   http.Header{"content-type": {"a"}, "Content-Length": {"1"}, "x-b": {"b"}},
			want: http.Header{"Content-Type": {"a"}, "Content-Length": {"1"}, "X-B": {"b"}},
		},
		{
			name: "already canonical",
			in:   http.Header{"Content-Type": {"a"}, http.HeaderOrderKey: {"content-type"}},
			want: http.Header{"Content-Type": {"a"}, http.HeaderOrderKey: {"content-type"}},
		},
		{
			name: "order key only",
			in:   http.Header{http.HeaderOrderKey: {"a"}},
			want: http.Header{http.HeaderOrderKey: {"a"}},
		},
		{name: "empty", in: http.Header{}, want: http.Header{}},
		{name: "32 fields", in: wire32, want: canonical32},
		{name: "40 fields", in: wire40, want: canonical40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]*string{}
			for k, v := range tc.in {
				if len(v) > 0 {
					values[http.CanonicalHeaderKey(k)] = &v[0]
				}
			}
			Canonical(tc.in)
			if !reflect.DeepEqual(tc.in, tc.want) {
				t.Fatalf("got %#v, want %#v", tc.in, tc.want)
			}
			for k, p := range values {
				if &tc.in[k][0] != p {
					t.Errorf("%s: values were copied rather than left in place", k)
				}
			}
		})
	}
	Canonical(nil)
}

// The common-name table must give what textproto gives, or a conversion
// would key a field differently from the HTTP/2 layer.
func TestCommonCanonicalAgreesWithTextproto(t *testing.T) {
	for lower, canon := range commonCanonical {
		if want := textproto.CanonicalMIMEHeaderKey(lower); canon != want {
			t.Errorf("%q maps to %q, textproto says %q", lower, canon, want)
		}
	}
}

func TestWithCanonical1xxLeavesAContextWithoutTheHook(t *testing.T) {
	ctx := context.Background()
	if got, ok := WithCanonical1xx(ctx); ok || got != ctx {
		t.Fatal("WithCanonical1xx changed a context with no trace")
	}
}
