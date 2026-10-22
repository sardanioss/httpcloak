package transport

import (
	"reflect"
	"testing"

	http "github.com/sardanioss/http"
)

// A fork-shaped HTTP/2 response header: lowercase keys, the order bookkeeping
// entry, and value slices carved out of one shared backing array the way the
// fork's read path builds them.
func wireShapedHeader() http.Header {
	strs := make([]string, 4)
	h := http.Header{}
	set := func(key, value string) {
		vv := strs[:1:1]
		vv[0] = value
		strs = strs[1:]
		h[key] = vv
	}
	set("content-type", "application/json;charset=utf-8")
	set("content-length", "18342")
	set("x-quota-limit", "500")
	h["set-cookie"] = append(h["set-cookie"], "session=abc; Path=/", "prefs=v1; Path=/")
	h[http.HeaderOrderKey] = []string{"content-type", "content-length", "x-quota-limit", "set-cookie"}
	h[http.PHeaderOrderKey] = []string{":status"}
	return h
}

// adoptWireHeaders must hand back the same entries buildHeadersMap would have
// copied out of a wire-case map: same keys, same values, no bookkeeping.
func TestAdoptWireHeadersMatchesBuild(t *testing.T) {
	adopted := adoptWireHeaders(wireShapedHeader())
	built := buildHeadersMap(wireShapedHeader())
	if !reflect.DeepEqual(adopted, built) {
		t.Errorf("adoptWireHeaders = %v, want buildHeadersMap's %v", adopted, built)
	}
	for _, key := range []string{http.HeaderOrderKey, http.PHeaderOrderKey, h1HeaderCasingKey, exactHeadersKey} {
		if _, ok := adopted[key]; ok {
			t.Errorf("adopted map still carries bookkeeping key %q", key)
		}
	}
}

// The point of adopting is that no second map is built: the returned map is
// the fork's, so the conversion is a handful of deletes.
func TestAdoptWireHeadersReturnsSameMap(t *testing.T) {
	h := wireShapedHeader()
	m := adoptWireHeaders(h)
	m["x-probe"] = []string{"v"}
	if got := h["x-probe"]; len(got) != 1 || got[0] != "v" {
		t.Error("adoptWireHeaders returned a copy, want the same map")
	}
}

func TestAdoptWireHeadersNil(t *testing.T) {
	m := adoptWireHeaders(nil)
	if m == nil || len(m) != 0 {
		t.Errorf("adoptWireHeaders(nil) = %v, want an empty map", m)
	}
}

// Entries out of the fork's shared backing must keep the isolation a fresh
// copy per entry gave: appending through one cannot disturb another.
func TestAdoptWireHeadersEntryIsolation(t *testing.T) {
	m := adoptWireHeaders(wireShapedHeader())
	before := map[string][]string{}
	for k, v := range m {
		before[k] = append([]string(nil), v...)
	}
	m["content-type"] = append(m["content-type"], "second")
	for _, k := range []string{"content-length", "x-quota-limit", "set-cookie"} {
		if !reflect.DeepEqual(m[k], before[k]) {
			t.Errorf("after append to content-type, m[%q] = %v, want %v", k, m[k], before[k])
		}
	}
}
