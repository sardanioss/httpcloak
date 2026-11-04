package client

import (
	"testing"

	"github.com/sardanioss/httpcloak/internal/respheader"
)

// The client marks the pool Manager it builds, whichever constructor path
// built it. A path that missed the mark would still work, only without the
// saving, so the hook is spied on directly.
func TestNewClientMarksItsPool(t *testing.T) {
	keep := respheader.KeepWireCase
	t.Cleanup(func() { respheader.KeepWireCase = keep })
	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{name: "direct"},
		{name: "proxy", opts: []Option{WithProxy("http://127.0.0.1:1")}},
		{name: "tcp proxy", opts: []Option{WithTCPProxy("http://127.0.0.1:1")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var marked []any
			respheader.KeepWireCase = func(m any) {
				marked = append(marked, m)
				keep(m)
			}
			c := NewClient("chrome-latest", tc.opts...)
			defer c.Close()
			if len(marked) != 1 || marked[0] != any(c.poolManager) {
				t.Errorf("KeepWireCase called with %v, want once with the client's Manager", marked)
			}
		})
	}
}
