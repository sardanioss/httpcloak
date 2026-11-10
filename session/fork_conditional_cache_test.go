package session

import (
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
)

// Fork copied the parent's conditional-cache entries but not the switch that
// uses them, so every fork had conditional requests off: no If-None-Match or
// If-Modified-Since, whatever the parent was set to.
func TestForkKeepsTheConditionalCacheSetting(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		parent := NewSession("", &protocol.SessionConfig{Preset: "chrome-146"})
		parent.SetConditionalCacheEnabled(enabled)
		forks := parent.Fork(2)
		for i, f := range forks {
			if got := f.ConditionalCacheEnabled(); got != enabled {
				t.Errorf("parent conditional cache %v: fork %d has %v", enabled, i, got)
			}
			f.Close()
		}
		parent.Close()
	}
}
