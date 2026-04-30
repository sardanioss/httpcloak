package fingerprint

import (
	"fmt"
	"sync"
)

// customPresets is a thread-safe registry for custom presets.
var customPresets sync.Map

// Register adds a custom preset to the registry. It will be found by Get().
// Nil presets are ignored. Silently overwrites any existing entry with the
// same name — use RegisterStrict to surface name collisions instead.
func Register(name string, preset *Preset) {
	if preset == nil {
		return
	}
	customPresets.Store(name, preset)
}

// RegisterStrict adds a custom preset to the registry but errors out if the
// name is already taken — by another custom preset OR by a built-in. JSON
// loader paths use this so that user-supplied specs can't accidentally
// shadow a shipped preset like "chrome-latest". Callers who want to update
// a registered preset should call Unregister(name) first.
func RegisterStrict(name string, preset *Preset) error {
	if preset == nil {
		return fmt.Errorf("preset is nil")
	}
	if name == "" {
		return fmt.Errorf("preset name is empty")
	}
	// Block collisions with already-registered custom presets.
	if _, exists := customPresets.Load(name); exists {
		return fmt.Errorf("preset name %q already registered (call Unregister first to replace)", name)
	}
	// Block collisions with built-in preset names.
	if _, builtin := presets[name]; builtin {
		return fmt.Errorf("preset name %q collides with a built-in — pick a different name", name)
	}
	customPresets.Store(name, preset)
	return nil
}

// Unregister removes a custom preset from the registry.
func Unregister(name string) {
	customPresets.Delete(name)
}

// LookupCustom returns a registered custom preset by name, or nil if not found.
// Returns a deep clone to prevent callers from mutating the registry copy.
func LookupCustom(name string) *Preset {
	if v, ok := customPresets.Load(name); ok {
		p, _ := v.(*Preset)
		if p != nil {
			return clonePreset(p)
		}
	}
	return nil
}
