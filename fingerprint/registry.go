package fingerprint

import "sync"

// customPresets is a thread-safe registry for custom presets.
var customPresets sync.Map

// Register adds a custom preset to the registry. It will be found by Get().
// Nil presets are ignored.
func Register(name string, preset *Preset) {
	if preset == nil {
		return
	}
	customPresets.Store(name, preset)
}

// Unregister removes a custom preset from the registry.
func Unregister(name string) {
	customPresets.Delete(name)
}

// LookupCustom returns a registered custom preset by name, or nil if not found.
func LookupCustom(name string) *Preset {
	if v, ok := customPresets.Load(name); ok {
		p, _ := v.(*Preset)
		return p
	}
	return nil
}
