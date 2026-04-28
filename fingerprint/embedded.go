package fingerprint

import (
	"embed"
	"io/fs"
	"log"
	"path"
	"strings"
)

// embeddedPresets bundles JSON preset definitions into the library binary at
// compile time. New monthly Chrome versions (which are usually pure header
// diffs over the previous version's TLS fingerprint) can be added without a
// Go-code change by dropping a JSON file in fingerprint/embedded/.
//
//go:embed embedded/*.json
var embeddedPresets embed.FS

// init auto-registers every embedded preset JSON via the standard
// LoadPresetFromJSON + BuildPreset path. Failures (missing dir, malformed
// JSON, unknown based_on, etc.) are logged and skipped so a single bad file
// can never prevent the library from loading.
func init() {
	entries, err := fs.ReadDir(embeddedPresets, "embedded")
	if err != nil {
		// embed.FS ErrNotExist when the embedded/ directory has no matching
		// files — expected if no JSON presets ship with the build.
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := embeddedPresets.ReadFile(path.Join("embedded", e.Name()))
		if err != nil {
			log.Printf("httpcloak: failed to read embedded preset %s: %v", e.Name(), err)
			continue
		}
		pf, err := LoadPresetFromJSON(data)
		if err != nil {
			log.Printf("httpcloak: failed to parse embedded preset %s: %v", e.Name(), err)
			continue
		}
		if pf.Preset == nil {
			log.Printf("httpcloak: embedded preset %s has no preset section, skipping", e.Name())
			continue
		}
		p, err := BuildPreset(pf.Preset)
		if err != nil {
			log.Printf("httpcloak: failed to build embedded preset %s: %v", e.Name(), err)
			continue
		}
		Register(p.Name, p)
	}
}
