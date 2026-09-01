package fingerprint

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// UnknownPresetFields returns every key in a preset JSON document that no field
// of the spec models, as dotted paths ("preset.tls.cipher_suits").
//
// It exists because the loader ignores what it does not recognise, which is the
// right default for forward compatibility and the wrong one for a typo. A
// misspelled key does not fail, it silently leaves that part of the preset at
// whatever the inheritance chain supplied: a preset written to mirror one client
// can go on the wire as another entirely, with no error anywhere. That is the
// worst failure shape in the loader, because every other kind announces itself.
//
// The whole document is walked rather than stopping at the first unknown key,
// so a caller sees every typo at once instead of one per run.
func UnknownPresetFields(data []byte) ([]string, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse preset JSON: %w", err)
	}
	var out []string
	walkUnknown(raw, reflect.TypeOf(PresetFile{}), "", &out)
	sort.Strings(out)
	return out, nil
}

// walkUnknown compares one JSON object against the struct that models it.
//
// A type it cannot introspect (a map, an interface, anything free-form) ends the
// walk for that subtree: the keys under it are data rather than schema, so
// calling them unknown would be wrong.
func walkUnknown(raw map[string]any, t reflect.Type, prefix string, out *[]string) {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}

	known := make(map[string]reflect.Type, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = f.Name
		}
		known[strings.ToLower(name)] = f.Type
	}

	for k, v := range raw {
		ft, ok := known[strings.ToLower(k)]
		if !ok {
			*out = append(*out, prefix+k)
			continue
		}
		child, isObj := v.(map[string]any)
		if !isObj {
			continue
		}
		for ft.Kind() == reflect.Ptr {
			ft = ft.Elem()
		}
		// A map-typed field holds caller data, not more schema.
		if ft.Kind() == reflect.Struct {
			walkUnknown(child, ft, prefix+k+".", out)
		}
	}
}

// LoadPresetFromJSONStrict is LoadPresetFromJSON with unknown keys rejected.
//
// Use it when a preset is meant to reproduce a specific client exactly and a
// silently ignored key would mean shipping the wrong fingerprint. The lenient
// loader stays the default so that a preset written for a newer version of the
// library still loads on an older one.
func LoadPresetFromJSONStrict(data []byte) (*PresetFile, error) {
	unknown, err := UnknownPresetFields(data)
	if err != nil {
		return nil, err
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("preset has %d field(s) this version does not model: %s. "+
			"They were ignored rather than applied, so the preset would not describe the "+
			"client you wrote it for. Check the spelling, or use LoadPresetFromJSON if the "+
			"keys are meant for a newer version",
			len(unknown), strings.Join(unknown, ", "))
	}
	return LoadPresetFromJSON(data)
}
