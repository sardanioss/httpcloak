package fingerprint

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The Python, Node.js, .NET and Rust bindings each carry their own list of
// preset name constants, and the Node.js typings carry a fourth copy of the Node
// list. Nothing ties those to the registry, so they drift: the typings stopped
// at Chrome 151 while the runtime object gained 152 to 155, and the binding
// constants once stopped at 151 while chrome-152 shipped. This reads each list
// from source and holds it to the registry.

type bindingConstants struct {
	name   string
	values map[string]string // constant name -> preset name
}

func readBindingFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "bindings", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

// between returns the part of s from the first start up to the next end.
func between(t *testing.T, s, start, end, what string) string {
	t.Helper()
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("%s: %q not found", what, start)
	}
	s = s[i+len(start):]
	j := strings.Index(s, end)
	if j < 0 {
		t.Fatalf("%s: end %q not found", what, end)
	}
	return s[:j]
}

// parseConstants reads NAME <sep> "value" pairs, plus NAME <sep> OTHER aliases
// resolved against the pairs already read.
func parseConstants(t *testing.T, what, block string, literal, alias *regexp.Regexp) bindingConstants {
	t.Helper()
	c := bindingConstants{name: what, values: map[string]string{}}
	for _, line := range strings.Split(block, "\n") {
		if m := literal.FindStringSubmatch(line); m != nil {
			c.values[m[1]] = m[2]
		} else if m := alias.FindStringSubmatch(line); m != nil {
			v, ok := c.values[m[2]]
			if !ok {
				t.Fatalf("%s: %s aliases %s, which is not defined above it", what, m[1], m[2])
			}
			c.values[m[1]] = v
		}
	}
	if len(c.values) == 0 {
		t.Fatalf("%s: no constants parsed; did the file layout change?", what)
	}
	return c
}

func TestBindingPresetConstantsMatchRegistry(t *testing.T) {
	py := parseConstants(t, "python",
		between(t, readBindingFile(t, "python/httpcloak/client.py"), "\nclass Preset", "\n    @classmethod", "python"),
		regexp.MustCompile(`^    ([A-Z0-9_]+) = "([^"]+)"`),
		regexp.MustCompile(`^    ([A-Z0-9_]+) = ([A-Z0-9_]+)\s*$`))

	nodeSrc := readBindingFile(t, "nodejs/lib/index.js")
	node := parseConstants(t, "node",
		between(t, nodeSrc, "\nconst Preset = {", "\n  /**", "node"),
		regexp.MustCompile(`^  ([A-Z0-9_]+): "([^"]+)",`),
		regexp.MustCompile(`^  ([A-Z0-9_]+): ([A-Z0-9_]+),`))

	dotnet := parseConstants(t, "dotnet",
		between(t, readBindingFile(t, "dotnet/HttpCloak/Session.cs"), "public static class Presets", "\n}", "dotnet"),
		regexp.MustCompile(`public const string (\w+) = "([^"]+)";`),
		regexp.MustCompile(`public const string (\w+) = (\w+);`))

	rust := parseConstants(t, "rust",
		between(t, readBindingFile(t, "rust/httpcloak/src/presets.rs"), "holds them to.\n", "\n/// Every preset name above", "rust"),
		regexp.MustCompile(`^pub const ([A-Z0-9_]+): &str = "([^"]+)";`),
		regexp.MustCompile(`^pub const ([A-Z0-9_]+): &str = ([A-Z0-9_]+);`))

	var current []string
	for name := range presets {
		// The ios-chrome-NNN / android-chrome-NNN spellings are kept for old
		// callers only; the bindings expose the chrome-NNN-ios form instead.
		if strings.HasPrefix(name, "ios-") || strings.HasPrefix(name, "android-") {
			continue
		}
		current = append(current, name)
	}
	sort.Strings(current)

	for _, b := range []bindingConstants{py, node, dotnet, rust} {
		have := map[string]bool{}
		for constant, value := range b.values {
			have[value] = true
			if _, ok := presets[value]; !ok {
				t.Errorf("%s: %s = %q is not a registered preset", b.name, constant, value)
			}
		}
		for _, name := range current {
			if !have[name] {
				t.Errorf("%s: no constant for preset %q", b.name, name)
			}
		}
	}

	// The three bindings name each preset the same way, modulo case style.
	for constant, value := range py.values {
		if v, ok := node.values[constant]; !ok || v != value {
			t.Errorf("node: Preset.%s is %q, python has %q", constant, v, value)
		}
	}
	// .NET spells the same constants in PascalCase: CHROME_155_IOS is
	// Chrome155IOS. Compared by name too, so two swapped values fail here.
	fold := func(constant string) string { return strings.ToLower(strings.ReplaceAll(constant, "_", "")) }
	dotnetByFold := map[string]string{}
	for constant, value := range dotnet.values {
		dotnetByFold[fold(constant)] = value
	}
	for constant, value := range py.values {
		if v, ok := dotnetByFold[fold(constant)]; !ok || v != value {
			t.Errorf("dotnet: the constant for python's %s is %q, python has %q", constant, v, value)
		}
	}
	// Rust spells them exactly as Python does.
	for constant, value := range py.values {
		if v, ok := rust.values[constant]; !ok || v != value {
			t.Errorf("rust: presets::%s is %q, python has %q", constant, v, value)
		}
	}
	if len(node.values) != len(py.values) || len(dotnet.values) != len(py.values) || len(rust.values) != len(py.values) {
		t.Errorf("constant counts differ: python %d, node %d, dotnet %d, rust %d",
			len(py.values), len(node.values), len(dotnet.values), len(rust.values))
	}

	// The typings declare exactly the runtime object's constants.
	typed := regexp.MustCompile(`(?m)^  ([A-Z0-9_]+): string;`).FindAllStringSubmatch(
		between(t, readBindingFile(t, "nodejs/lib/index.d.ts"), "export const Preset: {", "\n};", "typings"), -1)
	declared := map[string]bool{}
	for _, m := range typed {
		declared[m[1]] = true
		if _, ok := node.values[m[1]]; !ok {
			t.Errorf("index.d.ts declares Preset.%s, which index.js does not define", m[1])
		}
	}
	for constant := range node.values {
		if !declared[constant] {
			t.Errorf("index.d.ts does not declare Preset.%s", constant)
		}
	}
}
