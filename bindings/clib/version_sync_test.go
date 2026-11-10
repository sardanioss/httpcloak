//go:build hctest

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// libVersion is what every binding's version() reports, and it lives apart
// from the binding version files. It was missed for 1.7.2-beta.2 (every
// binding reported 1.6.11) and again by the first 1.7.3 bump, because
// bump-version.sh still searched for the pattern the version had moved out
// of. This holds it to every file the script bumps.
func TestLibVersionMatchesEveryBinding(t *testing.T) {
	files := map[string]*regexp.Regexp{
		"../python/pyproject.toml":              regexp.MustCompile(`(?m)^version = "([^"]+)"`),
		"../python/httpcloak/__init__.py":       regexp.MustCompile(`__version__ = "([^"]+)"`),
		"../nodejs/package.json":                regexp.MustCompile(`"version": "([^"]+)"`),
		"../dotnet/HttpCloak/HttpCloak.csproj":  regexp.MustCompile(`<Version>([^<]+)</Version>`),
		"../android/httpcloak/build.gradle.kts": regexp.MustCompile(`(?m)^version = "([^"]+)"`),
		"../rust/Cargo.toml":                    regexp.MustCompile(`(?m)^version = "([^"]+)"`),
		// The crate pins the sys crate exactly: they are one library.
		"../rust/httpcloak/Cargo.toml": regexp.MustCompile(`httpcloak-sys = \{ version = "=([^"]+)"`),
	}
	npm, _ := filepath.Glob("../nodejs/npm/*/package.json")
	for _, f := range npm {
		files[f] = regexp.MustCompile(`"version": "([^"]+)"`)
	}
	for f, re := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		m := re.FindSubmatch(data)
		if m == nil {
			t.Errorf("%s: no version found", f)
		} else if string(m[1]) != libVersion {
			t.Errorf("%s says %s, libVersion says %s", f, m[1], libVersion)
		}
	}
}
