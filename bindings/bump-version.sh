#!/bin/bash
# HTTPCloak Version Bump Script
# Usage: ./bump-version.sh <new_version>
# Example: ./bump-version.sh 1.0.7

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <new_version>"
    echo "Example: $0 1.0.7"
    exit 1
fi

NEW_VERSION="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Bumping all versions to $NEW_VERSION..."

# Validate version format
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z (e.g., 1.0.6)"
    exit 1
fi

# Update main Node.js package.json (version + optionalDependencies)
echo "  -> nodejs/package.json"
cd "$SCRIPT_DIR/nodejs"
# Use node to update JSON properly
node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
pkg.version = '$NEW_VERSION';
for (const dep of Object.keys(pkg.optionalDependencies || {})) {
    pkg.optionalDependencies[dep] = '$NEW_VERSION';
}
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
"

# Update all platform package.json files
for platform in linux-x64 linux-arm64 darwin-x64 darwin-arm64 win32-x64 win32-arm64; do
    if [ -f "$SCRIPT_DIR/nodejs/npm/$platform/package.json" ]; then
        echo "  -> nodejs/npm/$platform/package.json"
        cd "$SCRIPT_DIR/nodejs/npm/$platform"
        node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
pkg.version = '$NEW_VERSION';
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
"
    fi
done

# Update Python pyproject.toml
echo "  -> python/pyproject.toml"
cd "$SCRIPT_DIR/python"
sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" pyproject.toml

# Update clib httpcloak.go version string
echo "  -> clib/httpcloak.go"
cd "$SCRIPT_DIR/clib"
sed -i "s/^const libVersion = \".*\"/const libVersion = \"$NEW_VERSION\"/" httpcloak.go

# Update Python __init__.py version string
echo "  -> python/httpcloak/__init__.py"
cd "$SCRIPT_DIR/python"
sed -i "s/__version__ = \"[0-9]*\.[0-9]*\.[0-9]*\"/__version__ = \"$NEW_VERSION\"/" httpcloak/__init__.py

# Update .NET HttpCloak.csproj version
if [ -f "$SCRIPT_DIR/dotnet/HttpCloak/HttpCloak.csproj" ]; then
    echo "  -> dotnet/HttpCloak/HttpCloak.csproj"
    cd "$SCRIPT_DIR/dotnet/HttpCloak"
    sed -i "s/<Version>[0-9]*\.[0-9]*\.[0-9]*<\/Version>/<Version>$NEW_VERSION<\/Version>/" HttpCloak.csproj
fi

# Update Android library version
echo "  -> android/httpcloak/build.gradle.kts"
sed -i "s/^version = \"[0-9]*\.[0-9]*\.[0-9]*\"/version = \"$NEW_VERSION\"/" "$SCRIPT_DIR/android/httpcloak/build.gradle.kts"

# Update the Rust workspace version, and the exact pin the crate keeps on the
# sys crate, which is the same library.
echo "  -> rust/Cargo.toml, rust/httpcloak/Cargo.toml"
sed -i "s/^version = \"[0-9]*\.[0-9]*\.[0-9]*\"/version = \"$NEW_VERSION\"/" "$SCRIPT_DIR/rust/Cargo.toml"
sed -i "s/httpcloak-sys = { version = \"=[0-9]*\.[0-9]*\.[0-9]*\"/httpcloak-sys = { version = \"=$NEW_VERSION\"/" "$SCRIPT_DIR/rust/httpcloak/Cargo.toml"

# Every file must now carry the new version. A pattern that stops matching
# (as the clib one did when the version moved into libVersion, so 1.7.2-beta.2
# and the first 1.7.3 bump reported the previous version) fails here instead
# of shipping quietly.
#
# The paths are relative to this directory, which the glob needs too: the
# script has moved into dotnet/HttpCloak by now, so it used to match nothing
# and skip every npm platform package. The version must sit between quotes or
# tags, so 1.7.3 is not satisfied by 1.7.30 or 11.7.3; the Rust crate's exact
# pin on its sys crate writes it "=1.7.3".
cd "$SCRIPT_DIR"
version_re="[\">=]${NEW_VERSION//./\\.}[\"<]"
missing=0
for f in nodejs/package.json python/pyproject.toml python/httpcloak/__init__.py \
         clib/httpcloak.go android/httpcloak/build.gradle.kts \
         nodejs/npm/*/package.json dotnet/HttpCloak/HttpCloak.csproj \
         rust/Cargo.toml rust/httpcloak/Cargo.toml; do
    if [ ! -f "$f" ]; then
        echo "ERROR: $f not found" >&2
        missing=1
        continue
    fi
    if ! grep -qE "$version_re" "$f"; then
        echo "ERROR: $f does not contain $NEW_VERSION" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ] || exit 1

echo ""
echo "Version bumped to $NEW_VERSION successfully!"
echo ""
echo "Files updated:"
echo "  - bindings/nodejs/package.json (version + optionalDependencies)"
echo "  - bindings/nodejs/npm/*/package.json (the platform packages)"
echo "  - bindings/python/pyproject.toml"
echo "  - bindings/python/httpcloak/__init__.py"
echo "  - bindings/clib/httpcloak.go"
echo "  - bindings/dotnet/HttpCloak/HttpCloak.csproj (if exists)"
echo "  - bindings/android/httpcloak/build.gradle.kts"
echo "  - bindings/rust/Cargo.toml and bindings/rust/httpcloak/Cargo.toml"
echo ""
echo "Next steps:"
echo "  1. Rebuild native libraries: cd bindings && make build"
echo "  2. Test locally"
echo "  3. Commit and tag: git tag v$NEW_VERSION"
echo "  4. Push: git push && git push --tags"
