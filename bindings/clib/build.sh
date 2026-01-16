#!/bin/bash
# Build script for httpcloak shared library
# Supports Linux, macOS, and Windows (via cross-compilation)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Output directory
DIST_DIR="$SCRIPT_DIR/dist"
mkdir -p "$DIST_DIR"

# Detect current platform if not specified
if [ -z "$TARGET_OS" ]; then
    case "$(uname -s)" in
        Linux*)  TARGET_OS=linux;;
        Darwin*) TARGET_OS=darwin;;
        MINGW*|MSYS*|CYGWIN*) TARGET_OS=windows;;
        *)       TARGET_OS=linux;;
    esac
fi

if [ -z "$TARGET_ARCH" ]; then
    case "$(uname -m)" in
        x86_64|amd64) TARGET_ARCH=amd64;;
        aarch64|arm64) TARGET_ARCH=arm64;;
        *)             TARGET_ARCH=amd64;;
    esac
fi

# Determine output file extension
get_extension() {
    local os=$1
    case "$os" in
        darwin)  echo ".dylib";;
        windows) echo ".dll";;
        *)       echo ".so";;
    esac
}

# Build for a specific platform
build_for_platform() {
    local os=$1
    local arch=$2
    local cc=${3:-}
    local ext=$(get_extension "$os")
    local output="$DIST_DIR/libhttpcloak-${os}-${arch}${ext}"

    echo "Building for $os/$arch -> $output"

    if [ -n "$cc" ]; then
        CGO_ENABLED=1 GOOS="$os" GOARCH="$arch" CC="$cc" go build \
            -buildmode=c-shared \
            -ldflags="-s -w" \
            -o "$output" \
            httpcloak.go
    else
        CGO_ENABLED=1 GOOS="$os" GOARCH="$arch" go build \
            -buildmode=c-shared \
            -ldflags="-s -w" \
            -o "$output" \
            httpcloak.go
    fi

    # Move header file to dist directory
    local header_basename="libhttpcloak-${os}-${arch}.h"
    if [ -f "$DIST_DIR/$header_basename" ]; then
        mv "$DIST_DIR/$header_basename" "$DIST_DIR/httpcloak.h"
    fi

    echo "  Built: $output"
}

# Build for current platform only (default)
build_native() {
    build_for_platform "$TARGET_OS" "$TARGET_ARCH"
}

# Build for all supported platforms (requires cross-compilation setup)
build_all() {
    echo "Building for all platforms..."
    echo "Note: Cross-compilation requires appropriate toolchains"
    echo ""

    # Linux builds
    echo "=== Linux ==="
    build_for_platform "linux" "amd64" || echo "  Failed: linux/amd64"

    if command -v aarch64-linux-gnu-gcc &> /dev/null; then
        build_for_platform "linux" "arm64" "aarch64-linux-gnu-gcc" || echo "  Failed: linux/arm64"
    elif [ "$TARGET_OS" = "linux" ] && [ "$TARGET_ARCH" = "arm64" ]; then
        build_for_platform "linux" "arm64" || echo "  Failed: linux/arm64"
    else
        echo "  Skipping linux/arm64 (no cross-compiler: aarch64-linux-gnu-gcc)"
    fi

    # macOS builds (only on macOS or with osxcross)
    echo ""
    echo "=== macOS ==="
    if [ "$TARGET_OS" = "darwin" ]; then
        build_for_platform "darwin" "amd64" || echo "  Failed: darwin/amd64"
        build_for_platform "darwin" "arm64" || echo "  Failed: darwin/arm64"
    else
        echo "  Skipping darwin builds (only buildable on macOS)"
    fi

    # Windows builds (requires mingw)
    echo ""
    echo "=== Windows ==="
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        build_for_platform "windows" "amd64" "x86_64-w64-mingw32-gcc" || echo "  Failed: windows/amd64"
    else
        echo "  Skipping windows/amd64 (no cross-compiler: x86_64-w64-mingw32-gcc)"
    fi

    if command -v aarch64-w64-mingw32-gcc &> /dev/null; then
        build_for_platform "windows" "arm64" "aarch64-w64-mingw32-gcc" || echo "  Failed: windows/arm64"
    else
        echo "  Skipping windows/arm64 (no cross-compiler: aarch64-w64-mingw32-gcc)"
    fi

    echo ""
    echo "=============================================="
    echo "Build complete! Files in: $DIST_DIR"
    ls -la "$DIST_DIR"
}

# Copy libraries to binding directories
copy_to_bindings() {
    local ext=$(get_extension "$TARGET_OS")
    local lib="$DIST_DIR/libhttpcloak-${TARGET_OS}-${TARGET_ARCH}${ext}"

    if [ -f "$lib" ]; then
        echo "Copying to Python bindings..."
        mkdir -p "$SCRIPT_DIR/../python/httpcloak/lib"
        cp "$lib" "$SCRIPT_DIR/../python/httpcloak/lib/"
        # Also copy to top-level for direct import (search path priority)
        cp "$lib" "$SCRIPT_DIR/../python/httpcloak/"

        echo "Copying to Node.js bindings..."
        mkdir -p "$SCRIPT_DIR/../nodejs/lib"
        cp "$lib" "$SCRIPT_DIR/../nodejs/lib/"
        # Also copy to npm package location if it exists (takes priority in search)
        if [ -d "$SCRIPT_DIR/../nodejs/node_modules/@httpcloak/linux-x64" ]; then
            cp "$lib" "$SCRIPT_DIR/../nodejs/node_modules/@httpcloak/linux-x64/"
        fi

        echo "Copying to .NET bindings..."
        mkdir -p "$SCRIPT_DIR/../dotnet/HttpCloak/lib"
        cp "$lib" "$SCRIPT_DIR/../dotnet/HttpCloak/lib/"
        cp "$lib" "$SCRIPT_DIR/../dotnet/HttpCloak/"
        mkdir -p "$SCRIPT_DIR/../dotnet/HttpCloak/runtimes/linux-x64/native"
        cp "$lib" "$SCRIPT_DIR/../dotnet/HttpCloak/runtimes/linux-x64/native/"

        echo "Done!"
    else
        echo "Library not found: $lib"
        echo "Run build first: ./build.sh native"
    fi
}

# Show usage
usage() {
    echo "HTTPCloak Shared Library Build Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  native    Build for current platform (default)"
    echo "  all       Build for all platforms (requires cross-compilers)"
    echo "  linux     Build for Linux (amd64 + arm64)"
    echo "  darwin    Build for macOS (amd64 + arm64, macOS only)"
    echo "  windows   Build for Windows (amd64 + arm64)"
    echo "  copy      Copy built library to binding directories"
    echo "  clean     Remove build artifacts"
    echo ""
    echo "Cross-compilation requirements:"
    echo "  - Linux arm64:   aarch64-linux-gnu-gcc"
    echo "  - Windows amd64: x86_64-w64-mingw32-gcc"
    echo "  - Windows arm64: aarch64-w64-mingw32-gcc"
    echo "  - macOS:         Only buildable on macOS"
    echo ""
    echo "Environment variables:"
    echo "  TARGET_OS    Target OS (linux, darwin, windows)"
    echo "  TARGET_ARCH  Target architecture (amd64, arm64)"
}

# Main
case "${1:-native}" in
    native)
        build_native
        ;;
    all)
        build_all
        ;;
    linux)
        echo "=== Building Linux binaries ==="
        build_for_platform "linux" "amd64" || echo "  Failed: linux/amd64"
        if command -v aarch64-linux-gnu-gcc &> /dev/null; then
            build_for_platform "linux" "arm64" "aarch64-linux-gnu-gcc" || echo "  Failed: linux/arm64"
        else
            echo "  Skipping linux/arm64 (no cross-compiler)"
        fi
        ;;
    darwin)
        if [ "$TARGET_OS" != "darwin" ]; then
            echo "macOS builds can only be done on macOS"
            exit 1
        fi
        echo "=== Building macOS binaries ==="
        build_for_platform "darwin" "amd64"
        build_for_platform "darwin" "arm64"
        ;;
    windows)
        echo "=== Building Windows binaries ==="
        if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
            build_for_platform "windows" "amd64" "x86_64-w64-mingw32-gcc" || echo "  Failed: windows/amd64"
        else
            echo "  Skipping windows/amd64 (no cross-compiler)"
        fi
        if command -v aarch64-w64-mingw32-gcc &> /dev/null; then
            build_for_platform "windows" "arm64" "aarch64-w64-mingw32-gcc" || echo "  Failed: windows/arm64"
        else
            echo "  Skipping windows/arm64 (no cross-compiler)"
        fi
        ;;
    copy)
        copy_to_bindings
        ;;
    clean)
        echo "Cleaning build artifacts..."
        rm -rf "$DIST_DIR"
        rm -rf "$SCRIPT_DIR/../python/httpcloak/lib"
        rm -rf "$SCRIPT_DIR/../nodejs/lib/*.so"
        rm -rf "$SCRIPT_DIR/../nodejs/lib/*.dylib"
        rm -rf "$SCRIPT_DIR/../nodejs/lib/*.dll"
        echo "Done"
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        echo "Unknown command: $1"
        usage
        exit 1
        ;;
esac
