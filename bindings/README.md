# HTTPCloak Native Bindings

Native language bindings for HTTPCloak, providing direct FFI access to the Go library without IPC overhead.

## Supported Languages

- **Python** - Sync + async support with ctypes
- **Node.js** - Promises + callbacks with koffi
- **.NET** - P/Invoke, sync + `Task` async
- **Android (Kotlin)** - Coroutines over a thin JNI bridge, see [android/README.md](android/README.md)

## Supported Platforms

| Platform | amd64 (x64) | arm64 |
|----------|-------------|-------|
| Linux (glibc 2.17+) | Yes | Yes |
| macOS 12+ | Yes         | Yes   |
| Windows 10+ | Yes       | No prebuilt library |
| Android  | Yes (x86_64, x86) | Yes (arm64-v8a, armeabi-v7a) |

Alpine and other musl systems aren't supported yet.

## Quick Start

### Building

```bash
# Build for current platform
make build

# Build and copy to all bindings
make all

# Build for all platforms (needs cross-compilers)
make build-all
```

### Python

```bash
# Install in development mode
make install-python

# Test
make test-python
```

```python
from httpcloak import Session

session = Session(preset="chrome-latest")
response = session.get("https://example.com")
print(response.status_code, response.protocol)
```

### Node.js

```bash
# Install dependencies
make nodejs-install

# Test
make test-nodejs
```

```javascript
const { Session } = require("httpcloak");

const session = new Session({ preset: "chrome-latest" });
const response = await session.get("https://example.com");
console.log(response.statusCode, response.protocol);
```

## Directory Structure

```
bindings/
  clib/           # Go shared library source + build scripts
    httpcloak.go  # C API implementation
    build.sh      # Build script
    dist/         # Built libraries
  python/         # Python bindings
    httpcloak/
      client.py   # Main client
      lib/        # Native libraries
  nodejs/         # Node.js bindings
    lib/
      index.js    # Main module
  dotnet/         # .NET bindings
  android/        # Android library (Gradle project)
    httpcloak/src/main/cpp/     # JNI bridge
    httpcloak/src/main/kotlin/  # Kotlin API
  Makefile        # Build orchestration
```

## Cross-Compilation

To build for all platforms, you need the following tools:

- **Linux arm64**: `aarch64-linux-gnu-gcc`
- **Windows amd64**: `x86_64-w64-mingw32-gcc`
- **Windows arm64**: `aarch64-w64-mingw32-gcc`
- **macOS**: Can only be built on macOS

### Install cross-compilers (Ubuntu/Debian)

```bash
# Linux arm64
sudo apt install gcc-aarch64-linux-gnu

# Windows
sudo apt install mingw-w64
```

## API Reference

### Session Options

| Option          | Type   | Default      | Description                                              |
|-----------------|--------|--------------|----------------------------------------------------------|
| preset          | string | "chrome-latest" | Browser preset to emulate                                |
| proxy           | string | null         | Proxy URL                                                |
| timeout         | int    | 30           | Request timeout in seconds                               |
| httpVersion     | string | "auto"       | HTTP version: "auto", "h1", "h2", "h3"                   |
| quicIdleTimeout | int    | 30           | QUIC idle timeout in seconds (for HTTP/3 connections)    |
| http2MaxConnAge | int    | null (300)   | Seconds before an HTTP/2 connection takes no new requests; leave it out for five minutes, 0 turns it off |
| tlsOnly         | bool   | false        | TLS-only mode: skip preset HTTP headers                  |

### Response Object

| Property    | Type    | Description                      |
|-------------|---------|----------------------------------|
| status_code | int     | HTTP status code                 |
| headers     | object  | Response headers                 |
| body        | bytes   | Raw response body                |
| text        | string  | Response body as string          |
| final_url   | string  | Final URL after redirects        |
| protocol    | string  | Protocol used (h1, h2, h3)       |

### Available Presets

```python
from httpcloak import available_presets
print(available_presets())
# ['chrome-146', 'chrome-146-windows', 'chrome-146-linux', 'chrome-145', ...]
```

## License

MIT
