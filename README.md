# httpcloak

A Go HTTP client library with **completely identical to browser TLS/HTTP fingerprinting**. This library creates HTTP requests that are indistinguishable from real browsers, bypassing bot detection systems that fingerprint TLS handshakes, HTTP/2 settings, and header patterns.

## Why This Library Exists

Modern bot detection systems don't just look at headers or cookies - they analyze the **cryptographic fingerprint** of your connection itself. Every HTTP client has a unique signature based on:

1. **TLS Fingerprint (JA3/JA4)**: The cipher suites, extensions, and elliptic curves offered during TLS handshake
2. **HTTP/2 Fingerprint (Akamai)**: The SETTINGS frame values, WINDOW_UPDATE, PRIORITY frames
3. **Header Order and Values**: The exact order and format of HTTP headers

Go's standard `net/http` library has a **recognizable fingerprint** that bot detection systems (Cloudflare, Akamai, PerimeterX, DataDome) can identify instantly.

**Note:** The requests made via this lib definitely passes through most of **medium** level Cloudflare, Akamai or PerimeterX detection but hardcore ones which check js runtime and other browser fingerprinting is where this will fail.

### The Problem with Go's Standard Library

Every TLS connection has a fingerprint. Bot detection services maintain databases of fingerprints for:
- Every browser version (Chrome 143, Firefox 133, Safari 18, etc.)
- Known bot libraries (Go net/http, Python requests, curl, etc.)
- Known automation tools (Selenium, Puppeteer, etc.)

When your Go application connects, the server instantly knows it's not a browser. Here's a side-by-side comparison with **real data** from [tls.peet.ws/api/all](https://tls.peet.ws/api/all):

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                           FINGERPRINT COMPARISON (Real Data from tls.peet.ws)                        │
├──────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                      │
│  METRIC                      │ GO STDLIB              │ HTTPCLOAK              │ REAL CHROME 143     │
│  ────────────────────────────┼────────────────────────┼────────────────────────┼──────────────────── │
│                                                                                                      │
│  TLS FINGERPRINT                                                                                     │
│  ────────────────────────────┼────────────────────────┼────────────────────────┼──────────────────── │
│  Cipher Suites               │ 13                     │ 16                     │ 16                  │
│  TLS Extensions              │ 12                     │ 18                     │ 18                  │
│  GREASE Values               │ None                   │ Yes (random)           │ Yes (random)        │
│  Post-Quantum (X25519MLKEM)  │ No                     │ Yes                    │ Yes                 │
│  ECH (Encrypted ClientHello) │ No                     │ Yes                    │ Yes                 │
│                                                                                                      │
│  CIPHER SUITES (first 5)                                                                             │
│  ────────────────────────────┼────────────────────────┼────────────────────────┼──────────────────── │
│  1st cipher                  │ AES_128_GCM            │ GREASE (random)        │ GREASE (random)     │
│  2nd cipher                  │ AES_256_GCM            │ AES_128_GCM            │ AES_128_GCM         │
│  3rd cipher                  │ CHACHA20_POLY1305      │ AES_256_GCM            │ AES_256_GCM         │
│  4th cipher                  │ ECDHE_ECDSA_AES128     │ CHACHA20_POLY1305      │ CHACHA20_POLY1305   │
│  5th cipher                  │ ECDHE_RSA_AES128       │ ECDHE_ECDSA_AES128     │ ECDHE_ECDSA_AES128  │
│                                                                                                      │
│  SUPPORTED GROUPS                                                                                    │
│  ────────────────────────────┼────────────────────────┼────────────────────────┼──────────────────── │
│  Groups                      │ X25519, P-256,         │ GREASE, X25519MLKEM768,│ GREASE, X25519MLKEM,│
│                              │ P-384, P-521           │ X25519, P-256, P-384   │ X25519, P-256, P-384│
│                                                                                                      │
│  FINGERPRINT HASHES (verified against real Chrome 143)                                               │
│  ────────────────────────────┼────────────────────────┼────────────────────────┼──────────────────── │
│  JA3 Hash*                   │ e69402f870ecf542...    │ (varies per request)   │ (varies per request)│
│  JA4                         │ t13d1312h2_f57a46...   │ t13d1516h2_8daaf6152771_d8a2da3f94cd   MATCH │
│  peetprint_hash              │ (different)            │ 1d4ffe9b0e34acac0bd883fa7f79d7b5       MATCH │
│  Akamai HTTP/2 Hash          │ cbcbfae223bb97a0...    │ 52d84b11737d980aef856699f885ca86       MATCH │
│                                                                                                      │
│  * JA3 includes GREASE values which are randomized per connection (by design)                        │
│                                                                                                      │
│  HTTP/2 SETTINGS FRAME                                                                               │
│  ────────────────────────────┼────────────────────────┼────────────────────────┼──────────────────── │
│  HEADER_TABLE_SIZE           │ 4,096                  │ 65,536                 │ 65,536              │
│  ENABLE_PUSH                 │ 1 (enabled)            │ 0 (disabled)           │ 0 (disabled)        │
│  INITIAL_WINDOW_SIZE         │ 65,535 (64KB)          │ 6,291,456 (6MB)        │ 6,291,456 (6MB)     │
│  MAX_HEADER_LIST_SIZE        │ 10,485,760             │ 262,144                │ 262,144             │
│  WINDOW_UPDATE increment     │ (varies)               │ 15,663,105             │ 15,663,105          │
│                                                                                                      │
│  HTTP/2 HEADERS FRAME                                                                                │
│  ────────────────────────────┼────────────────────────┼────────────────────────┼──────────────────── │
│  Pseudo-header order         │ :method, :path,        │ :method, :authority,   │ :method, :authority,│
│                              │ :scheme, :authority    │ :scheme, :path         │ :scheme, :path      │
│  Header order                │ (Go's alphabetical)    │ sec-ch-ua, sec-ch-ua-  │ sec-ch-ua, sec-ch-  │
│                              │                        │ mobile, sec-ch-ua-     │ ua-mobile, sec-ch-  │
│                              │                        │ platform, upgrade-...  │ ua-platform, ...    │
│  Priority flag               │ Not present            │ Present                │ Present             │
│  Priority weight             │ N/A                    │ 256                    │ 256                 │
│  Priority exclusive          │ N/A                    │ 1                      │ 1                   │
│  Priority depends_on         │ N/A                    │ 0                      │ 0                   │
│                                                                                                      │
│  CLIENT HINTS                                                                                        │
│  ────────────────────────────┼────────────────────────┼────────────────────────┼──────────────────── │
│  sec-ch-ua                   │ (not sent)             │ "Google Chrome";v="143"│ "Google Chrome";v=" │
│                              │                        │ "Chromium";v="143",    │ 143", "Chromium";   │
│                              │                        │ "Not A(Brand";v="24"   │ v="143", "Not A(... │
│                                                                                                      │
│  MATCH STATUS                                                                                        │
│  ────────────────────────────┼────────────────────────┼────────────────────────┼──────────────────── │
│  Matches Chrome 143?         │           NO           │          YES           │     (is Chrome)     │
│  Bot Detection Result        │         BLOCKED        │         PASSED         │        PASSED       │
│                                                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Key observations:**
- **Akamai HTTP/2 Hash**: `52d84b11737d980aef856699f885ca86` — **identical to real Chrome 143**
- **JA4 Hash**: `t13d1516h2_8daaf6152771_d8a2da3f94cd` — **identical to real Chrome 143**
- **peetprint_hash**: `1d4ffe9b0e34acac0bd883fa7f79d7b5` — **identical to real Chrome 143**
- **GREASE**: Both Chrome and httpcloak randomize GREASE values per connection (this is correct behavior)
- **JA3 varies**: JA3 includes GREASE values, so it changes per connection — this is expected and correct
- **Priority frame**: Chrome 143 sends Priority data (weight=256, exclusive=1), and so does httpcloak
- **Header order**: Both send sec-ch-ua headers first, matching Chrome's exact ordering

#### Why Each Metric Matters

| Metric | Why It Matters |
|--------|----------------|
| **Cipher Suites** | Browsers offer more ciphers in a specific order. Go offers fewer in a different order. This alone identifies Go. |
| **TLS Extensions** | Chrome sends 18 extensions including GREASE (random values). Go sends 12 with no GREASE. Dead giveaway. |
| **Post-Quantum** | Chrome 131+ uses X25519MLKEM768 for quantum-resistant key exchange. Go doesn't support this yet. |
| **GREASE** | Generate Random Extensions And Sustain Extensibility - Chrome randomizes these values per connection. Using the same GREASE value every time is itself a fingerprint! |
| **JA3/JA4 Hash** | JA4 is the modern standard (JA3 is deprecated due to GREASE). Bot detection services maintain databases of known JA4 hashes. |
| **HTTP/2 SETTINGS** | The first HTTP/2 frame contains settings. Chrome's values differ significantly from Go's defaults. |
| **INITIAL_WINDOW_SIZE** | Chrome uses 6MB, Go uses 64KB. This 100x difference is instantly detectable. |
| **Priority Frame** | Chrome 143 sends Priority data (weight=256, exclusive=1) on HEADERS frames. Go doesn't send this. |
| **Header Order** | Chrome sends headers in a specific order (sec-ch-ua first). Go uses alphabetical order. The order itself is a fingerprint. |
| **sec-ch-ua Brand** | Chrome 143 uses `"Not A(Brand";v="24"`. Older/wrong brand strings identify automation. |

#### What Gets You Blocked

```
┌─────────────────────────────────────────────────────────────────┐
│                    BOT DETECTION LAYERS                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 1: TLS Fingerprint                                       │
│  ├─ JA3/JA4 hash lookup in known-bot database                   │
│  ├─ Cipher suite count and order analysis                       │
│  ├─ Extension presence check (GREASE, etc.)                     │
│  └─ Post-quantum support detection                              │
│       ↓ FAIL = Instant block (403/503)                          │
│                                                                 │
│  Layer 2: HTTP/2 Fingerprint                                    │
│  ├─ SETTINGS frame analysis                                     │
│  ├─ WINDOW_UPDATE patterns                                      │
│  └─ PRIORITY frame structure                                    │
│       ↓ FAIL = Captcha or block                                 │
│                                                                 │
│  Layer 3: Header Analysis                                       │
│  ├─ Header order (browsers have specific order)                 │
│  ├─ Sec-Fetch-* header coherence                                │
│  └─ Client Hints presence                                       │
│       ↓ FAIL = Suspicious flag                                  │
│                                                                 │
│  Layer 4: JavaScript Challenge (not covered by httpcloak)       │
│  ├─ Canvas fingerprint                                          │
│  ├─ WebGL fingerprint                                           │
│  └─ Browser API probing                                         │
│       ↓ FAIL = Block                                            │
│                                                                 │
│  httpcloak passes Layers 1-3                                    │
│  Layer 4 requires actual browser or specialized tools           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### How httpcloak Solves This

httpcloak uses **[uTLS](https://github.com/refraction-networking/utls)** to perfectly mimic browser TLS handshakes, combined with:

- Correct HTTP/2 SETTINGS, WINDOW_UPDATE, and PRIORITY frames
- Browser-accurate header ordering (`:method`, `:authority`, `:scheme`, `:path` pseudo-headers)
- Proper Sec-Fetch-* headers for navigation vs CORS requests
- Client Hints (Sec-Ch-Ua-*) matching the spoofed browser
- Organic jitter in quality values to match real browser behavior

The result: requests are **cryptographically indistinguishable** from a real Chrome browser.

## Installation

```bash
go get github.com/sardanioss/httpcloak
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/sardanioss/httpcloak/client"
)

func main() {
    // Create client with Chrome 143 fingerprint
    c := client.NewClient("chrome-143")
    defer c.Close()

    // Make a request - looks exactly like Chrome to the server
    resp, err := c.Get(context.Background(), "https://example.com", nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %d\n", resp.StatusCode)
    fmt.Printf("Protocol: %s\n", resp.Protocol) // "h2" or "h3"
    fmt.Println(resp.Text())
}
```

## How TLS Fingerprinting Works

When your client connects to a server over HTTPS, the TLS handshake exposes identifying information:

```
┌──────────────────────────────────────────────────────────────────┐
│                      TLS CLIENT HELLO                            │
├──────────────────────────────────────────────────────────────────┤
│ TLS Version: 1.3                                                 │
│                                                                  │
│ Cipher Suites (ordered list):                                    │
│   TLS_AES_128_GCM_SHA256                                         │
│   TLS_AES_256_GCM_SHA384                                         │
│   TLS_CHACHA20_POLY1305_SHA256                                   │
│   TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256                        │
│   ... (16 total for Chrome, 13 for Go)                           │
│                                                                  │
│ Extensions (ordered list):                                       │
│   server_name (SNI)                                              │
│   extended_master_secret                                         │
│   signature_algorithms                                           │
│   supported_versions                                             │
│   psk_key_exchange_modes                                         │
│   key_share (with X25519MLKEM768 for Chrome 131+)                │
│   application_layer_protocol_negotiation                         │
│   ... (18 total for Chrome, 12 for Go)                           │
│                                                                  │
│ Supported Groups (elliptic curves):                              │
│   X25519MLKEM768 (post-quantum, Chrome 131+)                     │
│   X25519                                                         │
│   P-256                                                          │
│   P-384                                                          │
├──────────────────────────────────────────────────────────────────┤
│                             ↓                                    │
│                   JA3/JA4 Fingerprint                            │
│                             ↓                                    │
│            Server knows you're Go, not Chrome                    │
└──────────────────────────────────────────────────────────────────┘
```

**JA3** hashes these fields into a fingerprint. **JA4** is the newer standard with more detail. Bot detection services maintain databases of fingerprints for every browser version and known bot libraries.

## How HTTP/2 Fingerprinting Works

After TLS, the HTTP/2 connection also has a fingerprint based on the SETTINGS frame:

```
┌──────────────────────────────────────────────────────────────────┐
│                    HTTP/2 SETTINGS FRAME                         │
├──────────────────────────────────────────────────────────────────┤
│ Go stdlib                      │ Chrome (httpcloak)              │
├────────────────────────────────┼─────────────────────────────────┤
│ HEADER_TABLE_SIZE: 4096        │ HEADER_TABLE_SIZE: 65536        │
│ ENABLE_PUSH: 1                 │ ENABLE_PUSH: 0                  │
│ MAX_CONCURRENT_STREAMS: 250    │ MAX_CONCURRENT_STREAMS: 1000    │
│ INITIAL_WINDOW_SIZE: 65535     │ INITIAL_WINDOW_SIZE: 6291456    │
│ MAX_FRAME_SIZE: 16384          │ MAX_FRAME_SIZE: 16384           │
│ MAX_HEADER_LIST_SIZE: 10485760 │ MAX_HEADER_LIST_SIZE: 262144    │
└──────────────────────────────────────────────────────────────────┘
```

These settings are hashed into the **Akamai fingerprint**. httpcloak sends the exact values Chrome uses.

## Features

### Browser Fingerprints
- **TLS Fingerprinting**: JA3/JA4 fingerprints match real Chrome/Firefox
- **HTTP/2 Fingerprinting**: SETTINGS, WINDOW_UPDATE, PRIORITY frames match browsers
- **HTTP/3 Support**: QUIC with proper fingerprinting (auto-fallback to HTTP/2)
- **Client Hints**: Sec-Ch-Ua-* headers matching the spoofed browser
- **Header Coherence**: Sec-Fetch-* headers are always consistent

### HTTP Features
- **Connection Pooling**: Efficient connection reuse with HTTP/2 multiplexing
- **Session Management**: Cookie jar for persistent sessions (like `requests.Session()`)
- **Automatic Decompression**: gzip, brotli, zstd
- **Redirect Following**: Configurable, with history tracking
- **Retry with Backoff**: Exponential backoff with jitter
- **Proxy Support**: HTTP, HTTPS, SOCKS5 proxies
- **Authentication**: Basic, Bearer, Digest auth

### Request Modes
- **Navigate Mode**: Simulates user-initiated navigation (Sec-Fetch-Mode: navigate)
- **CORS Mode**: Simulates JavaScript fetch() call (Sec-Fetch-Mode: cors)
- **Organic Jitter**: Random header variations to match real browser inconsistencies

## Available Presets

| Preset | Browser | TLS | HTTP/2 | HTTP/3 |
|--------|---------|-----|--------|--------|
| `chrome-143` | Chrome 143 | X25519MLKEM768 | ✓ | ✓ |
| `chrome-143-windows` | Chrome 143 (Windows) | X25519MLKEM768 | ✓ | ✓ |
| `chrome-141` | Chrome 141 | X25519MLKEM768 | ✓ | ✓ |
| `chrome-133` | Chrome 133 | X25519MLKEM768 | ✓ | ✓ |
| `chrome-131` | Chrome 131 | X25519MLKEM768 | ✓ | ✓ |
| `firefox-133` | Firefox 133 | X25519 | ✓ | ✗ |
| `safari-18` | Safari 18 | X25519 | ✓ | ✗ |

Presets auto-adapt to your OS (Windows/macOS/Linux) for User-Agent and Sec-Ch-Ua-Platform.

## Usage Examples

### Simple GET Request

```go
c := client.NewClient("chrome-143")
defer c.Close()

resp, err := c.Get(ctx, "https://api.example.com/data", nil)
if err != nil {
    log.Fatal(err)
}

fmt.Println(resp.Text())
```

### Session with Cookies

```go
// NewSession automatically persists cookies between requests
session := client.NewSession("chrome-143")
defer session.Close()

// Login - cookies are saved
session.Post(ctx, "https://example.com/login",
    []byte(`{"user":"test","pass":"secret"}`),
    map[string]string{"Content-Type": "application/json"})

// Subsequent requests include cookies automatically
resp, _ := session.Get(ctx, "https://example.com/dashboard", nil)
```

### API Request (CORS Mode)

```go
c := client.NewClient("chrome-143")
defer c.Close()

resp, err := c.Do(ctx, &client.Request{
    Method:    "POST",
    URL:       "https://api.example.com/graphql",
    Body:      []byte(`{"query": "{ user { name } }"}`),
    FetchMode: client.FetchModeCORS,  // Simulates fetch() call
    Referer:   "https://app.example.com/",
    Headers: map[string]string{
        "Content-Type": "application/json",
    },
})
```

### With Proxy

```go
c := client.NewClient("chrome-143",
    client.WithProxy("http://user:pass@proxy.example.com:8080"),
    client.WithTimeout(60*time.Second),
)
defer c.Close()
```

### With Retry

```go
c := client.NewClient("chrome-143",
    client.WithRetry(3),  // Retry up to 3 times on 429, 500, 502, 503, 504
)
defer c.Close()
```

### Force Protocol

```go
// Force HTTP/2 (skip HTTP/3 attempt)
resp, err := c.Do(ctx, &client.Request{
    Method:        "GET",
    URL:           "https://example.com",
    ForceProtocol: client.ProtocolHTTP2,
})

// Force HTTP/3
resp, err := c.Do(ctx, &client.Request{
    Method:        "GET",
    URL:           "https://example.com",
    ForceProtocol: client.ProtocolHTTP3,
})
```

## Examples

The `examples/` directory contains runnable examples:

```bash
# Basic usage - GET, POST, headers, timeout, redirects, retry, SSL, protocols
go run examples/basic/main.go

# Session management - cookies, login flow, cookie inspection
go run examples/session/main.go

# Cloudflare trace - multiple requests, protocol comparison
go run examples/cloudflare/main.go
```

## Architecture

```
httpcloak/
├── httpcloak.go       # High-level public API
├── client/
│   ├── client.go      # HTTP client with fingerprint spoofing
│   ├── options.go     # Configuration options
│   ├── cookie.go      # Cookie handling
│   ├── cookiejar.go   # Cookie jar implementation
│   ├── auth.go        # Authentication (Basic, Bearer, Digest)
│   ├── multipart.go   # Multipart form data
│   ├── stream.go      # SSE/streaming support
│   ├── url.go         # URL building utilities
│   ├── helpers.go     # Utility functions
│   └── http3_client.go # HTTP/3 client implementation
├── fingerprint/
│   └── presets.go     # Browser fingerprint definitions (TLS + HTTP/2)
├── transport/
│   ├── transport.go   # Transport layer abstraction
│   ├── http2_transport.go  # HTTP/2 with custom TLS
│   ├── http3_transport.go  # HTTP/3 (QUIC)
│   └── http2_custom.go     # Custom HTTP/2 framing
├── pool/
│   ├── pool.go        # Connection pool for HTTP/2
│   └── quic_pool.go   # Connection pool for HTTP/3
├── dns/
│   └── cache.go       # DNS caching
├── session/
│   ├── session.go     # Session management
│   └── manager.go     # Session manager
├── protocol/
│   └── types.go       # IPC protocol types for multi-language support
└── cmd/
    └── httpcloak-daemon/
        ├── main.go    # IPC daemon for Python/Node.js/Ruby SDKs
        └── ipc_test.go # Comprehensive IPC tests
```

## Multi-Language Support (IPC Daemon)

httpcloak includes an IPC daemon for use from **any programming language** via JSON over stdin/stdout.

```bash
# Build the daemon
go build -o httpcloak-daemon ./cmd/httpcloak-daemon/

# Simple request
echo '{"id":"1","type":"request","method":"GET","url":"https://example.com"}' | ./httpcloak-daemon
```

### Message Types

| Type | Description |
|------|-------------|
| `ping` | Health check |
| `preset.list` | List available browser presets |
| `session.create` | Create session with cookies |
| `session.close` / `session.list` | Manage sessions |
| `request` | Make HTTP request |
| `cookie.get` / `cookie.set` / `cookie.clear` / `cookie.all` | Cookie management |

### Example: Python

```python
import subprocess, json

proc = subprocess.Popen(['./httpcloak-daemon'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

def send(msg):
    proc.stdin.write(json.dumps(msg) + '\n')
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())

# Create session with Chrome 143 fingerprint
session = send({"id": "1", "type": "session.create", "options": {"preset": "chrome-143"}})

# Make request
resp = send({"id": "2", "type": "request", "session": session["session"], "method": "GET", "url": "https://example.com"})
print(f"Status: {resp['status']}, Protocol: {resp['protocol']}")
```

### Request Options

```json
{
    "id": "1", "type": "request", "session": "session-123",
    "method": "POST", "url": "https://api.example.com/data",
    "headers": {"Content-Type": "application/json"},
    "body": "{\"key\": \"value\"}",
    "options": {
        "timeout": 30000, "followRedirects": true, "forceProtocol": "h2",
        "fetchMode": "cors", "referer": "https://example.com/",
        "proxy": "http://user:pass@proxy:8080",
        "auth": {"type": "bearer", "token": "your-token"}
    }
}
```

### Future SDKs

| Language | Status |
|----------|--------|
| Go | ✅ `github.com/sardanioss/httpcloak` |
| Python | 🔜 Planned |
| Node.js | 🔜 Planned |

## Testing

Run the TLS fingerprint comparison test to verify httpcloak produces different fingerprints than Go's stdlib:

```bash
go test -v ./client -run TestTLSFingerprint_Comparison
```

This test:
1. Fetches `https://tls.peet.ws/api/all` with Go's `net/http`
2. Fetches the same URL with httpcloak
3. Compares JA3, JA4, and Akamai fingerprints
4. Asserts they are different (proving the fingerprint spoofing works)

## Comparison with Other Libraries

| Feature | net/http | resty | httpcloak |
|---------|----------|-------|-----------|
| TLS Fingerprint Spoofing | ✗ | ✗ | ✓ |
| HTTP/2 Fingerprint Spoofing | ✗ | ✗ | ✓ |
| HTTP/3 Support | ✗ | ✗ | ✓ |
| Browser-like Headers | ✗ | ✗ | ✓ |
| Connection Pooling | ✓ | ✓ | ✓ |
| Cookie Jar | ✓ | ✓ | ✓ |
| Bypasses Bot Detection | ✗ | ✗ | ✓ |

## Security Considerations

This lib is not specifically created to **bypass cloudflare** or other similar bot detection tools but mainly was created for implementing a transport layer identical to the ones is used by present in all modern browsers.

This library is intended for:
- Web scraping where you have permission
- Automated testing of your own services
- Research and security analysis
- Bypassing overly aggressive bot detection on legitimate use

**Do not use for**:
- Unauthorized access to systems
- Circumventing security for malicious purposes
- Violating terms of service

## License

MIT

## Credits

- [uTLS](https://github.com/refraction-networking/utls) - TLS fingerprint spoofing
- [quic-go](https://github.com/quic-go/quic-go) - HTTP/3 implementation
- [tls.peet.ws](https://tls.peet.ws) - TLS fingerprint analysis

## AI Assistance Note

I used claude code mainly to write code and a lot of it is written with its help. Just wanted to add this info, Thank you!
