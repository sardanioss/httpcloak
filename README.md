# httpcloak

**Browser-identical HTTP client** for Go, Python, Node.js, and C#. Makes your requests indistinguishable from real Chrome/Firefox/Safari browsers.

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://pkg.go.dev/github.com/sardanioss/httpcloak)
[![PyPI](https://img.shields.io/pypi/v/httpcloak?logo=python&logoColor=white)](https://pypi.org/project/httpcloak/)
[![npm](https://img.shields.io/npm/v/httpcloak?logo=npm)](https://www.npmjs.com/package/httpcloak)
[![NuGet](https://img.shields.io/nuget/v/HttpCloak?logo=nuget)](https://www.nuget.org/packages/HttpCloak)

```
Bot Score: 99/100  |  JA4 Fingerprint: MATCH  |  HTTP/2 + HTTP/3  |  Post-Quantum TLS
```

---

## Quick Start

```bash
# Go
go get github.com/sardanioss/httpcloak

# Python
pip install httpcloak

# Node.js
npm install httpcloak

# C# / .NET
dotnet add package HttpCloak
```

<table>
<tr>
<td><b>Go</b></td>
<td><b>Python</b></td>
</tr>
<tr>
<td>

```go
c := client.NewClient("chrome-143")
resp, _ := c.Get(ctx, url, nil)
fmt.Println(resp.Protocol) // "h3"
```

</td>
<td>

```python
import httpcloak
r = httpcloak.get(url)
print(r.protocol)  # "h3"
```

</td>
</tr>
<tr>
<td><b>Node.js</b></td>
<td><b>C#</b></td>
</tr>
<tr>
<td>

```javascript
import httpcloak from "httpcloak";
const r = await httpcloak.get(url);
console.log(r.protocol); // "h3"
```

</td>
<td>

```csharp
using var s = new Session(Presets.Chrome143);
var r = s.Get(url);
Console.WriteLine(r.Protocol); // "h3"
```

</td>
</tr>
</table>

---

## Why httpcloak?

Modern bot detection analyzes the **cryptographic fingerprint** of your connection - not just headers:

| Layer | What's Fingerprinted | Go stdlib | httpcloak |
|-------|---------------------|-----------|-----------|
| TLS | Cipher suites, extensions, curves | Detected | Chrome-identical |
| HTTP/2 | SETTINGS frame, WINDOW_UPDATE, priorities | Detected | Chrome-identical |
| HTTP/3 | QUIC transport parameters | No support | Chrome-identical |
| Headers | Order, format, client hints | Generic | Browser-accurate |

**Result:** Go's `net/http` gets blocked. httpcloak gets through.

---

## Features

### Browser Fingerprinting
Perfect TLS (JA3/JA4), HTTP/2, and HTTP/3 fingerprints matching real browsers.

| | Go | Python | Node.js | C# |
|---|:---:|:---:|:---:|:---:|
| Example | [basic](examples/go-examples/basic/main.go) | [basic](examples/python-examples/01_basic_requests.py) | [basic](examples/js-examples/01_basic_requests.js) | [basic](examples/csharp-examples/BasicExamples.cs) |

### Session Resumption (0-RTT)
TLS session tickets dramatically improve bot scores. First request scores ~43, resumed sessions score ~99.

```python
# Warm up session (acquires TLS ticket)
session.get("https://cloudflare.com/")

# Save for later
session.save("session.json")

# Restore and use - bot score jumps to 99
session = httpcloak.Session.load("session.json")
session.get("https://target-site.com/")  # 0-RTT resumption
```

**Cross-domain warming:** Session tickets from `cloudflare.com` work on any Cloudflare-protected site.

| | Go | Python | Node.js | C# |
|---|:---:|:---:|:---:|:---:|
| Example | [session-resumption](examples/go-examples/session-resumption/main.go) | [session-resumption](examples/python-examples/09_session_resumption.py) | [session-resumption](examples/js-examples/11_session_resumption.js) | [session-resumption](examples/csharp-examples/SessionResumption.cs) |

### HTTP/3 (QUIC)
Full HTTP/3 support with Chrome fingerprinting. Faster connections, 0-RTT, no head-of-line blocking.

| | Go | Python | Node.js | C# |
|---|:---:|:---:|:---:|:---:|
| Example | [cloudflare](examples/go-examples/cloudflare/main.go) | [presets](examples/python-examples/02_configure_and_presets.py) | [presets](examples/js-examples/02_configure_and_presets.js) | [basic](examples/csharp-examples/BasicExamples.cs) |

### Sessions & Cookies
Automatic cookie persistence between requests.

| | Go | Python | Node.js | C# |
|---|:---:|:---:|:---:|:---:|
| Example | [session](examples/go-examples/session/main.go) | [sessions](examples/python-examples/03_sessions_and_cookies.py) | [sessions](examples/js-examples/03_sessions_and_cookies.js) | [basic](examples/csharp-examples/BasicExamples.cs) |

### Streaming
Stream large downloads/uploads without loading everything into memory.

| | Go | Python | Node.js | C# |
|---|:---:|:---:|:---:|:---:|
| Example | [streaming](examples/go-examples/streaming/main.go) | [streaming](examples/python-examples/07_streaming.py) | [streaming](examples/js-examples/09_streaming.js) | - |

### Proxy Support
HTTP, HTTPS, and SOCKS5 proxies. **HTTP/3 over SOCKS5** using UDP ASSOCIATE.

| | Go | Python | Node.js | C# |
|---|:---:|:---:|:---:|:---:|
| Example | [basic](examples/go-examples/basic/main.go) | [proxy](examples/python-examples/04_auth_and_proxy.py) | [proxy](examples/js-examples/04_auth_and_proxy.js) | [basic](examples/csharp-examples/BasicExamples.cs) |

---

## Fingerprint Proof

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FINGERPRINT COMPARISON                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  METRIC                  │ GO STDLIB      │ HTTPCLOAK      │ CHROME 143    │
│  ────────────────────────┼────────────────┼────────────────┼───────────────│
│  TLS Extensions          │ 12             │ 18             │ 18            │
│  GREASE Values           │ None           │ Yes (random)   │ Yes           │
│  Post-Quantum Crypto     │ No             │ X25519MLKEM768 │ X25519MLKEM768│
│  ECH Support             │ No             │ Yes            │ Yes           │
│                          │                │                │               │
│  HTTP/2 WINDOW_SIZE      │ 64KB           │ 6MB            │ 6MB           │
│  HTTP/2 HEADER_TABLE     │ 4,096          │ 65,536         │ 65,536        │
│                          │                │                │               │
│  JA4 Hash                │ t13d1312h2_... │ t13d1516h2_... │ MATCH         │
│  Akamai FP Hash          │ cbcbfae223...  │ 52d84b1173...  │ MATCH         │
│                          │                │                │               │
│  Cloudflare Bot Score    │ ~10            │ ~99            │ ~99           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Available Presets

| Preset | Browser | Post-Quantum | HTTP/2 | HTTP/3 |
|--------|---------|--------------|--------|--------|
| `chrome-143` | Chrome 143 (default) | X25519MLKEM768 | Yes | Yes |
| `chrome-143-windows` | Chrome 143 (Windows) | X25519MLKEM768 | Yes | Yes |
| `chrome-143-linux` | Chrome 143 (Linux) | X25519MLKEM768 | Yes | Yes |
| `chrome-143-macos` | Chrome 143 (macOS) | X25519MLKEM768 | Yes | Yes |
| `chrome-131` | Chrome 131 | X25519MLKEM768 | Yes | Yes |
| `firefox-133` | Firefox 133 | X25519 | Yes | No |
| `safari-18` | Safari 18 | X25519 | Yes | No |
| `chrome-mobile-ios` | Chrome iOS | X25519MLKEM768 | Yes | Yes |
| `chrome-mobile-android` | Chrome Android | X25519MLKEM768 | Yes | Yes |

---

## Usage

### Go

```go
package main

import (
    "context"
    "fmt"
    "github.com/sardanioss/httpcloak/client"
)

func main() {
    c := client.NewClient("chrome-143")
    defer c.Close()

    // GET request
    resp, _ := c.Get(context.Background(), "https://example.com", nil)
    text, _ := resp.Text()
    fmt.Println(text)

    // With options
    c = client.NewClient("chrome-143",
        client.WithProxy("socks5://user:pass@proxy:1080"),
        client.WithTimeout(30*time.Second),
        client.WithRetry(3),
    )
}
```

**More examples:** [Go examples](examples/go-examples/)

### Python

```python
import httpcloak

# Simple request
r = httpcloak.get("https://example.com")
print(r.text)

# Session with cookies
with httpcloak.Session(preset="chrome-143") as session:
    session.get("https://example.com/login")
    r = session.get("https://example.com/dashboard")

# Configure defaults
httpcloak.configure(
    preset="chrome-143",
    proxy="socks5://user:pass@proxy:1080",
    timeout=30,
)
```

**More examples:** [Python examples](examples/python-examples/)

### Node.js

```javascript
import httpcloak from "httpcloak";

// Simple request
const r = await httpcloak.get("https://example.com");
console.log(r.text);

// Session with cookies
const session = new httpcloak.Session({ preset: "chrome-143" });
await session.get("https://example.com/login");
const r = await session.get("https://example.com/dashboard");
session.close();

// Sync methods available
const r = session.getSync("https://example.com");
```

**More examples:** [Node.js examples](examples/js-examples/)

### C# / .NET

```csharp
using HttpCloak;

// Simple request
using var session = new Session(preset: Presets.Chrome143);
var r = session.Get("https://example.com");
Console.WriteLine(r.Text);

// With options
using var session = new Session(
    preset: Presets.Chrome143,
    proxy: "socks5://user:pass@proxy:1080",
    timeout: 30
);

// Async
var r = await session.GetAsync("https://example.com");
```

**More examples:** [C# examples](examples/csharp-examples/)

---

## Response Object

| Property | Go | Python | Node.js | C# |
|----------|-----|--------|---------|-----|
| Status code | `resp.StatusCode` | `r.status_code` | `r.statusCode` | `r.StatusCode` |
| Headers | `resp.Headers` | `r.headers` | `r.headers` | `r.Headers` |
| Body bytes | `resp.Bytes()` | `r.content` | `r.content` | `r.Content` |
| Body text | `resp.Text()` | `r.text` | `r.text` | `r.Text` |
| JSON | `resp.JSON(&v)` | `r.json()` | `r.json()` | `r.Json<T>()` |
| Protocol | `resp.Protocol` | `r.protocol` | `r.protocol` | `r.Protocol` |
| Final URL | `resp.FinalURL` | `r.url` | `r.url` | `r.Url` |

---

## Proxy Support

```
http://host:port
http://user:pass@host:port
socks5://host:port
socks5://user:pass@host:port
```

**HTTP/3 over SOCKS5:** httpcloak supports QUIC through SOCKS5 proxies using UDP ASSOCIATE. Most residential proxies support this.

```python
# HTTP/3 works automatically through SOCKS5
session = httpcloak.Session(
    preset="chrome-143",
    proxy="socks5://user:pass@proxy:1080"
)
r = session.get("https://cloudflare.com")
print(r.protocol)  # "h3" if proxy supports UDP
```

---

## License

MIT

---

## Dependencies

Uses custom forks for browser-accurate fingerprinting:

| Library | Purpose |
|---------|---------|
| [sardanioss/utls](https://github.com/sardanioss/utls) | Chrome TLS fingerprints |
| [sardanioss/quic-go](https://github.com/sardanioss/quic-go) | HTTP/3 with Chrome fingerprinting |
| [sardanioss/net](https://github.com/sardanioss/net) | HTTP/2 frame fingerprinting |
