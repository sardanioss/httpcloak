# httpcloak

**A comprehensive browser fingerprint emulation library.** Native Go with bindings for Python, Node.js, and C#.

[![Go Reference](https://pkg.go.dev/badge/github.com/sardanioss/httpcloak.svg)](https://pkg.go.dev/github.com/sardanioss/httpcloak)
[![PyPI](https://img.shields.io/pypi/v/httpcloak)](https://pypi.org/project/httpcloak/)
[![npm](https://img.shields.io/npm/v/httpcloak)](https://www.npmjs.com/package/httpcloak)
[![NuGet](https://img.shields.io/nuget/v/HttpCloak)](https://www.nuget.org/packages/HttpCloak)

Modern bot detection fingerprints your TLS handshake, HTTP/2 frames, QUIC parameters, and header patterns. httpcloak makes every layer of your connection indistinguishable from a real browser.

---

## Features at a Glance

| Category | Features |
|----------|----------|
| **TLS Fingerprinting** | JA3/JA4 spoofing, GREASE randomization, post-quantum X25519MLKEM768, ECH (Encrypted Client Hello) |
| **HTTP/2 Fingerprinting** | SETTINGS frames, WINDOW_UPDATE, stream priorities, header compression (HPACK) |
| **HTTP/3 Fingerprinting** | QUIC transport parameters, 0-RTT early data, HTTP/3 GREASE frames |
| **Header Intelligence** | Sec-Fetch-* coherence, Client Hints (Sec-Ch-UA), correct Accept/Accept-Language formatting |
| **Session Management** | Cookie persistence, TLS session tickets, 0-RTT resumption, save/load sessions to disk |
| **Proxy Support** | HTTP, HTTPS, SOCKS5 (with UDP for HTTP/3), MASQUE tunneling |
| **Advanced Features** | Domain fronting, certificate pinning, digest auth, request hooks, multipart uploads |
| **Languages** | Go (native), Python, Node.js, C# |

---

## Why httpcloak?

### Comparison with curl_cffi

Tested against [tls.peet.ws](https://tls.peet.ws/api/all) and [cf.erisa.uk](https://cf.erisa.uk/):

| Feature | curl_cffi | httpcloak |
|---------|-----------|-----------|
| TLS Fingerprint (JA3/JA4) | ✅ Match | ✅ Match |
| HTTP/2 Fingerprint | ✅ Match | ✅ Match |
| Post-Quantum TLS | ✅ | ✅ |
| Cloudflare Bot Score | 99 | 99 |
| **HTTP/3 Fingerprinting** | Paid (impersonate.pro) | **Free** |
| **ECH (Encrypted Client Hello)** | ❌ | ✅ |
| **Session Persistence** | ❌ | ✅ |
| **0-RTT Resumption** | ❌ | ✅ |
| **MASQUE Proxy** | ❌ | ✅ |
| **Domain Fronting** | ❌ | ✅ |
| **Certificate Pinning** | ❌ | ✅ |
| **Languages** | Python only | Go, Python, Node.js, C# |

---

## ECH (Encrypted Client Hello)

ECH encrypts the SNI in your TLS handshake, hiding which domain you're connecting to. This is critical for privacy and can affect bot detection scores on Cloudflare-protected sites.

```python
# Fetch ECH config from Cloudflare and use encrypted SNI
session = httpcloak.Session(
    preset="chrome-143",
    ech_from="cloudflare.com"  # Fetches ECH config automatically
)
r = session.get("https://target-site.com/")
```

When ECH is active, Cloudflare's trace shows `sni=encrypted` instead of `sni=plaintext`.

---

## Session Resumption (0-RTT)

TLS session tickets allow 0-RTT resumption, dramatically improving bot scores:

| Connection Type | Bot Score |
|-----------------|-----------|
| Fresh connection (no ticket) | ~43 |
| With session resumption | ~99 |

```python
# First run - acquire TLS session ticket
session = httpcloak.Session(preset="chrome-143")
session.get("https://cloudflare.com/")  # Warm up
session.save("session.json")

# Later - restore with 0-RTT
session = httpcloak.Session.load("session.json")
r = session.get("https://target.com/")  # Bot score: 99
```

**Cross-domain warming:** Session tickets from `cloudflare.com` work on any Cloudflare-protected site because they share infrastructure.

> **Examples:** [Go](examples/go-examples/session-resumption/main.go) · [Python](examples/python-examples/09_session_resumption.py) · [Node.js](examples/js-examples/11_session_resumption.js) · [C#](examples/csharp-examples/SessionResumption.cs)

---

## Protocol Support

| Protocol | Fingerprinting | Features |
|----------|----------------|----------|
| **HTTP/3** | QUIC transport params, GREASE frames | 0-RTT, multiplexing, no head-of-line blocking |
| **HTTP/2** | SETTINGS, WINDOW_UPDATE, priorities | Multiplexing, header compression |
| **HTTP/1.1** | Header order | Keep-alive, connection pooling |

```python
# Force specific protocol
session = httpcloak.Session(preset="chrome-143", http_version="h3")  # Force HTTP/3
session = httpcloak.Session(preset="chrome-143", http_version="h2")  # Force HTTP/2
session = httpcloak.Session(preset="chrome-143", http_version="h1")  # Force HTTP/1.1
```

Auto mode tries HTTP/3 first, falls back to HTTP/2, then HTTP/1.1.

---

## Browser Presets

| Preset | Platform | Post-Quantum | HTTP/3 | Notes |
|--------|----------|--------------|--------|-------|
| `chrome-143` | Auto-detect | ✅ X25519MLKEM768 | ✅ | Default, latest Chrome |
| `chrome-143-windows` | Windows | ✅ | ✅ | Windows-specific ClientHello |
| `chrome-143-macos` | macOS | ✅ | ✅ | macOS-specific ClientHello |
| `chrome-143-linux` | Linux | ✅ | ✅ | Linux-specific ClientHello |
| `chrome-141` | Auto | ✅ | ✅ | |
| `chrome-133` | Auto | ✅ | ✅ | PSK resumption support |
| `chrome-131` | Auto | ✅ | ✅ | |
| `firefox-133` | Auto | ❌ | ❌ | Firefox fingerprint |
| `chrome-mobile-android` | Android | ✅ | ✅ | Mobile fingerprint |
| `chrome-mobile-ios` | iOS | ✅ | ✅ | Mobile fingerprint |

Each preset includes accurate:
- TLS cipher suites and extensions
- HTTP/2 SETTINGS frame values
- QUIC transport parameters
- Header order and formatting
- Client Hints (Sec-Ch-UA-*)

---

## Header Intelligence

### Sec-Fetch Headers
Automatic coherence between Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, and Sec-Fetch-User:

```python
# Navigation request (like clicking a link)
r = session.get(url, fetch_mode="navigate")
# Sets: Sec-Fetch-Mode: navigate, Sec-Fetch-Dest: document, Sec-Fetch-User: ?1

# API request (like fetch/XHR)
r = session.get(url, fetch_mode="cors")
# Sets: Sec-Fetch-Mode: cors, Sec-Fetch-Dest: empty
```

### Client Hints
Automatic Sec-Ch-UA headers matching the preset:
```
Sec-Ch-UA: "Chromium";v="143", "Google Chrome";v="143", "Not-A.Brand";v="24"
Sec-Ch-UA-Mobile: ?0
Sec-Ch-UA-Platform: "Windows"
```

---

## Proxy Support

### All Proxy Types
```python
# HTTP/HTTPS proxy
session = httpcloak.Session(proxy="http://user:pass@proxy:8080")

# SOCKS5 proxy (supports UDP for HTTP/3)
session = httpcloak.Session(proxy="socks5://user:pass@proxy:1080")

# MASQUE proxy (HTTP/3 tunneling)
session = httpcloak.Session(proxy="masque://proxy:443")
```

### Split Proxy Configuration
Use different proxies for TCP (HTTP/1.1, HTTP/2) and UDP (HTTP/3):

```go
session := httpcloak.NewSession("chrome-143",
    httpcloak.WithSessionTCPProxy("socks5://tcp-proxy:1080"),
    httpcloak.WithSessionUDPProxy("socks5://udp-proxy:1080"),
)
```

### HTTP/3 over SOCKS5
httpcloak supports HTTP/3 (QUIC) through SOCKS5 proxies using UDP ASSOCIATE. Most residential proxies support this.

---

## Advanced Features

### Domain Fronting
Connect to a different host than what appears in the TLS SNI:

```go
client := httpcloak.NewClient("chrome-143",
    httpcloak.WithConnectTo("public-cdn.com", "actual-backend.internal"),
)
// TLS SNI shows "public-cdn.com", but connects to "actual-backend.internal"
```

### Certificate Pinning
Pin certificates using SHA256 SPKI hashes:

```go
client := httpcloak.NewClient("chrome-143")
client.PinCertificate("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    httpcloak.PinOptions{IncludeSubdomains: true})
```

### Request Hooks
Inspect or modify requests and responses:

```go
client.OnPreRequest(func(req *http.Request) error {
    req.Header.Set("X-Custom", "value")
    return nil
})

client.OnPostResponse(func(resp *httpcloak.Response) {
    log.Printf("Got %d from %s", resp.StatusCode, resp.FinalURL)
})
```

### Cookie Challenge Handling
Automatic handling of bot protection that sets cookies on 403/429:

```go
client := httpcloak.NewClient("chrome-143",
    httpcloak.WithRetry(3),  // Automatically retries with cookies
)
```

### Request Timing
Get detailed timing breakdown:

```go
resp, _ := client.Get(ctx, url, nil)
fmt.Printf("DNS: %dms, TCP: %dms, TLS: %dms, FirstByte: %dms, Total: %dms\n",
    resp.Timing.DNSLookup,
    resp.Timing.TCPConnect,
    resp.Timing.TLSHandshake,
    resp.Timing.FirstByte,
    resp.Timing.Total,
)
```

---

## Installation

```bash
go get github.com/sardanioss/httpcloak         # Go
pip install httpcloak                           # Python
npm install httpcloak                           # Node.js
dotnet add package HttpCloak                    # C#
```

---

## Quick Start

<details>
<summary><b>Go</b></summary>

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

    resp, _ := c.Get(context.Background(), "https://example.com", nil)
    text, _ := resp.Text()
    fmt.Println(text)
    fmt.Printf("Protocol: %s\n", resp.Protocol)
}
```

</details>

<details>
<summary><b>Python</b></summary>

```python
import httpcloak

# Simple request
r = httpcloak.get("https://example.com")
print(r.text)
print(f"Protocol: {r.protocol}")

# With session
with httpcloak.Session(preset="chrome-143") as session:
    r = session.get("https://example.com")
```

</details>

<details>
<summary><b>Node.js</b></summary>

```javascript
import httpcloak from "httpcloak";

const r = await httpcloak.get("https://example.com");
console.log(r.text);
console.log(`Protocol: ${r.protocol}`);

// With session
const session = new httpcloak.Session({ preset: "chrome-143" });
const r = await session.get("https://example.com");
session.close();
```

</details>

<details>
<summary><b>C#</b></summary>

```csharp
using HttpCloak;

using var session = new Session(Presets.Chrome143);
var r = session.Get("https://example.com");
Console.WriteLine(r.Text);
Console.WriteLine($"Protocol: {r.Protocol}");
```

</details>

> **More examples:** [Go](examples/go-examples/) · [Python](examples/python-examples/) · [Node.js](examples/js-examples/) · [C#](examples/csharp-examples/)

---

## Authentication

```python
# Basic Auth
r = httpcloak.get(url, auth=("user", "pass"))

# Bearer Token
session.headers["Authorization"] = "Bearer token123"

# Digest Auth (automatic challenge handling)
session = httpcloak.Session(preset="chrome-143", auth=("user", "pass", "digest"))
```

---

## Streaming & Uploads

### Stream Large Downloads
```python
with session.get(url, stream=True) as r:
    for chunk in r.iter_content(chunk_size=8192):
        file.write(chunk)
```

### Multipart File Upload
```python
r = session.post(url, files={
    "file": ("filename.jpg", file_bytes, "image/jpeg")
})
```

---

## Response API

| Property | Go | Python | Node.js | C# |
|----------|-----|--------|---------|-----|
| Status | `resp.StatusCode` | `r.status_code` | `r.statusCode` | `r.StatusCode` |
| Headers | `resp.Headers` | `r.headers` | `r.headers` | `r.Headers` |
| Body | `resp.Text()` | `r.text` | `r.text` | `r.Text` |
| JSON | `resp.JSON(&v)` | `r.json()` | `r.json()` | `r.Json<T>()` |
| Protocol | `resp.Protocol` | `r.protocol` | `r.protocol` | `r.Protocol` |
| Final URL | `resp.FinalURL` | `r.url` | `r.url` | `r.Url` |

---

## Fingerprint Testing Tools

These tools were invaluable for development and testing:

| Tool | What it tests |
|------|---------------|
| [tls.peet.ws](https://tls.peet.ws/api/all) | TLS fingerprint (JA3, JA4), HTTP/2 Akamai fingerprint |
| [quic.browserleaks.com](https://quic.browserleaks.com/) | HTTP/3 QUIC fingerprint analysis |
| [cf.erisa.uk](https://cf.erisa.uk/) | Cloudflare bot score and JA4 detection |
| [cloudflare.com/cdn-cgi/trace](https://www.cloudflare.com/cdn-cgi/trace) | Connection info, TLS version, key exchange, ECH status |

---

## Dependencies

Custom forks for browser-accurate fingerprinting:

| Library | Purpose |
|---------|---------|
| [sardanioss/utls](https://github.com/sardanioss/utls) | TLS fingerprinting with Chrome/Firefox presets |
| [sardanioss/quic-go](https://github.com/sardanioss/quic-go) | HTTP/3 with accurate QUIC fingerprinting |
| [sardanioss/net](https://github.com/sardanioss/net) | HTTP/2 frame fingerprinting |

---

## License

MIT
