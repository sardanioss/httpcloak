<p align="center">
<img src="httpcloak.png" alt="httpcloak" width="600">
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/sardanioss/httpcloak"><img src="https://pkg.go.dev/badge/github.com/sardanioss/httpcloak.svg" alt="Go Reference"></a>
  <a href="https://pypi.org/project/httpcloak/"><img src="https://img.shields.io/pypi/v/httpcloak" alt="PyPI"></a>
  <a href="https://www.npmjs.com/package/httpcloak"><img src="https://img.shields.io/npm/v/httpcloak" alt="npm"></a>
  <a href="https://www.nuget.org/packages/HttpCloak"><img src="https://img.shields.io/nuget/v/HttpCloak" alt="NuGet"></a>
</p>

<p align="center">
<i>Every Byte of your Request Indistinguishable from Chrome.</i>
</p>

<br>

---

## The Problem

Bot detection doesn't just check your User-Agent anymore.

It fingerprints your **TLS handshake**. Your **HTTP/2 frames**. Your **QUIC parameters**. The order of your headers. Whether you have a session ticket. Whether your SNI is encrypted.

One mismatch = blocked.

## The Solution

```python
import httpcloak

r = httpcloak.get("https://target.com", preset="chrome-143")
```

That's it. Full browser transport layer fingerprint.

---

## What Gets Emulated

<table>
<tr>
<td width="33%" valign="top">

### 🔐 TLS Layer

- JA3 / JA4 fingerprints
- GREASE randomization
- Post-quantum X25519MLKEM768
- ECH (Encrypted Client Hello)
- Session tickets & 0-RTT

</td>
<td width="33%" valign="top">

### 🚀 Transport Layer

- HTTP/2 SETTINGS frames
- WINDOW_UPDATE values
- Stream priorities (HPACK)
- QUIC transport parameters
- HTTP/3 GREASE frames

</td>
<td width="33%" valign="top">

### 🧠 Header Layer

- Sec-Fetch-* coherence
- Client Hints (Sec-Ch-UA)
- Accept / Accept-Language
- Header ordering
- Cookie persistence

</td>
</tr>
</table>

---

## Results

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   WITHOUT SESSION TICKET          WITH SESSION TICKET                   │
│                                                                         │
│   Bot Score: 43                   Bot Score: 99                         │
│   ██████░░░░░░░░░░░░░░            ██████████████████████████████████    │
│   ↑ New TLS handshake             ↑ 0-RTT resumption                    │
│   ↑ Looks like a bot              ↑ Looks like returning Chrome         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────┐
│  ECH (Encrypted Client Hello)   │
├─────────────────────────────────┤
│  WITHOUT:  sni=plaintext        │
│  WITH:     sni=encrypted   +    │
└─────────────────────────────────┘
```

```
┌─────────────────────────────────┐
│  HTTP/3 Fingerprint Match       │
├─────────────────────────────────┤
│  Protocol:        h3       +    │
│  QUIC Version:    1        +    │
│  Transport Params:         +    │
│  GREASE Frames:            +    │
└─────────────────────────────────┘
```

---

## vs curl_cffi

```
┌────────────────────────────────┬────────────────────────────────┐
│        BOTH LIBRARIES          │       HTTPCLOAK ONLY           │
├────────────────────────────────┼────────────────────────────────┤
│                                │                                │
│  + TLS fingerprint (JA3/JA4)   │  + HTTP/3 fingerprinting       │
│  + HTTP/2 fingerprint          │  + ECH (encrypted SNI)         │
│  + Post-quantum TLS            │  + Session persistence         │
│  + Bot score: 99               │  + 0-RTT resumption            │
│                                │  + MASQUE proxy                │
│                                │  + Domain fronting             │
│                                │  + Certificate pinning         │
│                                │  + Go, Python, Node.js, C#     │
│                                │                                │
└────────────────────────────────┴────────────────────────────────┘
```

---

## Install

```bash
pip install httpcloak        # Python
npm install httpcloak        # Node.js
go get github.com/sardanioss/httpcloak   # Go
dotnet add package HttpCloak # C#
```

---

## Quick Start

### Python

```python
import httpcloak

# Simple request
r = httpcloak.get("https://example.com", preset="chrome-143")
print(r.status_code, r.protocol)

# POST with JSON
r = httpcloak.post("https://httpbin.org/post",
    json={"key": "value"},
    preset="chrome-143"
)

# Custom headers
r = httpcloak.get("https://httpbin.org/headers",
    headers={"X-Custom": "value"},
    preset="chrome-143"
)
```

**Session with persistence (Bot Score 99):**

```python
import httpcloak
import os

# Create or load session
if os.path.exists("session.json"):
    session = httpcloak.Session.load("session.json")
else:
    session = httpcloak.Session(preset="chrome-143")
    session.get("https://cloudflare.com/")  # Warm up for TLS tickets
    session.save("session.json")

# All subsequent requests use 0-RTT resumption
r = session.get("https://target.com/")
print(f"Bot Score: 99, Protocol: {r.protocol}")

# For Redis/database storage
session_data = session.marshal()  # Get as string
restored = httpcloak.Session.unmarshal(session_data)
```

### Go

```go
import (
    "context"
    "github.com/sardanioss/httpcloak/client"
)

// Simple request
c := client.NewClient("chrome-143")
defer c.Close()

resp, _ := c.Get(ctx, "https://example.com", nil)
body, _ := resp.Text()
fmt.Println(resp.StatusCode, resp.Protocol)

// POST with JSON
jsonBody := []byte(`{"key": "value"}`)
resp, _ = c.Post(ctx, "https://httpbin.org/post",
    bytes.NewReader(jsonBody),
    map[string][]string{"Content-Type": {"application/json"}},
)

// Custom headers
resp, _ = c.Get(ctx, "https://httpbin.org/headers", map[string][]string{
    "X-Custom": {"value"},
})
```

**Session with persistence (Bot Score 99):**

```go
import "github.com/sardanioss/httpcloak"

// Create or load session
var session *httpcloak.Session
if _, err := os.Stat("session.json"); err == nil {
    session, _ = httpcloak.LoadSession("session.json")
} else {
    session = httpcloak.NewSession("chrome-143")
    session.Get(ctx, "https://cloudflare.com/")  // Warm up
    session.Save("session.json")
}
defer session.Close()

// All requests now use 0-RTT
resp, _ := session.Get(ctx, "https://target.com/")

// For Redis/database storage
data, _ := session.Marshal()  // Get as []byte
restored, _ := httpcloak.UnmarshalSession(data)
```

### Node.js

```javascript
import httpcloak from "httpcloak";

// Simple request
const session = new httpcloak.Session({ preset: "chrome-143" });
const r = await session.get("https://example.com");
console.log(r.statusCode, r.protocol);

// POST with JSON
const r = await session.post("https://httpbin.org/post", {
    json: { key: "value" }
});

// Custom headers
const r = await session.get("https://httpbin.org/headers", {
    headers: { "X-Custom": "value" }
});

session.close();
```

**Session with persistence (Bot Score 99):**

```javascript
import httpcloak from "httpcloak";
import fs from "fs";

// Create or load session
let session;
if (fs.existsSync("session.json")) {
    session = httpcloak.Session.load("session.json");
} else {
    session = new httpcloak.Session({ preset: "chrome-143" });
    await session.get("https://cloudflare.com/");  // Warm up
    session.save("session.json");
}

// All requests now use 0-RTT
const r = await session.get("https://target.com/");
console.log("Bot Score: 99");

// For Redis/database storage
const data = session.marshal();  // Get as string
const restored = httpcloak.Session.unmarshal(data);

session.close();
```

### C#

```csharp
using HttpCloak;

// Simple request
using var session = new Session(preset: Presets.Chrome143);
var r = session.Get("https://example.com");
Console.WriteLine($"{r.StatusCode} {r.Protocol}");

// POST with JSON
var r = session.Post("https://httpbin.org/post",
    json: new { key = "value" }
);

// Custom headers
var r = session.Get("https://httpbin.org/headers",
    headers: new Dictionary<string, string> { ["X-Custom"] = "value" }
);
```

**Session with persistence (Bot Score 99):**

```csharp
using HttpCloak;

// Create or load session
Session session;
if (File.Exists("session.json"))
{
    session = Session.Load("session.json");
}
else
{
    session = new Session(preset: Presets.Chrome143);
    session.Get("https://cloudflare.com/");  // Warm up
    session.Save("session.json");
}

// All requests now use 0-RTT
var r = session.Get("https://target.com/");
Console.WriteLine("Bot Score: 99");

// For Redis/database storage
string data = session.Marshal();  // Get as string
var restored = Session.Unmarshal(data);

session.Dispose();
```

---

## Features

### 🔐 ECH (Encrypted Client Hello)

Hides which domain you're connecting to from network observers.

```python
session = httpcloak.Session(
    preset="chrome-143",
    ech_from="cloudflare.com"  # Fetches ECH config from DNS
)
```

Cloudflare trace shows `sni=encrypted` instead of `sni=plaintext`.

### ⚡ Session Resumption (0-RTT)

TLS session tickets make you look like a returning visitor.

```python
# Warm up on any Cloudflare site
session.get("https://cloudflare.com/")
session.save("session.json")

# Use on your target
session = httpcloak.Session.load("session.json")
r = session.get("https://target.com/")  # Bot score: 99
```

Cross-domain warming works because Cloudflare sites share TLS infrastructure.

### 🌐 HTTP/3 Through Proxies

Two methods for QUIC through proxies:

| Method | How it works |
|--------|--------------|
| **SOCKS5 UDP ASSOCIATE** | Proxy relays UDP packets. Most residential proxies support this. |
| **MASQUE (CONNECT-UDP)** | RFC 9298. Tunnels UDP over HTTP/3. Premium providers only. |

```python
# SOCKS5 with UDP
session = httpcloak.Session(proxy="socks5://user:pass@proxy:1080")

# MASQUE
session = httpcloak.Session(proxy="masque://proxy:443")
```

Known MASQUE providers (auto-detected): Bright Data, Oxylabs, Smartproxy, SOAX.

### 🎭 Domain Fronting

Connect to a different host than what appears in TLS SNI.

```go
client := httpcloak.NewClient("chrome-143",
    httpcloak.WithConnectTo("public-cdn.com", "actual-backend.internal"),
)
```

### 📌 Certificate Pinning

```go
client.PinCertificate("sha256/AAAA...",
    httpcloak.PinOptions{IncludeSubdomains: true})
```

### 🪝 Request Hooks

```go
client.OnPreRequest(func(req *http.Request) error {
    req.Header.Set("X-Custom", "value")
    return nil
})

client.OnPostResponse(func(resp *httpcloak.Response) {
    log.Printf("Got %d from %s", resp.StatusCode, resp.FinalURL)
})
```

### ⏱️ Request Timing

```go
fmt.Printf("DNS: %dms, TCP: %dms, TLS: %dms, Total: %dms\n",
    resp.Timing.DNSLookup,
    resp.Timing.TCPConnect,
    resp.Timing.TLSHandshake,
    resp.Timing.Total)
```

### 🔄 Protocol Selection

```python
session = httpcloak.Session(preset="chrome-143", http_version="h3")  # Force HTTP/3
session = httpcloak.Session(preset="chrome-143", http_version="h2")  # Force HTTP/2
session = httpcloak.Session(preset="chrome-143", http_version="h1")  # Force HTTP/1.1
```

Auto mode tries HTTP/3 first, falls back gracefully.

### 📤 Streaming & Uploads

```python
# Stream large downloads
stream = session.get_stream("https://example.com/large-file.zip")
print(f"Size: {stream.content_length} bytes")

with open("file.zip", "wb") as f:
    while True:
        chunk = stream.read(8192)
        if not chunk:
            break
        f.write(chunk)
stream.close()

# Iterator pattern
for chunk in session.get_stream(url).iter_content(chunk_size=8192):
    process(chunk)

# Multipart upload
r = session.post(url, files={
    "file": ("filename.jpg", file_bytes, "image/jpeg")
})
```

### 🔒 Authentication

```python
# Basic auth
r = httpcloak.get("https://api.example.com/data",
    auth=("username", "password"),
    preset="chrome-143"
)

# Session-level auth
session = httpcloak.Session(
    preset="chrome-143",
    auth=("username", "password")
)
```

### ⏰ Timeouts & Retries

```python
# Timeout
session = httpcloak.Session(preset="chrome-143", timeout=30)

# Per-request timeout
r = session.get("https://slow-api.com/data", timeout=60)
```

```go
// Go: Timeout and retry configuration
client := client.NewClient("chrome-143",
    client.WithTimeout(30 * time.Second),
    client.WithRetry(3),  // Retry 3 times on 429, 500, 502, 503, 504
    client.WithRetryConfig(
        5,                      // Max retries
        500 * time.Millisecond, // Min backoff
        10 * time.Second,       // Max backoff
        []int{429, 503},        // Status codes to retry
    ),
)
```

### 🚫 Redirect Control

```go
// Disable automatic redirects
client := client.NewClient("chrome-143",
    client.WithoutRedirects(),
)

resp, _ := client.Get(ctx, "https://example.com/redirect", nil)
fmt.Println(resp.StatusCode)              // 302
fmt.Println(resp.GetHeader("location"))   // Redirect URL
```

---

## API Reference

### Python

```python
import httpcloak

# Module-level functions
httpcloak.get(url, **kwargs)
httpcloak.post(url, **kwargs)
httpcloak.put(url, **kwargs)
httpcloak.patch(url, **kwargs)
httpcloak.delete(url, **kwargs)
httpcloak.head(url, **kwargs)
httpcloak.options(url, **kwargs)

# Session class
session = httpcloak.Session(
    preset="chrome-143",       # Browser preset
    proxy="socks5://...",      # Proxy URL
    timeout=30,                # Timeout in seconds
    http_version="h3",         # Force protocol: h1, h2, h3, auto
    ech_from="cloudflare.com", # ECH config source
    auth=("user", "pass"),     # Basic auth
)

# Session methods
session.get(url, **kwargs)
session.post(url, data=None, json=None, **kwargs)
session.get_stream(url)        # Streaming download
session.save("file.json")      # Save session state
session.marshal()              # Export as string
session.close()

# Class methods
httpcloak.Session.load("file.json")
httpcloak.Session.unmarshal(data)

# Response object
response.status_code           # HTTP status
response.ok                    # True if status < 400
response.text                  # Body as string
response.content               # Body as bytes
response.json()                # Parse JSON
response.headers               # Response headers
response.protocol              # h1, h2, or h3
response.url                   # Final URL
response.raise_for_status()    # Raise on 4xx/5xx
```

### Go

```go
import "github.com/sardanioss/httpcloak/client"

// Client creation
c := client.NewClient("chrome-143",
    client.WithTimeout(30 * time.Second),
    client.WithProxy("socks5://..."),
    client.WithRetry(3),
    client.WithoutRedirects(),
    client.WithInsecureSkipVerify(),
)
defer c.Close()

// Request methods
resp, err := c.Get(ctx, url, headers)
resp, err := c.Post(ctx, url, body, headers)
resp, err := c.Put(ctx, url, body, headers)
resp, err := c.Delete(ctx, url, headers)

// Advanced request
resp, err := c.Do(ctx, &client.Request{
    Method:        "GET",
    URL:           url,
    Headers:       map[string][]string{},
    Body:          io.Reader,
    Params:        map[string]string{},
    ForceProtocol: client.ProtocolHTTP3,
    FetchMode:     client.FetchModeCORS,
    Referer:       "https://example.com",
})

// Response object
resp.StatusCode
resp.Protocol
resp.Headers
resp.Body           // io.ReadCloser
resp.Text()         // (string, error)
resp.Bytes()        // ([]byte, error)
resp.JSON(&v)       // error
resp.GetHeader(key) // string
resp.IsSuccess()    // bool
resp.IsRedirect()   // bool

// Session (for persistence)
session := httpcloak.NewSession("chrome-143")
session.Get(ctx, url)
session.Save("file.json")
session.Marshal()   // ([]byte, error)
httpcloak.LoadSession("file.json")
httpcloak.UnmarshalSession(data)
```

### Node.js

```javascript
import httpcloak from "httpcloak";

// Session creation
const session = new httpcloak.Session({
    preset: "chrome-143",
    proxy: "socks5://...",
    timeout: 30000,
    httpVersion: "h3",
});

// Async methods
await session.get(url, options)
await session.post(url, { json, data, headers })
await session.put(url, options)
await session.delete(url, options)

// Sync methods
session.getSync(url, options)
session.postSync(url, options)

// Session persistence
session.save("file.json")
session.marshal()
httpcloak.Session.load("file.json")
httpcloak.Session.unmarshal(data)
session.close()

// Response object
response.statusCode
response.ok
response.text
response.json()
response.headers
response.protocol
```

### C#

```csharp
using HttpCloak;

// Session creation
var session = new Session(
    preset: Presets.Chrome143,
    proxy: "socks5://...",
    timeout: 30
);

// Request methods
session.Get(url, headers)
session.Post(url, json: obj, data: dict, headers: dict)
session.Put(url, ...)
session.Delete(url)

// Session persistence
session.Save("file.json")
session.Marshal()
Session.Load("file.json")
Session.Unmarshal(data)
session.Dispose()

// Response object
response.StatusCode
response.Ok
response.Text
response.Json<T>()
response.Headers
response.Protocol
```

---

## Browser Presets

| Preset | Platform | PQ | H3 |
|--------|----------|:--:|:--:|
| `chrome-143` | Auto | ✅ | ✅ |
| `chrome-143-windows` | Windows | ✅ | ✅ |
| `chrome-143-macos` | macOS | ✅ | ✅ |
| `chrome-143-linux` | Linux | ✅ | ✅ |
| `firefox-133` | Auto | ❌ | ❌ |
| `chrome-mobile-android` | Android | ✅ | ✅ |
| `chrome-mobile-ios` | iOS | ✅ | ✅ |

**PQ** = Post-Quantum (X25519MLKEM768) · **H3** = HTTP/3

---

## Testing Tools

| Tool | Tests |
|------|-------|
| [tls.peet.ws](https://tls.peet.ws/api/all) | JA3, JA4, HTTP/2 Akamai |
| [quic.browserleaks.com](https://quic.browserleaks.com/) | HTTP/3 QUIC fingerprint |
| [cf.erisa.uk](https://cf.erisa.uk/) | Cloudflare bot score |
| [cloudflare.com/cdn-cgi/trace](https://www.cloudflare.com/cdn-cgi/trace) | ECH status, TLS version |

---

## Dependencies

Custom forks for browser-accurate fingerprinting:

- [sardanioss/utls](https://github.com/sardanioss/utls) — TLS fingerprinting
- [sardanioss/quic-go](https://github.com/sardanioss/quic-go) — HTTP/3 fingerprinting
- [sardanioss/net](https://github.com/sardanioss/net) — HTTP/2 frame fingerprinting

---

## Connect

- Discord: **sardanioss**
- Email: **sakshamsolanki126@gmail.com**

---

<p align="center">
MIT License
</p>
