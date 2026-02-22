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

It fingerprints your **TLS handshake**. Your **HTTP/2 frames**. Your **QUIC parameters**. The order of your headers. Whether your SNI is encrypted.

One mismatch = blocked.

## The Solution

```python
import httpcloak

r = httpcloak.get("https://target.com", preset="chrome-latest")
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
│  + Post-quantum TLS            │  + MASQUE proxy                │
│  + Bot score: 99               │  + Domain fronting             │
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
r = httpcloak.get("https://example.com", preset="chrome-145")
print(r.status_code, r.protocol)

# POST with JSON
r = httpcloak.post("https://httpbin.org/post",
    json={"key": "value"},
    preset="chrome-145"
)

# Custom headers
r = httpcloak.get("https://httpbin.org/headers",
    headers={"X-Custom": "value"},
    preset="chrome-145"
)
```

### Go

```go
import (
    "context"
    "github.com/sardanioss/httpcloak/client"
)

// Simple request
c := client.NewClient("chrome-145")
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

### Node.js

```javascript
import httpcloak from "httpcloak";

// Simple request
const session = new httpcloak.Session({ preset: "chrome-145" });
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

### C#

```csharp
using HttpCloak;

// Simple request
using var session = new Session(preset: Presets.Chrome145);
var r = session.Get("https://example.com");
Console.WriteLine($"{r.StatusCode} {r.Protocol}");

// POST with JSON
var r = session.PostJson("https://httpbin.org/post",
    new { key = "value" }
);

// Custom headers
var r = session.Get("https://httpbin.org/headers",
    headers: new Dictionary<string, string> { ["X-Custom"] = "value" }
);
```

---

## Features

### 🔐 ECH (Encrypted Client Hello)

Hides which domain you're connecting to from network observers.

```python
session = httpcloak.Session(
    preset="chrome-145",
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

**Speculative TLS** (opt-in): CONNECT + TLS ClientHello are sent together, saving one proxy round-trip (~25% faster). Enable for compatible proxies:

```python
session = httpcloak.Session(proxy="socks5://...", enable_speculative_tls=True)
```

### 🎭 Domain Fronting

Connect to a different host than what appears in TLS SNI.

```go
client := httpcloak.NewClient("chrome-145",
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
session = httpcloak.Session(preset="chrome-145", http_version="h3")  # Force HTTP/3
session = httpcloak.Session(preset="chrome-145", http_version="h2")  # Force HTTP/2
session = httpcloak.Session(preset="chrome-145", http_version="h1")  # Force HTTP/1.1
```

Auto mode tries HTTP/3 first, falls back gracefully.

### 🔀 Runtime Proxy Switching

Switch proxies mid-session without creating new connections. Perfect for proxy rotation.

```python
session = httpcloak.Session(preset="chrome-145")

# Start with direct connection
r = session.get("https://api.ipify.org")
print(f"Direct IP: {r.text}")

# Switch to proxy 1
session.set_proxy("http://proxy1.example.com:8080")
r = session.get("https://api.ipify.org")
print(f"Proxy 1 IP: {r.text}")

# Switch to proxy 2
session.set_proxy("socks5://proxy2.example.com:1080")
r = session.get("https://api.ipify.org")
print(f"Proxy 2 IP: {r.text}")

# Back to direct
session.set_proxy("")
```

**Split proxy configuration** - use different proxies for HTTP/2 and HTTP/3:

```python
session = httpcloak.Session(preset="chrome-145")

# TCP proxy for HTTP/1.1 and HTTP/2
session.set_tcp_proxy("http://tcp-proxy.example.com:8080")

# UDP proxy for HTTP/3 (requires SOCKS5 UDP ASSOCIATE or MASQUE)
session.set_udp_proxy("socks5://udp-proxy.example.com:1080")

# Check current configuration
print(session.get_tcp_proxy())  # TCP proxy URL
print(session.get_udp_proxy())  # UDP proxy URL
```

### 📋 Header Order Customization

Control the order headers are sent for advanced fingerprinting scenarios.

```python
session = httpcloak.Session(preset="chrome-145")

# Get the current header order (from preset)
print(session.get_header_order())

# Set custom header order
session.set_header_order([
    "accept-language", "sec-ch-ua", "accept",
    "sec-fetch-site", "sec-fetch-mode", "user-agent",
    "sec-ch-ua-platform", "sec-ch-ua-mobile"
])

# Make request with custom order
r = session.get("https://example.com")

# Reset to preset's default order
session.set_header_order([])
```

**JavaScript:**
```javascript
session.setHeaderOrder(["accept-language", "sec-ch-ua", "accept", ...]);
console.log(session.getHeaderOrder());
session.setHeaderOrder([]);  // Reset to default
```

**C#:**
```csharp
session.SetHeaderOrder(new[] { "accept-language", "sec-ch-ua", "accept", ... });
Console.WriteLine(string.Join(", ", session.GetHeaderOrder()));
session.SetHeaderOrder(null);  // Reset to default
```

**Go:**
```go
c.SetHeaderOrder([]string{"accept-language", "sec-ch-ua", "accept", ...})
fmt.Println(c.GetHeaderOrder())
c.SetHeaderOrder(nil)  // Reset to default
```

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
    preset="chrome-145"
)

# Session-level auth
session = httpcloak.Session(
    preset="chrome-145",
    auth=("username", "password")
)
```

### ⏰ Timeouts & Retries

```python
# Timeout
session = httpcloak.Session(preset="chrome-145", timeout=30)

# Per-request timeout
r = session.get("https://slow-api.com/data", timeout=60)
```

```go
// Go: Timeout and retry configuration
client := client.NewClient("chrome-145",
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
client := client.NewClient("chrome-145",
    client.WithoutRedirects(),
)

resp, _ := client.Get(ctx, "https://example.com/redirect", nil)
fmt.Println(resp.StatusCode)              // 302
fmt.Println(resp.GetHeader("location"))   // Redirect URL
```

### 🔃 Refresh (Browser Page Refresh)

Simulates a browser page refresh - closes all TCP/QUIC connections but keeps TLS session cache intact. On next request, connections use TLS resumption (like a real browser).

```python
session = httpcloak.Session(preset="chrome-145")

# Make some requests
session.get("https://example.com/page1")
session.get("https://example.com/page2")

# Simulate browser refresh (F5)
session.refresh()

# Next request uses TLS resumption, looks like returning visitor
session.get("https://example.com/page1")
```

**Go:**
```go
session := httpcloak.NewSession("chrome-145")
session.Get(ctx, "https://example.com")
session.Refresh()  // Close connections, keep TLS cache
session.Get(ctx, "https://example.com")  // TLS resumption
```

**Node.js:**
```javascript
session.refresh();
```

**C#:**
```csharp
session.Refresh();
```

### 🌐 Warmup (Browser Page Load)

Simulates a real browser page load - fetches the HTML page and all its subresources (CSS, JS, images, fonts) with realistic headers, priorities, and timing. After warmup, the session has TLS session tickets, cookies, and cache headers populated.

```python
session = httpcloak.Session(preset="chrome-145")

# Fetches page + subresources with realistic browser behavior
session.warmup("https://example.com")

# Subsequent requests look like follow-up navigation from a real user
r = session.get("https://example.com/api/data")
```

**Go:**
```go
session := httpcloak.NewSession("chrome-145")
session.Warmup(ctx, "https://example.com")
session.Get(ctx, "https://example.com/api/data")  // Looks like real user
```

**Node.js:**
```javascript
session.warmup("https://example.com");
```

**C#:**
```csharp
session.Warmup("https://example.com");
```

### 🔀 Fork (Parallel Browser Tabs)

Creates N sessions that share cookies and TLS session caches with the parent but have independent connections. This simulates multiple browser tabs - same cookies, same TLS resumption tickets, same fingerprint, but independent TCP/QUIC connections for parallel requests.

```python
session = httpcloak.Session(preset="chrome-145")
session.warmup("https://example.com")

# Create 10 parallel "tabs" sharing cookies + TLS cache
tabs = session.fork(10)
for i, tab in enumerate(tabs):
    threading.Thread(
        target=lambda t, n: t.get(f"https://example.com/page/{n}"),
        args=(tab, i)
    ).start()
```

**Go:**
```go
session := httpcloak.NewSession("chrome-145")
session.Warmup(ctx, "https://example.com")

tabs := session.Fork(10)
for i, tab := range tabs {
    go func(t *httpcloak.Session, n int) {
        t.Get(ctx, fmt.Sprintf("https://example.com/page/%d", n))
    }(tab, i)
}
```

**Node.js:**
```javascript
session.warmup("https://example.com");
const tabs = session.fork(10);
await Promise.all(tabs.map((tab, i) => tab.get(`https://example.com/page/${i}`)));
```

**C#:**
```csharp
session.Warmup("https://example.com");
var tabs = session.Fork(10);
await Task.WhenAll(tabs.Select((tab, i) =>
    Task.Run(() => tab.Get($"https://example.com/page/{i}"))
));
```

### 🌍 Local Address Binding

Bind outgoing connections to a specific local IP address. Essential for IPv6 rotation scenarios where you have multiple IPs assigned to your machine.

```python
# Bind to specific IPv6 address
session = httpcloak.Session(
    preset="chrome-145",
    local_address="2001:db8::1"
)

# All requests use this source IP
r = session.get("https://api.ipify.org")
print(r.text)  # Shows 2001:db8::1

# IPv4 works too
session = httpcloak.Session(
    preset="chrome-145",
    local_address="192.168.1.100"
)
```

**Go:**
```go
session := httpcloak.NewSession("chrome-145",
    httpcloak.WithLocalAddress("2001:db8::1"),
)
```

**Node.js:**
```javascript
const session = new httpcloak.Session({
    preset: "chrome-145",
    localAddress: "2001:db8::1"
});
```

**C#:**
```csharp
var session = new Session(
    preset: Presets.Chrome145,
    localAddress: "2001:db8::1"
);
```

**Note:** When a local address is set, target IPs are automatically filtered to match the address family (IPv6 local → only IPv6 targets).

### 🔑 TLS Key Logging

Write TLS session keys to a file for traffic decryption in Wireshark. Works with HTTP/1.1, HTTP/2, and HTTP/3.

```python
session = httpcloak.Session(
    preset="chrome-145",
    key_log_file="/tmp/keys.log"
)

# Make requests - keys written to file
session.get("https://example.com")

# In Wireshark: Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
```

**Go:**
```go
session := httpcloak.NewSession("chrome-145",
    httpcloak.WithKeyLogFile("/tmp/keys.log"),
)
```

**Node.js:**
```javascript
const session = new httpcloak.Session({
    preset: "chrome-145",
    keyLogFile: "/tmp/keys.log"
});
```

**C#:**
```csharp
var session = new Session(
    preset: Presets.Chrome145,
    keyLogFile: "/tmp/keys.log"
);
```

Also supports `SSLKEYLOGFILE` environment variable (standard NSS Key Log Format).

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
    preset="chrome-145",       # Browser preset (default)
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
session.close()

# Proxy switching
session.set_proxy(url)         # Set both TCP and UDP proxy
session.set_tcp_proxy(url)     # Set TCP proxy only (H1/H2)
session.set_udp_proxy(url)     # Set UDP proxy only (H3)
session.get_proxy()            # Get current proxy
session.get_tcp_proxy()        # Get current TCP proxy
session.get_udp_proxy()        # Get current UDP proxy

# Header order customization
session.set_header_order(order)  # Set custom header order (list of lowercase names)
session.get_header_order()       # Get current header order

# Session persistence (0-RTT resumption)
session.save("session.json")   # Save to file
session = Session.load("session.json")  # Load from file
data = session.marshal()       # Export as string
session = Session.unmarshal(data)  # Import from string

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
c := client.NewClient("chrome-145",
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

// Proxy switching
c.SetProxy(url)            // Set both TCP and UDP proxy
c.SetTCPProxy(url)         // Set TCP proxy only (H1/H2)
c.SetUDPProxy(url)         // Set UDP proxy only (H3)
c.GetProxy()               // Get current proxy
c.GetTCPProxy()            // Get current TCP proxy
c.GetUDPProxy()            // Get current UDP proxy

// Session persistence (0-RTT resumption)
c.Save("session.json")     // Save to file
c, _ = client.Load("session.json")  // Load from file
data, _ := c.Marshal()     // Export as string
c, _ = client.Unmarshal(data)  // Import from string

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
```

### Node.js

```javascript
import httpcloak from "httpcloak";

// Session creation
const session = new httpcloak.Session({
    preset: "chrome-145",
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
session.close()

// Proxy switching
session.setProxy(url)          // Set both TCP and UDP proxy
session.setTcpProxy(url)       // Set TCP proxy only (H1/H2)
session.setUdpProxy(url)       // Set UDP proxy only (H3)
session.getProxy()             // Get current proxy
session.getTcpProxy()          // Get current TCP proxy
session.getUdpProxy()          // Get current UDP proxy
session.proxy                  // Property accessor (get/set)

// Session persistence (0-RTT resumption)
session.save("session.json")   // Save to file
session = httpcloak.Session.load("session.json")  // Load from file
const data = session.marshal() // Export as string
session = httpcloak.Session.unmarshal(data)  // Import from string

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
    preset: Presets.Chrome145,
    proxy: "socks5://...",
    timeout: 30
);

// Request methods
session.Get(url, headers)
session.Post(url, body, headers)
session.PostJson<T>(url, data, headers)
session.Put(url, body, headers)
session.Delete(url)
session.Dispose()

// Proxy switching
session.SetProxy(url)          // Set both TCP and UDP proxy
session.SetTcpProxy(url)       // Set TCP proxy only (H1/H2)
session.SetUdpProxy(url)       // Set UDP proxy only (H3)
session.GetProxy()             // Get current proxy
session.GetTcpProxy()          // Get current TCP proxy
session.GetUdpProxy()          // Get current UDP proxy
session.Proxy                  // Property accessor (get/set)

// Session persistence (0-RTT resumption)
session.Save("session.json")   // Save to file
var session = Session.Load("session.json")  // Load from file
var data = session.Marshal()   // Export as string
var session = Session.Unmarshal(data)  // Import from string

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
| `chrome-145` | Auto | ✅ | ✅ |
| `chrome-145-windows` | Windows | ✅ | ✅ |
| `chrome-145-macos` | macOS | ✅ | ✅ |
| `chrome-145-linux` | Linux | ✅ | ✅ |
| `chrome-145-ios` | iOS | ✅ | ✅ |
| `chrome-145-android` | Android | ✅ | ✅ |
| `chrome-144` | Auto | ✅ | ✅ |
| `chrome-144-windows` | Windows | ✅ | ✅ |
| `chrome-144-macos` | macOS | ✅ | ✅ |
| `chrome-144-linux` | Linux | ✅ | ✅ |
| `chrome-143` | Auto | ✅ | ✅ |
| `chrome-143-windows` | Windows | ✅ | ✅ |
| `chrome-143-macos` | macOS | ✅ | ✅ |
| `chrome-143-linux` | Linux | ✅ | ✅ |
| `chrome-141` | Auto | ✅ | ❌ |
| `chrome-133` | Auto | ✅ | ❌ |
| `firefox-133` | Auto | ❌ | ❌ |
| `safari-18` | macOS | ❌ | ✅ |
| `safari-18-ios` | iOS | ❌ | ✅ |
| `safari-17-ios` | iOS | ❌ | ❌ |
| `chrome-145-ios` | iOS | ✅ | ✅ |
| `chrome-144-ios` | iOS | ✅ | ✅ |
| `chrome-143-ios` | iOS | ✅ | ✅ |
| `chrome-145-android` | Android | ✅ | ✅ |
| `chrome-144-android` | Android | ✅ | ✅ |
| `chrome-143-android` | Android | ✅ | ✅ |

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
