# httpcloak

**Browser-identical HTTP client** for Go, Python, Node.js, and C#.

[![Go Reference](https://pkg.go.dev/badge/github.com/sardanioss/httpcloak.svg)](https://pkg.go.dev/github.com/sardanioss/httpcloak)
[![PyPI](https://img.shields.io/pypi/v/httpcloak)](https://pypi.org/project/httpcloak/)
[![npm](https://img.shields.io/npm/v/httpcloak)](https://www.npmjs.com/package/httpcloak)
[![NuGet](https://img.shields.io/nuget/v/HttpCloak)](https://www.nuget.org/packages/HttpCloak)

Modern bot detection systems fingerprint your **TLS handshake**, **HTTP/2 frames**, and **QUIC parameters**. Go's standard library gets flagged instantly. httpcloak makes every request look exactly like a real browser.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **TLS Fingerprinting** | JA3, JA4, and Akamai fingerprints identical to real Chrome/Firefox/Safari |
| 🌐 **HTTP/3 (QUIC)** | Full HTTP/3 support with accurate QUIC transport parameters |
| ⚡ **HTTP/2** | Correct SETTINGS frames, WINDOW_UPDATE, PRIORITY, and header compression |
| 🔄 **Session Resumption** | TLS session tickets for 0-RTT connections — bot score jumps from ~43 to ~99 |
| 🔮 **Post-Quantum TLS** | X25519MLKEM768 key exchange (Chrome 131+) |
| 🛡️ **ECH Support** | Encrypted Client Hello for enhanced privacy |
| 🎲 **GREASE** | Random GREASE values matching browser behavior |
| 🍪 **Cookie Management** | Automatic cookie persistence across requests |
| 💾 **Session Persistence** | Save/load sessions with TLS tickets for resumption |
| 🌍 **Proxy Support** | HTTP, HTTPS, SOCKS5 — including HTTP/3 over SOCKS5 UDP |
| 📡 **Streaming** | Stream large uploads/downloads without memory overhead |
| 🗜️ **Auto Decompression** | Handles gzip, brotli, zstd automatically |
| 🔁 **Smart Retries** | Exponential backoff with jitter |
| ↩️ **Redirect Handling** | Configurable redirect following with history |
| 🏊 **Connection Pooling** | Efficient connection reuse across requests |

---

## 📊 Fingerprint Comparison

Tested against [tls.peet.ws](https://tls.peet.ws/api/all) and [cf.erisa.uk](https://cf.erisa.uk/):

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                       curl_cffi vs HTTPCLOAK vs CHROME                       │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  FINGERPRINT MATCH                                                           │
│  ─────────────────────────────────────────────────────────────────────────── │
│  JA4 Hash                │  ✅ Match       │  ✅ Match        │  ✅ Baseline   │
│  Akamai FP Hash          │  ✅ Match       │  ✅ Match        │  ✅ Baseline   │
│  Post-Quantum (MLKEM)    │  ✅ Yes         │  ✅ Yes          │  ✅ Yes        │
│  Cloudflare Bot Score    │  99             │  99              │  99            │
│                                                                              │
│  PROTOCOL SUPPORT                                                            │
│  ─────────────────────────────────────────────────────────────────────────── │
│  HTTP/1.1                │  ✅ Yes         │  ✅ Yes          │  ✅ Yes        │
│  HTTP/2                  │  ✅ Yes         │  ✅ Yes          │  ✅ Yes        │
│  HTTP/3 (QUIC)           │  ❌ No          │  ✅ Yes          │  ✅ Yes        │
│                                                                              │
│  UNIQUE FEATURES                                                             │
│  ─────────────────────────────────────────────────────────────────────────── │
│  Session Persistence     │  ❌ No          │  ✅ Yes          │  ✅ Yes        │
│  0-RTT Resumption        │  ❌ No          │  ✅ Yes          │  ✅ Yes        │
│  ECH Support             │  ❌ No          │  ✅ Yes          │  ✅ Yes        │
│  Languages               │  Python         │  Go/Py/JS/C#     │  -             │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

```bash
go get github.com/sardanioss/httpcloak         # Go
pip install httpcloak                           # Python
npm install httpcloak                           # Node.js
dotnet add package HttpCloak                    # C#
```

---

## 🚀 Quick Start

<details>
<summary><b>Go</b></summary>

```go
import "github.com/sardanioss/httpcloak/client"

c := client.NewClient("chrome-143")
defer c.Close()

resp, _ := c.Get(ctx, "https://example.com", nil)
text, _ := resp.Text()
```

</details>

<details>
<summary><b>Python</b></summary>

```python
import httpcloak

r = httpcloak.get("https://example.com")
print(r.text)

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
```

</details>

> 📁 **More examples:** [Go](examples/go-examples/) · [Python](examples/python-examples/) · [Node.js](examples/js-examples/) · [C#](examples/csharp-examples/)

---

## ⚡ Session Resumption (0-RTT)

TLS session tickets dramatically improve bot detection scores. Without resumption you score ~43, with resumption you score **~99**.

```python
# Warm up session (acquires TLS ticket)
session.get("https://cloudflare.com/")
session.save("session.json")

# Later - restore and use with 0-RTT
session = httpcloak.Session.load("session.json")
session.get("https://target.com/")  # Bot score: 99
```

**🎯 Cross-domain warming:** Session tickets from `cloudflare.com` work on **any** Cloudflare-protected site.

> 📁 **Examples:** [Go](examples/go-examples/session-resumption/main.go) · [Python](examples/python-examples/09_session_resumption.py) · [Node.js](examples/js-examples/11_session_resumption.js) · [C#](examples/csharp-examples/SessionResumption.cs)

---

## 🌐 Proxy Support

Supports HTTP, HTTPS, and SOCKS5 proxies. **Unique feature:** HTTP/3 (QUIC) works through SOCKS5 proxies using UDP ASSOCIATE.

```python
session = httpcloak.Session(
    preset="chrome-143",
    proxy="socks5://user:pass@proxy:1080"
)
r = session.get("https://cloudflare.com")
print(r.protocol)  # "h3" if proxy supports UDP
```

---

## 🎭 Browser Presets

| Preset | Browser | HTTP/2 | HTTP/3 | Post-Quantum |
|--------|---------|:------:|:------:|:------------:|
| `chrome-143` | Chrome 143 | ✅ | ✅ | ✅ |
| `chrome-143-windows` | Chrome 143 (Windows) | ✅ | ✅ | ✅ |
| `chrome-143-macos` | Chrome 143 (macOS) | ✅ | ✅ | ✅ |
| `chrome-143-linux` | Chrome 143 (Linux) | ✅ | ✅ | ✅ |
| `chrome-131` | Chrome 131 | ✅ | ✅ | ✅ |
| `firefox-133` | Firefox 133 | ✅ | ❌ | ❌ |
| `safari-18` | Safari 18 | ✅ | ❌ | ❌ |
| `chrome-mobile-android` | Chrome Android | ✅ | ✅ | ✅ |
| `chrome-mobile-ios` | Chrome iOS | ✅ | ✅ | ✅ |

---

## 📋 Response API

| Property | Go | Python | Node.js | C# |
|----------|-----|--------|---------|-----|
| **Status Code** | `resp.StatusCode` | `r.status_code` | `r.statusCode` | `r.StatusCode` |
| **Headers** | `resp.Headers` | `r.headers` | `r.headers` | `r.Headers` |
| **Body (bytes)** | `resp.Bytes()` | `r.content` | `r.content` | `r.Content` |
| **Body (text)** | `resp.Text()` | `r.text` | `r.text` | `r.Text` |
| **JSON** | `resp.JSON(&v)` | `r.json()` | `r.json()` | `r.Json<T>()` |
| **Protocol** | `resp.Protocol` | `r.protocol` | `r.protocol` | `r.Protocol` |
| **Final URL** | `resp.FinalURL` | `r.url` | `r.url` | `r.Url` |

---

## 🔧 Dependencies

Custom forks for browser-accurate fingerprinting:

| Library | Purpose |
|---------|---------|
| [sardanioss/utls](https://github.com/sardanioss/utls) | TLS fingerprint spoofing with Chrome/Firefox/Safari presets |
| [sardanioss/quic-go](https://github.com/sardanioss/quic-go) | HTTP/3 with accurate QUIC fingerprinting |
| [sardanioss/net](https://github.com/sardanioss/net) | HTTP/2 frame fingerprinting |

---

## 📄 License

MIT

---

## 🧪 Fingerprint Testing Tools

These tools were invaluable for testing and verifying fingerprints:

| Tool | What it tests |
|------|---------------|
| [tls.peet.ws](https://tls.peet.ws/api/all) | TLS fingerprint (JA3, JA4), HTTP/2 Akamai fingerprint |
| [quic.browserleaks.com](https://quic.browserleaks.com/) | HTTP/3 QUIC fingerprint analysis |
| [cf.erisa.uk](https://cf.erisa.uk/) | Cloudflare bot score and JA4 detection |
| [cloudflare.com/cdn-cgi/trace](https://www.cloudflare.com/cdn-cgi/trace) | Connection info, TLS version, key exchange |
