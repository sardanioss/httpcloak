<h1 align="center">httpcloak</h1>

<p align="center">
<b>A browser, without the browser.</b>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/sardanioss/httpcloak"><img src="https://pkg.go.dev/badge/github.com/sardanioss/httpcloak.svg" alt="Go Reference"></a>
  <a href="https://pypi.org/project/httpcloak/"><img src="https://img.shields.io/pypi/v/httpcloak" alt="PyPI"></a>
  <a href="https://www.npmjs.com/package/httpcloak"><img src="https://img.shields.io/npm/v/httpcloak" alt="npm"></a>
  <a href="https://www.nuget.org/packages/HttpCloak"><img src="https://img.shields.io/nuget/v/HttpCloak" alt="NuGet"></a>
</p>

<br>

<p align="center">
  <img src="https://img.shields.io/badge/Bot_Score-99-brightgreen?style=for-the-badge" alt="Bot Score 99">
  <img src="https://img.shields.io/badge/HTTP%2F3-Free-blue?style=for-the-badge" alt="HTTP/3 Free">
  <img src="https://img.shields.io/badge/ECH-Encrypted_SNI-purple?style=for-the-badge" alt="ECH">
  <img src="https://img.shields.io/badge/0--RTT-Session_Tickets-orange?style=for-the-badge" alt="0-RTT">
</p>

<br>
<br>

```
██╗  ██╗████████╗████████╗██████╗  ██████╗██╗      ██████╗  █████╗ ██╗  ██╗
██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝
███████║   ██║      ██║   ██████╔╝██║     ██║     ██║   ██║███████║█████╔╝
██╔══██║   ██║      ██║   ██╔═══╝ ██║     ██║     ██║   ██║██╔══██║██╔═██╗
██║  ██║   ██║      ██║   ██║     ╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝      ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

<p align="center">
<i>Every layer. Every frame. Every byte. Indistinguishable from Chrome.</i>
</p>

<br>

---

<br>

## The Problem

Bot detection doesn't just check your User-Agent anymore.

It fingerprints your **TLS handshake**. Your **HTTP/2 frames**. Your **QUIC parameters**. The order of your headers. Whether you have a session ticket. Whether your SNI is encrypted.

One mismatch = blocked.

<br>

## The Solution

```python
import httpcloak

r = httpcloak.get("https://target.com", preset="chrome-143")
```

That's it. Full browser fingerprint. Every layer.

<br>

---

<br>

## What Gets Emulated

<br>

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

<br>

---

<br>

## Proof

<br>

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

<br>

```
┌─────────────────────────────────┐
│  ECH (Encrypted Client Hello)   │
├─────────────────────────────────┤
│  WITHOUT:  sni=plaintext        │
│  WITH:     sni=encrypted  ✓     │
└─────────────────────────────────┘
```

<br>

```
┌─────────────────────────────────┐
│  HTTP/3 Fingerprint Match       │
├─────────────────────────────────┤
│  Protocol:        h3        ✓   │
│  QUIC Version:    1         ✓   │
│  Transport Params:          ✓   │
│  GREASE Frames:             ✓   │
└─────────────────────────────────┘
```

<br>

---

<br>

## vs curl_cffi

```
┌────────────────────────────────┬────────────────────────────────┐
│        BOTH LIBRARIES          │       HTTPCLOAK ONLY           │
├────────────────────────────────┼────────────────────────────────┤
│                                │                                │
│  ✓ TLS fingerprint (JA3/JA4)   │  ✓ HTTP/3 fingerprinting       │
│  ✓ HTTP/2 fingerprint          │  ✓ ECH (encrypted SNI)         │
│  ✓ Post-quantum TLS            │  ✓ Session persistence         │
│  ✓ Bot score: 99               │  ✓ 0-RTT resumption            │
│                                │  ✓ MASQUE proxy                │
│                                │  ✓ Domain fronting             │
│                                │  ✓ Certificate pinning         │
│                                │  ✓ Go, Python, Node.js, C#     │
│                                │                                │
└────────────────────────────────┴────────────────────────────────┘
```

<br>

---

<br>

## Install

```bash
pip install httpcloak        # Python
npm install httpcloak        # Node.js
go get github.com/sardanioss/httpcloak   # Go
dotnet add package HttpCloak # C#
```

<br>

---

<br>

## Quick Start

<details>
<summary><b>Python</b></summary>

```python
import httpcloak

# One-liner
r = httpcloak.get("https://example.com", preset="chrome-143")
print(r.text, r.protocol)

# With session (for 0-RTT)
with httpcloak.Session(preset="chrome-143") as session:
    session.get("https://cloudflare.com/")  # Warm up
    session.save("session.json")

# Later
session = httpcloak.Session.load("session.json")
r = session.get("https://target.com/")  # Bot score: 99
```

</details>

<details>
<summary><b>Go</b></summary>

```go
c := client.NewClient("chrome-143")
defer c.Close()

resp, _ := c.Get(context.Background(), "https://example.com", nil)
text, _ := resp.Text()
fmt.Println(text, resp.Protocol)
```

</details>

<details>
<summary><b>Node.js</b></summary>

```javascript
import httpcloak from "httpcloak";

const session = new httpcloak.Session({ preset: "chrome-143" });
const r = await session.get("https://example.com");
console.log(r.text, r.protocol);
session.close();
```

</details>

<details>
<summary><b>C#</b></summary>

```csharp
using var session = new Session(Presets.Chrome143);
var r = session.Get("https://example.com");
Console.WriteLine($"{r.Text} {r.Protocol}");
```

</details>

<br>

---

<br>

## Features

<details>
<summary><b>🔐 ECH (Encrypted Client Hello)</b></summary>

<br>

Hides which domain you're connecting to from network observers.

```python
session = httpcloak.Session(
    preset="chrome-143",
    ech_from="cloudflare.com"  # Fetches ECH config from DNS
)
```

Cloudflare trace shows `sni=encrypted` instead of `sni=plaintext`.

</details>

<details>
<summary><b>⚡ Session Resumption (0-RTT)</b></summary>

<br>

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

</details>

<details>
<summary><b>🌐 HTTP/3 Through Proxies</b></summary>

<br>

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

</details>

<details>
<summary><b>🎭 Domain Fronting</b></summary>

<br>

Connect to a different host than what appears in TLS SNI.

```go
client := httpcloak.NewClient("chrome-143",
    httpcloak.WithConnectTo("public-cdn.com", "actual-backend.internal"),
)
```

</details>

<details>
<summary><b>📌 Certificate Pinning</b></summary>

<br>

```go
client.PinCertificate("sha256/AAAA...",
    httpcloak.PinOptions{IncludeSubdomains: true})
```

</details>

<details>
<summary><b>🪝 Request Hooks</b></summary>

<br>

```go
client.OnPreRequest(func(req *http.Request) error {
    req.Header.Set("X-Custom", "value")
    return nil
})

client.OnPostResponse(func(resp *httpcloak.Response) {
    log.Printf("Got %d from %s", resp.StatusCode, resp.FinalURL)
})
```

</details>

<details>
<summary><b>⏱️ Request Timing</b></summary>

<br>

```go
fmt.Printf("DNS: %dms, TCP: %dms, TLS: %dms, Total: %dms\n",
    resp.Timing.DNSLookup,
    resp.Timing.TCPConnect,
    resp.Timing.TLSHandshake,
    resp.Timing.Total)
```

</details>

<details>
<summary><b>🔄 Protocol Selection</b></summary>

<br>

```python
session = httpcloak.Session(preset="chrome-143", http_version="h3")  # Force HTTP/3
session = httpcloak.Session(preset="chrome-143", http_version="h2")  # Force HTTP/2
session = httpcloak.Session(preset="chrome-143", http_version="h1")  # Force HTTP/1.1
```

Auto mode tries HTTP/3 first, falls back gracefully.

</details>

<details>
<summary><b>📤 Streaming & Uploads</b></summary>

<br>

```python
# Stream large downloads
with session.get(url, stream=True) as r:
    for chunk in r.iter_content(chunk_size=8192):
        file.write(chunk)

# Multipart upload
r = session.post(url, files={
    "file": ("filename.jpg", file_bytes, "image/jpeg")
})
```

</details>

<br>

---

<br>

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

<br>

---

<br>

## Testing Tools

| Tool | Tests |
|------|-------|
| [tls.peet.ws](https://tls.peet.ws/api/all) | JA3, JA4, HTTP/2 Akamai |
| [quic.browserleaks.com](https://quic.browserleaks.com/) | HTTP/3 QUIC fingerprint |
| [cf.erisa.uk](https://cf.erisa.uk/) | Cloudflare bot score |
| [cloudflare.com/cdn-cgi/trace](https://www.cloudflare.com/cdn-cgi/trace) | ECH status, TLS version |

<br>

---

<br>

## Dependencies

Custom forks for browser-accurate fingerprinting:

- [sardanioss/utls](https://github.com/sardanioss/utls) — TLS fingerprinting
- [sardanioss/quic-go](https://github.com/sardanioss/quic-go) — HTTP/3 fingerprinting
- [sardanioss/net](https://github.com/sardanioss/net) — HTTP/2 frame fingerprinting

<br>

---

<p align="center">
MIT License
</p>
