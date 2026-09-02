---
title: httpcloak
slug: /
sidebar_position: 1
---

# httpcloak

httpcloak is a Go HTTP client that emits the same wire bytes as a real browser across HTTP/1.1, HTTP/2, and HTTP/3. The Go core handles TLS via uTLS, HTTP/2, HTTP/3 over QUIC, proxying through HTTP CONNECT, SOCKS5, and MASQUE, and per-resource RFC 7540 / RFC 9218 stream priorities. Python, Node.js, and .NET get the same API through a shared cgo library.

## Quickstart

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
	"context"
	"fmt"

	"github.com/sardanioss/httpcloak"
)

func main() {
	s := httpcloak.NewSession("chrome-latest")
	defer s.Close()

	resp, _ := s.Get(context.Background(), "https://example.com/")
	fmt.Println(resp.StatusCode)
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with httpcloak.Session(preset="chrome-latest") as s:
    resp = s.get("https://example.com/")
    print(resp.status_code)
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
const { Session } = require('httpcloak');

const s = new Session({ preset: 'chrome-latest' });
const resp = await s.get('https://example.com/');
console.log(resp.statusCode);
s.close();
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-latest");
var resp = await s.GetAsync("https://example.com/");
Console.WriteLine(resp.StatusCode);
```

</TabItem>
</Tabs>

## Features

### Connection lifecycle

- **`Refresh()`**: drops every live connection but keeps the TLS session
  tickets, the way a browser tab does on reload. The next request resumes
  0-RTT on the same preset.
- **`RefreshWithProtocol()` / `WithSwitchProtocol`**: hop between H1, H2,
  and H3 mid-session and re-handshake on the new transport.
- **`Save()` / `LoadSession()`**: persists the session (tickets, cookies,
  preset state) to disk so you can resume across processes.
- **`Warmup(ctx, url)`**: multi-hop browser-style warmup ahead of the real
  request. Pre-populates cookies, ECH state, and session tickets.

### Fingerprint customization

- **JSON preset describe / load**: `describe_preset(name)` dumps the full
  preset spec as JSON. `load_preset_from_json(json)` registers a mutated
  copy at runtime. Round-trips byte-for-byte.
- **Per-resource priority table**: RFC 7540 stream weights and RFC 9218
  `priority:` headers picked per request from `Sec-Fetch-Dest`. Every RFC
  7540 preset inherits a 14-dest default table, overridable per preset.
- **Custom JA3 + Akamai shorthand**: `WithCustomFingerprint` takes a JA3
  string and an Akamai HTTP/2 fingerprint string. A targeted override
  without writing a whole preset.
- **Cookie jar opt-out**: `WithoutCookieJar()` disables the internal jar.
  Cookies move through per-request headers instead.

### Privacy and advanced TLS

- **ECH (Encrypted Client Hello)**: on by default. Encrypts SNI on the
  wire. `WithDisableECH()` skips the DNS lookup. `WithECHFrom(domain)`
  borrows an ECH config from another domain (e.g. `cloudflare-ech.com`).
- **MASQUE**: HTTP/3 CONNECT-UDP proxy support. Tunnels QUIC over a
  remote endpoint.
- **Speculative TLS for proxy CONNECT**: `WithEnableSpeculativeTLS()`
  pipelines the CONNECT request with the inner ClientHello, saving one
  RTT on every proxied connection.
- **TLS keylog**: `WithKeyLogFile(path)` writes a Wireshark-compatible
  SSLKEYLOGFILE for offline decryption.

### Network and proxy

- **Proxy types**: HTTP CONNECT, SOCKS5, SOCKS5 with UDP ASSOCIATE, and
  MASQUE. Split-config works through `WithSessionTCPProxy` and
  `WithSessionUDPProxy` (HTTP proxy for H1/H2, MASQUE for H3, for example).
- **Source-address binding**: `WithLocalAddress(string)` and
  `WithLocalAddrIP(net.IP)` pin every dial socket to a chosen local IP.
  `IP_FREEBIND` / `IPV6_FREEBIND` gets set on Linux, so addresses that
  aren't configured on the interface (a routed IPv6 prefix for rotation,
  for example) bind without `CAP_NET_ADMIN`.
- **`WithSessionPreferIPv4()`**: skips Happy Eyeballs and forces v4.

### Presets

- **Chrome**: 133, 141, 143 through 152, with per-OS variants
  (Windows / Linux / macOS / Android / iOS) where they differ.
- **Firefox**: 133, 148.
- **Safari**: 18 (desktop), 17 / 18 (iOS).
- **`chrome-latest` aliases**: `chrome-latest`, `chrome-latest-windows`,
  `chrome-latest-linux`, `chrome-latest-macos`, `chrome-latest-android`,
  `chrome-latest-ios`. Auto-track the newest shipped Chrome major.

### Bindings

- **Go**: `go get github.com/sardanioss/httpcloak`
- **Python**: `pip install httpcloak`
- **Node.js**: `npm install httpcloak`
- **.NET**: `dotnet add package HttpCloak`

## Where to next

- New here, start with [Getting Started](/getting-started).
- Looking up something specific, the [Reference](/reference) is the place.
- Proxy setup is in [Proxies](/proxies).
- Fingerprint dial-in lives in [Fingerprinting](/fingerprinting).
- Long-running sessions, Refresh, Warmup, Save/Restore: see [Connection Lifecycle](/connection-lifecycle).
- ECH, keylog, speculative TLS: see [Advanced TLS](/advanced-tls).
- End-to-end patterns for real builds are in [Recipes](/recipes).
