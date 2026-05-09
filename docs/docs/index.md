---
title: httpcloak
slug: /
sidebar_position: 1
---

# httpcloak

httpcloak is a Go HTTP client that produces wire bytes indistinguishable from
mainstream browsers across HTTP/1.1, HTTP/2, and HTTP/3. The Go core handles
TLS (uTLS), HTTP/2, HTTP/3 (QUIC), proxying (HTTP CONNECT, SOCKS5, MASQUE),
and per-resource RFC 7540 / RFC 9218 stream priorities. Bindings expose the
same API in Python, Node.js, and .NET via a shared cgo library.

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

- **`Refresh()`**: sever every live connection while keeping TLS session
  tickets, the way a browser tab does on reload. Next request resumes 0-RTT
  on the same preset.
- **`RefreshWithProtocol()` / `WithSwitchProtocol`**: switch between H1, H2,
  and H3 mid-session and re-handshake on the chosen transport.
- **`Save()` / `LoadSession()`**: persist the session (tickets, cookies,
  preset state) to disk and resume across processes.
- **`Warmup(ctx, url)`**: multi-hop browser-style warmup before the real
  request, populating cookies, ECH state, and session tickets.

### Fingerprint customization

- **JSON preset describe / load**: `describe_preset(name)` emits the full
  preset spec as JSON; `load_preset_from_json(json)` registers a mutated
  copy at runtime. Round-trips byte-for-byte.
- **Per-resource priority table**: RFC 7540 stream weights and RFC 9218
  `priority:` headers selected per request from `Sec-Fetch-Dest`. Default
  14-dest table inherited by every RFC 7540 preset; overridable per preset.
- **Custom JA3 + Akamai shorthand**: `WithCustomFingerprint` accepts a JA3
  string and an Akamai HTTP/2 fingerprint string for fine-grained override
  without writing a full preset.
- **Cookie jar opt-out**: `WithoutCookieJar()` disables the internal jar
  entirely; caller manages cookies via per-request headers.

### Privacy and advanced TLS

- **ECH (Encrypted Client Hello)**: on by default; encrypts SNI on the
  wire. `WithDisableECH()` skips the DNS lookup; `WithECHFrom(domain)`
  borrows an ECH config from another domain (e.g. `cloudflare-ech.com`).
- **MASQUE**: HTTP/3 CONNECT-UDP proxy support for tunneling QUIC over a
  remote endpoint.
- **Speculative TLS for proxy CONNECT**: `WithEnableSpeculativeTLS()`
  pipelines the CONNECT request with the inner ClientHello, saving one RTT
  on every proxied connection.
- **TLS keylog**: `WithKeyLogFile(path)` writes a Wireshark-compatible
  SSLKEYLOGFILE for offline decryption.

### Network and proxy

- **Proxy types**: HTTP CONNECT, SOCKS5, SOCKS5 with UDP ASSOCIATE, and
  MASQUE. Split-config supported via `WithSessionTCPProxy` +
  `WithSessionUDPProxy` (e.g. HTTP proxy for H1/H2, MASQUE for H3).
- **Source-address binding**: `WithLocalAddress(string)` and
  `WithLocalAddrIP(net.IP)` bind every dial socket to a chosen local IP.
  `IP_FREEBIND` / `IPV6_FREEBIND` is set on Linux so non-locally-configured
  addresses (e.g. routed IPv6 prefix rotation) work without
  `CAP_NET_ADMIN`.
- **`WithSessionPreferIPv4()`**: opt out of Happy Eyeballs and force v4.

### Presets

- **Chrome**: 133, 141, 143, 144, 145, 146, 147, 148, with per-OS variants
  (Windows / Linux / macOS / Android / iOS) where applicable.
- **Firefox**: 133, 148.
- **Safari**: 18 (desktop), 17 / 18 (iOS).
- **`chrome-latest` aliases**: `chrome-latest`, `chrome-latest-windows`,
  `chrome-latest-linux`, `chrome-latest-macos`, `chrome-latest-android`,
  `chrome-latest-ios`. Auto-track the most recent shipped Chrome major.

### Bindings

- **Go**: `go get github.com/sardanioss/httpcloak`
- **Python**: `pip install httpcloak`
- **Node.js**: `npm install httpcloak`
- **.NET**: `dotnet add package HttpCloak`

## Where to next

- New here? Start at [Getting Started](/getting-started).
- Looking up something specific? See the [Reference](/reference).
- Need a proxy? See [Proxies](/proxies).
- Want to dial in the fingerprint? See [Fingerprinting](/fingerprinting).
- Long-running session, Refresh, Warmup, Save/Restore? See [Connection Lifecycle](/connection-lifecycle).
- ECH, keylog, speculative TLS? See [Advanced TLS](/advanced-tls).
- End-to-end patterns for real builds? See [Recipes](/recipes).
