---
title: HTTP/3 (QUIC)
sidebar_position: 4
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# HTTP/3 (QUIC)

H3 is H2 semantics riding on QUIC, which is TLS 1.3 plus a streaming transport built on UDP. The framing looks like H2 (streams, frames, HPACK-shaped header compression via QPACK), but the transport underneath is a different beast. No TCP, no head-of-line blocking when one stream's packet drops, faster cold start with 0-RTT, and connection migration when the client IP shifts.

httpcloak speaks H3 when the target advertises it (Alt-Svc on a previous H2 response, or a DNS HTTPS record) or when you force it.

## httpcloak's H3 stack

The H3 transport rides `sardanioss/quic-go`, a fork of upstream `quic-go` with our own fingerprinting hooks and bug fixes on top. Currently pinned at v1.2.25, the bump that shipped the PRIORITY_UPDATE fix described below.

The fork adds the following on top of upstream:

- Configurable QUIC transport parameters in the INITIAL packet (idle timeout, max UDP payload, initial max data, initial max streams, and so on).
- Configurable QUIC version order in the INITIAL packet's version-negotiation list.
- HTTP/3 SETTINGS frame values that line up with the H2 preset.
- HTTP/3 PRIORITY_UPDATE frames on the control stream, with the prioritized stream ID and priority field value matching real Chrome.
- 0-RTT session resumption that preserves the early-data flag across reconnects.

The transport lives in `transport/http3_transport.go` and uses `http3.Transport` from the fork.

## ALPN and discovery

The H3 ALPN ID is `h3`. The lib gets there one of two ways:

- **Alt-Svc**. The H2 response carried `alt-svc: h3=":443"; ma=86400`. The lib remembers that for the cache window, and the next request to that host can race H3 against H2. See [auto-negotiation](./auto-negotiation).
- **DNS HTTPS RR**. The HTTPS DNS record (RFC 9460) advertises ALPN values directly. If the resolver returns one with `h3` in it, the lib can try H3 on the first request without needing a previous H2 hit. Whether HTTPS RR fires depends on your DNS config (see `dns/`).

Forcing H3 on a host that doesn't actually serve it ends in a QUIC handshake timeout. The default `QuicIdleTimeout` is 30 seconds, which doubles as the upper bound on a stuck handshake. Override it with `WithQuicIdleTimeout(d)` if you want to fail faster, or pass a tighter context deadline on the request itself. The 5-second figure that comes up next door belongs to the auto-negotiation race, not to forced H3.

## 0-RTT resumption

A TLS session ticket from a previous successful handshake to the same host lets the lib attach the first request as 0-RTT data on the same UDP packet as the QUIC INITIAL. Saves a full round trip on the cold path.

That takes a ticket the server issued with early data allowed. On a ticket that doesn't allow it, the handshake still resumes, but nothing goes early and the hello carries no `early_data` extension, which is how Chrome and Firefox resume there.

The ticket cache is per-session by default. Plug in a `SessionCacheBackend` via `WithSessionCache(...)` to keep tickets across process restarts.

0-RTT comes with the usual replay caveat. The server decides what's safe (RFC 9001 says only idempotent methods should ride 0-RTT). httpcloak sends what you hand it, so the first request after a fresh session should be a `GET` or some other safe method.

## What gets fingerprinted at H3

Stacked from packet level up:

1. **QUIC INITIAL packet**. The first UDP packet carries the QUIC version, version-negotiation list, source and destination connection IDs, and the TLS 1.3 ClientHello inside the CRYPTO frame. The transport parameters in the ClientHello extension are part of the fingerprint too.
2. **TLS 1.3 ClientHello**. Same uTLS-backed handshake as H2, with `h3` in ALPN.
3. **HTTP/3 SETTINGS frame**. Same role as H2 SETTINGS but different setting IDs. Sent on the control stream (stream ID 2 from client).
4. **PRIORITY_UPDATE frames**. RFC 9218 priority signaling at the H3 layer. Real Chrome emits one PRIORITY_UPDATE on the control stream per request, referencing the request's actual stream ID.
5. **Pseudo-header order, header order, QPACK encoding**. Same surface as H2, encoded with QPACK instead of HPACK.

The H3 fingerprint at `tls.peet.ws/api/all` lands as `h3_text` and `h3_hash`. It rolls up SETTINGS values, the PRIORITY_UPDATE wire bytes, QPACK literal hints, and the pseudo-header order.

## Recent fix: PRIORITY_UPDATE on the control stream (1.6.6)

Worth calling out, because this was a long-standing bug only visible on H3-aware fingerprinters.

Before 1.6.6:

- The PRIORITY_UPDATE frame's `prioritized_stream_id` was hardcoded to `0`.
- The priority field value was hardcoded to `"u=0, i"`.

Real Chrome never emits PRIORITY_UPDATE for stream 0. Chrome's 0-RTT probe burns that bidi ID, so the first real request lands on stream 4. Fingerprinters parsing RFC 9218 silently dropped our PRIORITY_UPDATE as malformed, and the diff against real Chrome failed.

After 1.6.6:

- PRIORITY_UPDATE goes out lazily, right before the first request's HEADERS frame.
- `prioritized_stream_id` matches the actual stream the request is on.
- The priority field value comes from the request's `priority:` header, which the priority table sets per resource type.

Net wire change: `h3_text` now contains the visible `|984832|` token between `GREASE` and the pseudo-order, matching real Chrome 147+ H3 captures byte for byte.

## Code: force H3 and verify

`tls.peet.ws` advertises `h3` in Alt-Svc, but its UDP/443 port is closed in practice. A host that actually serves H3, like `www.cloudflare.com`, is the right target for a live H3 check.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/sardanioss/httpcloak"
)

func main() {
	sess := httpcloak.NewSession("chrome-latest",
		httpcloak.WithForceHTTP3(),
		httpcloak.WithSessionTimeout(30*time.Second),
	)
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := sess.Get(ctx, "https://www.cloudflare.com/")
	if err != nil {
		panic(err)
	}
	defer resp.Close()

	fmt.Println("resp.Protocol:", resp.Protocol) // h3
	fmt.Println("status:", resp.StatusCode)
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with httpcloak.Session(preset="chrome-latest", http_version="h3", timeout=30) as sess:
    r = sess.get("https://www.cloudflare.com/")
    print("resp protocol:", r.protocol)
    print("status:", r.status_code)
```

</TabItem>
<TabItem value="node" label="Node.js">

```javascript
const { Session } = require("httpcloak");

(async () => {
  const sess = new Session({ preset: "chrome-latest", httpVersion: "h3", timeout: 30 });
  try {
    const r = await sess.get("https://www.cloudflare.com/");
    console.log("resp protocol:", r.protocol);
    console.log("status:", r.statusCode);
  } finally {
    sess.close();
  }
})();
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var sess = new Session(preset: "chrome-latest", httpVersion: "h3", timeout: 30);
var r = sess.Get("https://www.cloudflare.com/");
Console.WriteLine($"resp protocol: {r.Protocol}");
Console.WriteLine($"status: {r.StatusCode}");
```

</TabItem>
</Tabs>

Expected output:

```
resp.Protocol: h3
status: 200
```

For an H3 host that returns the full peet-style fingerprint payload, swap in your own H3 reflector or one of the `cf.*` reflectors that returns JSON.

## H3 over proxies: read this before debugging

A lot of SOCKS5 proxies don't support `UDP_ASSOCIATE`, the SOCKS5 verb for tunneling UDP. Without it, H3 over SOCKS5 doesn't work because QUIC needs UDP end to end. Plain HTTP `CONNECT` proxies are TCP-only by definition, so they can't carry H3 either.

:::warning H3 needs a UDP-capable proxy
H3 over a proxy needs either a SOCKS5 server that supports `UDP_ASSOCIATE` ([SOCKS5 UDP](/proxies/socks5-udp)) or a MASQUE proxy ([MASQUE](/proxies/masque)). HTTP `CONNECT` won't work because it doesn't carry UDP. On a TCP-only proxy, H3-shaped fingerprints aren't reachable. Move to MASQUE or accept H2 as the wire.
:::

When the lib spots that the configured proxy can't carry UDP, forced-H3 requests fail fast with `HTTP/3 requires a SOCKS5 or MASQUE proxy (current proxy does not support UDP)`. Auto-negotiation falls back to H2 or H1 silently in that case.

## Knobs you might want

- `WithQuicIdleTimeout(d)` overrides the QUIC idle timeout. The default is conservative.
- `WithKeyLogFile(path)` writes TLS keys for Wireshark decryption. Works on H3 too, both the QUIC handshake and the inner application data.
- `WithSessionCache(...)` plugs in a persistent ticket store so 0-RTT survives process restarts.

## Switching mid-session

Same shape as H1 and H2:

```go
sess := httpcloak.NewSession("chrome-latest")
defer sess.Close()
sess.Get(ctx, "https://example.com/")          // auto-negotiated H2
sess.RefreshWithProtocol("h3")
sess.Get(ctx, "https://www.cloudflare.com/")   // forced H3 from here
```

`RefreshWithProtocol("h3")` refuses when the active preset doesn't support H3 (some legacy presets are H2-only on purpose).
