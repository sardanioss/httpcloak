---
title: HTTP/1.1
sidebar_position: 2
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# HTTP/1.1

H1 is the fallback path in httpcloak. Most modern hosts negotiate H2 or H3 by default, so H1 only shows up against legacy targets, internal services, and cases where ALPN won't hand back anything newer. The lib speaks H1 when it has to, and lets you force it when the situation calls for it.

## When the lib picks H1

Three paths land you on H1:

- The target's TLS server hello returns `http/1.1` in ALPN, with no `h2` advertised and no `h3` Alt-Svc. The negotiation has nowhere else to go.
- The auto-negotiation race finds H2 fails with an `ALPNMismatchError`. The lib reuses that same TLS connection and drops to H1 instead of redoing the handshake.
- You forced it, either with `WithForceHTTP1()` at construction or `RefreshWithProtocol("h1")` mid-session.

Forcing H1 covers two situations. The first is predictable behavior in tests, where you don't want the protocol to drift between runs. The second is targets sitting behind older WAFs or internal mTLS gateways that only speak H1, where letting the lib try H2 first wastes a round trip on a guaranteed downgrade.

## What the H1 transport does

Raw TCP, a uTLS handshake with `http/1.1` as the only ALPN entry, then plain text request-line plus headers plus CRLF plus body on the wire. No multiplexing, no header compression, no priority frames. One request per connection at a time, optionally pipelined with `Connection: keep-alive`.

The transport lives in `transport/http1_transport.go`. The interesting part is what gets fingerprinted on top.

## What gets fingerprinted at H1

Three layers, top to bottom:

1. **TLS handshake**. Same uTLS-backed ClientHello as H2 and H3, with the ALPN extension rewritten to `["http/1.1"]` only. JA3, JA4, and peetprint all still apply. See [TLS fingerprinting](/fingerprinting/what-is-tls-fingerprinting).
2. **Header order**. H1 is plain text, so header order is exactly the order of bytes you put on the wire. The preset's header order list drives this. DevTools won't show you the real order Chrome sends, so check `tls.peet.ws/api/all` when you need ground truth.
3. **`Connection` header behavior**. `keep-alive` vs `close` vs `Upgrade: websocket` is a real fingerprint signal, and so is where the header sits. Chrome on H1 sends `Connection: keep-alive` right after `Host`, and Chrome presets match that. Firefox sends it after `Accept-Encoding` when it loads a page and the stylesheets, scripts, images and frames in it, and Firefox presets put it there. A `Connection` you set yourself takes the preset's place; one you list in `ExactHeaders` goes where you listed it, spelled as you spelled it.

H1 has no SETTINGS, no WINDOW_UPDATE, and no PRIORITY frames, so the Akamai H2 hash is empty on this path and any check that relies on those signals just can't fire.

:::info H1 is also the websocket upgrade path
WebSocket starts as an H1 request with `Upgrade: websocket`. The upgrade flow needs H1. See [streaming and upgrades](/connection-lifecycle).
:::

## Code: force H1 and verify

Hit `tls.peet.ws/api/all`, assert `http_version` is `HTTP/1.1`, print the JA3.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sardanioss/httpcloak"
)

func main() {
	sess := httpcloak.NewSession("chrome-latest",
		httpcloak.WithForceHTTP1(),
		httpcloak.WithSessionTimeout(30*time.Second),
	)
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := sess.Get(ctx, "https://tls.peet.ws/api/all")
	if err != nil {
		panic(err)
	}
	defer resp.Close()

	body, _ := resp.Bytes()
	var pr struct {
		HTTPVersion string `json:"http_version"`
		TLS         struct {
			JA3Hash string `json:"ja3_hash"`
		} `json:"tls"`
	}
	json.Unmarshal(body, &pr)

	fmt.Println("resp.Protocol:", resp.Protocol)
	fmt.Println("peet http_version:", pr.HTTPVersion)
	fmt.Println("ja3:", pr.TLS.JA3Hash)
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with httpcloak.Session(preset="chrome-latest", http_version="h1", timeout=30) as sess:
    r = sess.get("https://tls.peet.ws/api/all")
    body = r.json()
    print("resp protocol:", r.protocol)
    print("peet http_version:", body["http_version"])
    print("ja3:", body["tls"]["ja3_hash"])
```

</TabItem>
<TabItem value="node" label="Node.js">

```javascript
const { Session } = require("httpcloak");

(async () => {
  const sess = new Session({ preset: "chrome-latest", httpVersion: "h1", timeout: 30 });
  try {
    const r = await sess.get("https://tls.peet.ws/api/all");
    const body = JSON.parse(r.text);
    console.log("resp protocol:", r.protocol);
    console.log("peet http_version:", body.http_version);
    console.log("ja3:", body.tls.ja3_hash);
  } finally {
    sess.close();
  }
})();
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;
using System.Text.Json;

using var sess = new Session(preset: "chrome-latest", httpVersion: "h1", timeout: 30);
var r = sess.Get("https://tls.peet.ws/api/all");
var body = JsonDocument.Parse(r.Text).RootElement;
Console.WriteLine($"resp protocol: {r.Protocol}");
Console.WriteLine($"peet http_version: {body.GetProperty("http_version").GetString()}");
Console.WriteLine($"ja3: {body.GetProperty("tls").GetProperty("ja3_hash").GetString()}");
```

</TabItem>
</Tabs>

Expected output:

```
resp.Protocol: h1
peet http_version: HTTP/1.1
ja3: fe202172df94b322cc6e1e888a464d43
```

`resp.Protocol` is the lib's internal label (`h1`, `h2`, `h3`). `http_version` from `tls.peet.ws` is what the server actually saw, so that field is the source of truth.

## Switching mid-session

`RefreshWithProtocol` swaps the active protocol on an existing session. Warm up on H2, drop to H1 for a single endpoint, keep the same cookies and tickets:

```go
sess := httpcloak.NewSession("chrome-latest")
defer sess.Close()

// First request: default auto-negotiation, will land on H2.
sess.Get(ctx, "https://example.com/")

// Switch to H1 for a legacy upgrade-only endpoint.
sess.RefreshWithProtocol("h1")
sess.Get(ctx, "https://legacy.example.com/api/upgrade")
```

`RefreshWithProtocol` drops the existing connection pool. Cookies and the TLS session ticket cache survive the switch.

:::caution H1 with HTTP proxies
Going through an HTTP `CONNECT` proxy where the upstream only speaks H1 still benefits from the lib's speculative-TLS optimization. The ClientHello rides on the same packet as `CONNECT`, saving a round trip. See [HTTP CONNECT proxies](/proxies/http-connect).
:::
