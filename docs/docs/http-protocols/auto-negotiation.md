---
title: Auto-Negotiation
sidebar_position: 5
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Auto-Negotiation

Auto-negotiation is the default. The lib races H3 and H2 in parallel, takes whichever connects first, and falls back to H1 only when H2 fails ALPN. No protocol pick on your end, just Chrome-shaped bytes on whichever wire the target actually serves.

## What `doAuto` does

The dispatcher in `transport/transport.go` is one function, `doAuto`. The steps it runs:

1. Look up the host in the `protocolSupport` cache. If a prior request already learned this host's best protocol, skip the race and dial that directly.
2. Otherwise fire two goroutines: one dials H3 over UDP via QUIC, the other dials H2 over TCP+TLS.
3. Take the first success. Cancel the loser.
4. If H2's TLS handshake came back with `http/1.1` in ALPN (`ALPNMismatchError`), reuse that same TLS connection for an H1 request. No second handshake.
5. If both attempts fail (or the 6-second race budget elapses), fall through to H1 on a fresh TCP connection. There's no extra H2 retry; H2 already had its shot inside the race.
6. Cache the winning protocol in `protocolSupport[host]` so the next request to the same host skips the race. Step 5's fallback is the exception: an H1 response served only because the H2 attempt failed says nothing about the host, so it is not cached, and the next request races again. An ALPN downgrade (step 4) is a fact about the host and is cached.

The race lives in `raceH3H2`. It dodges the 5-second wall you'd hit when H3 went first and the network silently swallowed UDP/443. With the race, H2 fills in the moment TCP comes back, usually under 200ms.

## How H3 gets discovered

Two ways:

- **Alt-Svc**. The first H2 response from a host carries `alt-svc: h3=":443"; ma=86400`. The lib parses it, the `protocolSupport` cache learns the host speaks H3, and the next request can race H3 against H2. H3 usually wins because the QUIC handshake finishes in fewer round trips.
- **DNS HTTPS RR**. RFC 9460 HTTPS records advertise ALPN values directly in DNS. If the resolver returns one with `h3` in it, the lib can skip the H2 detour entirely. Whether this fires depends on your DNS config in `dns/`.

When neither hint mentions H3, the race still includes H3 on the first try, but H3's handshake is unlikely to land first.

## When H1 shows up

H1 is the boring fallback. You land there when:

- The TLS server hello returns `http/1.1` in ALPN. The `ALPNMismatchError` path reuses the connection.
- Both H3 and H2 attempts fail outright and the lib has to try H1 on a fresh TCP connection.
- You forced it with `WithForceHTTP1()` or `RefreshWithProtocol("h1")`.

For normal browsing-shaped traffic against modern hosts, H1 should be rare.

## Forcing one protocol

Three options at session construction:

- `WithForceHTTP1()`: lock to H1. Skips H2 and H3 entirely.
- `WithForceHTTP2()`: lock to H2. Skips H3 and won't fall back to H1 unless ALPN drags it there.
- `WithForceHTTP3()`: lock to H3. Hard fails if the host doesn't speak H3.

Plus one for the common middle case:

- `WithDisableHTTP3()`: keep auto-negotiation but never try H3. The "old-school client" knob.

For mid-session changes:

- `RefreshWithProtocol("h1" | "h2" | "h3")` drops the connection pool and forces the named protocol from the next request.
- `WithSwitchProtocol("h2")` at construction time queues a protocol switch on the next `Refresh()`. Useful for the warmup-on-H3, serve-on-H2 pattern when you want to share a TLS ticket across protocols.

## Why force one

A handful of reasons come up in practice:

- **Tests**. You want predictable behavior. Auto-negotiation can land on H2 or H3 depending on what the target's edge advertises that day.
- **Broken H3 at the target**. Some hosts advertise `h3` in Alt-Svc but their UDP port is firewalled, or the QUIC stack is broken. Auto-negotiation handles this by losing the race, but on a host you're hitting millions of times the H3 attempt is wasted work, so `WithDisableHTTP3()` skips it.
- **Policy**. The network only allows TCP/443. Force H2.
- **Fingerprint surface**. Testing the H3 fingerprint your preset emits needs H3 forced against a known H3-capable target, otherwise you risk diffing an H2 capture instead.

## Code: default vs forced

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

func hit(label string, opts ...httpcloak.SessionOption) {
	sess := httpcloak.NewSession("chrome-latest", opts...)
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := sess.Get(ctx, "https://tls.peet.ws/api/all")
	if err != nil {
		fmt.Printf("[%s] err: %v\n", label, err)
		return
	}
	defer resp.Close()
	fmt.Printf("[%s] resp.Protocol=%s status=%d\n", label, resp.Protocol, resp.StatusCode)
}

func main() {
	hit("default")                              // h2 against tls.peet
	hit("force-h2", httpcloak.WithForceHTTP2()) // h2
	hit("disable-h3", httpcloak.WithDisableHTTP3())
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

def hit(label, **kwargs):
    with httpcloak.Session(preset="chrome-latest", timeout=30, **kwargs) as sess:
        r = sess.get("https://tls.peet.ws/api/all")
        print(f"[{label}] protocol={r.protocol} status={r.status_code}")

hit("default")
hit("force-h2", http_version="h2")
# Bindings have no direct H3-disable kwarg; pinning to h2 has the same effect.
hit("force-h2-only", http_version="h2")
```

</TabItem>
<TabItem value="node" label="Node.js">

```javascript
const { Session } = require("httpcloak");

async function hit(label, opts) {
  const sess = new Session({ preset: "chrome-latest", timeout: 30, ...opts });
  try {
    const r = await sess.get("https://tls.peet.ws/api/all");
    console.log(`[${label}] protocol=${r.protocol} status=${r.statusCode}`);
  } finally {
    sess.close();
  }
}

(async () => {
  await hit("default", {});
  await hit("force-h2", { httpVersion: "h2" });
  // Bindings have no direct H3-disable; pin to h2 for the same effect.
  await hit("force-h2-only", { httpVersion: "h2" });
})();
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

void Hit(string label, string httpVersion = "auto") {
    using var sess = new Session(preset: "chrome-latest", timeout: 30, httpVersion: httpVersion);
    var r = sess.Get("https://tls.peet.ws/api/all");
    Console.WriteLine($"[{label}] protocol={r.Protocol} status={r.StatusCode}");
}

Hit("default");          // auto-negotiate
Hit("force-h2", "h2");   // pin to HTTP/2
// HTTP/3 alone has no direct disable arg; pin to h2 for the same effect.
```

</TabItem>
</Tabs>

Expected output, hitting `tls.peet.ws`:

```
[default] resp.Protocol=h2 status=200
[force-h2] resp.Protocol=h2 status=200
[disable-h3] resp.Protocol=h2 status=200
```

All three land on H2 because tls.peet.ws's UDP/443 port is closed in practice, so the lib never gets an H3 path to win the race.

## Per-host learning

A request to `example.com` that comes back on H3 leaves a marker in the cache. The next request to `example.com` skips the race and dials H3 directly. The cache is keyed by hostname (no port, no path) and lives in `protocolSupport`. When the host stops responding on H3 later, recreating the session or calling `RefreshWithProtocol("h2")` is the way to evict the cached choice.

A planned `BrokenAltSvc` circuit breaker would suppress H3 attempts after repeated failures to a specific host without forcing a restart. Tracked in our internal docs, not landed yet.

:::tip Auto vs forced for production
For production traffic where the protocol doesn't matter, leave it on auto. The lib handles Alt-Svc, the H3 race, and ALPN fallback. For automation aimed at specific bot products, force the protocol the preset is shaped for. Most `chrome-148` presets are tuned for H2 and H3 side by side, but matching against a capture taken specifically on H3 needs H3 forced so the diff doesn't accidentally compare against an H2 fingerprint.
:::

## See also

- [HTTP/1.1](./http1) for what H1 negotiates and when it's the right call.
- [HTTP/2](./http2) for the SETTINGS, WINDOW_UPDATE, and Akamai signals on H2.
- [HTTP/3 (QUIC)](./http3-quic) for the QUIC INITIAL packet and PRIORITY_UPDATE.
- [Akamai shorthand](/fingerprinting/akamai-shorthand) for tweaking H2 fingerprint values without rebuilding a preset.
