---
title: Refresh
sidebar_position: 1
---

# Refresh

`Refresh()` closes every live connection on a session and leaves the rest of the state alone. Cookies stay in the jar. TLS tickets stay cached. ECH config holds. The preset name and any fingerprint overrides remain in place. Only the open sockets go.

The next request opens new TCP or QUIC connections and the TLS handshake resumes from a cached ticket: a PSK resumption on TLS 1.3, which over HTTP/3 also sends the first request as 0-RTT early data when the server's ticket allows it, or session-ID resumption on TLS 1.2. The cookie header on the new connection is byte-identical to the cookie header on the old one. From the server's side, the visible signal is one connection closing and another opening with the same cookies, which is what a browser tab reload looks like.

## Why this exists

Connection age is one of the cheaper signals an anti-bot stack tracks. A browser doesn't sit on a TCP socket for hours; the keep-alive timer expires, the next page load opens a fresh connection, and the cycle repeats. A scraper that pins one connection open for six hours stands out against that baseline.

`Refresh()` produces the same lifecycle without losing your cookies or tickets. Run it on a timer, two or three minutes is fine. The other reasons to call it: a connection has gone stale, the server is misbehaving, or you want to switch protocols (see [Protocol Switching](./protocol-switching)).

## What survives a Refresh

| State | Survives |
| --- | --- |
| Cookies (full jar with metadata) | Yes |
| TLS 1.3 session tickets | Yes |
| TLS 1.2 session IDs | Yes |
| ECH config cache | Yes |
| Preset name and fingerprint overrides | Yes |
| Header order | Yes |
| Proxy config | Yes |
| Cache-validation headers (ETag / Last-Modified) | Yes |
| Live TCP / QUIC connections | No, all closed |
| In-flight requests | No, cancelled |
| Open streaming responses | No, terminated |

Calling `Refresh()` while a streaming download is in flight kills that stream. There's no graceful drain. Finish or close streaming responses before refreshing.

## The 0-RTT story

Tickets stay in the cache across the refresh, so the next handshake resumes from the previous TLS state. Over HTTP/3, TLS 1.3 takes the 0-RTT early-data path when the server's ticket allows early data and resumes without it otherwise, as Chrome does; TLS 1.2 falls back to session-ID resumption, which skips the certificate roundtrip but doesn't ship request bytes early. Either way, the first request after a refresh is faster by a wide margin than the first request on a brand-new session.

:::tip
Long-running scrapers benefit from a `Refresh()` every few minutes. A connection that's been alive for hours is one of the cheaper signals an anti-bot stack can use against you, and the cost of refreshing is one resumed handshake.
:::

## Code

The shape is the same across every binding: send some requests, call `Refresh()`, send more.

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
s := httpcloak.NewSession("chrome-latest")
defer s.Close()
ctx := context.Background()

// Round 1 on the original connection.
for i := 0; i < 3; i++ {
	r, _ := s.Get(ctx, "https://tls.peet.ws/api/all")
	fmt.Printf("round1 #%d status=%d\n", i, r.StatusCode)
	r.Close()
}

// Cut the wire. Tickets, cookies, fingerprint state all survive.
s.Refresh()

// Round 2 picks up fresh sockets with TLS resumption.
for i := 0; i < 3; i++ {
	r, _ := s.Get(ctx, "https://tls.peet.ws/api/all")
	fmt.Printf("round2 #%d status=%d\n", i, r.StatusCode)
	r.Close()
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with httpcloak.Session(preset="chrome-latest") as s:
    # Round 1
    for i in range(3):
        r = s.get("https://tls.peet.ws/api/all")
        print(f"round1 #{i} status={r.status_code}")

    # Cut every connection. Cookies and tickets stay.
    s.refresh()

    # Round 2 picks up clean sockets with TLS resumption.
    for i in range(3):
        r = s.get("https://tls.peet.ws/api/all")
        print(f"round2 #{i} status={r.status_code}")
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```javascript
const httpcloak = require("httpcloak");

const s = new httpcloak.Session({ preset: "chrome-latest" });
try {
  for (let i = 0; i < 3; i++) {
    const r = await s.get("https://tls.peet.ws/api/all");
    console.log(`round1 #${i} status=${r.statusCode}`);
  }

  s.refresh();

  for (let i = 0; i < 3; i++) {
    const r = await s.get("https://tls.peet.ws/api/all");
    console.log(`round2 #${i} status=${r.statusCode}`);
  }
} finally {
  s.close();
}
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-latest");

for (int i = 0; i < 3; i++)
{
    var r = s.Get("https://tls.peet.ws/api/all");
    Console.WriteLine($"round1 #{i} status={r.StatusCode}");
}

s.Refresh();

for (int i = 0; i < 3; i++)
{
    var r = s.Get("https://tls.peet.ws/api/all");
    Console.WriteLine($"round2 #{i} status={r.StatusCode}");
}
```

</TabItem>
</Tabs>

## What's NOT preserved

- **Live connections.** Every TCP socket and every QUIC connection is closed.
- **Active requests.** Anything in flight is cancelled. The caller sees a context-cancelled or connection-closed error.
- **Streaming responses.** Body reads fail partway. Drain or close streams before refreshing.

Everything else (jar, tickets, ECH, header order, custom JA3, preset, proxy) carries forward. A save before and a save after `Refresh()` differ only in the timestamp.

## When NOT to use it

For a totally fresh session with no cookies, no tickets and no inherited state, don't `Refresh()`. Close the session and build a new one. `Refresh()` is the "keep my identity, drop my sockets" tool; "drop my identity" is what `NewSession` is for.

One detail to know: after `Refresh()` the session adds `cache-control: max-age=0` to the next request, which matches what a real browser F5 sends. Some servers treat that as a deliberate cache-bust. If that signal is unwanted, build a fresh session instead.

`Refresh()` and `Close()` both go through a timeout-bounded close path on QUIC, so a misbehaving H3 peer can't hang the call forever.
