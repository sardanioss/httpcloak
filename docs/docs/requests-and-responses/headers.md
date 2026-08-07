---
title: Headers
sidebar_position: 2
---

# Headers

Header order is part of your fingerprint, not just the values themselves. Chrome ships its headers in a fixed sequence: `sec-ch-ua` first, then `sec-ch-ua-mobile`, `sec-ch-ua-platform`, `upgrade-insecure-requests`, `user-agent`, `accept`, and so on down the list. Anti-bot vendors hash that sequence. Send the same set in a different order, add one Chrome would never emit, or skip one Chrome always sends, and the request stands out.

httpcloak bakes the canonical order into each preset. Your custom headers slot into preset-reserved positions, so adding `Authorization` or `X-Anything-Custom` lands at the offset Chrome would have used and the fingerprint stays intact.

:::tip
DevTools doesn't show you header order, so you're flying blind there. Hit [tls.peet.ws/api/all](https://tls.peet.ws/api/all) and check the `http2.sent_frames[].headers` array. That's the wire order.
:::

## What ships by default

Every preset carries its own browser header set. For `chrome-148-linux` (today's default), the request goes out as:

| Position | Header | Example value |
|---|---|---|
| 1 | `sec-ch-ua` | `"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"` |
| 2 | `sec-ch-ua-mobile` | `?0` |
| 3 | `sec-ch-ua-platform` | `"Linux"` |
| 4 | `upgrade-insecure-requests` | `1` |
| 5 | `user-agent` | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ...` |
| 6 | `accept` | `text/html,application/xhtml+xml,...` |
| 7 | `sec-fetch-site` | `none` |
| 8 | `sec-fetch-mode` | `navigate` |
| 9 | `sec-fetch-user` | `?1` |
| 10 | `sec-fetch-dest` | `document` |
| 11 | `accept-encoding` | `gzip, deflate, br, zstd` |
| 12 | `accept-language` | `en-US,en;q=0.9` |
| 13 | `priority` | `u=0, i` |

Different presets ship different defaults. Firefox skips `sec-ch-ua-*` entirely, Safari sends a different `accept-language`, mobile presets flip `sec-ch-ua-mobile` to `?1`. The full list per preset lives in `fingerprint/embedded/<preset>.json`.

The lib also auto-rewrites the `sec-fetch-*` cluster based on the kind of request you're firing. POST/PUT/PATCH and most XHR-shaped GETs flip from navigation mode (`navigate`/`document`/`?1`) to CORS mode (`cors`/`empty`/cross-site, no `sec-fetch-user`). The browser does the same rewrite, so an API call doesn't go out with navigation-style headers attached.

## Setting custom headers

Two scopes: per-request, or session-wide as a default.

### Per-request

Drop a `Headers` map on the request. Whatever you set merges into the preset defaults. If your key matches a preset header, your value wins (single-value Set semantics).

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
    "context"
    "fmt"

    httpcloak "github.com/sardanioss/httpcloak"
)

func main() {
    s := httpcloak.NewSession("chrome-latest")
    defer s.Close()

    req := &httpcloak.Request{
        Method: "GET",
        URL:    "https://httpbin.org/headers",
        Headers: map[string][]string{
            "X-My-Header":   {"hello-world"},
            "Authorization": {"Bearer xxx"},
        },
    }
    resp, _ := s.Do(context.Background(), req)
    defer resp.Close()

    body, _ := resp.Text()
    fmt.Println(body)
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

s = httpcloak.Session(preset="chrome-latest")

r = s.get(
    "https://httpbin.org/headers",
    headers={
        "X-My-Header": "hello-world",
        "Authorization": "Bearer xxx",
    },
)
print(r.text)
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```js
const { Session } = require("httpcloak");

const s = new Session({ preset: "chrome-latest" });

const r = await s.get("https://httpbin.org/headers", {
  headers: {
    "X-My-Header": "hello-world",
    "Authorization": "Bearer xxx",
  },
});
console.log(r.text);
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-latest");

var headers = new Dictionary<string, string> {
    { "X-My-Header", "hello-world" },
    { "Authorization", "Bearer xxx" }
};
var r = s.Get("https://httpbin.org/headers", headers: headers);
Console.WriteLine(r.Text);
```

</TabItem>
</Tabs>

httpbin echoes back the headers it saw. You'll spot your `X-My-Header: hello-world` next to the full preset cluster: User-Agent, Accept, sec-ch-ua, and the rest.

### Session-wide defaults

If a header should ride on every request in a session (auth tokens, an `X-API-Key`, a static `Referer`), set it once and leave it.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
// Go has no built-in WithHeaders for session defaults.
// Closure-wrap the session and inject headers in your wrapper:
type apiClient struct {
    s    *httpcloak.Session
    auth string
}

func (c *apiClient) Get(ctx context.Context, url string) (*httpcloak.Response, error) {
    return c.s.Do(ctx, &httpcloak.Request{
        Method: "GET",
        URL:    url,
        Headers: map[string][]string{
            "Authorization": {c.auth},
        },
    })
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
s = httpcloak.Session(preset="chrome-latest")
s.headers.update({"Authorization": "Bearer xxx"})

# now every s.get / s.post / s.request includes the Authorization header
r = s.get("https://httpbin.org/headers")
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```js
const s = new Session({ preset: "chrome-latest" });
s.headers["Authorization"] = "Bearer xxx";

const r = await s.get("https://httpbin.org/headers");
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
// .NET binding doesn't expose a session-default headers bag. Pass headers per request
// or wrap the session in your own class that injects defaults.
```

</TabItem>
</Tabs>

## How merge works

Merge order is preset defaults first, your custom headers second. If your key collides with a preset key (case-insensitive), your value wins. New keys land at the position the preset reserved for them, or at the end if the preset doesn't reserve a slot.

The reserved-slot bit is what matters. The preset's full HPACK position table, separate from the smaller "always emit" set, carves out spots for situational headers like `cache-control`, `content-type`, `content-length`, `cookie`, `origin`, `referer`. So when you add `Content-Type: application/json` on a POST, it lands at the same offset Chrome would have placed it. Without that, your custom headers pile up after `priority`, which is the small kind of drift fingerprinters pick up on.

## Things that don't behave the way you'd expect

- **Casing.** HTTP/2 and HTTP/3 are lowercase on the wire, and the preset stores everything lowercase. Pass `User-Agent: foo` and the lib normalizes it to `user-agent: foo` for H2/H3. On HTTP/1.1, casing is preserved per the request map.
- **Removing a preset header.** Set it to `""` in your headers map and the lib won't emit it. Useful for dropping `Accept-Encoding` or similar defaults.
- **Custom headers vs each other.** Custom headers the preset reserves no slot for are emitted after the preset's own headers, sorted by name. Sorting is deliberate rather than a fallback: the request header map has no insertion order to preserve in the first place, and ranging over it directly — which is what the library used to do — put a different order on the wire for every request, which is its own fingerprint. Sorted is also what a browser sends for `fetch()`, since the Fetch standard sorts field names before they ever reach the network stack.
- **Cookie.** Don't set `Cookie` directly unless you've thought it through. The session jar handles it. See [Per-Request Cookies](../cookies-and-state/per-request-cookies) for the override path.

## Inspecting what went out

The cleanest verification path is sending to [tls.peet.ws/api/all](https://tls.peet.ws/api/all) and reading the `http2.sent_frames` array. Each HEADERS frame lists the headers in the exact order they hit the wire. That's ground truth.

httpbin.org/headers is fine for "did my custom header show up?" checks, but it returns a Python dict, not the wire order. For order, use peet.

## Header order overrides

`SetHeaderOrder(order []string)` mutates the session's emit sequence at runtime. The next request through the session uses the new order on the wire. `GetHeaderOrder()` returns whatever's currently active, custom or preset-default. Pass `nil` or an empty slice to `SetHeaderOrder` and the session falls back to the preset's baked-in order, which is what you want most of the time.

The list you pass is a prefix, not a whole-cloth replacement. The headers you name lead, in the order you named them; the preset's own table then covers every header you left out; anything still unplaced follows, sorted by name. So a short list is a safe way to pin the first few positions without giving up the preset's ordering for everything else. Pass a complete list and the two later passes have nothing left to do, which is the old behaviour exactly.

This is the nuclear option. The preset's order is copied from a real browser capture, and any deviation from it is new fingerprint signal that the target can hash. Use this method only when you've confirmed (with peet output, with a captured PCAP, with vendor docs) that the target runs a header-order check no shipped preset matches. That situation is rare. For nearly every site, `chrome-latest` or `firefox-148` or `safari-18` already lines up.

Header names go in lowercase. HTTP/2 and HTTP/3 send field names lowercase on the wire, the preset stores them lowercase, the transport lowercases anything you pass anyway. Sticking to lowercase in your code keeps the surface boring and matches what tooling like peet shows. The current Chrome desktop order, copied from the table above, looks like this:

```
sec-ch-ua
sec-ch-ua-mobile
sec-ch-ua-platform
upgrade-insecure-requests
user-agent
accept
sec-fetch-site
sec-fetch-mode
sec-fetch-user
sec-fetch-dest
accept-encoding
accept-language
priority
```

Two situations come up in practice. First is rotating between known-good orders mid-session for adversarial probing: dropping into a stripped-down order to see whether the target actually checks order at all, or swapping a Chrome order for a Firefox order on the same TLS connection to test cross-fingerprint detection. Second is pinning an explicit order before a `Save` checkpoint when you want determinism on reload, since the stored config carries the preset name but the runtime override sits on the transport struct.

Heads up on persistence: the custom order is held in memory on the transport. `Save` / `LoadSession` round-trip the preset, cookies, TLS tickets, and ECH configs, but they don't currently serialize a custom header order. If you set a custom order, save the session, then load it, the session comes back on the preset's default. Re-apply your `SetHeaderOrder` call after `LoadSession` if you need the override to stick.

Custom orders don't disable the preset's HPACK position table for situational headers. The preset reserves slots for headers Chrome only emits some of the time (`cache-control`, `content-type`, `content-length`, `cookie`, `origin`, `referer`), and those slots stay live on top of whatever base order you set. So a custom order of `[user-agent, accept, x-my-header]` plus a POST with `Content-Type: application/json` and a `Cookie` from the jar still places `content-type` and `cookie` at the offsets the preset reserves for them, behind the three headers you named. Your list sets the leading sequence; the slot machinery underneath keeps running for everything else.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
s := httpcloak.NewSession("chrome-latest")
defer s.Close()

s.SetHeaderOrder([]string{
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "x-my-header",
})

current := s.GetHeaderOrder()
fmt.Println(current)

// Reset to preset default
s.SetHeaderOrder(nil)
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

s = httpcloak.Session(preset="chrome-latest")

s.set_header_order([
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "x-my-header",
])

print(s.get_header_order())

# Reset to preset default
s.set_header_order([])
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```js
const { Session } = require("httpcloak");

const s = new Session({ preset: "chrome-latest" });

s.setHeaderOrder([
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "user-agent",
  "accept",
  "accept-language",
  "accept-encoding",
  "x-my-header",
]);

console.log(s.getHeaderOrder());

// Reset to preset default
s.setHeaderOrder([]);
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-latest");

s.SetHeaderOrder(new[] {
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "x-my-header",
});

var current = s.GetHeaderOrder();
Console.WriteLine(string.Join(", ", current));

// Reset to preset default
s.SetHeaderOrder(null);
```

</TabItem>
</Tabs>

Verify the result on [tls.peet.ws/api/all](https://tls.peet.ws/api/all). The `http2.sent_frames[].headers` array shows the exact order on the wire after your override, and that's the only place to confirm the change took effect.
