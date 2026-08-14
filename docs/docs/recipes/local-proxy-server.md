---
title: Local Proxy Server
sidebar_position: 5
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Local Proxy Server

`LocalProxy` runs httpcloak as a tiny HTTP proxy on `127.0.0.1`. Point any HTTP client at it and the requests going through pick up Chrome-grade TLS fingerprinting on the way out, with the client side staying as it was. No SDK install in the target language, no code changes beyond a proxy URL in the client config.

The use case is having existing code you don't want to rewrite. A Python scraper on `requests`, a Node service on Undici, a Playwright setup, or a .NET app that picked `HttpClient` years ago. All of them speak HTTP-proxy out of the box, so all of them work with this.

The combo this was specifically built for is Undici with Playwright. Playwright drives a real Chrome and emits authentic Chrome cookies and headers in the correct order, but Node's TLS underneath still fingerprints as Node, so the request gets flagged anyway. Routing Playwright through `LocalProxy` in TLS-only mode swaps the TLS layer for httpcloak's while leaving Playwright's headers alone. The same pattern applies to any Node app on Undici; Playwright is just the most common case.

## Quick start

Spin one up. Pick whichever language your control plane lives in:

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
    "log"
    "github.com/sardanioss/httpcloak"
)

func main() {
    lp, err := httpcloak.StartLocalProxy(8080,
        httpcloak.WithProxyPreset("chrome-latest"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer lp.Stop()

    log.Printf("listening on :%d", lp.Port())
    select {} // block forever
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
from httpcloak import LocalProxy

proxy = LocalProxy(port=8080, preset="chrome-latest")
print(f"listening on {proxy.proxy_url}")

try:
    input("Press enter to stop...\n")
finally:
    proxy.close()
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
import { LocalProxy } from "httpcloak";

const proxy = new LocalProxy({ port: 8080, preset: "chrome-latest" });
console.log(`listening on ${proxy.proxyUrl}`);

process.on("SIGINT", () => {
    proxy.close();
    process.exit(0);
});
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var proxy = new LocalProxy(port: 8080, preset: "chrome-latest");
Console.WriteLine($"listening on http://localhost:{proxy.Port}");

Console.WriteLine("Press enter to stop...");
Console.ReadLine();
```

</TabItem>
</Tabs>

Then, from anywhere on the box, point any client at it. One detail decides whether this works at all: request the target as `http://` and add the scheme-upgrade header, rather than requesting `https://` directly.

```bash
curl -x http://127.0.0.1:8080 \
     -H "X-HTTPCloak-Scheme: https" \
     http://tls.peet.ws/api/all
```

The response body holds the JA4, akamai hash and peetprint hash, and they match real Chrome rather than curl's own TLS stack.

:::danger Requesting `https://` through the proxy applies no fingerprint at all
Every mainstream HTTP client, curl included, handles an `https://` URL through a proxy by sending `CONNECT` and then performing **its own** TLS handshake straight through to the target. The proxy is relaying encrypted bytes it cannot read, so the target sees the client's handshake, not the preset's. Nothing errors and you get a real response, which is what makes it easy to miss.

Measured against `tls.peet.ws`, same proxy, same `chrome-latest` preset:

| Client | Pattern | JA4 |
| --- | --- | --- |
| curl | `-x proxy https://target` | `t13d3013h2_1d37bd780c83_...` |
| curl | `-x proxy` + header, `http://target` | `t13d1516h2_8daaf6152771_...` |
| Python `requests` | `proxies=` + `https://target` | `t13d1713h1_ab0a1bf427ad_...` |
| Python `requests` | `proxies=` + header, `http://target` | `t13d1516h2_8daaf6152771_...` |
| Node `undici` | `ProxyAgent` + `https://target` | `t13d5212h1_b262b3658495_...` |
| Node `undici` | `ProxyAgent` + header, `http://target` | `t13d1516h2_8daaf6152771_...` |

The first row of each pair is byte-identical to that client with no proxy configured at all. The same applies to `X-HTTPCloak-Session`: on a `CONNECT` request your headers travel inside the tunnel, so the proxy never reads them and session routing silently does nothing.

The `.NET` binding wraps this for you, see `LocalProxy.CreateClient()` on the [.NET page](/bindings/dotnet). For every other language, use the header.
:::

:::tip
The proxy binds to `127.0.0.1` only, never `0.0.0.0`. That's deliberate. You don't want a fingerprinting proxy reachable from your LAN by accident. If you need it on a different host, run it inside that host or front it with something like `socat` or an SSH tunnel you actually trust.
:::

## How it works

`LocalProxy` runs two paths inside one server, and which one fires depends on what the client sends:

- **HTTP-proxy-style request** (`GET http://target/path HTTP/1.1`): the proxy forwards it through `Session.DoStream()` and the full TLS+H2 fingerprint stack lights up. This is the path where fingerprinting actually happens.
- **CONNECT tunnel** (`CONNECT target:443 HTTP/1.1`): the proxy opens a raw TCP tunnel to the target and then steps out of the way. TLS happens directly between the client and the target so the proxy is just plumbing, and fingerprinting falls back to whatever the client's TLS stack does (which, if you're reading this, probably isn't great).

Most HTTP clients use CONNECT for HTTPS by default, which puts them on the tunnel path. The proxy never sees the TLS, so it can't fingerprint it. To force the request onto the fingerprint-applying path, set this header:

```
X-HTTPCloak-Scheme: https
```

When the header is present, the proxy treats the request as HTTP-proxy-style, upgrades the URL to HTTPS internally, and runs it through `Session.DoStream()`. The TLS handshake on the wire then comes from httpcloak instead of the client. Without the header, the client tunnels via CONNECT and the handshake comes from the client's own TLS stack, so the proxy adds nothing.

Plain HTTP requests (no scheme upgrade) skip `Session` entirely and get forwarded by a stock `http.Client`. There's no TLS to fingerprint on plain HTTP.

## Options

Pass these to `StartLocalProxy(port, opts...)` (Go) or as kwargs to the binding constructors:

| Option | What it does |
| --- | --- |
| `WithProxyPreset(name)` | The fingerprint preset. `chrome-latest`, `firefox-148`, `safari-18`, etc. Default is `chrome-146`. |
| `WithProxyTimeout(d)` | Per-request timeout. Default 30s. |
| `WithProxyMaxConnections(n)` | Hard cap on concurrent client connections. Anything above gets dropped at accept. Default 1000. |
| `WithProxyUpstream(tcp, udp)` | Chain through an upstream proxy. SOCKS5 or HTTP for `tcp`, MASQUE for `udp`. Both are optional. |
| `WithProxyTLSOnly()` | Skip the preset's HTTP headers. Pass client headers through unchanged. Use when your client already ships authentic browser headers (Playwright, Undici, real browsers driven by CDP). |
| `WithProxySessionCache(backend, errCb)` | Plug in a distributed TLS session ticket cache. Lets multiple LocalProxy instances share resumption state. |

Pass `0` as the port to let the kernel pick one, then read it back with `lp.Port()`.

## Special headers

The proxy reads four request headers to drive per-request behavior. They get stripped before the request goes upstream.

| Header | What it does |
| --- | --- |
| `X-HTTPCloak-Session` | Routes the request through a registered session by ID. See [Session registry](#session-registry) below. |
| `X-HTTPCloak-TlsOnly` | Per-request override of the TLS-only mode. `"true"` skips preset headers, `"false"` applies them, omitting the header uses the proxy's global setting. |
| `X-HTTPCloak-Scheme` | Set to `"https"` to upgrade an HTTP-proxy-style request to HTTPS with full fingerprinting. The trick that gets fingerprinting working from clients that would otherwise CONNECT-tunnel. |
| `X-Upstream-Proxy` | Per-request upstream proxy override (HTTP-proxy-style requests only). |

For HTTPS / CONNECT requests the upstream-proxy override goes through `Proxy-Authorization` instead, since `X-Upstream-Proxy` won't actually survive the CONNECT step (most clients drop arbitrary headers on CONNECT requests):

```
Proxy-Authorization: HTTPCloak http://user:pass@upstream.example.com:8080
```

The `HTTPCloak` scheme is the per-request signal, and the proxy strips this header before forwarding so the upstream never sees it. Regular `Basic` / `Bearer` auth headers in the same `Proxy-Authorization` slot pass through untouched, so this doesn't break any auth setup you already have.

## TLSOnly mode

By default, `LocalProxy` applies the preset's HTTP headers to every forwarded request. That covers User-Agent, sec-ch-ua, Accept-Language, and the rest of the Chrome header bundle. For a client like stock `requests` or `HttpClient` that emits its own non-browser User-Agent (`python-requests/2.31.0`, `Go-http-client/1.1`), this is the correct behavior; the preset headers are what makes the request look like a browser at all.

For a client that already emits authentic browser headers, this is wrong. Playwright drives a real Chrome and sends real Chrome headers in the correct order, which is what bot vendors actually check for. Replacing those with preset stand-ins makes the fingerprint worse, not better, because no synthetic header bundle matches a real browser as exactly as the bundle a real browser produces.

`WithProxyTLSOnly()` skips the preset headers. The proxy passes the client's headers through unmodified and only fingerprints the TLS layer underneath. Combined with `X-HTTPCloak-Scheme: https`, the result is the client's real headers riding on httpcloak's TLS handshake:

- Playwright's authentic headers, untouched
- httpcloak's TLS handshake on the wire (uTLS, real Chrome cipher list, extension order, the whole shape)

Wire it up like this from a Node service running Undici:

<Tabs groupId="lang">
<TabItem value="node" label="Node.js (Undici)">

```js
import { LocalProxy } from "httpcloak";
import { fetch, ProxyAgent } from "undici";

const proxy = new LocalProxy({ port: 8080, preset: "chrome-latest", tlsOnly: true });
const dispatcher = new ProxyAgent(proxy.proxyUrl);

// Tell the proxy to upgrade this HTTP request to HTTPS with fingerprinting
const r = await fetch("http://tls.peet.ws/api/all", {
    dispatcher,
    headers: { "X-HTTPCloak-Scheme": "https" },
});

console.log((await r.json()).tls.ja4);
proxy.close();
```

Notice the URL is `http://`, not `https://`. That's deliberate. Plain HTTP plus the scheme-upgrade header keeps the request out of CONNECT and into the fingerprinting path. The proxy sees the `https` upgrade and treats the target as HTTPS.

</TabItem>
<TabItem value="playwright" label="Playwright">

```js
import { chromium } from "playwright";
import { LocalProxy } from "httpcloak";

const proxy = new LocalProxy({ port: 8080, preset: "chrome-latest", tlsOnly: true });

const browser = await chromium.launch({
    proxy: { server: `http://localhost:${proxy.port}` },
});
const ctx = await browser.newContext({
    extraHTTPHeaders: { "X-HTTPCloak-Scheme": "https" },
});
const page = await ctx.newPage();
await page.goto("https://tls.peet.ws/api/all");
console.log(await page.content());

await browser.close();
proxy.close();
```

Playwright sets the scheme-upgrade header on every navigation via `extraHTTPHeaders`, then the proxy handles the rest. Real Chrome cookies, real Chrome headers, httpcloak's TLS on the wire.

</TabItem>
<TabItem value="python" label="Python (requests)">

```python
from httpcloak import LocalProxy
import requests

proxy = LocalProxy(port=8080, preset="chrome-latest", tls_only=True)

# requests sends its own User-Agent, but with TLS-only mode, that's what gets used
r = requests.get(
    "http://tls.peet.ws/api/all",
    proxies={"http": proxy.proxy_url, "https": proxy.proxy_url},
    headers={"X-HTTPCloak-Scheme": "https"},
)
print(r.json()["tls"]["ja4"])
proxy.close()
```

</TabItem>
</Tabs>

When not to use `TLSOnly`: any client that doesn't already produce authentic browser headers. Stock `requests`, generic Go `net/http`, plain `curl` without `--user-agent`. The User-Agent alone gives the request away on those clients, and no TLS-layer fingerprinting recovers from it. The preset headers are doing real work in those cases; leave them on.

## Session registry

Sometimes you want one proxy port to serve different "users", each with their own cookies, IP, and TLS resumption state. That's the registry. Pre-build sessions, register them with an ID, the client picks one per-request via `X-HTTPCloak-Session`.

```go
lp, _ := httpcloak.StartLocalProxy(8080, httpcloak.WithProxyPreset("chrome-latest"))
defer lp.Stop()

alice := httpcloak.NewSession("chrome-latest",
    httpcloak.WithSessionTCPProxy("socks5://user1:pass@residential.example:1080"))
bob := httpcloak.NewSession("firefox-148",
    httpcloak.WithSessionTCPProxy("socks5://user2:pass@residential.example:1080"))

lp.RegisterSession("alice", alice)
lp.RegisterSession("bob", bob)
```

From the client side, set the header. Note the `http://` target and the scheme upgrade: on a `CONNECT` request the session header rides inside the tunnel where the proxy cannot read it, so the routing would silently fall back to the default session.

```bash
curl -x http://127.0.0.1:8080 \
     -H "X-HTTPCloak-Session: alice" \
     -H "X-HTTPCloak-Scheme: https" \
     http://example.com/profile
```

| Method (Go) | What it does | Bindings |
| --- | --- | --- |
| `RegisterSession(id, *Session) error` | Adds a session under `id`. Errors if `id` is taken. Calls `SetSessionIdentifier(id)` on the session so distributed TLS caches stay isolated per persona. | `register_session` (Python), `registerSession` (Node), `RegisterSession` (.NET) |
| `UnregisterSession(id) *Session` | Removes the session and returns it. Does NOT close it. That's your call, since you might reuse it. | `unregister_session` (Python), `unregisterSession` (Node), `UnregisterSession` (.NET) |
| `GetSession(id) *Session` | Direct lookup. Returns `nil` if missing. | Go-only at this release |
| `ListSessions() []string` | All registered IDs. Handy for `/health` endpoints. | `list_sessions` (Python), `listSessions` (Node), `ListSessions` (.NET) |
| `HasSession(id) bool` | Existence check for one ID. Cheaper than scanning `ListSessions()`. | `has_session` (Python), `hasSession` (Node), `HasSession` (.NET) |

Unknown session IDs return a 400 from the proxy, so typos surface fast instead of silently falling back to the default session.

The session identifier matters when a distributed cache is wired up (next section). `RegisterSession` calls `session.SetSessionIdentifier(id)` so cache keys get namespaced per registered session. Without it, two sessions hitting the same host share cache entries and end up reusing each other's TLS tickets. The visible failure mode is one session getting flagged and the rest inheriting the reputation through the shared ticket.

:::info
The registry is a routing layer, not a state layer. Sessions you register stay normal `*Session` values. Same options, same cookie jar, same `Refresh()` semantics. You can swap their proxies on the fly with `SetTCPProxy`, the next request through the registry picks up the change.
:::

## Distributed TLS session cache

Running more than one `LocalProxy` instance behind a load balancer turns the in-memory session cache into a per-instance cache. Each replica starts cold and the first request to any new host pays a full TLS handshake, since the other replicas' tickets aren't reachable.

`WithProxySessionCache` replaces the in-memory store with an external backend so all instances share resumption state. A request that lands on a replica which has never seen the host before still gets 0-RTT resumption, as long as some other replica has handled the handshake earlier.

The interface lives in `transport/tls_cache.go` and has five methods covering TLS tickets and ECH config caching:

```go
type SessionCacheBackend interface {
    Get(ctx context.Context, key string) (*TLSSessionState, error)
    Put(ctx context.Context, key string, session *TLSSessionState, ttl time.Duration) error
    Delete(ctx context.Context, key string) error
    GetECHConfig(ctx context.Context, key string) ([]byte, error)
    PutECHConfig(ctx context.Context, key string, config []byte, ttl time.Duration) error
}
```

`TLSSessionState` is a small struct holding the base64 ticket, the base64 session state, and a creation timestamp. The ECH methods are only consulted on the H3 path, so returning `(nil, nil)` from both is fine if you don't care about HTTP/3 ECH resumption.

A Redis-backed implementation looks like this:

```go
type RedisCache struct {
    client *redis.Client
}

func (r *RedisCache) Get(ctx context.Context, key string) (*transport.TLSSessionState, error) {
    val, err := r.client.Get(ctx, key).Bytes()
    if err == redis.Nil {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    var state transport.TLSSessionState
    if err := json.Unmarshal(val, &state); err != nil {
        return nil, err
    }
    return &state, nil
}

func (r *RedisCache) Put(ctx context.Context, key string, session *transport.TLSSessionState, ttl time.Duration) error {
    payload, err := json.Marshal(session)
    if err != nil {
        return err
    }
    return r.client.Set(ctx, key, payload, ttl).Err()
}

// Delete + GetECHConfig + PutECHConfig follow the same pattern.
// See /advanced-tls/session-cache for a complete example.

// Wire it in:
lp, _ := httpcloak.StartLocalProxy(8080,
    httpcloak.WithProxyPreset("chrome-latest"),
    httpcloak.WithProxySessionCache(&RedisCache{client: redisClient}, func(operation, key string, err error) {
        log.Printf("session cache error: op=%s key=%s err=%v", operation, key, err)
    }),
)
```

The error callback fires on any backend failure (network error, Redis unavailable, etc). It's advisory only. The proxy doesn't fail the request on cache errors; it falls back to a full handshake on that connection. Pipe the callback into a logger or metrics sink and treat it as observability, not error handling.

Cache keys carry the session identifier when one is set (see registry section above), so a multi-tenant proxy with multiple registered sessions stays isolated even when they share a backend.

## Lifecycle and stats

The returned `*LocalProxy` is the whole control surface:

| Method | What it returns / does |
| --- | --- |
| `Stop() error` | Graceful shutdown. Closes the listener, waits up to 10s for in-flight requests, closes the underlying session and idle conns. Idempotent. |
| `Port() int` | The port the proxy actually bound to. Useful when you started with `0`. |
| `IsRunning() bool` | True between successful start and `Stop`. |
| `Stats() map[string]interface{}` | Snapshot. Briefly holds the session-registry read lock to count registered sessions; otherwise atomic loads. |

Go `Stats()` returns:

| Key | Type | Meaning |
| --- | --- | --- |
| `running` | `bool` | Whether the listener is up. |
| `port` | `int` | Bound port. |
| `active_conns` | `int64` | Connections currently being served. |
| `total_requests` | `int64` | Lifetime request count. |
| `preset` | `string` | The preset name. |
| `max_connections` | `int` | The cap from `WithProxyMaxConnections`. |
| `registered_sessions` | `int` | Count of entries in the session registry. |

Wire `Stop()` into your shutdown handler, scrape `Stats()` into Prometheus on a 15-second interval, you're set.

The binding Stats shapes differ from Go and from each other:

- **.NET `GetStats()`** returns a `LocalProxyStats` class with `Running`, `Port`, `ActiveConnections`, `TotalRequests`, `Preset`, `MaxConnections`. The `registered_sessions` field is not deserialized into the typed object; if you need it from .NET, parse the underlying JSON yourself.
- **Node `getStats()`** returns the Go map JSON.parse'd as-is, with the snake_case keys: `running`, `port`, `active_conns`, `total_requests`, `preset`, `max_connections`, `registered_sessions`. The `LocalProxyStats` TS interface mirrors these field names exactly.
- **Python `get_stats()`** returns a dict mirroring the Go map keys.

## Multi-proxy pattern

Multiple `LocalProxy` instances can run in the same process on different ports, each pinned to a different preset. Useful when one app talks to two targets that expect different browsers, or when you want to A/B fingerprints behind a feature flag.

```go
chrome, _ := httpcloak.StartLocalProxy(8080, httpcloak.WithProxyPreset("chrome-latest"))
firefox, _ := httpcloak.StartLocalProxy(8081, httpcloak.WithProxyPreset("firefox-148"))
safari, _ := httpcloak.StartLocalProxy(8082, httpcloak.WithProxyPreset("safari-18"))
defer chrome.Stop()
defer firefox.Stop()
defer safari.Stop()
```

Then route from the client by port:

```python
import requests

CHROME = {"http": "http://127.0.0.1:8080"}
FIREFOX = {"http": "http://127.0.0.1:8081"}
UPGRADE = {"X-HTTPCloak-Scheme": "https"}

# Chrome for the API
api = requests.get("http://api.example.com/...", proxies=CHROME, headers=UPGRADE)

# Firefox for the legacy site that hates Chrome
legacy = requests.get("http://legacy.example.com/...", proxies=FIREFOX, headers=UPGRADE)
```

Each instance is fully isolated. Own connection pool, own cookies, own stats. Three proxies cost roughly 3x the memory of one and one extra goroutine per accept loop, which is negligible at proxy scale.

## Hitting the proxy from any language

The whole point is that you don't need an httpcloak SDK in the calling language. Standard HTTP-proxy config does it.

<Tabs groupId="lang">
<TabItem value="python" label="Python">

```python
import requests

proxies = {"http": "http://127.0.0.1:8080"}

headers = {
    "X-HTTPCloak-Scheme": "https",   # required, see the warning above
    "X-HTTPCloak-Session": "alice",  # per-request session pick
}

# http:// target, upgraded by the proxy. https:// here would bypass everything.
r = requests.get("http://tls.peet.ws/api/all", proxies=proxies, headers=headers)
print(r.json()["tls"]["ja4"])
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
import { fetch, ProxyAgent } from "undici";

const dispatcher = new ProxyAgent("http://127.0.0.1:8080");

// http:// target, upgraded by the proxy. https:// here would bypass everything.
const r = await fetch("http://tls.peet.ws/api/all", {
    dispatcher,
    headers: {
        "X-HTTPCloak-Scheme": "https",
        "X-HTTPCloak-Session": "alice",
    },
});

console.log((await r.json()).tls.ja4);
```

</TabItem>
<TabItem value="go" label="Go">

```go
proxyURL, _ := url.Parse("http://127.0.0.1:8080")
client := &http.Client{
    Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
}
// http:// target, upgraded by the proxy. https:// here would bypass everything.
req, _ := http.NewRequest("GET", "http://tls.peet.ws/api/all", nil)
req.Header.Set("X-HTTPCloak-Scheme", "https")
req.Header.Set("X-HTTPCloak-Session", "alice")
resp, _ := client.Do(req)
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

// CreateClient does the http:// rewrite and the scheme header for you, so an
// https:// URL here is fine. A bare HttpClientHandler pointed at the proxy URL
// is NOT, see the warning above.
using var client = proxy.CreateClient();
client.DefaultRequestHeaders.Add("X-HTTPCloak-Session", "alice");

var r = await client.GetStringAsync("https://tls.peet.ws/api/all");
Console.WriteLine(r);
```

</TabItem>
<TabItem value="curl" label="curl">

```bash
curl -x http://127.0.0.1:8080 \
     -H "X-HTTPCloak-Scheme: https" \
     -H "X-HTTPCloak-Session: alice" \
     http://tls.peet.ws/api/all
```

</TabItem>
</Tabs>

For the Undici / Playwright drop-in path with `TLSOnly`, see the [TLSOnly mode](#tlsonly-mode) section above.

## What's next

- [Multi-Proxy Rotation With State](./multi-proxy-rotation-with-state): rotate IPs under a single registered session without burning tickets.
- [Long-Running Scraper Patterns](./long-running-scraper-patterns): lifecycle and refresh strategies that play nicely with the registry.
