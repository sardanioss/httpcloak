---
title: Common Options
sidebar_position: 4
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Common Options

Every HTTP client has the same handful of knobs. Timeouts, redirects, retries, default headers, cookies. This page covers those for httpcloak. Nothing fancy here, just the everyday stuff you'll reach for in week one.

For the full option surface, including everything not covered on this page, see [Reference: Options](/reference/options).

## Timeout

`WithSessionTimeout` is the default timeout for every request on the session. You can override it per-request via the `Timeout` field on `Request` (or `timeout` kwarg on the bindings).

The session timeout covers the whole request: DNS, connect, TLS handshake, request send, response read. It does not cover reading the body once `Get`/`Do` has returned, you handle that yourself.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
sess := httpcloak.NewSession("chrome-latest",
	httpcloak.WithSessionTimeout(10*time.Second),
)
```

</TabItem>
<TabItem value="python" label="Python">

```python
session = httpcloak.Session(preset="chrome-latest", timeout=10)
```

</TabItem>
<TabItem value="node" label="Node.js">

```javascript
const session = new Session({ preset: "chrome-latest", timeout: 10 });
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using var session = new Session(preset: "chrome-latest", timeout: 10);
```

</TabItem>
</Tabs>

In Go, the timeout is also bounded by the `context.Context` you pass to `Get`/`Do`. Whichever fires first wins. Use the context for caller cancellation, the session timeout as a backstop.

## Redirects

By default httpcloak follows redirects, up to 10 hops. You can turn that off, or change the cap.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
// Don't follow at all
noRedir := httpcloak.NewSession("chrome-latest", httpcloak.WithoutRedirects())

// Follow but cap at 5
capped := httpcloak.NewSession("chrome-latest", httpcloak.WithRedirects(true, 5))
```

</TabItem>
<TabItem value="python" label="Python">

```python
no_redir = httpcloak.Session(preset="chrome-latest", allow_redirects=False)
capped   = httpcloak.Session(preset="chrome-latest", max_redirects=5)
```

</TabItem>
<TabItem value="node" label="Node.js">

```javascript
const noRedir = new Session({ preset: "chrome-latest", allowRedirects: false });
const capped  = new Session({ preset: "chrome-latest", maxRedirects: 5 });
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using var noRedir = new Session(preset: "chrome-latest", allowRedirects: false);
using var capped  = new Session(preset: "chrome-latest", maxRedirects: 5);
```

</TabItem>
</Tabs>

When redirects are followed, the response object exposes the chain via `response.History` (Go), `r.history` (Python), `r.history` (Node), `Response.History` (.NET). Each entry has the status, URL, and headers of the intermediate hop. The final URL is on `FinalURL` / `final_url` / `finalUrl` / `FinalUrl`.

When redirects are off, a 301/302/etc just comes back as the response, body and all. No magic.

## Retries

Retries are off by default. Turn them on with `WithRetry(n)` for sane defaults, or `WithRetryConfig` to tune the backoff window and which status codes trigger a retry. Default retry-on-status when you enable retries is `[429, 500, 502, 503, 504]`.

Important: retries on POST/PUT/PATCH bodies require the body to be re-readable. Pass a `bytes.Buffer` or a `[]byte`-backed reader, not a one-shot stream, or the retry won't have anything to send.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
// 3 retries with default 500ms-10s exponential backoff on default statuses
sess := httpcloak.NewSession("chrome-latest", httpcloak.WithRetry(3))

// Custom: 5 retries, 1s-30s backoff, only 429 and 503
tuned := httpcloak.NewSession("chrome-latest",
	httpcloak.WithRetryConfig(5, 1*time.Second, 30*time.Second, []int{429, 503}),
)
```

</TabItem>
<TabItem value="python" label="Python">

```python
session = httpcloak.Session(preset="chrome-latest", retry=3)

tuned = httpcloak.Session(
    preset="chrome-latest",
    retry=5,
    retry_wait_min=1000,   # ms
    retry_wait_max=30000,  # ms
    retry_on_status=[429, 503],
)
```

</TabItem>
<TabItem value="node" label="Node.js">

```javascript
const session = new Session({ preset: "chrome-latest", retry: 3 });

const tuned = new Session({
  preset: "chrome-latest",
  retry: 5,
  retryWaitMin: 1000,
  retryWaitMax: 30000,
  retryOnStatus: [429, 503],
});
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using var session = new Session(preset: "chrome-latest", retry: 3);

using var tuned = new Session(
    preset: "chrome-latest",
    retry: 5,
    retryWaitMin: 1000,
    retryWaitMax: 30000,
    retryOnStatus: new[] { 429, 503 });
```

</TabItem>
</Tabs>

## Custom headers

Presets ship with a default header set in the right order. Most of the time you don't want to touch this, the whole point is to look like Chrome. But you'll usually need to add an `Authorization`, `Cookie`, `Referer`, or app-specific header.

Add them per-request. They get merged into the preset's order at the right slot (httpcloak knows where Chrome puts authorization vs accept etc).

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
resp, err := sess.Do(ctx, &httpcloak.Request{
	Method: "GET",
	URL:    "https://httpbin.org/headers",
	Headers: map[string][]string{
		"Authorization": {"Bearer abc123"},
		"X-Request-Id":  {"42"},
	},
})
```

</TabItem>
<TabItem value="python" label="Python">

```python
r = session.get(
    "https://httpbin.org/headers",
    headers={"Authorization": "Bearer abc123", "X-Request-Id": "42"},
)
```

</TabItem>
<TabItem value="node" label="Node.js">

```javascript
const r = await session.get("https://httpbin.org/headers", {
  headers: { Authorization: "Bearer abc123", "X-Request-Id": "42" },
});
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
var r = session.Get("https://httpbin.org/headers", headers: new() {
    ["Authorization"] = "Bearer abc123",
    ["X-Request-Id"]  = "42",
});
```

</TabItem>
</Tabs>

If you need to override the preset's header order entirely, that's a separate concern (`SetHeaderOrder` on the session, see [Reference: Options](/reference/options)).

## Cookies

The session has a built-in cookie jar that captures `Set-Cookie` from every response and replays the right cookies on subsequent requests, scoped to domain/path the way browsers do it.

That just works out of the box. You don't need to opt in. If you want to inspect or seed the jar, see [Cookies and State](/cookies-and-state).

If your app already manages cookies somewhere else (e.g., shared store across many sessions, or you're proxying for another tool that owns the jar), turn the internal jar off:

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
sess := httpcloak.NewSession("chrome-latest", httpcloak.WithoutCookieJar())
```

</TabItem>
<TabItem value="python" label="Python">

```python
session = httpcloak.Session(preset="chrome-latest", without_cookie_jar=True)
```

</TabItem>
<TabItem value="node" label="Node.js">

```javascript
const session = new Session({ preset: "chrome-latest", withoutCookieJar: true });
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using var session = new Session(preset: "chrome-latest", withoutCookieJar: true);
```

</TabItem>
</Tabs>

When the jar is off, `Set-Cookie` values from responses aren't stored, and nothing gets auto-injected on subsequent requests. You handle the `Cookie` header yourself per-request. See [Disabling the Cookie Jar](/cookies-and-state/disabling-cookie-jar) for the full pattern.

## Local source address

If you've got an IPv6 prefix routed to your host (cheap rotating egress) or multiple IPv4 addresses on one box, you can pin a session to a specific source IP. Linux freebind kicks in automatically so you don't have to configure each address on the interface.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
sess := httpcloak.NewSession("chrome-latest",
	httpcloak.WithLocalAddress("2001:db8::1234"),
)
```

</TabItem>
<TabItem value="python" label="Python">

```python
session = httpcloak.Session(preset="chrome-latest", local_address="2001:db8::1234")
```

</TabItem>
<TabItem value="node" label="Node.js">

```javascript
const session = new Session({ preset: "chrome-latest", localAddress: "2001:db8::1234" });
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using var session = new Session(preset: "chrome-latest", localAddress: "2001:db8::1234");
```

</TabItem>
</Tabs>

Works for IPv4 too. For the rotation patterns and freebind details, see [Source Address Binding](/proxies/source-address-binding).

## What's not on this page

- Proxies (HTTP CONNECT, SOCKS5, MASQUE, split TCP/UDP): see [Proxies](/proxies).
- Fingerprint customization (custom JA3, Akamai shorthand, JSON presets): see [Fingerprinting](/fingerprinting).
- Advanced TLS knobs (ECH, key logging, session resumption): see [Advanced TLS](/advanced-tls).
- Streaming uploads/downloads, multipart, redirect history details: see [Requests and Responses](/requests-and-responses).

:::info Full option list
The options here are the everyday set. For everything else (`WithForceHTTP3`, `WithKeyLogFile`, `WithECHFrom`, `WithCustomFingerprint`, `WithSessionCache`, etc.), see [Reference: Options](/reference/options).
:::
