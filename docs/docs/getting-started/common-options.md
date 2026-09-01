---
title: Common Options
sidebar_position: 4
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Common Options

Every HTTP client exposes the same handful of knobs: timeouts, redirects, retries, default headers, cookies. This page covers those for httpcloak. The full option surface lives in [Reference: Options](/reference/options).

## Timeout

`WithSessionTimeout` sets the default timeout for every request on the session. Per-request overrides go through the `Timeout` field on `Request` in Go, or the `timeout` kwarg in the bindings.

The session timeout covers the whole request: DNS, connect, TLS handshake, request send, response read. It does not cover reading the body once `Get` or `Do` has returned. The body read is on you.

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

In Go, the timeout is also bounded by the `context.Context` passed to `Get` or `Do`, and whichever deadline fires first wins. The context handles caller cancellation, the session timeout is the backstop.

## Redirects

Redirects are followed by default, up to 10 hops. You can disable them entirely or just change the cap.

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

When redirects are followed, the response object exposes the full chain through `response.History` (Go), `r.history` (Python and Node), or `Response.History` (.NET). Each entry carries the status, URL, and headers of the intermediate hop. The final URL lands on `FinalURL`, `final_url`, `finalUrl`, or `FinalUrl` depending on the binding.

With redirects off, a 301 or 302 comes back as the response, body and all, with no auto-follow.

### The Referer on a redirect hop

Each hop carries a `Referer` built the way a browser builds one, following Chrome's
default policy: the full previous URL when the hop stays on the same origin, the
origin alone when it crosses to another, and nothing at all on an https to http
downgrade. That is what a browser sends, so leave it alone unless you have a
reason not to.

`disable_redirect_referer` turns it off, for reproducing a client that sends no
`Referer` at all, or replaying a captured chain verbatim.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
resp, err := session.Do(&httpcloak.Request{
    Method:                 "GET",
    URL:                    url,
    DisableRedirectReferer: true,
})
```

</TabItem>
<TabItem value="python" label="Python">

```python
r = session.get(url, disable_redirect_referer=True)
```

</TabItem>
<TabItem value="node" label="Node.js">

```javascript
const r = await session.get(url, { disableRedirectReferer: true });
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
var r = session.Get(url, disableRedirectReferer: true);
```

</TabItem>
</Tabs>

It suppresses the header entirely rather than just skipping the synthesis: a
`Referer` you set on the original request is dropped too, since it names the
pre-redirect URL and forwarding it would hand that to the new host.

## Retries

Retries are off by default. `WithRetry(n)` turns them on with sensible defaults. `WithRetryConfig` tunes the backoff window and the trigger status codes. The default retry-on-status set is `[429, 500, 502, 503, 504]`.

One thing to watch: retries on POST, PUT, and PATCH need a re-readable body. A `bytes.Buffer` or `[]byte`-backed reader works. A one-shot stream does not, since the retry has nothing left to send.

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

Presets ship with a default header set in the order Chrome sends. Most of the time these stay untouched, since matching Chrome is the point. What you'll usually need is to add an `Authorization`, `Cookie`, `Referer`, or some app-specific header on top.

Per-request additions get merged into the preset's order at the correct slot. httpcloak knows where Chrome puts `authorization` relative to `accept`, and so on for every standard header.

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

To lead the preset's header order with headers of your own, use `SetHeaderOrder` on the session. See [Reference: Options](/reference/options) for that one.

## Cookies

The session has a built-in cookie jar. It captures `Set-Cookie` from every response and replays the right cookies on subsequent requests, scoped to domain and path the way browsers do.

The jar is on by default with no opt-in needed. To inspect or seed it, see [Cookies and State](/cookies-and-state).

If cookies are already managed elsewhere (a shared store across many sessions, or proxying for another tool that owns the jar), turn the internal jar off:

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

With the jar off, `Set-Cookie` values are not stored and nothing gets auto-injected on later requests. The `Cookie` header is yours to manage per-request. See [Disabling the Cookie Jar](/cookies-and-state/disabling-cookie-jar) for the full pattern.

## Local source address

A session can be pinned to a specific source IP, which is the move when an IPv6 prefix is routed to the host (cheap rotating egress) or when multiple IPv4 addresses live on the same box. Linux freebind kicks in automatically, so addresses that aren't configured on the interface still bind without `CAP_NET_ADMIN`.

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

IPv4 works the same way. For rotation patterns and freebind details, see [Source Address Binding](/proxies/source-address-binding).

## What's not on this page

- Proxies (HTTP CONNECT, SOCKS5, MASQUE, split TCP/UDP): see [Proxies](/proxies).
- Fingerprint customization (custom JA3, Akamai shorthand, JSON presets): see [Fingerprinting](/fingerprinting).
- Advanced TLS knobs (ECH, key logging, session resumption): see [Advanced TLS](/advanced-tls).
- Streaming uploads/downloads, multipart, redirect history details: see [Requests and Responses](/requests-and-responses).

:::info Full option list
This page covers the everyday set. For the rest (`WithForceHTTP3`, `WithKeyLogFile`, `WithECHFrom`, `WithCustomFingerprint`, `WithSessionCache`, and the rest of the surface), see [Reference: Options](/reference/options).
:::
