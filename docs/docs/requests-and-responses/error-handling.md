---
title: Error Handling
sidebar_position: 6
---

# Error Handling

Errors come in two flavors and they're not the same thing:

1. **Network / protocol errors.** DNS failed, connection refused, TLS handshake blew up, or the request timed out before a response. Either it never made it, or it made it and the server never replied. These come back as a Go `error`, a Python exception, a Node thrown error, or a .NET exception.

2. **Real responses with a non-2xx status.** The server got the request, processed it, didn't like it, and sent back `404` or `500` or similar. The HTTP exchange completed. These come back as normal Response objects, and the caller checks `StatusCode`.

Mixing them up is the most common bug in this space. A 500 isn't a network error. The server told you no, and the connection is fine.

## The split, with code

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
resp, err := s.Get(ctx, url)
if err != nil {
    // Network / protocol / context error. No response.
    return err
}
defer resp.Close()

if resp.StatusCode >= 500 {
    // Server-side error. The exchange completed.
    return fmt.Errorf("server error: %d", resp.StatusCode)
}
if resp.StatusCode >= 400 {
    // Client-side error. You sent something the server rejected.
    return fmt.Errorf("client error: %d", resp.StatusCode)
}

// 2xx. We're good.
body, _ := resp.Bytes()
```

</TabItem>
<TabItem value="python" label="Python">

```python
try:
    r = s.get(url)
except httpcloak.HTTPCloakError as e:
    # Network / protocol / context error
    raise

if r.status_code >= 500:
    raise RuntimeError(f"server error: {r.status_code}")
if r.status_code >= 400:
    raise RuntimeError(f"client error: {r.status_code}")
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```js
let r;
try {
  r = await s.get(url);
} catch (e) {
  // Network / protocol error
  throw e;
}

if (r.statusCode >= 500) throw new Error(`server error: ${r.statusCode}`);
if (r.statusCode >= 400) throw new Error(`client error: ${r.statusCode}`);
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
Response r;
try {
    r = s.Get(url);
} catch (HttpCloakException e) {
    // Network / protocol error
    throw;
}

if (r.StatusCode >= 500) throw new Exception($"server error: {r.StatusCode}");
if (r.StatusCode >= 400) throw new Exception($"client error: {r.StatusCode}");
```

</TabItem>
</Tabs>

## Common error shapes

These come back as a real error, not a Response:

### DNS failure

```
dns_resolve nope.example: lookup nope.example: no such host
```

In Go, this wraps a `*net.DNSError`. Check `IsNotFound`, `IsTemporary`, `IsTimeout` on it.

```go
var dnsErr *net.DNSError
if errors.As(err, &dnsErr) {
    if dnsErr.IsNotFound { /* domain doesn't exist */ }
    if dnsErr.IsTimeout  { /* DNS server didn't reply in time */ }
}
```

In other bindings the message string contains `dns_resolve` or `lookup`.

### Connection refused

```
dial example.com: dial tcp 1.2.3.4:443: connect: connection refused
```

Server isn't listening, or a firewall is dropping it. Same shape across all bindings.

### TLS handshake failure

```
tls: handshake failure
remote error: tls: protocol_version
```

Could be a cert mismatch, an expired cert, a server that only speaks TLS 1.3 with your config disabling it, or an anti-bot system rejecting your fingerprint at TLS level. The message usually carries a hint, though they're not always easy to read.

### Timeout

```
context deadline exceeded
i/o timeout
```

In Go, `errors.Is(err, context.DeadlineExceeded)` returns true when the request didn't finish before your context deadline. There's also a wrapped `*net.OpError` with `Timeout() == true` for raw socket timeouts.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

_, err := s.Get(ctx, "https://httpbin.org/delay/10")
if errors.Is(err, context.DeadlineExceeded) {
    // we hit our timeout
}
```

### Cancellation

```
context canceled
```

Same as timeout but voluntary. `errors.Is(err, context.Canceled)`.

## What's a real response (not an error)

These come back as a populated `Response` with a status code, not as an error:

- `4xx`: Bad Request, Unauthorized, Forbidden, Not Found, Method Not Allowed, the usual suspects.
- `5xx`: Server errors, Bad Gateway, Service Unavailable, Gateway Timeout.
- `3xx` redirects (when the lib stops following them, e.g. with `WithoutRedirects()`, `Request.FollowRedirects`, or an `OnRedirect` callback returning `ErrUseLastResponse`).
- Empty bodies, unexpected Content-Types, malformed JSON in the body.

The HTTP exchange completed and the server replied. Whether the caller treats it as a failure is business logic, not a transport concern.

## Redirect errors that still carry a response

Two redirect failures hand back a non-nil `Response` *and* a non-nil error. The
response is the 3xx that ended the chain, so you can read its `Location` and
decide what to do rather than only learning that something went wrong. Ignoring
it leaks nothing — the body is already buffered, and closing it is a no-op.

```go
resp, err := s.Do(ctx, req)
if errors.Is(err, httpcloak.ErrTooManyRedirects) {
    loc, _ := resp.Location() // where the chain had got to
}
```

| Sentinel | When |
|---|---|
| `ErrTooManyRedirects` | The chain exceeded the cap. `client.Client` returns the same sentinel but no response: at the point it detects the cap it has not built one. |
| `ErrBodyNotReplayable` | A 307 or 308 needed the request body a second time, but it was a one-shot stream with no `Request.GetBody` to re-open it. The hop is refused rather than sent with an empty body. See [Redirects](/reference/options#bodies-on-307-and-308). |

An error returned from your own `OnRedirect` callback comes back unwrapped, so
`errors.Is` against your own sentinel matches what you returned.

## Typed errors (Go)

The transport package wraps every network-side error in a `transport.TransportError` carrying enough context to skip string-matching the message. The struct is what `errors.As` unwraps into, and the package ships predicates for the common questions.

```go
type TransportError struct {
    Op       string  // "dial", "tls_handshake", "request", "dns_resolve", ...
    Host     string
    Port     string
    Protocol string  // "h1", "h2", "h3"
    Cause    error   // the underlying net/tls/dns error
    Category error   // ErrConnection, ErrTLS, ErrDNS, ErrTimeout, ErrProxy, ErrProtocol, ErrRequest, ErrResponse, ErrClosed
    Retryable bool
}
```

`TransportError` implements `Error`, `Unwrap`, and `Is`. `Is(target)` matches on either the category sentinel (`ErrTLS`, `ErrDNS`, etc.) or the wrapped cause, so `errors.Is(err, transport.ErrTLS)` works whether the error came back from the lib's TLS dial or from a deeper cause that string-matches a TLS keyword.

The five predicates cover the common branches without you having to reach into the struct yourself:

```go
import "github.com/sardanioss/httpcloak/transport"

if transport.IsTimeout(err) { /* deadline / i/o timeout */ }
if transport.IsTLSError(err) { /* handshake / cert / x509 */ }
if transport.IsDNSError(err) { /* lookup failed */ }
if transport.IsConnectionError(err) { /* refused / reset / unreachable */ }
if transport.IsProxyError(err) { /* proxy hop failed */ }
```

When you want the structured fields:

```go
var te *transport.TransportError
if errors.As(err, &te) {
    log.Printf("op=%s host=%s:%s proto=%s retryable=%v cause=%v",
        te.Op, te.Host, te.Port, te.Protocol, te.Retryable, te.Cause)

    if te.Retryable {
        // one safe place to gate retries: the wrapper already decided
    }
}
```

`Retryable` is the lib's opinion on whether the underlying cause is worth retrying. Timeouts and DNS failures are flagged retryable; TLS handshake failures and proxy auth errors are not. The retry config (`WithRetryConfig`) reads this same flag, so a custom retry loop and the built-in retry agree on which errors to bounce.

### `ALPNMismatchError`

A separate type, returned from H2 dials when the server's TLS hello negotiates `http/1.1` instead. The error carries the live `*utls.UConn` so the H1 path can reuse it without a fresh handshake.

```go
var ame *transport.ALPNMismatchError
if errors.As(err, &ame) {
    // ame.TLSConn is the open TLS conn, ame.Negotiated is "http/1.1"
}
```

You usually don't see this surface in user code; the lib handles it internally inside `doAuto` and the H2 race. It matters when you're driving the transport manually.

### `HTTPError`

Wraps a non-success response in a typed error for callers who explicitly opted into "raise on bad status". Returned from `Response.RaiseForStatus()` (and the binding equivalents) and from any caller that uses `transport.NewHTTPError`:

```go
type HTTPError struct {
    StatusCode int
    Status     string
    Body       []byte
    Headers    map[string]string
}

(*HTTPError).IsClientError() bool   // 4xx
(*HTTPError).IsServerError() bool   // 5xx
(*HTTPError).IsRetryable()  bool    // 408, 425, 429, 500, 502, 503, 504
```

The default response handler does NOT raise on 4xx/5xx. Go callers check `resp.StatusCode` directly and construct an `*HTTPError` with `transport.NewHTTPError` when they want a typed wrapper. The bindings ship a `RaiseForStatus()` / `raise_for_status()` shortcut on the response object, but Go has no equivalent on `*Response`. See [Hooks](./hooks) for a hook-driven pattern that emits `HTTPError` from a status filter.

## Retry guidance

:::warning
Don't retry on 4xx. The server told you no for a reason. Retrying just hammers it and won't change the outcome. Fix the request.
:::

Rough rules:

| Situation | Retry? |
|---|---|
| Network error (DNS, refused, reset) | Yes, with backoff |
| Timeout | Yes, but bump the deadline if the upstream is slow |
| TLS handshake failure | No, fix the config |
| 4xx | No |
| 5xx + idempotent verb (GET, HEAD, PUT, DELETE) | Yes |
| 5xx + POST/PATCH | Only if you're sure the server didn't already process it. POST is **not** idempotent. |
| 429 Too Many Requests | Yes, but back off harder. Honor `Retry-After` if present. |

The session has built-in retry support. The default is off. Issue #57 flipped the default from 3 to 0 because the old behavior silently retried POSTs on 5xx and broke idempotency assumptions:

```go
s := httpcloak.NewSession("chrome-latest",
    httpcloak.WithRetry(3),
    // or fine-grained:
    httpcloak.WithRetryConfig(3, 500*time.Millisecond, 10*time.Second, []int{500, 502, 503, 504}),
)
```

Pass status codes you want to retry on. Don't blindly retry on 4xx.

## A timeout test

The easiest way to verify timeout handling is to hit `httpbin.org/delay/N` with a context shorter than N.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()

_, err := s.Get(ctx, "https://httpbin.org/delay/10")
fmt.Println(err)
// dial httpbin.org [h1]: dial tcp4 ...: i/o timeout
fmt.Println(errors.Is(err, context.DeadlineExceeded))
// true
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

s = httpcloak.Session(preset="chrome-latest", timeout=2)
try:
    r = s.get("https://httpbin.org/delay/10")
except httpcloak.HTTPCloakError as e:
    print("timed out:", e)
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```js
const s = new Session({ preset: "chrome-latest", timeout: 2 });
try {
  await s.get("https://httpbin.org/delay/10");
} catch (e) {
  console.log("timed out:", e.message);
}
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using var s = new Session(preset: "chrome-latest", timeout: 2);
try {
    s.Get("https://httpbin.org/delay/10");
} catch (HttpCloakException e) {
    Console.WriteLine($"timed out: {e.Message}");
}
```

</TabItem>
</Tabs>

`/delay/10` makes the server sit on the request for 10 seconds. With a 2-second timeout you get back a deadline-exceeded error and no Response.

## Logging tip

When debugging unknown failures in prod, log three things:

1. The full error message (don't strip the wrap chain).
2. The error's Go type (or Python class) so you can pattern-match later.
3. The status code and a tail of the body, when a Response made it back.

The error message alone isn't always enough to tell DNS-failed from timeout-on-DNS-server. The type usually is.
