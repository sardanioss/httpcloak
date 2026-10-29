---
title: Authentication
sidebar_position: 6
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Authentication

A static `Authorization` header you can hand-roll. For anything more involved than that, the auth helpers carry their weight: they know the wire format, they keep the header at the offset Chrome would emit it from, and Digest runs the challenge-response loop for you. Three flavors ship: Basic, Bearer, and Digest.

The Authorization header is one fingerprinters watch for ordering drift. Going through the helpers lands it in the slot the preset reserved, not bolted onto the end after the rest of the headers.

## The Auth interface

Every helper satisfies the same small interface:

```go
type Auth interface {
    Apply(req *http.Request) error
    HandleChallenge(resp *http.Response, req *http.Request) (bool, error)
}
```

`Apply` writes the Authorization header onto the outgoing request. `HandleChallenge` is the second-pass hook: when the server returns a 401, the client calls `HandleChallenge` so the auth scheme can read `WWW-Authenticate`, compute what to send back, and tell the client whether to retry. Basic and Bearer don't have a challenge dance, so their `HandleChallenge` always returns `false`. Digest runs the full nonce/cnonce exchange.

## Basic

Username and password, base64-encoded, prefixed with `Basic `. That's the entire scheme.

```go
auth := client.NewBasicAuth("user", "passwd")
// or, on the client itself:
c.SetBasicAuth("user", "passwd")
```

`SetBasicAuth` is the shortcut. It builds a `BasicAuth` and parks it on the client so every request from that point gets the header. `NewBasicAuth` returns the value when you want to scope it per-request via `Request.Auth`.

## Bearer

Same shape, different scheme. Pass the token in, get `Authorization: Bearer <token>` on every request.

```go
auth := client.NewBearerAuth("eyJhbGc...")
// or:
c.SetBearerAuth("eyJhbGc...")
```

:::tip
Tokens expire. For rotating tokens (OAuth refresh, short-lived JWTs, signed STS creds), don't bake the token into the client at construction. Wrap your refresh logic and call `SetBearerAuth` again whenever the token rolls. Or, when requests come from different identities, skip the session setter entirely and stamp `Request.Auth = client.NewBearerAuth(token)` on each call so a stale token never leaks into the wrong request.
:::

## Digest

Digest is the picky one. The server hands you a `WWW-Authenticate: Digest realm=..., nonce=..., qop=...` on the first 401. The scheme hashes username + password + realm into HA1, hashes method + URI into HA2, then hashes those together with the nonce, a counter, and a cnonce you generate. That hash goes back as `Authorization: Digest response="..."`. The client runs the second leg automatically:

```go
auth := client.NewDigestAuth("user", "passwd")
c.SetAuth(auth)
```

Flow on the wire:

1. Request fires with no Authorization header (Digest doesn't pre-emptively send).
2. Server replies 401 with the `WWW-Authenticate` challenge.
3. `HandleChallenge` parses realm, nonce, qop, opaque, algorithm.
4. Client retries the same request, this time with the computed `Digest response=...`.
5. Server returns the real response.

If the server answers that response with another challenge, the credentials were wrong. The client returns that 401 rather than answering again, and forgets the challenge, so the next request starts over with no Authorization header. That is where Chrome and Firefox drop the credentials and ask the user, and where curl returns the 401. There are two exceptions. A challenge with `stale=true` means the nonce expired but the credentials were right, so the client sends the request again with an answer to the new nonce. And a reused `DigestAuth` answers the last challenge it saw up front, before the server asks: if the server has moved to a new nonce in the meantime without saying `stale=true`, the client answers the new one once, as Chrome does when the same credentials are given again, and returns the 401 only if that answer is refused too. A hop's request goes out at most 32 times, as in Chrome, after which the last 401 comes back. The bound holds for any `Auth` whose `HandleChallenge` keeps asking for a retry.

The nonce-counter (`nc`) starts at `00000001` for each challenge and increments on every reuse, so the same `DigestAuth` value can ride multiple requests without re-challenging. Discard it once the credentials change.

## Custom schemes via SetAuth

For a target that speaks something less standard (HMAC-SHA256 signed requests, AWS SigV4, a custom token-and-timestamp scheme), implement the `Auth` interface yourself and hand it to `SetAuth`:

```go
type myAuth struct { secret string }

func (a *myAuth) Apply(req *http.Request) error {
    sig := sign(req, a.secret)
    req.Header.Set("Authorization", "MyScheme "+sig)
    return nil
}

func (a *myAuth) HandleChallenge(resp *http.Response, req *http.Request) (bool, error) {
    return false, nil
}

c.SetAuth(&myAuth{secret: "..."})
```

`Apply` runs once per request right before send. If the signature depends on the body, hash it from the request before Apply returns. If it depends on a timestamp, generate a fresh one each call.

## Try it: Basic auth against httpbin

httpbin's `/basic-auth/user/passwd` endpoint returns 401 without credentials and 200 with the right ones. A quick way to confirm the helper is wiring the header.

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
    "context"
    "fmt"
    "io"

    "github.com/sardanioss/httpcloak/client"
)

func main() {
    c := client.NewClient("chrome-latest")
    defer c.Close()

    ctx := context.Background()

    // Without auth: 401
    resp, _ := c.Get(ctx, "https://httpbin.org/basic-auth/user/passwd", nil)
    fmt.Println("no-auth:", resp.StatusCode)
    resp.Body.Close()

    // With BasicAuth: 200
    c.SetBasicAuth("user", "passwd")
    resp, _ = c.Get(ctx, "https://httpbin.org/basic-auth/user/passwd", nil)
    fmt.Println("with-auth:", resp.StatusCode)
    body, _ := io.ReadAll(resp.Body)
    resp.Body.Close()
    fmt.Println(string(body))
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with httpcloak.Session(preset="chrome-latest") as s:
    # Without auth: 401
    r = s.get("https://httpbin.org/basic-auth/user/passwd")
    print("no-auth:", r.status_code)

    # With auth tuple: 200
    r = s.get(
        "https://httpbin.org/basic-auth/user/passwd",
        auth=("user", "passwd"),
    )
    print("with-auth:", r.status_code)
    print(r.text)
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```js
const { Session } = require("httpcloak");

const s = new Session({ preset: "chrome-latest" });

// Without auth: 401
let r = await s.get("https://httpbin.org/basic-auth/user/passwd");
console.log("no-auth:", r.statusCode);

// With Authorization header: 200
const creds = Buffer.from("user:passwd").toString("base64");
r = await s.get("https://httpbin.org/basic-auth/user/passwd", {
  headers: { Authorization: `Basic ${creds}` },
});
console.log("with-auth:", r.statusCode);
console.log(r.text);

s.close();
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;
using System;
using System.Text;

using var s = new Session(preset: "chrome-latest");

// Without auth: 401
var r = s.Get("https://httpbin.org/basic-auth/user/passwd");
Console.WriteLine($"no-auth: {r.StatusCode}");

// With auth header: 200
var creds = Convert.ToBase64String(Encoding.ASCII.GetBytes("user:passwd"));
var headers = new Dictionary<string, string> {
    { "Authorization", $"Basic {creds}" }
};
r = s.Get("https://httpbin.org/basic-auth/user/passwd", headers: headers);
Console.WriteLine($"with-auth: {r.StatusCode}");
Console.WriteLine(r.Text);
```

</TabItem>
</Tabs>

Run the Go example and you'll see:

```text
no-auth: 401
with-auth: 200
{
  "authenticated": true,
  "user": "user"
}
```

## Per-request vs session-level

Two scopes, same idea as headers.

Session-level (the `Set*Auth` family on the client) parks an Auth on the client. Every request from that point gets it applied automatically. The fit is "this whole script is one identity".

Per-request (the `Auth` field on `Request`) overrides the session-level Auth for one call. When both are set, the request-level wins. The fit is one client juggling multiple identities, or mostly anonymous traffic with a handful of endpoints that need credentials.

```go
// session default
c.SetBearerAuth("anon-token")

// this single request uses a different token
resp, _ := c.Do(ctx, &client.Request{
    Method: "GET",
    URL:    "https://api.example.com/admin",
    Auth:   client.NewBearerAuth("admin-token"),
})
```

One safety bit lives in the redirect handler: a redirect that crosses origins drops `Authorization` and `Proxy-Authorization` before following. The same rule applies to HTTPS-to-HTTP downgrades. It holds for both scopes: once a hop leaves the origin the request started on, neither the client's Auth nor `Request.Auth` is applied to it or to any hop after it, even one that comes back to that origin. Browsers behave the same way, and httpcloak matches that, so credentials don't leak to whatever domain the response bounces to.
