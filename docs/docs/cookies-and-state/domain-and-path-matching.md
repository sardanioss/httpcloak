---
title: Domain and Path Matching
sidebar_position: 5
---

# Domain and Path Matching

The jar runs four checks before a stored cookie rides out on a request: domain, path, secure, expiry. Each one decides whether the cookie belongs on this particular call, and a wrong setting on any of them either leaks the cookie to a host that shouldn't see it or silently drops it from a request that should have carried it. This page covers the rules httpcloak's jar follows and the edge cases that catch most callers out.

## Domain matching

A cookie's domain is set in one of two ways:

- **No `Domain` attribute on `Set-Cookie`.** The cookie is **host-only**. It only goes back to the exact host that set it.
- **`Domain=foo.example.com` (with or without leading dot).** The cookie is a **domain cookie**. It goes back to `foo.example.com` and any subdomain.

Examples with a request to `https://api.example.com/`:

| Stored `Domain` | Type | Sent? |
|---|---|---|
| (none, set by `api.example.com`) | host-only | yes |
| (none, set by `example.com`) | host-only | no |
| `.example.com` | domain | yes |
| `example.com` | domain | yes (modern, see note) |
| `.api.example.com` | domain | yes |
| `.other.com` | domain | no |

:::caution Leading dot, RFC vs reality
Strict RFC 2109 read `Domain=example.com` (no leading dot) as "exactly example.com". RFC 6265 and every modern browser treat the same string as if it had been written `.example.com`, which includes subdomains. When httpcloak parses `Set-Cookie` from a response, it follows the modern behaviour: stored with the leading dot internally, matches subdomains.

One thing to watch: the programmatic `SetCookie()` / `set_cookie()` API currently stores the same string `Domain="example.com"` (no leading dot) as **host-only**, which is the older RFC 2109 reading. That's an asymmetry between response-header parsing and the manual API. To register a domain cookie through the API, write the leading dot explicitly: `Domain=".example.com"`.
:::

A response also can't set a cookie for a domain it doesn't control. If `api.example.com` returns `Set-Cookie: x=1; Domain=other.com`, the jar rejects it. The request host has to equal the cookie domain or sit beneath it as a subdomain.

## Path matching

The path rule is a prefix match with a `/` boundary. A cookie set for `Path=/api` matches:

- `/api` (exact)
- `/api/` (cookie path is a prefix and the next char is `/`)
- `/api/foo`
- `/api/foo/bar`

It does **not** match:

- `/apixyz` (next char isn't `/`)
- `/foo/api` (cookie path isn't a prefix)
- `/` (request path is shorter)

If the cookie path ends in `/`, like `Path=/api/`, the slash boundary is implicit and any request path that starts with that exact prefix matches.

When `Set-Cookie` doesn't include `Path`, httpcloak defaults it to `/`, which matches every request to that domain.

## Secure flag

A cookie carrying the `Secure` flag only rides out on HTTPS. Even when domain, path, and expiry all match, a plain `http://` request won't see it.

The same rule applies on the way in: a server can only **set** a `Secure` cookie over HTTPS. If `Set-Cookie: x=1; Secure` arrives on a plain HTTP response, the jar rejects it before storing.

## Expiry

The jar checks expiry at send time. A cookie whose `Expires` is in the past gets skipped on the next outbound match. A session cookie (no `Expires`, no `Max-Age`) lives until the session is closed or `ClearCookies()` is called.

The jar doesn't sweep expired cookies eagerly. They get filtered at send time but stay resident in the map until then. There's no public `ClearExpired()` on `Session` (the method exists only on the internal `*CookieJar`). For a forced sweep, `ClearCookies()` empties everything; cookies still valid get refetched on the next round-trip.

## Worked example

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
s := httpcloak.NewSession("chrome-152")
defer s.Close()

// host-only scoping: bare domain via the API stores as host-only
s.SetCookie(httpcloak.CookieInfo{
	Name: "scoped", Value: "yes",
	Domain: "httpbin.org", Path: "/cookies",
})

ctx := context.Background()

r1, _ := s.Get(ctx, "https://httpbin.org/cookies")
// matches → {"cookies": {"scoped": "yes"}}
r1.Close()

r2, _ := s.Get(ctx, "https://httpbin.org/anything")
// path /anything doesn't match /cookies → cookie not sent
r2.Close()
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with httpcloak.Session(preset="chrome-152") as s:
    s.set_cookie(
        name="scoped",
        value="yes",
        domain="httpbin.org",
        path="/cookies",
    )

    r1 = s.get("https://httpbin.org/cookies")
    print(r1.json())
    # {'cookies': {'scoped': 'yes'}}

    r2 = s.get("https://httpbin.org/anything")
    # cookie not sent, path /anything doesn't match /cookies
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```js
const httpcloak = require("httpcloak");

const s = new httpcloak.Session({ preset: "chrome-152" });
try {
  s.setCookie("scoped", "yes", {
    domain: "httpbin.org",
    path: "/cookies",
  });

  let r = await s.get("https://httpbin.org/cookies");
  console.log(r.json());
  // { cookies: { scoped: 'yes' } }

  r = await s.get("https://httpbin.org/anything");
  // cookie not sent
} finally {
  s.close();
}
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-152");

s.SetCookie("scoped", "yes", domain: "httpbin.org", path: "/cookies");

var r1 = s.Get("https://httpbin.org/cookies");
Console.WriteLine(r1.Text);
// {"cookies": {"scoped": "yes"}}

var r2 = s.Get("https://httpbin.org/anything");
// cookie not sent
```

</TabItem>
</Tabs>

## Common gotchas

- **Host-only intent, but `Domain` was set.** Adding `Domain=example.com` makes the cookie ride out to every subdomain. To keep it on `example.com` itself, omit the `Domain` attribute entirely.
- **Path looks like it matches but doesn't.** `/api` does not match `/apiv2`. The boundary check requires a `/` after the prefix or exact equality.
- **Secure cookie sent on an HTTP response.** Some local dev setups proxy through plain HTTP. The jar won't store a `Secure` cookie if the response that delivered it wasn't HTTPS.
- **`Domain` set for a host the response doesn't own.** A response from `a.com` setting `Domain=b.com` gets rejected. Cross-site cookie injection isn't something the jar will help with.
- **Expiry forgotten on long-lived sessions.** A cookie with `Max-Age=10` is gone in ten seconds, and the jar quietly stops sending it. When a server-side flow appears to log out for no reason, check cookie expiry first.

:::warning Don't leak cookies to subdomains
A `Domain` attribute on a manually set cookie opts the cookie into subdomain delivery for the rest of its life, which can leak it to hosts you didn't intend. The browser's behaviour is to leave `Domain` empty on host-only cookies; match that pattern when setting cookies through the API.
:::
