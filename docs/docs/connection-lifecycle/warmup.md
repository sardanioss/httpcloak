---
title: Warmup
sidebar_position: 2
---

# Warmup

`Warmup(ctx, url)` runs a multi-hop preflight that mimics what a browser does when a user types a URL and hits enter. It loads the HTML, parses out the stylesheets, scripts, images and fonts the page references, then fetches them in parallel with browser-style headers and timing. By the time it returns, the session holds cookies, cache validators, TLS tickets and ECH state consistent with a tab that's already been used.

## Why bother

Cold-start fingerprinting catches a lot of bots. The first request from a fresh session can have correct header order and a clean JA3, but the timing and the request graph give it away. There's no Referer chain. The cookie jar is empty. No cache-validation headers. No subresource fetches. The site never sent an `Accept-CH`, so no high-entropy client hints come back on the next hop. Each gap on its own isn't decisive, but together they describe a connection that opened solely to grab one specific endpoint, which is the canonical bot shape.

`Warmup` covers most of that in one call. It:

- Fetches the navigation HTML with proper Sec-Fetch headers.
- Parses the HTML for `<link>`, `<script>`, `<img>` and `<link rel="preload">` references.
- Splits them into priority groups: CSS and fonts first, then scripts, then images.
- Fires each batch concurrently (up to 6 in flight, matching Chrome's per-host H1 connection limit) with 50-300ms gaps between batches.
- Picks up Set-Cookie headers along the way.
- Records the page's `Accept-CH`, so the high-entropy client hints it asks for go out on the next request to it. As in Chrome, a subresource's `Accept-CH` is not honoured; only a top-level navigation's is.
- Caches ETag and Last-Modified so the next request to the same URL ships conditional headers.
- Lets the TLS layer cache session tickets for every host hit.

By the time it returns, the next request from the session looks like the user clicked through to it, not like the connection just opened to grab it.

## Common pattern

Warm up against the home page, then hit the endpoint you actually care about.

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
s := httpcloak.NewSession("chrome-latest")
defer s.Close()
ctx := context.Background()

// Warm up against the target. Loads HTML, fetches CSS/JS/images,
// grabs whatever cookies the site sets.
if err := s.Warmup(ctx, "https://tls.peet.ws/api/all"); err != nil {
	panic(err)
}
fmt.Printf("cookies: %d\n", len(s.GetCookies()))

// Now the actual request, with tickets, cookies and a believable history
// already in place.
r, _ := s.Get(ctx, "https://tls.peet.ws/api/all")
defer r.Close()
fmt.Printf("status=%d proto=%s\n", r.StatusCode, r.Protocol)
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with httpcloak.Session(preset="chrome-latest") as s:
    s.warmup("https://tls.peet.ws/api/all", timeout=60000)
    print("cookies:", len(s.get_cookies()))

    r = s.get("https://tls.peet.ws/api/all")
    print(r.status_code, r.headers.get("content-type"))
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```javascript
const httpcloak = require("httpcloak");

const s = new httpcloak.Session({ preset: "chrome-latest" });
try {
  s.warmup("https://tls.peet.ws/api/all", { timeout: 60000 });
  console.log("cookies:", s.getCookies().length);

  const r = await s.get("https://tls.peet.ws/api/all");
  console.log(r.statusCode);
} finally {
  s.close();
}
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-latest");

s.Warmup("https://tls.peet.ws/api/all", timeoutMs: 60000);
Console.WriteLine($"cookies: {s.GetCookies().Count}");

var r = s.Get("https://tls.peet.ws/api/all");
Console.WriteLine($"status={r.StatusCode}");
```

</TabItem>
</Tabs>

## What gets populated

| State after Warmup | Source |
| --- | --- |
| Cookies | Set-Cookie from the page and every subresource |
| TLS session tickets | One per origin touched during warmup |
| ECH config cache | DNS HTTPS records seen during the navigation |
| Cache validators (ETag, Last-Modified) | Per-URL response headers |
| Client hints map | `Accept-CH` from the navigation's response |
| Header order memory | Already preset-driven, no drift |
| Cookie jar size | Whatever the site sets, often 5-20 |

If the warmed page redirects (301/302), the redirect chain is followed and cookies set along the way land in the jar with the right domain scoping.

## Edge cases worth knowing

Warmup caps at 50 subresources. Big news sites reference 200+ images on a single page, so the cap exists to keep the call from running forever. Subresource fetch failures are silent, which matches browser behaviour where one broken image shouldn't kill the whole page load. If the navigation URL returns something other than `text/html`, warmup returns nil after the navigation. TLS and cookies still populate, the subresource crawl is just skipped.

The inter-batch delays (50-150ms before scripts, 100-300ms before images) are randomised per call, so back-to-back warmups don't share an identical timing fingerprint.

## When NOT to warmup

- The target endpoint is on a different origin from any plausible home page. Cookies set on site A don't help requests against site B.
- You're inside a tight retry loop. Warming up before every retry is overkill.
- The target is a JSON-only API that never sets cookies. The request graph adds bandwidth and gives you nothing back.

For those cases, skip `Warmup`, or call it once at session creation and not again.

## Warmup vs Refresh

These aren't interchangeable. `Refresh()` closes connections without touching state. `Warmup()` does the opposite: leaves connections alone and pumps state into the session. The typical pipeline is one `Warmup` at startup followed by periodic `Refresh()` calls.

`Warmup` respects the context. Cancel it and the call returns the context error after the in-flight batch finishes.
