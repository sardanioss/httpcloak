---
title: Disabling the Cookie Jar
sidebar_position: 3
---

# Disabling the Cookie Jar

`WithoutCookieJar()` (added in 1.6.6) is a session option that turns the internal jar off. With it set, `Set-Cookie` headers from responses are not stored, the jar is not consulted when building the next request's `Cookie` header, and `GetCookies()` returns an empty list. Caller-provided `Cookie` headers still pass through untouched; the only thing the flag suppresses is the lib's own auto-injection.

## When to reach for it

A few situations where switching the jar off is the right call:

- **You manage cookies yourself.** An application-level cookie store in Redis, Postgres, or anywhere else, owns the truth. You read from there, build the `Cookie` header per request, and don't want the lib layering anything on top.
- **You want each request fully independent.** Useful for fan-out crawling where two requests on the same session shouldn't share state.
- **You're debugging.** When you're trying to figure out why a response sets a particular cookie, having the jar silently swallow and replay it makes the trace harder to read. Switch it off and watch the raw headers.

Outside of those, leave the jar on. The default behaviour matches what most calling code expects.

## Code

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
	"context"
	"fmt"
	"io"

	"github.com/sardanioss/httpcloak"
)

func main() {
	s := httpcloak.NewSession("chrome-152", httpcloak.WithoutCookieJar())
	defer s.Close()

	ctx := context.Background()

	r1, _ := s.Get(ctx, "https://httpbin.org/cookies/set?demo=hello")
	r1.Close()

	r2, _ := s.Get(ctx, "https://httpbin.org/cookies")
	body, _ := io.ReadAll(r2.Body)
	r2.Close()
	fmt.Println(string(body))
	// {"cookies": {}} (jar didn't store anything)

	fmt.Println(s.GetCookies()) // []
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with httpcloak.Session(preset="chrome-152", without_cookie_jar=True) as s:
    s.get("https://httpbin.org/cookies/set?demo=hello")
    r = s.get("https://httpbin.org/cookies")
    print(r.json())
    # {'cookies': {}}
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```js
const httpcloak = require("httpcloak");

const s = new httpcloak.Session({
  preset: "chrome-152",
  withoutCookieJar: true,
});
try {
  await s.get("https://httpbin.org/cookies/set?demo=hello");
  const r = await s.get("https://httpbin.org/cookies");
  console.log(r.json());
  // { cookies: {} }
} finally {
  s.close();
}
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-152", withoutCookieJar: true);

s.Get("https://httpbin.org/cookies/set?demo=hello");
var r = s.Get("https://httpbin.org/cookies");
Console.WriteLine(r.Text);
// {"cookies": {}}
```

</TabItem>
</Tabs>

## Managing cookies yourself

With the jar off, the calling code owns cookie state. Two patterns cover most cases:

1. **Send a `Cookie` header per request.** Build the string yourself and attach it to the request headers. See [Per-Request Cookies](./per-request-cookies) for examples in each language.
2. **Pull `Set-Cookie` out of the response.** Each `Response` exposes its raw headers; parse `Set-Cookie` yourself and stash the result wherever your store lives.

:::info Headers still pass through
Even with the jar off, the `Cookie` header set on a request goes out byte-for-byte as written. The flag only suppresses the lib's auto-injection; manual headers are unaffected.
:::

## Mixing modes

`WithoutCookieJar` is a session option, set once at construction, and can't be toggled mid-session. To run both modes side by side (jar-on for one workflow, jar-off for another), build two sessions.

For shared TLS state across the two, `Fork()` creates a sibling that carries the same TLS resumption cache while starting fresh on other state. One thing to watch: forks share the cookie jar pointer with the parent, so a fork from a jar-enabled session ends up sharing the jar. Genuinely separate cookie state needs a fresh session built from scratch.
