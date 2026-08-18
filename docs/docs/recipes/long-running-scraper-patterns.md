---
title: Long-Running Scraper Patterns
sidebar_position: 3
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Long-Running Scraper Patterns

A long-running scraper is one that holds a `Session` open for hours or days and reuses it across many requests. Two problems show up at that timescale:

1. **Connections age out.** Servers and load balancers close idle keep-alive connections, and some kill them mid-flight. The TLS tickets and 0-RTT setup that came with the original handshake get dropped along with them.
2. **Session fingerprints get tracked.** A scraper that holds one TCP connection open for hours does not look like a browser. Real browsers cycle connections constantly as tabs open, close, and time out.

The patterns in this recipe handle both: periodic `Refresh()` to mirror browser connection cycling, `Warmup()` at startup, deliberate cookie strategy, and Save/Load across process restarts.

## Pattern 1: Periodic Refresh

Browsers do not sit on TCP connections for hours. Keepalives expire, tabs close, the user navigates away, and the connection drops. A scraper should mirror that rhythm.

`session.Refresh()` drops every live connection but keeps:

- TLS session tickets (the next handshake is 0-RTT)
- Cookies
- ECH config
- Preset plus any custom fingerprint overrides

The next request opens a fresh TCP socket and resumes TLS instantly with the same cookies. From the server's view that looks like a returning visitor with a slightly older session, which is what real browsers look like.

:::warning
Don't refresh after every request. That defeats session continuity. The cadence is minutes, not seconds.
:::

A reasonable default is every two to five minutes:

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/sardanioss/httpcloak"
)

func main() {
    s := httpcloak.NewSession("chrome-latest", httpcloak.WithSessionTimeout(30*time.Second))
    defer s.Close()

    // Refresh ticker. Reasonable cadence: 2-5 min.
    refreshEvery := 3 * time.Minute
    nextRefresh := time.Now().Add(refreshEvery)

    for i := 0; i < 1000; i++ {
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        r, err := s.Get(ctx, "https://example.com/page")
        cancel()
        if err != nil {
            fmt.Println("err:", err)
            time.Sleep(5 * time.Second)
            continue
        }
        r.Close()

        if time.Now().After(nextRefresh) {
            s.Refresh()
            nextRefresh = time.Now().Add(refreshEvery)
            fmt.Println("refreshed")
        }
    }
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import time
import httpcloak

with httpcloak.Session("chrome-latest", timeout=30) as s:
    refresh_every = 180  # seconds
    next_refresh = time.time() + refresh_every

    for i in range(1000):
        try:
            r = s.get("https://example.com/page")
        except Exception as e:
            print("err:", e)
            time.sleep(5)
            continue

        if time.time() > next_refresh:
            s.refresh()
            next_refresh = time.time() + refresh_every
            print("refreshed")
```

</TabItem>
</Tabs>

A scraper sending one request every 30 seconds and refreshing on the same cadence pays for a fresh TCP and TLS handshake on every request. Even with 0-RTT that is wasted RTT. The right place for a refresh is an idle gap, not the start of every request.

## Pattern 2: Warmup at startup

`Warmup(ctx, url)` mimics a real browser page load. It fetches the page HTML, parses it, and pulls the obvious subresources (CSS, JS, fonts) with realistic headers, priorities, and request ordering.

After warmup runs, the session holds:

- TLS session tickets for the target's edge servers
- Cookies set by the page and its subresources (analytics, CDN cookies)
- Cache headers (ETag, Last-Modified) ready for follow-up requests

The first scrape request after warmup looks like a second navigation inside an open tab rather than a cold first hit, which is a much weaker signal for bot detection to grab onto.

```go
s := httpcloak.NewSession("chrome-latest")
defer s.Close()

ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
defer cancel()

// One-time warmup. Hit the home page or a typical entry page.
if err := s.Warmup(ctx, "https://example.com"); err != nil {
    log.Printf("warmup soft-fail: %v", err)
    // Don't bail, warmup is opportunistic. If it fails, scrape anyway.
}

// Now run your scrape loop. The session has CDN cookies, tickets,
// and cache state populated.
scrapeLoop(ctx, s)
```

Warmup is opportunistic. If the home page fails or hits a challenge, log it and keep going. The scrape loop should handle missing warmup state on its own.

:::tip
For a target with a heavy login flow, do the authenticated warmup once per process: log in, navigate, save with `Save()`. Subsequent runs call `LoadSession()` and start scraping immediately without re-running the login dance.
:::

## Pattern 3: Cookie strategy

Sessions ship with a cookie jar by default: one jar per session, shared across every request the session sends.

Three patterns cover almost every use case:

### One session, one target

The default. A shared cookie jar means every request through the session sees the same cookies.

```go
s := httpcloak.NewSession("chrome-latest")
// Hit target.com 1000 times. All requests share the cookie jar.
```

### N sessions, N targets (jar isolation)

For a scraper hitting several different targets, one session per target is almost always the right shape. Cookies stay scoped to the right host and there's no risk of jar entries leaking between unrelated sites.

```go
sessions := map[string]*httpcloak.Session{
    "site-a.com": httpcloak.NewSession("chrome-latest"),
    "site-b.com": httpcloak.NewSession("chrome-latest"),
    "site-c.com": httpcloak.NewSession("chrome-latest"),
}
defer func() {
    for _, s := range sessions {
        s.Close()
    }
}()

// Route each request to the right session by host.
```

Side benefit: each session warms up independently against its own target, and Save/Load works per-session.

### Manual cookie management

Some setups need cookie state managed outside the jar: sharing one cookie across multiple sessions, A/B testing two cookie sets against the same site, or driving session state from an external store. For those, use `WithoutCookieJar()` and set the `Cookie` header by hand on each request:

```go
s := httpcloak.NewSession("chrome-latest", httpcloak.WithoutCookieJar())

req := &httpcloak.Request{
    Method: "GET",
    URL:    "https://example.com/page",
    Headers: map[string][]string{
        "Cookie": {"session=abc123; csrf=xyz"},
    },
}
resp, _ := s.Do(ctx, req)
```

The trade-off is automatic cookie tracking. Set-Cookie response headers are now the caller's responsibility to parse and persist. Most scrapers should stay on the default jar.

## Pattern 4: Save / LoadSession across restarts

For a scraper that runs for hours and may crash or restart, persisting state to disk turns a process bounce into a non-event. Save periodically, and load on startup. Warmed-up tickets, ECH config, and cookies all survive.

```go
const stateFile = "/var/lib/scraper/state.json"

func main() {
    var s *httpcloak.Session

    // Try to load from disk. If it fails, start fresh.
    if loaded, err := httpcloak.LoadSession(stateFile); err == nil {
        s = loaded
        log.Println("loaded state from disk")
    } else {
        s = httpcloak.NewSession("chrome-latest")
        // Cold-start warmup.
        ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
        s.Warmup(ctx, "https://example.com")
        cancel()
    }
    defer s.Close()

    // Save every 5 minutes.
    saveTicker := time.NewTicker(5 * time.Minute)
    defer saveTicker.Stop()

    go func() {
        for range saveTicker.C {
            if err := s.Save(stateFile); err != nil {
                log.Printf("save: %v", err)
            }
        }
    }()

    // Save on shutdown.
    defer func() {
        if err := s.Save(stateFile); err != nil {
            log.Printf("save on shutdown: %v", err)
        }
    }()

    scrapeLoop(s)
}
```

For setups where a file is not the right place, `Marshal()` and `UnmarshalSession()` serialise to bytes (Redis, S3, anywhere else):

```go
data, _ := s.Marshal()
redisClient.Set(ctx, "scraper:state", data, 24*time.Hour)

// Later:
data, _ := redisClient.Get(ctx, "scraper:state").Bytes()
s, _ := httpcloak.UnmarshalSession(data)
```

## Putting it together

The full long-running pattern, in pseudocode shape:

```go
func main() {
    s := loadOrCreate("state.json")
    defer s.Close()
    defer s.Save("state.json")

    refreshEvery := 3 * time.Minute
    saveEvery := 5 * time.Minute

    nextRefresh := time.Now().Add(refreshEvery)
    nextSave := time.Now().Add(saveEvery)

    for {
        url, ok := nextWorkItem()
        if !ok {
            break
        }

        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        resp, err := s.Get(ctx, url)
        cancel()

        if err != nil {
            handleError(err)
            continue
        }
        process(resp)
        resp.Close()

        if time.Now().After(nextRefresh) {
            s.Refresh()
            nextRefresh = time.Now().Add(refreshEvery)
        }
        if time.Now().After(nextSave) {
            s.Save("state.json")
            nextSave = time.Now().Add(saveEvery)
        }
    }
}

func loadOrCreate(path string) *httpcloak.Session {
    if s, err := httpcloak.LoadSession(path); err == nil {
        return s
    }
    s := httpcloak.NewSession("chrome-latest")
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()
    s.Warmup(ctx, "https://example.com")
    return s
}
```

Tune the cadences to the target. A scraper hammering one host per second wants longer refresh intervals so it doesn't cycle TCP under load. A scraper running once a minute can refresh every five to ten minutes without any downside.

## Things to NOT do

- **Don't refresh on every request.** That throws away the connection benefit you just paid the handshake for.
- **Don't save state on every request.** Disk IO ends up dominating. Every few minutes is plenty.
- **Don't share one session across very different targets.** Cookies in the jar are scoped per-host, but session-level state (TLS tickets, ECH config) crosses targets. One session per target keeps everything tidy.
- **Don't forget `resp.Close()`.** Body leaks tie up connection resources and make `Refresh()` less effective, since the connection it would have dropped is still bound to a leaked body.
- **Don't `Close()` a session other goroutines are still reading from.** `Close()` drops every connection at once, so a worker halfway through a response body gets "use of closed network connection". When you retire a live session (rotating identities, swapping proxies), call `CloseGraceful()` instead: it refuses new requests immediately and lets each in-flight body finish before its connection goes away.

## Forking sessions for parallel scrapes

For N parallel workers hitting the same target with shared warm state, use `Fork(n)`:

```go
s := httpcloak.NewSession("chrome-latest")
s.Warmup(ctx, "https://example.com")

workers := s.Fork(8)
var wg sync.WaitGroup
for _, w := range workers {
    wg.Add(1)
    go func(w *httpcloak.Session) {
        defer wg.Done()
        defer w.Close()
        runWorkerLoop(w)
    }(w)
}
wg.Wait()
s.Close()
```

Each forked session shares the cookie jar and the TLS ticket cache, so all 8 workers get 0-RTT on their first request, but each keeps its own connection state. The shape is 8 browser tabs sharing one profile.

## Related

- [Refresh](../connection-lifecycle/refresh), what `Refresh()` does
- [Warmup](../connection-lifecycle/warmup), full warmup mechanics
- [Session Save/Restore](../connection-lifecycle/session-save-restore), Save / Load API
- [Cookies and State](../cookies-and-state/), cookie jar internals
