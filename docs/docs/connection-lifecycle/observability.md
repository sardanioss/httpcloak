---
title: Observability
sidebar_position: 6
---

# Observability

This chapter covers session-level observability: the methods that report what a live session is doing, the idle-timer controls that decide when a session gets refreshed or closed, and the escape hatch that lets Go code reach into the underlying transport. The whole surface is read-cheap. `Stats()` returns a struct snapshot, `IdleTime()` and `IsActive()` are short read-locks, and `Touch()` is a single timestamp write. Calling any of them in a worker loop on a 60-second tick costs nothing measurable.

What this chapter doesn't cover: per-request timing data lives in [Hooks](../requests-and-responses/hooks), which fire around request boundaries and carry timing fields the session-level snapshot doesn't have. Metrics emission to Prometheus, OpenTelemetry, statsd or anything similar is out of scope. Build it on top of `Stats()`. The library itself stays free of opinions about a metrics backend.

As of v1.6.7 every Session-level observability method except `GetTransport` is wired through cgo. The bindings (Python, Node, .NET) expose `Stats`, `IdleTime`, `IsActive`, `Touch`, `ClearCache`, `SetSessionIdentifier`, plus a separate `LocalProxy.GetStats()` for proxy-level metrics. `GetTransport` stays Go-only by design; the `*transport.Transport` surface is private and not safe to expose past the cgo boundary. The Bindings section at the end maps the surface explicitly. Code examples in this chapter are Go unless noted; binding callers needing Session counters today either work through `LocalProxy` (proxy-level stats are available everywhere) or run a small Go-side service that exposes counters over HTTP.

## Stats and SessionStats

`Stats()` returns a `SessionStats` struct carrying the headline counters and timestamps. Read it whenever you want a snapshot of where the session is, log it on a periodic tick, or feed individual fields into a metrics system. Go-only today.

```go
s := httpcloak.NewSession("chrome-latest")
defer s.Close()

ctx := context.Background()
_, _ = s.Get(ctx, "https://example.com/")
_, _ = s.Get(ctx, "https://example.com/api/v1/me")

st := s.Stats()
fmt.Printf("preset=%s requests=%d cookies=%d cache=%d age=%s idle=%s\n",
    st.Preset, st.RequestCount, st.CookieCount, st.CacheEntryCount,
    st.Age.Round(time.Millisecond), st.IdleTime.Round(time.Millisecond))
```

The fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `ID` | `string` | The session's internal UUID. Stable for the life of the session. Useful as a log correlation key. |
| `Preset` | `string` | Preset name the session was built from (`chrome-latest`, `firefox-148`, etc.). |
| `CreatedAt` | `time.Time` | Wall-clock time when `NewSession` returned. |
| `LastUsed` | `time.Time` | Wall-clock time of the last request *start* (or explicit `Touch()`). Set at the top of `Do` / `DoStream` / `Warmup`, not on exit, so a long-running streaming request keeps `IdleTime()` near zero for its whole duration rather than only after the body finishes. |
| `RequestCount` | `int64` | Total request count since creation. Counts every request that left the session, including failed ones. |
| `Active` | `bool` | False after `Close()` or `CloseGraceful()` returns. Same value `IsActive()` reports. |
| `CookieCount` | `int` | Number of cookies in the jar at snapshot time. |
| `CacheEntryCount` | `int` | Number of conditional-request cache entries (one per URL with an ETag or Last-Modified seen). |
| `Age` | `time.Duration` | `time.Since(CreatedAt)`. |
| `IdleTime` | `time.Duration` | `time.Since(LastUsed)`. Same value `IdleTime()` returns. |
| `TransportStats` | `map[string]interface{}` | Per-protocol counters from the active transports. |

`TransportStats` carries protocol-specific counters: H1 connection-pool size, H2 active stream count, H3 connection state. The exact keys are loose. They change as transports evolve, and the library doesn't guarantee any particular shape. Treat the map as opaque telemetry suitable for logging and dashboards, not as a stable contract you parse and branch on. If you find yourself writing `if stats["http2_streams_active"] > 0 { ... }`, that's a sign the right surface is a hook or a transport-level method, not the stats map.

## IdleTime, Touch, IsActive

These three methods cover the idle-management lifecycle: read how long a session has been quiet, override the timestamp manually, and check whether the session is still usable.

### IdleTime

`IdleTime()` returns `time.Since(LastUsed)`. The session updates `LastUsed` at the start of every request (and on `Touch()`), not on exit, so during a long-running streaming request `IdleTime()` reads as small even while the body is still draining. The standard pattern is a janitor goroutine that wakes every 60 seconds, walks a session pool, and refreshes or closes anything that's been quiet for too long. Go-only.

```go
// Janitor: every 60s, refresh sessions idle > 5min, close those idle > 30min.
go func() {
    t := time.NewTicker(60 * time.Second)
    defer t.Stop()
    for range t.C {
        for id, s := range pool {
            switch idle := s.IdleTime(); {
            case idle > 30*time.Minute:
                s.Close()
                delete(pool, id)
            case idle > 5*time.Minute:
                s.Refresh()
            }
        }
    }
}()
```

The 5-minute threshold is the typical TLS ticket validity window for big CDNs. Refreshing under that bound keeps subsequent requests on the 0-RTT resumption path. Past 30 minutes most servers have expired the ticket anyway, so closing the session and rebuilding it later costs the same handshake.

### Touch

`Touch()` resets `LastUsed` to `time.Now()`. The use case is signalling to the janitor that the session is alive even when no request has flown recently, for instance when an external event handler decides a session is reserved for a slow background job and shouldn't get culled.

```go
sess.Touch()  // reset idle clock; request count is unchanged
```

`Touch()` doesn't issue a network request and doesn't reset any other counter. It's a single mutex write to one timestamp field.

### IsActive

`IsActive()` returns `false` once `Close()` or `CloseGraceful()` has run, `true` otherwise. The flag is set during the close under the same lock that guards every other session operation, so a `true` result means the session can still service a new request, and a `false` result is permanent (closed sessions don't reopen, build a new one with `NewSession`). Use it as a guard at the top of code paths that share a session pointer across goroutines or worker tasks.

```go
if !sess.IsActive() {
    return errSessionClosed
}
resp, err := sess.Get(ctx, url)
```

The same value lands in `Stats().Active`, so a metrics scrape on the stats struct already covers this without a separate call.

## ClearCache

`ClearCache()` drops all conditional-request cache entries from the session. Each entry maps a URL to the `ETag` and `Last-Modified` values the server returned. On the next request to one of those URLs the session would normally send `If-None-Match` and `If-Modified-Since` headers, hoping for a 304 Not Modified that skips the response body. After `ClearCache()` those headers go out empty on the next hit, so the server returns the full 200 response.

What `ClearCache()` does not touch:

- Cookies stay in the jar. Use `ClearCookies()` for that.
- TLS session tickets stay in their caches. The next handshake still resumes from a stored ticket if one is valid.
- Header order, fingerprint state, proxy config: untouched.

When to call it:

- Debugging a response that diverges between the first and second request. A stale 304 from a cached validator can mask a real change in the server's output. `ClearCache()` forces the next request to fetch the full body so you can compare.
- Verification runs that need to see the canonical 200 response, not a 304 short-circuit. Common when capturing a fresh `Content-Length` or hashing the body.
- Long-running workers where the cache map grows monotonically (one entry per unique URL seen). For a scraper hitting millions of pages, periodic `ClearCache()` keeps the map size bounded. The cost is one full re-fetch per cleared URL the next time it's visited.

`ClearCache()` doesn't drop in-flight requests and doesn't close any connections. It mutates the session's cache map under a write lock and returns immediately.

## SetSessionIdentifier

`SetSessionIdentifier(id)` attaches a string identifier that the transport layer mixes into TLS session-cache keys. The default cache key is the host and protocol, so two sessions in the same process talking to the same host and protocol share a key, share their tickets, and resume from each other's handshakes. With distinct identifiers, the cache key becomes (host, protocol, identifier) and the two sessions stay isolated.

The reason this matters is distributed cache deployment. With `WithSessionCache(redisBackend, errCb)` plugged in, the session-cache keys go into Redis (or whatever backend you wired). Two sessions sharing a key means they read each other's tickets out of Redis. The visible failure mode is one session getting flagged and the rest inheriting the same reputation through the shared ticket. Each persona, fork, or registered session needs its own identifier or the isolation collapses.

`LocalProxy` handles this for you. `RegisterSession(id, sess)` calls `SetSessionIdentifier(id)` internally so every registered session gets namespaced by its registry ID. See the [Session registry](../recipes/local-proxy-server#session-registry) section of the LocalProxy chapter for the full pattern.

For standalone sessions in a multi-session process with a shared backend, set the identifier yourself:

```go
backend := &RedisCache{client: redisClient}

alice := httpcloak.NewSession("chrome-latest", httpcloak.WithSessionCache(backend, nil))
alice.SetSessionIdentifier("alice")

bob := httpcloak.NewSession("chrome-latest", httpcloak.WithSessionCache(backend, nil))
bob.SetSessionIdentifier("bob")
```

Without those two `SetSessionIdentifier` calls, both sessions would share Redis keys for any host they both touch. With them, the cache stays partitioned. The identifier should be unique within the deployment (a UUID, a tenant ID, a worker name, anything stable). Reusing an identifier across processes is fine and intentional; that's how a process restart resumes from earlier tickets.

## GetTransport (Go escape hatch)

`GetTransport()` returns the `*transport.Transport` the session is built on. It's the escape hatch for cases where the session-level API doesn't expose a transport-level knob you need.

```go
tr := sess.GetTransport()
// ... reach into transport-level state ...
```

The bindings don't expose this method. Cgo can't return a Go pointer in a useful way, and the surface of `*transport.Transport` is wide enough that the binding overhead wouldn't justify the result.

Don't reach for `GetTransport()` unless you've read `transport/transport.go` and you know what you're after. The library treats the transport as private and reserves the right to change its surface between releases. If a knob you want isn't exposed at the session level, the right move is usually filing an issue rather than reaching past the boundary, since the session-level API exists exactly so the transport can evolve without breaking your code.

## Bindings

Every Session-level observability method in this chapter is exposed in Python, Node, and .NET, with `GetTransport` as the one exception (Go-only by design). `Stats`, `IdleTime`, `IsActive`, `Touch`, `ClearCache`, and `SetSessionIdentifier` all map straight through cgo, and `LocalProxy.GetStats()` covers proxy-level inspection on top of that.

| Go method | Python | Node.js | .NET |
| --- | --- | --- | --- |
| `Stats() SessionStats` | `session.stats()` -> dict | `session.stats()` -> SessionStats | `Session.Stats()` -> SessionStats? |
| `IdleTime() time.Duration` | `session.idle_time()` -> float (s) | `session.idleTime()` -> number (s) | `Session.IdleTime()` -> TimeSpan |
| `IsActive() bool` | `session.is_active()` | `session.isActive()` | `Session.IsActive()` |
| `Touch()` | `session.touch()` | `session.touch()` | `Session.Touch()` |
| `ClearCache()` | `session.clear_cache()` | `session.clearCache()` | `Session.ClearCache()` |
| `SetSessionIdentifier(id)` | `session.set_session_identifier(id)` | `session.setSessionIdentifier(id)` | `Session.SetSessionIdentifier(id)` |
| `GetTransport() *transport.Transport` | not exposed (Go-only by design) | not exposed (Go-only by design) | not exposed (Go-only by design) |

`LocalProxy` also exposes its own stats on every binding (`local_proxy.get_stats()` in Python, `localProxy.getStats()` in Node, `LocalProxy.GetStats()` in .NET), so proxy-level counters work cross-language alongside the Session-level methods above. For cross-process visibility you can still persist a session via `Save()`/`Marshal()` and read its counters back after a restart.
