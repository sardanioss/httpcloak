---
title: Preset Pool Rotation
sidebar_position: 6
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Preset Pool Rotation

`fingerprint.PresetPool` is a thin wrapper around a list of presets with a selection strategy attached. You build it once at startup, hand the pool to your worker code, and each request (or each new Session) draws a fresh preset from it without you tracking indices or shuffle state. The pool exposes `Pick()`, `Random()`, and `Next()`, and the JSON loader auto-registers every preset it finds so the returned name drops straight into `Session(preset=...)`.

The use case is a long-running scraper that fans out enough volume to wear a single fingerprint thin. High-volume targets profile per-fingerprint reputation, so a million requests off one JA4 starts to look like one client doing a million requests, which is exactly the shape they flag. Rotating across a small set of presets, say three Chrome platform variants or two Chrome versions plus a Firefox, distributes the load across distinct fingerprints and breaks that single-source signal.

Pools also keep your session-construction code stable. The Session constructor still takes a preset name. The pool is a producer of preset names. Adding rotation to an existing scraper boils down to building the pool at startup and replacing the hardcoded preset string with `pool.next()` at the call site.

## Strategies

Two strategies, both set on the pool at construction time:

- **`PoolRandom`** picks uniformly at random per call. Crypto-seeded RNG, mutex-guarded so concurrent callers see independent draws. Use this when you want true uniform load distribution and don't care about exact ordering. Over a few thousand requests, each preset ends up with roughly its share of traffic, but the sequence is unpredictable so any pattern-matching defense looking for repeated cycles sees nothing.
- **`PoolRoundRobin`** cycles through presets sequentially. The counter is a lock-free `atomic.Int64`, so concurrent goroutines (or threads, across the cgo boundary) get balanced selection without contention. Useful when you want predictable per-fingerprint rate-limiting: a 5-preset pool firing 100 requests guarantees each preset gets exactly 20 of them.

Pick `PoolRoundRobin` when you've thought about per-fingerprint quotas and want them honored exactly. Pick `PoolRandom` for everything else, since unpredictability is usually what you want and the slight imbalance washes out at any reasonable scale.

`Pick()` dispatches based on the configured strategy. `Random()` and `Next()` force the respective behavior regardless of how the pool was configured, which is useful when most requests use the default but a specific code path wants the other mode.

## Pool from JSON

The pool format is a top-level `PoolSpec` with a `version`, a name, an optional strategy, and a list of preset definitions:

```json
{
  "version": 1,
  "pool": {
    "name": "chrome-rotation",
    "strategy": "round-robin",
    "presets": [
      {
        "name": "pool-chrome-win",
        "based_on": "chrome-152-windows",
        "headers": { "values": { "Accept-Language": "en-US,en;q=0.9" } },
        "tcp": { "platform": "Windows" }
      },
      {
        "name": "pool-chrome-linux",
        "based_on": "chrome-152-linux",
        "headers": { "values": { "Accept-Language": "en-US,en;q=0.9" } },
        "tcp": { "platform": "Linux" }
      },
      {
        "name": "pool-chrome-mac",
        "based_on": "chrome-152-macos",
        "headers": { "values": { "Accept-Language": "en-US,en;q=0.9" } },
        "tcp": { "platform": "macOS" }
      }
    ]
  }
}
```

`version: 1` is the current schema. `strategy` accepts `"round-robin"`, `"random"`, or `""` (empty defaults to random). Each preset entry follows the same shape as a standalone preset file, so `based_on` inheritance, header overrides, TCP/H2/H3 settings, all of it works the same way inside a pool entry.

The loader builds every preset first and only registers them after all of them succeed. If any one preset fails to build (bad `based_on`, malformed JSON, unknown ClientHelloID), the pool load fails and nothing gets registered. Half-loaded pools never exist.

You can also wrap a single preset in a pool of one. Drop the `pool` block, write a `preset` block instead, the loader auto-promotes it:

```json
{ "version": 1, "preset": { "name": "...", "based_on": "...", "..." : "..." } }
```

That mode is mostly useful for code that wants to consume "one or many presets" through the same pool API without branching on the count.

Loading from a file:

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
pool, err := fingerprint.NewPresetPoolFromFile("examples/presets/rotation_pool.json")
if err != nil {
    log.Fatal(err)
}
defer pool.Close()
```

</TabItem>
<TabItem value="python" label="Python">

```python
from httpcloak import PresetPool

pool = PresetPool("examples/presets/rotation_pool.json")
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
import { PresetPool } from "httpcloak";

const pool = new PresetPool("examples/presets/rotation_pool.json");
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var pool = new PresetPool("examples/presets/rotation_pool.json");
```

</TabItem>
</Tabs>

For in-memory loading (config built in code, fetched from a config service, generated per-tenant), each binding has a JSON-string entry point: Go's `NewPresetPoolFromJSON([]byte)`, Python's `PresetPool.from_json(json_data)`, Node's `PresetPool.fromJSON(jsonData)`, .NET's `PresetPool.FromJson(jsonData)`. Same auto-registration behavior, no file involved.

After load, the names listed under `pool.presets[*].name` are live in the global preset registry, so passing them straight to `Session(preset=...)` resolves correctly. No separate `Register` call needed.

## Pool programmatically (Go)

For Go callers, `NewPresetPool(name, strategy, []*Preset)` skips the JSON path entirely. Useful when you're building presets in code, either through `BuildPreset` from a `PresetSpec` you constructed in memory, or by combining presets you loaded individually:

```go
chromeWin, _ := fingerprint.LoadPresetFromFile("presets/chrome_win.json")
chromeMac, _ := fingerprint.LoadPresetFromFile("presets/chrome_mac.json")
firefox, _ := fingerprint.LoadPresetFromFile("presets/firefox.json")

p1, _ := fingerprint.BuildPreset(chromeWin.Preset)
p2, _ := fingerprint.BuildPreset(chromeMac.Preset)
p3, _ := fingerprint.BuildPreset(firefox.Preset)

pool := fingerprint.NewPresetPool("desktop-mix", fingerprint.PoolRoundRobin,
    []*fingerprint.Preset{p1, p2, p3})
defer pool.Close()
```

Constraints are the same as the JSON path: empty slice panics, a `nil` element panics, the slice gets defensively copied so caller mutation after construction has no effect. The constructor does not auto-register the presets it receives, since you may have already registered them yourself or may want them living only in the pool. If you want them callable as `Session(preset=name)`, register them before or after pool construction with `fingerprint.Register(name, p)`.

## Wiring it into a session

The pattern is: build the pool once at startup, then per-request (or per-session) call `pool.Next()` (or `Pick()` or `Random()`), and pass the returned preset to a fresh Session. A 6-request loop rotating across a 3-preset pool:

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
pool, err := fingerprint.NewPresetPoolFromFile("examples/presets/rotation_pool.json")
if err != nil {
    log.Fatal(err)
}
defer pool.Close()

ctx := context.Background()
for i := 0; i < 6; i++ {
    preset := pool.Next() // *fingerprint.Preset
    sess := httpcloak.NewSession(preset.Name)

    resp, err := sess.Get(ctx, "https://tls.peet.ws/api/all")
    if err != nil {
        log.Printf("request %d: %v", i, err)
        sess.Close()
        continue
    }
    log.Printf("request %d via %s: %d", i, preset.Name, resp.StatusCode)
    resp.Close()
    sess.Close()
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
from httpcloak import PresetPool, Session

pool = PresetPool("examples/presets/rotation_pool.json")

try:
    for i in range(6):
        preset_name = pool.next()
        sess = Session(preset=preset_name)
        try:
            r = sess.get("https://tls.peet.ws/api/all")
            print(f"request {i} via {preset_name}: {r.status_code}")
        finally:
            sess.close()
finally:
    pool.close()
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
import { PresetPool, Session } from "httpcloak";

const pool = new PresetPool("examples/presets/rotation_pool.json");

try {
    for (let i = 0; i < 6; i++) {
        const presetName = pool.next();
        const sess = new Session({ preset: presetName });
        try {
            const r = await sess.get("https://tls.peet.ws/api/all");
            console.log(`request ${i} via ${presetName}: ${r.statusCode}`);
        } finally {
            sess.close();
        }
    }
} finally {
    pool.close();
}
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var pool = new PresetPool("examples/presets/rotation_pool.json");

for (int i = 0; i < 6; i++)
{
    var presetName = pool.Next();
    using var sess = new Session(preset: presetName);
    var r = await sess.GetAsync("https://tls.peet.ws/api/all");
    Console.WriteLine($"request {i} via {presetName}: {(int)r.StatusCode}");
}
```

</TabItem>
</Tabs>

One thing to flag about the API divergence. In Go, `pool.Next()` returns `*fingerprint.Preset` and the `Preset.Name` field is what you pass to `NewSession`. In Python, Node, and .NET, the same call returns the registered preset name directly as a string, since the cgo boundary keeps presets identified by their registry name. Either way, the Session construction line ends up taking a string-shaped argument; only the access pattern differs.

If you want to amortize TCP and TLS connection setup across multiple requests through the same fingerprint, batch them on one Session and rotate the preset between batches instead of between every request. A Session pooled over 50 requests against the same host will reuse the TCP connection and TLS ticket, which is exactly the behavior a real browser produces. Per-request session churn forces a full handshake every time and starts to look unnatural in itself. The right batch size depends on the target, but anywhere between 10 and 200 requests per session before rotating is a reasonable starting band.

## Lifetime and cleanup

`pool.Close()` (or `Dispose()` in .NET, the `__exit__` of the Python context manager, or the `finally` block in Node) unregisters every preset the pool registered on load. After close, the preset names no longer resolve through the global registry, so a subsequent `Session(preset="pool-chrome-linux")` would fail with an unknown-preset error.

In-flight Sessions keep working. The Session resolves and copies the `*Preset` value at construction time, so once a Session has been built, it doesn't depend on the registry anymore. The lifecycle pattern is: build pool, build sessions off it, run requests, close sessions, then close the pool. Doing it in the other order, closing the pool while sessions are still being constructed, races with new Session creation and is the only failure mode worth thinking about.

Recommended:

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
pool, _ := fingerprint.NewPresetPoolFromFile("pool.json")
defer pool.Close()
```

</TabItem>
<TabItem value="python" label="Python">

```python
with PresetPool("pool.json") as pool:
    # use pool
    ...
# pool.close() runs on exit
```

</TabItem>
<TabItem value="node" label="Node.js">

```js
const pool = new PresetPool("pool.json");
try {
    // use pool
} finally {
    pool.close();
}
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using var pool = new PresetPool("pool.json");
// pool.Dispose() runs at end of scope
```

</TabItem>
</Tabs>

## Considerations

A few things to think about when wiring a pool into a real workload.

**Cookie jar.** Each Session has its own jar. Rotating Sessions per request means jars don't carry state across rotations, so a login flow spread across two preset draws will lose the login cookie. Pair pool rotation with `Session.Save()` and `LoadSession()` if you need cookie state to survive a fingerprint switch, or batch a coherent set of related requests onto one Session and only rotate at logical boundaries (per-account, per-job, per-target).

**TLS resumption.** Each Session has its own ticket cache. A fresh Session against a host with no shared cache backend pays a full handshake every time. For a pool that rotates often, this is fine: a real user loading the same site from three browsers wouldn't share tickets across them either. For a pool used inside a multi-replica scraper where you do want resumption to survive Session churn, wire in `WithSessionCache(backend, errCb)` and let all replicas share resumption state through the same Redis or memcached. The `local-proxy-server` chapter walks through a Redis-backed implementation that drops in here unchanged.

**Mixed browser families.** A pool can hold any combination of presets. Built-in plus custom, Chrome plus Firefox, different platforms within one Chrome version. Mixing browser families per request is allowed but rarely useful, since one IP serving Chrome and Firefox in alternation is itself a signal. The standard rotation is across versions or platforms within one browser family: chrome-152-windows, chrome-152-macos, chrome-152-linux. That looks like three users on the same site, which is what a single residential IP can plausibly be doing.

**Custom presets are not required.** Built-in preset names can sit alongside custom ones in the same `PoolSpec.presets` list as long as they're built by the loader correctly (custom presets typically use `based_on` to inherit from built-ins). For pure built-in rotation without any customization, the programmatic Go constructor is the cleaner path: load each built-in by name, hand the slice to `NewPresetPool`.

**Pool size.** Three to five presets covers most rotation scenarios. Two is enough for an A/B split. Beyond ten, the marginal benefit drops since residential-IP traffic profiles tend not to span that many distinct fingerprints anyway, and the configuration surface starts to be its own maintenance burden. Pick the smallest set that breaks the single-fingerprint signal you're trying to break.
