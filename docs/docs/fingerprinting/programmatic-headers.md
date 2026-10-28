---
title: Programmatic Headers
sidebar_position: 8
---

# Programmatic Headers

The `fingerprint` package exposes a small set of helpers that build the `Sec-Fetch-*` cluster and the `sec-ch-ua-*` Client Hints cluster from a description of the request. You hand them a context (navigation, XHR, image, script, etc.) and they hand you back a header bundle that lines up with what a real browser would emit for that same request.

Most callers never need to touch any of this. Every `Session.Get` / `Session.Post` / `Session.Do` already runs the same logic internally and rewrites these headers per request before the bytes hit the wire. The helpers exist for code that builds custom flows on top of `Session`: tooling that wants to pre-compute a header bundle, scrapers that fire a navigation followed by five XHRs and need each one to look like the page's own JavaScript firing it, or callers that want to inspect what httpcloak is going to send before sending it.

This chapter is a tour of the surface. The types and functions all live in `github.com/sardanioss/httpcloak/fingerprint`.

## The Sec-Fetch family

`Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, and `Sec-Fetch-User` are four headers Chrome adds to every request. Together they tell the server how the request was triggered and what kind of resource it expects back. Anti-bot vendors check that the four values are coherent (e.g. an image load can't claim `Sec-Fetch-Mode: navigate`) and that they line up with the URL pattern (e.g. an XHR to an API path shouldn't carry `Sec-Fetch-Site: none`). Get any of them wrong and the request looks synthetic.

`Sec-Fetch-Mode` describes how the request was made:

| Constant | Value | When |
| --- | --- | --- |
| `FetchModeNavigate` | `navigate` | Top-level document load. |
| `FetchModeCORS` | `cors` | `fetch()` / XHR with CORS. |
| `FetchModeNoCORS` | `no-cors` | `<img>`, `<script>`, `<link rel=stylesheet>`. |
| `FetchModeSameOrigin` | `same-origin` | Same-origin fetch / XHR. |
| `FetchModeWebSocket` | `websocket` | WS handshake. |

`Sec-Fetch-Dest` describes the resource type:

| Constant | Value |
| --- | --- |
| `FetchDestDocument` | `document` |
| `FetchDestImage` | `image` |
| `FetchDestScript` | `script` |
| `FetchDestStyle` | `style` |
| `FetchDestFont` | `font` |
| `FetchDestXHR` | `empty` |
| `FetchDestMedia` | `media` |
| `FetchDestEmbed` | `embed` |
| `FetchDestObject` | `object` |
| `FetchDestManifest` | `manifest` |
| `FetchDestReport` | `report` |
| `FetchDestServiceWorker` | `serviceworker` (lowercase, no separator) |
| `FetchDestSharedWorker` | `sharedworker` (lowercase, no separator) |
| `FetchDestWorker` | `worker` |

`Sec-Fetch-Site` describes the relationship between where the request came from and where it's going:

| Constant | Value | When |
| --- | --- | --- |
| `FetchSiteNone` | `none` | Direct hit. Typed URL, bookmark, no referrer. |
| `FetchSiteSameOrigin` | `same-origin` | Same scheme, host, and port. |
| `FetchSiteSameSite` | `same-site` | Same registrable domain, different subdomain. |
| `FetchSiteCrossSite` | `cross-site` | Different registrable domain. |

`Sec-Fetch-User: ?1` is sent only when the navigation is user-triggered (a click or address-bar entry). Programmatic navigations omit it.

The shape table below covers the cases most callers hit:

| Resource | Mode | Dest | Site (typical) |
| --- | --- | --- | --- |
| Page navigation (typed URL) | `navigate` | `document` | `none` |
| Page navigation (clicked link, same-origin) | `navigate` | `document` | `same-origin` |
| `fetch()` / XHR | `cors` | `empty` | `same-origin` / `same-site` / `cross-site` |
| `<img>` | `no-cors` | `image` | derived from referrer + target |
| `<script src=...>` | `no-cors` | `script` | derived from referrer + target |
| `<link rel=stylesheet>` | `no-cors` | `style` | derived from referrer + target |
| `@font-face` | `cors` | `font` | derived from referrer + target |

## RequestContext

`RequestContext` is the input bag the generators read. You almost never construct it by hand. The constructors below cover the common cases and they take care of computing `Site` for you.

```go
type RequestContext struct {
    Mode            FetchMode
    Dest            FetchDest
    Site            FetchSite
    IsUserTriggered bool
    Referrer        string
    TargetURL       string
}
```

The constructors:

- `NavigationContext()`: a fresh top-level navigation. Mode `navigate`, dest `document`, site `none`, user-triggered. Use this for a typed URL, a bookmark, or any flow that doesn't have a referring page.
- `XHRContext(referrer, targetURL)`: a `fetch()` / XHR call from page JavaScript. Mode `cors`, dest `empty`. `Site` is computed from the referrer and target.
- `ImageContext(referrer, targetURL)`: a subresource `<img>` load. Mode `no-cors`, dest `image`.
- `ScriptContext(referrer, targetURL)`: a subresource `<script src=...>` load. Mode `no-cors`, dest `script`.
- `StyleContext(referrer, targetURL)`: a subresource `<link rel=stylesheet>` load. Mode `no-cors`, dest `style`.
- `FontContext(referrer, targetURL)`: a `@font-face` load. Mode `cors`, dest `font`.

`Site` is filled in by `calculateFetchSite(referrer, targetURL)` under the hood. Empty referrer gives `none`. Same scheme + host + port gives `same-origin`. Same registrable domain (last two labels of the host) gives `same-site`. Anything else is `cross-site`. The registrable-domain check is a two-label heuristic, not a full Public Suffix List walk, so multi-label public suffixes (`co.uk`, `com.au`) classify as `same-site` when the second-to-last labels match. For practical scraping work the heuristic is fine; if you need PSL-correct behaviour, set `Site` yourself.

## GenerateSecFetchHeaders

`GenerateSecFetchHeaders` takes a `RequestContext` and returns a `SecFetchHeaders` struct with the four header values:

```go
type SecFetchHeaders struct {
    Site string
    Mode string
    Dest string
    User string // "?1" on user-triggered navigation, empty otherwise
}
```

For an XHR from a page on `example.com` to an API on a same-site subdomain:

```go
import "github.com/sardanioss/httpcloak/fingerprint"

ctx := fingerprint.XHRContext("https://example.com/", "https://api.example.com/data")
h := fingerprint.GenerateSecFetchHeaders(ctx)
// h.Site == "same-site"
// h.Mode == "cors"
// h.Dest == "empty"
// h.User == ""
```

`example.com` and `api.example.com` share the registrable domain `example.com`, so `Site` resolves to `same-site`. Swap the target for `https://api.other-site.com/data` and `Site` flips to `cross-site`. Hit the same target with no referrer (typed URL) and `Site` is `none`.

`Sec-Fetch-User` only gets a value when the context is both user-triggered and a navigation. `XHRContext` returns `IsUserTriggered: false`, so `User` stays empty. `NavigationContext` returns `IsUserTriggered: true` with `Mode: navigate`, so `User` is `"?1"`.

## GenerateClientHints

Client Hints are the `sec-ch-ua-*` family Chrome started shipping in 2021 to advertise the browser brand, version, platform, and (after server opt-in) high-entropy details like architecture and full version. The low-entropy hints go on every request. The high-entropy hints only go on requests to origins that have asked for them via an `Accept-CH` response header.

Chrome's quoted-list format is unusual. The browser brands are emitted as a comma-separated list of `"brand";v="version"` triples, including a fake "Not_A Brand" entry that exists to discourage servers from string-matching the brand list:

```
sec-ch-ua: "Google Chrome";v="146", "Chromium";v="146", "Not_A Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
```

`GenerateClientHints` builds the bundle:

```go
func GenerateClientHints(
    chromeVersion string,
    platform fingerprint.PlatformInfo,
    includeHighEntropy bool,
) fingerprint.ClientHints
```

The returned struct splits low-entropy from high-entropy:

```go
type ClientHints struct {
    // Low-entropy (always sent)
    UA         string // sec-ch-ua
    UAMobile   string // sec-ch-ua-mobile
    UAPlatform string // sec-ch-ua-platform

    // High-entropy (only after Accept-CH opt-in)
    UAArch            string // sec-ch-ua-arch
    UABitness         string // sec-ch-ua-bitness
    UAFullVersion     string // sec-ch-ua-full-version
    UAFullVersionList string // sec-ch-ua-full-version-list
    UAModel           string // sec-ch-ua-model
    UAPlatformVersion string // sec-ch-ua-platform-version
    UAWow64           string // sec-ch-ua-wow64
}
```

Pass `includeHighEntropy: true` when you've already seen the server's `Accept-CH` and want to pre-build the full bundle. Pass `false` for the first request to a host, before you know what the server is going to ask for.

In normal use you don't call this directly. `Session` parses incoming `Accept-CH` response headers via `parseAcceptCH` and starts emitting the matching high-entropy hints on subsequent requests to the same origin. `GenerateClientHints` is for cases where you want to construct the bundle outside of a `Session` (e.g. injecting it into a different transport, building a fixture for tests, or pre-warming a header set before opening a session).

## What a session learned from Accept-CH

Three `Session` methods read and set what each host asked for:

```go
s.AcceptCH("example.com")       // []string{"sec-ch-ua-arch", "sec-ch-ua-platform-version"}, or nil
s.ClientHintsFor("example.com") // map[string]string{"sec-ch-ua-arch": `"x86"`, ...}, or nil
s.SetAcceptCH("example.com", []string{"Sec-CH-UA-Arch", "Sec-CH-UA-Platform-Version"})
```

`AcceptCH` is the host's last `Accept-CH`, lowercase and sorted. `ClientHintsFor` is what the session adds to its next request to that host, lowercase header name to value. The request path reads the same map, so it is what goes on the wire, unless the session has the hints turned off (then it is nil) or the request sets one of them itself. `SetAcceptCH` replaces what the session has from the host, as a new `Accept-CH` would, and an empty list forgets the host. Each takes a host name or a URL.

Chrome keeps every host's `Accept-CH` in the profile, so a host that asked last week gets the hints on the first request of the next visit. `Save` and `Marshal` keep them the same way. A session rebuilt from state you store yourself, cookies in your own database say, can be given them with `SetAcceptCH` before its first request, or the first request goes without hints the second one carries.

## HeaderCoherence

`HeaderCoherence` is a higher-level wrapper around the two generators above plus the rest of a preset's headers. It binds them to a specific preset so you can ask for a complete header map for a given request type:

```go
preset := fingerprint.Get("chrome-latest")
hc := fingerprint.NewHeaderCoherence(preset)

navHeaders := hc.GenerateNavigationHeaders()
xhrHeaders := hc.GenerateXHRHeaders(
    "https://example.com/",
    "https://api.example.com/data",
)
```

`GenerateNavigationHeaders` returns the full preset header map with `Sec-Fetch-*` set to navigation values, `Upgrade-Insecure-Requests: 1`, and `Accept` set to the long document Accept string Chrome sends on top-level navigations.

`GenerateXHRHeaders` builds a leaner map: `User-Agent`, `Accept: */*`, `Accept-Encoding`, `Accept-Language`, the low-entropy client hints from the preset, and the `Sec-Fetch-*` values for an XHR with the given referrer and target. `Upgrade-Insecure-Requests` and `Cache-Control` are not included.

`ApplyToHeaders` is the underlying primitive both methods share. It mutates a `map[string]string` in place against a `RequestContext`:

```go
func (h *HeaderCoherence) ApplyToHeaders(
    headers map[string]string,
    ctx fingerprint.RequestContext,
)
```

What it does:

- Writes `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`. Writes `Sec-Fetch-User: ?1` only on user-triggered navigation; deletes the key otherwise.
- Rewrites `Accept` based on Mode and Dest. Navigation gets the long document string. CORS / same-origin gets `*/*`. No-CORS image gets the preset's image Accept: `image/jxl,image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8` on 155 and newer, and the same string without `image/jxl` on older presets. No-CORS style gets `text/css,*/*;q=0.1`. No-CORS script falls back to `*/*`.
- Sets `Upgrade-Insecure-Requests: 1` for navigation; deletes it for everything else.
- Deletes `Cache-Control` for non-navigation modes.
- Sets `Referer` from `ctx.Referrer` when present.

The mutation model means you can take any existing header map, run `ApplyToHeaders` against it with the right context, and the `Sec-Fetch-*` and `Accept` slots get overwritten while everything else stays where you put it.

## When you need this

Most flows do not need any of this. The session layer already calls `ApplyToHeaders` on every request through the same code paths described above, so a plain `session.Get(ctx, url)` ends up on the wire with the right `Sec-Fetch-*` for a navigation and a real `Accept` string. Cross-origin XHRs from inside a custom `Do` call get the correct `Site` value because the session tracks the previous response URL as the referrer.

The programmatic helpers come in when the auto-rewrite isn't enough on its own. Three concrete cases:

1. Multi-step request chains where you load a page, then fire several XHRs that should reference back to that page. You want each XHR's `Referer` and `Sec-Fetch-Site` to point at the page URL, not at whatever the session last saw. `XHRContext(pageURL, apiURL)` plus `ApplyToHeaders` gives you precise control over the relationship.
2. Building a header fixture for an external transport. You want the bundle as a flat `map[string]string` to inject into something that isn't a `Session` (a worker pool, a queue, a different HTTP library). `GenerateXHRHeaders` returns exactly that map.
3. Pre-computing or auditing what httpcloak is going to send before sending it. The generators are pure functions of their inputs, so you can run them in tests, log their output, or diff them against a real-browser capture without spinning up a full session.

## Bindings

The Python, Node, and .NET bindings do not currently expose the `fingerprint` package's programmatic constructors. The auto-applied `Sec-Fetch-*` and `sec-ch-ua-*` rewrite still runs on every request from those bindings, because it lives inside `Session` itself, but the standalone helpers (`XHRContext`, `GenerateSecFetchHeaders`, `HeaderCoherence`, etc.) are reachable only from Go.

If you need explicit programmatic header control from a binding, two paths work:

1. Build the headers Go-side and surface them to the binding through your own thin service. A small Go program that exposes `GenerateXHRHeaders` over a local socket or HTTP endpoint covers most use cases.
2. Set the `Sec-Fetch-*` values directly via the request `headers` argument the binding already accepts. The session layer respects caller-supplied headers and won't overwrite values you set explicitly, so you get the same end result without going through the helper types.

For binding users whose flows are plain GET / POST / XHR with the session-tracked referrer behaviour, neither path is needed. The defaults match what real Chrome sends on the same request.
