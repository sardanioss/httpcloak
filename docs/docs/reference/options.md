---
title: Options
sidebar_position: 1
---

# Options

Every option you can pass to `httpcloak.New(...)` and `httpcloak.NewSession(...)`, in one flat list. The topic pages (Proxies, Fingerprinting, Sessions) cover the reasoning; this page is the lookup table.

:::info
Flat reference. For why each option exists and when to reach for it, see the topic sections (Proxies, Fingerprinting, Sessions, etc.).
:::

There are two construction surfaces. `httpcloak.New(preset, ...Option)` returns a stateless `*Client` and takes a small set of options. `httpcloak.NewSession(preset, ...SessionOption)` returns a stateful `*Session` that owns cookies, TLS resumption tickets, and header memory; that's where most of the surface lives.

If you're new, start with `NewSession`. `New` is the right call for one-shot scripts where state across requests doesn't matter.

---

## Client options (`httpcloak.New`)

The stateless `Client` exposes two options. Anything that needs state lives on `NewSession`.

| Signature | Default | What it does |
|---|---|---|
| `WithTimeout(d time.Duration) Option` | `30s` | Per-request timeout for `client.Do`, `Get`, `Post`, etc. Resets on every call. |
| `WithProxy(url string) Option` | `""` (no proxy) | Single-protocol proxy URL (`http://`, `https://`, `socks5://`). Applied to every request. For per-protocol split routing, use `NewSession` with the TCP/UDP proxy options. |

---

## Session options (`httpcloak.NewSession`)

The full session surface, grouped by category. Every constructor returns a `SessionOption`.

### Lifecycle and cookies

Session-level state. The cookie jar, header memory, and the protocol the session flips to after `Refresh()`.

| Signature | Default | What it does |
|---|---|---|
| `WithoutCookieJar() SessionOption` | jar enabled | Disables the internal cookie jar entirely. `Set-Cookie` is not stored, jar contents are not auto-injected as `Cookie:` headers. Caller-provided `Cookie` headers always pass through. Use when you have your own jar (database, shared cache). See [Disabling the cookie jar](/cookies-and-state/disabling-cookie-jar). |
| `WithoutConditionalCache() SessionOption` | cache enabled | Disables the session's ETag / If-Modified-Since handling for the session's lifetime. No validators get injected, no validators get stored. Runtime toggle: `Session.SetConditionalCacheEnabled(bool)`. Per-request opt-out: `Request.DisableConditionalCache bool`. See [Conditional Cache](/connection-lifecycle/conditional-cache). |
| `WithSwitchProtocol(proto string) SessionOption` | `""` (no switch) | Protocol the session switches to on the next `Refresh()`. Valid values: `"h1"`, `"h2"`, `"h3"`. Useful for warming TLS on H3 then serving on H2 with resumption. |
| `WithKeyLogFile(path string) SessionOption` | `SSLKEYLOGFILE` env | Per-session override for the TLS key log path. Wireshark / Chrome use this to decrypt captured traffic. |

### Network, proxies, local binding

How outbound connections are made. Proxy routing, IP family preference, source-IP binding.

| Signature | Default | What it does |
|---|---|---|
| `WithSessionProxy(url string) SessionOption` | `""` | Single proxy URL applied to all protocols (TCP and UDP). Schemes: `http://`, `https://`, `socks5://`. See [Proxies](../proxies). |
| `WithSessionTCPProxy(url string) SessionOption` | `""` | TCP-only proxy (HTTP/1.1, HTTP/2). Pair with `WithSessionUDPProxy` for split routing. |
| `WithSessionUDPProxy(url string) SessionOption` | `""` | UDP-only proxy (HTTP/3 via SOCKS5 or MASQUE). Pair with `WithSessionTCPProxy`. |
| `WithSessionPreferIPv4() SessionOption` | IPv4/IPv6 racing | Forces IPv4 dial. Use on networks where IPv6 is broken or slow. Disables Happy Eyeballs racing. |
| `WithLocalAddress(addr string) SessionOption` | OS-chosen | Binds outgoing connections to a specific local IP (v4 or v6). On Linux, freebind is auto-applied so any address from a routed prefix works without per-IP interface config. Useful for IPv6 rotation. |
| `WithLocalAddrIP(ip net.IP) SessionOption` | OS-chosen | Same as `WithLocalAddress` but takes a parsed `net.IP`. Nil is a no-op (so conditional builders don't clobber a previous value). |
| `WithConnectTo(requestHost, connectHost string) SessionOption` | no override | Domain fronting: requests to `requestHost` connect to `connectHost`. SNI and `Host:` keep `requestHost`. Can be called multiple times for multiple mappings. |
| `WithEnableSpeculativeTLS() SessionOption` | off | Sends CONNECT and TLS ClientHello together over a proxy, saving one round-trip (~25% speedup). Off by default because some HTTP proxies choke on it. Enable when you've validated the proxy supports it. |

### Protocol forcing

Pin or disable specific HTTP versions.

| Signature | Default | What it does |
|---|---|---|
| `WithForceHTTP1() SessionOption` | auto | Forces HTTP/1.1. Implies `WithDisableHTTP3()`. |
| `WithForceHTTP2() SessionOption` | auto | Forces HTTP/2. Implies `WithDisableHTTP3()`. |
| `WithForceHTTP3() SessionOption` | auto | Forces HTTP/3 (QUIC). Fails on hosts that don't advertise H3. |
| `WithDisableHTTP3() SessionOption` | H3 enabled when preset supports it | Disables HTTP/3 racing while keeping H1/H2 negotiation. Use when QUIC is unreliable on the network or you bound to an address that can't UDP. |
| `WithTLSOnly() SessionOption` | off | Keeps the preset's TLS fingerprint but skips its default HTTP headers. You set every header per-request. Auto-enabled when `WithCustomFingerprint` provides a JA3. |

### TLS, ECH, certificate verification

| Signature | Default | What it does |
|---|---|---|
| `WithInsecureSkipVerify() SessionOption` | verify enabled | Skips TLS certificate verification. Test-only, never ship this enabled. |
| `WithDisableECH() SessionOption` | ECH attempted when DNS has it | Skips the ECH (Encrypted Client Hello) HTTPS RR lookup. Saves ~15-20ms on first connect at the cost of the privacy bump ECH gives you. |
| `WithECHFrom(domain string) SessionOption` | target domain | Pulls ECH config from a different domain's DNS than the request target. Common pattern for Cloudflare: `WithECHFrom("cloudflare-ech.com")` works for any CF-fronted host. |
| `WithSessionCache(backend, errCb) SessionOption` | in-memory | Plugs a distributed TLS session cache (e.g. Redis). `backend` implements `transport.SessionCacheBackend`; `errCb` is called when the backend fails. Lets multiple processes share TLS resumption tickets. |

### Fingerprint customization

| Signature | Default | What it does |
|---|---|---|
| `WithCustomFingerprint(fp CustomFingerprint) SessionOption` | preset's defaults | Override TLS (JA3) and HTTP/2 (Akamai) fingerprints. When `JA3` is set, `WithTLSOnly()` is auto-enabled. The struct fields: `JA3` (full string), `Akamai` (settings/window/priority/pseudo string), `SignatureAlgorithms`, `ALPN`, `CertCompression`, `PermuteExtensions`. See [Custom fingerprints](../fingerprinting/custom-ja3). |
| `WithTCPFingerprint(fp fingerprint.TCPFingerprint) SessionOption` | preset's defaults | Override TCP/IP fingerprint fields (TTL, MSS, window size, window scale, DF bit). Only non-zero fields apply; zero fields keep the preset value. |

### Timeouts and retries

| Signature | Default | What it does |
|---|---|---|
| `WithSessionTimeout(d time.Duration) SessionOption` | `30s` | Default per-request timeout. Each `Do` / `Get` can override via `req.Timeout`. |
| `WithQuicIdleTimeout(d time.Duration) SessionOption` | `30s` | QUIC idle timeout. Connections close after this much silence. Match Chrome's default unless you need long-lived H3 sessions across request gaps. |
| `WithRetry(count int) SessionOption` | retry off | Enables retry with default backoff. `count` is total retry attempts (not including the first try). |
| `WithoutRetry() SessionOption` | retry off | Explicitly disables retry. No-op if retry was never enabled. |
| `WithRetryConfig(count int, waitMin, waitMax time.Duration, retryOnStatus []int) SessionOption` | see source | Full retry config. `waitMin/waitMax` define exponential backoff bounds. `retryOnStatus` is the set of HTTP statuses that trigger a retry. |

### Redirects

| Signature | Default | What it does |
|---|---|---|
| `WithoutRedirects() SessionOption` | follow on | Don't follow redirects. The first 3xx response returns to caller. |
| `WithRedirects(follow bool, maxRedirects int) SessionOption` | follow=true, max=10 | Toggle follow + cap the chain. `maxRedirects=0` with `follow=true` falls back to the package default. |

Runtime toggles (no ctor option required) live on `*Session`: `SetFollowRedirects(bool)` / `FollowRedirects()`, `SetMaxRedirects(int)` / `MaxRedirects()`. Per-request override: set `Request.FollowRedirects *bool` before `Do`. See [Conditional Cache](/connection-lifecycle/conditional-cache) for the parallel surface on ETag handling.

### Custom fingerprint struct (`CustomFingerprint`)

The value passed to `WithCustomFingerprint`. Defined in the root package.

| Field | Type | Notes |
|---|---|---|
| `JA3` | `string` | Full JA3 string: `Version,Ciphers,Extensions,Curves,Formats`. Setting this implies TLS-only mode. |
| `Akamai` | `string` | Akamai HTTP/2 fingerprint: `SETTINGS\|WINDOW_UPDATE\|PRIORITY\|PSEUDO_ORDER`. Example: `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p`. |
| `SignatureAlgorithms` | `[]string` | Names like `"ecdsa_secp256r1_sha256"`, `"rsa_pss_rsae_sha256"`. Replaces the JA3 spec's default sig-algs. |
| `ALPN` | `[]string` | Default `["h2", "http/1.1"]`. Override to limit (e.g. H1-only). |
| `CertCompression` | `[]string` | One or more of `"brotli"`, `"zlib"`, `"zstd"`. |
| `PermuteExtensions` | `bool` | When true, the TLS extension order is permuted per handshake (Chrome 110+ behavior). |

---

## Per-request options

Fields on the `Request` struct override session-level settings for a single call. These don't go through `SessionOption`.

| Field | Type | What it does |
|---|---|---|
| `Method` | `string` | HTTP method. |
| `URL` | `string` | Absolute URL. |
| `Headers` | `map[string][]string` | Extra headers (multi-value, matches `http.Header`). Caller-provided `Cookie:` always passes through. |
| `Body` | `io.Reader` | Streaming body (no length needed for chunked). |
| `Timeout` | `time.Duration` | Per-request timeout override. |
| `TLSOnly` | `*bool` | Per-request override for `WithTLSOnly`. `nil` falls back to the session setting. Useful for `LocalProxy` where each request has its own TLS-only flag via `X-HTTPCloak-TlsOnly`. |

---

## Session methods (mutators after construction)

Methods on `*Session` itself, called after `NewSession` returns. These aren't `SessionOption` constructors and can't be passed at build time.

| Method | What it does |
|---|---|
| `SetProxy(url string)` | Replaces the unified proxy. Closes existing connections. Empty string switches to direct. |
| `SetTCPProxy(url string)` | Replaces only the TCP proxy. |
| `SetUDPProxy(url string)` | Replaces only the UDP proxy. |
| `GetProxy() string` | Current unified or TCP proxy URL. |
| `GetTCPProxy() string` | Current TCP proxy URL. |
| `GetUDPProxy() string` | Current UDP proxy URL. |
| `SetHeaderOrder(order []string)` | Override the preset's header order. Lowercase names. `nil` resets to preset default. |
| `GetHeaderOrder() []string` | Current header order, or preset default if no override. |
| `SetSessionIdentifier(id string)` | TLS-cache key namespace. Used when a session is registered with `LocalProxy` so distributed caches isolate per-session tickets. |
| `Warmup(ctx, url) error` | Simulates a real browser page load: fetches HTML + CSS/JS/image subresources with realistic headers, priorities, and timing. Warms TLS, cookies, ticket cache. |
| `Fork(n int) []*Session` | Create `n` child sessions sharing cookies and TLS cache but with independent connections. Mimics multiple browser tabs. |
| `Refresh()` | Close all connections, keep TLS cache and cookies. Switches protocol if `WithSwitchProtocol` was set. |
| `RefreshWithProtocol(proto string) error` | Same as `Refresh` but switches to the given protocol. The change persists for future `Refresh()` calls. Valid: `"h1"`, `"h2"`, `"h3"`, `"auto"`. |
| `Save(path string) error` | Persist cookies + TLS sessions to a file. |
| `Marshal() ([]byte, error)` | Persist cookies + TLS sessions to bytes. |
| `Close()` | Release everything. Always defer this. |

Cookie methods on `*Session`:

| Method | What it does |
|---|---|
| `GetCookies() []CookieInfo` | All cookies with full metadata. |
| `GetCookiesDetailed() []CookieInfo` | Same shape (the bindings split this; in Go they're identical). |
| `SetCookie(c CookieInfo)` | Insert / replace a cookie with full metadata. |
| `DeleteCookie(name, domain string)` | Delete by name. Empty domain wipes from every domain. |
| `ClearCookies()` | Wipe the jar. |

Package-level loaders, not methods on `*Session`:

| Function | What it does |
|---|---|
| `LoadSession(path string) (*Session, error)` | Restore a session saved with `Save`. |
| `UnmarshalSession(data []byte) (*Session, error)` | Restore a session from bytes saved with `Marshal`. |
| `Presets() []string` | The built-in preset names. Custom presets registered via `fingerprint.Register(name, *Preset)` go into a separate map and are NOT returned by `Presets()`. To resolve a name (built-in or custom) at runtime, use `fingerprint.Get(name)`. |

---

## Top-level helpers

Symbols in the root package that aren't options. Request and response types, multipart helpers, body readers.

| Symbol | What it does |
|---|---|
| `BuildMultipart(fields []MultipartField) ([]byte, string, error)` | Encode a multipart/form-data body. Returns body bytes + the `Content-Type` header value (with boundary). Handles both text fields (`Name`, `Value`) and file fields (`Name`, `Filename`, `Content`, `ContentType`). |
| `MultipartField` | Struct passed to `BuildMultipart`. Fields: `Name`, `Value`, `Filename`, `Content`, `ContentType`. |
| `Request`, `Response`, `RedirectInfo`, `StreamResponse` | Request/response shapes. |
| `Response.Bytes() / Text() / JSON(v)` | Read the body once, with caching. |
| `Response.GetHeader(key) / GetHeaders(key)` | Case-insensitive lookup (header keys are stored lowercase). |
| `StreamResponse.Read / ReadChunk / ReadAll / Close` | Streaming body reads. Streaming does **not** support redirects, use `Do` for redirect handling. |

---

## Defaults at a glance

The values you get when no option is set.

| Setting | Default |
|---|---|
| Request timeout | `30s` |
| QUIC idle timeout | `30s` |
| Cookie jar | enabled |
| Redirect follow | on, max 10 |
| Retry | off |
| HTTP/3 | enabled when preset supports it |
| ECH lookup | on if the target's DNS publishes HTTPS RRs |
| Speculative TLS | off |
| TLS verify | on |
| Header order | preset default |
| Local IP bind | none (OS-chosen) |
| IPv4/IPv6 preference | racing (Happy Eyeballs) |

If a default doesn't match what you expected, file an issue with the preset name and a `tls.peet.ws/api/all` capture.
