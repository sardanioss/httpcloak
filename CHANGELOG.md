# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Issue #56: Per-resource-type H2 stream priority — now the default for every RFC 7540 preset** — Real browsers emit a different RFC 7540 stream weight per resource type (sec-fetch-dest), driven by an internal RFC 9218 urgency: `document/iframe/object/embed/style → u=0 (256)`, `script/font/empty/preload-as=fetch → u=1 (220)`, `manifest/image → u=2 (183)`, `video/audio/track/async-defer-script → u=3 default (147)`, `worker/prefetch/beacon → u=4 (110)`. The previous single-weight model emitted `weight=256, exclusive=true` on every HEADERS frame regardless of dest. New `H2FingerprintConfig.PriorityTable map[string]ResourcePriority` carries `{Urgency, Incremental, EmitHeader}` per dest; the deterministic formula `weight = 256 - (urgency × 73) / 2` derives the H2 wire weight, and `PriorityHeaderFromResource` renders the matching `priority:` HTTP header per the four RFC 9218 emission rules. Wire-up: a new per-request `HeaderPriorityFunc` callback on the underlying H2 transport (sardanioss/net v1.2.6) consults the table by `Sec-Fetch-Dest`, returning a fresh `PriorityParam` for each request — same connection, different streams, distinct priorities. **Resolution rule**: a preset that defines its own `PriorityTable` uses it as-is; a preset without one inherits a package-level default 14-dest table — but only when it uses RFC 7540 priorities (`NoRFC7540Priorities=false`). Safari, iOS Chrome, and iOS Safari all carry `NoRFC7540Priorities=true` and stay opted out (they don't emit RFC 7540 PRIORITY frames at all). Setting `PriorityTable` to a non-nil empty map disables the default for a single preset. Effect on shipping presets: every chrome-* desktop/android variant (chrome-141 through chrome-147) and Firefox 148 now emit per-dest priorities by default, matching real browser behaviour. JSON spec gains `priority_table` field on the HTTP/2 section; `Describe()` round-trips it byte-equal. New API surface: `Preset.H2HasPriorityTable()`, `Preset.H2PriorityFor(dest)`, `PriorityFromUrgency(urgency)`, `PriorityHeaderFromResource(rp)`, `DefaultPriorityTable()`. Tests cover the formula across all 8 urgencies, every emission rule combination, full round-trip, end-to-end wire-frame capture against a local raw-framer server for every dest, default-inheritance for legacy Chrome and Firefox, NoRFC7540 opt-out for Safari/iOS variants, explicit-empty-disables override, unknown-dest fallback, per-request distinctness on a pooled connection, and concurrent request stress under `-race`.
- **User-supplied `Sec-Fetch-Dest` / `Sec-Fetch-Mode` / `Sec-Fetch-Site` are no longer clobbered by the XHR sniff** — When the auto-sniff decided a request was XHR, it forced `mode=cors, dest=empty, site=cross-site` even if the caller had explicitly pinned a different value (e.g. `dest=image` for browser sub-resource emulation). Now the sniff coercion only fills in headers the caller didn't supply; explicit pins win. Required for the priority-table architecture above to be useful — power users can now request browser sub-resource fetches like `<link rel=preload as=image>`, `<script src>`, `<link rel=manifest>`, etc., and get the matching wire priority.
- **`chrome-148-ios` preset** — New iOS Chrome 148 fingerprint with refreshed User-Agent, navigation header set, HTTP/2 wire shape, and HTTP/3 QUIC flow-control windows. `chrome-latest-ios` / `ios-chrome-latest` now resolve to it.
- **`H3FingerprintConfig.QUICInitialStreamReceiveWindow` + `QUICInitialConnectionReceiveWindow`** — New optional pointer fields for per-preset QUIC flow-control windows. nil-default leaves quic-go defaults in place, so existing presets are unchanged. JSON spec gains matching `quic_initial_stream_receive_window` / `quic_initial_connection_receive_window` keys; `Describe()` emits them only when set.
- **Chrome 147 preset family + embedded JSON registry** — New `chrome-147` / `chrome-147-{windows,linux,macos,ios,android}` presets shipped as JSON files in `fingerprint/embedded/` and auto-registered at package init via `//go:embed`. All `*-latest` aliases now resolve to Chrome 147 via thin `LookupCustom` wrapper factories that delegate to the embedded JSON. The `//go:embed` mechanism is the future home for monthly Chrome bumps — header-only diffs ship as JSON files instead of Go-code edits.
- **`describe_preset` / `describePreset` / `Describe` — flatten any preset to JSON for save / edit / reload** — New `fingerprint.Describe(name)` Go API plus matching `httpcloak_describe_preset` clib export and bindings (Python `describe_preset(name)`, Node.js `describePreset(name)`, .NET `CustomPresets.Describe(name)`). Returns a fully-resolved JSON document for any registered preset (built-in or runtime-loaded): inheritance is collapsed, getter fallbacks (`H2Config` / `H3Config` nil → Chrome defaults) are emitted explicitly, header values map keys are sorted alphabetically, and `HeaderOrder` slice order is preserved. The output round-trips byte-equal through `LoadPresetFromJSON` → `BuildPreset` → `Describe`, so it can be saved, hand-edited, reloaded as a custom preset, and re-described without drift. Two consecutive calls return byte-identical bytes (no map-iteration leakage). Empty/zero `TCPFingerprint` is omitted; the `HTTP3` section appears only when `SupportHTTP3=true`. Unregistered utls `ClientHelloID`s (e.g. randomized variants or hand-built IDs) error rather than silently corrupt JSON. `JA3`-defined presets dump to `tls.ja3` + `tls.ja3_extras` (never `client_hello`). Verified against all 53 built-in presets in Go, Python, Node.js, and .NET — strict round-trip passes for every name in `Available()` including `-latest` aliases. The Node.js export uses the leak-safe `HeapStr` koffi disposable from issue #48; Python uses `_ptr_to_string`; .NET uses `Native.PtrToStringAndFree`. Internal helper: new `ClientHelloIDName(id)` inverse lookup over the canonical-name map, with concrete names taking precedence over `-auto` aliases (so `HelloFirefox_Auto` resolves to `firefox-120`, not the alias).
- **`WithDisableHTTP3()` session option** — Disables HTTP/3 (QUIC) while keeping H1/H2 auto-negotiation. Useful when binding to a local address that doesn't support UDP or when QUIC is unreliable on the network. Previously the only way to avoid H3 was `WithForceHTTP2()` which locked out H1.
- **JSON preset loader + custom preset registry** — New `BuildPreset` path accepts a JSON spec (TLS, H2, H3, QUIC, headers, header order, TCP fingerprint) and registers named presets at runtime. Exposed via `httpcloak.loadPreset(filePath)` / `loadPresetFromJSON(jsonData)` / `unregisterPreset(name)` in Python, Node.js, and .NET. Supports inheritance from built-in presets, deep-clone on lookup, mutual exclusion between `ja3` + explicit TLS fields, and PSK session resumption for JA3-defined presets. Example JSON spec files ship under `examples/presets/` (Chrome 146 Linux, Safari 18, Firefox 148).
- **`PresetPool` for rotation** — Load a JSON pool file containing multiple presets and pick round-robin or random. All presets auto-register on construction; name is returned verbatim for `Session(preset: ...)`. Available in all bindings. Hardened against nil presets, empty pools, constructor overflow, and orphaned registrations.
- **`H2FingerprintConfig` / `H3FingerprintConfig` types** — Explicit per-preset configuration for HTTP/2 settings, header tables, priority frames, pseudo-header order, QPACK settings, and QUIC transport parameters. Replaces hardcoded values scattered across `http2_transport.go`, `http3_transport.go`, and pool builders with preset getters. All 30 built-in presets now carry explicit H2 configs; Safari/iOS presets gained explicit H3 configs replacing the prior heuristic fallback.
- **Firefox 148 preset** — New preset with JA3 TLS fingerprint and explicit H2/H3 configs. Illustrates the JSON preset spec with `key_share_curves`, `delegated_credential_algorithms`, and full QUIC parameters.
- **Per-connection QUIC transport parameters** — QUIC connection ID length and max datagram frame size are now per-connection (derived from the preset) instead of process-global constants, so mixed-preset workloads no longer leak parameters across sessions.
- **Preset pool and registry exports in clib and bindings** — `PresetPool` lifecycle (load/pick/random/next/get/close) and the custom-preset registry are surfaced through the C API and exposed in Python/Node.js/.NET.
- **`fetchMode` / `fetch_mode` knob on every request method** — Escape hatch for requests where the auto-sniff can't pick the right `Sec-Fetch-Mode`. Accepts `"cors"`, `"no-cors"`, `"navigate"`, or `"websocket"` and is available as a kwarg (Python `fetch_mode`), option field (Node.js `fetchMode`), and parameter (.NET `fetchMode:`) on every Get/Post/Put/Patch/Delete/Head/Options/Request + Async/Fast/Stream variant. Injects `Sec-Fetch-Mode` + a coherent `Sec-Fetch-Dest` when the user didn't supply them, so the final header set stays self-consistent.

### Fixed

- **Per-request `timeout` semantics consistent across Python, Node.js, and .NET** — Three coordinated bugs surfaced from one root cause (the clib has different unit conventions on its sync vs. async request paths): (1) Python `Session.get(url, timeout=30)` routed through `Session.request()` which forwarded the value as-is into the sync `request_config.timeout` field that the C side interprets as **milliseconds**, so a 30-second-intent call fast-failed in 30 ms. (2) .NET `Session.Get(url, timeout: 30)` had the identical issue at `bindings/dotnet/HttpCloak/Session.cs:530`. (3) Node.js `Session.get(url, { timeout })` and `Session.post(url, { timeout })` never destructured `timeout` from the options object, silently dropping the value; the underlying clib `httpcloak_get_async` / `httpcloak_post_async` paths parsed `options.Timeout` but never enforced it on the request context. **Fix:** Python `Session.request()` and .NET `Session.Request()` now multiply `timeout * 1000` at the boundary before stuffing the JSON config (sync C paths read ms). Node.js `get()` / `post()` destructure `timeout` and forward as `reqOptions.timeout`. Clib `get_async` / `post_async` now layer `context.WithTimeout(time.Second)`, matching the existing `request_async` unit. Public API across all bindings is now uniformly seconds (matching `Session(timeout=)`). Verified end-to-end: `s.get(url, timeout=30)` returns 200 promptly; `s.get(url, timeout=1)` against a 2-second sleep endpoint fast-fails in ~1 second.
- **Caller-supplied headers landed in the wrong HPACK wire position** — When a caller supplied a header outside the preset's default emit set (e.g. `cache-control: max-age=0` on an F5 reload, `content-type` on a POST, or `cookie` on a follow-up request), the magic per-request `Header-Order:` key was being populated from the preset's *header values list* (which only enumerates headers Chrome sends every time) instead of the *full HPACK position table* (which also reserves slots for situational headers). The forked H2 encoder then appended the unknown header after the last value-list entry, producing a wire ordering distinguishable from real browsers — `cache-control` ended up after `priority` instead of right after `:path`. Three call sites now use `Preset.H2HeaderOrder()` (the complete position table including `cache-control`, `content-type`, `content-length`, `origin`, `referer`, `cookie`, and `priority`): `transport/transport.go:1869`, `client/client.go:1500`, `client/client.go:1585`. Default fresh-nav requests stay byte-identical because the encoder skips order entries with no matching `req.Header` key. New regression test `TestUserSuppliedCacheControl_RespectsHPACKPosition` pins `cache-control`'s wire position relative to `:path` / `sec-ch-ua` / `priority`.
- **Issue #57: Python and Node.js silently enabled 3 retries on 5xx by default** — Python's `Session(retry: int = 3)` and Node.js's `{ retry = 3 }` destructuring defaults always wrote `retry=3` into the session config, so callers that never asked for retries quietly fired 4 requests per failed call (1 attempt + 3 retries on the default `[429, 500, 502, 503, 504]` status list). Worse, this hit POST/PUT/PATCH the same as GET/HEAD — a clear idempotency violation that could double-charge or duplicate writes. Root cause was a binding-level default disagreement: .NET correctly defaulted to 0, Python and Node.js defaulted to 3. Both bindings now default to 0 (matching .NET); enabling retry is opt-in via `retry=N` / `{ retry: N }`. Three regression locks added so this can't drift back: a Python signature test (`internal_tests/python/test_retry_default.py`), a Node.js source-pattern test (`internal_tests/nodejs/test_retry_default.js`), and a Go-level option-chain test (`retry_default_test.go`) that pins the default at every layer from `WithRetry` / `WithoutRetry` down through `NewSession` and into the `protocol.SessionConfig` that drives the retry loop. **Behavior change**: callers that relied on the implicit default-3 retry now see 0 retries; pass `retry=3` explicitly for the old behavior.
- **JA3 with X25519MLKEM768 (group 4588) as the first supported group caused `tls: internal error` on every handshake** — Firefox 141+ ships JA3s starting with `4588-29-23-24-25-256-257`. Our `ParseJA3` defaulted `KeyShareCurves` to 1, so the resulting spec carried a single MLKEM key share. utls' TLS 1.3 client handshake then trips its `keyShareKeys.ecdhe == nil` consistency check (`handshake_client_tls13.go:63`) — the preset path that generates MLKEM key shares populates `KeyShareKeys.MlkemEcdhe` but not the legacy `Ecdhe` field, while the consistency check still requires `Ecdhe`. The result was `local error: tls: internal error` before any wire bytes left the socket. Real Firefox and Chrome always pair the MLKEM key share with an X25519 share anyway, so the fix is to auto-bump `KeyShareCurves` to 2 in `ParseJA3` when the first non-GREASE curve is X25519MLKEM768 (0x11EC) or X25519Kyber768Draft00 (0x6399). Explicit `JA3Extras.KeyShareCurves` values are still honored. Added regression tests `TestParseJA3_HybridPQAutoBumpsKeyShares`, `TestParseJA3_HybridPQRespectsExplicitKeyShareCurves`, and `TestParseJA3_NoBumpWithoutHybridPQ`.
- **QUIC `google_connection_options` regression (post-1.6.1-beta.3)** — Commit `7465c7e` (in v1.6.1) added QUIC transport parameter 0x3128 (`google_connection_options`) with value `"B2ON"` to the Chrome H3 fingerprint. The value was wrong: in QUICHE, `B2ON` is the "Enable BBRv2" option, only sent by Chrome instances launched with `--enable-features=QuicConnectionOptions=B2ON` or a Finch override — vanishingly rare in real traffic. Stable Chrome's actual default is `"ORIG"` (origin-frame experiment hint). Some QUIC frontends accepted the handshake fine but silently dropped follow-up frames for non-trivial requests, manifesting as a 30s `MaxIdleTimeout`. Reverted the value to `"ORIG"`; added a transport-package regression test (`TestBuildChromeTransportParams_GoogleConnectionOptions`) that locks the wire bytes so this can't drift back silently.
- **Issue #52: Credential leakage across scheme-downgrade and cross-origin redirects** — Chain `https://A → https://B → http://C → https://D` forwarded whatever `Referer` and `Authorization` headers the caller set on the first hop all the way through, including to the plain-HTTP hop. Real browsers (Chrome's default `strict-origin-when-cross-origin` referrer policy, plus WHATWG Fetch §4.3 "HTTP-redirect fetch") strip `Referer` entirely on any `https → http` transition and strip `Authorization` / `Proxy-Authorization` on any scheme downgrade or cross-origin redirect. `curl ≥7.58` does the same for auth. `session.requestWithRedirects` and the parallel redirect loop in `client.Client.doOnce` now both apply this scrubbing. `Cookie` was already rebuilt from the cookie jar per-hop and the jar's `Secure` gate was already correct — those paths are unchanged.
- **Issue #48: Node.js binding leaked C-allocated strings on every FFI return** — Every FFI decl in `bindings/nodejs/lib/index.js` that returned `"str"` let koffi copy the C string into a JS string while dropping the original pointer, which Go had allocated with `C.CString` (malloc). The pointer was never fed back to `httpcloak_free_string`, so each `Session.get/post/request`, `getCookies`, `session.refresh`, proxy getters, header-order getters, stream metadata, session save/marshal, local-proxy stats — 26 functions in all — silently leaked a few KB to tens of KB per call, producing significant RSS growth under sustained traffic. Fixed by wrapping `"str"` in a koffi `disposable` type (`HeapStr`) whose auto-invoked disposer is `httpcloak_free_string`, so every C→JS conversion immediately frees the source allocation. Zero call-site changes; Python and .NET already freed correctly via their own helpers and were not affected.
- **Issue #53: Navigate headers on bindings POST/XHR requests** — The binding path (`httpcloak_post_raw` → `session.Do` → `transport.applyPresetHeaders`) had an Accept-only sniff that picked `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`, and `Sec-Fetch-Site: none` for any POST without an explicit `Accept` header. Python's `json=` kwarg set `Content-Type: application/json` but not `Accept`, so every JSON POST emitted navigation headers — an obvious mismatch since browsers send CORS headers for fetch/XHR. The sniff now considers HTTP method, `Content-Type`, `Accept`, and any user-supplied `Sec-Fetch-*` headers, and `applyPresetHeaders` applies a coherent CORS header block (mode=cors, dest=empty, no `upgrade-insecure-requests`) when the request looks like fetch()/XHR. The direct-Go-`client.Client` path was fixed alongside the transport path so the two stay in lockstep. Explicit `Sec-Fetch-Mode: navigate` from the user still forces navigation (e.g. SPA mimicking a form submit).
- **Issue #51: .NET cookie `Max-Age > int32.MaxValue` crash** — `CookieData.MaxAge`, `Cookie.MaxAge`, and the `SetCookie(maxAge:)` parameter were typed as `int`. Servers that advertise 100-year-lifetime cookies (`Max-Age=3153600000`) triggered `System.Text.Json` to throw "The JSON value could not be converted to System.Int32" during deserialization, taking down sync and async request paths. All three are now `long`. Wire format unchanged; existing scripts pass `int` literals without change.
- **Issue #42: Binary response body corruption across all bindings** — Non-UTF-8 response bodies (PDFs, images, gzip streams that slipped past auto-decompression) were silently corrupted when passed through the JSON response channel. The C API now base64-encodes non-UTF-8 bodies and tags them with `body_encoding: "base64"`; Python, Node.js, and .NET decoders decode on receipt. Covers the main request/response path, `httpcloak_upload_finish`, and the `Session.post()` / `Session.request()` binary flows.
- **.NET and Node.js sync paths migrated to raw binary C API** — The sync request paths were still routing bodies through the JSON channel, doubling binary payloads through base64 round-trips. Both now use `httpcloak_{get,post,request}_raw` which takes `(ptr, len)` directly, matching Python.
- **Preset headers overridden by Chrome defaults at client/transport layer** — `applyNavigationModeHeaders` and the client layer were applying hardcoded Chrome `Accept` / `Accept-Language` / `Accept-Encoding` values on top of the preset's own headers, silently clobbering Firefox/Safari/iOS presets. Now uses preset values when present, falls back to Chrome only when the preset doesn't define that header. Pseudo-header order override in client and transport layers is also fixed — `PseudoHeaderOrder` from the preset now survives through both layers.
- **Pool H2 transport was missing `DisableCookieSplit: true`** — Pool-path HTTP/2 was sending cookies as separate HPACK entries instead of a single entry like real Chrome. Detectable by passive H2 fingerprinters.
- **H2 proxy CONNECT missing keep-alive** — H2 proxy `CONNECT` requests did not include `Connection: keep-alive`, causing some proxies to close the tunnel after the CONNECT response.
- **H2 transport close-race nil-map panic** — Added regression tests and guards for the close-race path where a concurrent `Close()` and request could dereference a nil map.
- **`LookupCustom` did not deep-clone presets** — Returning a shared pointer let subsequent mutations leak across sessions. Now returns a deep copy.
- **Session cache guard in pool and orphaned TLS extension fields** — Pool now validates TLS extension fields and guards the session cache lookup to prevent a nil-deref on certain preset shapes.

### Changed

- **`describe_preset` now emits the effective `priority_table`, including the inherited package default** — Previously `Describe()` only emitted `priority_table` when the preset carried an explicit one, so a Chrome 146 dump (which inherits the 14-dest default) returned JSON that omitted the field — confusing for users who wanted to tweak just one entry, since the describe → edit → reload workflow had nothing to edit. `flattenHTTP2` now resolves the same way the runtime does: explicit table wins; otherwise, RFC 7540 presets emit the package default; `NoRFC7540Priorities=true` presets (Safari, iOS Chrome, iOS Safari) still omit the field because they don't carry an RFC 7540 PRIORITY frame at all. Empty `PriorityTable` map is now treated identically to nil at the resolution layer (both fall through to default), simplifying the round-trip semantics. Round-trip stability locked in tests across all 50+ built-in presets.
- **Tweak-fingerprint examples added across Python, Node.js, and .NET** — New `examples/python-examples/17_tweak_fingerprint.py`, `examples/js-examples/18_tweak_fingerprint.js`, and `examples/csharp-examples/TweakFingerprint.cs` demonstrate the four-recipe describe → edit → load workflow: bump per-resource H2 priority, customize HPACK header order, import an externally-captured JA3 + Akamai fingerprint, and clean up via `unregister_preset`. README gains a flagship "Build Any Browser Fingerprint From JSON" feature section plus a compact "Custom Preset Edit Points" reference table.
- **JSON preset spec expanded** — `key_share_curves`, `delegated_credential_algorithms`, and QUIC H3 fields (`connection_id_length`, `max_datagram_frame_size`) are now first-class JSON fields. Inheritance, mutual exclusion validation, and deep-copy behavior are hardened in the loader.
- **H2 settings order is dynamic per browser type** — Matches what real Chrome/Firefox/Safari send instead of a shared static order.

## [1.6.1] - 2026-03-16

### Added

- **Chrome 146 preset** — New default preset with updated `sec-ch-ua` brand rotation (`"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`) and User-Agent version bump. TLS and HTTP/2 fingerprints are identical to Chrome 145/144/143. All `-latest` aliases now resolve to Chrome 146. All code examples updated to use `chrome-latest` to avoid version-specific churn.
- **`getCookiesDetailed()` / `getCookieDetailed()`** — New methods that return Cookie objects with full metadata (domain, path, expires, maxAge, secure, httpOnly, sameSite). Available in all bindings. The existing `getCookies()` / `getCookie()` methods continue to return the old flat format (name→value dict / string) with a deprecation notice — in a future release they will return the same format as the detailed methods.
- **Userspace UDP receive buffering** — On platforms where the kernel limits UDP socket buffer size (Azure Container Apps: 416 KiB), a dedicated drain goroutine now keeps the kernel buffer permanently drained by buffering packets in userspace (256–4096 slots). Prevents silent packet drops, retransmissions, and connection failures for HTTP/3. Activates automatically when the kernel buffer is below 7 MB; zero overhead on systems with proper buffers.
- **`google_connection_options` QUIC transport parameter** — Chrome sends `google_connection_options` (0x3128) with value "B2ON" in QUIC handshakes. This was the last missing Chrome-specific transport parameter identified in a full fingerprint audit. (Note: subsequently corrected to `"ORIG"` in the Unreleased block — see fix entry above.)
- **HPACK never-indexed representation for sensitive headers** — `cookie`, `authorization`, and `proxy-authorization` now use the HPACK "Never Indexed" wire encoding (0x10 prefix) matching Chrome's behavior. Previously used "Without Indexing" (0x00 prefix) which passive H2 fingerprinters can distinguish.
- **`tcp_df` option in Python and Node.js bindings** — The DF (Don't Fragment) bit was missing from the Python and Node.js session constructors. Now all 5 TCP fingerprint fields are exposed in all bindings.
- **All TCP fingerprint fields in .NET binding** — The .NET `Session` constructor and `SessionConfig` class now expose `tcpTtl`, `tcpMss`, `tcpWindowSize`, `tcpWindowScale`, and `tcpDf` parameters.

### Fixed

- **Fix Cookie API losing domain/path/expiry metadata** — The internal cookie jar stored full metadata correctly, but `getCookies()` flattened it to a name→value dict, losing domain/path/expiry and causing last-write-wins collisions when two domains set a cookie with the same name. `setCookie()` now accepts domain/path/flags for domain-scoped cookies — `setCookie("name", "value")` still works unchanged. `deleteCookie()` properly removes cookies (was setting to empty string) and accepts an optional domain parameter. `clearCookies()` calls the Go core directly (was doing a broken client-side loop). All existing scripts continue to work — `getCookies()` still returns a flat dict, `getCookie()` still returns a string. Wire behavior, session serialization, and per-request `cookies` parameter are unchanged.
- **Fix pool H2 path splitting cookies per RFC 9113** — The pool `http2.Transport` was missing `DisableCookieSplit: true`, causing cookies to be sent as separate HPACK entries instead of a single entry like real Chrome. Detectable by passive H2 fingerprinters.

### Changed

- **TCP/IP fingerprint spoofing disabled by default** — Spoofing (TTL, MSS, WindowSize, WindowScale, DF bit) applied to proxy connections breaks connectivity and is useless — the proxy terminates TCP, so the target never sees spoofed values. All 24 presets now ship with zero TCPFingerprint. Users can opt in via `WithTCPFingerprint()` (Go) or `tcp_ttl`/`tcp_mss` etc. in bindings.
- **UDP buffer size warnings permanently suppressed** — The `log.Printf` warnings about insufficient kernel UDP buffer sizes are removed. `setReceiveBuffer`/`setSendBuffer` still attempt to increase buffers best-effort; failures are silently handled by userspace buffering.

### Dependencies

- sardanioss/utls v1.10.2 → v1.10.3
- sardanioss/quic-go v1.2.21 → v1.2.23
- sardanioss/net v1.2.4 → v1.2.5

## [1.6.1-beta.3] - 2026-03-08

### Added

- **TCP/IP fingerprint spoofing** — Spoof OS-level TCP/IP stack parameters (TTL, MSS, Window Size, Window Scale, DF bit) to match the claimed browser platform. Anti-bot systems check SYN packet characteristics to verify Windows/Linux/macOS claims. Platform-specific presets included: Windows (TTL=128, WS=8), Linux (TTL=64, WS=7), macOS (TTL=64, WS=6). Override via `WithTCPFingerprint` in Go or `tcp_ttl`/`tcp_mss`/`tcp_window_size`/`tcp_window_scale` options in bindings.
- **`FetchModeNoCors`** — Simulate subresource loads (`<script>`, `<link>`, `<img>`) with `sec-fetch-mode: no-cors` and content-type-appropriate Accept headers. Use with `FetchDest` field to set `sec-fetch-dest` (script, style, image).
- **`SetForceProtocol()`** — Switch HTTP protocol version (H1/H2/H3) at runtime without creating a new client. Useful for mimicking Chrome's H2→H3 alt-svc upgrade pattern.

### Fixed

- **Fix duplicate Content-Length in H1 transport** — The `writeHeadersInOrder` "remaining headers" loop wrote headers not in the preset order but did not mark them in the tracking map. The fallback "ensure Content-Length" block then wrote Content-Length a second time. Duplicate Content-Length is an HTTP/1.1 protocol violation — nginx and other strict servers return 400 Bad Request. This affected all H1 POST/PUT/PATCH requests with a body through all language bindings.
- **Fix bindings sending Navigate headers to API endpoints** — The transport-level `applyPresetHeaders` always applied Navigate mode headers (`sec-fetch-mode: navigate`, `upgrade-insecure-requests: 1`) regardless of request type. API calls via Python/Node.js/.NET bindings emitted browser navigation headers on JSON requests — a clear protocol mismatch since real browsers send CORS headers for fetch/XHR. Now auto-detects CORS mode from the user's Accept header (`application/json`, `*/*`, etc.) and adjusts sec-fetch headers accordingly.
- **Fix Chrome 145 sending unnecessary MAX_FRAME_SIZE** — Chrome omits HTTP/2 SETTINGS_MAX_FRAME_SIZE (setting 5), relying on the RFC default of 16384. Our preset was sending it explicitly, creating a fingerprint mismatch.

### Changed

- **H3 header order unified with H2** — Removed separate `H3HeaderOrder` from presets. Chrome uses the same `request_->extra_headers` ordered vector for both H2 and H3 (confirmed from Chromium source). The previous H3-specific order was a stale artifact from an upstream tool whose output had been observed-but-incorrectly-ordered.
- **QPACK Never-Index bit for sensitive headers** — Cookie, Authorization, and Proxy-Authorization headers are now encoded with the N=1 (Never-Index) bit in QPACK, matching Chrome's behavior of preventing intermediaries from caching sensitive values in dynamic tables.
- **H3 SETTINGS frame delivery** — Re-added 5ms delay after opening control/QPACK streams to ensure the SETTINGS frame is parsed by the server before request HEADERS arrive. Without this, SETTINGS and request can be bundled in the same packet.
- **Deterministic H3 header ordering** — Headers not in the preset order are now sorted alphabetically instead of random Go map iteration order. Canonical key lookup added for case-insensitive header matching in QPACK encoder.
- **Chrome QUIC Initial packet structure** — Fixed to match Chrome's exact packet layout for fingerprint consistency.
- **Chrome DefaultInitialRTT** — Set to 100ms matching Chrome's PTO (Probe Timeout) behavior.

### Dependencies

- quic-go v1.2.18 → v1.2.21
- qpack v0.6.2 → v0.6.3

## [1.6.1-beta.2] - 2026-02-23

### Fixed

- Fix query parameters duplicated in URL for .NET async methods (`GetAsync`, `PostAsync`) — params were applied in the method then passed again to `RequestAsync` which applied them a second time (only affected async path with explicit timeout)
- Fix `SetProxy()` and `SetPreset()` losing `insecureSkipVerify` setting — recreated child transports started with default `false`, ignoring the parent's `verify: false` setting
- Fix query parameter order not preserved in .NET binding — changed `parameters` type from `Dictionary<string, string>` to `IEnumerable<KeyValuePair<string, string>>` across all request methods (source-compatible, users can now pass ordered collections like `List<KeyValuePair<>>` for order-sensitive APIs)

## [1.6.1-beta.1] - 2026-02-22

### Added

- **Custom JA3 fingerprinting** — Override the preset's TLS fingerprint with a custom JA3 string. Supports all 25+ known TLS extensions, GREASE filtering, and automatic defaults for unspecified fields. Available via `WithCustomFingerprint` in Go and `ja3` option in all bindings (Python, Node.js, .NET, clib).
- **Custom Akamai HTTP/2 fingerprinting** — Override the preset's HTTP/2 SETTINGS, WINDOW_UPDATE, PRIORITY, and pseudo-header order with an Akamai fingerprint string. Available via `WithCustomFingerprint` in Go and `akamai` option in all bindings.
- **Extra fingerprint options** — Fine-tune TLS extensions beyond what JA3 captures: `tls_signature_algorithms`, `tls_alpn`, `tls_cert_compression`, `tls_permute_extensions`. Available via `extra_fp` dict in bindings or `CustomFingerprint` struct fields in Go.
- **JA3 parser** (`fingerprint/ja3.go`) — Converts JA3 strings to uTLS `ClientHelloSpec` with extension ID to `TLSExtension` mapping for 25+ known extensions, GREASE handling, and Chrome-like defaults for signature algorithms, ALPN, and cert compression.
- **Akamai parser** (`fingerprint/akamai.go`) — Converts Akamai HTTP/2 fingerprint strings to `HTTP2Settings` + pseudo-header order.
- **JA3/Akamai unit tests** — 29 unit tests covering Chrome/Firefox/Safari fingerprints, malformed input, GREASE filtering, extension type verification, defaults merging, and edge cases.
- **E2E fingerprint tests** — 4 E2E tests verifying JA3 match, H2 fingerprint match, preset sanity, and cross-session reproducibility.

### Changed

- TLS-only mode is automatically enabled when a custom JA3 fingerprint is set (preset HTTP headers are skipped)
- Extension 50 (`signature_algorithms_cert`) now uses a broader Chrome-like list including `PKCS1WithSHA1` for legacy certificate chain verification
- Extension 51 (`key_share`) now generates a key share only for the first preferred curve, matching real browser behavior (previously generated for all curves, which was a detectable fingerprint signal)

### Fixed

- Fix `DoStream` missing `configErr` check — invalid Akamai fingerprint errors were silently ignored for streaming requests
- Fix H1 speculative TLS fallback unconditionally setting session cache — could cause handshake failures with custom JA3 specs that lack PSK extension
- Fix `ParseJA3` mutating caller's `*JA3Extras` struct when filling in defaults — now makes a shallow copy
- Fix `SetProxy()` and `SetPreset()` silently dropping custom fingerprint config — recreated transports with nil config, losing `CustomJA3`, `CustomH2Settings`, speculative TLS, key log writer, and other settings
- Fix `Fork()` dropping custom fingerprint settings — forked sessions now copy the parent's transport config (including custom JA3, H2 settings, pseudo-header order)
- Fix clib `extra_fp` silently ignored when neither `ja3` nor `akamai` is set — `tls_permute_extensions` and other extra options now work standalone

## [1.6.0] - 2026-02-22

### Added

- **Chrome 145 presets** — Added `chrome-145`, `chrome-145-windows`, `chrome-145-linux`, `chrome-145-macos`, `chrome-145-ios`, `chrome-145-android` browser presets with updated TLS fingerprints and HTTP/2/H3 settings.

### Changed

- Default preset updated from `chrome-144` to `chrome-145`
- Total available presets increased from 18 to 24

## [1.6.0-beta.13] - 2026-02-15

### Added

- **`session.Fork(n)`** — Create N sessions sharing cookies and TLS session caches but with independent connections. Simulates multiple browser tabs from the same browser for parallel scraping. Available in Go, Python, Node.js, and C#.
- **`session.Warmup(url)`** — Simulate a real browser page load by fetching HTML and all subresources (CSS, JS, images, fonts) with realistic headers, priorities, and timing. Populates TLS session tickets, cookies, and cache headers before real work begins. Available in Go, Python, Node.js, and C#.
- **Speculative TLS** — Sends CONNECT + TLS ClientHello together on proxy connections, saving one round-trip (~25% faster proxy handshakes). Disabled by default due to compatibility issues with some proxies; enable with `enable_speculative_tls`.
- **`switch_protocol` on Refresh()** — Switch HTTP protocol version (h1/h2/h3) when calling `Refresh()`, persisting for future refreshes.
- **`-latest` preset aliases** — `chrome-latest`, `firefox-latest`, `safari-latest` aliases that automatically resolve to the newest preset version.
- **`available_presets()` returns dict** — Now returns a dict with protocol support info (`{name: {h1, h2, h3}}`) instead of a flat list.
- **Auto Content-Type for JSON POST** — Automatically sets `Content-Type: application/json` when body is a JSON object/dict.
- **C# CancellationToken support** — Native Go context cancellation for C# async methods.
- **C# Session finalizer** — Prevents Go session leaks when `Dispose()` is missed.
- **`disable_ech` toggle** — Disable ECH lookup per-session for faster first requests when ECH is not needed.
- **`cache-control: max-age=0` after Refresh()** — Automatically adds cache-control header to requests after `Refresh()`, matching real browser F5 behavior.
- **Local address binding** — Bind outgoing connections to a specific local IP address for IPv6 rotation. Available via `WithLocalAddress` in Go and `local_address` option in bindings.
- **TLS key logging** — Per-session `key_log_file` option and `SSLKEYLOGFILE` environment variable support for Wireshark TLS inspection.
- **Fast-path clib bindings** — Zero-copy APIs (`httpcloak_fast_*`) for high-throughput transfers via C FFI.
- **New mobile presets** — Added `chrome-144-ios`, `chrome-144-android`, `safari-18-ios` presets.

### Changed

- Parallel DNS + ECH resolution in SOCKS5 proxy QUIC dial path and H3 transport dial
- Pre-load x509 system root CAs at init to avoid ~40ms delay on first TLS handshake
- Default preset updated from `chrome-131`/`chrome-143` to `chrome-latest`
- Replace `SOCKS5UDPConn` with `udpbara` for H3 proxy transport

### Fixed

#### Transport Reliability
- Fix H2 head-of-line blocking: release `connsMu` during TCP+TLS dial so other requests aren't blocked
- Fix H2 cleanup killing long-running requests by adding in-flight request counter
- Fix H2 per-address dial timeout using `min(remaining_budget/remaining_addrs, 10s)`
- Fix H1 POST body never sent when preset header order omits `Content-Length`
- Fix H1 connection returned to pool before body is fully drained
- Fix H1 deadline cleared while response body still being read
- Fix H3 UDP fallback and narrow 0-RTT early data check
- Fix H3 GREASE ID/value and QPACK capacity drift in `Refresh()`/`recreateTransport()`
- Fix H3 local address IP family filtering (IPv6 local address connecting to IPv4-only host)
- Fix H3 0-RTT rejection after `Refresh()` by re-adding missing preset configurations
- Fix speculative TLS causing 30s body read delay on HTTP/2 connections
- Fix speculative TLS blocklist key mismatch in H1 and H2
- Fix `bufio.Reader` data loss in proxy CONNECT for H1 and H2
- Fix corrupted pool connections, swallowed flush errors, nil-proxy guards
- Fix case-sensitive `Connection` header, H2 cleanup race, dead MASQUE code
- Fix nil-return on UDP failure and stale H2 connection entry
- Fix relative path redirect resolution using `net/url` for proper base URL joining

#### Proxy & QUIC
- Fix `quic.Transport` goroutine leak in SOCKS5 H3 proxy path
- Auto-cleanup proxy QUIC resources when connection dies
- Fix proxy CONNECT deadline to respect context timeout in H1 and H2

#### Session & Config
- Fix `verify: false` not disabling TLS certificate validation
- Fix `connect_to` domain fronting connection pool key sharing
- Fix POST payload encoding: use `UnsafeRelaxedJsonEscaping` for all JSON serialization
- Fix per-request `X-HTTPCloak-TlsOnly` header support in LocalProxy
- Fix bogus fallback values in clib getter functions returning incorrect defaults
- Fix stale default presets (`chrome-131`/`chrome-143`) across all bindings

#### Bindings
- Fix async headers not forwarded in Python `get_async()`/`post_async()` methods
- Fix clib build missing `httpcloak_fast.go` source file
- Remove non-existent `chrome-131` preset from all binding defaults

#### Resource Leaks
- Fix resource leaks and race conditions across all HTTP transports (comprehensive audit)
- Fix H3 transport `Close()` blocking indefinitely on QUIC graceful drain
- 8 timeout bugs fixed where context cancellation/deadline was ignored across all transports
- `wg.Wait()` in goroutines now uses channel+select on `ctx.Done()`
- `time.Sleep()` in goroutines replaced with `select { case <-time.After(): case <-ctx.Done(): }`
- `http.ReadResponse()` on proxy connections now sets `conn.SetReadDeadline()`
- QUIC transport `Close()` wrapped in `closeWithTimeout()` in both `Refresh()` and `Close()` paths

## [1.5.10] - 2025-12-18

Baseline release. This changelog begins tracking changes from this version forward.

[1.6.1-beta.3]: https://github.com/sardanioss/httpcloak/compare/v1.6.1-beta.2...v1.6.1-beta.3
[1.6.1-beta.2]: https://github.com/sardanioss/httpcloak/compare/v1.6.1-beta.1...v1.6.1-beta.2
[1.6.1-beta.1]: https://github.com/sardanioss/httpcloak/compare/v1.6.0...v1.6.1-beta.1
[1.6.0]: https://github.com/sardanioss/httpcloak/compare/v1.6.0-beta.13...v1.6.0
[1.6.0-beta.13]: https://github.com/sardanioss/httpcloak/compare/v1.5.10...v1.6.0-beta.13
[1.5.10]: https://github.com/sardanioss/httpcloak/releases/tag/v1.5.10
