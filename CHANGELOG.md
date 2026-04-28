# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`chrome-148-ios` preset (real-capture validated, deeper changes than 147)** — Apple ships Chrome iOS updates ahead of the desktop bump, so 148 lands first. Validated against live `tls.peet.ws/api/all` (H2) + `quic.browserleaks.com` (H3) captures. Diff vs `chrome-146-ios` is bigger than just User-Agent: HTTP/2 SettingsOrder is `[2,3,4,9]` (drops MAX_FRAME_SIZE, reorders 3↔4), pseudo-order is `m,s,a,p` (was `m,s,p,a` from `safariH2Config`), `ConnectionWindowUpdate` is `10420225`, headers gain `priority: u=0, i`, drop `sec-fetch-user`, `accept-encoding` adds `zstd`, and the wire header order is reshuffled. HTTP/3 uses Safari-reduced QUIC flow control (2 MiB stream / 16 MiB connection windows, 8 max incoming uni streams vs Chrome's 103). The 146 / 147 iOS presets are intentionally NOT updated; this profile captures the deeper iOS-Chrome-specific divergences as of 148 only. TLS bytes (HelloIOS_18, HelloIOS_18_QUIC) are byte-identical to Chrome 146 iOS — utls update not needed. `chrome-latest-ios` / `ios-chrome-latest` now resolve to Chrome 148.
- **`H3FingerprintConfig.QUICInitialStreamReceiveWindow` + `QUICInitialConnectionReceiveWindow`** — New optional pointer fields on the H3 fingerprint config that map directly to quic-go's `InitialStreamReceiveWindow` / `InitialConnectionReceiveWindow` and ultimately to wire transport parameters `initial_max_stream_data_*` (5/6/7) and `initial_max_data` (4). nil-default = quic-go default behavior, so existing presets are unchanged. JSON spec gains matching `quic_initial_stream_receive_window` / `quic_initial_connection_receive_window` keys. Surfaces through the `Describe()` flattener only when set explicitly, so flat output for nil cases stays clean. Used by `chrome-148-ios` to emit Safari-style 2 MiB / 16 MiB windows on the wire.
- **Chrome 147 preset family + embedded JSON registry** — New `chrome-147` / `chrome-147-{windows,linux,macos,ios,android}` presets shipped as JSON files in `fingerprint/embedded/` and auto-registered at package init via `//go:embed`. Windows is byte-validated against a live `tls.peet.ws/api/all` (H2) + `quic.browserleaks.com` (H3) capture. Android is byte-validated against a live `tls.peet.ws/api/all` (H2) capture — same JA4, identical Akamai H2 fp hash, matching `sec-ch-ua` brand string and User-Agent. Linux / macOS follow Chrome's standard cross-platform pattern (same brand, same order, swap UA OS string + `sec-ch-ua-platform` — no behavioral risk since TLS bytes and H2 settings are OS-independent in Chrome's network stack). iOS overrides only the `CriOS/147.0.6917.0` User-Agent since WebKit doesn't support Client Hints. Diff vs Chrome 146 is exactly two header fields per platform: `User-Agent` (146 → 147) and `sec-ch-ua` (`"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"` → `"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"` — GREASE label rotated, GREASE version rotated, brand order reshuffled). TLS bytes (JA3, JA4, ciphers, sigalgs, supported_groups, key_share, ALPN, ALPS, cert compression) and H2/H3 settings (Akamai fingerprint, QPACK config, QUIC transport params, `google_connection_options=ORIG`) are byte-identical to Chrome 146, so the presets reuse `HelloChrome_146_{Windows,Linux,macOS,QUIC}` / `_PSK` (desktop + Android) and `HelloIOS_18` / `_QUIC` (iOS, Safari TLS via WebKit) and inherit all H2/H3 state via the new JSON-preset `based_on` mechanism. All `*-latest` aliases (desktop, Android, iOS) now resolve to Chrome 147 via thin `LookupCustom` wrapper factories that delegate to the embedded JSON. The `//go:embed` mechanism is the future home for monthly Chrome bumps — header-only diffs now ship as JSON files instead of Go-code edits.
- **`describe_preset` / `describePreset` / `Describe` — flatten any preset to JSON for save / edit / reload** — New `fingerprint.Describe(name)` Go API plus matching `httpcloak_describe_preset` clib export and bindings (Python `describe_preset(name)`, Node.js `describePreset(name)`, .NET `CustomPresets.Describe(name)`). Returns a fully-resolved JSON document for any registered preset (built-in or runtime-loaded): inheritance is collapsed, getter fallbacks (`H2Config` / `H3Config` nil → Chrome defaults) are emitted explicitly, header values map keys are sorted alphabetically, and `HeaderOrder` slice order is preserved. The output round-trips byte-equal through `LoadPresetFromJSON` → `BuildPreset` → `Describe`, so it can be saved, hand-edited, reloaded as a custom preset, and re-described without drift. Two consecutive calls return byte-identical bytes (no map-iteration leakage). Empty/zero `TCPFingerprint` is omitted; the `HTTP3` section appears only when `SupportHTTP3=true`. Unregistered utls `ClientHelloID`s (e.g. randomized variants or hand-built IDs) error rather than silently corrupt JSON. `JA3`-defined presets dump to `tls.ja3` + `tls.ja3_extras` (never `client_hello`). Verified against all 53 built-in presets in Go, Python, Node.js, and .NET — strict round-trip passes for every name in `Available()` including `-latest` aliases. The Node.js export uses the leak-safe `HeapStr` koffi disposable from issue #48; Python uses `_ptr_to_string`; .NET uses `Native.PtrToStringAndFree`. Internal helper: new `ClientHelloIDName(id)` inverse lookup over the canonical-name map, with concrete names taking precedence over `-auto` aliases (so `HelloFirefox_Auto` resolves to `firefox-120`, not the alias).
- **`WithDisableHTTP3()` session option** — Disables HTTP/3 (QUIC) while keeping H1/H2 auto-negotiation. Useful when binding to a local address that doesn't support UDP or when QUIC is unreliable on the network. Previously the only way to avoid H3 was `WithForceHTTP2()` which locked out H1.
- **JSON preset loader + custom preset registry** — New `BuildPreset` path accepts a JSON spec (TLS, H2, H3, QUIC, headers, header order, TCP fingerprint) and registers named presets at runtime. Exposed via `httpcloak.loadPreset(filePath)` / `loadPresetFromJSON(jsonData)` / `unregisterPreset(name)` in Python, Node.js, and .NET. Supports inheritance from built-in presets, deep-clone on lookup, mutual exclusion between `ja3` + explicit TLS fields, and PSK session resumption for JA3-defined presets. Example JSON spec files ship under `examples/presets/` (Chrome 146 Linux, Safari 18, Firefox 148).
- **`PresetPool` for rotation** — Load a JSON pool file containing multiple presets and pick round-robin or random. All presets auto-register on construction; name is returned verbatim for `Session(preset: ...)`. Available in all bindings. Hardened against nil presets, empty pools, constructor overflow, and orphaned registrations.
- **`H2FingerprintConfig` / `H3FingerprintConfig` types** — Explicit per-preset configuration for HTTP/2 settings, header tables, priority frames, pseudo-header order, QPACK settings, and QUIC transport parameters. Replaces hardcoded values scattered across `http2_transport.go`, `http3_transport.go`, and pool builders with preset getters. All 30 built-in presets now carry explicit H2 configs; Safari/iOS presets gained explicit H3 configs replacing the prior heuristic fallback.
- **Firefox 148 preset** — New preset with JA3 TLS fingerprint (tlspeet.ws score 29 → 98) and explicit H2/H3 configs. Illustrates the JSON preset spec with `key_share_curves`, `delegated_credential_algorithms`, and full QUIC parameters.
- **Per-connection QUIC transport parameters** — QUIC connection ID length and max datagram frame size are now per-connection (derived from the preset) instead of process-global constants, so mixed-preset workloads no longer leak parameters across sessions.
- **Preset pool and registry exports in clib and bindings** — `PresetPool` lifecycle (load/pick/random/next/get/close) and the custom-preset registry are surfaced through the C API and exposed in Python/Node.js/.NET.
- **`fetchMode` / `fetch_mode` knob on every request method** — Escape hatch for requests where the auto-sniff can't pick the right `Sec-Fetch-Mode`. Accepts `"cors"`, `"no-cors"`, `"navigate"`, or `"websocket"` and is available as a kwarg (Python `fetch_mode`), option field (Node.js `fetchMode`), and parameter (.NET `fetchMode:`) on every Get/Post/Put/Patch/Delete/Head/Options/Request + Async/Fast/Stream variant. Injects `Sec-Fetch-Mode` + a coherent `Sec-Fetch-Dest` when the user didn't supply them, so the final header set stays self-consistent.

### Fixed

- **JA3 with X25519MLKEM768 (group 4588) as the first supported group caused `tls: internal error` on every handshake** — Firefox 141+ ships JA3s starting with `4588-29-23-24-25-256-257`. Our `ParseJA3` defaulted `KeyShareCurves` to 1, so the resulting spec carried a single MLKEM key share. utls' TLS 1.3 client handshake then trips its `keyShareKeys.ecdhe == nil` consistency check (`handshake_client_tls13.go:63`) — the preset path that generates MLKEM key shares populates `KeyShareKeys.MlkemEcdhe` but not the legacy `Ecdhe` field, while the consistency check still requires `Ecdhe`. The result was `local error: tls: internal error` before any wire bytes left the socket. Real Firefox and Chrome always pair the MLKEM key share with an X25519 share anyway, so the fix is to auto-bump `KeyShareCurves` to 2 in `ParseJA3` when the first non-GREASE curve is X25519MLKEM768 (0x11EC) or X25519Kyber768Draft00 (0x6399). Explicit `JA3Extras.KeyShareCurves` values are still honored. Added regression tests `TestParseJA3_HybridPQAutoBumpsKeyShares`, `TestParseJA3_HybridPQRespectsExplicitKeyShareCurves`, and `TestParseJA3_NoBumpWithoutHybridPQ`.
- **QUIC `google_connection_options` regression on PerimeterX-fronted endpoints (post-1.6.1-beta.3)** — Commit `7465c7e` (in v1.6.1) added QUIC transport parameter 0x3128 (`google_connection_options`) with value `"B2ON"` to the Chrome H3 fingerprint, citing an azuretls-client comparison. The value was wrong: in QUICHE, `B2ON` is the "Enable BBRv2" option, only sent by Chrome instances launched with `--enable-features=QuicConnectionOptions=B2ON` or a Finch override — vanishingly rare in real traffic. Stable Chrome's actual default per `net/base/features.cc` is `"ORIG"` (origin-frame experiment hint). PerimeterX's QUIC frontend accepted the handshake fine but silently dropped follow-up frames for non-trivial requests, manifesting as a 30s `MaxIdleTimeout` (`IdleTimeoutError("timeout: no recent network activity")`) on POSTs to www.skyscanner.es. Reverted the value to `"ORIG"`; added a transport-package regression test (`TestBuildChromeTransportParams_GoogleConnectionOptions`) that locks the wire bytes so this can't drift back silently.
- **Issue #52: Credential leakage across scheme-downgrade and cross-origin redirects** — Chain `https://A → https://B → http://C → https://D` forwarded whatever `Referer` and `Authorization` headers the caller set on the first hop all the way through, including to the plain-HTTP hop. Real browsers (Chrome's default `strict-origin-when-cross-origin` referrer policy, plus WHATWG Fetch §4.3 "HTTP-redirect fetch") strip `Referer` entirely on any `https → http` transition and strip `Authorization` / `Proxy-Authorization` on any scheme downgrade or cross-origin redirect. `curl ≥7.58` does the same for auth. `session.requestWithRedirects` and the parallel redirect loop in `client.Client.doOnce` now both apply this scrubbing. `Cookie` was already rebuilt from the cookie jar per-hop and the jar's `Secure` gate was already correct — those paths are unchanged.
- **Issue #48: Node.js binding leaked C-allocated strings on every FFI return** — Every FFI decl in `bindings/nodejs/lib/index.js` that returned `"str"` let koffi copy the C string into a JS string while dropping the original pointer, which Go had allocated with `C.CString` (malloc). The pointer was never fed back to `httpcloak_free_string`, so each `Session.get/post/request`, `getCookies`, `session.refresh`, proxy getters, header-order getters, stream metadata, session save/marshal, local-proxy stats — 26 functions in all — silently leaked a few KB to tens of KB per call. Customers reported sustained ~48 MB/h RSS growth under steady production traffic (Cloudflare-sized response metadata). Fixed by wrapping `"str"` in a koffi `disposable` type (`HeapStr`) whose auto-invoked disposer is `httpcloak_free_string`, so every C→JS conversion immediately frees the source allocation. Zero call-site changes; Python and .NET already freed correctly via their own helpers and were not affected.
- **Issue #53: Navigate headers on bindings POST/XHR requests** — The binding path (`httpcloak_post_raw` → `session.Do` → `transport.applyPresetHeaders`) had an Accept-only sniff that picked `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`, and `Sec-Fetch-Site: none` for any POST without an explicit `Accept` header. Python's `json=` kwarg set `Content-Type: application/json` but not `Accept`, so every JSON POST emitted navigation headers — an obvious bot signal for WAFs like Incapsula. The sniff now considers HTTP method, `Content-Type`, `Accept`, and any user-supplied `Sec-Fetch-*` headers, and `applyPresetHeaders` applies a coherent CORS header block (mode=cors, dest=empty, no `upgrade-insecure-requests`) when the request looks like fetch()/XHR. The direct-Go-`client.Client` path was fixed alongside the transport path so the two stay in lockstep. Explicit `Sec-Fetch-Mode: navigate` from the user still forces navigation (e.g. SPA mimicking a form submit).
- **Issue #51: .NET cookie `Max-Age > int32.MaxValue` crash** — `CookieData.MaxAge`, `Cookie.MaxAge`, and the `SetCookie(maxAge:)` parameter were typed as `int`. Servers that advertise 100-year-lifetime cookies (`Max-Age=3153600000`) triggered `System.Text.Json` to throw "The JSON value could not be converted to System.Int32" during deserialization, taking down sync and async request paths. All three are now `long`. Wire format unchanged; existing scripts pass `int` literals without change.
- **Issue #42: Binary response body corruption across all bindings** — Non-UTF-8 response bodies (PDFs, images, gzip streams that slipped past auto-decompression) were silently corrupted when passed through the JSON response channel. The C API now base64-encodes non-UTF-8 bodies and tags them with `body_encoding: "base64"`; Python, Node.js, and .NET decoders decode on receipt. Covers the main request/response path, `httpcloak_upload_finish`, and the `Session.post()` / `Session.request()` binary flows.
- **.NET and Node.js sync paths migrated to raw binary C API** — The sync request paths were still routing bodies through the JSON channel, doubling binary payloads through base64 round-trips. Both now use `httpcloak_{get,post,request}_raw` which takes `(ptr, len)` directly, matching Python.
- **Preset headers overridden by Chrome defaults at client/transport layer** — `applyNavigationModeHeaders` and the client layer were applying hardcoded Chrome `Accept` / `Accept-Language` / `Accept-Encoding` values on top of the preset's own headers, silently clobbering Firefox/Safari/iOS presets. Now uses preset values when present, falls back to Chrome only when the preset doesn't define that header. Pseudo-header order override in client and transport layers is also fixed — `PseudoHeaderOrder` from the preset now survives through both layers.
- **Pool H2 transport was missing `DisableCookieSplit: true`** — Pool-path HTTP/2 was sending cookies as separate HPACK entries instead of a single entry like real Chrome. Detectable by Akamai's H2 fingerprinter.
- **H2 proxy CONNECT missing keep-alive** — H2 proxy `CONNECT` requests did not include `Connection: keep-alive`, causing some proxies to close the tunnel after the CONNECT response.
- **H2 transport close-race nil-map panic** — Added regression tests and guards for the close-race path where a concurrent `Close()` and request could dereference a nil map.
- **`LookupCustom` did not deep-clone presets** — Returning a shared pointer let subsequent mutations leak across sessions. Now returns a deep copy.
- **Session cache guard in pool and orphaned TLS extension fields** — Pool now validates TLS extension fields and guards the session cache lookup to prevent a nil-deref on certain preset shapes.

### Changed

- **JSON preset spec expanded** — `key_share_curves`, `delegated_credential_algorithms`, and QUIC H3 fields (`connection_id_length`, `max_datagram_frame_size`) are now first-class JSON fields. Inheritance, mutual exclusion validation, and deep-copy behavior are hardened in the loader.
- **H2 settings order is dynamic per browser type** — Matches what real Chrome/Firefox/Safari send instead of a shared static order.

## [1.6.1] - 2026-03-16

### Added

- **Chrome 146 preset** — New default preset with updated `sec-ch-ua` brand rotation (`"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`) and User-Agent version bump. TLS and HTTP/2 fingerprints are identical to Chrome 145/144/143. All `-latest` aliases now resolve to Chrome 146. All code examples updated to use `chrome-latest` to avoid version-specific churn.
- **`getCookiesDetailed()` / `getCookieDetailed()`** — New methods that return Cookie objects with full metadata (domain, path, expires, maxAge, secure, httpOnly, sameSite). Available in all bindings. The existing `getCookies()` / `getCookie()` methods continue to return the old flat format (name→value dict / string) with a deprecation notice — in a future release they will return the same format as the detailed methods.
- **Userspace UDP receive buffering** — On platforms where the kernel limits UDP socket buffer size (Azure Container Apps: 416 KiB), a dedicated drain goroutine now keeps the kernel buffer permanently drained by buffering packets in userspace (256–4096 slots). Prevents silent packet drops, retransmissions, and connection failures for HTTP/3. Activates automatically when the kernel buffer is below 7 MB; zero overhead on systems with proper buffers.
- **`google_connection_options` QUIC transport parameter** — Chrome sends `google_connection_options` (0x3128) with value "B2ON" in QUIC handshakes. This was the last missing Chrome-specific transport parameter identified in a full fingerprint audit against azuretls-client.
- **HPACK never-indexed representation for sensitive headers** — `cookie`, `authorization`, and `proxy-authorization` now use the HPACK "Never Indexed" wire encoding (0x10 prefix) matching Chrome's behavior. Previously used "Without Indexing" (0x00 prefix) which anti-bot systems like Akamai can distinguish.
- **`tcp_df` option in Python and Node.js bindings** — The DF (Don't Fragment) bit was missing from the Python and Node.js session constructors. Now all 5 TCP fingerprint fields are exposed in all bindings.
- **All TCP fingerprint fields in .NET binding** — The .NET `Session` constructor and `SessionConfig` class now expose `tcpTtl`, `tcpMss`, `tcpWindowSize`, `tcpWindowScale`, and `tcpDf` parameters.

### Fixed

- **Fix Cookie API losing domain/path/expiry metadata** — The internal cookie jar stored full metadata correctly, but `getCookies()` flattened it to a name→value dict, losing domain/path/expiry and causing last-write-wins collisions when two domains set a cookie with the same name. `setCookie()` now accepts domain/path/flags for domain-scoped cookies — `setCookie("name", "value")` still works unchanged. `deleteCookie()` properly removes cookies (was setting to empty string) and accepts an optional domain parameter. `clearCookies()` calls the Go core directly (was doing a broken client-side loop). All existing scripts continue to work — `getCookies()` still returns a flat dict, `getCookie()` still returns a string. Wire behavior, session serialization, and per-request `cookies` parameter are unchanged.
- **Fix pool H2 path splitting cookies per RFC 9113** — The pool `http2.Transport` was missing `DisableCookieSplit: true`, causing cookies to be sent as separate HPACK entries instead of a single entry like real Chrome. Detectable by Akamai's H2 fingerprinter.

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
- **Fix bindings sending Navigate headers to API endpoints** — The transport-level `applyPresetHeaders` always applied Navigate mode headers (`sec-fetch-mode: navigate`, `upgrade-insecure-requests: 1`) regardless of request type. API calls via Python/Node.js/.NET bindings were flagged by WAFs like Incapsula because browser navigation headers on an API call is a bot signal. Now auto-detects CORS mode from the user's Accept header (`application/json`, `*/*`, etc.) and adjusts sec-fetch headers accordingly.
- **Fix Chrome 145 sending unnecessary MAX_FRAME_SIZE** — Chrome omits HTTP/2 SETTINGS_MAX_FRAME_SIZE (setting 5), relying on the RFC default of 16384. Our preset was sending it explicitly, creating a fingerprint mismatch.

### Changed

- **H3 header order unified with H2** — Removed separate `H3HeaderOrder` from presets. Chrome uses the same `request_->extra_headers` ordered vector for both H2 and H3 (confirmed from Chromium source). The previous H3-specific order was based on tls3.peet.ws's randomized output (their Go server uses maps internally, losing QPACK header order).
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
- **E2E fingerprint tests** — 4 E2E tests against `tls.peet.ws` verifying JA3 match, Akamai match, preset sanity, and cross-session reproducibility.

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
