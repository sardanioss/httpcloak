# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
