# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/sardanioss/httpcloak/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/sardanioss/httpcloak/compare/v1.6.0-beta.13...v1.6.0
[1.6.0-beta.13]: https://github.com/sardanioss/httpcloak/compare/v1.5.10...v1.6.0-beta.13
[1.5.10]: https://github.com/sardanioss/httpcloak/releases/tag/v1.5.10
