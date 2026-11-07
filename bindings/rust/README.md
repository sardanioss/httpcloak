# httpcloak for Rust

Safe Rust bindings for [httpcloak](https://httpcloak.dev): an HTTP client whose
TLS handshake, HTTP/2 settings, QUIC parameters and header order match a real
browser's.

```rust
use httpcloak::{presets, Session};

let session = Session::builder().preset(presets::CHROME_LATEST).build()?;
let response = session.get("https://example.com").send()?.error_for_status()?;
println!("{} over {:?}: {}", response.status(), response.version(), response.text());
```

Two crates live here:

- **`httpcloak`**: the API to use.
- **`httpcloak-sys`**: the raw C declarations, and the build script that compiles
  the Go library (`bindings/clib`) into a static archive and links it in.

## Building

By default the Go library is built from this repository and linked statically, so
the binary you ship needs no shared library. That needs:

- Go 1.26 or newer (see `bindings/clib/go.mod`), and network access the first
  time, to fetch the Go modules;
- a C compiler for cgo.

Depend on the crate by path, or by git, which checks out the whole repository so
the Go sources are there:

```toml
[dependencies]
httpcloak = { git = "https://github.com/sardanioss/httpcloak" }
```

To link a prebuilt library instead, set `HTTPCLOAK_LIB_DIR` to the directory
holding it: `libhttpcloak.a`, `libhttpcloak.so`/`.dylib`/`httpcloak.dll`, or a
release artifact named the way `bindings/clib/build.sh` names them
(`libhttpcloak-linux-amd64.so`). `HTTPCLOAK_LINK=static|dynamic` picks between
the two kinds when both are there. A shared library has to be findable at run
time (`LD_LIBRARY_PATH`, an rpath, or next to the binary). `HTTPCLOAK_GO_SRC`
points the build at `bindings/clib` from elsewhere, and `GO` at a particular Go
binary.

Supported: Linux, macOS and Windows with the GNU toolchain. A Go archive cannot
be linked by MSVC, so `*-windows-msvc` links the DLL
(`libhttpcloak-windows-amd64.dll`, as `bindings/clib/build.sh` builds it)
through an import library, `httpcloak.lib`, both in `HTTPCLOAK_LIB_DIR`. Make
the import library in a Developer Command Prompt: write `httpcloak.def` with the
line `LIBRARY libhttpcloak-windows-amd64.dll`, then `EXPORTS`, then the names
`dumpbin /exports` lists, one per line, and run
`lib /def:httpcloak.def /out:httpcloak.lib /machine:x64`. The DLL must be on
`PATH` or next to the binary at run time. Cross-compiling uses the C compiler
cargo would (`CC_<target>`).

## Using it

### Sessions

A `Session` is a browser profile: cookies, TLS session tickets and connections
persist between its requests. It is cheap to clone (clones share the session),
`Send` and `Sync`, and requests on it may run concurrently from any number of
threads or tasks. The session is closed once the last clone, and every request,
stream and upload using it, is gone.

```rust
use std::time::Duration;
use httpcloak::{HttpVersion, Session};

let session = Session::builder()
    .preset(httpcloak::presets::FIREFOX_LATEST)
    .proxy("socks5://user:pass@127.0.0.1:1080")
    .timeout(Duration::from_secs(20))
    .http_version(HttpVersion::Auto)
    .build()?;
```

Options the library would silently reinterpret are rejected by `build()` rather
than passed on: an unknown preset (the library accepts it and fails every
request), a zero timeout (it means "30 seconds"), `max_redirects(0)` (it means
10).

### Requests

```rust
let response = session
    .post("https://httpbin.org/post")
    .query(&[("page", "2")])
    .header("X-Requested-With", "XMLHttpRequest")
    .json(&serde_json::json!({"hello": "world"}))
    .timeout(Duration::from_millis(1500))
    .send()?;
let data: serde_json::Value = response.json()?;
```

`body`, `json`, `form` and `multipart` set the body; the latter three also set a
`Content-Type` unless you set one. Headers you add replace the preset's under the
same name and go out in the browser's order. `exact_headers` replaces the whole
pipeline for replaying a captured request, and `header_order` reorders one
request without touching the session.

### Async

Every request can also be sent as a future, on any executor, the session being
the same either way. The library completes futures from its own threads, so
nothing needs a particular runtime, and dropping a future cancels its request.

```rust
let response = session.get("https://example.com").send_async().await?;
```

### Streaming

`send_stream` returns once the headers arrive, with the body to read as it comes
through `std::io::Read`, or as a `futures_core::Stream` of chunks with
`into_body_stream`. Trailers are available once the body has been read.

```rust
use std::io::{BufRead, BufReader};

let stream = session.get("https://example.com/events").send_stream()?;
for line in BufReader::new(stream).lines() {
    println!("{}", line?);
}
```

Large request bodies are written incrementally through `std::io::Write`:

```rust
let mut upload = session.upload("https://example.com/upload").start()?;
std::io::copy(&mut std::fs::File::open("big.bin")?, &mut upload)?;
let response = upload.finish()?;
```

### Timeouts

A session's timeout, 30 seconds unless set, bounds each request including its
redirects and retries. A request's own `timeout` replaces it, longer or shorter,
and is exact: the library counts in whole seconds, so the crate keeps its own
deadline and cancels the request when it passes.

For a streamed request, `timeout` bounds the whole exchange, body included, just
as exactly: a read still blocked when it passes is cancelled. Without one, the
body may take as long as it likes; only the connection and the response headers
are bounded, by the session's timeout.

### Errors

Every fallible call returns `httpcloak::Result`. `Error::kind()` says what went
wrong (`Timeout`, `Connect`, `Dns`, `Tls`, `Proxy`, `Redirect`, `Status`,
`InvalidInput`, ...), and the library's own message is kept as the error's
`Display`. The library reports failures as text, so the kind is worked out from
it; the tests hold the classification to the messages the library produces.

Arguments the library cannot carry, a string with a NUL in it, a header with a
line break, a URL that is not `http` or `https`, are refused before anything is
sent. Nothing in the crate panics on bad input, and no panic from your code (a
session cache, say) crosses into the library.

### Everything else

Cookies (`Session::cookies`, `set_cookie`, `delete_cookie`), proxies switched at
run time, `fork`, `refresh`, `warmup`, `save`/`load` and `marshal`/`unmarshal`,
session statistics, custom presets (`load_preset`, `describe_preset`), preset
pools (`PresetPool`), the local proxy (`LocalProxy`) and an external TLS session
cache (`set_session_cache`) are all covered. See the API documentation:
`cargo doc --open -p httpcloak`.

## How it works

Every request, blocking or not, goes through the library's asynchronous exports.
They report the result, or why it failed, to a callback; the synchronous `_raw`
exports instead leave the reason in a slot per session that concurrent requests
overwrite, so a shared session would report one request's failure as another's.
They can also be cancelled, which is how exact timeouts and future cancellation
work. A blocking `send` simply waits on the callback.

Each handle the library hands out is owned by exactly one Rust value, freed in
its `Drop`, and kept from outliving what it depends on: streams, uploads,
in-flight requests and local-proxy registrations each hold their session.

## Testing

```bash
cargo test --workspace                       # unit, integration and property tests, offline
cargo test --test live -- --ignored          # against real servers: fingerprints, HTTP/3, ECH
PROPTEST_CASES=5000 cargo test --release --test fuzz_wire   # a longer fuzz run
```

The integration tests run local HTTP/1.1 and HTTP/2 servers, over TLS and plain
TCP, and a scripted TCP server for misbehaviour: truncated bodies, hangs,
garbage. `httpcloak-sys` checks its declarations against the header cgo
generates. Coverage-guided fuzz targets for the C layer's parsers are in
`bindings/clib/fuzz_test.go` (`go test -fuzz`).

## Limitations

- A failed read of a streamed body says only that it failed: the C function
  returns -1 without a reason.
- Reading a streamed body blocks the calling thread; `into_body_stream` reads
  on a thread of its own, one per stream.
- Dropping the last handle to a session closes it, which can take up to three
  seconds when it has HTTP/3 connections to shut down.
- A session's timeout is in whole seconds (a request's is exact).
