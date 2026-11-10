---
title: Rust
sidebar_position: 6
---

# Rust

The Rust binding is a safe API over the same cgo-built library the other bindings use, compiled into a static archive and linked into your binary, so there is no shared library to ship. The wire behaviour is the same as everywhere else: a Rust session sends the same JA4, HTTP/2 settings and header order as the same preset in Go or Python.

The surface follows Rust conventions: builders for sessions and requests, `Result` with a typed error kind, `std::io::Read` and `Write` for streamed bodies, futures for async that work on any executor, and `Drop` for everything that owns native resources.

## Install

The crate builds the Go library from the repository, so depend on it by git (or by path in a checkout):

```toml
[dependencies]
httpcloak = { git = "https://github.com/sardanioss/httpcloak" }
```

Building needs Go 1.26+ and a C compiler. To link a prebuilt library instead, set `HTTPCLOAK_LIB_DIR` to the directory holding it; see `bindings/rust/README.md` for the details and the other build variables.

## A request

```rust
use httpcloak::{presets, Session};

fn main() -> httpcloak::Result<()> {
    let session = Session::builder().preset(presets::CHROME_LATEST).build()?;
    let r = session.get("https://tls.peet.ws/api/all").send()?.error_for_status()?;
    println!("{} {:?}", r.status(), r.version());
    Ok(())
}
```

`send()` blocks the calling thread. `send_async()` returns a future instead; the library completes it from its own threads, so it needs no particular runtime, and dropping it cancels the request.

```rust
let r = session.post("https://httpbin.org/post")
    .json(&serde_json::json!({"k": "v"}))
    .timeout(std::time::Duration::from_millis(1500))
    .send_async()
    .await?;
```

## Sessions

A `Session` is cheap to clone, and clones share cookies, TLS tickets and connections. It is `Send` and `Sync`, so one session can serve many threads or tasks at once. It closes when the last clone, and every request, stream and upload still using it, is dropped.

Options are checked when the session is built. An unknown preset, a zero timeout or `max_redirects(0)` are errors there, rather than values the library would quietly read as something else.

## Streaming

```rust
use std::io::{BufRead, BufReader};

let stream = session.get("https://example.com/events").send_stream()?;
for line in BufReader::new(stream).lines() {
    println!("{}", line?);
}
```

From async code, `into_body_stream()` turns the response into a `futures_core::Stream` of chunks. Uploads too large for memory go through `session.upload(url).start()?`, which implements `std::io::Write`; `finish()` returns the response.

## Timeouts

A request's `timeout` replaces the session's, whether longer or shorter, and is exact to the millisecond: the binding cancels the request itself, since the library counts in whole seconds. For a streamed request it bounds the whole exchange, body included. A stream without one may read for as long as it likes, and only the connection and the headers are bounded.

## Errors

`Error::kind()` is one of `Timeout`, `Connect`, `Dns`, `Tls`, `Proxy`, `Redirect`, `Status`, `InvalidInput`, `Decode`, `Io` or `Other`, with the library's message kept as the error's text. Inputs the library cannot carry, such as a NUL in a string, a line break in a header, or a non-HTTP scheme, are refused before anything is sent.

## Everything else

Cookies, runtime proxy changes, `fork`, `refresh`, `warmup`, `save`/`load`, custom presets and preset pools, the local proxy and an external TLS session cache (`set_session_cache`, a trait) are all available. `cargo doc --open -p httpcloak` has the full API.
