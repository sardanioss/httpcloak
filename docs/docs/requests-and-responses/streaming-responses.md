---
title: Streaming Responses
sidebar_position: 5
---

# Streaming Responses

`DoStream()` returns a response whose body you read incrementally. It returns the moment the response headers arrive, leaving the body for the caller to pull. Plain `Do()` reads the full body into memory before returning, which is fine for small payloads and the wrong call for large ones.

Use streaming for:

- **Big downloads.** A 2 GB file doesn't belong in RAM.
- **Server-Sent Events.** Long-lived connections that drip events.
- **NDJSON / line-delimited streams.** One record at a time.
- **Anything chunked.** When the server doesn't know the content length up front.

:::info
On builds older than v1.6.6, the lower-level `client.Client.DoStream` didn't update the cookie jar from the response. The fix shipped in 1.6.6 (commit `e3acf96`); session-level `DoStream` and every binding had jar parity already. On 1.6.6 or newer, `Do` and `DoStream` feed the same jar identically.
:::

## The shape

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

`Session.DoStream(ctx, req)` returns a `*StreamResponse` that implements `io.Reader`. Anything that takes a Reader works: bufio.Scanner, json.Decoder, io.Copy.

```go
package main

import (
    "bufio"
    "context"
    "fmt"

    httpcloak "github.com/sardanioss/httpcloak"
)

func main() {
    s := httpcloak.NewSession("chrome-latest")
    defer s.Close()

    stream, err := s.GetStream(context.Background(), "https://httpbin.org/stream/10")
    if err != nil {
        panic(err)
    }
    defer stream.Close()

    fmt.Println("status:", stream.StatusCode)
    fmt.Println("content-length:", stream.ContentLength) // -1 if chunked

    scanner := bufio.NewScanner(stream)
    n := 0
    for scanner.Scan() {
        n++
        fmt.Printf("chunk %d: %s\n", n, scanner.Text())
    }
    fmt.Printf("got %d lines\n", n)
}
```

`Close()` is mandatory. Defer it the second you have the stream. Without it, the underlying connection leaks instead of returning to the pool, and the next request eats the dial cost.

</TabItem>
<TabItem value="python" label="Python">

The Python binding folds streaming into `get(stream=True)`:

```python
import httpcloak

s = httpcloak.Session(preset="chrome-latest")

with s.get("https://httpbin.org/stream/10", stream=True) as r:
    print("status:", r.status_code)
    n = 0
    for line in r.iter_lines():
        n += 1
        print(f"chunk {n}: {line}")
    print(f"got {n} lines")
```

`iter_lines()` and `iter_content(chunk_size=N)` both work. The `with` block calls Close for you when the body is done.

</TabItem>
<TabItem value="nodejs" label="Node.js">

`session.getStream()` returns a StreamResponse you can iterate with `for await`:

```js
const { Session } = require("httpcloak");

const s = new Session({ preset: "chrome-latest" });

const stream = s.getStream("https://httpbin.org/stream/10");
console.log("status:", stream.statusCode);

let n = 0;
for await (const chunk of stream) {
  n++;
  console.log(`chunk ${n}: ${chunk.toString()}`);
}
stream.close();
console.log(`got ${n} chunks`);
```

Always call `stream.close()` after iterating, otherwise the connection leaks.

</TabItem>
<TabItem value="dotnet" label=".NET">

`Session.GetStream()` (and `RequestStream` for non-GET) returns a `StreamResponse` with a `Stream` body:

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-latest");

using var stream = s.GetStream("https://httpbin.org/stream/10");
Console.WriteLine($"status: {stream.StatusCode}");

using var content = stream.GetContentStream();
using var reader = new StreamReader(content);
int n = 0;
string? line;
while ((line = reader.ReadLine()) != null)
{
    n++;
    Console.WriteLine($"chunk {n}: {line}");
}
Console.WriteLine($"got {n} lines");
```

The `using` on the StreamResponse handles Close.

</TabItem>
</Tabs>

## What you can read it as

The body is bytes coming off the wire. The caller decides how to split them.

- **Line-delimited.** `bufio.Scanner` (Go), `iter_lines()` (Python), readline loop (Node).
- **Fixed-size chunks.** `Read(buf)` (Go), `iter_content(chunk_size=N)` (Python), `read(N)` (Node).
- **JSON streams.** Wrap in a JSON decoder. Go: `json.NewDecoder(stream).Decode(&v)` in a loop for NDJSON. Python: `for line in r.iter_lines(): obj = json.loads(line)`.
- **Pipe to a file.** Go: `io.Copy(file, stream)`. Python: `for chunk in r.iter_content(8192): f.write(chunk)`.

## Trailers

`Trailer()` returns the trailing header block, lowercase-keyed, or nil when there
was none.

Call it after the body has been read to EOF. On a streamed response the trailers
have not arrived when the header block does, which is why this is a method rather
than the plain field it is on a buffered response. Before EOF it returns nil, or
on HTTP/1.1 the declared names with no values, which is all the protocol makes
available at that point.

gRPC is the case that needs it: the call's real status arrives in the trailers
and the response is a 200 either way, so a streamed gRPC call read without this
reports every failure as a success.

```python
st = session.get_stream("https://example.com/grpc")
body = st.read_all()          # drain to EOF first
print(st.trailer())           # {'grpc-status': ['14'], 'grpc-message': ['unavailable']}
st.close()
```

## Opening a stream without blocking

The synchronous entry points block the calling thread until the response headers
arrive, which for a stream can be the whole point of the request. Opening several
long-lived streams costs a thread each, and a single-threaded runtime cannot open
one at all without stalling everything else.

The async variant hands the stream back through a callback instead, carrying the
same metadata the synchronous path returns plus the stream handle, so there is no
second call to fetch it. From there it is the same stream: read it, then close it.

Cancelling before the response arrives goes through the request, as it does for
any other async call. Once the stream exists its lifetime belongs to the stream
itself and ends at `close`.

## Lifetime and Close

The contract is the caller must call Close when done. There's no GC fallback because the stream wraps real syscall resources: a TCP socket, an H2 stream window, an H3 stream.

Common ways to forget:

- Returning early from a function on an error path without `defer stream.Close()`. Always defer right after the err check.
- Iterating partway and bailing without closing.
- In Python, skipping `with`. The non-with form needs an explicit `r.close()`.

Closing partway through is fine. The lib reads-and-discards the rest in the background to keep the underlying connection clean for reuse, or hard-aborts the H2/H3 stream when there's a lot of body left.

## ContentLength and chunked

`stream.ContentLength` (or `content_length` / `contentLength` in the bindings) is `-1` when the server uses chunked transfer encoding, or H2/H3 without an explicit content-length frame. Don't assume it's positive when sizing a download progress bar.

To know the size up front, fire a `HEAD` request first, read `Content-Length` from the response headers, then `DoStream()` the GET. Most servers send a length on HEAD even when they switch to chunked on GET.

## Cookie jar parity (since 1.6.6)

Streaming responses go through the same cookie extraction path as regular ones. `Set-Cookie` headers from the response, including any in-stream redirect the lib resolved before handing you the body, land in the session jar.

Before 1.6.6, the lower-level Go `client.Client.DoStream` skipped jar reads and writes; sessions that authenticated via `Do()` and then issued a streaming request silently lost their auth state on the wire. The session-level `DoStream` and every binding had parity already, so this only affected callers using the `client/` subpackage directly. Fixed in 1.6.6 ([`e3acf96`](../changelog)).

For builds that predate the fix and can't upgrade:

```go
// Manual cookie extraction from a streamed response, pre-1.6.6 workaround.
for _, sc := range stream.Headers["Set-Cookie"] {
    // parse sc with net/http or store as raw and inject on next request
}
```

## Server-Sent Events

SSE is a long-lived HTTP response with `text/event-stream` as the content type. The body is a sequence of newline-delimited fields belonging to four field types: `event`, `data`, `id`, `retry`. A blank line dispatches whatever fields the parser has buffered as one event. Lines beginning with `:` are comments, used by some servers as keepalives, and the parser drops them.

The lib ships an `SSEReader` that wraps a streaming response and parses these fields into `SSEEvent` records. The byte-level scanner, the buffer rules, the multi-line `data:` join, the comment skip, all of it lives in the lib. You hand it a stream and pull events back.

`SSEReader`, `SSEEvent`, and `NewSSEReader` live in the `client` subpackage and operate on `*client.StreamResponse`, which is a different type from the `*httpcloak.StreamResponse` returned by `Session.GetStream`. The two streaming surfaces don't share a stream type today, so SSE consumers drop to the `client` package's API for the whole pipeline:

```go
package main

import (
    "context"
    "fmt"
    "io"

    "github.com/sardanioss/httpcloak/client"
)

func main() {
    c := client.NewClient("chrome-latest")
    defer c.Close()

    stream, err := c.GetStream(context.Background(), "https://example.com/events", nil)
    if err != nil {
        panic(err)
    }
    defer stream.Close()

    reader := client.NewSSEReader(stream)
    defer reader.Close()

    for {
        event, err := reader.Next()
        if err == io.EOF {
            break
        }
        if err != nil {
            panic(err)
        }
        fmt.Printf("event=%s id=%s data=%s\n", event.Event, event.ID, event.Data)
    }
}
```

`Next()` blocks until the next blank line dispatches an event, returns `io.EOF` when the stream ends cleanly, and surfaces any scanner error otherwise. `Close()` on the reader closes the underlying `StreamResponse` and releases the connection back to the pool.

The `SSEEvent` struct has four fields. `Event` is the event name from the `event:` field, empty when the server didn't set one. `Data` is the payload. Multi-line `data:` lines are joined with `\n` between them, matching the behaviour the SSE spec requires. `ID` carries the last event ID, which a client would normally echo back as `Last-Event-ID` on reconnect. `Retry` is the reconnection delay hint in milliseconds when the server sends one, parsed as a non-negative integer.

For loops over multiple sources, or for a graceful shutdown driven by a context, the channel-based variant fits better:

```go
events := reader.Events()
for {
    select {
    case event, ok := <-events:
        if !ok {
            return // stream closed
        }
        handle(event)
    case <-ctx.Done():
        reader.Close() // unblocks the goroutine inside Events()
        return
    }
}
```

`Events()` runs `Next()` in a goroutine and pipes the results down the channel. When `Next()` returns an error (including `io.EOF`), the channel closes. Closing the reader from outside is the way to stop iteration early; the inner goroutine sees the EOF on the closed connection and exits.

A few SSE behaviours worth knowing in advance. SSE connections are long-lived by design and the server can reissue cookies, rotate auth tokens, or 401 you mid-stream. None of that gets handled implicitly. If a token rotates, the caller closes the reader, refreshes the token, opens a new stream, optionally with `Last-Event-ID` set from the last `event.ID` so the server can replay missed events. Anti-bot vendors do fingerprint SSE consumer behaviour. Clients that read events too fast, in lockstep, or with timing that doesn't match a real browser's event loop stand out. The lib's H2 timing is browser-shaped at the transport layer, and the SSE parser doesn't add detectable polling artefacts on top, so what hits the wire on the read side stays clean.

### Bindings

`SSEReader` and `SSEEvent` are Go-only. The Python, Node, and .NET bindings expose the streaming response itself, not the SSE parser on top, so an SSE consumer in those languages parses the body with the binding's own line-iteration tools. The protocol is small enough that a hand-rolled parser fits in twenty lines.

Python:

```python
with s.get("https://example.com/events", stream=True) as r:
    event = {}
    for line in r.iter_lines():
        if line == "":
            if event:
                print(event)
                event = {}
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "data":
            event["data"] = event.get("data", "") + value + "\n"
        else:
            event[field] = value
```

Node:

```js
const stream = s.getStream("https://example.com/events");
let buf = "";
let event = {};
for await (const chunk of stream) {
    buf += chunk.toString();
    let idx;
    while ((idx = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        if (line === "") { if (Object.keys(event).length) console.log(event); event = {}; continue; }
        if (line.startsWith(":")) continue;
        const colon = line.indexOf(":");
        const field = colon === -1 ? line : line.slice(0, colon);
        let value = colon === -1 ? "" : line.slice(colon + 1);
        if (value.startsWith(" ")) value = value.slice(1);
        if (field === "data") event.data = (event.data || "") + value + "\n";
        else event[field] = value;
    }
}
stream.close();
```

.NET sits on top of `StreamReader.ReadLine()` in a loop, with the same blank-line-dispatches-event rule. The shape mirrors the Python version closely enough to port directly.

## A note on H2 and H3

Streaming over HTTP/2 or HTTP/3 still rides on a single multiplexed connection underneath. `stream.Close()` doesn't kill that connection, just the one stream on it. Multiple streaming requests can run in flight on the same H2 connection at once, which works well for SSE plus an API call running side by side.

On HTTP/1.1, a streaming response holds the whole TCP connection until you close. Concurrent requests need separate connections. The lib handles connection pooling either way so the caller doesn't manage it, with the caveat that 100 concurrent streams on H1 means 100 TCP connections.
